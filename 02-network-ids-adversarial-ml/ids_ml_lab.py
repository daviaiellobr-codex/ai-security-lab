"""
Experimento 2: Adversarial Machine Learning em um detector de intrusão (KDD Cup 99).

Etapas:
  1. [BLUE TEAM] Treina um Random Forest em tráfego limpo.
  2. [RED TEAM]  Simula uma evasão "Low-and-Slow" alterando atributos de taxa e volume.
  3. [BLUE TEAM] Re-treina o modelo com amostras evadidas (Adversarial Training).
  4. Avalia o modelo blindado com testes que o experimento original não fazia:
       - falsos positivos no tráfego normal limpo;
       - uma perturbação diferente da usada no treino (o ganho generaliza?);
       - um teste de atalho (o modelo decorou o valor src_bytes = 250?);
       - resultados por categoria de ataque (DoS, Probe, R2L, U2R).
  5. Salva as métricas e a feature importance em results/exp2/.

Uso (a partir da raiz do repositório):
  python3 02-network-ids-adversarial-ml/ids_ml_lab.py           # mesma configuração do README
  python3 02-network-ids-adversarial-ml/ids_ml_lab.py --dedup   # remove conexões duplicadas antes do split
"""

import argparse
import json
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.datasets import fetch_kddcup99
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import train_test_split

RESULTS_DIR = Path(__file__).resolve().parent.parent / "results" / "exp2"
ADV_TRAINING_FRACTION = 0.3

# Mapeamento padrão dos rótulos do KDD Cup 99 para as quatro categorias de ataque
ATTACK_CATEGORY = {
    "back": "DoS", "land": "DoS", "neptune": "DoS", "pod": "DoS", "smurf": "DoS", "teardrop": "DoS",
    "ipsweep": "Probe", "nmap": "Probe", "portsweep": "Probe", "satan": "Probe",
    "ftp_write": "R2L", "guess_passwd": "R2L", "imap": "R2L", "multihop": "R2L",
    "phf": "R2L", "spy": "R2L", "warezclient": "R2L", "warezmaster": "R2L",
    "buffer_overflow": "U2R", "loadmodule": "U2R", "perl": "U2R", "rootkit": "U2R",
}
CATEGORIES = ["DoS", "Probe", "R2L", "U2R"]


# --------------------------------------------------------------------------- dados

def load_data(dedup):
    print("1. Carregando dataset de tráfego de rede (KDD99 10%, subset SA)...")
    data = fetch_kddcup99(subset="SA", percent10=True, as_frame=True)
    df = data.frame.copy()

    n_total = len(df)
    n_dup = int(df.duplicated().sum())
    print(f"   {n_total} conexões, das quais {n_dup} são duplicatas exatas ({n_dup / n_total:.1%}).")
    if dedup:
        df = df.drop_duplicates().reset_index(drop=True)
        print(f"   --dedup ativo: {len(df)} conexões únicas mantidas.")

    labels = df["labels"].map(lambda v: v.decode() if isinstance(v, bytes) else str(v)).str.rstrip(".")

    # Converte colunas categóricas (protocolo, serviço, flag) em numéricas
    for col in ["protocol_type", "service", "flag"]:
        df[col] = df[col].astype("category").cat.codes

    # Rótulo binário: 0 = Tráfego Normal, 1 = Ataque
    y = (labels != "normal").astype(int)
    category = labels.map(lambda l: "Normal" if l == "normal" else ATTACK_CATEGORY.get(l, "Outro"))
    X = df.drop(columns=["labels"]).astype(float)

    info = {"conexoes": n_total, "duplicatas": n_dup, "dedup": dedup, "conexoes_usadas": len(df)}
    return X, y, category, info


# ----------------------------------------------------------------- perturbações

def low_and_slow_fixed(X):
    """Perturbação original do README: sempre os mesmos valores.

    O atacante reduz a taxa de conexões ('count', 'srv_count'), fixa 'src_bytes'
    e zera as taxas de erro SYN para imitar uma conexão legítima lenta.
    """
    Xp = X.copy()
    Xp["count"] = np.clip(Xp["count"].to_numpy() * 0.02, 1, 5)
    Xp["srv_count"] = np.clip(Xp["srv_count"].to_numpy() * 0.02, 1, 5)
    Xp["src_bytes"] = 250.0
    Xp["serror_rate"] = 0.0
    Xp["srv_serror_rate"] = 0.0
    return Xp


def low_and_slow_random(X, rng):
    """Mesma estratégia, mas com valores sorteados que o modelo blindado nunca viu no treino.

    Serve para medir se o Adversarial Training aprendeu o padrão de evasão
    ou só decorou os valores fixos da perturbação original.
    """
    Xp = X.copy()
    n = len(Xp)
    factor = rng.uniform(0.01, 0.05, n)
    ceiling = rng.integers(3, 11, n)  # teto entre 3 e 10 conexões
    Xp["count"] = np.clip(np.round(Xp["count"].to_numpy() * factor), 1, ceiling)
    Xp["srv_count"] = np.clip(np.round(Xp["srv_count"].to_numpy() * factor), 1, ceiling)
    Xp["src_bytes"] = rng.integers(100, 1001, n).astype(float)
    Xp["serror_rate"] = rng.uniform(0.0, 0.05, n)
    Xp["srv_serror_rate"] = rng.uniform(0.0, 0.05, n)
    return Xp


# ---------------------------------------------------------------------- métricas

def pct(part, whole):
    return round(100.0 * part / whole, 2) if whole else None


def detection_rate(model, X):
    """Percentual de amostras classificadas como ataque."""
    if len(X) == 0:
        return None
    return round(float(model.predict(X).mean() * 100), 2)


def clean_metrics(model, X, y):
    tn, fp, fn, tp = confusion_matrix(y, model.predict(X), labels=[0, 1]).ravel()
    return {
        "acuracia": pct(tp + tn, tp + tn + fp + fn),
        "recall": pct(tp, tp + fn),
        "precisao": pct(tp, tp + fp),
        "taxa_falsos_positivos": pct(fp, fp + tn),
        "falsos_positivos": int(fp),
        "falsos_negativos": int(fn),
    }


def fmt(value):
    return "     -" if value is None else f"{value:6.2f}%"


# -------------------------------------------------------------------- execução

def main():
    parser = argparse.ArgumentParser(description="Experimento 2: evasão e Adversarial Training em um IDS.")
    parser.add_argument("--dedup", action="store_true",
                        help="remove conexões duplicadas antes de separar treino e teste")
    parser.add_argument("--seed", type=int, default=42, help="semente aleatória (padrão: 42)")
    args = parser.parse_args()

    X, y, category, dataset_info = load_data(args.dedup)
    X_train, X_test, y_train, y_test, cat_train, cat_test = train_test_split(
        X, y, category, test_size=0.25, random_state=args.seed, stratify=y
    )

    # --- DETECTOR ORIGINAL ---
    print("\n2. [BLUE TEAM] Treinando Detector de Intrusão (Random Forest)...")
    clf = RandomForestClassifier(n_estimators=100, random_state=args.seed, n_jobs=-1)
    clf.fit(X_train, y_train)

    print("\n--- RELATÓRIO DE DETECÇÃO (TRÁFEGO LIMPO) ---")
    print(classification_report(y_test, clf.predict(X_test), target_names=["Normal", "Ataque"], digits=4))

    # --- ATAQUE DE EVASÃO ---
    print("3. [RED TEAM] Gerando tráfego de ataque ofuscado (Evasion Attack)...")
    is_attack = (y_test == 1).to_numpy()
    X_attacks = X_test[is_attack]
    cat_attacks = cat_test[is_attack].to_numpy()
    X_evasion = low_and_slow_fixed(X_attacks)

    detected_before = detection_rate(clf, X_attacks)
    detected_after = detection_rate(clf, X_evasion)
    print(f"   Taxa de detecção nos ataques originais: {detected_before:.2f}%")
    print(f"   Taxa de detecção após evasão (Low-and-Slow): {detected_after:.2f}%")
    print(f"   Ataques que passaram despercebidos: {100 - detected_after:.2f}%")

    # --- ADVERSARIAL TRAINING ---
    print(f"\n4. [BLUE TEAM] Adversarial Training (re-treinando com {ADV_TRAINING_FRACTION:.0%} "
          "dos ataques de treino evadidos)...")
    X_adv_train = low_and_slow_fixed(
        X_train[y_train == 1].sample(frac=ADV_TRAINING_FRACTION, random_state=args.seed)
    )
    X_train_hardened = pd.concat([X_train, X_adv_train], ignore_index=True)
    y_train_hardened = pd.concat([y_train, pd.Series(1, index=X_adv_train.index)], ignore_index=True)

    clf_hardened = RandomForestClassifier(n_estimators=100, random_state=args.seed, n_jobs=-1)
    clf_hardened.fit(X_train_hardened, y_train_hardened)
    print(f"   Taxa de detecção após Adversarial Training: {detection_rate(clf_hardened, X_evasion):.2f}%")

    # --- AVALIAÇÃO DO MODELO BLINDADO ---
    print("\n5. Avaliando se o ganho do Adversarial Training é real...")
    rng = np.random.default_rng(args.seed)
    X_evasion_random = low_and_slow_random(X_attacks, rng)

    # Teste de atalho: tráfego NORMAL com src_bytes = 250 (o valor fixo usado no treino adversarial).
    # Se o modelo blindado passar a acusar essas conexões, ele decorou o valor em vez de aprender o padrão.
    X_shortcut = X_test[~is_attack].copy()
    X_shortcut["src_bytes"] = 250.0

    models = {"original": clf, "blindado": clf_hardened}
    summary = {}
    for name, model in models.items():
        summary[name] = {
            "trafego_limpo": clean_metrics(model, X_test, y_test),
            "deteccao_ataques_originais": detection_rate(model, X_attacks),
            "deteccao_evasao_fixa": detection_rate(model, X_evasion),
            "deteccao_evasao_aleatoria": detection_rate(model, X_evasion_random),
            "falsos_positivos_normal_src_bytes_250": detection_rate(model, X_shortcut),
        }

    rows = [
        ("Recall (tráfego limpo)", lambda s: s["trafego_limpo"]["recall"]),
        ("Taxa de falsos positivos (tráfego limpo)", lambda s: s["trafego_limpo"]["taxa_falsos_positivos"]),
        ("Detecção: evasão fixa (vista no treino)", lambda s: s["deteccao_evasao_fixa"]),
        ("Detecção: evasão aleatória (nunca vista)", lambda s: s["deteccao_evasao_aleatoria"]),
        ("Falsos positivos: normal com src_bytes=250", lambda s: s["falsos_positivos_normal_src_bytes_250"]),
    ]
    print(f"\n   {'Métrica':<44}{'Original':>10}{'Blindado':>10}")
    for label, get in rows:
        print(f"   {label:<44}{fmt(get(summary['original'])):>10}{fmt(get(summary['blindado'])):>10}")

    # --- RESULTADOS POR CATEGORIA DE ATAQUE ---
    print("\n6. Resultados por categoria de ataque (detecção, %)")
    print("   DoS por volume (smurf, neptune...) deixa de ser DoS quando a taxa de conexões cai para 1-5:")
    print("   nessa linha, a 'evasão' descreve um ataque que não funcionaria mais.\n")
    groups = [(cat, cat_attacks == cat) for cat in CATEGORIES]
    groups.append(("Sem DoS", cat_attacks != "DoS"))

    per_category = []
    print(f"   {'Categoria':<10}{'n':>6}{'Original':>10}{'Orig.+evasão':>14}{'Blind.+fixa':>13}{'Blind.+aleat.':>15}")
    for cat, mask in groups:
        row = {
            "categoria": cat,
            "n": int(mask.sum()),
            "original_limpo": detection_rate(clf, X_attacks[mask]),
            "original_evasao_fixa": detection_rate(clf, X_evasion[mask]),
            "blindado_evasao_fixa": detection_rate(clf_hardened, X_evasion[mask]),
            "blindado_evasao_aleatoria": detection_rate(clf_hardened, X_evasion_random[mask]),
        }
        per_category.append(row)
        print(f"   {cat:<10}{row['n']:>6}{fmt(row['original_limpo']):>10}{fmt(row['original_evasao_fixa']):>14}"
              f"{fmt(row['blindado_evasao_fixa']):>13}{fmt(row['blindado_evasao_aleatoria']):>15}")

    # --- FEATURE IMPORTANCE ---
    print("\n7. Feature importance (top 10 do modelo original)")
    importance = pd.DataFrame(
        {"original": clf.feature_importances_, "blindado": clf_hardened.feature_importances_},
        index=X.columns,
    ).sort_values("original", ascending=False)
    top = importance.head(10)
    print(f"   {'Atributo':<30}{'Original':>10}{'Blindado':>10}")
    for feature, values in top.iterrows():
        print(f"   {feature:<30}{values['original']:>10.4f}{values['blindado']:>10.4f}")
    volume_share = importance.loc[["count", "srv_count"]].sum()
    print(f"   Peso de count + srv_count: {volume_share['original']:.2%} (original) -> "
          f"{volume_share['blindado']:.2%} (blindado)")

    # --- SALVANDO RESULTADOS ---
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    out_file = RESULTS_DIR / ("ids_results_dedup.json" if args.dedup else "ids_results.json")
    results = {
        "config": {
            "seed": args.seed,
            "dedup": args.dedup,
            "n_estimators": 100,
            "test_size": 0.25,
            "fracao_adversarial_training": ADV_TRAINING_FRACTION,
        },
        "dataset": dataset_info | {
            "treino": len(X_train),
            "teste": len(X_test),
            "ataques_no_teste": int(is_attack.sum()),
        },
        "modelos": summary,
        "por_categoria": per_category,
        "feature_importance_top10": [
            {"atributo": f, "original": round(float(v["original"]), 4), "blindado": round(float(v["blindado"]), 4)}
            for f, v in top.iterrows()
        ],
    }
    out_file.write_text(json.dumps(results, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"\nResultados salvos em {out_file.relative_to(RESULTS_DIR.parent.parent)}")


if __name__ == "__main__":
    main()
