import numpy as np
import pandas as pd
from sklearn.datasets import fetch_kddcup99
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix

print("1. Carregando dataset de tráfego de rede (KDD99 10%)...")
data = fetch_kddcup99(subset="SA", percent10=True, as_frame=True)
df = data.frame.copy()

# Converte colunas categóricas (protocolo, serviço, flag) em numéricas
for col in ["protocol_type", "service", "flag"]:
    df[col] = df[col].astype("category").cat.codes

# Rótulo binário: 0 = Tráfego Normal, 1 = Ataque
y = (df["labels"] != b"normal.").astype(int)
X = df.drop(columns=["labels"]).astype(float)

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.25, random_state=42, stratify=y
)

print("2. [BLUE TEAM] Treinando Detector de Intrusão (Random Forest)...")
clf = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
clf.fit(X_train, y_train)

y_pred = clf.predict(X_test)
print("\n--- RELATÓRIO DE DETECÇÃO (TRÁFEGO LIMPO) ---")
print(classification_report(y_test, y_pred, target_names=["Normal", "Ataque"], digits=4))

# --- SIMULAÇÃO DE ATAQUE ADVERSARIAL (EVASÃO) ---
print("3. [RED TEAM] Gerando tráfego de ataque ofuscado (Evasion Attack)...")
X_attacks = X_test[y_test == 1].copy()
detected_before = clf.predict(X_attacks).mean() * 100

# O atacante reduz a taxa de pacotes ('count', 'srv_count') e ajusta 'src_bytes'
# para imitar o perfil estatístico de uma conexão legítima lenta (Low-and-Slow attack)
X_evasion = X_attacks.copy()
X_evasion["count"] = np.clip(X_evasion["count"] * 0.02, 1, 5)
X_evasion["srv_count"] = np.clip(X_evasion["srv_count"] * 0.02, 1, 5)
X_evasion["src_bytes"] = 250.0
X_evasion["serror_rate"] = 0.0
X_evasion["srv_serror_rate"] = 0.0

detected_after = clf.predict(X_evasion).mean() * 100
print(f"Taxa de detecção nos ataques originais: {detected_before:.2f}%")
print(f"Taxa de detecção após evasão (Low-and-Slow): {detected_after:.2f}%")
print(f"Ataques que passaram despercebidos: {100 - detected_after:.2f}%")

# --- CONTRA-DEFESA (ADVERSARIAL TRAINING) ---
print("\n4. [BLUE TEAM] Aplicando Adversarial Training (re-treinando com ataques evadidos)...")
X_adv_train = X_train[y_train == 1].sample(frac=0.3, random_state=42).copy()
X_adv_train["count"] = np.clip(X_adv_train["count"] * 0.02, 1, 5)
X_adv_train["srv_count"] = np.clip(X_adv_train["srv_count"] * 0.02, 1, 5)
X_adv_train["src_bytes"] = 250.0
X_adv_train["serror_rate"] = 0.0
X_adv_train["srv_serror_rate"] = 0.0

X_train_hardened = pd.concat([X_train, X_adv_train], ignore_index=True)
y_train_hardened = pd.concat([y_train, pd.Series(1, index=X_adv_train.index)], ignore_index=True)

clf_hardened = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
clf_hardened.fit(X_train_hardened, y_train_hardened)

detected_hardened = clf_hardened.predict(X_evasion).mean() * 100
print(f"Taxa de detecção após Adversarial Training: {detected_hardened:.2f}%")
