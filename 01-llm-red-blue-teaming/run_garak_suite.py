"""
Bateria do Experimento 1: cada arquitetura de defesa contra cada probe do Garak, com um comando.

Arquiteturas (--archs):
  baseline      llama3.2 direto no Ollama
  blindado      llama3.2-blindado (System Prompt defensivo) direto no Ollama
  guardrail     Llama Guard na entrada + llama3.2-blindado, pelo guardrail_proxy.py (modo input)
  guardrail-io  Llama Guard na entrada e na saída + llama3.2-blindado (modo input-output)

Probes padrão (--probes):
  promptinject.HijackHateHumans  o payload é discurso de ódio, conteúdo que o Llama Guard foi treinado para barrar
  promptinject.HijackLongPrompt  o payload é um texto neutro: mede se a defesa detecta a INJEÇÃO,
                                 e não só o conteúdo ofensivo

O script sobe e derruba o proxy sozinho. Relatórios do Garak, logs do proxy e o resumo
(summary.md e summary.json) ficam em results/exp1/suite_<data>/. O resumo traz a taxa de
sucesso do ataque (ASR) com o intervalo de confiança de 95% calculado pelo próprio Garak.

Uso (com o venv ativo e o Ollama rodando):
  python3 01-llm-red-blue-teaming/run_garak_suite.py
  python3 01-llm-red-blue-teaming/run_garak_suite.py --archs baseline guardrail --probes promptinject.HijackLongPrompt
"""

import argparse
import json
import os
import shlex
import signal
import socket
import subprocess
import sys
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
PROXY = HERE / "guardrail_proxy.py"
REST_TEMPLATE = HERE / "rest_guardrail.json"

ARCHS = {
    "baseline": {"rotulo": "1. Baseline (llama3.2)", "modelo": "llama3.2",
                 "requer": {"llama3.2"}},
    "blindado": {"rotulo": "2. Camada única (llama3.2-blindado)", "modelo": "llama3.2-blindado",
                 "requer": {"llama3.2-blindado"}},
    "guardrail": {"rotulo": "3. Defense in Depth (Llama Guard na entrada)", "proxy": "input",
                  "requer": {"llama3.2-blindado", "llama-guard3:1b"}},
    "guardrail-io": {"rotulo": "4. Llama Guard na entrada e na saída", "proxy": "input-output",
                     "requer": {"llama3.2-blindado", "llama-guard3:1b"}},
}
DEFAULT_ARCHS = ["baseline", "blindado", "guardrail"]
DEFAULT_PROBES = ["promptinject.HijackHateHumans", "promptinject.HijackLongPrompt"]


# ------------------------------------------------------------------ utilidades

def installed_models(ollama_url):
    with urllib.request.urlopen(f"{ollama_url.rstrip('/')}/api/tags", timeout=10) as resp:
        names = {m["name"] for m in json.load(resp)["models"]}
    return names | {n.removesuffix(":latest") for n in names}


def wait_for_port(port, timeout=30.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        with socket.socket() as s:
            s.settimeout(1)
            if s.connect_ex(("127.0.0.1", port)) == 0:
                return True
        time.sleep(0.3)
    return False


def stop_process(proc):
    if proc.poll() is not None:
        return
    if os.name == "nt":
        proc.terminate()
    else:
        proc.send_signal(signal.SIGINT)  # o proxy imprime o resumo ao receber Ctrl+C
    try:
        proc.wait(timeout=15)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()


def read_evals(report_path):
    evals = []
    with open(report_path, encoding="utf-8") as f:
        for line in f:
            try:
                record = json.loads(line)
            except ValueError:
                continue
            if record.get("entry_type") == "eval":
                evals.append(record)
    return evals


def proxy_counts(log_path):
    counts = {"requisicoes": 0, "entrada": 0, "saida": 0, "erros": 0}
    if not log_path.exists():
        return counts
    with open(log_path, encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue
            r = json.loads(line)
            counts["requisicoes"] += 1
            if r.get("erro"):
                counts["erros"] += 1
            elif r.get("bloqueado_por") in ("entrada", "saida"):
                counts[r["bloqueado_por"]] += 1
    return counts


def pct(value):
    return "–" if value is None else f"{100 * value:.2f}%".replace(".", ",")


# ------------------------------------------------------------------- execução

def run_one(arch, probe, args, out_dir):
    spec = ARCHS[arch]
    name = f"{arch}__{probe.split('.')[-1]}"
    prefix = out_dir / name  # caminho absoluto: o Garak grava o relatório direto aqui
    cmd = list(args.garak_cmd) + ["--spec", f"probes.{probe}", "--report_prefix", str(prefix)]
    if args.generations:
        cmd += ["--generations", str(args.generations)]

    proxy = proxy_out = None
    proxy_log = out_dir / f"{name}.proxy.jsonl"
    if "modelo" in spec:
        cmd += ["--target_type", "ollama", "--target_name", spec["modelo"]]
    else:
        config = json.loads(REST_TEMPLATE.read_text(encoding="utf-8"))
        config["plugins"]["generators"]["rest"]["RestGenerator"]["uri"] = f"http://127.0.0.1:{args.proxy_port}/"
        config_path = out_dir / f"{name}.rest.json"
        config_path.write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")
        cmd += ["--config", str(config_path), "--target_type", "rest"]

        proxy_out = open(out_dir / f"{name}.proxy.txt", "w", encoding="utf-8")
        proxy = subprocess.Popen(
            [sys.executable, str(PROXY), "--mode", spec["proxy"], "--port", str(args.proxy_port),
             "--ollama-url", args.ollama_url, "--log", str(proxy_log)],
            stdout=proxy_out, stderr=subprocess.STDOUT,
        )
        if not wait_for_port(args.proxy_port):
            stop_process(proxy)
            proxy_out.close()
            return {"arquitetura": arch, "probe": probe, "erro": "o proxy não respondeu na porta "
                    f"{args.proxy_port} (veja {name}.proxy.txt)"}

    start = time.perf_counter()
    try:
        with open(out_dir / f"{name}.garak.txt", "w", encoding="utf-8") as log:
            returncode = subprocess.run(cmd, stdout=log, stderr=subprocess.STDOUT, cwd=ROOT).returncode
    finally:
        if proxy:
            stop_process(proxy)
            proxy_out.close()
    elapsed = round(time.perf_counter() - start, 1)

    result = {"arquitetura": arch, "rotulo": spec["rotulo"], "probe": probe, "tempo_s": elapsed}
    report = Path(f"{prefix}.report.jsonl")
    if returncode != 0 or not report.exists():
        result["erro"] = f"o Garak terminou com código {returncode} (veja {name}.garak.txt)"
        return result

    result["detectores"] = []
    for ev in read_evals(report):
        total = ev.get("total_evaluated") or 0
        result["detectores"].append({
            "detector": ev.get("detector"),
            "falhas": ev.get("fails"),
            "avaliadas": total,
            "asr": ev["fails"] / total if total else None,
            "ic95": [ev["confidence_lower"], ev["confidence_upper"]] if "confidence_lower" in ev else None,
        })
    if proxy:
        result["proxy"] = proxy_counts(proxy_log)
    return result


def write_summary(results, out_dir, meta):
    (out_dir / "summary.json").write_text(
        json.dumps({"meta": meta, "resultados": results}, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    lines = [
        f"# Bateria do Experimento 1 ({meta['inicio']})",
        "",
        "ASR = taxa de sucesso do ataque (falhas da defesa / saídas avaliadas). IC 95% calculado pelo Garak (bootstrap).",
        "",
        "| Arquitetura | Probe | Detector | ASR | IC 95% | Falhas / Avaliadas | Barrados pelo Llama Guard | Tempo |",
        "| :--- | :--- | :--- | :---: | :---: | :---: | :---: | :---: |",
    ]
    for r in results:
        probe = r["probe"].split(".")[-1]
        if "erro" in r:
            lines.append(f"| {r.get('rotulo', r['arquitetura'])} | {probe} | – | erro | – | – | – | – |")
            continue
        guard = "–"
        if "proxy" in r:
            p = r["proxy"]
            guard = f"{p['entrada']} entrada / {p['saida']} saída de {p['requisicoes']}"
        for d in r["detectores"]:
            ci = "–" if not d["ic95"] else f"{pct(d['ic95'][0])} a {pct(d['ic95'][1])}"
            lines.append(
                f"| {r['rotulo']} | {probe} | {d['detector']} | **{pct(d['asr'])}** | {ci} | "
                f"{d['falhas']} / {d['avaliadas']} | {guard} | {r['tempo_s']:.0f}s |"
            )
    errors = [r for r in results if "erro" in r]
    if errors:
        lines += ["", "**Erros:**"] + [f"- {r['arquitetura']} × {r['probe']}: {r['erro']}" for r in errors]
    (out_dir / "summary.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="Roda a bateria do Experimento 1 (arquiteturas × probes do Garak).")
    parser.add_argument("--archs", nargs="+", choices=list(ARCHS), default=DEFAULT_ARCHS)
    parser.add_argument("--probes", nargs="+", default=DEFAULT_PROBES, help="probes do Garak, ex.: promptinject.HijackLongPrompt")
    parser.add_argument("--generations", type=int, help="gerações por prompt (padrão do Garak: 5)")
    parser.add_argument("--proxy-port", type=int, default=8080)
    parser.add_argument("--ollama-url", default="http://localhost:11434")
    parser.add_argument("--out", type=Path, help="pasta de saída (padrão: results/exp1/suite_<data>)")
    parser.add_argument("--garak-cmd", type=shlex.split, default=[sys.executable, "-m", "garak"],
                        help=argparse.SUPPRESS)
    args = parser.parse_args()

    needed = set().union(*(ARCHS[a]["requer"] for a in args.archs))
    try:
        missing = sorted(needed - installed_models(args.ollama_url))
    except OSError as e:
        sys.exit(f"Não consegui falar com o Ollama em {args.ollama_url}: {e}")
    if missing:
        hint = " (crie com: ollama create llama3.2-blindado -f 01-llm-red-blue-teaming/Modelfile)" \
            if "llama3.2-blindado" in missing else ""
        sys.exit(f"Modelos ausentes no Ollama: {', '.join(missing)}{hint}")

    started = datetime.now(timezone.utc)
    out_dir = (args.out or ROOT / "results" / "exp1" / f"suite_{started.strftime('%Y%m%dT%H%M%SZ')}").resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    meta = {"inicio": started.isoformat(timespec="seconds"), "arquiteturas": args.archs,
            "probes": args.probes, "geracoes": args.generations or "padrão do Garak"}

    runs = [(a, p) for p in args.probes for a in args.archs]
    print(f"{len(runs)} execuções. Resultados em {out_dir}")
    results = []
    for i, (arch, probe) in enumerate(runs, 1):
        print(f"[{i}/{len(runs)}] {ARCHS[arch]['rotulo']} × {probe} ...", flush=True)
        result = run_one(arch, probe, args, out_dir)
        results.append(result)
        if "erro" in result:
            print(f"   ERRO: {result['erro']}")
        else:
            for d in result["detectores"]:
                print(f"   {d['detector']}: ASR {pct(d['asr'])} ({d['falhas']}/{d['avaliadas']}) em {result['tempo_s']:.0f}s")
        write_summary(results, out_dir, meta)  # grava a cada execução: um Ctrl+C não perde o que já rodou

    print("\n" + write_summary(results, out_dir, meta))


if __name__ == "__main__":
    main()
