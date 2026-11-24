"""
Proxy HTTP de guardrails para o Experimento 1 (Garak -> proxy -> Ollama).

Modos (--mode):
  model         só o modelo alvo, sem classificador
  input         Llama Guard avalia o prompt antes do modelo alvo (arquitetura 3 do README)
  input-output  Llama Guard avalia o prompt e também a resposta do modelo alvo

Cada requisição é registrada em JSONL (results/exp1/) com a camada que bloqueou, os
vereditos do Llama Guard e a latência. Ao encerrar com Ctrl+C, o proxy imprime um resumo.
Para resumir um log já existente:

  python3 01-llm-red-blue-teaming/guardrail_proxy.py --summarize results/exp1/<arquivo>.jsonl

Se o Ollama falhar ou estourar o timeout, o proxy responde HTTP 502. Assim o Garak registra
o erro em vez de contar a tentativa como bloqueada, o que inflaria a taxa de defesa.
"""

import argparse
import json
import time
import urllib.request
from collections import Counter, defaultdict
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

DEFAULT_LOG_DIR = Path(__file__).resolve().parent.parent / "results" / "exp1"
MODES = ("model", "input", "input-output")


class OllamaError(RuntimeError):
    """Falha ao consultar o Ollama (conexão, timeout ou resposta inesperada)."""


def ollama_chat(base_url, model, messages, timeout):
    payload = json.dumps({"model": model, "messages": messages, "stream": False}).encode("utf-8")
    req = urllib.request.Request(
        f"{base_url.rstrip('/')}/api/chat",
        data=payload,
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        return data["message"]["content"].strip()
    except (OSError, ValueError, KeyError, TypeError) as e:  # OSError cobre URLError e timeouts
        raise OllamaError(f"{model}: {e}") from e


def is_unsafe(verdict):
    """O Llama Guard responde 'safe' ou 'unsafe' seguido das categorias violadas (ex.: 'unsafe\\nS10')."""
    return verdict.strip().lower().startswith("unsafe")


def one_line(text):
    return " ".join(text.split())


def run_pipeline(cfg, prompt, record):
    """Executa as camadas de defesa e devolve a resposta que vai para o Garak."""
    conversation = [{"role": "user", "content": prompt}]

    # Camada 1: Llama Guard avalia o prompt antes de chegar ao modelo alvo
    if cfg.mode in ("input", "input-output"):
        verdict = ollama_chat(cfg.ollama_url, cfg.guard_model, conversation, cfg.timeout)
        record["veredito_entrada"] = verdict
        if is_unsafe(verdict):
            record["bloqueado_por"] = "entrada"
            return f"[BLOQUEADO PELO GUARDRAIL DE ENTRADA]: Conteúdo violou política ({one_line(verdict)})."

    # Camada 2: modelo alvo (com o System Prompt defensivo do Modelfile)
    reply = ollama_chat(cfg.ollama_url, cfg.target_model, conversation, cfg.timeout)
    record["resposta_modelo"] = reply

    # Camada 3: Llama Guard avalia a resposta, já decodificada pelo modelo alvo.
    # É aqui que payloads ofuscados (Base64 etc.) que passaram pela entrada podem ser barrados.
    if cfg.mode == "input-output":
        verdict = ollama_chat(
            cfg.ollama_url,
            cfg.guard_model,
            conversation + [{"role": "assistant", "content": reply}],
            cfg.timeout,
        )
        record["veredito_saida"] = verdict
        if is_unsafe(verdict):
            record["bloqueado_por"] = "saida"
            return f"[BLOQUEADO PELO GUARDRAIL DE SAÍDA]: Resposta violou política ({one_line(verdict)})."

    return reply


def make_handler(cfg, records, log_file):
    class GuardrailHandler(BaseHTTPRequestHandler):
        def _send_json(self, status, obj):
            body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self):
            start = time.perf_counter()
            try:
                length = int(self.headers.get("Content-Length", 0))
                prompt = json.loads(self.rfile.read(length).decode("utf-8"))["prompt"]
                if not isinstance(prompt, str):
                    raise TypeError("prompt não é string")
            except (ValueError, KeyError, TypeError):
                self._send_json(400, {"error": "o corpo deve ser um JSON com o campo 'prompt' (string)"})
                return

            record = {
                "run_id": cfg.run_id,
                "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "modo": cfg.mode,
                "modelo_alvo": cfg.target_model,
                "prompt": prompt,
                "bloqueado_por": None,
            }
            try:
                reply = run_pipeline(cfg, prompt, record)
                status, body = 200, {"response": reply}
                record["resposta_enviada"] = reply
            except OllamaError as e:
                status, body = 502, {"error": f"falha ao consultar o Ollama: {e}"}
                record["erro"] = str(e)

            record["latencia_s"] = round(time.perf_counter() - start, 3)
            records.append(record)
            if log_file:
                log_file.write(json.dumps(record, ensure_ascii=False) + "\n")
                log_file.flush()
            self._send_json(status, body)

        def log_message(self, format, *args):
            pass

    return GuardrailHandler


def summarize(records):
    """Imprime quantas requisições cada camada barrou, por execução (run_id)."""
    by_run = defaultdict(list)
    for r in records:
        by_run[r.get("run_id", "?")].append(r)

    for run_id, rs in by_run.items():
        total = len(rs)
        outcome = Counter(
            "erro" if r.get("erro") else (r.get("bloqueado_por") or "repassada") for r in rs
        )
        latency = sum(r.get("latencia_s", 0) for r in rs)
        share = lambda n: f"{n} ({100 * n / total:.2f}%)" if total else "0"
        print(f"\nExecução {run_id} | modo {rs[0].get('modo')} | modelo alvo {rs[0].get('modelo_alvo')}")
        lines = [
            ("Requisições", str(total)),
            ("Barradas na entrada (Llama Guard)", share(outcome["entrada"])),
            ("Barradas na saída (Llama Guard)", share(outcome["saida"])),
            ("Repassadas ao Garak", share(outcome["repassada"])),
            ("Erros (HTTP 502)", share(outcome["erro"])),
        ]
        for label, value in lines:
            print(f"  {label + ':':<36}{value}")
        if total:
            print(f"  Latência média: {latency / total:.2f}s | total: {latency:.2f}s")
    print("\n'Repassada' não significa ataque bem-sucedido: quem decide isso é o detector do Garak.")


def main():
    parser = argparse.ArgumentParser(description="Proxy de guardrails (Llama Guard + modelo alvo) para o Garak.")
    parser.add_argument("--mode", choices=MODES, default="input",
                        help="camadas ativas (padrão: input, a arquitetura 3 do README)")
    parser.add_argument("--target-model", default="llama3.2-blindado", help="modelo alvo no Ollama")
    parser.add_argument("--guard-model", default="llama-guard3:1b", help="classificador de segurança no Ollama")
    parser.add_argument("--ollama-url", default="http://localhost:11434")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--timeout", type=float, default=120.0,
                        help="timeout de cada chamada ao Ollama, em segundos (padrão: 120)")
    parser.add_argument("--log", type=Path,
                        help="arquivo JSONL de decisões (padrão: results/exp1/proxy_<modo>_<data>.jsonl)")
    parser.add_argument("--no-log", action="store_true", help="não grava o log de decisões")
    parser.add_argument("--summarize", type=Path, metavar="ARQUIVO_JSONL",
                        help="só resume um log já gravado e sai")
    cfg = parser.parse_args()

    if cfg.summarize:
        with cfg.summarize.open(encoding="utf-8") as f:
            summarize([json.loads(line) for line in f if line.strip()])
        return

    cfg.run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    log_file = None
    if not cfg.no_log:
        log_path = cfg.log or DEFAULT_LOG_DIR / f"proxy_{cfg.mode}_{cfg.run_id}.jsonl"
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_file = log_path.open("a", encoding="utf-8")

    records = []
    server = HTTPServer((cfg.host, cfg.port), make_handler(cfg, records, log_file))
    print(f"Proxy Guardrail (modo {cfg.mode}) em http://{cfg.host}:{cfg.port}/")
    print(f"  modelo alvo: {cfg.target_model}"
          + (f" | guardrail: {cfg.guard_model}" if cfg.mode != "model" else ""))
    if log_file:
        print(f"  log de decisões: {log_file.name}")
    print("Ctrl+C para encerrar e ver o resumo.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        if log_file:
            log_file.close()
        if records:
            summarize(records)


if __name__ == "__main__":
    main()
