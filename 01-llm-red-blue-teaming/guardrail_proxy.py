from http.server import BaseHTTPRequestHandler, HTTPServer
import json, urllib.request

OLLAMA_URL = "http://localhost:11434/api/generate"

def call_ollama(model, prompt):
    req = urllib.request.Request(
        OLLAMA_URL,
        data=json.dumps({"model": model, "prompt": prompt, "stream": False}).encode(),
        headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read().decode())["response"].strip()

class GuardrailHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(length).decode())
        user_prompt = body.get("prompt", "")

        # Camada 1: Llama Guard avalia o prompt antes de chegar ao modelo alvo
        guard_verdict = call_ollama("llama-guard3:1b", user_prompt)
        if guard_verdict.lower().startswith("unsafe"):
            reply = f"[BLOQUEADO PELO GUARDRAIL]: Conteúdo violou política ({guard_verdict})."
        else:
            # Camada 2: Se passar, vai para o modelo blindado
            reply = call_ollama("llama3.2-blindado", user_prompt)

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps({"response": reply}).encode())

    def log_message(self, format, *args):
        pass

print("Proxy Guardrail rodando na porta 8080...")
HTTPServer(("127.0.0.1", 8080), GuardrailHandler).serve_forever()
