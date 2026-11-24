# Resultados

Evidências dos experimentos, versionadas junto com o código.

| Pasta | Conteúdo | Gerado por |
| :--- | :--- | :--- |
| `exp1/` | Relatórios do Garak (`.report.jsonl` e `.report.html`, copiados de `~/.local/share/garak/garak_runs/`), logs de decisão do proxy (`proxy_<modo>_<data>.jsonl`) e `base64_decode_check.json` | `garak`, `guardrail_proxy.py`, `base64_decode_check.py` |
| `exp2/` | Métricas do IDS (`ids_results.json` e `ids_results_dedup.json`) | `ids_ml_lab.py` |

Os logs do Experimento 1 contêm os payloads de ataque e as respostas dos modelos.
