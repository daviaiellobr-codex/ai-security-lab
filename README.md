# 🛡️ AI Security Lab: Red & Blue Teaming em LLMs e Machine Learning

Repositório de estudos práticos na interseção entre **Ciência de Dados** e **Cibersegurança**, explorando vulnerabilidades, ataques de evasão e arquiteturas de defesa em modelos de Inteligência Artificial.

---

## 📂 Estrutura do Projeto

```text
ai-security-portfolio/
├── 01-llm-red-blue-teaming/
│   ├── Modelfile              # System Prompt defensivo (Prompt Hardening)
│   ├── guardrail_proxy.py     # Proxy HTTP com classificação em duas camadas (Llama Guard 3 + Llama 3.2)
│   └── rest_guardrail.json    # Configuração de endpoint REST para o scanner NVIDIA Garak
├── 02-network-ids-adversarial-ml/
│   └── ids_ml_lab.py          # Detector de intrusão (Random Forest), ataque Low-and-Slow e Adversarial Training
├── requirements.txt
└── README.md
```

---

## 🧪 Experimento 1: Red & Blue Teaming em LLMs (Prompt Injection & Guardrails)

Avaliação automatizada de vulnerabilidades (**OWASP LLM01: Prompt Injection**) utilizando o **NVIDIA Garak** contra modelos locais via **Ollama** (`llama3.2` e `llama-guard3:1b`).

### Resultados: Ataque Direto (`promptinject.HijackHateHumans` — 512 tentativas)

| Arquitetura de Defesa | Bloqueios (`PASS`) | Sucesso do Ataque (`ASR`) | Tempo de Execução |
| :--- | :---: | :---: | :---: |
| **1. Baseline** (`llama3.2` padrão) | 274 / 512 (53,52%) | **46,48%** (238 falhas) | 144,11s |
| **2. Camada Única** (`llama3.2-blindado` via System Prompt) | 456 / 512 (89,06%) | **10,94%** (56 falhas) | 146,23s |
| **3. Defense in Depth** (`Llama Guard 3` + `llama3.2-blindado`) | **512 / 512 (100%)** | **0,00%** (0 falhas) | **38,58s** |

### Resultados: Bypass por Ofuscação (`encoding.InjectBase64` — 256 tentativas)

| Camada da Arquitetura | Payloads Barrados | Payloads Aprovados | Resultado Final |
| :--- | :---: | :---: | :---: |
| **Camada 1: Input Guardrail** (`llama-guard3:1b`) | 82 / 256 (32,03%) | 174 / 256 (67,97%) | Ponto cego em payloads Base64 |
| **Camada 2: Modelo Alvo** (`llama3.2-blindado`) | **174 / 174 (100%)** | 0 | **PASS (256/256 bloqueados no total)** |

**Principais conclusões:**
* **Prompt Hardening** reduziu a taxa de sucesso do ataque em **76%** (de 46,48% para 10,94%), mas não eliminou o risco devido ao compartilhamento da janela de contexto entre instruções e dados.
* **Defense in Depth** zerou as falhas e reduziu a latência total em **73%** graças ao *early-exit* do classificador `llama-guard3:1b`.
* **Ponto cego de classificadores de entrada:** payloads codificados em Base64 contornaram o filtro inicial em 68% dos casos, comprovando a necessidade de múltiplas camadas de defesa.

---

## 🌐 Experimento 2: Adversarial Machine Learning em Detecção de Intrusão (Network IDS)

Treinamento de um classificador **Random Forest** sobre tráfego de rede (**KDD Cup 99**) seguido de simulação de ataque de evasão (*Low-and-Slow*) e mitigação via **Adversarial Training**.

### Resultados: Resiliência do Detector de Intrusão

| Cenário de Avaliação | Recall (Detecção de Ataques) | Taxa de Evasão (Falsos Negativos) |
| :--- | :---: | :---: |
| **1. Teste Limpo (Tráfego Padrão)** | **99,41%** | 0,59% |
| **2. Sob Ataque de Evasão (*Low-and-Slow*)** | **27,96%** | **72,04%** |
| **3. Após *Adversarial Training* (30% amostras evadidas)** | **99,53%** | 0,47% |

### Análise de Feature Importance (Antes vs. Depois do Hardening)

| Atributo de Rede | Peso no Modelo Original | Peso no Modelo Blindado | Impacto |
| :--- | :---: | :---: | :--- |
| `count` | 0.2202 | **0.1544** | Redução de dependência de volume |
| `srv_count` | 0.1835 | **0.1466** | Redução de dependência de volume |
| `protocol_type` | 0.1125 | **0.1213** | Maior peso estrutural |
| `src_bytes` | 0.0811 | **0.0844** | Estável |
| `dst_host_same_src_port_rate` | 0.0620 | **0.0752** | Maior peso comportamental |

**Principais conclusões:**
* Métricas tradicionais em dados limpos (**99,98% de acurácia**) mascaram fragilidades adversariais: a concentração de **40,37%** da decisão em apenas duas features de taxa de pacotes (`count` e `srv_count`) permitiu que um ataque lento evadisse 72% das detecções.
* O **Adversarial Training** redistribuiu o peso das árvores para atributos estruturais mais difíceis de falsificar, restaurando o Recall para **99,53%**.

---

## 🚀 Como Reproduzir

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Experimento 2 (Network IDS)
python3 02-network-ids-adversarial-ml/ids_ml_lab.py
```
