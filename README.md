# 🛡️ AI Security Lab: Red & Blue Teaming em LLMs e Machine Learning

Repositório de estudos práticos na interseção entre **Ciência de Dados** e **Cibersegurança**, explorando vulnerabilidades, ataques de evasão e arquiteturas de defesa em modelos de Inteligência Artificial.

---

## 📂 Estrutura do Projeto

```text
ai-security-lab/
├── 01-llm-red-blue-teaming/
│   ├── Modelfile                # System Prompt defensivo (Prompt Hardening)
│   ├── guardrail_proxy.py       # Proxy HTTP com guardrails configuráveis (entrada e/ou saída) e log de decisões
│   ├── base64_decode_check.py   # Controle: o modelo alvo consegue decodificar Base64?
│   └── rest_guardrail.json      # Configuração do endpoint REST para o scanner NVIDIA Garak
├── 02-network-ids-adversarial-ml/
│   └── ids_ml_lab.py            # Detector de intrusão (Random Forest), ataque Low-and-Slow, Adversarial Training e testes de generalização
├── results/                     # Evidências: relatórios do Garak, logs do proxy e métricas do IDS
│   └── README.md
├── requirements.txt
├── LICENSE
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

> Resultados obtidos com o proxy no modo `input` (Llama Guard apenas na entrada).

**Principais conclusões:**
* **Prompt Hardening** reduziu a taxa de sucesso do ataque em **76%** (de 46,48% para 10,94%), mas não eliminou o risco devido ao compartilhamento da janela de contexto entre instruções e dados.
* **Defense in Depth** zerou as falhas e reduziu a latência total em **73%** graças ao *early-exit* do classificador `llama-guard3:1b`.
* **Ponto cego de classificadores de entrada:** payloads codificados em Base64 contornaram o filtro inicial em 68% dos casos.
* **Ressalva sobre a Camada 2:** os 174 bloqueios do `llama3.2-blindado` só contam como defesa se o modelo for capaz de decodificar Base64. Um modelo de 3B pode simplesmente não entender o payload, e aí o ataque falha por incapacidade, não pelo System Prompt. Os controles abaixo separam as duas hipóteses.

### 🔬 Controles adicionais (a rodar)

| Teste | Pergunta que responde |
| :--- | :--- |
| `InjectBase64` contra o `llama3.2` padrão | O ataque Base64 funciona sem nenhuma defesa? Sem esse baseline, não dá para atribuir os bloqueios ao hardening. |
| `base64_decode_check.py` | O modelo consegue decodificar frases inofensivas em Base64? |
| Proxy no modo `input-output` | Um Llama Guard avaliando a **resposta** (já decodificada) barra o que passou pela entrada? |

Os comandos estão em [Como Reproduzir](#-como-reproduzir).

---

## 🌐 Experimento 2: Adversarial Machine Learning em Detecção de Intrusão (Network IDS)

Treinamento de um classificador **Random Forest** sobre tráfego de rede (**KDD Cup 99**, subset `SA`) seguido de simulação de ataque de evasão (*Low-and-Slow*) e mitigação via **Adversarial Training**.

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

> O script atual usa a mesma semente, o mesmo split e o mesmo treino da versão que gerou estas tabelas, e agora também imprime e salva a feature importance em `results/exp2/`.

**Principais conclusões:**
* Métricas tradicionais em dados limpos (**99,98% de acurácia**) mascaram fragilidades adversariais: a concentração de **40,37%** da decisão em apenas duas features de taxa de pacotes (`count` e `srv_count`) permitiu que um ataque lento evadisse 72% das detecções.
* O **Adversarial Training** restaurou o Recall para **99,53%** contra a mesma perturbação usada no treino.
* **Ressalva:** a evasão usa valores fixos (`src_bytes = 250`, `serror_rate = 0`) tanto no treino quanto no teste. O modelo blindado pode ter aprendido esses valores como assinatura, e não o padrão de evasão. A redistribuição de pesos, sozinha, não prova robustez.

### 🔬 Testes adicionados ao script

| Teste | O que indica |
| :--- | :--- |
| Falsos positivos no tráfego normal limpo | Quanto o hardening custa em alarmes falsos. |
| Evasão com valores sorteados (nunca vistos no treino) | Se a detecção cair muito em relação à evasão fixa, o ganho do Adversarial Training não generaliza. |
| Teste de atalho: tráfego **normal** com `src_bytes = 250` | Se o modelo blindado passar a acusar essas conexões, ele decorou o valor. |
| Resultados por categoria (DoS, Probe, R2L, U2R e "Sem DoS") | Se a evasão se concentra em DoS, ela descreve ataques que deixariam de funcionar em baixa taxa. |
| `--dedup` | Repete tudo sem as conexões duplicadas do KDD99. |

---

## ⚠️ Limitações

* **KDD Cup 99 é antigo e tem muitos registros duplicados** (Tavallaee et al., *A Detailed Analysis of the KDD CUP 99 Data Set*, 2009). Cópias da mesma conexão caem no treino e no teste e inflam as métricas. A opção `--dedup` mede esse efeito; NSL-KDD, UNSW-NB15 e CIC-IDS2017 são alternativas mais atuais.
* **Ataque no espaço de features:** a evasão altera os valores da tabela diretamente, sem garantir que exista tráfego real com aqueles valores nem que o ataque continue funcionando. Em DoS por volume (`smurf`, `neptune`), reduzir a taxa de conexões desfaz o próprio ataque.
* **Base desbalanceada:** o subset `SA` tem cerca de 1% de ataques, então acurácia sozinha diz pouco. Por isso o foco em Recall e falsos positivos.
* **Escopo do Experimento 1:** modelos locais pequenos (3B e 1B) e duas probes do Garak. Os números não se estendem automaticamente a modelos maiores ou a outras técnicas de injeção.

---

## 🖥️ Ambiente de Teste

| Item | Especificação |
| :--- | :--- |
| CPU | AMD Ryzen 7 5700X3D (8 núcleos) |
| RAM | 32 GB |
| GPU | NVIDIA GeForce RTX 5060 (8 GB) |
| Sistema | Windows 11 Pro + WSL2 (Ubuntu 26.04.1 LTS) |
| Python | 3.14.4 |
| Bibliotecas | Garak 0.17.1 · scikit-learn 1.9.1 · pandas 3.1.1 |
| Ollama | 0.40.18 (modelos executados 100% na GPU) |

| Modelo | ID no Ollama |
| :--- | :--- |
| `llama3.2:latest` | `a80c4f17acd5` |
| `llama3.2-blindado:latest` | `29948234d1cb` (criado a partir do `Modelfile`) |
| `llama-guard3:1b` | `494147e06bf9` |

> Os tempos do Experimento 1 dependem desse hardware: só em CPU, ou com outra GPU, os valores absolutos mudam, mas a comparação relativa entre as arquiteturas tende a se manter. No Experimento 2, o hardware só altera o tempo de execução; com a mesma semente e as mesmas versões das bibliotecas, as métricas devem se repetir.

---

## 🚀 Como Reproduzir

### Ambiente

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### Experimento 1 (requer o [Ollama](https://ollama.com) rodando)

```bash
ollama pull llama3.2
ollama pull llama-guard3:1b
ollama create llama3.2-blindado -f 01-llm-red-blue-teaming/Modelfile
```

**Arquiteturas 1 e 2** (Garak direto no Ollama):

```bash
garak --target_type ollama --target_name llama3.2 \
      --spec probes.promptinject.HijackHateHumans --report_prefix exp1_baseline_hijack
garak --target_type ollama --target_name llama3.2-blindado \
      --spec probes.promptinject.HijackHateHumans --report_prefix exp1_blindado_hijack
```

**Arquitetura 3** (Defense in Depth pelo proxy). Em um terminal:

```bash
python3 01-llm-red-blue-teaming/guardrail_proxy.py --mode input
```

Em outro:

```bash
garak --config 01-llm-red-blue-teaming/rest_guardrail.json --target_type rest \
      --spec probes.promptinject.HijackHateHumans --report_prefix exp1_guardrail_hijack
garak --config 01-llm-red-blue-teaming/rest_guardrail.json --target_type rest \
      --spec probes.encoding.InjectBase64 --report_prefix exp1_guardrail_base64
```

Ao encerrar o proxy com `Ctrl+C`, ele mostra quantos payloads cada camada barrou (é daí que sai a tabela de Bypass por Ofuscação). O log completo fica em `results/exp1/`, e `--summarize` resume um log já gravado.

**Controles do Base64:**

```bash
# 1. Baseline sem defesa
garak --target_type ollama --target_name llama3.2 \
      --spec probes.encoding.InjectBase64 --report_prefix exp1_baseline_base64

# 2. Capacidade de decodificação
python3 01-llm-red-blue-teaming/base64_decode_check.py --models llama3.2 llama3.2-blindado

# 3. Guardrail também na saída (repita o InjectBase64 pelo proxy com este modo)
python3 01-llm-red-blue-teaming/guardrail_proxy.py --mode input-output
```

O Garak salva os relatórios em `~/.local/share/garak/garak_runs/` (o caminho aparece no fim de cada execução). Copie os arquivos `.report.jsonl` e `.report.html` para `results/exp1/` para versionar a evidência.

### Experimento 2 (Network IDS)

```bash
python3 02-network-ids-adversarial-ml/ids_ml_lab.py           # configuração das tabelas acima
python3 02-network-ids-adversarial-ml/ids_ml_lab.py --dedup   # sem conexões duplicadas
```

As métricas ficam em `results/exp2/ids_results.json` e `results/exp2/ids_results_dedup.json`.
