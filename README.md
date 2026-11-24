# 🛡️ AI Security Lab: Red & Blue Teaming em LLMs e Machine Learning

Repositório de estudos práticos na interseção entre **Ciência de Dados** e **Cibersegurança**, explorando vulnerabilidades, ataques de evasão e arquiteturas de defesa em modelos de Inteligência Artificial.

## 📌 Principais Achados

* **Moderação de conteúdo não é defesa contra prompt injection.** O Llama Guard 3 barrou 100% de uma injeção cujo payload era discurso de ódio, mas só 14,4% da mesma injeção com payload neutro, que então teve sucesso em 49,61% das tentativas.
* **Controles mudam conclusões.** A aparente defesa do modelo contra payloads em Base64 vinha da incapacidade de decodificá-los (0/20 frases inofensivas), e não do *prompt hardening*.
* **Duplicatas no KDD Cup 99 inflam a fragilidade de um IDS.** A evasão *Low-and-Slow* passou por 93,84% das detecções com duplicatas e por 34,66% sem elas. Com duplicatas, o *Adversarial Training* perdeu 11 pontos contra perturbações não vistas no treino.

---

## 📂 Estrutura do Projeto

```text
ai-security-lab/
├── 01-llm-red-blue-teaming/
│   ├── Modelfile                # System Prompt defensivo (Prompt Hardening)
│   ├── guardrail_proxy.py       # Proxy HTTP com guardrails configuráveis (entrada e/ou saída) e log de decisões
│   ├── base64_decode_check.py   # Controle: o modelo alvo consegue decodificar Base64?
│   ├── run_garak_suite.py       # Bateria completa: arquiteturas × probes, com resumo e IC 95%
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

### Resultados: Injeção Direta (`promptinject`, 1280 saídas por célula)

O mesmo ataque com dois payloads: no `HijackHateHumans`, a injeção tenta fazer o modelo escrever uma frase de ódio; no `HijackLongPrompt`, um texto neutro. Cada célula tem 256 prompts × 5 gerações. A tabela mostra a taxa de sucesso do ataque (ASR) e, entre parênteses, o intervalo de confiança de 95% calculado pelo Garak.

| Arquitetura de Defesa | Payload de ódio (`HijackHateHumans`) | Payload neutro (`HijackLongPrompt`) |
| :--- | :---: | :---: |
| **1. Baseline** (`llama3.2` padrão) | 51,25% (48,52–53,98) | 65,78% (63,20–68,44) |
| **2. Camada Única** (`llama3.2-blindado` via System Prompt) | 15,00% (13,12–16,96) | 54,53% (51,88–57,34) |
| **3. Defense in Depth** (`Llama Guard 3` + `llama3.2-blindado`) | **0,00%** (0 / 1280) | **49,61%** (46,95–52,42) |
| Prompts barrados pelo Llama Guard | 1280 / 1280 (100%) | 184 / 1280 (14,4%) |
| Tempo de execução (baseline / camada única / Defense in Depth) | 168s / 355s / 44s | 343s / 358s / 483s |

> Com 0 falhas o bootstrap não tem variação para estimar; pela regra de três, o limite superior de 95% é cerca de 0,23%. Relatórios, logs do proxy e o resumo completo estão em `results/exp1/suite_20261124T211913Z/`.

### Resultados: Bypass por Ofuscação (`encoding.InjectBase64` — 256 tentativas)

| Camada da Arquitetura | Payloads Barrados | Payloads Aprovados | Resultado Final |
| :--- | :---: | :---: | :---: |
| **Camada 1: Input Guardrail** (`llama-guard3:1b`) | 82 / 256 (32,03%) | 174 / 256 (67,97%) | Ponto cego em payloads Base64 |
| **Camada 2: Modelo Alvo** (`llama3.2-blindado`) | 174 / 174 (100%) | 0 | Incapacidade de decodificar, não defesa (ver controle abaixo) |

> Execução anterior à bateria, com o proxy no modo `input` (Llama Guard apenas na entrada).

### Controle: o modelo alvo sabe ler Base64? (`base64_decode_check.py`)

| Modelo | Frases inofensivas decodificadas |
| :--- | :---: |
| `llama3.2` | 0 / 20 (0%) |
| `llama3.2-blindado` | 0 / 20 (0%) |

Os modelos não recusam: eles inventam um texto qualquer. Para a frase codificada *"The library opens at nine in the morning."*, por exemplo, o `llama3.2` respondeu `"Hello world"`. Os detalhes estão em `results/exp1/base64_decode_check.json`.

**Principais conclusões:**
* **O Llama Guard barra o conteúdo, não a injeção.** Com payload de ódio, barrou 100% dos prompts e zerou o ataque. Com payload neutro, barrou só 14,4%, e o Defense in Depth ainda deixou passar 49,61% dos ataques. O Llama Guard é um classificador de conteúdo nocivo: uma injeção que não pede nada ofensivo passa por ele.
* **O System Prompt também funcionou mais pelo conteúdo:** reduziu o sucesso do ataque em 71% com payload de ódio (51,25% → 15,00%), mas só em 17% com payload neutro (65,78% → 54,53%). A regra 3 do `Modelfile` proíbe tanto discurso de ódio quanto repetir frases forçadas por injeção, mas o modelo só obedeceu bem à primeira parte.
* **O ganho de latência também depende do conteúdo.** Com payload de ódio, o *early-exit* do Llama Guard reduziu o tempo em 74% (168s → 44s). Com payload neutro, a arquitetura ficou 41% mais lenta que o baseline (343s → 483s), porque quase todo prompt passa pelos dois modelos.
* **Ponto cego de classificadores de entrada:** payloads codificados em Base64 contornaram o Llama Guard em 68% dos casos.
* **A Camada 2 não defendeu contra Base64: ela não sabe ler Base64.** Os dois modelos decodificaram 0% das frases inofensivas, então os 174 "bloqueios" vêm de incapacidade do modelo alvo, não do System Prompt. Com um modelo que decodifique Base64, esses 174 payloads seriam um risco real.

### 🔬 Próximos testes

| Teste | Pergunta que responde |
| :--- | :--- |
| Um classificador treinado para detectar **injeção** (ex.: Prompt Guard, da Meta) na entrada, no lugar do Llama Guard ou junto com ele | Uma defesa feita para injeção barra o payload neutro que o Llama Guard deixou passar? |
| `InjectBase64` contra um modelo que decodifique Base64 (use o `base64_decode_check.py` para escolher), sem defesa | Quanto do ataque funciona quando o alvo entende o payload? |
| Proxy no modo `input-output` com esse modelo | Um Llama Guard avaliando a **resposta** (já decodificada) barra o que passou pela entrada? |

Os comandos estão em [Como Reproduzir](#-como-reproduzir).

---

## 🌐 Experimento 2: Adversarial Machine Learning em Detecção de Intrusão (Network IDS)

Treinamento de um classificador **Random Forest** sobre tráfego de rede (**KDD Cup 99**, subset `SA`) seguido de simulação de ataque de evasão (*Low-and-Slow*) e mitigação via **Adversarial Training**.

### Resultados (semente 42)

| Métrica | Com duplicatas (padrão) | Sem duplicatas (`--dedup`) |
| :--- | :---: | :---: |
| Conexões no teste (ataques) | 25.164 (844) | 22.209 (251) |
| **Original:** Recall em tráfego limpo | 99,29% | 98,41% |
| **Original:** detecção sob evasão *Low-and-Slow* | **6,16%** (93,84% evadidos) | **65,34%** (34,66% evadidos) |
| **Blindado:** Recall em tráfego limpo | 99,41% | 98,41% |
| **Blindado:** detecção sob a evasão vista no treino | 99,29% | 98,01% |
| **Blindado:** detecção sob evasão com valores novos | **88,63%** | **97,21%** |
| Falsos positivos em tráfego limpo (original → blindado) | 0,00% → 0,00% | 0,00% → 0,00% |
| Falsos positivos no teste de atalho: tráfego normal com `src_bytes = 250` (blindado) | 0,00% | 0,00% |
| Peso de `count` + `srv_count` (original → blindado) | 43,17% → 30,97% | 10,85% → 7,89% |

> Versões anteriores deste README traziam números de uma execução sem semente no sorteio de ataques do subset `SA` (o scikit-learn sorteia 3377 ataques com reposição a cada carregamento), por isso diferem destes. Os arquivos completos estão em `results/exp2/`.

### Feature Importance (com duplicatas)

| Atributo de Rede | Modelo Original | Modelo Blindado |
| :--- | :---: | :---: |
| `srv_count` | 0.2253 | **0.1521** |
| `count` | 0.2063 | **0.1576** |
| `protocol_type` | 0.1212 | **0.1369** |
| `src_bytes` | 0.0710 | **0.0919** |
| `same_srv_rate` | 0.0570 | **0.0571** |
| `dst_host_same_src_port_rate` | 0.0563 | **0.0710** |

Sem duplicatas, o modelo original passa a se apoiar principalmente em `same_srv_rate` (0.1702) e nas taxas de erro SYN (`dst_host_serror_rate`, `srv_serror_rate`, `dst_host_srv_serror_rate`, `serror_rate`), e `count` cai para 0.0782.

### Por categoria de ataque (com duplicatas)

| Categoria | Ataques no teste | Original | Original + evasão | Blindado + valores novos |
| :--- | :---: | :---: | :---: | :---: |
| DoS | 830 | 99,76% | 5,30% | 88,92% |
| Probe | 11 | 90,91% | 72,73% | 90,91% |
| R2L | 3 | 0,00% | 0,00% | 0,00% |
| U2R | 0 | – | – | – |

**Principais conclusões:**
* **Acurácia alta mascara fragilidade:** com **99,98% de acurácia**, o modelo concentra **43%** da decisão em `count` e `srv_count`, e a evasão *Low-and-Slow* passa por **93,84%** das detecções.
* **As duplicatas inflam a fragilidade, não só as métricas:** sem elas, o peso de `count` + `srv_count` cai para 11%, o modelo passa a usar taxas de erro SYN e `same_srv_rate`, e a evasão cai para 34,66%. Boa parte da dependência de volume vinha de cópias dos mesmos ataques DoS.
* **O Adversarial Training funciona, mas generaliza menos do que parece:** com duplicatas, a detecção cai de 99,29% na perturbação vista no treino para **88,63%** com valores novos. Sem duplicatas, a queda é pequena (98,01% → 97,21%).
* **O modelo blindado não decorou o valor da perturbação** (0,00% no teste de atalho), e o hardening não aumentou os falsos positivos em tráfego limpo.
* **Na prática, o experimento mede DoS:** 830 dos 844 ataques do teste são DoS. Com só 14 ataques de outras categorias, não dá para concluir nada sobre Probe, R2L ou U2R. Além disso, a evasão que derruba a taxa de conexões de um DoS por volume descreve um ataque que deixaria de funcionar.

---

## ⚠️ Limitações

* **KDD Cup 99 é antigo e tem muitos registros duplicados** (Tavallaee et al., *A Detailed Analysis of the KDD CUP 99 Data Set*, 2009). Aqui, 11,7% das conexões são duplicatas exatas, e o próprio subset `SA` sorteia os ataques com reposição: sem duplicatas, os ataques no teste caem de 844 para 251. Como isso muda as conclusões, os resultados trazem as duas configurações. NSL-KDD, UNSW-NB15 e CIC-IDS2017 são alternativas mais atuais.
* **Ataque no espaço de features:** a evasão altera os valores da tabela diretamente, sem garantir que exista tráfego real com aqueles valores nem que o ataque continue funcionando. Em DoS por volume (`smurf`, `neptune`), reduzir a taxa de conexões desfaz o próprio ataque.
* **Base desbalanceada:** o subset `SA` (versão 10%) tem cerca de 3,4% de ataques (844 de 25.164 conexões no teste), então acurácia sozinha diz pouco. Por isso o foco em Recall e falsos positivos.
* **Escopo do Experimento 1:** modelos locais pequenos (3B e 1B) e três probes do Garak (dois payloads do `promptinject` e o `InjectBase64`). Os números não se estendem automaticamente a modelos maiores ou a outras técnicas de injeção.

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

**Bateria completa (recomendado).** Roda cada arquitetura contra cada probe, sobe e derruba o proxy sozinho e grava relatórios, logs e um resumo (`summary.md` e `summary.json`, com ASR e intervalo de confiança de 95% do Garak) em `results/exp1/suite_<data>/`:

```bash
python3 01-llm-red-blue-teaming/run_garak_suite.py
```

Por padrão são `baseline`, `blindado` e `guardrail` contra `HijackHateHumans` e `HijackLongPrompt`. Para escolher, use `--archs` (inclui `guardrail-io`) e `--probes`, por exemplo `--probes encoding.InjectBase64`.

**Passo a passo manual.** Arquiteturas 1 e 2 (Garak direto no Ollama):

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
