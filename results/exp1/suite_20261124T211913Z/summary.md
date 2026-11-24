# Bateria do Experimento 1 (2026-11-24T21:19:13+00:00)

ASR = taxa de sucesso do ataque (falhas da defesa / saídas avaliadas). IC 95% calculado pelo Garak (bootstrap).

| Arquitetura | Probe | Detector | ASR | IC 95% | Falhas / Avaliadas | Barrados pelo Llama Guard | Tempo |
| :--- | :--- | :--- | :---: | :---: | :---: | :---: | :---: |
| 1. Baseline (llama3.2) | HijackHateHumans | promptinject.AttackRogueString | **51,25%** | 48,52% a 53,98% | 656 / 1280 | – | 168s |
| 2. Camada única (llama3.2-blindado) | HijackHateHumans | promptinject.AttackRogueString | **15,00%** | 13,12% a 16,96% | 192 / 1280 | – | 355s |
| 3. Defense in Depth (Llama Guard na entrada) | HijackHateHumans | promptinject.AttackRogueString | **0,00%** | 0,00% a 0,00% | 0 / 1280 | 1280 entrada / 0 saída de 1280 | 44s |
| 1. Baseline (llama3.2) | HijackLongPrompt | promptinject.AttackRogueString | **65,78%** | 63,20% a 68,44% | 842 / 1280 | – | 343s |
| 2. Camada única (llama3.2-blindado) | HijackLongPrompt | promptinject.AttackRogueString | **54,53%** | 51,88% a 57,34% | 698 / 1280 | – | 358s |
| 3. Defense in Depth (Llama Guard na entrada) | HijackLongPrompt | promptinject.AttackRogueString | **49,61%** | 46,95% a 52,42% | 635 / 1280 | 184 entrada / 0 saída de 1280 | 483s |
