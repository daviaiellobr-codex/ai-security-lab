"""
Classificador de prompt injection (Hugging Face) usado como camada de entrada.

Padrão: Llama Prompt Guard 2 86M, da Meta. É um modelo BERT (mDeBERTa) que só devolve
um rótulo, benigno ou malicioso, treinado para reconhecer padrões explícitos de ataque
(injeções e jailbreaks). O modelo publicado usa rótulos genéricos: LABEL_0 (benigno) e
LABEL_1 (malicioso). Diferente do Llama Guard, ele não avalia se o conteúdo é nocivo:
avalia se o texto tenta sequestrar as instruções do modelo.

O modelo é restrito no Hugging Face: é preciso aceitar a licença na página do modelo e
fazer login com `hf auth login`. Alternativa sem restrição, também compatível:
protectai/deberta-v3-base-prompt-injection-v2 (rótulos SAFE / INJECTION, só inglês).

torch e transformers já vêm instalados como dependências do Garak.
"""

DEFAULT_MODEL = "meta-llama/Llama-Prompt-Guard-2-86M"

# Rótulos tratados como ataque nos classificadores suportados
MALICIOUS_LABELS = {"MALICIOUS", "INJECTION", "JAILBREAK"}


class InjectionClassifier:
    def __init__(self, model_id=DEFAULT_MODEL, device=None):
        import torch
        from transformers import AutoModelForSequenceClassification, AutoTokenizer

        self.torch = torch
        self.model_id = model_id
        self.device = device or ("cuda" if torch.cuda.is_available() else "cpu")
        self.tokenizer = AutoTokenizer.from_pretrained(model_id)
        self.model = AutoModelForSequenceClassification.from_pretrained(model_id).to(self.device).eval()

        labels = {int(i): str(name).upper() for i, name in self.model.config.id2label.items()}
        self.malicious_ids = sorted(i for i, name in labels.items() if name in MALICIOUS_LABELS)
        if not self.malicious_ids and set(labels.values()) == {"LABEL_0", "LABEL_1"}:
            # Classificador binário com rótulos genéricos (caso do Prompt Guard 2): 1 = malicioso
            self.malicious_ids = [i for i, name in labels.items() if name == "LABEL_1"]
        if not self.malicious_ids:
            raise ValueError(f"{model_id}: nenhum rótulo de ataque reconhecido em {labels}")
        self.labels = labels
        # O Prompt Guard 2 aceita no máximo 512 tokens por vez
        self.max_length = min(getattr(self.tokenizer, "model_max_length", 512) or 512, 512)

    def _encode(self, text):
        common = dict(truncation=True, max_length=self.max_length, padding=True, return_tensors="pt")
        try:
            # Textos longos viram janelas de 512 tokens (com sobreposição) e todas são avaliadas
            enc = self.tokenizer(text, return_overflowing_tokens=True, stride=64, **common)
        except (NotImplementedError, ValueError, TypeError):
            enc = self.tokenizer(text, **common)  # tokenizador sem suporte a janelas: só o início
        enc.pop("overflow_to_sample_mapping", None)
        return {k: v.to(self.device) for k, v in enc.items()}

    def score(self, text):
        """Probabilidade de o texto ser um ataque (0 a 1). Em textos longos, vale a janela mais suspeita."""
        with self.torch.no_grad():
            logits = self.model(**self._encode(text)).logits
            probs = self.torch.softmax(logits, dim=-1)
        return float(probs[:, self.malicious_ids].sum(dim=-1).max())
