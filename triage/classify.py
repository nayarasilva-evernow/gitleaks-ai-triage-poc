"""Classificação de findings Gitleaks via Groq (tier gratuito) ou Ollama."""

from __future__ import annotations

import json
import os
from typing import Any, Literal

from openai import BadRequestError, OpenAI
from pydantic import BaseModel, Field

from .heuristics import local_false_positive_hint, matched_placeholder
from .mask import mask_secret, redact_in_text

Verdict = Literal["true_positive", "false_positive", "uncertain"]

# Groq = API gratuita (https://console.groq.com) | ollama = 100% local
DEFAULT_PROVIDER = os.getenv("TRIAGE_PROVIDER", "groq").lower()

PROVIDERS = {
    "groq": {
        "base_url": "https://api.groq.com/openai/v1",
        "api_key_env": "GROQ_API_KEY",
        "default_model": "openai/gpt-oss-20b",
    },
    "ollama": {
        "base_url": os.getenv("OLLAMA_BASE_URL", "http://127.0.0.1:11434/v1"),
        "api_key_env": None,  # Ollama não exige key
        "default_model": os.getenv("OLLAMA_MODEL", "llama3.2"),
    },
}


class TriageResult(BaseModel):
    verdict: Verdict
    confidence: float = Field(ge=0.0, le=1.0)
    reason: str
    suggested_allowlist: str | None = None
    source: Literal["heuristic", "llm"] = "llm"


SYSTEM_PROMPT = """Você é um analista de AppSec revisando findings do Gitleaks (secret scanning).

Classifique cada finding como:
- true_positive: credencial real ou altamente provável em código de aplicação/produção
- false_positive: o VALOR em si é inválido (placeholder, fake_token, exemplo de documentação)
- uncertain: evidência insuficiente

Política obrigatória: estar em arquivo de teste, fixture ou documentação NÃO torna o
finding falso positivo. Julgue pelo valor: se ele tem formato de credencial real, é
true_positive mesmo em arquivo de teste. Segredo de teste deve ser um valor
explicitamente inválido — quando não é, o time precisa revisar.

Regras de decisão, na ordem:

1. placeholder_marker_found = true significa que o valor contém marcador explícito
   de invalidez (changeme, fake_token, example) — aí sim false_positive.
2. Prefixo de credencial de produção (sk_live_, AKIA, ghp_, gho_, gsk_, AIza, xoxb)
   em código de aplicação é true_positive, mesmo em arquivo de teste.
3. O valor chega MASCARADO (asteriscos no meio) para não expor a credencial. Nem o
   mascaramento nem secret_length provam invalidez: os asteriscos ocultam caracteres
   reais e o comprimento varia por provedor e por época. NÃO justifique
   false_positive dizendo que o formato ou o tamanho não parece válido.
4. Se nenhuma regra acima decide, use uncertain.

Responda APENAS com JSON válido no formato:
{
  "verdict": "true_positive" | "false_positive" | "uncertain",
  "confidence": 0.0-1.0,
  "reason": "explicação curta em português",
  "suggested_allowlist": "se FP: allowlist do PRÓPRIO VALOR, no formato stopwords = ['''fake_token'''] ou regexes = ['''regex-do-valor''']; NUNCA sugira paths (suprimir arquivo esconde segredo novo inserido depois); senão null"
}

Seja conservador: na dúvida, use uncertain (não dismiss automático).
"""

# gpt-oss no Groq rejeita json_object (400 json_validate_failed).
# Structured Outputs (json_schema + strict) é o modo suportado nesse modelo.
TRIAGE_JSON_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "verdict": {
            "type": "string",
            "enum": ["true_positive", "false_positive", "uncertain"],
        },
        "confidence": {"type": "number"},
        "reason": {"type": "string"},
        "suggested_allowlist": {"type": ["string", "null"]},
    },
    "required": ["verdict", "confidence", "reason", "suggested_allowlist"],
    "additionalProperties": False,
}


def _provider_config() -> dict[str, Any]:
    if DEFAULT_PROVIDER not in PROVIDERS:
        raise ValueError(f"TRIAGE_PROVIDER inválido: {DEFAULT_PROVIDER}. Use: {', '.join(PROVIDERS)}")
    return PROVIDERS[DEFAULT_PROVIDER]


def _make_client(client: OpenAI | None = None) -> OpenAI:
    if client is not None:
        return client
    cfg = _provider_config()
    api_key = "ollama"
    if cfg["api_key_env"]:
        api_key = os.getenv(cfg["api_key_env"]) or ""
    return OpenAI(base_url=cfg["base_url"], api_key=api_key)


def _has_credentials() -> bool:
    cfg = _provider_config()
    if cfg["api_key_env"] is None:
        return True  # Ollama local
    return bool(os.getenv(cfg["api_key_env"]))


def _finding_payload(finding: dict[str, Any]) -> dict[str, Any]:
    secret = finding.get("Secret") or finding.get("secret") or ""
    match = finding.get("Match") or finding.get("match") or ""
    snippet = finding.get("Snippet") or finding.get("snippet") or match
    return {
        "rule_id": finding.get("RuleID") or finding.get("RuleId") or finding.get("rule_id"),
        "description": finding.get("Description") or finding.get("description"),
        "file": finding.get("File") or finding.get("file"),
        "start_line": finding.get("StartLine") or finding.get("start_line"),
        "commit": finding.get("Commit") or finding.get("commit"),
        "author": finding.get("Author") or finding.get("author"),
        "secret_masked": mask_secret(secret),
        # o mascaramento apaga o formato do valor; sem esses dois campos a IA
        # conclui "asteriscos = formato inválido = placeholder" e dispensa
        # credencial real
        "secret_length": len(secret),
        "placeholder_marker_found": matched_placeholder(finding) is not None,
        "snippet_redacted": redact_in_text(snippet, secret)[:500],
    }


def _is_oss_model(model: str) -> bool:
    return "gpt-oss" in model.lower()


def _groq_response_format(model: str) -> dict[str, Any]:
    if _is_oss_model(model):
        return {
            "type": "json_schema",
            "json_schema": {
                "name": "triage_result",
                "strict": True,
                "schema": TRIAGE_JSON_SCHEMA,
            },
        }
    return {"type": "json_object"}


def _parse_llm_json(raw: str) -> dict[str, Any]:
    text = (raw or "").strip()
    if text.startswith("```"):
        text = text.strip("`")
        if text.startswith("json"):
            text = text[4:].strip()
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        start, end = text.find("{"), text.rfind("}")
        if start == -1 or end <= start:
            raise
        data = json.loads(text[start : end + 1])
    if not isinstance(data, dict):
        raise ValueError("resposta da IA não é um objeto JSON")
    return data


def classify_with_llm(finding: dict[str, Any], client: OpenAI | None = None) -> TriageResult:
    cfg = _provider_config()
    client = _make_client(client)
    model = os.getenv("TRIAGE_MODEL", cfg["default_model"])
    payload = _finding_payload(finding)

    kwargs: dict[str, Any] = {
        "model": model,
        "temperature": 0,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {
                "role": "user",
                "content": "Classifique este finding do Gitleaks:\n"
                + json.dumps(payload, ensure_ascii=False, indent=2),
            },
        ],
    }
    if DEFAULT_PROVIDER == "groq":
        kwargs["response_format"] = _groq_response_format(model)

    try:
        response = client.chat.completions.create(**kwargs)
    except BadRequestError:
        # json_object / schema inválido: tenta de novo só com o prompt
        kwargs.pop("response_format", None)
        response = client.chat.completions.create(**kwargs)

    raw = response.choices[0].message.content or "{}"
    data = _parse_llm_json(raw)
    data.pop("source", None)
    return TriageResult(source="llm", **data)


def classify_finding(finding: dict[str, Any], client: OpenAI | None = None) -> TriageResult:
    hint = local_false_positive_hint(finding)
    if hint:
        token = matched_placeholder(finding)
        return TriageResult(
            verdict="false_positive",
            confidence=0.85,
            reason=f"Heurística local: {hint}",
            suggested_allowlist=_suggest_stopword(token) if token else None,
            source="heuristic",
        )
    if not _has_credentials():
        env_name = _provider_config()["api_key_env"] or "N/A"
        return TriageResult(
            verdict="uncertain",
            confidence=0.3,
            reason=f"{env_name} ausente; não foi possível triar com IA (provider={DEFAULT_PROVIDER})",
            source="heuristic",
        )
    return classify_with_llm(finding, client=client)


def _suggest_stopword(token: str) -> str:
    """Allowlist pelo valor inválido, consolidável em poucas entradas.

    Stopwords e regexes são avaliadas contra o secret extraído, então um segredo
    real inserido depois no mesmo arquivo continua sendo detectado — ao
    contrário da supressão por caminho.
    """
    value = token.lower()
    if set(value) == {"x"}:
        # sequência de x tem tamanho variável: regex cobre todas de uma vez
        return "regexes = ['''(?i)xxx+''']"
    return f"stopwords = ['''{value}''']"
