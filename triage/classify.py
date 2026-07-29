"""Classificação de findings Gitleaks via Groq (tier gratuito) ou Ollama."""

from __future__ import annotations

import json
import os
from typing import Any, Literal

from openai import OpenAI
from pydantic import BaseModel, Field

from .heuristics import local_false_positive_hint
from .mask import mask_secret, redact_in_text

Verdict = Literal["true_positive", "false_positive", "uncertain"]

# Groq = API gratuita (https://console.groq.com) | ollama = 100% local
DEFAULT_PROVIDER = os.getenv("TRIAGE_PROVIDER", "groq").lower()

PROVIDERS = {
    "groq": {
        "base_url": "https://api.groq.com/openai/v1",
        "api_key_env": "GROQ_API_KEY",
        "default_model": "llama-3.3-70b-versatile",
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
- false_positive: placeholder, exemplo, mock de teste, documentação, ou valor claramente fictício
- uncertain: evidência insuficiente

Responda APENAS com JSON válido no formato:
{
  "verdict": "true_positive" | "false_positive" | "uncertain",
  "confidence": 0.0-1.0,
  "reason": "explicação curta em português",
  "suggested_allowlist": "regex ou path sugerido para .gitleaks.toml se FP, senão null"
}

Seja conservador: na dúvida, use uncertain (não dismiss automático).
"""


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
        "snippet_redacted": redact_in_text(snippet, secret)[:500],
    }


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
    # Groq aceita json_object; Ollama pode variar — tenta e faz fallback
    if DEFAULT_PROVIDER == "groq":
        kwargs["response_format"] = {"type": "json_object"}

    response = client.chat.completions.create(**kwargs)
    raw = response.choices[0].message.content or "{}"
    # Alguns modelos envolvem JSON em ``` — limpa
    raw = raw.strip()
    if raw.startswith("```"):
        raw = raw.strip("`")
        if raw.startswith("json"):
            raw = raw[4:].strip()
    data = json.loads(raw)
    return TriageResult(source="llm", **data)


def classify_finding(finding: dict[str, Any], client: OpenAI | None = None) -> TriageResult:
    hint = local_false_positive_hint(finding)
    if hint:
        return TriageResult(
            verdict="false_positive",
            confidence=0.85,
            reason=f"Heurística local: {hint}",
            suggested_allowlist=_suggest_from_path(finding),
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


def _suggest_from_path(finding: dict[str, Any]) -> str | None:
    path = (finding.get("File") or finding.get("file") or "").replace("\\", "/")
    if not path:
        return None
    if "/tests/" in f"/{path}" or path.startswith("sample-app/tests/"):
        return "paths = ['''sample-app/tests/.*''']"
    if "/docs/" in f"/{path}":
        return "paths = ['''sample-app/docs/.*''']"
    return None
