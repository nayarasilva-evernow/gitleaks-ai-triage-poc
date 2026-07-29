"""Mascaramento de secrets antes de enviar contexto ao LLM."""

from __future__ import annotations


def mask_secret(value: str, keep_start: int = 4, keep_end: int = 4) -> str:
    if not value:
        return ""
    if len(value) <= keep_start + keep_end:
        return "*" * len(value)
    return f"{value[:keep_start]}{'*' * max(4, len(value) - keep_start - keep_end)}{value[-keep_end:]}"


def redact_in_text(text: str, secret: str) -> str:
    if not text or not secret:
        return text or ""
    return text.replace(secret, mask_secret(secret))
