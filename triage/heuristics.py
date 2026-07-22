"""Heurísticas locais antes de chamar a IA (custo / ruído)."""

from __future__ import annotations

import re
from pathlib import Path

PLACEHOLDER_RE = re.compile(
    r"(?i)(changeme|replace[_-]?me|example|dummy|placeholder|xxx+|your[_-]?api[_-]?key|not[_-]?a[_-]?secret|test[_-]?key)",
)

TEST_PATH_HINTS = (
    "/tests/",
    "\\tests\\",
    "/test/",
    "\\test\\",
    "/fixtures/",
    "\\fixtures\\",
    "/docs/",
    "\\docs\\",
    ".md",
    ".env.example",
)


def local_false_positive_hint(finding: dict) -> str | None:
    """Retorna motivo se parecer FP óbvio; senão None (enviar à IA)."""
    path = (finding.get("File") or finding.get("file") or "").replace("\\", "/")
    secret = finding.get("Secret") or finding.get("secret") or ""
    match = finding.get("Match") or finding.get("match") or ""
    snippet = f"{secret} {match}"

    lower_path = path.lower()
    if any(h.replace("\\", "/") in f"/{lower_path}" or lower_path.endswith(h.lstrip("/\\")) for h in TEST_PATH_HINTS):
        if PLACEHOLDER_RE.search(snippet) or "sk_test_" in secret or "xxxx" in secret.lower():
            return "path_de_teste_ou_docs_com_placeholder"

    if PLACEHOLDER_RE.search(snippet):
        return "placeholder_obvio_no_match"

    name = Path(path).name.lower()
    if name in {"readme.md", "setup.md", ".env.example"}:
        return "arquivo_de_documentacao_ou_exemplo"

    return None
