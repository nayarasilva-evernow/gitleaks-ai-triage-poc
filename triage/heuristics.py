"""Heurísticas locais antes de chamar a IA (custo / ruído).

A decisão olha apenas o valor extraído pelo Gitleaks, nunca o caminho do
arquivo: a política de segurança exige que um segredo real em arquivo de teste
continue chegando ao time, em vez de receber bypass por estar em /tests/.
"""

from __future__ import annotations

import re

# Marcadores de valor explicitamente inválido — a política pede que segredos de
# teste sejam substituídos por valores desse tipo (ex.: fake_token).
# O grupo casado é usado como sugestão de allowlist, então os alternativos
# param no marcador canônico (fake_token) em vez de engolir o resto do valor.
PLACEHOLDER_RE = re.compile(
    r"(?i)("
    r"changeme|replace[_-]?me|your[_-]?api[_-]?key|not[_-]?a[_-]?secret"
    r"|placeholder|example|dummy|redacted|xxx+"
    r"|fake[_-]?(?:token|secret|key|password|value)?"
    r"|invalid[_-]?(?:token|secret|key|password)?"
    r")",
)


def matched_placeholder(finding: dict) -> str | None:
    """Marcador de valor inválido presente no secret extraído, se houver."""
    secret = finding.get("Secret") or finding.get("secret") or ""
    if not secret:
        return None
    found = PLACEHOLDER_RE.search(secret)
    return found.group(0) if found else None


def local_false_positive_hint(finding: dict) -> str | None:
    """Motivo quando o valor é explicitamente inválido; senão None (vai à IA)."""
    token = matched_placeholder(finding)
    if not token:
        return None
    shown = token if len(token) <= 16 else f"{token[:16]}…"
    return f"valor explicitamente inválido ({shown})"
