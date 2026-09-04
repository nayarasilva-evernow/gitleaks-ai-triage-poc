"""Gera fragmento TOML sugerido a partir de FPs confirmados.

Duas restrições moldam o formato de saída:

1. O allowlist global do Gitleaks é uma tabela única (`[allowlist]`), não um
   array — por isso tudo é consolidado em um bloco só.
2. Supressão por caminho não é sugerida: se o arquivo é suprimido e um segredo
   novo é inserido nele depois, a ferramenta não detecta.
"""

from __future__ import annotations

import re
from collections import defaultdict
from typing import Any

_ASSIGNMENT_RE = re.compile(r"^(?P<key>[a-zA-Z]+)\s*=\s*(?P<rhs>.+)$", re.DOTALL)
_ITEM_RE = re.compile(r"'''(.*?)'''|\"(.*?)\"|'(.*?)'", re.DOTALL)

# Critérios aceitos: ambos avaliados contra o valor extraído, não contra o path
_VALUE_KEYS = ("stopwords", "regexes")


def _items(rhs: str) -> list[str]:
    """Valores entre quotes no lado direito da atribuição."""
    found = []
    for groups in _ITEM_RE.findall(rhs):
        value = next((g for g in groups if g), "")
        if value:
            found.append(value.strip())
    if found:
        return found
    bare = rhs.strip().strip("[]").strip()
    return [bare] if bare else []


def _parse_suggestion(suggestion: str) -> tuple[str, list[str]]:
    """(chave, itens). Chave vazia quando a sugestão não é utilizável."""
    match = _ASSIGNMENT_RE.match(suggestion.strip())
    if not match:
        # sugestão solta, sem `chave = `: trata como regex do valor
        return "regexes", [suggestion.strip()]

    key = match.group("key").lower()
    if key not in _VALUE_KEYS and key != "paths":
        return "", []
    return key, _items(match.group("rhs"))


def build_suggested_toml(triaged: list[dict[str, Any]]) -> str:
    fps = [t for t in triaged if t.get("verdict") == "false_positive"]
    if not fps:
        return "# Nenhum falso positivo confirmado — nada a sugerir.\n"

    buckets: dict[str, dict[str, list[str]]] = {key: defaultdict(list) for key in _VALUE_KEYS}
    manual: list[tuple[str, str]] = []

    for item in fps:
        file = item.get("file") or "?"
        suggestion = (item.get("suggested_allowlist") or "").strip()
        if not suggestion:
            manual.append((file, "sem sugestão automática"))
            continue

        key, items = _parse_suggestion(suggestion)
        if key == "paths":
            manual.append((file, "sugestão por caminho recusada — substitua o valor por um explicitamente inválido"))
            continue
        if not key or not items:
            manual.append((file, f"sugestão não reconhecida: {suggestion}"))
            continue
        if any("*" in value for value in items):
            # a IA às vezes devolve o valor mascarado que recebeu; como allowlist
            # isso nunca casa com o secret real
            manual.append((file, "sugestão contém valor mascarado — inútil como allowlist"))
            continue
        for value in items:
            buckets[key][value].append(file)

    lines = [
        "# Sugestões geradas pela triagem (revisar antes de aplicar)",
        "# Cole os itens abaixo dentro do [allowlist] do .gitleaks.toml.",
        "#",
        "# Allowlist por valor, não por caminho: um segredo real inserido depois",
        "# no mesmo arquivo continua sendo detectado.",
        "",
    ]

    if any(buckets[key] for key in _VALUE_KEYS):
        lines.append("[allowlist]")
        for key in _VALUE_KEYS:
            entries = buckets[key]
            if not entries:
                continue
            lines.append(f"{key} = [")
            for value, files in sorted(entries.items()):
                unique = sorted(set(files))
                origem = ", ".join(unique[:3])
                if len(unique) > 3:
                    origem += f" (+{len(unique) - 3})"
                lines.append(f"  '''{value}''',  # {origem}")
            lines.append("]")
        lines.append("")

    if manual:
        lines.append("# Revisar manualmente:")
        for file, motivo in sorted(set(manual)):
            lines.append(f"#   - {file}: {motivo}")
        lines.append("")

    return "\n".join(lines)
