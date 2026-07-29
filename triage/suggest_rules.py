"""Gera fragmento TOML sugerido a partir de FPs confirmados."""

from __future__ import annotations

from collections import defaultdict
from typing import Any


def build_suggested_toml(triaged: list[dict[str, Any]]) -> str:
    fps = [t for t in triaged if t.get("verdict") == "false_positive"]
    if not fps:
        return "# Nenhum falso positivo confirmado — nada a sugerir.\n"

    by_allowlist: dict[str, list[str]] = defaultdict(list)
    for item in fps:
        suggestion = item.get("suggested_allowlist") or "revisar_manualmente"
        file = item.get("file") or "?"
        by_allowlist[suggestion].append(file)

    lines = [
        "# Sugestões geradas pela triagem (revisar antes de mergear)",
        "# Copie blocos úteis para .gitleaks.toml",
        "",
    ]
    for i, (suggestion, files) in enumerate(sorted(by_allowlist.items()), start=1):
        unique_files = sorted(set(files))
        lines.append(f"[[allowlists]]")
        lines.append(f'id = "ai-suggested-{i}"')
        lines.append(f'description = "Gerado a partir de FPs: {", ".join(unique_files[:5])}"')
        if suggestion.startswith("paths"):
            lines.append(suggestion)
        elif suggestion != "revisar_manualmente":
            lines.append(f"regexes = ['''{suggestion}''']")
        else:
            lines.append("# TODO: definir paths/regexes manualmente")
            for f in unique_files:
                lines.append(f"# - {f}")
        lines.append("")
    return "\n".join(lines)
