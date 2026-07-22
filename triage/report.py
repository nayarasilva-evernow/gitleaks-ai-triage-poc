"""Formatação amigável do relatório de triagem (console + GitHub Actions)."""

from __future__ import annotations

import os
from collections import Counter
from pathlib import Path
from typing import Any

VERDICT_LABEL = {
    "true_positive": ("🔴", "Verdadeiro positivo", "error"),
    "false_positive": ("🟢", "Falso positivo", "notice"),
    "uncertain": ("🟡", "Incerto", "warning"),
}

SOURCE_LABEL = {
    "llm": "IA",
    "heuristic": "Heurística",
}


def _loc(entry: dict[str, Any]) -> str:
    file = entry.get("file") or "?"
    line = entry.get("start_line")
    return f"{file}:{line}" if line is not None else file


def print_console_report(report: list[dict[str, Any]]) -> None:
    counts = Counter(r["verdict"] for r in report)
    width = 64

    print()
    print("=" * width)
    print("  TRIAGEM DE SECRETS (Gitleaks + IA)")
    print("=" * width)
    print(f"  Total analisado ...... {len(report)}")
    print(f"  Verdadeiros positivos  {counts.get('true_positive', 0)}")
    print(f"  Falsos positivos ..... {counts.get('false_positive', 0)}")
    print(f"  Incertos ............. {counts.get('uncertain', 0)}")
    print("=" * width)

    order = ("true_positive", "false_positive", "uncertain")
    for verdict in order:
        items = [r for r in report if r["verdict"] == verdict]
        if not items:
            continue
        icon, label, _ = VERDICT_LABEL[verdict]
        print()
        print(f"{icon}  {label.upper()} ({len(items)})")
        print("-" * width)
        for i, entry in enumerate(items, start=1):
            src = SOURCE_LABEL.get(entry.get("source", ""), entry.get("source", "?"))
            conf = entry.get("confidence")
            conf_s = f"{conf:.0%}" if isinstance(conf, (int, float)) else "?"
            print(f"  {i}. {_loc(entry)}")
            print(f"     Regra      : {entry.get('rule_id') or '—'}")
            print(f"     Confiança  : {conf_s}  |  Fonte: {src}")
            print(f"     Motivo     : {entry.get('reason') or '—'}")
            if entry.get("suggested_allowlist"):
                print(f"     Sugestão   : {entry['suggested_allowlist']}")
            print()


def print_gate_result(ok: bool, tps: int, uncertain: int) -> None:
    width = 64
    print("=" * width)
    if ok:
        print("  RESULTADO: PASSOU")
        print("  Nenhum verdadeiro positivo bloqueante.")
    else:
        print("  RESULTADO: FALHOU")
        print(f"  {tps} verdadeiro(s) positivo(s) precisam de ação.")
        if uncertain:
            print(f"  ({uncertain} finding(s) incerto(s) — revise manualmente)")
        print()
        print("  O que fazer:")
        print("  1. Remova o secret do código / rotacione a credencial")
        print("  2. Se for FP legítimo, ajuste .gitleaks.toml (allowlist)")
        print("  3. Veja suggested_rules.toml e o Summary desta run")
    print("=" * width)
    print()


def emit_github_annotations(report: list[dict[str, Any]]) -> None:
    """Anotações clicáveis na aba Files / na UI do job."""
    if not os.getenv("GITHUB_ACTIONS"):
        return
    for entry in report:
        verdict = entry.get("verdict", "uncertain")
        _, label, level = VERDICT_LABEL.get(verdict, ("?", "Finding", "warning"))
        file = entry.get("file") or "unknown"
        line = entry.get("start_line") or 1
        reason = (entry.get("reason") or "").replace("\n", " ").replace("%", "%25")
        msg = f"[{label}] {reason}"
        # GitHub workflow command
        print(f"::{level} file={file},line={line}::{msg}")


def write_github_step_summary(
    report: list[dict[str, Any]],
    *,
    ok: bool,
    out_json: Path,
    suggested_toml: Path,
) -> None:
    summary_path = os.getenv("GITHUB_STEP_SUMMARY")
    if not summary_path:
        return

    counts = Counter(r["verdict"] for r in report)
    status = "Passed" if ok else "Failed"
    status_emoji = "PASSED" if ok else "FAILED"

    lines: list[str] = [
        "# Secret scan — triagem IA",
        "",
        f"**Status do gate:** `{status_emoji}`",
        "",
        "## Resumo",
        "",
        "| Veredicto | Qtd |",
        "|-----------|-----|",
        f"| Verdadeiro positivo | {counts.get('true_positive', 0)} |",
        f"| Falso positivo | {counts.get('false_positive', 0)} |",
        f"| Incerto | {counts.get('uncertain', 0)} |",
        f"| **Total** | **{len(report)}** |",
        "",
    ]

    order = ("true_positive", "false_positive", "uncertain")
    for verdict in order:
        items = [r for r in report if r["verdict"] == verdict]
        if not items:
            continue
        icon, label, _ = VERDICT_LABEL[verdict]
        lines.append(f"## {icon} {label}")
        lines.append("")
        lines.append("| Arquivo | Linha | Regra | Confiança | Motivo |")
        lines.append("|---------|------:|-------|----------:|--------|")
        for entry in items:
            file = entry.get("file") or "?"
            line = entry.get("start_line") or "—"
            rule = entry.get("rule_id") or "—"
            conf = entry.get("confidence")
            conf_s = f"{conf:.0%}" if isinstance(conf, (int, float)) else "—"
            reason = (entry.get("reason") or "—").replace("|", "\\|")
            lines.append(f"| `{file}` | {line} | `{rule}` | {conf_s} | {reason} |")
        lines.append("")

    if not ok:
        lines.extend(
            [
                "## Próximos passos",
                "",
                "1. Remova o secret do código e **rotacione** a credencial.",
                "2. Se for falso positivo, ajuste allowlist em `.gitleaks.toml`.",
                f"3. Artifacts desta run: `{out_json.name}`, `{suggested_toml.name}`.",
                "",
            ]
        )

    Path(summary_path).write_text("\n".join(lines) + "\n", encoding="utf-8")
