"""CLI: python -m triage --findings findings.json --out triage-report.json"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .classify import classify_finding
from .report import (
    emit_github_annotations,
    print_console_report,
    print_gate_result,
    write_github_step_summary,
)
from .suggest_rules import build_suggested_toml


def load_findings(path: Path) -> list[dict]:
    text = path.read_text(encoding="utf-8").strip()
    if not text:
        return []
    # Gitleaks --report-format json: array OU json lines
    if text.startswith("["):
        data = json.loads(text)
        return data if isinstance(data, list) else [data]
    findings = []
    for line in text.splitlines():
        line = line.strip()
        if line:
            findings.append(json.loads(line))
    return findings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Triagem AI de findings Gitleaks")
    parser.add_argument("--findings", type=Path, required=True, help="JSON do Gitleaks")
    parser.add_argument("--out", type=Path, default=Path("triage-report.json"))
    parser.add_argument(
        "--suggested-toml",
        type=Path,
        default=Path("suggested_rules.toml"),
        help="Arquivo TOML sugerido a partir de FPs",
    )
    parser.add_argument(
        "--fail-on",
        choices=("true_positive", "true_positive_or_uncertain"),
        default="true_positive",
        help="Quando sair com código != 0",
    )
    args = parser.parse_args(argv)

    findings = load_findings(args.findings)
    report: list[dict] = []

    print(f"Analisando {len(findings)} finding(s) do Gitleaks...")
    for finding in findings:
        result = classify_finding(finding)
        entry = {
            "file": finding.get("File") or finding.get("file"),
            "rule_id": finding.get("RuleID") or finding.get("RuleId") or finding.get("rule_id"),
            "start_line": finding.get("StartLine") or finding.get("start_line"),
            "verdict": result.verdict,
            "confidence": result.confidence,
            "reason": result.reason,
            "suggested_allowlist": result.suggested_allowlist,
            "source": result.source,
        }
        report.append(entry)

    args.out.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    args.suggested_toml.write_text(build_suggested_toml(report), encoding="utf-8")

    print_console_report(report)
    emit_github_annotations(report)

    tps = [r for r in report if r["verdict"] == "true_positive"]
    uncertain = [r for r in report if r["verdict"] == "uncertain"]

    fail = False
    if args.fail_on == "true_positive" and tps:
        fail = True
    if args.fail_on == "true_positive_or_uncertain" and (tps or uncertain):
        fail = True

    print_gate_result(ok=not fail, tps=len(tps), uncertain=len(uncertain))
    write_github_step_summary(
        report,
        ok=not fail,
        out_json=args.out,
        suggested_toml=args.suggested_toml,
    )

    print(f"Arquivos: {args.out} | {args.suggested_toml}")
    return 1 if fail else 0


if __name__ == "__main__":
    sys.exit(main())
