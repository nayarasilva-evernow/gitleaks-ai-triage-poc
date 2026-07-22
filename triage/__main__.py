"""CLI: python -m triage --findings findings.json --out triage-report.json"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .classify import classify_finding
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
        print(
            f"[{result.verdict}] ({result.source}) "
            f"{entry['file']}:{entry['start_line']} — {result.reason}"
        )

    args.out.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    args.suggested_toml.write_text(build_suggested_toml(report), encoding="utf-8")
    print(f"\nRelatório: {args.out}")
    print(f"Sugestões TOML: {args.suggested_toml}")

    tps = [r for r in report if r["verdict"] == "true_positive"]
    uncertain = [r for r in report if r["verdict"] == "uncertain"]

    if args.fail_on == "true_positive" and tps:
        print(f"\nFAIL: {len(tps)} verdadeiro(s) positivo(s)")
        return 1
    if args.fail_on == "true_positive_or_uncertain" and (tps or uncertain):
        print(f"\nFAIL: {len(tps)} TP(s), {len(uncertain)} incerto(s)")
        return 1

    print(f"\nOK: {len(report)} finding(s) triados; gate passou")
    return 0


if __name__ == "__main__":
    sys.exit(main())
