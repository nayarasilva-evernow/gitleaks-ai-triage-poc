"""Exporta contagens do relatório de triagem como outputs do GitHub Actions."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path


def main() -> int:
    report_path = Path(sys.argv[1])
    triage_exit = sys.argv[2] if len(sys.argv) > 2 else ""

    verdicts: list[str] = []
    if report_path.is_file():
        report = json.loads(report_path.read_text(encoding="utf-8"))
        verdicts = [r.get("verdict", "") for r in report]

    lines = [
        f"total={len(verdicts)}",
        f"true_positives={verdicts.count('true_positive')}",
        f"false_positives={verdicts.count('false_positive')}",
        f"uncertain={verdicts.count('uncertain')}",
        f"gate_passed={'true' if triage_exit == '0' else 'false'}",
    ]

    output = os.getenv("GITHUB_OUTPUT")
    text = "\n".join(lines) + "\n"
    if output:
        with open(output, "a", encoding="utf-8") as fh:
            fh.write(text)
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
