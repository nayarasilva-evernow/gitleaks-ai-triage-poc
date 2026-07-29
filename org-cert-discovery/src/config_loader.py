from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml


def project_root() -> Path:
    return Path(__file__).resolve().parent.parent


def load_config(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as f:
        cfg = yaml.safe_load(f) or {}

    org = os.getenv("GITHUB_ORG", "").strip()
    if not org:
        raise SystemExit(
            "Defina GITHUB_ORG no arquivo .env (organização a varrer)."
        )
    cfg["org"] = org

    # Gitleaks path pode vir do env também
    env_gitleaks = os.getenv("GITLEAKS_EXCEL", "").strip()
    if env_gitleaks:
        cfg["gitleaks_excel"] = env_gitleaks

    cfg.setdefault("keystore_extensions", [".jks", ".keystore", ".p12", ".pfx"])
    cfg.setdefault("cert_file_extensions", [".pem", ".crt", ".cer", ".key"])
    cfg.setdefault("include_cert_files", True)
    cfg.setdefault("rate_limit_floor", 50)
    cfg.setdefault("min_request_interval_seconds", 0.35)
    cfg.setdefault("include_forks", False)
    cfg.setdefault("include_archived", False)
    cfg.setdefault("gitleaks_excel", "")
    cfg.setdefault("gitleaks_cert_keywords", ["cert", "private", "key", "pem", "rsa", "ssh"])
    cfg.setdefault(
        "paths",
        {"checkpoint_dir": "data/checkpoints", "output_dir": "data/output"},
    )
    return cfg
