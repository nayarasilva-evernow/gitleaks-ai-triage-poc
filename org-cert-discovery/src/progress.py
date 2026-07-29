from __future__ import annotations

import logging
import time
from typing import Optional


class ProgressLog:
    """Log com etapa atual e progresso residual."""

    def __init__(self, logger: Optional[logging.Logger] = None) -> None:
        self._log = logger or logging.getLogger("org_cert_discovery")
        self.current_stage = ""

    def stage(self, name: str, message: str) -> None:
        self.current_stage = name
        self._log.info("=" * 72)
        self._log.info("[%s] %s", name, message)
        self._log.info("=" * 72)

    def info(self, message: str) -> None:
        prefix = f"[{self.current_stage}] " if self.current_stage else ""
        self._log.info("%s%s", prefix, message)

    def warning(self, message: str) -> None:
        prefix = f"[{self.current_stage}] " if self.current_stage else ""
        self._log.warning("%s%s", prefix, message)

    def progress(self, done: int, total: int, label: str = "") -> None:
        total = max(total, 0)
        done = min(done, total) if total else done
        remaining = max(total - done, 0) if total else "?"
        pct = (100.0 * done / total) if total else 0.0
        extra = f" | {label}" if label else ""
        self._log.info(
            "[%s] Progresso: %s/%s (%.1f%%) | faltam: %s%s",
            self.current_stage or "?",
            done,
            total if total else "?",
            pct,
            remaining,
            extra,
        )

    def rate_limit(self, remaining: int, reset_epoch: int, resource: str = "core") -> None:
        wait = max(0, reset_epoch - int(time.time()))
        self._log.info(
            "[%s] Rate limit (%s): remaining=%s | reset em ~%ss",
            self.current_stage or "API",
            resource,
            remaining,
            wait,
        )
