from __future__ import annotations

import os
import time
from typing import Any, Optional
from urllib.parse import urlparse

import requests

from progress import ProgressLog

ALLOWED_METHODS = frozenset({"GET", "HEAD"})


class ReadOnlyViolation(RuntimeError):
    pass


class GitHubReadOnlyClient:
    """
    Cliente HTTP estritamente read-only (GET/HEAD).
    Respeita rate limit e faz backoff em erros transitórios.
    """

    def __init__(
        self,
        token: Optional[str] = None,
        api_url: Optional[str] = None,
        rate_limit_floor: int = 50,
        min_interval: float = 0.35,
        progress: Optional[ProgressLog] = None,
    ) -> None:
        self.token = (token or os.getenv("GITHUB_TOKEN") or "").strip()
        if not self.token:
            raise SystemExit(
                "Defina GITHUB_TOKEN no .env (token somente leitura)."
            )

        raw_api = (api_url or os.getenv("GITHUB_API_URL") or "").strip()
        self.api_url = raw_api.rstrip("/") if raw_api else "https://api.github.com"
        self.rate_limit_floor = rate_limit_floor
        self.min_interval = min_interval
        self.progress = progress or ProgressLog()
        self._last_request_at = 0.0

        self.session = requests.Session()
        self.session.headers.update(
            {
                "Authorization": f"Bearer {self.token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
                "User-Agent": "org-cert-discovery-readonly",
            }
        )

    def _throttle(self) -> None:
        elapsed = time.time() - self._last_request_at
        if elapsed < self.min_interval:
            time.sleep(self.min_interval - elapsed)

    def _respect_rate_limit(self, response: requests.Response) -> None:
        resource = "core"
        remaining = response.headers.get("X-RateLimit-Remaining")
        reset = response.headers.get("X-RateLimit-Reset")
        if remaining is None:
            return
        rem = int(remaining)
        reset_epoch = int(reset or 0)
        if rem <= self.rate_limit_floor:
            wait = max(reset_epoch - int(time.time()) + 2, 5)
            self.progress.rate_limit(rem, reset_epoch, resource=resource)
            self.progress.warning(
                f"Budget baixo ({rem}). Aguardando {wait}s para não estourar o limite."
            )
            time.sleep(wait)

    def request(
        self,
        method: str,
        path_or_url: str,
        *,
        params: Optional[dict] = None,
        max_retries: int = 8,
    ) -> requests.Response:
        method = method.upper()
        if method not in ALLOWED_METHODS:
            raise ReadOnlyViolation(
                f"Bloqueado: método {method} não é permitido. "
                "Este cliente aceita apenas GET/HEAD."
            )

        if path_or_url.startswith("http"):
            url = path_or_url
        else:
            url = f"{self.api_url}/{path_or_url.lstrip('/')}"

        for attempt in range(1, max_retries + 1):
            self._throttle()
            try:
                resp = self.session.request(
                    method, url, params=params, timeout=60
                )
            except requests.RequestException as exc:
                wait = min(2 ** attempt, 60)
                self.progress.warning(
                    f"Falha de rede ({exc}). Tentativa {attempt}/{max_retries}; "
                    f"retomará em {wait}s (checkpoint preservado)."
                )
                time.sleep(wait)
                continue
            finally:
                self._last_request_at = time.time()

            self._respect_rate_limit(resp)

            if resp.status_code == 403 and "rate limit" in resp.text.lower():
                reset = int(resp.headers.get("X-RateLimit-Reset") or time.time() + 60)
                wait = max(reset - int(time.time()) + 2, 10)
                self.progress.warning(
                    f"Rate limit atingido. Aguardando {wait}s (não perde progresso)."
                )
                time.sleep(wait)
                continue

            if resp.status_code in (502, 503, 504):
                wait = min(2 ** attempt, 60)
                self.progress.warning(
                    f"HTTP {resp.status_code}. Retry em {wait}s "
                    f"({attempt}/{max_retries})."
                )
                time.sleep(wait)
                continue

            if resp.status_code == 404:
                return resp

            if resp.status_code >= 400:
                raise RuntimeError(
                    f"GitHub API {resp.status_code} em {url}: {resp.text[:300]}"
                )
            return resp

        raise RuntimeError(f"Esgotaram-se as tentativas para {url}")

    def get_json(self, path_or_url: str, *, params: Optional[dict] = None) -> Any:
        resp = self.request("GET", path_or_url, params=params)
        if resp.status_code == 404:
            return None
        return resp.json()

    def get_paginated(
        self,
        path: str,
        *,
        params: Optional[dict] = None,
        per_page: int = 100,
    ) -> list[dict]:
        params = dict(params or {})
        params["per_page"] = per_page
        items: list[dict] = []
        url: Optional[str] = path
        query = params

        while url:
            resp = self.request("GET", url, params=query)
            if resp.status_code == 404:
                break
            batch = resp.json()
            if isinstance(batch, list):
                items.extend(batch)
            else:
                # algumas APIs encapsulam
                items.extend(batch.get("items") or [])
            next_url = _parse_next_link(resp.headers.get("Link"))
            url = next_url
            query = None  # next já traz querystring
        return items


def _parse_next_link(link_header: Optional[str]) -> Optional[str]:
    if not link_header:
        return None
    # Format: <url>; rel="next", <url>; rel="last"
    parts = [p.strip() for p in link_header.split(",")]
    for part in parts:
        if 'rel="next"' not in part:
            continue
        start = part.find("<")
        end = part.find(">")
        if start >= 0 and end > start:
            return part[start + 1 : end]
    return None


def split_repo(full_name: str) -> tuple[str, str]:
    owner, _, name = full_name.partition("/")
    return owner, name


def is_github_host(url: str) -> bool:
    host = urlparse(url).netloc
    return bool(host)
