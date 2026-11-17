"""Shared HTTP client with timeout and limited retries."""
from __future__ import annotations

import time

import httpx

from ..config import settings

UA = "cyber-risk-pyramid/0.2 (local threat-signal dashboard)"


class SourceError(Exception):
    pass


class RateLimited(SourceError):
    """The provider throttled us (HTTP 403/429/503 after retries). `retry_after` seconds is a hint for backoff."""
    def __init__(self, msg: str, retry_after: float = 0.0):
        super().__init__(msg)
        self.retry_after = retry_after


def get_json(url: str, params: dict | None = None, headers: dict | None = None) -> dict:
    h = {"User-Agent": UA, "Accept": "application/json", **(headers or {})}
    last: Exception | None = None
    throttled, hint = False, 0.0
    for attempt in range(settings.http_retries):
        try:
            r = httpx.get(url, params=params, headers=h, timeout=settings.http_timeout, follow_redirects=True)
            if r.status_code in (403, 429, 500, 502, 503, 504):
                wait = min(60.0, float(r.headers.get("Retry-After", 0) or 0) or 8.0 * (attempt + 1))
                last = SourceError(f"HTTP {r.status_code} from {httpx.URL(url).host}")
                throttled, hint = r.status_code in (403, 429, 503), max(hint, wait)
                if attempt < settings.http_retries - 1:
                    time.sleep(wait)
                continue
            r.raise_for_status()
            data = r.json()
            if not isinstance(data, dict):
                raise SourceError("Unexpected JSON payload")
            return data
        except (httpx.HTTPError, ValueError) as e:
            last = e
            if attempt < settings.http_retries - 1:
                time.sleep(2.0 * (attempt + 1))
    if throttled:
        raise RateLimited(f"{url.split('?')[0]}: {last}", hint)
    raise SourceError(f"{url.split('?')[0]}: {last}")
