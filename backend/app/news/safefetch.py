"""SSRF-hardened feed fetcher: http(s) only, per-source host allow-list, private/internal IPs blocked,
redirects re-validated hop by hop, size/time limits, limited retries, conditional GET."""
from __future__ import annotations

import ipaddress
import socket
import time
from dataclasses import dataclass
from urllib.parse import urljoin, urlparse

import httpx

from ..config import settings
from .sources import FeedSource

MAX_BYTES = 15 * 1024 * 1024  # some feeds (e.g. Elastic Security Labs, 300+ full-text entries) exceed 5 MB
MAX_REDIRECTS = 3
UA = "cyber-risk-pyramid/0.3 (RSS reader; respects ETag/Last-Modified)"


class FetchError(Exception):
    def __init__(self, msg: str, status: int | None = None, retry_after: int | None = None):
        super().__init__(msg)
        self.status, self.retry_after = status, retry_after


def parse_retry_after(v: str | None) -> int | None:
    """Retry-After in seconds (HTTP-date form is honoured too). Capped at 24h."""
    if not v:
        return None
    v = v.strip()
    try:
        return max(0, min(int(v), 86400))
    except ValueError:
        pass
    try:
        from email.utils import parsedate_to_datetime
        from datetime import datetime, timezone
        return max(0, min(int((parsedate_to_datetime(v) - datetime.now(timezone.utc)).total_seconds()), 86400))
    except (TypeError, ValueError):
        return None


@dataclass
class FetchResult:
    status: int
    content: bytes | None  # None on 304
    etag: str | None
    last_modified: str | None
    final_url: str | None = None
    redirects: int = 0


def _is_public_ip(ip: str) -> bool:
    a = ipaddress.ip_address(ip)
    if isinstance(a, ipaddress.IPv6Address) and a.ipv4_mapped:
        a = a.ipv4_mapped
    return not (a.is_private or a.is_loopback or a.is_link_local or a.is_multicast or a.is_reserved or a.is_unspecified)


def peer_ok(response) -> bool:
    """The socket actually connected must be public: DNS rebinding between validate_url() and connect() would otherwise reach internal services."""
    try:
        stream = response.extensions.get("network_stream")
        addr = stream.get_extra_info("server_addr") if stream else None
        return True if not addr else _is_public_ip(addr[0])
    except Exception:
        return True


def validate_url(url: str, allowed_hosts: frozenset[str], resolver=socket.getaddrinfo) -> None:
    p = urlparse(url)
    if p.scheme not in ("http", "https"):
        raise FetchError(f"blocked scheme: {p.scheme!r}")
    host = (p.hostname or "").lower()
    if not host or host not in {h.lower() for h in allowed_hosts}:
        raise FetchError(f"host not in allow-list: {host!r}")
    try:
        ips = {i[4][0] for i in resolver(host, p.port or (443 if p.scheme == "https" else 80), type=socket.SOCK_STREAM)}
    except OSError as e:
        raise FetchError(f"DNS failure for {host}: {e}") from e
    if not ips or not all(_is_public_ip(ip) for ip in ips):
        raise FetchError(f"blocked non-public address for {host}")


def _once(src: FeedSource, etag: str | None, last_modified: str | None) -> FetchResult:
    headers = {"User-Agent": UA, "Accept": "application/rss+xml, application/atom+xml, application/xml, text/xml;q=0.9, */*;q=0.5"}
    if etag:
        headers["If-None-Match"] = etag
    if last_modified:
        headers["If-Modified-Since"] = last_modified
    url = src.url
    hops = 0
    deadline = time.monotonic() + settings.news_source_deadline
    with httpx.Client(timeout=settings.http_timeout, follow_redirects=False, headers=headers) as client:
        for _ in range(MAX_REDIRECTS + 1):
            validate_url(url, src.hosts)
            with client.stream("GET", url) as r:
                if not peer_ok(r):
                    raise FetchError("blocked non-public peer address")
                if r.status_code in (301, 302, 303, 307, 308):
                    loc = r.headers.get("location")
                    if not loc:
                        raise FetchError("redirect without location")
                    url = urljoin(url, loc)
                    hops += 1
                    continue
                if r.status_code == 304:
                    return FetchResult(304, None, etag, last_modified, url, hops)
                if r.status_code >= 400:
                    raise FetchError(f"HTTP {r.status_code}", r.status_code, parse_retry_after(r.headers.get("retry-after")))
                buf = bytearray()
                for chunk in r.iter_bytes():
                    buf += chunk
                    if len(buf) > MAX_BYTES:
                        raise FetchError("response too large")
                    if time.monotonic() > deadline:          # a slow-drip server must not hold a worker (and the whole cycle) hostage
                        raise FetchError(f"timeout: download exceeded {int(settings.news_source_deadline)}s")
                return FetchResult(r.status_code, bytes(buf), r.headers.get("etag"), r.headers.get("last-modified"), url, hops)
    raise FetchError("too many redirects")


def fetch_feed(src: FeedSource, etag: str | None = None, last_modified: str | None = None) -> FetchResult:
    last: Exception | None = None
    for attempt in range(2):
        try:
            return _once(src, etag, last_modified)
        except FetchError as e:
            last = e
            if e.status in (429, 503):
                break  # rate limited: back off through the scheduler instead of hammering the provider
            if str(e).startswith(("blocked", "host not", "HTTP 4")):
                break  # permanent: don't retry
        except httpx.HTTPError as e:
            last = FetchError(f"{type(e).__name__}: {e}"[:200])
        if attempt == 0:
            time.sleep(2)
    if isinstance(last, FetchError):
        raise last
    raise FetchError(str(last))
