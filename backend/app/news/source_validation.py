"""Validation of candidate feeds: real fetch, real parse, real relevance check. HTTP 200 is never enough.

Statuses: verified | temporarily_unavailable | unsupported | invalid | duplicate.
No CAPTCHA / paywall / anti-bot control is bypassed: a challenge or 401/403 is reported as `unsupported`. Every hop is SSRF-checked
(public IPs only, http(s) only) and the address actually connected to is verified too."""
from __future__ import annotations

import re
import time
from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qsl, urljoin, urlencode, urlparse, urlunparse

import httpx

from ..config import settings
from . import collector
from .classify import canonical_url
from .safefetch import MAX_REDIRECTS, FetchError, UA, peer_ok as _peer_ok, validate_url

MAX_PROBE_BYTES = 6 * 1024 * 1024
STALE_DAYS = 400
MIN_RELEVANCE = 0.25
SECURITY_RE = re.compile(r"secur|vulnerab|malware|ransom|breach|cyber|exploit|\bcve-|phish|hack|attack|threat|privacy|zero[- ]day|botnet|apt\b|trojan|patch|advisor|leak|"
                         r"seguridad|sicherheit|sécurité|securit|segurança|безопасн|уязвим|セキュリティ|脆弱|보안|安全|漏洞|bezpiecz|veilig|privacid|datenschutz|incident|forensic|pentest|infosec|encrypt|spyware|ddos|cert\b|csirt", re.I)
CHALLENGE_RE = re.compile(rb"captcha|cf-chl|just a moment|attention required|access denied|enable javascript|bot detection|ddos protection", re.I)


def normalize_feed_url(url: str) -> str:
    """Comparable form: scheme-less, no www, no tracking params, no trailing slash."""
    p = urlparse((url or "").strip())
    q = sorted((k, v) for k, v in parse_qsl(p.query, keep_blank_values=True) if not k.lower().startswith("utm_"))
    host = (p.hostname or "").lower()
    host = host[4:] if host.startswith("www.") else host
    return urlunparse(("", host + (f":{p.port}" if p.port and p.port not in (80, 443) else ""), (p.path.rstrip("/") or "/").lower(), "", urlencode(q), "")).lstrip("/")


def registrable(host: str) -> str:
    parts = (host or "").lower().rstrip(".").split(".")
    return ".".join(parts[-3:]) if len(parts) >= 3 and parts[-2] in ("co", "com", "gov", "org", "ac", "go", "ne", "or") else ".".join(parts[-2:])


def _classify_http(status: int) -> str:
    if status in (401, 403, 451):
        return "unsupported"
    if status in (404, 410):
        return "invalid"
    if status == 429 or status >= 500 or status in (408, 425):
        return "temporarily_unavailable"
    return "invalid"


def probe(url: str, *, timeout: float | None = None, max_bytes: int = MAX_PROBE_BYTES) -> dict:
    """Fetch `url` following at most MAX_REDIRECTS safe redirects. Returns raw facts; never raises."""
    out = {"status": "invalid", "http": None, "final_url": url, "hosts": [], "content": None, "note": None, "redirects": 0}
    headers = {"User-Agent": UA, "Accept": "application/rss+xml, application/atom+xml, application/xml, text/xml;q=0.9, */*;q=0.5"}
    cur, hops = url, 0
    try:
        with httpx.Client(timeout=timeout or settings.http_timeout, follow_redirects=False, headers=headers) as client:
            for _ in range(MAX_REDIRECTS + 1):
                host = (urlparse(cur).hostname or "").lower()
                validate_url(cur, frozenset({host}))                      # scheme + public-IP check per hop
                out["hosts"].append(host)
                with client.stream("GET", cur) as r:
                    if not _peer_ok(r):
                        out.update(status="invalid", note="blocked: connected to a non-public address")
                        return out
                    if r.status_code in (301, 302, 303, 307, 308):
                        loc = r.headers.get("location")
                        if not loc:
                            out.update(note="redirect without location")
                            return out
                        cur, hops = urljoin(cur, loc), hops + 1
                        continue
                    out.update(http=r.status_code, final_url=cur, redirects=hops, etag=r.headers.get("etag"), last_modified=r.headers.get("last-modified"))
                    if r.status_code >= 400:
                        out.update(status=_classify_http(r.status_code), note=f"HTTP {r.status_code}")
                        return out
                    buf = bytearray()
                    for chunk in r.iter_bytes():
                        buf += chunk
                        if len(buf) > max_bytes:
                            out.update(note="response too large")
                            return out
                    out["content"] = bytes(buf)
                    out["status"] = "ok"
                    return out
            out["note"] = "too many redirects"
    except FetchError as e:
        out.update(status="invalid", note=str(e)[:160])
    except (httpx.TimeoutException, httpx.ConnectError, httpx.RemoteProtocolError, httpx.ReadError) as e:
        out.update(status="temporarily_unavailable", note=f"{type(e).__name__}"[:160])
    except httpx.HTTPError as e:
        out.update(status="temporarily_unavailable", note=f"{type(e).__name__}: {e}"[:160])
    return out


def assess(url: str, *, now: datetime | None = None, require_relevance: bool = True) -> dict:
    """Probe + parse + judge. The result carries what a registry row needs (title, language, newest, entries, final url, redirect hosts, signature)."""
    now = now or datetime.now(timezone.utc)
    p = probe(url)
    res = {"url": url, "status": p["status"], "http": p["http"], "note": p["note"], "final_url": p["final_url"], "hosts": p["hosts"], "entries": 0, "newest": None, "language": None,
           "title": None, "signature": [], "relevance": None, "etag": p.get("etag"), "last_modified": p.get("last_modified"), "validated_at": now.isoformat(timespec="seconds")}
    if p["status"] != "ok":
        return res
    body = p["content"] or b""
    if CHALLENGE_RE.search(body[:4000]) and b"<rss" not in body[:2000].lower() and b"<feed" not in body[:2000].lower():
        res.update(status="unsupported", note="anti-bot / access challenge page")
        return res
    try:
        items, meta = collector.parse_feed_ex(body)
    except ValueError as e:
        res.update(status="invalid", note=("HTML page, not a feed" if body.lstrip()[:15].lower().startswith((b"<!doctype", b"<html")) else str(e)[:120]))
        return res
    import feedparser
    f = feedparser.parse(body)
    res.update(entries=meta["entries"], newest=meta["newest"], language=meta["language"] if meta["language"] != "unknown" else None, title=(f.feed.get("title") or "")[:120] or None,
               signature=[canonical_url(i["url"]) for i in items[:10]])
    if not items:
        res.update(status="invalid", note="valid feed but no usable entries")
        return res
    texts = [f"{i['title']} {i['summary']}" for i in items[:30]]
    rel = sum(1 for t in texts if SECURITY_RE.search(t)) / len(texts)
    res["relevance"] = round(rel, 2)
    if meta["newest"] and datetime.fromisoformat(meta["newest"]) < now - timedelta(days=STALE_DAYS):
        res.update(status="invalid", note=f"inactive feed (newest entry {meta['newest'][:10]})")
    elif require_relevance and rel < MIN_RELEVANCE:
        res.update(status="invalid", note=f"not security-focused ({int(rel * 100)}% of entries match security terms)")
    else:
        res["status"] = "verified"
    return res


def jitter_sleep(base: float = 0.2) -> None:
    import random
    time.sleep(base + random.random() * base)
