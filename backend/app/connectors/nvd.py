"""NVD CVE API 2.0 (https://nvd.nist.gov/developers/vulnerabilities).

Public rate limit: 5 requests / rolling 30 s (50 with an API key) -> we space requests out.
Date-range filters may span at most 120 days.
"""
from __future__ import annotations

import json
import re
import threading
import time
from datetime import datetime, timedelta, timezone

from ..config import settings
from .http import SourceError, get_json
from ..correlation import parse_cpe

URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
PAGE = 2000

_lock = threading.Lock()
_last_call = 0.0


def _throttle() -> None:
    global _last_call
    interval = 0.7 if settings.nvd_api_key else 6.5
    with _lock:
        wait = _last_call + interval - time.monotonic()
        if wait > 0:
            time.sleep(wait)
        _last_call = time.monotonic()


def _call(params: dict) -> dict:
    _throttle()
    headers = {"apiKey": settings.nvd_api_key} if settings.nvd_api_key else None
    return get_json(URL, params=params, headers=headers)


def _best_cvss(metrics: dict) -> tuple[float | None, str | None]:
    for key, ver in (("cvssMetricV31", "3.1"), ("cvssMetricV40", "4.0"), ("cvssMetricV30", "3.0"), ("cvssMetricV2", "2.0")):
        entries = metrics.get(key) or []
        entries = sorted(entries, key=lambda e: e.get("type") != "Primary")
        for e in entries:
            try:
                s = float(e["cvssData"]["baseScore"])
            except (KeyError, TypeError, ValueError):
                continue
            if 0 <= s <= 10:
                return s, ver
    return None, None


def parse_item(item: dict) -> dict | None:
    cve = item.get("cve") if isinstance(item, dict) else None
    if not isinstance(cve, dict):
        return None
    cve_id = str(cve.get("id", "")).upper()
    if not CVE_RE.match(cve_id) or str(cve.get("vulnStatus", "")).lower() == "rejected":
        return None
    desc = next((d.get("value", "") for d in cve.get("descriptions") or [] if d.get("lang") == "en"), "")
    cvss, ver = _best_cvss(cve.get("metrics") or {})
    cpes: set[str] = set()
    vers: list[dict] = []
    for conf in cve.get("configurations") or []:
        for node in conf.get("nodes") or []:
            for m in node.get("cpeMatch") or []:
                if m.get("vulnerable") is True:
                    p = parse_cpe(m.get("criteria", ""))
                    if p:
                        cpes.add(":".join(p))
                        parts = re.split(r"(?<!\\):", m.get("criteria", ""))
                        v = {"v": p[1], "p": p[2], "ver": parts[5] if len(parts) > 5 and parts[5] not in ("*", "-") else None,
                             "fi": m.get("versionStartIncluding"), "fe": m.get("versionStartExcluding"), "ti": m.get("versionEndIncluding"), "te": m.get("versionEndExcluding"),
                             "complex": len(conf.get("nodes") or []) > 1 or conf.get("operator") == "AND" or node.get("operator") == "AND" or bool(node.get("negate"))}
                        if v not in vers and len(vers) < 200:
                            vers.append(v)
    return {
        "cve_id": cve_id,
        "published": cve.get("published"),
        "last_modified": cve.get("lastModified"),
        "cvss": cvss,
        "cvss_version": ver,
        "description": desc[:600],
        "cpes": ",".join(sorted(cpes)),
        "versions": json.dumps(vers, separators=(",", ":")) if vers else None,
    }


def _parse_page(payload: dict) -> tuple[list[dict], int]:
    vulns = payload.get("vulnerabilities")
    if not isinstance(vulns, list) or "totalResults" not in payload:
        raise SourceError("NVD payload malformed")
    items = [r for r in (parse_item(v) for v in vulns) if r]
    return items, int(payload["totalResults"])


def fetch_by_cpe(cpe_prefix: str, window_days: int, max_pages: int) -> tuple[list[dict], int, bool]:
    """Recently *published* CVEs matching a CPE prefix. Returns (items, totalResults, truncated)."""
    end = datetime.now(timezone.utc).replace(tzinfo=None)
    start = end - timedelta(days=window_days)
    fmt = "%Y-%m-%dT%H:%M:%S.000"
    items: list[dict] = []
    total = 0
    for page in range(max_pages):
        payload = _call({
            "virtualMatchString": cpe_prefix, "pubStartDate": start.strftime(fmt), "pubEndDate": end.strftime(fmt),
            "noRejected": "", "resultsPerPage": PAGE, "startIndex": page * PAGE,
        })
        got, total = _parse_page(payload)
        items += got
        if (page + 1) * PAGE >= total:
            break
    return items, total, total > max_pages * PAGE


def fetch_page(cpe_prefix: str, start_index: int = 0, per_page: int = PAGE, pub_start: datetime | None = None, pub_end: datetime | None = None) -> tuple[list[dict], int]:
    """ONE NVD call for a verified CPE prefix: (parsed CVEs, totalResults). Without dates it covers the whole history; with dates the span must be <= 120 days."""
    fmt = "%Y-%m-%dT%H:%M:%S.000"
    params = {"virtualMatchString": cpe_prefix, "noRejected": "", "resultsPerPage": per_page, "startIndex": start_index}
    if pub_start and pub_end:
        params.update(pubStartDate=pub_start.strftime(fmt), pubEndDate=pub_end.strftime(fmt))
    return _parse_page(_call(params))


def fetch_cve(cve_id: str) -> dict | None:
    items, _ = _parse_page(_call({"cveId": cve_id}))
    return items[0] if items else None
