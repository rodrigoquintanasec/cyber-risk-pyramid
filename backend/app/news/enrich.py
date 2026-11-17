"""Enriches CVEs cited in news with NVD/EPSS signals into the separate `intel_cve` table.
Never writes to nvd_cve/epss/tech_cve, so news can't influence the pyramid Threat Signal Score."""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from .. import db
from ..config import settings
from ..connectors import epss as epss_c, nvd as nvd_c
from ..connectors.http import SourceError

log = logging.getLogger("news.enrich")
NVD_BUDGET = 8


def recent_news_cves(con, days: int = 30, limit: int = 400) -> list[str]:
    since = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat(timespec="seconds")
    return [r[0] for r in con.execute(
        "SELECT c.cve_id FROM news_cve c JOIN news_item n ON n.id=c.news_id WHERE n.sort_ts>=? "
        "GROUP BY c.cve_id ORDER BY MAX(n.sort_ts) DESC LIMIT ?", (since, limit))]


def enrich_epss(cves: list[str]) -> int:
    """One bounded batch call; failures are tolerated (returns number stored)."""
    with db.connect() as con:
        ttl = (datetime.now(timezone.utc) - timedelta(hours=settings.epss_ttl_hours)).isoformat(timespec="seconds")
        have = {r[0] for r in con.execute("SELECT cve_id FROM intel_cve WHERE epss_fetched_at>=?", (ttl,))}
        have |= {r[0] for r in con.execute("SELECT cve_id FROM epss WHERE fetched_at>=?", (ttl,))}
    todo = [c for c in cves if c not in have][:400]
    if not todo:
        return 0
    try:
        rows = epss_c.fetch(todo)
    except SourceError as e:
        log.warning("EPSS enrichment failed: %s", e)
        return 0
    ts = db.now_iso()
    with db.connect() as con:
        for r in rows:
            con.execute("INSERT INTO intel_cve(cve_id,epss,epss_pct,epss_date,epss_fetched_at) VALUES(?,?,?,?,?) "
                        "ON CONFLICT(cve_id) DO UPDATE SET epss=excluded.epss,epss_pct=excluded.epss_pct,epss_date=excluded.epss_date,"
                        "epss_fetched_at=excluded.epss_fetched_at", (r["cve_id"], r["score"], r["percentile"], r["date"], ts))
    return len(rows)


def enrich_nvd(cves: list[str], budget: int = NVD_BUDGET) -> int:
    with db.connect() as con:
        have = {r[0] for r in con.execute("SELECT cve_id FROM intel_cve WHERE nvd_fetched_at IS NOT NULL")}
        have |= {r[0] for r in con.execute("SELECT cve_id FROM nvd_cve")}
    n = 0
    for c in [c for c in cves if c not in have][:budget]:
        try:
            item = nvd_c.fetch_cve(c)
        except SourceError as e:
            log.warning("NVD enrichment stopped: %s", e)
            break
        ts = db.now_iso()
        with db.connect() as con:
            if item:
                con.execute("INSERT INTO intel_cve(cve_id,cvss,cvss_version,published,description,cpes,nvd_fetched_at) VALUES(?,?,?,?,?,?,?) "
                            "ON CONFLICT(cve_id) DO UPDATE SET cvss=excluded.cvss,cvss_version=excluded.cvss_version,published=excluded.published,"
                            "description=excluded.description,cpes=excluded.cpes,nvd_fetched_at=excluded.nvd_fetched_at",
                            (c, item["cvss"], item["cvss_version"], item["published"], item["description"], item["cpes"], ts))
            else:  # unknown to NVD yet: remember the attempt so we don't retry every sync
                con.execute("INSERT INTO intel_cve(cve_id,nvd_fetched_at) VALUES(?,?) ON CONFLICT(cve_id) DO UPDATE SET nvd_fetched_at=excluded.nvd_fetched_at", (c, ts))
        n += 1
    return n


def run() -> dict:
    with db.connect() as con:
        cves = recent_news_cves(con)
    return {"epss": enrich_epss(cves), "nvd": enrich_nvd(cves)}
