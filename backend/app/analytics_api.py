"""Read-only, versioned analytics endpoints (/api/v1/analytics/*). Every aggregation is memoised per corpus build."""
from __future__ import annotations

import re
from datetime import date

from fastapi import APIRouter, Depends, HTTPException, Query

from . import analytics
from .catalog import BY_ID as TECH
from .news.classify import CATEGORIES, CVE_RE
from .news.sources import BY_ID as SOURCES

router = APIRouter(prefix="/api/v1/analytics", tags=["analytics"])
TID_RE = re.compile(r"^T\d{4}(\.\d{3})?$")


def filters(period: str = Query("7d", pattern="^(24h|7d|30d|90d|custom)$"), date_from: date | None = None, date_to: date | None = None,
            category: str | None = Query(None, max_length=40), source: str | None = Query(None, max_length=40), vendor: str | None = Query(None, max_length=60),
            tech: str | None = Query(None, max_length=40), mode: str = Query("all", pattern="^(all|comparable)$")) -> analytics.Filters:
    if category and category not in CATEGORIES:
        raise HTTPException(422, "Unknown category")
    if source and source not in SOURCES:
        raise HTTPException(422, "Unknown source")
    if tech and tech not in TECH:
        raise HTTPException(422, "Unknown technology")
    return analytics.Filters(period, date_from.isoformat() if date_from else None, date_to.isoformat() if date_to else None, category, source, vendor, tech, mode)


def _run(fn, *a, **k):
    try:
        return fn(*a, **k)
    except analytics.AnalyticsError as e:
        raise HTTPException(422, str(e))


F = Depends(filters)


@router.get("/meta")
def meta():
    return analytics.meta()


@router.get("/overview")
def overview(f: analytics.Filters = F):
    return _run(analytics.overview, f)


@router.get("/trends")
def trends(f: analytics.Filters = F):
    return _run(analytics.trends, f)


@router.get("/events")
def events(f: analytics.Filters = F, at: str | None = Query(None, max_length=40), span_hours: int = Query(24, ge=1, le=24), cve: str | None = Query(None, max_length=20),
           sort: str = Query("priority", pattern="^(priority|recent|sources)$"), page: int = Query(1, ge=1, le=200), page_size: int = Query(20, ge=1, le=50)):
    if cve:
        cve = cve.strip().upper()
        if not CVE_RE.fullmatch(cve):
            raise HTTPException(422, "Invalid CVE id")
    return _run(analytics.events_list, f, at=at, span_hours=span_hours, cve=cve, sort=sort, page=page, page_size=page_size)


@router.get("/vulnerabilities")
def vulnerabilities(f: analytics.Filters = F, cvss_min: float | None = Query(None, ge=0, le=10), cvss_max: float | None = Query(None, ge=0, le=10),
                    epss_min: float | None = Query(None, ge=0, le=1), epss_max: float | None = Query(None, ge=0, le=1), kev_only: bool = False,
                    q: str | None = Query(None, max_length=20)):
    return _run(analytics.vulnerabilities, f, cvss_min=cvss_min, cvss_max=cvss_max, epss_min=epss_min, epss_max=epss_max, kev_only=kev_only, q=q)


_SORT = "^(events|articles|cves|kev|sources)$"


@router.get("/vendors")
def vendors(f: analytics.Filters = F, sort: str = Query("events", pattern=_SORT), page: int = Query(1, ge=1, le=50), page_size: int = Query(15, ge=1, le=50)):
    return _run(analytics.entities, f, "vendor", sort, page, page_size)


@router.get("/technologies")
def technologies(f: analytics.Filters = F, sort: str = Query("events", pattern=_SORT), page: int = Query(1, ge=1, le=50), page_size: int = Query(15, ge=1, le=50)):
    return _run(analytics.entities, f, "technology", sort, page, page_size)


@router.get("/entity")
def entity(f: analytics.Filters = F, kind: str = Query(..., pattern="^(vendor|technology)$"), id: str = Query(..., max_length=80)):
    if kind == "technology" and id not in TECH:
        raise HTTPException(404, "Unknown technology")
    return _run(analytics.entity_detail, f, kind, id)


@router.get("/emerging")
def emerging(f: analytics.Filters = F, sort: str = Query("growth", pattern="^(growth|sources|recency|priority)$"), page: int = Query(1, ge=1, le=50), page_size: int = Query(15, ge=1, le=50)):
    return _run(analytics.emerging, f, sort, page, page_size)


@router.get("/attack")
def attack(f: analytics.Filters = F):
    return _run(analytics.attack_intel, f)


@router.get("/attack/technique/{tid}")
def attack_technique(tid: str, f: analytics.Filters = F):
    tid = tid.upper()
    if not TID_RE.match(tid):
        raise HTTPException(422, "Invalid technique id")
    d = _run(analytics.attack_technique, f, tid)
    if d is None:
        raise HTTPException(404, "Unknown technique")
    return d


@router.get("/quality")
def quality(f: analytics.Filters = F):
    return _run(analytics.quality, f)


@router.get("/history")
def history(limit: int = Query(60, ge=1, le=200), since: str | None = Query(None, max_length=30)):
    return analytics.history(limit, since)
