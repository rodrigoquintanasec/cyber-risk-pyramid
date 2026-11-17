"""REST endpoints: Vulnerability Explorer and Technology Watchlists."""
from __future__ import annotations

import re
from datetime import date

from fastapi import APIRouter, Header, HTTPException, Query, Request
from pydantic import BaseModel, Field

from . import db, vulns, watchlists
from .catalog import BY_ID, CATALOG
from .security import authorize_sync

router = APIRouter(prefix="/api/v1", tags=["vulnerabilities", "watchlists"])
CVE_PATH = re.compile(r"^CVE-\d{4}-\d{4,7}$", re.I)


def _cve(v: str) -> str:
    v = v.strip().upper()
    if not CVE_PATH.match(v):
        raise HTTPException(422, "Invalid CVE id")
    return v


def _techs(con, watchlist: int | None, tech: str | None) -> list[str] | None:
    if tech and tech not in BY_ID:
        raise HTTPException(422, "Unknown technology")
    sets = []
    if watchlist is not None:
        ids = watchlists.tech_ids(con, watchlist)
        if ids is None:
            raise HTTPException(404, "Watchlist not found")
        sets.append(set(ids))
    if tech:
        sets.append({tech})
    if not sets:
        return None
    return sorted(set.intersection(*sets))


# ------------------------------------------------------------ vulnerabilities
@router.get("/vulns")
def search_vulns(q: str | None = Query(None, max_length=100), vendor: str | None = Query(None, max_length=60), product: str | None = Query(None, max_length=60),
                 tech: str | None = Query(None, max_length=40), watchlist: int | None = Query(None, ge=1),
                 cvss_min: float | None = Query(None, ge=0, le=10), cvss_max: float | None = Query(None, ge=0, le=10),
                 epss_min: float | None = Query(None, ge=0, le=1), kev: bool | None = None, has_news: bool | None = None,
                 date_from: date | None = None, date_to: date | None = None,
                 sort: str = Query("published", pattern="^(published|cvss|epss|kev_date)$"), order: str = Query("desc", pattern="^(asc|desc)$"),
                 page: int = Query(1, ge=1, le=2000), page_size: int = Query(25, ge=1, le=50)):
    with db.connect() as con:
        techs = _techs(con, watchlist, tech)
        cov = None
        if tech:
            from . import catalog_api
            cov = next((r for r in catalog_api.rows(con) if r["id"] == tech), None)
        res = vulns.search(con, q=q, vendor=vendor, product=product, techs=techs, cvss_min=cvss_min, cvss_max=cvss_max, epss_min=epss_min, kev=kev,
                            has_news=has_news, date_from=date_from.isoformat() if date_from else None, date_to=date_to.isoformat() if date_to else None,
                            sort=sort, order=order, page=page, page_size=page_size, history=bool(tech))
        if cov:
            res["tech_coverage"] = {"id": cov["id"], "name": cov["name"], "coverage_state": cov["coverage_state"], "coverage_label": cov["coverage_label"], "sync": cov["sync"], "limitations": cov["limitations"],
                                    "recent_cves": cov["recent_cve_count"], "historical_cves": cov["historical_cve_count"],
                                    "note": None if cov["cves_complete"] else "Vulnerability data for this technology is still being collected: the list is incomplete and an empty result does not mean no vulnerabilities."}
        return res


@router.get("/vulns/coverage")
def vuln_coverage():
    with db.connect() as con:
        return vulns.coverage(con)


@router.get("/vulns/facets")
def vuln_facets(vendor: str | None = Query(None, max_length=60)):
    with db.connect() as con:
        from . import catalog_api
        cov = {r["id"]: r for r in catalog_api.rows(con)}
        return {**vulns.facets(con, vendor), "technologies": [{"id": t.id, "name": t.name, "category": t.category, "coverage_state": cov[t.id]["coverage_state"], "coverage_label": cov[t.id]["coverage_label"]} for t in CATALOG]}


@router.get("/vulns/{cve_id}")
def vuln_detail(cve_id: str):
    cve_id = _cve(cve_id)
    with db.connect() as con:
        d = vulns.detail(con, cve_id)
    if not d:
        raise HTTPException(404, "CVE is not in the local catalogue. You can look it up in NVD.")
    return d


@router.post("/vulns/{cve_id}/lookup")
def vuln_lookup(cve_id: str, request: Request, x_sync_token: str | None = Header(default=None)):
    """Fetch one CVE from NVD (rate limited, user-triggered). Stored apart from the pyramid scoring tables."""
    authorize_sync(request, x_sync_token)
    cve_id = _cve(cve_id)
    try:
        vulns.lookup(cve_id)
    except vulns.LookupError_ as e:
        raise HTTPException(e.status, e.msg)
    with db.connect() as con:
        return vulns.detail(con, cve_id)


# ------------------------------------------------------------ watchlists
class WatchlistIn(BaseModel):
    name: str = Field(max_length=80)
    technologies: list[str] = Field(default_factory=list, max_length=20)


class TechIn(BaseModel):
    tech_id: str = Field(max_length=40)


class RenameIn(BaseModel):
    name: str = Field(max_length=80)


def _run(fn, *a):
    try:
        with db.connect() as con:
            return fn(con, *a)
    except watchlists.WatchlistError as e:
        raise HTTPException(e.status, e.msg)


@router.get("/watchlists")
def list_watchlists():
    with db.connect() as con:
        return {"items": watchlists.list_all(con), "available_technologies": [{"id": t.id, "name": t.name, "category": t.category} for t in CATALOG]}


@router.post("/watchlists", status_code=201)
def create_watchlist(body: WatchlistIn, request: Request, x_sync_token: str | None = Header(default=None)):
    authorize_sync(request, x_sync_token)
    return _run(watchlists.create, body.name, body.technologies)


@router.get("/watchlists/{wid}")
def watchlist_summary(wid: int):
    return _run(watchlists.summary, wid)


@router.put("/watchlists/{wid}")
def rename_watchlist(wid: int, body: RenameIn, request: Request, x_sync_token: str | None = Header(default=None)):
    authorize_sync(request, x_sync_token)
    return _run(watchlists.rename, wid, body.name)


@router.delete("/watchlists/{wid}", status_code=204)
def delete_watchlist(wid: int, request: Request, x_sync_token: str | None = Header(default=None)):
    authorize_sync(request, x_sync_token)
    _run(watchlists.delete, wid)


@router.post("/watchlists/{wid}/technologies")
def add_technology(wid: int, body: TechIn, request: Request, x_sync_token: str | None = Header(default=None)):
    authorize_sync(request, x_sync_token)
    return _run(watchlists.add_tech, wid, body.tech_id)


@router.delete("/watchlists/{wid}/technologies/{tech_id}")
def remove_technology(wid: int, tech_id: str, request: Request, x_sync_token: str | None = Header(default=None)):
    authorize_sync(request, x_sync_token)
    return _run(watchlists.remove_tech, wid, tech_id)
