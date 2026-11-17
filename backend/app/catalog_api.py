"""Technology catalogue REST API (/api/v1/catalog). Reads are public (global data, nothing about companies); every write requires the
existing administrative policy (local machine or SYNC_TOKEN)."""
from __future__ import annotations

from collections import Counter

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request
from pydantic import BaseModel, Field

from . import catalog, catalog_db, db, service, techsync
from .catalog_db import CatalogError
from .catalog_seed import CATEGORIES
from .security import authorize_sync
from . import catalog as catalog_mod

router = APIRouter(prefix="/api/v1/catalog", tags=["catalog"])


def admin(request: Request, x_sync_token: str | None = Header(default=None)) -> None:
    authorize_sync(request, x_sync_token)


def run(fn, *a, **k):
    try:
        with db.connect() as con:
            return fn(con, *a, **k)
    except CatalogError as e:
        raise HTTPException(e.status, e.msg)


class TechIn(BaseModel):
    id: str | None = Field(None, max_length=60)
    name: str | None = Field(None, max_length=120)
    vendor: str | None = Field(None, max_length=100)
    product: str | None = Field(None, max_length=100)
    category: str | None = Field(None, max_length=60)
    kind: str | None = Field(None, max_length=20)
    description: str | None = Field(None, max_length=400)
    aliases: list[str] | None = Field(None, max_length=15)
    cpe_part: str | None = Field(None, max_length=1)
    cpe_vendor: str | None = Field(None, max_length=100)
    cpe_product: str | None = Field(None, max_length=100)
    news_terms: list[str] | None = Field(None, max_length=5)


# ----------------------------------------------------------------------------- read model
def rows(con) -> list[dict]:
    """One row per technology with coverage/CVE/KEV/news counts, computed from a handful of grouped queries (no per-technology scans)."""
    cves = {r[0]: r[1] for r in con.execute("SELECT tech_id,COUNT(*) FROM tech_cve GROUP BY tech_id")}
    kev = {r[0]: r[1] for r in con.execute("SELECT t.tech_id,COUNT(*) FROM tech_cve t JOIN kev_entry k ON k.cve_id=t.cve_id GROUP BY t.tech_id")}
    news = {r[0]: r[1] for r in con.execute("SELECT tech_id,COUNT(*) FROM news_tech GROUP BY tech_id")}
    hist = {r[0]: r[1] for r in con.execute("SELECT tech_id,COUNT(*) FROM tech_cve_hist GROUP BY tech_id")}
    hkev = {r[0]: r[1] for r in con.execute("SELECT h.tech_id,COUNT(*) FROM tech_cve_hist h JOIN kev_entry k ON k.cve_id=h.cve_id GROUP BY h.tech_id")}
    logs = {r["key"]: dict(r) for r in con.execute("SELECT key,truncated,last_success FROM query_log")}
    mon = catalog_db.monitored_ids(con)
    sync = techsync.statuses(con, mon)
    meta = {r["id"]: dict(r) for r in con.execute("SELECT id,last_sync,created_at,updated_at,source,edited FROM technology")}
    out = []
    for t in catalog.BY_ID.values():
        ok = [logs[q] for q in t.nvd_queries if q in logs]
        cov = {"nvd_queries_ok": len(ok), "nvd_queries_total": len(t.nvd_queries), "truncated_queries": sum(x["truncated"] for x in ok), "fraction": len(ok) / len(t.nvd_queries) if t.nvd_queries else 0.0}
        sy = sync[t.id]
        known = cves.get(t.id, 0) + hist.get(t.id, 0)
        cs = service.coverage_state(t, cov, known, kev.get(t.id, 0) + hkev.get(t.id, 0), t.id in mon, sy)
        newest = max((x["last_success"] for x in ok), default=None)
        out.append({"id": t.id, "name": t.name, "vendor": t.vendor, "product": t.product, "category": t.category, "kind": t.kind, "description": t.description, "aliases": list(t.aliases),
                    "enabled": t.enabled, "custom": t.custom, "monitor": t.monitor, "monitored": t.id in mon, "dashboard": t.dashboard,
                    "coverage_state": cs["state"], "coverage_label": cs["label"], "limitations": cs["limitations"],
                    "has_cpe": bool(t.nvd_queries), "score_possible": bool(t.nvd_queries), "correlation": {"kind": catalog_mod.match_kind(t), "source": t.correlation_source},
                    "cve_count": known, "recent_cve_count": cves.get(t.id, 0), "historical_cve_count": hist.get(t.id, 0), "kev_count": kev.get(t.id, 0) + hkev.get(t.id, 0),
                    "sync": sy, "cves_complete": sy["complete"] or not sy["applicable"], "news_count": news.get(t.id, 0), "nvd_queries": f"{cov['nvd_queries_ok']}/{cov['nvd_queries_total']}",
                    "last_sync": newest or meta.get(t.id, {}).get("last_sync")})
    return out


def _filter(items: list[dict], q, category, vendor, kind, coverage, status, monitored, pinned) -> list[dict]:
    ql = (q or "").strip().lower()
    res = []
    for r in items:
        if status == "enabled" and not r["enabled"] or status == "disabled" and r["enabled"]:
            continue
        if category and r["category"] != category: continue
        if vendor and r["vendor"].lower() != vendor.lower(): continue
        if kind and r["kind"] != kind: continue
        if coverage and r["coverage_state"] != coverage: continue
        if monitored is not None and r["monitored"] != monitored: continue
        if pinned is not None and r["dashboard"] != pinned: continue
        if ql and not (ql in r["name"].lower() or ql in r["id"] or ql in r["vendor"].lower() or ql in r["product"].lower() or any(ql in a.lower() for a in r["aliases"])): continue
        res.append(r)
    return res


@router.get("")
def list_catalog(q: str | None = Query(None, max_length=80), category: str | None = Query(None, max_length=60), vendor: str | None = Query(None, max_length=80),
                 kind: str | None = Query(None, pattern="^(product|family|platform|cloud)$"), coverage: str | None = Query(None, pattern="^(monitored|partial|catalog_only)$"),
                 status: str = Query("enabled", pattern="^(enabled|disabled|all)$"), monitored: bool | None = None, pinned: bool | None = None,
                 sort: str = Query("name", pattern="^(name|category|vendor|cves|kev|news)$"), page: int = Query(1, ge=1, le=200), page_size: int = Query(24, ge=1, le=50)):
    with db.connect() as con:
        if category and not con.execute("SELECT 1 FROM technology_category WHERE name=? COLLATE NOCASE", (category,)).fetchone():
            raise HTTPException(422, "Unknown category")
        items = _filter(rows(con), q, category, vendor, kind, coverage, status, monitored, pinned)
    key = {"name": lambda r: r["name"].lower(), "category": lambda r: (r["category"], r["name"].lower()), "vendor": lambda r: (r["vendor"].lower(), r["name"].lower()),
           "cves": lambda r: (-r["cve_count"], r["name"].lower()), "kev": lambda r: (-r["kev_count"], r["name"].lower()), "news": lambda r: (-r["news_count"], r["name"].lower())}[sort]
    items.sort(key=key)
    return {"items": items[(page - 1) * page_size: page * page_size], "total": len(items), "page": page, "page_size": page_size, "pages": max(1, -(-len(items) // page_size)),
            "note": "Catalogue entries are not necessarily monitored: only monitored technologies get NVD data. The absence of CVEs is not the absence of vulnerabilities."}


@router.get("/facets")
def facets():
    from . import categories
    with db.connect() as con:
        items = rows(con)
        cats = categories.list_all(con)
    en = [r for r in items if r["enabled"]]
    return {"total": len(items), "enabled": len(en), "categories": [{"id": c["id"], "name": c["name"], "active": c["active"], "count": sum(1 for r in en if r["category"] == c["name"])} for c in cats if c["active"] or c["enabled_technologies"]],
            "vendors": [{"name": k, "count": v} for k, v in sorted(Counter(r["vendor"] for r in en if r["vendor"]).items(), key=lambda kv: kv[0].lower())],
            "kinds": [{"name": k, "count": sum(1 for r in en if r["kind"] == k)} for k in catalog_db.KINDS],
            "coverage": {k: sum(1 for r in en if r["coverage_state"] == k) for k in ("monitored", "partial", "catalog_only")},
            "pinned": sum(1 for r in en if r["dashboard"]), "max_pinned": catalog_db.MAX_PINNED, "custom": sum(1 for r in items if r["custom"])}


@router.get("/cpe-search")
def cpe_search(q: str = Query(..., min_length=2, max_length=60), limit: int = Query(15, ge=1, le=30)):
    """Candidate official vendor/product ids for a new technology, from the LOCAL CPE dictionary (suggestions to validate, never auto-confirmed)."""
    from . import intel_corr
    with db.connect() as con:
        return intel_corr.search_cpe(con, q, limit)


@router.get("/{tid}")
def detail(tid: str):
    if tid not in catalog.BY_ID:
        raise HTTPException(404, "Technology not found")
    with db.connect() as con:
        base = next(r for r in rows(con) if r["id"] == tid)
        t = catalog.BY_ID[tid]
        full = service.build_technology(con, tid, detail=True)
        news = [dict(r) for r in con.execute(
            "SELECT n.id,n.title,n.url,n.published,n.collected_at,s.name AS source FROM news_tech nt JOIN news_item n ON n.id=nt.news_id JOIN news_source s ON s.id=n.source_id "
            "WHERE nt.tech_id=? ORDER BY n.sort_ts DESC LIMIT 10", (tid,))]
        reasons = catalog_db.monitored_reasons(con, tid)
        jobs = techsync.tech_status(con, tid, catalog_db.monitored_ids(con)).get("jobs", [])
    return {**base, "monitoring_reasons": reasons, "identifiers": {"cpe_matchers": [list(m) for m in t.cpe_matchers], "nvd_queries": list(t.nvd_queries), "kev_matchers": [list(m) for m in t.kev_matchers]},
            "news_patterns": list(t.news_patterns), "score": full["score"], "level": full["level"], "insufficient_reason": full["insufficient_reason"], "cves": full.get("cves", [])[:25],
            "news": news, "quality": full["quality"], "explanation": full["explanation"], "sync_status": full["sync"], "sync_jobs": jobs,
            "historical": full["historical"]}


# ----------------------------------------------------------------------------- administration (guarded)
@router.post("", status_code=201, dependencies=[Depends(admin)])
def create(body: TechIn):
    t = run(catalog_db.create_custom, body.model_dump(exclude_unset=True))
    return {"id": t.id}


@router.put("/{tid}", dependencies=[Depends(admin)])
def update(tid: str, body: TechIn):
    t = run(catalog_db.update_custom, tid, body.model_dump(exclude_unset=True))
    return {"id": t.id}


@router.post("/{tid}/enable", dependencies=[Depends(admin)])
def enable(tid: str):
    return {"id": run(catalog_db.set_enabled, tid, True).id, "enabled": True}


@router.post("/{tid}/disable", dependencies=[Depends(admin)])
def disable(tid: str):
    return {"id": run(catalog_db.set_enabled, tid, False).id, "enabled": False}


class MonitorIn(BaseModel):
    monitor: str = Field(..., pattern="^(auto|on|off)$")


class PinIn(BaseModel):
    pinned: bool


@router.post("/{tid}/sync", status_code=202, dependencies=[Depends(admin)])
def sync_now(tid: str):
    """Ask for a vulnerability-data synchronisation of ONE technology. Returns immediately; the work runs in the background runner within the NVD limits."""
    if tid not in catalog.BY_ID:
        raise HTTPException(404, "Technology not found")
    with db.connect() as con:
        r = techsync.request(con, tid)
    if r.get("accepted"):
        r["runner_started"] = techsync.start_background(tid)
    with db.connect() as con:
        r["sync"] = techsync.tech_status(con, tid, catalog_db.monitored_ids(con))
    return r


@router.get("/{tid}/sync")
def sync_status(tid: str):
    if tid not in catalog.BY_ID:
        raise HTTPException(404, "Technology not found")
    with db.connect() as con:
        return techsync.tech_status(con, tid, catalog_db.monitored_ids(con))


@router.put("/{tid}/monitoring", dependencies=[Depends(admin)])
def monitoring(tid: str, body: MonitorIn):
    return {"id": run(catalog_db.set_monitor, tid, body.monitor).id, "monitor": body.monitor}


@router.put("/{tid}/dashboard", dependencies=[Depends(admin)])
def dashboard(tid: str, body: PinIn):
    return {"id": run(catalog_db.set_dashboard, tid, body.pinned).id, "pinned": body.pinned}
