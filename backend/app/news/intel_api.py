"""Versioned REST endpoints for the intelligence modules (read-only except briefing generation)."""
from __future__ import annotations

import re
from datetime import date

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

from .. import briefing, db
from ..catalog import BY_ID
from . import entities as ent
from . import intel
from .classify import CATEGORIES, CVE_RE

router = APIRouter(prefix="/api/v1", tags=["intelligence"])
PERIOD_RE = "^(24h|48h|7d|30d)$"
PERIOD_ALL_RE = "^(24h|48h|7d|30d|all)$"
EVT_RE = re.compile(r"^evt_[0-9a-f]{12}$")
TID_RE = re.compile(r"^T\d{4}(\.\d{3})?$")


def _corpus():
    return intel.get_corpus()


def _cve(v: str | None) -> str | None:
    if v is None:
        return None
    v = v.strip().upper()
    if not CVE_RE.fullmatch(v):
        raise HTTPException(422, "Invalid CVE id")
    return v


def _cluster(corpus, cid: str):
    if not EVT_RE.match(cid) or cid not in corpus.by_cluster:
        raise HTTPException(404, "Event not found")
    return corpus.by_cluster[cid]


def _check(category=None, tech=None):
    if category and category not in CATEGORIES:
        raise HTTPException(422, "Unknown category")
    if tech and tech not in BY_ID:
        raise HTTPException(422, "Unknown technology")


# ---- clusters / coverage / timeline / priority
@router.get("/clusters")
def clusters(period: str = Query("7d", pattern=PERIOD_ALL_RE), category: str | None = Query(None, max_length=40), tech: str | None = Query(None, max_length=40),
             vendor: str | None = Query(None, max_length=60), cve: str | None = Query(None, max_length=20), source: str | None = Query(None, max_length=40),
             q: str | None = Query(None, max_length=100), min_sources: int = Query(1, ge=1, le=30),
             sort: str = Query("priority", pattern="^(priority|recent|size)$"),
             page: int = Query(1, ge=1, le=1000), page_size: int = Query(20, ge=1, le=50)):
    _check(category, tech)
    c = _corpus()
    return intel.list_clusters(c, period=period, category=category, tech=tech, vendor=vendor, cve=_cve(cve), source=source, q=q,
                               min_sources=min_sources, sort=sort, page=page, page_size=page_size)


@router.get("/clusters/{cid}")
def cluster_detail(cid: str):
    c = _corpus()
    return intel.shape_cluster(c, _cluster(c, cid), detail=True)


@router.get("/clusters/{cid}/coverage")
def cluster_coverage(cid: str):
    return intel.coverage(_cluster(_corpus(), cid))


@router.get("/clusters/{cid}/timeline")
def cluster_timeline(cid: str):
    return intel.timeline(_cluster(_corpus(), cid))


@router.get("/priority")
def priority_top(period: str = Query("24h", pattern=PERIOD_ALL_RE), limit: int = Query(10, ge=1, le=50)):
    c = _corpus()
    out = intel.list_clusters(c, period=period, sort="priority", page=1, page_size=limit)
    cfg = intel.PRIORITY
    return {**out, "name": "News Priority Score", "note": "Reading priority for analysts — not a risk measurement; independent of the pyramid Threat Signal Score.",
            "weights": {"recency": cfg.w_recency, "cves": cfg.w_cve, "official": cfg.w_official, "tech": cfg.w_tech, "breadth": cfg.w_breadth}}


# ---- trending / observatory
@router.get("/trending")
def trending(period: str = Query("24h", pattern="^(24h|7d|30d)$")):
    return intel.trending(_corpus(), period)


@router.get("/observatory")
def observatory(period: str = Query("7d", pattern="^(24h|7d|30d)$"), limit: int = Query(10, ge=1, le=25)):
    return intel.observatory(_corpus(), period, limit)


# ---- explorer
@router.get("/intel/facets")
def facets():
    return intel.facets(_corpus())


@router.get("/intel/search")
def search(q: str | None = Query(None, max_length=100), cve: str | None = Query(None, max_length=20), vendor: str | None = Query(None, max_length=60),
           product: str | None = Query(None, max_length=60), tech: str | None = Query(None, max_length=40), malware: str | None = Query(None, max_length=60),
           ransomware: str | None = Query(None, max_length=60), mitre: str | None = Query(None, max_length=10), category: str | None = Query(None, max_length=40),
           source: str | None = Query(None, max_length=40), period: str = Query("all", pattern=PERIOD_ALL_RE),
           date_from: date | None = None, date_to: date | None = None,
           page: int = Query(1, ge=1, le=1000), page_size: int = Query(20, ge=1, le=50)):
    _check(category, tech)
    if mitre and not TID_RE.match(mitre.upper()):
        raise HTTPException(422, "Invalid MITRE technique id")
    return intel.search(_corpus(), q=q, cve=_cve(cve), vendor=vendor, product=product, tech=tech, malware=malware, ransomware=ransomware,
                        mitre=mitre.upper() if mitre else None, category=category, source=source, period=period,
                        date_from=date_from.isoformat() if date_from else None, date_to=date_to.isoformat() if date_to else None,
                        page=page, page_size=page_size)


# ---- MITRE ATT&CK
@router.get("/mitre/techniques")
def mitre_techniques(q: str | None = Query(None, max_length=60), mentioned: bool = True, limit: int = Query(50, ge=1, le=100)):
    cat = ent.mitre_catalog()
    meta = {"source": cat["source"], "version": cat["version"], "catalog_size": len(cat["techniques"])}
    if mentioned and not q:
        corpus = _corpus()
        cnt: dict[str, set] = {}
        for it in corpus.items:
            for t in it["entities"]["mitre"]:
                cnt.setdefault(t["id"], set()).add(it["id"])
        rows = [{"id": k, "name": cat["techniques"][k]["n"], "tactics": cat["techniques"][k]["t"], "url": ent.mitre_url(k), "articles": len(v)}
                for k, v in sorted(cnt.items(), key=lambda kv: -len(kv[1]))][:limit]
        return {**meta, "techniques": rows, "scope": "mentioned in stored news"}
    ql = (q or "").strip().lower()
    rows = [{"id": k, "name": v["n"], "tactics": v["t"], "url": ent.mitre_url(k)} for k, v in cat["techniques"].items()
            if not ql or ql in k.lower() or ql in v["n"].lower()][:limit]
    return {**meta, "techniques": rows, "scope": "official catalogue"}


@router.get("/mitre/techniques/{tid}")
def mitre_technique(tid: str):
    tid = tid.upper()
    cat = ent.mitre_catalog()["techniques"]
    if not TID_RE.match(tid) or tid not in cat:
        raise HTTPException(404, "Unknown technique")
    corpus = _corpus()
    arts = intel.search(corpus, mitre=tid, page=1, page_size=20)
    return {"id": tid, "name": cat[tid]["n"], "tactics": cat[tid]["t"], "url": ent.mitre_url(tid), "articles": arts,
            "mapping_rule": "Mapped only when the technique id is explicitly written in the article title or excerpt and exists in the official catalogue."}


# ---- briefings
class BriefingRequest(BaseModel):
    hours: int = Field(24, description="24, 48 or 168")
    force: bool = False


@router.post("/briefings", status_code=201)
def generate_briefing(req: BriefingRequest):
    if req.hours not in briefing.ALLOWED_HOURS:
        raise HTTPException(422, f"hours must be one of {sorted(briefing.ALLOWED_HOURS)}")
    return briefing.generate(req.hours, force=req.force)


@router.get("/briefings")
def list_briefings(limit: int = Query(10, ge=1, le=30)):
    return {"items": briefing.list_recent(limit)}


@router.get("/briefings/{bid}")
def get_briefing(bid: str):
    b = briefing.get(bid) if re.fullmatch(r"brf_[0-9a-z]{6,40}", bid) else None
    if not b:
        raise HTTPException(404, "Briefing not found")
    return b


@router.get("/briefings/{bid}/markdown")
def briefing_markdown(bid: str):
    b = briefing.get(bid) if re.fullmatch(r"brf_[0-9a-z]{6,40}", bid) else None
    if not b:
        raise HTTPException(404, "Briefing not found")
    return {"id": bid, "format": "markdown", "text": briefing.to_markdown(b)}
