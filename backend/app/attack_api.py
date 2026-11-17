"""REST endpoints for MITRE ATT&CK intelligence: actors (intrusion sets), campaigns, techniques, software, relationships."""
from __future__ import annotations

import re

from fastapi import APIRouter, BackgroundTasks, Header, HTTPException, Query, Request

from . import attack, attack_news, db
from .security import authorize_sync

router = APIRouter(prefix="/api/v1", tags=["attack"])
ATT_ID = re.compile(r"^(G|C|S)\d{4}$|^T\d{4}(\.\d{3})?$", re.I)


def _id(v: str | None, prefix: str | None = None) -> str | None:
    if v is None or v == "":
        return None
    v = v.strip()
    if not ATT_ID.match(v) or (prefix and not v.upper().startswith(prefix)):
        raise HTTPException(422, "Invalid ATT&CK identifier")
    return v.upper()


def _ident(v: str) -> str:
    if not (ATT_ID.match(v) or attack.STIX_ID_RE.match(v)):
        raise HTTPException(404, "Not found")
    return v


@router.get("/attack/status")
def attack_status():
    with db.connect() as con:
        return attack.status(con)


@router.post("/attack/sync", status_code=202)
def attack_sync(request: Request, bg: BackgroundTasks, force: bool = False, x_sync_token: str | None = Header(default=None)):
    authorize_sync(request, x_sync_token)
    if attack.state["running"]:
        return {"started": False, "reason": "Sync already running"}
    bg.add_task(attack.sync, force)
    return {"started": True}


@router.get("/actors")
def actors(q: str | None = Query(None, max_length=80), technique: str | None = Query(None, max_length=10), software: str | None = Query(None, max_length=10),
           campaign: str | None = Query(None, max_length=10), sort: str = Query("name", pattern="^(name|techniques|modified)$"),
           page: int = Query(1, ge=1, le=1000), page_size: int = Query(24, ge=1, le=50)):
    with db.connect() as con:
        return attack.list_actors(con, q=q, technique=_id(technique, "T"), software=_id(software, "S"), campaign=_id(campaign, "C"), sort=sort, page=page, page_size=page_size)


@router.get("/actors/{ident}")
def actor(ident: str):
    with db.connect() as con:
        d = attack.actor_detail(con, _ident(ident))
    if not d:
        raise HTTPException(404, "Actor not found")
    return {**d, "news": attack_news.news_for(d["id"])}


@router.get("/campaigns")
def campaigns(q: str | None = Query(None, max_length=80), group: str | None = Query(None, max_length=10), technique: str | None = Query(None, max_length=10),
              software: str | None = Query(None, max_length=10), sort: str = Query("name", pattern="^(name|first_seen|modified)$"),
              page: int = Query(1, ge=1, le=1000), page_size: int = Query(24, ge=1, le=50)):
    with db.connect() as con:
        return attack.list_campaigns(con, q=q, group=_id(group, "G"), technique=_id(technique, "T"), software=_id(software, "S"), sort=sort, page=page, page_size=page_size)


@router.get("/campaigns/{ident}")
def campaign(ident: str):
    with db.connect() as con:
        d = attack.campaign_detail(con, _ident(ident))
    if not d:
        raise HTTPException(404, "Campaign not found")
    return {**d, "news": attack_news.news_for(d["id"])}


@router.get("/attack/techniques/{ident}")
def technique(ident: str):
    with db.connect() as con:
        d = attack.technique_detail(con, _ident(ident))
    if not d:
        raise HTTPException(404, "Technique not found")
    return d


@router.get("/attack/software/{ident}")
def software(ident: str):
    with db.connect() as con:
        d = attack.software_detail(con, _ident(ident))
    if not d:
        raise HTTPException(404, "Software not found")
    return d


@router.get("/attack/lookup")
def lookup(q: str = Query("", max_length=60), kind: str = Query("technique", pattern="^(technique|software|actor|campaign)$"), limit: int = Query(15, ge=1, le=30)):
    if not q.strip():
        return {"items": []}
    with db.connect() as con:
        return {"items": attack.lookup(con, q, kind, limit)}


@router.get("/attack/relationships")
def relationships(source: str | None = Query(None, max_length=80), target: str | None = Query(None, max_length=80),
                  type: str | None = Query(None, pattern="^(uses|attributed-to|subtechnique-of|revoked-by)$"),
                  page: int = Query(1, ge=1, le=2000), page_size: int = Query(50, ge=1, le=100)):
    for v in (source, target):
        if v:
            _ident(v)
    with db.connect() as con:
        return attack.relationships(con, source=source, target=target, rel_type=type, page=page, page_size=page_size)
