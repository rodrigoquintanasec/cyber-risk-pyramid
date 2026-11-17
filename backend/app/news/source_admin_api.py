"""Source administration API (/api/v1/news/source-admin). Reads are public; every write needs the existing administrative policy (localhost or SYNC_TOKEN).
Validation and onboarding fetch only configured/registered feed URLs through the SSRF-hardened fetcher."""
from __future__ import annotations

import threading

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request
from pydantic import BaseModel, Field

from .. import db
from ..security import authorize_sync
from . import source_admin as sa, source_onboarding as ob
from .sources import CATEGORIES

router = APIRouter(prefix="/api/v1/news/source-admin", tags=["source-admin"])


def admin(request: Request, x_sync_token: str | None = Header(default=None)) -> None:
    authorize_sync(request, x_sync_token)


def guard(fn, *a, **k):
    try:
        return fn(*a, **k)
    except sa.AdminError as e:
        raise HTTPException(e.status, e.msg)


class SourceIn(BaseModel):
    name: str | None = Field(None, max_length=120)
    url: str | None = Field(None, max_length=600)
    category: str | None = Field(None, max_length=30)
    publisher: str | None = Field(None, max_length=120)
    site: str | None = Field(None, max_length=320)
    country: str | None = Field(None, max_length=2)
    language: str | None = Field(None, max_length=8)


class EnabledIn(BaseModel):
    enabled: bool


class BulkIn(BaseModel):
    ids: list[str] = Field(..., min_length=1, max_length=sa.BULK_MAX)
    action: str = Field(..., pattern="^(enable|disable|validate)$")


@router.get("")
def list_sources(q: str | None = Query(None, max_length=80), category: str | None = Query(None, max_length=30), country: str | None = Query(None, max_length=2),
                 language: str | None = Query(None, max_length=8), status: str | None = Query(None, max_length=30), enabled: bool | None = None,
                 origin: str | None = Query(None, pattern="^(builtin|catalog|manual)$"), batch: int | None = Query(None, ge=1, le=20),
                 sort: str = Query("name", pattern="^(" + "|".join(sa.SORTS) + ")$"), order: str = Query("asc", pattern="^(asc|desc)$"),
                 page: int = Query(1, ge=1, le=1000), page_size: int = Query(25, ge=1, le=100)):
    if category and category not in CATEGORIES:
        raise HTTPException(422, "Unknown category")
    with db.connect() as con:
        return sa.query(con, q=q, category=category, country=country, language=language, status=status, enabled=enabled, origin=origin, batch=batch, sort=sort, order=order, page=page, page_size=page_size)


@router.get("/coverage")
def coverage():
    with db.connect() as con:
        return sa.coverage(con)


@router.get("/onboarding")
def onboarding():
    with db.connect() as con:
        return ob.overview(con)


@router.post("/onboarding/{batch}", status_code=202, dependencies=[Depends(admin)])
def start_onboarding(batch: int, force: bool = False, initial_entries: int | None = Query(None, ge=1, le=300)):
    if batch not in ob.BATCH_PLAN:
        raise HTTPException(422, "Unknown batch")
    if ob.state["running"]:
        raise HTTPException(409, "An onboarding batch is already running")
    err: list = []

    def run():
        try:
            ob.run_batch(batch, initial_entries=initial_entries, force=force)
        except Exception as e:  # recorded in source_onboarding by run_batch
            err.append(e)
    threading.Thread(target=run, name=f"onboarding-{batch}", daemon=True).start()
    return {"started": True, "batch": batch}


@router.post("", status_code=201, dependencies=[Depends(admin)])
def add_source(b: SourceIn):
    return guard(sa.add_manual, b.model_dump(exclude_unset=True))


@router.post("/bulk", dependencies=[Depends(admin)])
def bulk(b: BulkIn):
    return guard(sa.bulk, b.ids, b.action)


@router.patch("/{sid}", dependencies=[Depends(admin)])
def edit_source(sid: str, b: SourceIn):
    return guard(sa.edit, sid, b.model_dump(exclude_unset=True))


@router.delete("/{sid}", dependencies=[Depends(admin)])
def delete_source(sid: str):
    guard(sa.delete_manual, sid)
    return {"deleted": True}


@router.post("/{sid}/validate", dependencies=[Depends(admin)])
def validate(sid: str):
    return guard(sa.validate_source, sid)


@router.post("/{sid}/enabled", dependencies=[Depends(admin)])
def enabled(sid: str, b: EnabledIn):
    ok, why = guard(sa.set_enabled, sid, b.enabled)
    if not ok:
        raise HTTPException(409, why)
    return {"id": sid, "enabled": b.enabled}
