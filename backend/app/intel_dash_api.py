"""Custom Intelligence Dashboards REST API (/api/v1/intelligence-dashboards). Reads are public (global news data); every write needs the existing administrative policy (localhost or SYNC_TOKEN)."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request
from pydantic import BaseModel, Field

from . import db, intel_dash
from .intel_dash import DashError
from .security import authorize_sync

router = APIRouter(prefix="/api/v1/intelligence-dashboards", tags=["intelligence-dashboards"])


def admin(request: Request, x_sync_token: str | None = Header(default=None)) -> None:
    authorize_sync(request, x_sync_token)


def run(fn, *a, **k):
    try:
        with db.connect(timeout=60) as con:
            return fn(con, *a, **k)
    except DashError as e:
        raise HTTPException(e.status, e.msg)


class TermIn(BaseModel):
    term: str = Field(..., max_length=intel_dash.TERM_MAX + 20)
    match_type: str = Field("word", max_length=10)
    is_exclusion: bool = False


class KeywordIn(BaseModel):
    display_name: str | None = Field(None, max_length=intel_dash.KEYWORD_MAX + 20)
    enabled: bool | None = None
    terms: list[TermIn] | None = Field(None, max_length=intel_dash.MAX_INCLUDE)
    excluded_terms: list[TermIn] | None = Field(None, max_length=intel_dash.MAX_EXCLUDE)


class DashIn(BaseModel):
    name: str | None = Field(None, max_length=intel_dash.NAME_MAX + 20)
    description: str | None = Field(None, max_length=intel_dash.DESC_MAX + 20)
    default_period: str | None = Field(None, max_length=10)
    keywords: list[KeywordIn] | None = Field(None, max_length=intel_dash.MAX_KEYWORDS)


class OrderIn(BaseModel):
    ids: list[int] = Field(..., max_length=100)


def _dump(m: BaseModel) -> dict:
    return m.model_dump(exclude_unset=True)


# ----------------------------------------------------------------------------- dashboards
@router.get("")
def list_all():
    return {"items": run(intel_dash.list_dashboards), "periods": [{"id": k, "label": v[1]} for k, v in intel_dash.PERIODS.items()] + [{"id": "custom", "label": "Custom Range"}],
            "limits": {"dashboards": intel_dash.MAX_DASHBOARDS, "keywords": intel_dash.MAX_KEYWORDS, "search_terms": intel_dash.MAX_INCLUDE, "excluded_terms": intel_dash.MAX_EXCLUDE},
            "match_types": [{"id": "word", "label": "Whole word"}, {"id": "phrase", "label": "Exact phrase"}, {"id": "exact", "label": "Exact text"}]}


@router.post("", status_code=201, dependencies=[Depends(admin)])
def create(b: DashIn):
    return run(intel_dash.create_dashboard, _dump(b))


@router.put("/order", dependencies=[Depends(admin)])
def order(b: OrderIn):
    return {"items": run(intel_dash.reorder_dashboards, b.ids)}


@router.get("/{did}")
def get_one(did: int):
    return run(intel_dash.get_dashboard, did)


@router.patch("/{did}", dependencies=[Depends(admin)])
def patch(did: int, b: DashIn):
    d = _dump(b)
    d.pop("keywords", None)
    return run(intel_dash.update_dashboard, did, d)


@router.delete("/{did}", dependencies=[Depends(admin)])
def delete(did: int):
    run(intel_dash.delete_dashboard, did)
    intel_dash.invalidate()
    return {"deleted": True}


@router.post("/{did}/duplicate", status_code=201, dependencies=[Depends(admin)])
def duplicate(did: int):
    return run(intel_dash.duplicate_dashboard, did)


# ----------------------------------------------------------------------------- keywords
@router.post("/{did}/keywords", status_code=201, dependencies=[Depends(admin)])
def add_keyword(did: int, b: KeywordIn):
    return run(intel_dash.add_keyword, did, _dump(b))


@router.put("/{did}/keywords/order", dependencies=[Depends(admin)])
def order_keywords(did: int, b: OrderIn):
    return run(intel_dash.reorder_keywords, did, b.ids)


@router.patch("/{did}/keywords/{kid}", dependencies=[Depends(admin)])
def patch_keyword(did: int, kid: int, b: KeywordIn):
    return run(intel_dash.update_keyword, did, kid, _dump(b))


@router.delete("/{did}/keywords/{kid}", dependencies=[Depends(admin)])
def delete_keyword(did: int, kid: int):
    return run(intel_dash.delete_keyword, did, kid)


# ----------------------------------------------------------------------------- statistics & articles (read-only, local data only)
PERIOD_RE, DATE_RE = "^(24h|48h|7d|30d|90d|custom)$", r"^\d{4}-\d{2}-\d{2}$"      # a fresh Query() per parameter: FastAPI must not share one FieldInfo between start and end


@router.get("/{did}/statistics")
def statistics(did: int, period: str | None = Query(None, pattern=PERIOD_RE), start: str | None = Query(None, pattern=DATE_RE), end: str | None = Query(None, pattern=DATE_RE)):
    return intel_dash.public(run(intel_dash.statistics, did, period, start, end))


@router.get("/{did}/keywords/{kid}/articles")
def keyword_articles(did: int, kid: int, period: str | None = Query(None, pattern=PERIOD_RE), start: str | None = Query(None, pattern=DATE_RE), end: str | None = Query(None, pattern=DATE_RE),
                     sort: str = Query("newest", pattern="^(newest|oldest|priority|source)$"), source: str | None = Query(None, max_length=60), event: str | None = Query(None, max_length=60),
                     page: int = Query(1, ge=1, le=2000), page_size: int = Query(20, ge=1, le=50)):
    return run(intel_dash.articles, did, kid, period, start, end, sort, source, event, page, page_size)
