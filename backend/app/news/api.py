from datetime import date, datetime, timezone

from pydantic import BaseModel
from fastapi import APIRouter, BackgroundTasks, Header, HTTPException, Query, Request

from .. import db
from ..catalog import BY_ID, CATALOG
from ..config import settings
from ..security import authorize_sync
from . import collector, repo
from .classify import CATEGORIES, CVE_RE
from .sources import BY_ID as _BY_ID, SOURCE_TYPES

router = APIRouter(prefix="/api/v1/news", tags=["news"])
NEWS_INTERVAL_MINUTES = settings.news_interval_minutes


def _collector_state(st: dict, sources: list[dict]) -> str:
    """live only when everything configured is operational and fresh; never 'live' otherwise."""
    if collector.state["running"] and not st["total_news"]:
        return "loading"
    if not st["last_success"]:
        return "loading" if st["sources_pending"] == st["sources_enabled"] else "error"
    if st["sources_active"] == 0:
        return "error"
    age = (datetime.now(timezone.utc) - datetime.fromisoformat(st["last_success"])).total_seconds() / 60
    if age > 2 * NEWS_INTERVAL_MINUTES or st["sources_failed"]:
        return "stale"
    return "live"


@router.get("/sources")
def sources():
    with db.connect() as con:
        repo.sync_source_rows(con)
        return {"sources": repo.list_sources(con),
                "types": [{"id": k, "label": v} for k, v in SOURCE_TYPES.items()]}


class SourcePatch(BaseModel):
    enabled: bool


@router.patch("/sources/{source_id}")
def patch_source(source_id: str, body: SourcePatch, request: Request, x_sync_token: str | None = Header(default=None)):
    """Enable/disable a configured source without touching code (same access rule as manual sync). Stored articles are kept."""
    authorize_sync(request, x_sync_token)
    if source_id not in _BY_ID:
        raise HTTPException(404, "Unknown source")
    with db.connect() as con:
        repo.sync_source_rows(con)
        repo.set_source_enabled(con, source_id, body.enabled)
        return next(s for s in repo.list_sources(con) if s["id"] == source_id)


@router.get("/stats")
def stats():
    with db.connect() as con:
        repo.sync_source_rows(con)
        st = repo.stats(con)
        src = repo.list_sources(con)
    st["state"] = _collector_state(st, src)
    st["syncing"] = collector.state["running"]
    st["interval_minutes"] = NEWS_INTERVAL_MINUTES
    st["technologies"] = [{"id": t.id, "name": t.name, "category": t.category} for t in CATALOG]
    st["failed_sources"] = [{"id": s["id"], "name": s["name"], "error": s["error"]} for s in src if s["health"] == "failed"]
    st["interval_minutes"] = NEWS_INTERVAL_MINUTES
    st["articles_per_source"] = {s["id"]: s["items_stored"] for s in src}
    return st


@router.get("")
def list_news(
    q: str | None = Query(None, max_length=100), source: str | None = Query(None, max_length=40),
    source_type: str | None = Query(None, max_length=40), category: str | None = Query(None, max_length=40),
    tech: str | None = Query(None, max_length=40), cve: str | None = Query(None, max_length=20),
    period: str = Query("all", pattern="^(24h|7d|30d|all)$"), watchlist: int | None = Query(None, ge=1),
    date_from: date | None = None, date_to: date | None = None,
    page: int = Query(1, ge=1, le=10000), page_size: int = Query(20, ge=1, le=repo.MAX_PAGE_SIZE),
):
    if category and category not in CATEGORIES:
        raise HTTPException(422, "Unknown category")
    if source_type and source_type not in SOURCE_TYPES:
        raise HTTPException(422, "Unknown source type")
    if tech and tech not in BY_ID:
        raise HTTPException(422, "Unknown technology")
    if cve and not CVE_RE.fullmatch(cve.strip()):
        raise HTTPException(422, "Invalid CVE id")
    with db.connect() as con:
        techs = None
        if watchlist is not None:
            from .. import watchlists
            techs = watchlists.tech_ids(con, watchlist)
            if techs is None:
                raise HTTPException(404, "Watchlist not found")
        return repo.search_news(con, q=q, source=source, source_type=source_type, category=category, tech=tech, techs=techs,
                                cve=cve.strip() if cve else None, period=period,
                                date_from=date_from.isoformat() if date_from else None,
                                date_to=date_to.isoformat() if date_to else None, page=page, page_size=page_size)


@router.post("/sync", status_code=202)
def sync_news(request: Request, bg: BackgroundTasks, force: bool = False, x_sync_token: str | None = Header(default=None)):
    authorize_sync(request, x_sync_token)
    if collector.state["running"]:
        return {"started": False, "reason": "Sync already running"}
    bg.add_task(collector.run_news_sync_and_enrich, force, False)
    return {"started": True}


@router.get("/{news_id}")
def get_news(news_id: str):
    if not news_id.isalnum() or len(news_id) > 40:
        raise HTTPException(404, "Not found")
    with db.connect() as con:
        item = repo.get_item(con, news_id)
    if not item:
        raise HTTPException(404, "Not found")
    return item
