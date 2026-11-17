import asyncio
import logging
from contextlib import asynccontextmanager

from fastapi import BackgroundTasks, FastAPI, Header, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware

from . import analytics, analytics_api, attack, catalog_api, intel_api as intel_db_api, intel_import, product_api, intel_dash_api, company_api, attack_api, db, graph_api, service, sync, vuln_api
from .news import api as news_api, collector, intel_api
from .config import settings
from .security import authorize_sync

logging.basicConfig(level=logging.INFO)


async def _scheduler():
    if settings.sync_on_startup:
        await asyncio.to_thread(sync.run_sync, False)
    while settings.sync_interval_minutes > 0:
        await asyncio.sleep(settings.sync_interval_minutes * 60)
        await asyncio.to_thread(sync.run_sync, False)


async def _news_scheduler():
    await asyncio.to_thread(collector.run_news_sync_and_enrich, False, True)
    while settings.news_interval_minutes > 0:
        await asyncio.sleep(settings.news_interval_minutes * 60)
        await asyncio.to_thread(collector.run_news_sync_and_enrich, False, True)


async def _intel_scheduler():
    """Keeps an initialised local intelligence database current. Never starts a full import: that is an explicit administrator action."""
    try:
        with db.connect() as con:
            n = intel_import.recover_interrupted(con)
            if n:
                logging.getLogger("intel").warning("%s interrupted import run(s) marked resumable", n)
    except Exception:
        logging.getLogger("intel").exception("intel recovery failed")
    while True:
        await asyncio.sleep(120)
        try:
            await asyncio.to_thread(intel_import.scheduled_tick)
            await asyncio.to_thread(intel_import.bootstrap_enrichment)
        except Exception:
            logging.getLogger("intel").exception("intel scheduler tick failed")
        await asyncio.sleep(1800)


async def _warm_analytics():
    try:
        await asyncio.to_thread(analytics.warm)
    except Exception:
        logging.getLogger("analytics").warning("analytics warm-up failed", exc_info=True)


async def _attack_scheduler():
    """Import ATT&CK only when never imported or stale (never on every start); then re-check hourly."""
    while True:
        with db.connect() as con:
            due = attack.needs_sync(con)
        if due:
            await asyncio.to_thread(attack.sync, False)
        if settings.attack_interval_hours <= 0:
            return
        await asyncio.sleep(3600)


@asynccontextmanager
async def lifespan(_: FastAPI):
    db.init_db()
    tasks = [asyncio.create_task(_scheduler()), asyncio.create_task(_news_scheduler()), asyncio.create_task(_attack_scheduler()), asyncio.create_task(_warm_analytics()), asyncio.create_task(_intel_scheduler())]
    yield
    for t in tasks:
        t.cancel()


app = FastAPI(title="Cyber Risk Pyramid API", version="0.1.0-beta", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=[o.strip() for o in settings.cors_origins.split(",") if o.strip()],
                   allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"], allow_headers=["*"])


from .news import source_admin_api  # noqa: E402
app.include_router(source_admin_api.router)      # before news_api: its /{news_id} catch-all would otherwise swallow /news/source-admin
app.include_router(news_api.router)
app.include_router(intel_api.router)
app.include_router(vuln_api.router)
app.include_router(attack_api.router)
app.include_router(graph_api.router)
app.include_router(analytics_api.router)
app.include_router(company_api.router)
app.include_router(catalog_api.router)
app.include_router(intel_db_api.router)
app.include_router(product_api.router)
app.include_router(product_api.cat_router)
app.include_router(intel_dash_api.router)


@app.get("/api/health")
def health():
    return {"ok": True}


@app.get("/api/technologies")
def technologies():
    return service.overview()


@app.get("/api/technologies/{tech_id}")
def technology(tech_id: str):
    data = service.technology(tech_id)
    if data is None:
        raise HTTPException(404, "Unknown technology")
    return data


@app.get("/api/status")
def status():
    return service.status()


@app.post("/api/sync", status_code=202)
def trigger_sync(request: Request, bg: BackgroundTasks, force: bool = False, x_sync_token: str | None = Header(default=None)):
    """Manual refresh. Local only (loopback client) unless/and guarded by SYNC_TOKEN."""
    authorize_sync(request, x_sync_token)
    if sync.state["running"]:
        return {"started": False, "reason": "Sync already running"}
    bg.add_task(sync.run_sync, force)
    return {"started": True}
