"""Administration API of the Local Intelligence Database (/api/v1/intel-db). Reads are public (aggregate counts only); every operation that
downloads or changes data requires the existing administrative policy (local machine or SYNC_TOKEN). URLs are never taken from the client."""
from __future__ import annotations

import shutil
import time
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request
from pydantic import BaseModel, Field

from . import db, intel_import as ii
from .config import settings
from .intel_io import FeedError
from .security import authorize_sync

router = APIRouter(prefix="/api/v1/intel-db", tags=["intelligence-database"])
_cache: dict = {"t": 0.0, "v": None}


def admin(request: Request, x_sync_token: str | None = Header(default=None)) -> None:
    authorize_sync(request, x_sync_token)


def affected_rows(con) -> int:
    """(CVE, product) pairs. COUNT(*) over the 2.7M-row cve_cpe table took minutes on a cold 3 GB database and made the Settings page fail, so the
    precomputed per-product totals are used; the raw count is only taken while that table is still empty (fresh or test databases)."""
    if con.execute("SELECT 1 FROM cve_product_stats LIMIT 1").fetchone():
        return con.execute("SELECT COALESCE(SUM(cves),0) FROM cve_product_stats").fetchone()[0]
    return con.execute("SELECT COUNT(*) FROM cve_cpe").fetchone()[0]


def counts(con, fresh: float = 60.0) -> dict:
    if _cache["v"] and time.monotonic() - _cache["t"] < fresh:
        return _cache["v"]
    one = lambda q: con.execute(q).fetchone()[0]  # noqa: E731
    v = {"cves": one("SELECT COUNT(*) FROM nvd_cve"), "cpe_records": one("SELECT COUNT(*) FROM cpe_dictionary"), "cpe_match_criteria": one("SELECT COUNT(*) FROM cpe_match_criteria"),
         "cves_with_cvss": one("SELECT COUNT(*) FROM nvd_cve WHERE cvss IS NOT NULL"), "cves_with_cwe": one("SELECT COUNT(*) FROM nvd_cve n WHERE EXISTS (SELECT 1 FROM cve_cwe c WHERE c.cve_id=n.cve_id)"),
         "cves_in_kev": one("SELECT COUNT(*) FROM kev_entry"), "cves_with_epss": one("SELECT COUNT(*) FROM epss"), "affected_product_rows": affected_rows(con),
         "nvd_products": one("SELECT COUNT(*) FROM nvd_product"), "nvd_vendors": one("SELECT COUNT(*) FROM nvd_vendor"), "epss_score_date": one("SELECT MAX(score_date) FROM epss"), "epss_model_version": one("SELECT MAX(model_version) FROM epss")}
    _cache.update(t=time.monotonic(), v=v)
    return v


def invalidate() -> None:
    _cache.update(t=0.0, v=None)


def disk() -> dict:
    p = Path(settings.db_path)
    size = sum(f.stat().st_size for f in (p, Path(str(p) + "-wal"), Path(str(p) + "-shm")) if f.exists())
    try:
        free = shutil.disk_usage(p.parent).free
    except OSError:
        free = None
    return {"database_bytes": size, "disk_free_bytes": free}


def _alive(run) -> bool:
    if not run or not run["heartbeat"]:
        return False
    return (datetime.now(timezone.utc) - datetime.fromisoformat(run["heartbeat"])).total_seconds() < 180


@router.get("/status")
def status():
    with db.connect() as con:
        datasets = {k: ii.dataset_info(con, k) for k in ii.DATASETS}
        run = con.execute("SELECT * FROM intel_import_run WHERE status='running' ORDER BY id DESC LIMIT 1").fetchone()
        last = [dict(r) for r in con.execute("SELECT id,mode,datasets,status,started_at,finished_at,processed,new_items,updated_items,errors,message FROM intel_import_run ORDER BY id DESC LIMIT 8")]
        errs = [dict(r) for r in con.execute("SELECT run_id,dataset,item,message,at FROM intel_import_error ORDER BY id DESC LIMIT 20")]
        c = counts(con)
        index_rows = con.execute("SELECT COUNT(*) FROM cve_index").fetchone()[0]
    active = _alive(run)
    st = [d["status"] for d in datasets.values()]
    if active:
        overall = "importing" if any(s in ("not_initialized", "importing", "partial") for s in st) else "updating"
    elif all(s == "not_initialized" for s in st):
        overall = "not_initialized"
    elif "failed" in st and not any(s in ("complete", "partial", "stale") for s in st):
        overall = "failed"
    elif any(s in ("partial", "not_initialized", "importing", "failed") for s in st):
        overall = "partial"
    elif "stale" in st:
        overall = "stale"
    else:
        overall = "complete"
    successes = [d["last_success"] for d in datasets.values() if d["last_success"]]
    return {"overall": overall, "datasets": datasets, "counts": c, "last_successful_sync": max(successes) if successes else None, "listing_index_rows": index_rows,
            "active_run": ({k: run[k] for k in ("id", "mode", "datasets", "started_at", "heartbeat", "processed", "new_items", "updated_items", "errors", "current", "message")} if active else None),
            "recent_runs": last, "recent_errors": errs, **disk(),
            "limits": {"batch": settings.intel_batch, "max_download_mb": settings.intel_max_download_mb, "max_uncompressed_mb": settings.intel_max_uncompressed_mb, "throttle_ms": settings.intel_throttle_ms,
                       "epss_history_days": settings.epss_history_days},
            "note": "A partially imported dataset is never reported as complete. A CVE without version data does not mean it does not affect a product."}


@router.get("/estimate", dependencies=[Depends(admin)])
def estimate():
    try:
        return ii.estimate()
    except FeedError as e:
        raise HTTPException(502, str(e))


class InitIn(BaseModel):
    datasets: list[str] = Field(default_factory=lambda: list(ii.DATASETS), max_length=5)
    confirm: bool = False


def _start(mode: str, datasets: list[str] | None = None):
    r = ii.start(mode, datasets)
    if not r["started"]:
        raise HTTPException(409, "An import is already running" if r["reason"] == "already_running" else "Nothing to do")
    invalidate()
    return r


@router.post("/initialize", status_code=202, dependencies=[Depends(admin)])
def initialize(body: InitIn):
    """Start the FULL import. Requires an explicit confirmation after the estimate was shown; refuses when the disk cannot hold it."""
    if not body.confirm:
        raise HTTPException(422, "Confirmation required: review the estimate (GET /estimate) and send confirm=true")
    bad = [d for d in body.datasets if d not in ii.DATASETS]
    if bad:
        raise HTTPException(422, f"unknown dataset: {bad[0]}")
    free = disk()["disk_free_bytes"]
    if free is not None and free < settings.intel_min_free_gb * 1e9:
        raise HTTPException(409, f"Less than {settings.intel_min_free_gb} GB free on the disk: refusing to start")
    return _start("full", body.datasets)


@router.post("/sync", status_code=202, dependencies=[Depends(admin)])
def sync_now():
    with db.connect() as con:
        if not ii.dataset_info(con, "cve")["units_done"]:
            raise HTTPException(409, "The database is not initialised yet: use Initialize Database first")
    return _start("incremental", ["cve", "kev", "epss"])


@router.post("/epss", status_code=202, dependencies=[Depends(admin)])
def update_epss():
    return _start("enrichment", ["epss"])


@router.post("/kev", status_code=202, dependencies=[Depends(admin)])
def update_kev():
    return _start("enrichment", ["kev"])


@router.post("/resume", status_code=202, dependencies=[Depends(admin)])
def resume():
    return _start("resume")


@router.post("/stop", dependencies=[Depends(admin)])
def stop():
    ii.request_stop()
    return {"requested": True, "note": "The import stops at the next batch boundary; its checkpoint is saved and it can be resumed."}


@router.get("/runs/{rid}/errors")
def run_errors(rid: int, limit: int = Query(50, ge=1, le=200)):
    with db.connect() as con:
        return {"items": [dict(r) for r in con.execute("SELECT dataset,item,message,at FROM intel_import_error WHERE run_id=? ORDER BY id LIMIT ?", (rid, limit))]}
