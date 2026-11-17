"""Per-technology vulnerability data synchronisation with persisted, resumable progress.

Three kinds of work, kept apart:
  * INITIAL HISTORICAL BACKFILL (this module): for each verified CPE query of a MONITORED technology (or one an administrator requested).
      probe  -> one call: totalResults without date filter
      all    -> small products (<= nvd_backfill_all_cap CVEs): paginate the whole history
      windows-> bigger products: newest-first in <=119-day publication windows back to nvd_backfill_years (then marked history-limited)
    Progress (phase, cursor, counters) is stored in `tech_sync_job` after every API call, so an interrupted job resumes where it stopped.
  * INCREMENTAL UPDATES (sync.sync_nvd): the existing recent-publication window per query (feeds the Threat Signal Score).
  * ON-DEMAND ENRICHMENT (vulns.lookup / sync._nvd_lookups): single-CVE lookups, unchanged.
Every NVD call goes through the shared throttle; 403/429/503 stop the whole run and set an exponential backoff (`next_eligible`) that manual
requests do NOT bypass. At most one backfill runner exists at a time, and a technology already running is never duplicated.
"""
from __future__ import annotations

import json
import logging
import threading
from datetime import datetime, timedelta, timezone

from . import catalog, db
from .config import settings
from .connectors import nvd as nvd_c
from .connectors.http import RateLimited, SourceError

log = logging.getLogger("techsync")
WINDOW_DAYS = 119            # NVD accepts at most 120 consecutive days per publication window
STALE_AFTER = timedelta(minutes=10)   # an in_progress job whose heartbeat is older was interrupted and is resumable
MANUAL_CALLS = 30
MAX_ATTEMPTS = 4
LABELS = {"not_started": "Not Started", "pending": "Pending", "in_progress": "In Progress", "partial": "Partial", "completed": "Completed", "failed": "Failed", "rate_limited": "Rate Limited"}
_runner = threading.Lock()
_thread: dict = {"t": None}


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(d: datetime | None) -> str | None:
    return d.isoformat(timespec="seconds") if d else None


def _dt(s: str | None) -> datetime | None:
    if not s:
        return None
    d = datetime.fromisoformat(s)
    return d if d.tzinfo else d.replace(tzinfo=timezone.utc)


# ----------------------------------------------------------------------------- planning / requests
def ensure_jobs(con, tid: str) -> int:
    t = catalog.BY_ID.get(tid)
    if not t or not t.enabled:
        return 0
    for q in t.nvd_queries:
        con.execute("INSERT OR IGNORE INTO tech_sync_job(query,tech_id) VALUES(?,?)", (q, tid))
    return len(t.nvd_queries)


def request(con, tid: str) -> dict:
    """Administrator request: prioritise this technology. Does not bypass backoff, never duplicates a running job."""
    t = catalog.BY_ID.get(tid)
    if not t or not t.enabled:
        raise KeyError(tid)
    if not t.nvd_queries:
        return {"accepted": False, "reason": "no_cpe", "message": "This technology has no verified CPE identifier, so there is nothing to synchronise."}
    ensure_jobs(con, tid)
    now = _now()
    st = tech_status(con, tid)
    if st["status"] == "in_progress":
        return {"accepted": False, "reason": "already_running", "message": "A synchronisation is already running for this technology.", "sync": st}
    con.execute("UPDATE tech_sync_job SET requested_at=? WHERE tech_id=? AND status!='completed'", (_iso(now), tid))
    if st["status"] == "completed":
        # re-request of a finished technology: refresh from the beginning of the incremental window is handled by sync_nvd; nothing to backfill
        return {"accepted": False, "reason": "completed", "message": "Historical backfill is already completed; incremental updates keep it current.", "sync": st}
    return {"accepted": True, "sync": st}


def start_background(tid: str | None = None) -> bool:
    """Start (or keep) the single background runner. Returns False when one is already alive."""
    t = _thread["t"]
    if t is not None and t.is_alive():
        return False
    th = threading.Thread(target=lambda: drain(MANUAL_CALLS, manual=True), name="techsync", daemon=True)
    _thread["t"] = th
    th.start()
    return True


# ----------------------------------------------------------------------------- the job state machine
def _upsert(items: list[dict]) -> None:
    from . import sync
    with db.connect() as con:
        sync._upsert_nvd(con, items)


def _save(q: str, **cols) -> None:
    sets = ",".join(f"{k}=?" for k in cols)
    with db.connect() as con:
        con.execute(f"UPDATE tech_sync_job SET {sets} WHERE query=?", [*cols.values(), q])


def _step(job: dict) -> dict:
    """Perform exactly ONE API call for the job and return the column updates (progress is persisted by the caller)."""
    q = job["query"]
    cur = json.loads(job["cursor"] or "{}")
    phase, now = job["phase"], _now()
    if phase == "probe":
        _, total = nvd_c.fetch_page(q, 0, per_page=1)
        if total == 0:
            return {"total": 0, "status": "completed", "completed_at": _iso(now), "phase": "done", "cursor": None}
        if total <= settings.nvd_backfill_all_cap:
            return {"total": total, "phase": "all", "cursor": json.dumps({"start_index": 0})}
        return {"total": total, "phase": "windows", "cursor": json.dumps({"window_end": _iso(now), "start_index": 0, "horizon": _iso(now - timedelta(days=365 * settings.nvd_backfill_years))})}
    if phase == "all":
        start = cur.get("start_index", 0)
        items, total = nvd_c.fetch_page(q, start, per_page=nvd_c.PAGE)
        _upsert(items)
        nxt = start + nvd_c.PAGE
        upd = {"total": total, "fetched": job["fetched"] + len(items), "cursor": json.dumps({"start_index": nxt})}
        if nxt >= total:
            upd.update(status="completed", completed_at=_iso(now), phase="done")
        return upd
    if phase == "windows":
        end = _dt(cur["window_end"])
        start_w = end - timedelta(days=WINDOW_DAYS)
        si = cur.get("start_index", 0)
        items, wtotal = nvd_c.fetch_page(q, si, per_page=nvd_c.PAGE, pub_start=start_w, pub_end=end)
        _upsert(items)
        upd = {"fetched": job["fetched"] + len(items)}
        if si + nvd_c.PAGE < wtotal:
            cur["start_index"] = si + nvd_c.PAGE
        else:
            cur.update(window_end=_iso(start_w - timedelta(seconds=1)), start_index=0)
            if start_w <= _dt(cur["horizon"]):
                upd.update(status="completed", completed_at=_iso(now), phase="done", limited_by="horizon")
        upd["cursor"] = json.dumps(cur)
        return upd
    return {"status": "completed", "phase": "done"}


def run_job(job: dict, budget: int) -> tuple[int, str]:
    """Run up to `budget` API calls on one job. Returns (calls used, outcome) where outcome is one of
    done | budget | rate_limited | error."""
    q, used = job["query"], 0
    now = _now()
    _save(q, status="in_progress", started_at=job["started_at"] or _iso(now), heartbeat=_iso(now), last_attempt=_iso(now), attempts=job["attempts"] + 1, error=None, error_kind=None, next_eligible=None)
    job = dict(job, attempts=job["attempts"] + 1)
    while used < budget:
        try:
            upd = _step(job)
        except RateLimited as e:
            wait = max(e.retry_after, min(3 * 3600, 300 * 2 ** max(0, job["attempts"] - 1)))
            _save(q, status="rate_limited", error=str(e)[:300], error_kind="rate_limit", next_eligible=_iso(_now() + timedelta(seconds=wait)), heartbeat=None)
            return used, "rate_limited"
        except SourceError as e:
            wait = 600 * job["attempts"]
            _save(q, status="failed", error=str(e)[:300], error_kind="error", next_eligible=_iso(_now() + timedelta(seconds=wait)), heartbeat=None)
            return used, "error"
        used += 1
        ts = _iso(_now())
        upd.setdefault("status", "in_progress")
        upd.update(heartbeat=ts, calls=job["calls"] + 1, last_success=ts)
        if upd["status"] == "completed":
            upd["heartbeat"] = None
        _save(q, **upd)
        job = {**job, **upd}
        if upd["status"] == "completed":
            try:   # make the score's recent window current too, so the pyramid reflects the finished backfill
                with db.connect() as con:
                    last = con.execute("SELECT last_success FROM query_log WHERE key=?", (q,)).fetchone()
                if not last or not db.is_fresh(last[0], settings.nvd_ttl_hours):
                    used += recent_update(q)
            except RateLimited as e:
                _save(q, error=str(e)[:300], error_kind="rate_limit", next_eligible=_iso(_now() + timedelta(seconds=max(e.retry_after, 300))))
                return used, "rate_limited"
            except SourceError as e:
                _save(q, error=f"recent window: {e}"[:300], error_kind="error")
            return used, "done"
    _save(q, status="pending", heartbeat=None)    # budget spent: progress is kept, the job resumes next time
    return used, "budget"


def recent_update(q: str) -> int:
    """INCREMENTAL part for one query: the recent-publication window that feeds the score (same call sync.sync_nvd makes). Returns API calls used (>=1)."""
    from . import sync
    items, total, truncated = nvd_c.fetch_by_cpe(q, settings.nvd_window_days, settings.nvd_max_pages)
    with db.connect() as con:
        sync._upsert_nvd(con, items)
        con.execute("INSERT INTO query_log(key,last_success,total_results,truncated) VALUES(?,?,?,?) ON CONFLICT(key) DO UPDATE SET last_success=excluded.last_success,"
                    "total_results=excluded.total_results,truncated=excluded.truncated", (q, db.now_iso(), total, int(truncated)))
    return max(1, -(-total // nvd_c.PAGE)) if total else 1


# ----------------------------------------------------------------------------- scheduling
def _eligible_jobs(con, monitored: set[str], manual_only: bool) -> list[dict]:
    now = _now()
    out = []
    for r in con.execute("SELECT * FROM tech_sync_job WHERE status!='completed'"):
        r = dict(r)
        if r["tech_id"] not in catalog.BY_ID or not catalog.BY_ID[r["tech_id"]].enabled:
            continue
        if not (r["tech_id"] in monitored or r["requested_at"]):
            continue
        if manual_only and not r["requested_at"]:
            continue
        if r["status"] == "in_progress" and r["heartbeat"] and now - _dt(r["heartbeat"]) < STALE_AFTER:
            continue                                  # genuinely running elsewhere
        if r["next_eligible"] and _dt(r["next_eligible"]) > now:
            continue                                  # backoff is respected, even for manual requests
        out.append(r)
    # requested first, then jobs that already have progress (finish what was started), then the rest
    out.sort(key=lambda r: (r["requested_at"] is None, r["fetched"] == 0 and r["phase"] == "probe", r["tech_id"], r["query"]))
    return out


def drain(calls: int, manual: bool = False) -> dict:
    """Spend up to `calls` NVD calls on eligible jobs. Single runner process-wide; recomputes correlations and invalidates caches when data arrived."""
    if not _runner.acquire(blocking=False):
        return {"ran": False, "reason": "busy"}
    summary = {"ran": True, "calls": 0, "techs": set(), "stopped": None}
    try:
        from . import catalog_db
        with db.connect() as con:
            monitored = catalog_db.monitored_ids(con)
            for tid in monitored:
                ensure_jobs(con, tid)
            jobs = _eligible_jobs(con, monitored, manual)
        left = calls
        for job in jobs:
            if left <= 0:
                break
            used, outcome = run_job(job, left)
            left -= used
            summary["calls"] += used
            if used:
                summary["techs"].add(job["tech_id"])
            if outcome == "rate_limited":
                summary["stopped"] = "rate_limited"
                break                                  # stop everything: do not hammer a throttled API
        if summary["calls"]:
            finalize(summary["techs"])
        return summary
    except Exception:
        log.exception("techsync drain failed")
        raise
    finally:
        _runner.release()


def finalize(tids) -> None:
    """New CVEs arrived: rebuild derived tables/caches. Scores keep their semantics (recent window); history goes to tech_cve_hist."""
    from . import catalog_db, sync
    sync.recompute_correlations()
    with db.connect() as con:
        catalog_db.mark_synced(con, tids)
    invalidate_caches()


def invalidate_caches() -> None:
    try:
        from . import analytics, company_expo
        from .news import intel
        intel.reset_cache()
        analytics.reset()
        company_expo._memo.clear()
    except Exception:  # caches are best-effort
        log.warning("cache invalidation failed", exc_info=True)


# ----------------------------------------------------------------------------- status read model
def _local(con) -> dict | None:
    """When the local intelligence database is initialised it answers for every technology instantly: Completed if the CVE dataset is complete, else Partial."""
    from . import intel_corr
    st = intel_corr.local_state(con)
    if not st["initialized"]:
        return None
    status = "in_progress" if st["cve"] in ("importing",) else ("completed" if st["complete"] else "partial")
    return {"status": status, "label": LABELS[status], "last_success": st["last_success"], "source": "local database",
            "note": None if status == "completed" else "The local CVE database is only partially imported: counts are lower bounds until the import completes."}



def tech_status(con, tid: str, monitored: set[str] | None = None, now: datetime | None = None) -> dict:
    t = catalog.BY_ID[tid]
    now = now or _now()
    base = {"applicable": bool(t.nvd_queries), "queries_required": len(t.nvd_queries)}
    loc = _local(con) if t.nvd_queries else None
    if loc:
        return {**base, **loc, "queries_completed": len(t.nvd_queries) if loc["status"] == "completed" else 0, "cves_retrieved": con.execute("SELECT COUNT(*) FROM tech_cve WHERE tech_id=?", (tid,)).fetchone()[0]
                + con.execute("SELECT COUNT(*) FROM tech_cve_hist WHERE tech_id=?", (tid,)).fetchone()[0], "last_attempt": loc["last_success"], "last_error": None, "error_kind": None, "next_eligible": None,
                "history_limited": False, "jobs": []}
    if not t.nvd_queries:
        return {**base, "status": "not_started", "label": "Not Started", "queries_completed": 0, "cves_retrieved": 0, "last_success": None, "last_attempt": None, "last_error": None,
                "next_eligible": None, "history_limited": False, "note": "No verified CPE identifier: there is no NVD query to run for this technology."}
    jobs = [dict(r) for r in con.execute("SELECT * FROM tech_sync_job WHERE tech_id=?", (tid,))]
    jobs = [j for j in jobs if j["query"] in t.nvd_queries]
    done = [j for j in jobs if j["status"] == "completed"]
    pending = [j for j in jobs if j["status"] != "completed"]
    future = [j for j in pending if j["next_eligible"] and _dt(j["next_eligible"]) > now]
    limited = any(j["limited_by"] == "horizon" for j in done)
    status = _status_from(t, jobs, monitored is not None and tid in monitored, now)["status"]
    err = max((j for j in pending if j["error"]), key=lambda j: j["last_attempt"] or "", default=None)
    nxt = min((j["next_eligible"] for j in future), default=None)
    note = None
    if limited:
        note = f"History is limited to the last {settings.nvd_backfill_years} years for large products; older CVEs are not collected."
    elif status == "partial" and not err:
        note = "Backfill in progress or waiting for its next turn; counts are lower bounds until it completes."
    return {**base, "status": status, "label": LABELS[status], "queries_completed": len(done), "cves_retrieved": sum(j["fetched"] for j in jobs),
            "last_success": max((j["last_success"] for j in jobs if j["last_success"]), default=None), "last_attempt": max((j["last_attempt"] for j in jobs if j["last_attempt"]), default=None),
            "last_error": err["error"] if err else None, "error_kind": err["error_kind"] if err else None, "next_eligible": nxt, "history_limited": limited, "note": note,
            "jobs": [{"query": j["query"], "status": j["status"], "phase": j["phase"], "fetched": j["fetched"], "total": j["total"], "calls": j["calls"]} for j in jobs]}


def statuses(con, monitored: set[str]) -> dict[str, dict]:
    """tech_id -> light status for every technology that has queries (used by list views); one query for all jobs."""
    now = _now()
    loc = _local(con)
    by: dict[str, list] = {}
    for r in con.execute("SELECT * FROM tech_sync_job"):
        by.setdefault(r["tech_id"], []).append(dict(r))
    out = {}
    for tid, t in catalog.BY_ID.items():
        if loc and t.nvd_queries:
            out[tid] = {"status": loc["status"], "label": loc["label"], "applicable": True, "queries_completed": len(t.nvd_queries) if loc["status"] == "completed" else 0,
                        "queries_required": len(t.nvd_queries), "complete": loc["status"] == "completed"}
        else:
            out[tid] = _status_from(t, by.get(tid, []), tid in monitored, now)
    return out


def _status_from(t, jobs: list[dict], monitored: bool, now: datetime) -> dict:
    if not t.nvd_queries:
        return {"status": "not_started", "label": "Not Started", "applicable": False, "queries_completed": 0, "queries_required": 0, "complete": False}
    jobs = [j for j in jobs if j["query"] in t.nvd_queries]
    done = [j for j in jobs if j["status"] == "completed"]
    pending = [j for j in jobs if j["status"] != "completed"]
    progress = any(j["fetched"] > 0 or j["status"] == "completed" or j["phase"] != "probe" for j in jobs)
    limited = any(j["limited_by"] == "horizon" for j in done)
    fresh = lambda j: j["heartbeat"] and now - _dt(j["heartbeat"]) < STALE_AFTER  # noqa: E731
    future = [j for j in pending if j["next_eligible"] and _dt(j["next_eligible"]) > now]
    if len(done) == len(t.nvd_queries) and not limited:
        st = "completed"
    elif any(j["status"] == "in_progress" and fresh(j) for j in jobs):
        st = "in_progress"
    elif any(j["status"] == "rate_limited" for j in pending) and (future or not progress):
        st = "rate_limited"
    elif any(j["status"] == "failed" for j in pending) and not progress:
        st = "failed"
    elif progress or limited:
        st = "partial"
    elif monitored or any(j["requested_at"] for j in jobs):
        st = "pending"
    else:
        st = "not_started"
    return {"status": st, "label": LABELS[st], "applicable": True, "queries_completed": len(done), "queries_required": len(t.nvd_queries), "complete": st == "completed"}
