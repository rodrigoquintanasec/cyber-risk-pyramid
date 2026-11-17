"""Progressive onboarding of catalogue sources (batches of 25/25/50/50/50/50). Each batch: validate -> enable the verified ones -> ONE controlled sync (same collector, same lock,
newest N entries per source, no history flood) -> check errors, duplicates and SQLite lock waits -> record the result. A batch with generalised failures halts the next ones."""
from __future__ import annotations

import json
import threading
import time
from datetime import datetime, timedelta, timezone

from .. import db
from . import collector, repo, source_admin, source_validation as sv
from .sources import BY_ID

BATCH_PLAN = {1: 25, 2: 25, 3: 50, 4: 50, 5: 50, 6: 50}
FAIL_RATE_HALT = 0.30
REVALIDATE_AFTER_DAYS = 7
_lock = threading.Lock()
state = {"running": False, "batch": None, "phase": None}


def _now() -> datetime:
    return datetime.now(timezone.utc)


def overview(con) -> dict:
    repo.sync_source_rows(con)
    rows = con.execute("SELECT batch,COUNT(*) n,SUM(enabled) en FROM news_source WHERE origin='catalog' GROUP BY batch").fetchall()
    last = {r["batch"]: dict(r) for r in con.execute("SELECT * FROM source_onboarding WHERE id IN (SELECT MAX(id) FROM source_onboarding GROUP BY batch)")}
    out = []
    for r in sorted(rows, key=lambda r: r["batch"] or 0):
        b = r["batch"]
        lr = last.get(b)
        out.append({"batch": b, "sources": r["n"], "enabled": r["en"] or 0, "last_run": ({**lr, "detail": None} if lr else None)})
    history = [dict(r, detail=None) for r in con.execute("SELECT * FROM source_onboarding ORDER BY id DESC LIMIT 30")]
    return {"batches": out, "history": history, "running": state["running"], "current": {k: state[k] for k in ("batch", "phase")}, "plan": BATCH_PLAN,
            "rule": f"A batch is halted when more than {int(FAIL_RATE_HALT * 100)}% of its sources fail their first sync; the next batch is then refused until it is reviewed."}


def _probe(stop: threading.Event, out: dict) -> None:
    """Measures how long a tiny write has to wait while the batch synchronises (SQLite lock health)."""
    while not stop.is_set():
        t = time.monotonic()
        try:
            with db.connect(timeout=20) as con:
                con.execute("INSERT INTO app_meta(key,value) VALUES('onboarding_probe',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (db.now_iso(),))
            out["max_wait"] = max(out["max_wait"], time.monotonic() - t)
        except Exception as e:
            out["locked"] += 1
            out["errors"].append(str(e)[:80])
        stop.wait(0.5)


def run_batch(batch: int, *, initial_entries: int | None = None, force: bool = False) -> dict:
    """Synchronous (the API runs it in a background thread). Returns the recorded result."""
    if batch not in BATCH_PLAN:
        raise source_admin.AdminError(422, f"batch must be one of {sorted(BATCH_PLAN)}")
    if not _lock.acquire(blocking=False):
        raise source_admin.AdminError(409, "An onboarding batch is already running")
    state.update(running=True, batch=batch, phase="preparing")
    rid = None
    try:
        with db.connect() as con:
            repo.sync_source_rows(con)
            if not force and batch > 1:
                prev = con.execute("SELECT status FROM source_onboarding WHERE batch=? ORDER BY id DESC LIMIT 1", (batch - 1,)).fetchone()
                if not prev or prev["status"] != "completed":
                    raise source_admin.AdminError(409, f"Batch {batch - 1} has not completed cleanly: review it first (or force)")
            ids = [r["id"] for r in con.execute("SELECT id FROM news_source WHERE origin='catalog' AND batch=? ORDER BY id", (batch,))]
            if not ids:
                raise source_admin.AdminError(404, "This batch has no sources")
            before = con.execute("SELECT COUNT(*) FROM news_item").fetchone()[0]
            rid = con.execute("INSERT INTO source_onboarding(batch,started_at,sources) VALUES(?,?,?)", (batch, db.now_iso(), len(ids))).lastrowid
        # 1-2) connectivity + structure: re-validate what has not been validated recently (network only)
        state["phase"] = "validating"
        stale_cut = (_now() - timedelta(days=REVALIDATE_AFTER_DAYS)).isoformat(timespec="seconds")
        with db.connect() as con:
            meta = {r["id"]: dict(r) for r in con.execute(f"SELECT id,validation_status,validated_at,enabled FROM news_source WHERE id IN ({','.join('?' * len(ids))})", ids)}
        revalidated = 0
        for sid in ids:
            m = meta[sid]
            if m["validation_status"] != "verified" or not m["validated_at"] or m["validated_at"] < stale_cut:
                source_admin.validate_source(sid)
                revalidated += 1
                time.sleep(0.3)
        with db.connect() as con:
            verified = [r["id"] for r in con.execute(f"SELECT id FROM news_source WHERE id IN ({','.join('?' * len(ids))}) AND validation_status='verified'", ids)]
            for sid in verified:
                repo.set_source_enabled(con, sid, True)           # only verified sources are ever enabled automatically
        # 4-8) one controlled sync with a lock-wait probe running beside it
        state["phase"] = "syncing"
        probe = {"max_wait": 0.0, "locked": 0, "errors": []}
        stop = threading.Event()
        th = threading.Thread(target=_probe, args=(stop, probe), daemon=True)
        th.start()
        summary = None
        for _ in range(60):                                       # the collector allows one cycle at a time: wait for a running one instead of overlapping it
            summary = collector.run_news_sync(force=True, only_ids=verified, initial_entries=initial_entries)
            if summary is not None:
                break
            time.sleep(5)
        stop.set()
        th.join(3)
        if summary is None:
            raise source_admin.AdminError(409, "The regular synchronisation kept running; try again")
        out = {o["id"]: o for o in summary.get("outcomes", [])}
        ok = sum(1 for o in out.values() if o.get("ok"))
        failed = sum(1 for o in out.values() if not o.get("ok"))
        rate = failed / max(1, ok + failed)
        with db.connect() as con:
            after = con.execute("SELECT COUNT(*) FROM news_item").fetchone()[0]
            bad = [{"id": i, "error": o.get("error"), "http": o.get("http")} for i, o in out.items() if not o.get("ok")]
        status = "halted" if (rate > FAIL_RATE_HALT or probe["locked"] > 0) else "completed"
        note = (f"{failed} of {ok + failed} sources failed their first sync ({int(rate * 100)}%): next batches are blocked" if rate > FAIL_RATE_HALT else
                f"SQLite lock errors during the batch: {probe['locked']}" if probe["locked"] else None)
        with db.connect() as con:
            con.execute("UPDATE source_onboarding SET finished_at=?,status=?,enabled=?,ok=?,failed=?,new_items=?,duplicate_items=?,max_write_wait=?,note=?,detail=? WHERE id=?",
                        (db.now_iso(), status, len(verified), ok, failed, summary["new"], summary["duplicate"], round(probe["max_wait"], 3), note,
                         json.dumps({"revalidated": revalidated, "not_verified": len(ids) - len(verified), "articles_before": before, "articles_after": after, "failed": bad[:40],
                                     "lock_errors": probe["errors"][:5], "updated": summary["updated"], "deferred": summary.get("deferred", 0)}), rid))
        return {"batch": batch, "status": status, "sources": len(ids), "enabled": len(verified), "ok": ok, "failed": failed, "new_items": summary["new"], "duplicate_items": summary["duplicate"],
                "max_write_wait_s": round(probe["max_wait"], 3), "lock_errors": probe["locked"], "articles_before": before, "articles_after": after, "note": note, "failures": bad[:10]}
    except Exception as e:
        if rid:
            with db.connect() as con:
                con.execute("UPDATE source_onboarding SET finished_at=?,status='failed',note=? WHERE id=?", (db.now_iso(), str(e)[:200], rid))
        raise
    finally:
        state.update(running=False, phase=None)
        _lock.release()
