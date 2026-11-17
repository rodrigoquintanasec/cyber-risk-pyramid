"""RSS/Atom collector. One failing source never stops the others.

Per sync: only ENABLED sources are fetched, sources in backoff are skipped (unless forced), at most `WORKERS` requests run
at once, ETag / Last-Modified make unchanged feeds free, Retry-After and exponential backoff protect providers, and
`only_due` (used by the scheduler) skips sources that were fetched recently so a restart never repeats a full sync.
"""
from __future__ import annotations

import logging
import re
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone

import feedparser

from .. import db
from ..config import settings
from . import repo
from .classify import clean_text, safe_url
from .safefetch import FetchError, fetch_feed
from . import sources as registry
from .sources import FeedSource

log = logging.getLogger("news")
_lock = threading.Lock()
state = {"running": False, "started": None}
MAX_ENTRIES = 300
CHUNK = 40                                  # articles written per transaction: write locks stay in the tens of milliseconds
BACKOFF_BASE_MIN = 30
BACKOFF_MAX_H = 6
EN_WORDS = frozenset("the of and to in for on with is are a an by from at as this that new how what why after over".split())


def _dt(st) -> str | None:
    if not st:
        return None
    try:
        return datetime(*st[:6], tzinfo=timezone.utc).isoformat(timespec="seconds")
    except (TypeError, ValueError):
        return None


def detect_language(feed_lang: str | None, titles: list[str]) -> str:
    """Declared feed language (primary subtag) or a conservative English check over titles; 'unknown' otherwise."""
    if feed_lang and re.match(r"^[A-Za-z]{2,3}", feed_lang):
        return feed_lang[:2].lower()
    words = " ".join(titles[:20]).lower().split()
    if len(words) >= 8 and sum(w in EN_WORDS for w in words) / len(words) >= 0.06:
        return "en"
    return "unknown"


def parse_feed_ex(content: bytes) -> tuple[list[dict], dict]:
    """Validate and normalise entries (newest first, capped). Raises ValueError if the payload is not a usable feed."""
    f = feedparser.parse(content)
    if not f.entries and not f.get("version"):
        raise ValueError(f"not a valid RSS/Atom feed ({type(f.get('bozo_exception')).__name__})")
    out = []
    for e in f.entries:
        url = safe_url(e.get("link"))
        title = clean_text(e.get("title"), 300)
        if not url or not title:
            continue
        summ = e.get("summary") or (e.get("content") or [{}])[0].get("value") or ""
        out.append({
            "guid": (e.get("id") or None) and str(e.get("id"))[:500],
            "url": url[:2000], "title": title, "summary": clean_text(summ, 400),
            "published": _dt(e.get("published_parsed") or e.get("updated_parsed")),
            "feed_updated": _dt(e.get("updated_parsed")) if "updated" in e else None,
            "tags": [clean_text(t.get("term"), 60) for t in e.get("tags", []) if t.get("term")][:10],
        })
    out.sort(key=lambda x: x["published"] or "", reverse=True)   # keep the NEWEST entries when a feed is huge
    total = len(out)
    out = out[:MAX_ENTRIES]
    dated = [x["published"] for x in out if x["published"]]
    meta = {"entries": total, "undated": sum(1 for x in out if not x["published"]), "newest": max(dated) if dated else None,
            "language": detect_language(f.feed.get("language"), [x["title"] for x in out])}
    return out, meta


def parse_feed(content: bytes) -> list[dict]:
    return parse_feed_ex(content)[0]


def backoff_until(failures: int, retry_after: int | None = None, now: datetime | None = None, jitter: float = 0.0) -> str:
    """Exponential backoff (30 min, 1 h, 2 h ... capped at 6 h) with optional +/- jitter so sources that failed together do not return together;
    a provider's Retry-After wins when longer."""
    import random
    now = now or datetime.now(timezone.utc)
    secs = min(BACKOFF_MAX_H * 3600, BACKOFF_BASE_MIN * 60 * 2 ** max(0, failures - 1))
    secs = int(secs * (1 + random.uniform(-jitter, jitter))) if jitter else secs
    return (now + timedelta(seconds=max(secs, retry_after or 0))).isoformat(timespec="seconds")


def _fetch(src: FeedSource, etag, lm, force):
    try:
        return src, fetch_feed(src, None if force else etag, None if force else lm), None
    except FetchError as e:
        return src, None, e
    except Exception as e:  # never propagate
        return src, None, FetchError(f"{type(e).__name__}: {e}"[:200])


def _record(con, src_id: str, ok: bool, error=None, items=0, etag=None, lm=None, res=None, meta=None, err: FetchError | None = None) -> None:
    ts = db.now_iso()
    if ok:
        newest = (meta or {}).get("newest")
        con.execute("UPDATE news_source SET status='ok',last_attempt=?,last_success=?,error=NULL,consecutive_failures=0,backoff_until=NULL,"
                    "last_items=?,etag=?,last_modified=?,last_http=?,final_url=?,redirects=?,language=COALESCE(?,language),"
                    "newest_item=COALESCE(?,newest_item),undated=?,validation_status='verified',validated_at=?,validation_note=NULL WHERE id=?",
                    (ts, ts, items, etag, lm, res.status if res else None, res.final_url if res else None, res.redirects if res else 0,
                     (meta or {}).get("language"), newest, (meta or {}).get("undated", 0), ts, src_id))
    else:
        n = (con.execute("SELECT consecutive_failures FROM news_source WHERE id=?", (src_id,)).fetchone() or [0])[0] + 1
        con.execute("UPDATE news_source SET status='error',last_attempt=?,error=?,consecutive_failures=?,last_http=?,backoff_until=? WHERE id=?",
                    (ts, (error or "")[:300], n, getattr(err, "status", None), backoff_until(n, getattr(err, "retry_after", None), jitter=0.15), src_id))


def select_sources(con, sources, force: bool, only_due: bool, now: datetime | None = None) -> tuple[list[FeedSource], dict]:
    """Enabled sources that may be fetched now. Returns (sources, skipped-counts)."""
    now = now or datetime.now(timezone.utc)
    rows = {r["id"]: r for r in con.execute("SELECT id,enabled,backoff_until,last_attempt,status FROM news_source")}
    due_after = settings.news_interval_minutes * 60 * 0.9
    out, skipped = [], {"disabled": 0, "backoff": 0, "not_due": 0}
    for s in sources:
        r = rows.get(s.id)
        if r is not None and not r["enabled"]:
            skipped["disabled"] += 1
        elif r is not None and not force and r["backoff_until"] and datetime.fromisoformat(r["backoff_until"]) > now:
            skipped["backoff"] += 1
        elif r is not None and only_due and r["last_attempt"] and r["status"] != "error" and (now - datetime.fromisoformat(r["last_attempt"])).total_seconds() < due_after:
            skipped["not_due"] += 1
        else:
            out.append(s)
    out.sort(key=lambda s: (rows[s.id]["last_attempt"] or "") if s.id in rows else "")     # never attempted first, then the longest-waiting
    return out, skipped


def run_news_sync(force: bool = False, sources=None, only_due: bool = False, only_ids=None, initial_entries: int | None = None, max_items: int | None = None) -> dict | None:
    """One cycle at a time (non-blocking lock). `only_ids` restricts the cycle (batch onboarding); a source with no stored article yet is limited to its newest
    `initial_entries` items (no historical flood); `max_items` caps what one cycle writes, the rest of the feeds wait for the next cycle."""
    if not _lock.acquire(blocking=False):
        return None
    summary = {"new": 0, "updated": 0, "duplicate": 0, "ok": 0, "failed": 0, "deferred": 0, "skipped": {}}
    started, outcomes, written = db.now_iso(), [], 0
    cap = max_items if max_items is not None else settings.news_max_items_per_run
    first_n = initial_entries if initial_entries is not None else settings.news_initial_entries
    try:
        state.update(running=True, started=db.now_iso())
        with db.connect() as con:
            repo.sync_source_rows(con)
            pool = list(registry.SOURCES) if sources is None else list(sources)
            if only_ids is not None:
                pool = [s for s in pool if s.id in set(only_ids)]
            todo, summary["skipped"] = select_sources(con, pool, force, only_due)
            meta_rows = {r["id"]: (r["etag"], r["last_modified"]) for r in con.execute("SELECT id,etag,last_modified FROM news_source")}
            stored = {r[0]: r[1] for r in con.execute("SELECT source_id,COUNT(*) FROM news_item GROUP BY source_id")}
            cve_techs = repo.load_cve_techs(con)
        with ThreadPoolExecutor(max_workers=settings.news_workers) as ex:       # bounded: never all sources at once; network only, no database connection open
            futs = [ex.submit(_fetch, s, *meta_rows.get(s.id, (None, None)), force) for s in todo]
            for fut in as_completed(futs):
                src, res, err = fut.result()
                try:
                    if err:
                        raise err
                    if res.status == 304:
                        with db.connect() as con:
                            _record(con, src.id, True, items=0, etag=res.etag, lm=res.last_modified, res=res)
                        summary["ok"] += 1
                        outcomes.append({"id": src.id, "ok": True, "http": res.status, "new": 0})
                        continue
                    items, meta = parse_feed_ex(res.content)                    # parsing happens with no transaction open
                    if not stored.get(src.id):
                        items = items[:first_n]
                    if written >= cap:
                        summary["deferred"] += 1
                        outcomes.append({"id": src.id, "ok": True, "http": res.status, "deferred": True})
                        continue
                    n_new = 0
                    for k in range(0, len(items), CHUNK):                      # short write transactions
                        with db.connect() as con:
                            for it in items[k:k + CHUNK]:
                                r = repo.upsert_item(con, src, it, cve_techs)
                                summary[r] += 1
                                n_new += r == "new"
                    written += len(items)
                    with db.connect() as con:
                        _record(con, src.id, True, items=len(items), etag=res.etag, lm=res.last_modified, res=res, meta=meta)
                    summary["ok"] += 1
                    outcomes.append({"id": src.id, "ok": True, "http": res.status, "items": len(items), "new": n_new})
                except Exception as e:  # per-source isolation
                    log.warning("source %s failed: %s", src.id, e)
                    with db.connect() as con:
                        _record(con, src.id, False, error=str(e), err=e if isinstance(e, FetchError) else None)
                    summary["failed"] += 1
                    outcomes.append({"id": src.id, "ok": False, "http": getattr(e, "status", None), "error": str(e)[:120]})
        with db.connect() as con:
            repo.recorrelate(con)
        _log_sync(started, force, only_due, summary, outcomes)
        summary["outcomes"] = outcomes
        return summary
    finally:
        state.update(running=False)
        _lock.release()


def _log_sync(started, force, only_due, summary, outcomes) -> None:
    """Instrumentation only: one row per sync attempt (history starts when this was introduced; nothing is back-filled)."""
    try:
        import json
        with db.connect() as con:
            con.execute("INSERT INTO news_sync_log(started_at,finished_at,forced,only_due,ok,failed,new_items,updated_items,resighted,skipped,sources) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                        (started, db.now_iso(), int(force), int(only_due), summary["ok"], summary["failed"], summary["new"], summary["updated"],
                         summary["duplicate"], json.dumps(summary["skipped"]), json.dumps(outcomes)))
            con.execute("DELETE FROM news_sync_log WHERE id NOT IN (SELECT id FROM news_sync_log ORDER BY id DESC LIMIT 2000)")
    except Exception as e:  # never break a sync because of logging
        log.warning("sync log failed: %s", e)


def run_news_sync_and_enrich(force: bool = False, only_due: bool = False) -> dict | None:
    """Collect feeds, then add NVD/EPSS signals for cited CVEs (bounded; separate from the pyramid score tables)."""
    from . import enrich
    summary = run_news_sync(force, only_due=only_due)
    try:
        enrich.run()
    except Exception as e:  # enrichment is best-effort
        log.warning("enrichment failed: %s", e)
    try:  # instrumentation: pre-build the analytics corpus and record a snapshot (best-effort)
        from .. import analytics
        analytics.after_sync()
    except Exception as e:
        log.warning("analytics snapshot failed: %s", e)
    return summary
