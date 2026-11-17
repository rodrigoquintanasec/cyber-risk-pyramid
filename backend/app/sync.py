"""Orchestrates connectors -> SQLite cache -> correlation. On any source failure the last valid
data stays in the cache and the source is flagged (stale)."""
from __future__ import annotations

import json
import logging
import threading
from datetime import datetime, timedelta, timezone

from . import db
from .catalog import CATALOG
from .config import settings
from .connectors import epss as epss_c
from .connectors import kev as kev_c
from .connectors import nvd as nvd_c
from .connectors.http import SourceError
from .correlation import correlate_cpes, correlate_kev, kev_is_ambiguous_candidate

log = logging.getLogger("sync")
_run_lock = threading.Lock()
state = {"running": False, "phase": None, "started": None}


def _cutoffs() -> tuple[str, str]:
    now = datetime.now(timezone.utc)
    return (
        (now - timedelta(days=settings.nvd_window_days)).isoformat(),
        (now - timedelta(days=settings.kev_lookback_days)).date().isoformat(),
    )


def _upsert_nvd(con, items: list[dict]) -> None:
    ts = db.now_iso()
    con.executemany(
        "INSERT INTO nvd_cve(cve_id,published,last_modified,cvss,cvss_version,description,cpes,fetched_at,versions) "
        "VALUES(:cve_id,:published,:last_modified,:cvss,:cvss_version,:description,:cpes,:ts,:versions) "
        "ON CONFLICT(cve_id) DO UPDATE SET published=excluded.published,last_modified=excluded.last_modified,"
        "cvss=excluded.cvss,cvss_version=excluded.cvss_version,description=excluded.description,"
        "cpes=excluded.cpes,fetched_at=excluded.fetched_at,versions=excluded.versions",
        [{"versions": None, **i, "ts": ts} for i in items],
    )


def sync_kev(force: bool) -> None:
    with db.connect() as con:
        row = con.execute("SELECT last_success, ok FROM source_status WHERE source='kev'").fetchone()
    if not force and row and row["ok"] and db.is_fresh(row["last_success"], settings.kev_ttl_hours):
        return
    state["phase"] = "kev"
    try:
        entries = kev_c.fetch()
    except SourceError as e:
        db.set_status("kev", False, str(e)); return
    from . import intel_import
    with db.connect() as con:
        intel_import.store_kev(con, entries)
        from . import vulns
        if vulns.index_ready(con):       # keep the listing index's KEV flags current: only the KEV rows, never the whole index
            vulns.refresh_index_ids(con, [e["cve_id"] for e in entries])
    db.set_status("kev", True, None, f"{len(entries)} entries")


def sync_nvd(force: bool) -> None:
    """Incremental NVD sync restricted to MONITORED technologies (dashboard / watchlist / company inventory / forced on).
    Each query is cached (TTL); at most `nvd_query_budget` queries run per sync, never-synced and stalest first, so the public API limits hold."""
    from . import catalog_db, intel_corr
    state["phase"] = "nvd"
    failures: list[str] = []
    with db.connect() as con:
        if intel_corr.local_state(con)["initialized"]:   # the local database (bulk feeds) serves NVD data; per-technology API queries are unnecessary
            db.set_status("nvd", True, None, "served by the local intelligence database")
            return
    with db.connect() as con:
        monitored = catalog_db.monitored_ids(con)
        logged = {r["key"]: r["last_success"] for r in con.execute("SELECT key,last_success FROM query_log")}
    due: list[tuple[str, str, str]] = []   # (last_success or '', query, tech)
    for tech in CATALOG:
        if tech.id not in monitored:
            continue
        for q in tech.nvd_queries:
            last = logged.get(q)
            if force or not last or not db.is_fresh(last, settings.nvd_ttl_hours):
                due.append((last or "", q, tech.id))
    due.sort()
    done: set[str] = set()
    for _, q, tid in due[: settings.nvd_query_budget]:
        try:
            items, total, truncated = nvd_c.fetch_by_cpe(q, settings.nvd_window_days, settings.nvd_max_pages)
        except SourceError as e:
            failures.append(f"{q}: {e}"); continue
        with db.connect() as con:
            _upsert_nvd(con, items)
            con.execute(
                "INSERT INTO query_log(key,last_success,total_results,truncated) VALUES(?,?,?,?) "
                "ON CONFLICT(key) DO UPDATE SET last_success=excluded.last_success,total_results=excluded.total_results,truncated=excluded.truncated",
                (q, db.now_iso(), total, int(truncated)))
        done.add(tid)
    if done:
        with db.connect() as con:
            catalog_db.mark_synced(con, done)
    _nvd_lookups(failures)
    db.set_status("nvd", not failures, "; ".join(failures[:3])[:400] or None)


def _nvd_lookups(failures: list[str]) -> None:
    """Per-CVE NVD lookups (budgeted) for recent KEV entries of catalog vendors, to get CPE/CVSS."""
    _, kev_cut = _cutoffs()
    with db.connect() as con:
        rows = con.execute(
            "SELECT k.cve_id,k.vendor,k.product FROM kev_entry k LEFT JOIN nvd_cve n ON n.cve_id=k.cve_id "
            "WHERE n.cve_id IS NULL AND k.date_added>=? ORDER BY k.date_added DESC", (kev_cut,)).fetchall()
    todo = [r["cve_id"] for r in rows if correlate_kev(r["vendor"], r["product"]) or kev_is_ambiguous_candidate(r["vendor"])]
    for cve_id in todo[: settings.nvd_lookup_budget]:
        try:
            item = nvd_c.fetch_cve(cve_id)
        except SourceError as e:
            failures.append(f"{cve_id}: {e}"); break  # likely rate limited: stop, retry next sync
        if item:
            with db.connect() as con:
                _upsert_nvd(con, [item])


def sync_epss(force: bool) -> None:
    state["phase"] = "epss"
    with db.connect() as con:
        if con.execute("SELECT 1 FROM intel_unit WHERE dataset='epss' LIMIT 1").fetchone():   # full daily EPSS file is loaded locally: no per-CVE API calls
            return
    nvd_cut, kev_cut = _cutoffs()
    with db.connect() as con:
        ids = [r[0] for r in con.execute(
            "SELECT DISTINCT t.cve_id FROM tech_cve t LEFT JOIN epss e ON e.cve_id=t.cve_id "
            "WHERE e.cve_id IS NULL OR e.fetched_at < ?",
            ((datetime.now(timezone.utc) - timedelta(hours=settings.epss_ttl_hours)).isoformat(timespec="seconds"),))]
    if not ids:
        return
    try:
        rows = epss_c.fetch(ids)
    except SourceError as e:
        db.set_status("epss", False, str(e)); return
    ts = db.now_iso()
    with db.connect() as con:
        con.executemany(
            "INSERT INTO epss(cve_id,score,percentile,score_date,fetched_at) VALUES(?,?,?,?,?) "
            "ON CONFLICT(cve_id) DO UPDATE SET score=excluded.score,percentile=excluded.percentile,"
            "score_date=excluded.score_date,fetched_at=excluded.fetched_at",
            [(r["cve_id"], r["score"], r["percentile"], r["date"], ts) for r in rows])
    db.set_status("epss", True, None, f"{len(rows)} scores")


def _applicability(prods_by_vendor, versions_json) -> str:
    """'versioned' (explicit version/range data for the product), 'review' (complex/conditional NVD configuration) or 'product' (product listed, no version data cached)."""
    if not versions_json:
        return "product"
    try:
        ents = json.loads(versions_json)
    except ValueError:
        return "product"
    rel = [e for e in ents if e.get("p") in prods_by_vendor.get(e.get("v"), ())]
    if not rel:
        return "product"
    return "review" if any(e.get("complex") for e in rel) else "versioned"


def _legacy_recompute(con) -> None:
    """Rebuild tech_cve (recent window: feeds the Threat Signal Score) and tech_cve_hist (older CVEs, shown separately, never scored)
    from cached data. Attribution requires structured evidence (verified CPE product match or CISA KEV product name)."""
    nvd_cut, kev_cut = _cutoffs()
    links: dict[tuple[str, str], tuple[str, str]] = {}
    hist: dict[tuple[str, str], tuple[str, str, str]] = {}
    if True:
        kev = {r["cve_id"]: r for r in con.execute("SELECT * FROM kev_entry")}
        for r in con.execute("SELECT cve_id,published,cpes,versions FROM nvd_cve"):
            in_scope = (r["published"] or "") >= nvd_cut[:19] or (r["cve_id"] in kev and (kev[r["cve_id"]]["date_added"] or "") >= kev_cut)
            matched = correlate_cpes([c for c in r["cpes"].split(",") if c])
            for tid, prods in matched.items():
                prod = ", ".join(sorted(prods)[:3])
                if in_scope:
                    links[(tid, r["cve_id"])] = (prod, "nvd-cpe")
                else:
                    pv: dict[str, set] = {}
                    for x in prods:
                        v, _, p = x.partition(" ")
                        pv.setdefault(v, set()).add(p)
                    hist[(tid, r["cve_id"])] = (prod, "nvd-cpe", _applicability(pv, r["versions"]))
        for cve_id, k in kev.items():
            t = correlate_kev(k["vendor"], k["product"])
            if not t:
                continue
            if (k["date_added"] or "") >= kev_cut:
                if (t.id, cve_id) not in links:
                    links[(t.id, cve_id)] = (f'{k["vendor"]} {k["product"]}', "kev-product")
            elif (t.id, cve_id) not in links and (t.id, cve_id) not in hist:
                hist[(t.id, cve_id)] = (f'{k["vendor"]} {k["product"]}', "kev-product", "product")
        con.execute("DELETE FROM tech_cve")
        con.executemany("INSERT INTO tech_cve(tech_id,cve_id,product,match_source) VALUES(?,?,?,?)",
                        [(t, c, p, s) for (t, c), (p, s) in links.items()])
        con.execute("DELETE FROM tech_cve_hist")
        con.executemany("INSERT INTO tech_cve_hist(tech_id,cve_id,product,match_source,applicability) VALUES(?,?,?,?,?)",
                        [(t, c, p, s, a) for (t, c), (p, s, a) in hist.items() if (t, c) not in links])


def recompute_correlations() -> None:
    """Correlation tables are built from the LOCAL intelligence database when it is initialised (see intel_corr); otherwise from the legacy cache."""
    from . import intel_corr
    intel_corr.rebuild()


def run_sync(force: bool = False) -> bool:
    """Returns False if a sync is already running."""
    if not _run_lock.acquire(blocking=False):
        return False
    try:
        state.update(running=True, started=db.now_iso(), phase="start")
        recompute_correlations()  # make cached data usable immediately
        for step in (sync_kev, sync_nvd):
            try:
                step(force)
            except Exception as e:  # never let one source break the run
                log.exception("sync step failed")
                db.set_status(step.__name__.removeprefix("sync_"), False, f"unexpected error: {e}")
            recompute_correlations()
        try:   # initial historical backfill for monitored technologies (bounded, resumable, rate-limit aware)
            from . import intel_corr, techsync
            state["phase"] = "backfill"
            with db.connect() as con:
                local = intel_corr.local_state(con)["initialized"]
            if not local:
                techsync.drain(settings.nvd_backfill_calls)
        except Exception:
            log.exception("backfill failed")
        try:
            sync_epss(force)
        except Exception as e:
            log.exception("epss failed")
            db.set_status("epss", False, f"unexpected error: {e}")
        return True
    finally:
        state.update(running=False, phase=None)
        _run_lock.release()
