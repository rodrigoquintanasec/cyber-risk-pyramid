"""SQLite persistent cache."""
from __future__ import annotations

import sqlite3
import logging
import threading
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

from .config import settings

log = logging.getLogger("db")

SCHEMA = """
CREATE TABLE IF NOT EXISTS nvd_cve(
  cve_id TEXT PRIMARY KEY, published TEXT, last_modified TEXT, cvss REAL, cvss_version TEXT,
  description TEXT, cpes TEXT NOT NULL DEFAULT '', fetched_at TEXT NOT NULL, versions TEXT);
CREATE TABLE IF NOT EXISTS kev_entry(
  cve_id TEXT PRIMARY KEY, vendor TEXT, product TEXT, name TEXT, date_added TEXT, ransomware INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS epss(
  cve_id TEXT PRIMARY KEY, score REAL, percentile REAL, score_date TEXT, fetched_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS tech_cve(
  tech_id TEXT NOT NULL, cve_id TEXT NOT NULL, product TEXT, match_source TEXT, PRIMARY KEY(tech_id, cve_id));
CREATE TABLE IF NOT EXISTS app_meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS source_onboarding(
  id INTEGER PRIMARY KEY AUTOINCREMENT, batch INTEGER NOT NULL, started_at TEXT NOT NULL, finished_at TEXT, status TEXT NOT NULL DEFAULT 'running', sources INTEGER NOT NULL DEFAULT 0,
  enabled INTEGER NOT NULL DEFAULT 0, ok INTEGER NOT NULL DEFAULT 0, failed INTEGER NOT NULL DEFAULT 0, new_items INTEGER NOT NULL DEFAULT 0, duplicate_items INTEGER NOT NULL DEFAULT 0,
  max_write_wait REAL, note TEXT, detail TEXT);
CREATE TABLE IF NOT EXISTS source_status(
  source TEXT PRIMARY KEY, last_attempt TEXT, last_success TEXT, ok INTEGER, error TEXT, detail TEXT);
CREATE TABLE IF NOT EXISTS news_source(
  id TEXT PRIMARY KEY, name TEXT, type TEXT, url TEXT, status TEXT DEFAULT 'pending', last_attempt TEXT, last_success TEXT,
  error TEXT, consecutive_failures INTEGER DEFAULT 0, last_items INTEGER DEFAULT 0, etag TEXT, last_modified TEXT,
  enabled INTEGER NOT NULL DEFAULT 1, note TEXT, language TEXT, last_http INTEGER, final_url TEXT, newest_item TEXT,
  undated INTEGER NOT NULL DEFAULT 0, backoff_until TEXT, redirects INTEGER NOT NULL DEFAULT 0, validated_at TEXT,
  publisher TEXT, site_url TEXT, category TEXT, country TEXT, origin TEXT NOT NULL DEFAULT 'builtin', batch INTEGER, validation_status TEXT, validation_note TEXT,
  extra_hosts TEXT, official_domains TEXT, enabled_at TEXT);
CREATE TABLE IF NOT EXISTS news_item(
  id TEXT PRIMARY KEY, source_id TEXT NOT NULL, guid TEXT, url TEXT NOT NULL, url_canon TEXT NOT NULL UNIQUE,
  title TEXT NOT NULL, summary TEXT, published TEXT, collected_at TEXT NOT NULL, updated_at TEXT, content_hash TEXT,
  sort_ts TEXT NOT NULL,
  UNIQUE(source_id, guid));
CREATE INDEX IF NOT EXISTS ix_news_sort ON news_item(sort_ts DESC);
CREATE INDEX IF NOT EXISTS ix_news_source ON news_item(source_id);
CREATE TABLE IF NOT EXISTS news_cat(news_id TEXT NOT NULL, category TEXT NOT NULL, PRIMARY KEY(news_id, category));
CREATE TABLE IF NOT EXISTS news_tech(news_id TEXT NOT NULL, tech_id TEXT NOT NULL, basis TEXT, PRIMARY KEY(news_id, tech_id));
CREATE INDEX IF NOT EXISTS ix_news_tech ON news_tech(tech_id);
CREATE TABLE IF NOT EXISTS news_cve(news_id TEXT NOT NULL, cve_id TEXT NOT NULL, PRIMARY KEY(news_id, cve_id));
CREATE INDEX IF NOT EXISTS ix_news_cve ON news_cve(cve_id);
CREATE TABLE IF NOT EXISTS intel_cve(
  cve_id TEXT PRIMARY KEY, cvss REAL, cvss_version TEXT, published TEXT, description TEXT, cpes TEXT,
  nvd_fetched_at TEXT, epss REAL, epss_pct REAL, epss_date TEXT, epss_fetched_at TEXT);
CREATE TABLE IF NOT EXISTS briefing(
  id TEXT PRIMARY KEY, generated_at TEXT NOT NULL, period_hours INTEGER NOT NULL, since TEXT, until TEXT,
  coverage_status TEXT, data_hash TEXT NOT NULL, event_ids TEXT, refs TEXT, content TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS ix_briefing_gen ON briefing(generated_at DESC);
CREATE TABLE IF NOT EXISTS cve_detail(
  cve_id TEXT PRIMARY KEY, status TEXT, cwes TEXT, refs TEXT, versions TEXT, fetched_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS watchlist(
  id INTEGER PRIMARY KEY AUTOINCREMENT, owner_id TEXT NOT NULL DEFAULT 'local', name TEXT NOT NULL,
  created_at TEXT NOT NULL, updated_at TEXT NOT NULL, UNIQUE(owner_id, name));
CREATE TABLE IF NOT EXISTS watchlist_item(
  watchlist_id INTEGER NOT NULL REFERENCES watchlist(id) ON DELETE CASCADE, kind TEXT NOT NULL DEFAULT 'technology',
  ref_id TEXT NOT NULL, added_at TEXT NOT NULL, PRIMARY KEY(watchlist_id, kind, ref_id));
CREATE TABLE IF NOT EXISTS stix_object(
  stix_id TEXT PRIMARY KEY, type TEXT NOT NULL, attack_id TEXT, name TEXT NOT NULL, description TEXT, aliases TEXT,
  created TEXT, modified TEXT, revoked INTEGER NOT NULL DEFAULT 0, deprecated INTEGER NOT NULL DEFAULT 0,
  external_refs TEXT, extra TEXT, domain TEXT, imported_at TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS ix_stix_type ON stix_object(type, revoked, deprecated);
CREATE INDEX IF NOT EXISTS ix_stix_attack ON stix_object(attack_id);
CREATE TABLE IF NOT EXISTS stix_rel(
  stix_id TEXT PRIMARY KEY, source_ref TEXT NOT NULL, target_ref TEXT NOT NULL, rel_type TEXT NOT NULL, description TEXT,
  modified TEXT, revoked INTEGER NOT NULL DEFAULT 0, deprecated INTEGER NOT NULL DEFAULT 0, evidence_refs TEXT,
  source TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'confirmed', imported_at TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS ix_rel_src ON stix_rel(source_ref, rel_type);
CREATE INDEX IF NOT EXISTS ix_rel_dst ON stix_rel(target_ref, rel_type);
CREATE TABLE IF NOT EXISTS stix_sync(
  key TEXT PRIMARY KEY, url TEXT, etag TEXT, last_modified TEXT, last_attempt TEXT, last_success TEXT, status TEXT,
  error TEXT, counts TEXT, collection_version TEXT, spec_version TEXT);
CREATE TABLE IF NOT EXISTS news_sync_log(
  id INTEGER PRIMARY KEY AUTOINCREMENT, started_at TEXT NOT NULL, finished_at TEXT NOT NULL, forced INTEGER NOT NULL DEFAULT 0,
  only_due INTEGER NOT NULL DEFAULT 0, ok INTEGER NOT NULL DEFAULT 0, failed INTEGER NOT NULL DEFAULT 0, new_items INTEGER NOT NULL DEFAULT 0,
  updated_items INTEGER NOT NULL DEFAULT 0, resighted INTEGER NOT NULL DEFAULT 0, skipped TEXT, sources TEXT);
CREATE INDEX IF NOT EXISTS ix_sync_log ON news_sync_log(finished_at DESC);
CREATE TABLE IF NOT EXISTS analytics_snapshot(
  id INTEGER PRIMARY KEY AUTOINCREMENT, taken_at TEXT NOT NULL, analytics_version TEXT NOT NULL, config_hash TEXT NOT NULL,
  cluster_fingerprint TEXT, sources_configured INTEGER, sources_enabled INTEGER, sources_operational INTEGER, sources_failed INTEGER,
  sources_quiet INTEGER, articles INTEGER, dated_articles INTEGER, undated_articles INTEGER, events INTEGER, multi_source_events INTEGER,
  quality TEXT, sync_state TEXT, last_sync_id INTEGER, note TEXT);
CREATE INDEX IF NOT EXISTS ix_snapshot_taken ON analytics_snapshot(taken_at DESC);
CREATE INDEX IF NOT EXISTS ix_news_collected ON news_item(collected_at);
CREATE INDEX IF NOT EXISTS ix_news_src_sort ON news_item(source_id, sort_ts);
CREATE TABLE IF NOT EXISTS company(
  id TEXT PRIMARY KEY, name TEXT NOT NULL, trade_name TEXT, industry TEXT NOT NULL, country TEXT, description TEXT,
  status TEXT NOT NULL DEFAULT 'active', owner_id TEXT NOT NULL DEFAULT 'local', created_at TEXT NOT NULL, updated_at TEXT NOT NULL, archived_at TEXT);
CREATE UNIQUE INDEX IF NOT EXISTS ux_company_name ON company(owner_id, name COLLATE NOCASE);
CREATE TABLE IF NOT EXISTS company_technology(
  id INTEGER PRIMARY KEY AUTOINCREMENT, company_id TEXT NOT NULL REFERENCES company(id), tech_id TEXT, vendor TEXT, product TEXT, label TEXT NOT NULL,
  created_at TEXT NOT NULL);
CREATE UNIQUE INDEX IF NOT EXISTS ux_ctech_catalog ON company_technology(company_id, tech_id) WHERE tech_id IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS ux_ctech_custom ON company_technology(company_id, vendor, product) WHERE tech_id IS NULL;
CREATE TABLE IF NOT EXISTS company_asset(
  id INTEGER PRIMARY KEY AUTOINCREMENT, company_id TEXT NOT NULL REFERENCES company(id), company_tech_id INTEGER NOT NULL REFERENCES company_technology(id),
  asset_ref TEXT, version TEXT, version_min TEXT, version_max TEXT, environment TEXT NOT NULL DEFAULT 'production', criticality TEXT NOT NULL DEFAULT 'medium',
  internet_exposed TEXT NOT NULL DEFAULT 'unknown', status TEXT NOT NULL DEFAULT 'active', last_verified TEXT, notes TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS ix_casset_company ON company_asset(company_id, status);
CREATE INDEX IF NOT EXISTS ix_casset_tech ON company_asset(company_tech_id);
CREATE TABLE IF NOT EXISTS company_vulnerability_assessment(
  id INTEGER PRIMARY KEY AUTOINCREMENT, company_id TEXT NOT NULL REFERENCES company(id), cve_id TEXT NOT NULL, company_tech_id INTEGER NOT NULL REFERENCES company_technology(id),
  status TEXT NOT NULL, evidence TEXT, reference_url TEXT, assessed_by TEXT, assessed_at TEXT NOT NULL, updated_at TEXT NOT NULL,
  UNIQUE(company_id, cve_id, company_tech_id));
CREATE TABLE IF NOT EXISTS company_assessment_history(
  id INTEGER PRIMARY KEY AUTOINCREMENT, assessment_id INTEGER NOT NULL, company_id TEXT NOT NULL, cve_id TEXT NOT NULL, company_tech_id INTEGER NOT NULL,
  old_status TEXT, new_status TEXT NOT NULL, evidence TEXT, reference_url TEXT, assessed_by TEXT, changed_at TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS ix_chist_company ON company_assessment_history(company_id, cve_id);
CREATE TABLE IF NOT EXISTS company_event(
  id INTEGER PRIMARY KEY AUTOINCREMENT, company_id TEXT NOT NULL REFERENCES company(id), kind TEXT NOT NULL, ref TEXT, detail TEXT, occurred_at TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS ix_cevent ON company_event(company_id, occurred_at DESC);
CREATE TABLE IF NOT EXISTS company_snapshot(
  id INTEGER PRIMARY KEY AUTOINCREMENT, company_id TEXT NOT NULL REFERENCES company(id), taken_at TEXT NOT NULL, reason TEXT, technologies INTEGER, assets INTEGER,
  related_cves INTEGER, kev_cves INTEGER, status_counts TEXT, news_events INTEGER, official_advisories INTEGER, inventory_coverage REAL, cve_ids TEXT, kev_ids TEXT, epss TEXT);
CREATE INDEX IF NOT EXISTS ix_csnap ON company_snapshot(company_id, taken_at DESC);
CREATE TABLE IF NOT EXISTS company_report(
  id TEXT PRIMARY KEY, company_id TEXT NOT NULL REFERENCES company(id), period TEXT NOT NULL, generated_at TEXT NOT NULL, last_sync TEXT, content TEXT NOT NULL, summary TEXT);
CREATE INDEX IF NOT EXISTS ix_creport ON company_report(company_id, generated_at DESC);
CREATE TABLE IF NOT EXISTS technology(
  id TEXT PRIMARY KEY, name TEXT NOT NULL, vendor TEXT NOT NULL DEFAULT '', product TEXT NOT NULL DEFAULT '', category TEXT NOT NULL DEFAULT 'Other',
  kind TEXT NOT NULL DEFAULT 'product', description TEXT NOT NULL DEFAULT '', aliases TEXT NOT NULL DEFAULT '[]', cpe_matchers TEXT NOT NULL DEFAULT '[]',
  nvd_queries TEXT NOT NULL DEFAULT '[]', kev_matchers TEXT NOT NULL DEFAULT '[]', ambiguous_kev_vendors TEXT NOT NULL DEFAULT '[]', news_patterns TEXT NOT NULL DEFAULT '[]',
  enabled INTEGER NOT NULL DEFAULT 1, monitor TEXT NOT NULL DEFAULT 'auto', dashboard INTEGER NOT NULL DEFAULT 0, custom INTEGER NOT NULL DEFAULT 0,
  source TEXT NOT NULL DEFAULT 'seed', correlation_source TEXT, edited INTEGER NOT NULL DEFAULT 0, backfilled INTEGER NOT NULL DEFAULT 0, last_sync TEXT,
  created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS ix_tech_cat ON technology(category, enabled);
CREATE INDEX IF NOT EXISTS ix_tech_vendor ON technology(vendor COLLATE NOCASE);
CREATE TABLE IF NOT EXISTS tech_cve_hist(
  tech_id TEXT NOT NULL, cve_id TEXT NOT NULL, product TEXT, match_source TEXT, applicability TEXT NOT NULL DEFAULT 'product', PRIMARY KEY(tech_id, cve_id));
CREATE INDEX IF NOT EXISTS ix_tech_cve_hist_cve ON tech_cve_hist(cve_id);
CREATE TABLE IF NOT EXISTS tech_sync_job(
  query TEXT PRIMARY KEY, tech_id TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pending', phase TEXT NOT NULL DEFAULT 'probe', cursor TEXT, total INTEGER, fetched INTEGER NOT NULL DEFAULT 0,
  calls INTEGER NOT NULL DEFAULT 0, attempts INTEGER NOT NULL DEFAULT 0, limited_by TEXT, requested_at TEXT, started_at TEXT, heartbeat TEXT, last_attempt TEXT, last_success TEXT,
  completed_at TEXT, error TEXT, error_kind TEXT, next_eligible TEXT);
CREATE INDEX IF NOT EXISTS ix_sync_job_tech ON tech_sync_job(tech_id, status);
CREATE TABLE IF NOT EXISTS query_log(
  key TEXT PRIMARY KEY, last_success TEXT, total_results INTEGER, truncated INTEGER DEFAULT 0);
"""


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# SQLite allows ONE writer at a time. Rules that keep it usable: write transactions are short; heavy scans are read BEFORE the write transaction starts
# (readers never block writers in WAL mode); long maintenance jobs take `maintenance` so they cannot overlap each other; nothing holds a write
# transaction while it downloads or sleeps.
maintenance = threading.RLock()
SCHEMA_REV = 2          # bump when a migration step has to run again; start-up skips every migration while the stored revision matches


@contextmanager
def connect(timeout: float = 30):
    Path(settings.db_path).parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(settings.db_path, timeout=timeout)
    con.execute("PRAGMA foreign_keys=ON")
    con.execute("PRAGMA synchronous=NORMAL")        # safe with WAL; shortens every commit (and therefore every lock hold)
    con.row_factory = sqlite3.Row
    try:
        yield con
        con.commit()
    finally:
        con.close()


NEWS_SOURCE_COLUMNS = {
    "enabled": "INTEGER NOT NULL DEFAULT 1", "note": "TEXT", "language": "TEXT", "last_http": "INTEGER", "final_url": "TEXT", "newest_item": "TEXT",
    "undated": "INTEGER NOT NULL DEFAULT 0", "backoff_until": "TEXT", "redirects": "INTEGER NOT NULL DEFAULT 0", "validated_at": "TEXT",
    "publisher": "TEXT", "site_url": "TEXT", "category": "TEXT", "country": "TEXT", "origin": "TEXT NOT NULL DEFAULT 'builtin'", "batch": "INTEGER",
    "validation_status": "TEXT", "validation_note": "TEXT", "extra_hosts": "TEXT", "official_domains": "TEXT", "enabled_at": "TEXT",
}


def migrate(con) -> None:
    """Additive, idempotent migrations (never drops or rewrites existing news data)."""
    have = {r[1] for r in con.execute("PRAGMA table_info(news_source)")}
    for col, ddl in NEWS_SOURCE_COLUMNS.items():
        if col not in have:
            con.execute(f"ALTER TABLE news_source ADD COLUMN {col} {ddl}")
            if col == "enabled":  # first time only: apply the documented default (sources known to be blocked/obsolete start disabled)
                from .news.sources import SOURCES
                con.executemany("UPDATE news_source SET enabled=0 WHERE id=?", [(s.id,) for s in SOURCES if not s.enabled])


def migrate_versions(con) -> None:
    """nvd_cve.versions: affected-version ranges, filled by the next NVD sync (older rows stay NULL = unknown, never guessed)."""
    if "versions" not in {r[1] for r in con.execute("PRAGMA table_info(nvd_cve)")}:
        con.execute("ALTER TABLE nvd_cve ADD COLUMN versions TEXT")


def _migration_needed(con) -> bool:
    if not con.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='app_meta'").fetchone():
        return True
    r = con.execute("SELECT value FROM app_meta WHERE key='schema_rev'").fetchone()
    return not r or r[0] != str(SCHEMA_REV)


def _init_once() -> None:
    with connect(timeout=120) as con:
        if str(con.execute("PRAGMA journal_mode").fetchone()[0]).lower() != "wal":
            con.execute("PRAGMA journal_mode=WAL")
        if _migration_needed(con):          # the only start-up path that writes schema: runs once per revision, never on a normal restart
            con.executescript(SCHEMA)
            migrate(con)
            migrate_versions(con)
            from . import intel_schema
            intel_schema.migrate(con)
            from . import categories, nvd_products
            categories.migrate(con)
            nvd_products.migrate(con)
            from . import intel_dash
            intel_dash.migrate(con)
            con.execute("INSERT INTO app_meta(key,value) VALUES('schema_rev',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (str(SCHEMA_REV),))
        from . import catalog_db
        catalog_db.sync(con)                # writes only when a seed technology actually changed


def init_db(retries: int = 6) -> None:
    """Start-up initialisation. If another process (e.g. a previous backend still finishing an import) holds the write lock, wait and retry instead of crashing."""
    for attempt in range(retries + 1):
        try:
            _init_once()
            return
        except sqlite3.OperationalError as e:
            if "locked" not in str(e).lower() or attempt == retries:
                raise
            log.warning("database busy during start-up (%s): retrying in %ss", e, 5 * (attempt + 1))
            time.sleep(5 * (attempt + 1))


def set_status(source: str, ok: bool, error: str | None = None, detail: str | None = None) -> None:
    with connect() as con:
        con.execute(
            "INSERT INTO source_status(source,last_attempt,last_success,ok,error,detail) VALUES(?,?,?,?,?,?) "
            "ON CONFLICT(source) DO UPDATE SET last_attempt=excluded.last_attempt, ok=excluded.ok, error=excluded.error, "
            "detail=COALESCE(excluded.detail, detail), "
            "last_success=CASE WHEN excluded.ok=1 THEN excluded.last_attempt ELSE last_success END",
            (source, now_iso(), now_iso() if ok else None, int(ok), error, detail),
        )


def is_fresh(ts: str | None, ttl_hours: float) -> bool:
    if not ts:
        return False
    try:
        d = datetime.fromisoformat(ts)
    except ValueError:
        return False
    return (datetime.now(timezone.utc) - d).total_seconds() < ttl_hours * 3600
