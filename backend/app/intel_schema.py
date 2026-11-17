"""Schema of the LOCAL VULNERABILITY INTELLIGENCE DATABASE (additive; reuses nvd_cve / kev_entry / epss as the single source of truth).

nvd_cve        one row per CVE (existing table, extended). `config_json` keeps the ORIGINAL NVD `configurations` tree so AND/OR/negate and
               vulnerable=false platform conditions are never lost; `cpes` (flat) and `versions` stay populated for the legacy readers.
cve_cpe        normalised VULNERABLE cpeMatch rows (vendor/product/version bounds) -> fast "which CVEs affect product X" queries.
cve_cwe, cve_ref   weaknesses and references.
cpe_dictionary NVD CPE dictionary (normalisation base; NOT the technology catalogue).
cpe_match_criteria  NVD CPE Match Criteria records (the registry of match strings; distinct from their use inside a CVE configuration).
kev_entry / epss / epss_history   enrichment datasets.
intel_dataset / intel_unit / intel_import_run / intel_import_error   status, checkpoints, history, errors of the ingestion engine.
"""
from __future__ import annotations

NVD_CVE_COLUMNS = {
    "vuln_status": "TEXT", "source_identifier": "TEXT", "cvss_vector": "TEXT", "cvss_severity": "TEXT", "config_json": "TEXT",
    "complex_config": "INTEGER NOT NULL DEFAULT 0", "imported_at": "TEXT", "origin": "TEXT",
}
CPE_COLUMNS = {"deprecated_by": "TEXT"}
KEV_COLUMNS = {"description": "TEXT", "required_action": "TEXT", "due_date": "TEXT", "notes": "TEXT", "cwes": "TEXT", "imported_at": "TEXT"}
EPSS_COLUMNS = {"model_version": "TEXT"}

SCHEMA = """
CREATE TABLE IF NOT EXISTS cve_cwe(cve_id TEXT NOT NULL, cwe_id TEXT NOT NULL, source TEXT NOT NULL DEFAULT '', PRIMARY KEY(cve_id, cwe_id, source)) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS ix_cve_cwe_cwe ON cve_cwe(cwe_id);
CREATE TABLE IF NOT EXISTS cve_ref(cve_id TEXT NOT NULL, url TEXT NOT NULL, source TEXT, tags TEXT);
CREATE INDEX IF NOT EXISTS ix_cve_ref ON cve_ref(cve_id);
CREATE TABLE IF NOT EXISTS cve_cpe(
  cve_id TEXT NOT NULL, mc_id TEXT, part TEXT, vendor TEXT NOT NULL, product TEXT NOT NULL, version TEXT, vsi TEXT, vse TEXT, vei TEXT, vee TEXT);
CREATE INDEX IF NOT EXISTS ix_cve_cpe_prod ON cve_cpe(vendor, product);
CREATE INDEX IF NOT EXISTS ix_cve_cpe_cve ON cve_cpe(cve_id);
CREATE INDEX IF NOT EXISTS ix_cve_cpe_mc ON cve_cpe(mc_id);
CREATE TABLE IF NOT EXISTS cpe_dictionary(
  cpe_name_id TEXT PRIMARY KEY, cpe_name TEXT NOT NULL, part TEXT, vendor TEXT, product TEXT, version TEXT, deprecated INTEGER NOT NULL DEFAULT 0,
  title TEXT, created TEXT, last_modified TEXT, refs TEXT, deprecated_by TEXT);
CREATE INDEX IF NOT EXISTS ix_cpe_prod ON cpe_dictionary(vendor, product);
CREATE INDEX IF NOT EXISTS ix_cpe_part_prod ON cpe_dictionary(part, vendor, product);
CREATE TABLE IF NOT EXISTS cpe_match_criteria(
  mc_id TEXT PRIMARY KEY, criteria TEXT NOT NULL, part TEXT, vendor TEXT, product TEXT, version TEXT, vsi TEXT, vse TEXT, vei TEXT, vee TEXT,
  status TEXT, created TEXT, last_modified TEXT, cpe_last_modified TEXT, match_count INTEGER NOT NULL DEFAULT 0);
CREATE INDEX IF NOT EXISTS ix_cpem_prod ON cpe_match_criteria(vendor, product);
CREATE TABLE IF NOT EXISTS cve_product_stats(vendor TEXT NOT NULL, product TEXT NOT NULL, cves INTEGER NOT NULL, PRIMARY KEY(vendor, product)) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS cve_index(id TEXT PRIMARY KEY, published TEXT, cvss REAL, epss REAL, in_kev INTEGER NOT NULL DEFAULT 0, kev_date TEXT, ransomware INTEGER NOT NULL DEFAULT 0, has_nvd INTEGER NOT NULL DEFAULT 0) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS ix_cidx_pub ON cve_index(published);
CREATE INDEX IF NOT EXISTS ix_cidx_cvss ON cve_index(cvss);
CREATE INDEX IF NOT EXISTS ix_cidx_epss ON cve_index(epss);
CREATE INDEX IF NOT EXISTS ix_cidx_kev ON cve_index(in_kev, kev_date);
CREATE TABLE IF NOT EXISTS epss_history(cve_id TEXT NOT NULL, score_date TEXT NOT NULL, score REAL, percentile REAL, PRIMARY KEY(cve_id, score_date)) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS intel_dataset(
  key TEXT PRIMARY KEY, kind TEXT, status TEXT NOT NULL DEFAULT 'not_initialized', records INTEGER NOT NULL DEFAULT 0, dataset_date TEXT, last_attempt TEXT, last_success TEXT,
  last_error TEXT, checkpoint TEXT, source_meta TEXT, updated_at TEXT);
CREATE TABLE IF NOT EXISTS intel_unit(
  dataset TEXT NOT NULL, unit TEXT NOT NULL, sha256 TEXT, meta TEXT, items INTEGER NOT NULL DEFAULT 0, completed_at TEXT, PRIMARY KEY(dataset, unit));
CREATE TABLE IF NOT EXISTS intel_import_run(
  id INTEGER PRIMARY KEY AUTOINCREMENT, mode TEXT NOT NULL, datasets TEXT, status TEXT NOT NULL, started_at TEXT NOT NULL, finished_at TEXT, heartbeat TEXT,
  processed INTEGER NOT NULL DEFAULT 0, new_items INTEGER NOT NULL DEFAULT 0, updated_items INTEGER NOT NULL DEFAULT 0, errors INTEGER NOT NULL DEFAULT 0,
  current TEXT, message TEXT, checkpoint TEXT);
CREATE TABLE IF NOT EXISTS intel_import_error(id INTEGER PRIMARY KEY AUTOINCREMENT, run_id INTEGER, dataset TEXT, item TEXT, message TEXT, at TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS ix_nvd_published ON nvd_cve(published);
CREATE INDEX IF NOT EXISTS ix_nvd_cvss ON nvd_cve(cvss);
CREATE INDEX IF NOT EXISTS ix_nvd_modified ON nvd_cve(last_modified);
CREATE INDEX IF NOT EXISTS ix_kev_prod ON kev_entry(vendor, product);
CREATE INDEX IF NOT EXISTS ix_kev_added ON kev_entry(date_added);
CREATE INDEX IF NOT EXISTS ix_epss_score ON epss(score);
"""


def migrate(con) -> None:
    for table, cols in (("nvd_cve", NVD_CVE_COLUMNS), ("kev_entry", KEV_COLUMNS), ("epss", EPSS_COLUMNS)):
        have = {r[1] for r in con.execute(f"PRAGMA table_info({table})")}
        for col, ddl in cols.items():
            if col not in have:
                con.execute(f"ALTER TABLE {table} ADD COLUMN {col} {ddl}")
    if "deprecated_by" not in {r[1] for r in con.execute("PRAGMA table_info(cpe_dictionary)")} and con.execute("SELECT 1 FROM sqlite_master WHERE name='cpe_dictionary'").fetchone():
        con.execute("ALTER TABLE cpe_dictionary ADD COLUMN deprecated_by TEXT")      # tables created before this column existed
    con.executescript(SCHEMA)
