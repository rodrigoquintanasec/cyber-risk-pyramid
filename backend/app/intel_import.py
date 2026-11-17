"""Local Vulnerability Intelligence Database: ingestion engine.

Datasets (official sources only):
  cve       NVD CVE 2.0 yearly/recent/modified feeds (.json.gz + .meta)        -> nvd_cve, cve_cwe, cve_ref, cve_cpe
  cpe       NVD CPE dictionary (tar.gz of JSON chunks)                          -> cpe_dictionary
  cpematch  NVD CPE Match Criteria (tar.gz of JSON chunks)                      -> cpe_match_criteria
  kev       CISA Known Exploited Vulnerabilities (JSON)                          -> kev_entry
  epss      FIRST EPSS daily scores (csv.gz)                                     -> epss (+ epss_history when retention is enabled)

Every dataset is split in UNITS (a yearly file, the archive...). A unit is downloaded to a temp file (size-capped, resumable), verified, then
streamed into SQLite in batches; each batch commits together with its checkpoint, so an interrupted import resumes at the exact item.
A failed import never deletes earlier data (rows are only upserted; stale child rows are replaced per CVE inside the same transaction).
Nothing here is started automatically: a FULL import only runs when an administrator asks for it.
"""
from __future__ import annotations

import csv
import gzip
import io
import json
import logging
import re
import shutil
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

from . import db, intel_io
from .config import settings
from .connectors import kev as kev_c
from .connectors.nvd import _best_cvss  # noqa: F401  (kept for parity of the CVSS preference order)
from .intel_io import FeedError

log = logging.getLogger("intel")
NVD_FEEDS = "https://nvd.nist.gov/feeds/json"
EPSS_URL = "https://epss.cyentia.com/epss_scores-current.csv.gz"
FIRST_YEAR = 2002
MODIFIED_WINDOW_DAYS = 7          # NVD's `modified` feed covers roughly the last 8 days
FRESH_HOURS = {"cve": 36, "kev": 48, "epss": 48, "cpe": 24 * 10, "cpematch": 24 * 10}
DATASETS = ("cve", "cpe", "cpematch", "kev", "epss")
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
CPE_SPLIT = re.compile(r"(?<!\\):")
VER_KEYS = (("versionStartIncluding", "vsi"), ("versionStartExcluding", "vse"), ("versionEndIncluding", "vei"), ("versionEndExcluding", "vee"))
_lock = threading.Lock()
_stop = threading.Event()
_thread: dict = {"t": None}


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso() -> str:
    return _now().isoformat(timespec="seconds")


# ----------------------------------------------------------------------------- normalisation
def parse_cpe(criteria: str):
    """'cpe:2.3:a:vendor:product:version:update:...' -> (part, vendor, product, version|None, update|None); None for wildcard vendor/product."""
    if not isinstance(criteria, str):
        return None
    p = CPE_SPLIT.split(criteria)
    if len(p) < 6 or p[0] != "cpe" or p[1] != "2.3":
        return None
    part, vendor, product = p[2].lower(), p[3].lower(), p[4].lower()
    if not vendor or vendor in ("*", "-") or not product or product in ("*", "-"):
        return None
    ver = p[5] if p[5] not in ("*", "-", "") else None
    return part, vendor, product, ver, (p[6] if len(p) > 6 and p[6] not in ("*", "-") else None)


def best_cvss(metrics: dict):
    for key, ver in (("cvssMetricV31", "3.1"), ("cvssMetricV40", "4.0"), ("cvssMetricV30", "3.0"), ("cvssMetricV2", "2.0")):
        for e in sorted(metrics.get(key) or [], key=lambda e: e.get("type") != "Primary"):
            try:
                d = e["cvssData"]
                s = float(d["baseScore"])
            except (KeyError, TypeError, ValueError):
                continue
            if 0 <= s <= 10:
                return s, ver, str(d.get("vectorString") or "")[:200] or None, str(d.get("baseSeverity") or e.get("baseSeverity") or "")[:20] or None
    return None, None, None, None


def normalize_cve(cve: dict) -> dict | None:
    """One NVD CVE 2.0 record -> flat columns + child rows + the ORIGINAL configuration tree. Raises ValueError for an invalid record."""
    cid = str(cve.get("id", "")).upper()
    if not CVE_RE.match(cid):
        raise ValueError(f"invalid CVE id: {cid[:30]!r}")
    status = str(cve.get("vulnStatus") or "")
    desc = next((d.get("value", "") for d in cve.get("descriptions") or [] if d.get("lang") == "en"), "")
    cvss, ver, vector, sev = best_cvss(cve.get("metrics") or {})
    cwes = sorted({(str(d.get("value", ""))[:30], str(w.get("source") or "")[:80]) for w in cve.get("weaknesses") or [] for d in w.get("description") or [] if d.get("value")})
    refs, seen = [], set()
    for r in cve.get("references") or []:
        u = str(r.get("url", ""))[:1000]
        if re.match(r"^https?://", u) and u not in seen:
            seen.add(u)
            refs.append((u, str(r.get("source") or "")[:80], json.dumps([str(t)[:30] for t in (r.get("tags") or [])][:8]) if r.get("tags") else None))
    matches, legacy, flat, complex_cfg = [], [], set(), False
    confs = cve.get("configurations") or []
    for conf in confs:
        nodes = conf.get("nodes") or []
        for node in nodes:
            for m in node.get("cpeMatch") or []:
                cx = len(nodes) > 1 or conf.get("operator") == "AND" or node.get("operator") == "AND" or bool(node.get("negate"))
                if m.get("vulnerable") is not True:
                    complex_cfg = complex_cfg or cx      # a platform / non-vulnerable condition makes the configuration conditional
                    continue
                p = parse_cpe(m.get("criteria", ""))
                if not p:
                    continue
                part, vendor, product, ver_, upd = p
                row = {"mc_id": m.get("matchCriteriaId"), "part": part, "vendor": vendor, "product": product, "version": ver_}
                row.update({short: (str(m[long]) if m.get(long) else None) for long, short in VER_KEYS})
                matches.append(row)
                flat.add(f"{part}:{vendor}:{product}")
                complex_cfg = complex_cfg or cx
                if len(legacy) < 200:
                    legacy.append({"v": vendor, "p": product, "ver": ver_, "fi": row["vsi"], "fe": row["vse"], "ti": row["vei"], "te": row["vee"], "complex": cx})
    return {"id": cid, "published": cve.get("published"), "last_modified": cve.get("lastModified"), "status": status, "source": str(cve.get("sourceIdentifier") or "")[:120],
            "description": desc[:8000], "cvss": cvss, "cvss_version": ver, "vector": vector, "severity": sev, "cwes": cwes, "refs": refs, "matches": matches,
            "cpes": ",".join(sorted(flat)), "versions": json.dumps(legacy, separators=(",", ":")) if legacy else None,
            "config_json": json.dumps(confs, separators=(",", ":")) if confs else None, "complex": int(complex_cfg)}


def upsert_cve(con, rec: dict, now: str, origin: str) -> str:
    """'new' | 'updated' | 'unchanged' | 'removed'. Children are replaced atomically with the parent row (same transaction)."""
    cid = rec["id"]
    row = con.execute("SELECT last_modified, origin FROM nvd_cve WHERE cve_id=?", (cid,)).fetchone()
    if rec["status"].lower() == "rejected":
        if row:
            for t in ("cve_cwe", "cve_ref", "cve_cpe"):
                con.execute(f"DELETE FROM {t} WHERE cve_id=?", (cid,))
            con.execute("DELETE FROM nvd_cve WHERE cve_id=?", (cid,))
            return "removed"
        return "unchanged"
    if row and row["origin"] and row["last_modified"] and rec["last_modified"] and row["last_modified"] >= rec["last_modified"]:
        return "unchanged"
    con.execute(
        "INSERT INTO nvd_cve(cve_id,published,last_modified,cvss,cvss_version,description,cpes,fetched_at,versions,vuln_status,source_identifier,cvss_vector,cvss_severity,config_json,complex_config,imported_at,origin) "
        "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(cve_id) DO UPDATE SET published=excluded.published,last_modified=excluded.last_modified,cvss=excluded.cvss,"
        "cvss_version=excluded.cvss_version,description=excluded.description,cpes=excluded.cpes,fetched_at=excluded.fetched_at,versions=excluded.versions,vuln_status=excluded.vuln_status,"
        "source_identifier=excluded.source_identifier,cvss_vector=excluded.cvss_vector,cvss_severity=excluded.cvss_severity,config_json=excluded.config_json,complex_config=excluded.complex_config,"
        "imported_at=excluded.imported_at,origin=excluded.origin",
        (cid, rec["published"], rec["last_modified"], rec["cvss"], rec["cvss_version"], rec["description"], rec["cpes"], now, rec["versions"], rec["status"], rec["source"], rec["vector"],
         rec["severity"], rec["config_json"], rec["complex"], now, origin))
    for t in ("cve_cwe", "cve_ref", "cve_cpe"):
        con.execute(f"DELETE FROM {t} WHERE cve_id=?", (cid,))
    con.executemany("INSERT OR IGNORE INTO cve_cwe(cve_id,cwe_id,source) VALUES(?,?,?)", [(cid, w, s) for w, s in rec["cwes"]])
    con.executemany("INSERT INTO cve_ref(cve_id,url,source,tags) VALUES(?,?,?,?)", [(cid, *r) for r in rec["refs"]])
    con.executemany("INSERT INTO cve_cpe(cve_id,mc_id,part,vendor,product,version,vsi,vse,vei,vee) VALUES(?,?,?,?,?,?,?,?,?,?)",
                    [(cid, m["mc_id"], m["part"], m["vendor"], m["product"], m["version"], m["vsi"], m["vse"], m["vei"], m["vee"]) for m in rec["matches"]])
    return "updated" if row else "new"


def apply_cve(con, item: dict, ctx) -> str:
    rec = normalize_cve(item.get("cve") or {})
    return upsert_cve(con, rec, ctx.now, ctx.unit)


def apply_cpe(con, item: dict, ctx) -> str:
    c = item.get("cpe") or {}
    name, nid = c.get("cpeName"), c.get("cpeNameId")
    if not name or not nid:
        raise ValueError("CPE record without cpeName/cpeNameId")
    p = CPE_SPLIT.split(name)
    part, vendor, product, ver = (p[2] if len(p) > 2 else None), (p[3] if len(p) > 3 else None), (p[4] if len(p) > 4 else None), (p[5] if len(p) > 5 and p[5] not in ("*", "-") else None)
    title = next((t.get("title") for t in c.get("titles") or [] if t.get("lang") == "en"), None)
    refs = json.dumps([{"ref": r.get("ref"), "type": r.get("type")} for r in (c.get("refs") or [])[:6] if r.get("ref")])[:1500] if c.get("refs") else None
    dep_by = json.dumps([d.get("cpeName") for d in (c.get("deprecatedBy") or [])[:10] if d.get("cpeName")]) if c.get("deprecatedBy") else None
    old = con.execute("SELECT last_modified FROM cpe_dictionary WHERE cpe_name_id=?", (nid,)).fetchone()
    if old and old[0] and c.get("lastModified") and old[0] >= c["lastModified"]:
        return "unchanged"
    con.execute("INSERT OR REPLACE INTO cpe_dictionary(cpe_name_id,cpe_name,part,vendor,product,version,deprecated,title,created,last_modified,refs,deprecated_by) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                (nid, name, part, (vendor or "").lower(), (product or "").lower(), ver, int(bool(c.get("deprecated"))), (title or "")[:300] or None, c.get("created"), c.get("lastModified"), refs, dep_by))
    return "updated" if old else "new"


def apply_match(con, item: dict, ctx) -> str:
    m = item.get("matchString") or {}
    mid, crit = m.get("matchCriteriaId"), m.get("criteria")
    if not mid or not crit:
        raise ValueError("match string without matchCriteriaId/criteria")
    p = CPE_SPLIT.split(crit)
    old = con.execute("SELECT last_modified FROM cpe_match_criteria WHERE mc_id=?", (mid,)).fetchone()
    if old and old[0] and m.get("lastModified") and old[0] >= m["lastModified"]:
        return "unchanged"
    vals = [m.get(long) for long, _ in VER_KEYS]
    con.execute("INSERT OR REPLACE INTO cpe_match_criteria(mc_id,criteria,part,vendor,product,version,vsi,vse,vei,vee,status,created,last_modified,cpe_last_modified,match_count) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (mid, crit, p[2] if len(p) > 2 else None, (p[3] if len(p) > 3 else "").lower(), (p[4] if len(p) > 4 else "").lower(), p[5] if len(p) > 5 and p[5] not in ("*", "-") else None,
                 *vals, m.get("status"), m.get("created"), m.get("lastModified"), m.get("cpeLastModified"), len(m.get("matches") or [])))
    return "updated" if old else "new"


# ----------------------------------------------------------------------------- run context & checkpoints
class Ctx:
    """Holds the run counters and persists checkpoints. One SQLite connection per run; commits happen only at batch boundaries."""
    def __init__(self, run_id: int, con):
        self.run_id, self.con, self.now = run_id, con, _iso()
        self.processed = self.new = self.updated = self.errors = 0
        self.unit = ""

    def heartbeat(self, current: str | None = None, message: str | None = None) -> None:
        self.con.execute("UPDATE intel_import_run SET heartbeat=?,processed=?,new_items=?,updated_items=?,errors=?,current=COALESCE(?,current),message=COALESCE(?,message) WHERE id=?",
                         (_iso(), self.processed, self.new, self.updated, self.errors, current, message, self.run_id))

    def error(self, dataset: str, item: str, msg: str) -> None:
        self.errors += 1
        if self.errors <= 200:
            self.con.execute("INSERT INTO intel_import_error(run_id,dataset,item,message,at) VALUES(?,?,?,?,?)", (self.run_id, dataset, item[:120], msg[:300], _iso()))

    def checkpoint(self, dataset: str, cp: dict | None) -> None:
        self.con.execute("UPDATE intel_dataset SET checkpoint=?, updated_at=? WHERE key=?", (json.dumps(cp) if cp else None, _iso(), dataset))
        self.con.commit()


def _ds_row(con, key: str) -> dict:
    r = con.execute("SELECT * FROM intel_dataset WHERE key=?", (key,)).fetchone()
    if r is None:       # read first: the status endpoint calls this on every refresh and must not need the write lock
        con.execute("INSERT OR IGNORE INTO intel_dataset(key,kind,status,updated_at) VALUES(?,?,?,?)", (key, key, "not_initialized", _iso()))
        r = con.execute("SELECT * FROM intel_dataset WHERE key=?", (key,)).fetchone()
    return dict(r)


def _unit_done(con, dataset: str, unit: str) -> dict | None:
    r = con.execute("SELECT * FROM intel_unit WHERE dataset=? AND unit=?", (dataset, unit)).fetchone()
    return dict(r) if r else None


def _finish_unit(ctx: Ctx, dataset: str, unit: str, sha: str | None, meta: dict | None, items: int) -> None:
    ctx.con.execute("INSERT OR REPLACE INTO intel_unit(dataset,unit,sha256,meta,items,completed_at) VALUES(?,?,?,?,?,?)", (dataset, unit, sha, json.dumps(meta) if meta else None, items, _iso()))
    ctx.checkpoint(dataset, None)


def stream_batches(ctx: Ctx, dataset: str, unit: str, it, apply, skip: int = 0, extra: dict | None = None) -> int:
    """Apply `apply(con, item, ctx)` to every item, committing item batches together with their checkpoint. Returns the number of items seen."""
    ctx.unit = unit
    n = pending = 0
    try:
        return _stream_loop(ctx, dataset, unit, it, apply, skip, extra)
    finally:
        close = getattr(it, "close", None)
        if close:
            close()                                    # always release the file handle (an abandoned generator keeps it open on Windows)


def _stream_loop(ctx: Ctx, dataset: str, unit: str, it, apply, skip: int, extra: dict | None) -> int:
    n = pending = 0
    for obj in it:
        n += 1
        if n <= skip:
            continue
        try:
            res = apply(ctx.con, obj, ctx)
        except (ValueError, KeyError, TypeError) as e:       # a bad record must not stop the dataset
            ctx.error(dataset, f"{unit}#{n}", str(e))
            res = "error"
        ctx.processed += 1
        if res == "new":
            ctx.new += 1
        elif res in ("updated", "removed"):
            ctx.updated += 1
        pending += 1
        if pending >= settings.intel_batch:
            ctx.heartbeat(f"{dataset}:{unit}")
            ctx.checkpoint(dataset, {"unit": unit, "items_done": n, "phase": "import", **(extra or {})})
            pending = 0
            if _stop.is_set():
                raise InterruptedError("stop requested")
            if settings.intel_throttle_ms:
                time.sleep(settings.intel_throttle_ms / 1000)
    ctx.heartbeat(f"{dataset}:{unit}")
    ctx.con.commit()
    return n


# ----------------------------------------------------------------------------- dataset runners
def _rm(path: Path) -> None:
    """Best-effort temp file removal (a lingering handle must never fail an import that already succeeded)."""
    try:
        path.unlink(missing_ok=True)
    except OSError:
        log.warning("could not remove temp file %s", path)


def _tmp(name: str) -> Path:
    p = Path(settings.intel_tmp_dir)
    p.mkdir(parents=True, exist_ok=True)
    return p / name


def cve_units(con, mode: str) -> list[str]:
    year = _now().year
    if mode == "full":
        return [f"nvdcve-2.0-{y}" for y in range(year, FIRST_YEAR - 1, -1)] + ["nvdcve-2.0-modified"]
    units = ["nvdcve-2.0-modified", "nvdcve-2.0-recent"]
    last = con.execute("SELECT last_success FROM intel_dataset WHERE key='cve'").fetchone()
    if last and last[0] and _now() - datetime.fromisoformat(last[0]) > timedelta(days=MODIFIED_WINDOW_DAYS):
        units += [f"nvdcve-2.0-{y}" for y in range(year, FIRST_YEAR - 1, -1)]      # gap larger than the `modified` window: refresh files whose hash changed
    return units


def _fetch_verified(ctx: Ctx, dataset: str, unit: str, url: str, kind: str, max_mb: int, cp: dict | None):
    """Download (resumable) + integrity check. Returns (path, meta, sha, skipped) where skipped=True means the stored unit already matches the official .meta."""
    meta = intel_io.parse_meta(intel_io.fetch_text(url.rsplit(".", 2)[0] + ".meta" if kind == "gz" else url.replace(".tar.gz", ".meta")))
    done = _unit_done(ctx.con, dataset, unit)
    if done and meta.get("sha256") and done["sha256"] == meta["sha256"]:
        return None, meta, done["sha256"], True
    path = _tmp(f"{unit}.{'json.gz' if kind == 'gz' else 'tar.gz'}")
    if cp and cp.get("verified") and cp.get("unit") == unit and path.exists() and path.stat().st_size == cp.get("size"):
        return path, meta, cp.get("sha"), False                                  # already downloaded and verified in an earlier attempt
    ctx.heartbeat(f"{dataset}:{unit}", f"downloading {unit}")
    ctx.con.commit()
    size = intel_io.fetch_to(url, path, max_mb * 1_000_000, meta.get("gzSize"), resume=True)
    ctx.heartbeat(f"{dataset}:{unit}", f"verifying {unit}")
    ctx.con.commit()
    if kind == "gz":
        sha = intel_io.verify_gz(path, meta)
    else:   # tar.gz: NVD's .meta hashes the concatenated member contents (size = sum of member sizes); the archive hash is also accepted
        if meta.get("gzSize") and path.stat().st_size != meta["gzSize"]:
            _rm(path)
            raise FeedError(f"{unit}: archive size mismatch ({path.stat().st_size} != {meta['gzSize']})")
        sha, content_size = intel_io.tar_members_sha256(path)
        if meta.get("sha256") and sha != meta["sha256"]:
            if intel_io.file_sha256(path) != meta["sha256"]:
                _rm(path)
                raise FeedError(f"{unit}: sha256 does not match the official .meta")
        elif meta.get("size") and content_size != meta["size"]:
            _rm(path)
            raise FeedError(f"{unit}: content size mismatch ({content_size} != {meta['size']})")
    ctx.checkpoint(dataset, {"unit": unit, "phase": "verified", "verified": True, "size": size, "sha": sha, "items_done": 0})
    return path, meta, sha, False


def _resume_skip(ctx: Ctx, dataset: str, unit: str) -> tuple[dict | None, int]:
    cp = json.loads(_ds_row(ctx.con, dataset)["checkpoint"] or "null")
    return cp, (cp.get("items_done", 0) if cp and cp.get("unit") == unit else 0)


def run_cve(ctx: Ctx, mode: str) -> int:
    total = 0
    for unit in cve_units(ctx.con, mode):
        url = f"{NVD_FEEDS}/cve/2.0/{unit}.json.gz"
        cp, skip = _resume_skip(ctx, "cve", unit)
        try:
            path, meta, sha, skipped = _fetch_verified(ctx, "cve", unit, url, "gz", settings.intel_max_download_mb, cp)
        except FeedError as e:
            if "HTTP 404" in str(e) and re.search(r"-(\d{4})$", unit) and int(unit[-4:]) > _now().year - 1:
                continue                                                         # a year that does not exist yet
            raise
        if skipped:
            continue
        n = stream_batches(ctx, "cve", unit, intel_io.iter_gz_json(path, "vulnerabilities"), apply_cve, skip, {"verified": True, "size": path.stat().st_size, "sha": sha})
        _finish_unit(ctx, "cve", unit, sha, meta, n)
        _rm(path)
        total += n
    return total


def run_archive(ctx: Ctx, dataset: str, unit: str, url: str, key: str, apply) -> int:
    cp, skip = _resume_skip(ctx, dataset, unit)
    path, meta, sha, skipped = _fetch_verified(ctx, dataset, unit, url, "tar", settings.intel_max_download_mb, cp)
    if skipped:
        return 0
    n = stream_batches(ctx, dataset, unit, intel_io.iter_tar_json(path, key), apply, skip, {"verified": True, "size": path.stat().st_size, "sha": sha})
    _finish_unit(ctx, dataset, unit, sha, meta, n)
    _rm(path)
    return n


def store_kev(con, entries: list[dict]) -> tuple[int, int]:
    """Upsert the CISA KEV catalogue (single copy, shared by every module). Returns (new, updated). Never deletes: KEV entries are not removed."""
    now, new = _iso(), 0
    for e in entries:
        had = con.execute("SELECT 1 FROM kev_entry WHERE cve_id=?", (e["cve_id"],)).fetchone()
        con.execute(
            "INSERT INTO kev_entry(cve_id,vendor,product,name,date_added,ransomware,description,required_action,due_date,notes,cwes,imported_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?) "
            "ON CONFLICT(cve_id) DO UPDATE SET vendor=excluded.vendor,product=excluded.product,name=excluded.name,date_added=excluded.date_added,ransomware=excluded.ransomware,"
            "description=excluded.description,required_action=excluded.required_action,due_date=excluded.due_date,notes=excluded.notes,cwes=excluded.cwes,imported_at=excluded.imported_at",
            (e["cve_id"], e["vendor"], e["product"], e["name"], e["date_added"], e["ransomware"], e.get("description"), e.get("required_action"), e.get("due_date"), e.get("notes"), e.get("cwes"), now))
        new += 0 if had else 1
    con.execute("INSERT OR REPLACE INTO intel_unit(dataset,unit,sha256,meta,items,completed_at) VALUES('kev','kev',NULL,?,?,?)", (json.dumps({"entries": len(entries)}), len(entries), now))
    con.execute("INSERT INTO source_status(source,last_attempt,last_success,ok,error,detail) VALUES('kev',?,?,1,NULL,?) ON CONFLICT(source) DO UPDATE SET last_attempt=excluded.last_attempt,"
                "last_success=excluded.last_success,ok=1,error=NULL,detail=excluded.detail", (now, now, f"{len(entries)} entries"))
    return new, len(entries) - new


def run_kev(ctx: Ctx) -> int:
    text = intel_io.fetch_text(kev_c.URL, max_bytes=50_000_000)
    try:
        entries = kev_c.parse(json.loads(text))
    except Exception as e:   # invalid payload: the previous catalogue stays untouched
        raise FeedError(f"KEV payload invalid: {e}")
    new, upd = store_kev(ctx.con, entries)
    ctx.processed += len(entries)
    ctx.new += new
    ctx.updated += upd
    ctx.con.commit()
    return len(entries)


def parse_epss_header(first_line: str) -> tuple[str | None, str | None]:
    m = re.match(r"^#\s*model_version:([^,\s]+),\s*score_date:(\S+)", first_line)
    return (m.group(1), m.group(2)) if m else (None, None)


def run_epss(ctx: Ctx) -> int:
    path = _tmp("epss_scores-current.csv.gz")
    size = intel_io.fetch_to(EPSS_URL, path, 200_000_000, resume=False)
    lines = intel_io.gz_text_lines(path)
    first = next(lines, "")
    model, sdate = parse_epss_header(first)
    if not sdate:
        raise FeedError("EPSS file has no '#model_version/score_date' header")
    header = next(lines, "")
    if [h.strip() for h in header.split(",")] != ["cve", "epss", "percentile"]:
        raise FeedError("EPSS file has an unexpected header")
    day = sdate[:10]
    keep_history = settings.epss_history_days > 0
    rows, n, bad, ts = [], 0, 0, _iso()
    for ln in lines:
        if not ln:
            continue
        try:
            cve, s, p = ln.split(",")
            s, p = float(s), float(p)
            if not CVE_RE.match(cve) or not (0 <= s <= 1 and 0 <= p <= 1):
                raise ValueError
        except ValueError:
            bad += 1
            continue
        rows.append((cve, s, p, day, ts, model))
        n += 1
        if len(rows) >= 5000:
            _flush_epss(ctx, rows, keep_history)
            rows = []
    _flush_epss(ctx, rows, keep_history)
    if n == 0:
        raise FeedError("EPSS file contained no valid rows")
    if bad:
        ctx.error("epss", "rows", f"{bad} malformed EPSS rows skipped")
    if keep_history:
        cut = (_now() - timedelta(days=settings.epss_history_days)).date().isoformat()
        ctx.con.execute("DELETE FROM epss_history WHERE score_date<?", (cut,))
    ctx.con.execute("INSERT OR REPLACE INTO intel_unit(dataset,unit,sha256,meta,items,completed_at) VALUES('epss','epss',NULL,?,?,?)", (json.dumps({"score_date": day, "model_version": model, "bytes": size}), n, ts))
    ctx.con.execute("INSERT INTO source_status(source,last_attempt,last_success,ok,error,detail) VALUES('epss',?,?,1,NULL,?) ON CONFLICT(source) DO UPDATE SET last_attempt=excluded.last_attempt,"
                    "last_success=excluded.last_success,ok=1,error=NULL,detail=excluded.detail", (ts, ts, f"{n} scores {day} (local database)"))
    ctx.con.commit()
    _rm(path)
    ctx.processed += n
    ctx.updated += n
    return n


def _flush_epss(ctx: Ctx, rows: list, history: bool) -> None:
    if not rows:
        return
    ctx.con.executemany("INSERT INTO epss(cve_id,score,percentile,score_date,fetched_at,model_version) VALUES(?,?,?,?,?,?) ON CONFLICT(cve_id) DO UPDATE SET score=excluded.score,"
                        "percentile=excluded.percentile,score_date=excluded.score_date,fetched_at=excluded.fetched_at,model_version=excluded.model_version", rows)
    if history:
        ctx.con.executemany("INSERT OR REPLACE INTO epss_history(cve_id,score_date,score,percentile) VALUES(?,?,?,?)", [(r[0], r[3], r[1], r[2]) for r in rows])
    ctx.con.commit()
    ctx.heartbeat("epss")


# ----------------------------------------------------------------------------- orchestration
def _mark(con, dataset: str, **cols) -> None:
    _ds_row(con, dataset)
    sets = ",".join(f"{k}=?" for k in cols)
    con.execute(f"UPDATE intel_dataset SET {sets},updated_at=? WHERE key=?", [*cols.values(), _iso(), dataset])
    con.commit()


def _count(con, dataset: str) -> int:
    t = {"cve": "nvd_cve", "cpe": "cpe_dictionary", "cpematch": "cpe_match_criteria", "kev": "kev_entry", "epss": "epss"}[dataset]
    return con.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]


def _dataset_date(con, dataset: str):
    if dataset == "epss":
        r = con.execute("SELECT MAX(score_date) FROM epss").fetchone()
        return r[0] if r else None
    r = con.execute("SELECT meta FROM intel_unit WHERE dataset=? ORDER BY completed_at DESC LIMIT 1", (dataset,)).fetchone()
    try:
        return json.loads(r[0]).get("lastModifiedDate") if r and r[0] else None
    except ValueError:
        return None


def run_dataset(ctx: Ctx, dataset: str, mode: str) -> None:
    con = ctx.con
    _mark(con, dataset, status="importing" if _unit_count(con, dataset) == 0 or mode == "full" else "updating", last_attempt=_iso(), last_error=None)
    try:
        if dataset == "cve":
            run_cve(ctx, mode)
        elif dataset == "cpe":
            run_archive(ctx, "cpe", "nvdcpe-2.0", f"{NVD_FEEDS}/cpe/2.0/nvdcpe-2.0.tar.gz", "products", apply_cpe)
        elif dataset == "cpematch":
            run_archive(ctx, "cpematch", "nvdcpematch-2.0", f"{NVD_FEEDS}/cpematch/2.0/nvdcpematch-2.0.tar.gz", "matchStrings", apply_match)
        elif dataset == "kev":
            run_kev(ctx)
        elif dataset == "epss":
            run_epss(ctx)
        con.commit()
        _mark(con, dataset, status="complete" if _is_complete(con, dataset) else "partial", last_success=_iso(), records=_count(con, dataset), dataset_date=_dataset_date(con, dataset), last_error=None)
    except InterruptedError:
        con.commit()
        _mark(con, dataset, status="partial", last_error="interrupted (resumable)")
        raise
    except Exception as e:
        con.rollback()
        _mark(con, dataset, status="failed" if _unit_count(con, dataset) == 0 else "partial", last_error=f"{type(e).__name__}: {e}"[:300], records=_count(con, dataset))
        raise


def _unit_count(con, dataset: str) -> int:
    return con.execute("SELECT COUNT(*) FROM intel_unit WHERE dataset=?", (dataset,)).fetchone()[0]


def required_units(dataset: str) -> list[str]:
    year = _now().year
    return {"cve": [f"nvdcve-2.0-{y}" for y in range(FIRST_YEAR, year + 1)], "cpe": ["nvdcpe-2.0"], "cpematch": ["nvdcpematch-2.0"], "kev": ["kev"], "epss": ["epss"]}[dataset]


def _is_complete(con, dataset: str) -> bool:
    have = {r[0] for r in con.execute("SELECT unit FROM intel_unit WHERE dataset=?", (dataset,))}
    need = set(required_units(dataset))
    if dataset == "cve":                      # the current year may legitimately not exist yet in January
        need = {u for u in need if not (u.endswith(str(_now().year)) and _now().month == 1 and _now().day < 5)}
    return need <= have


def dataset_info(con, key: str) -> dict:
    """Derived status: not_initialized | importing | updating | partial | complete | stale | failed. A partially imported dataset is never 'complete'."""
    r = _ds_row(con, key)
    running = con.execute("SELECT datasets,mode,heartbeat FROM intel_import_run WHERE status='running'").fetchone()
    active = bool(running and key in json.loads(running["datasets"] or "[]") and running["heartbeat"] and _now() - datetime.fromisoformat(running["heartbeat"]) < timedelta(minutes=3))
    units = {u["unit"] for u in con.execute("SELECT unit FROM intel_unit WHERE dataset=?", (key,)).fetchall()}
    need = required_units(key)
    complete = _is_complete(con, key)
    if active:
        status = "updating" if complete else "importing"
    elif complete:
        status = "complete"
        if r["last_success"] and _now() - datetime.fromisoformat(r["last_success"]) > timedelta(hours=FRESH_HOURS[key]):
            status = "stale"
    elif units or (r["checkpoint"] and r["status"] in ("partial", "importing")):
        status = "partial"
    elif r["status"] == "failed":
        status = "failed"
    else:
        status = "not_initialized"
    if r["status"] == "failed" and not units:
        status = "failed"
    return {"key": key, "status": status, "records": r["records"] or (_count(con, key) if units else 0), "dataset_date": r["dataset_date"], "last_attempt": r["last_attempt"], "last_success": r["last_success"],
            "last_error": r["last_error"], "units_done": len(units & set(need)), "units_total": len(need), "resumable": bool(r["checkpoint"]) or (bool(units) and not complete)}


def recover_interrupted(con) -> int:
    """At start-up: a run left 'running' by a crash is marked interrupted; its dataset checkpoints are kept, so Resume continues it."""
    n = con.execute("UPDATE intel_import_run SET status='interrupted', finished_at=?, message=COALESCE(message,'')||' (process stopped; resumable)' WHERE status='running'", (_iso(),)).rowcount
    return n


def _run(run_id: int, mode: str, datasets: list[str]) -> None:
    status, msg = "completed", None
    try:
        with db.connect(timeout=300) as con:
            con.execute("PRAGMA synchronous=NORMAL")
            ctx = Ctx(run_id, con)
            changed = False
            for ds in datasets:
                try:
                    run_dataset(ctx, ds, mode)
                    changed = changed or ctx.processed > 0
                except InterruptedError:
                    status, msg = "interrupted", "stop requested"
                    break
                except Exception as e:
                    log.warning("dataset %s failed: %s", ds, e)
                    status, msg = "partial", f"{ds}: {e}"[:300]
                    ctx.error(ds, "dataset", str(e))
                    con.commit()
            if status == "completed" and ctx.errors:
                msg = f"{ctx.errors} record(s) skipped (see errors)"
            ctx.heartbeat()
            con.commit()
        if changed or mode in ("full", "incremental"):
            post_import(datasets)
    except Exception as e:  # never let the thread die silently
        log.exception("import run crashed")
        status, msg = "failed", f"{type(e).__name__}: {e}"[:300]
    finally:
        with db.connect() as con:
            con.execute("UPDATE intel_import_run SET status=?,finished_at=?,message=COALESCE(?,message),heartbeat=? WHERE id=?", (status, _iso(), msg, _iso(), run_id))
        _lock.release()


def post_import(datasets: list[str]) -> None:
    """Derived data after new intelligence arrived: correlation tables + every dependent cache."""
    try:
        from . import intel_corr
        intel_corr.rebuild(derived=True)
    except Exception:
        log.exception("correlation rebuild failed")
    if "cpe" in datasets:
        try:
            from . import nvd_products
            with db.connect() as con:
                nvd_products.refresh(con)
        except Exception:
            log.exception("NVD product index rebuild failed")
    try:
        from . import techsync
        techsync.invalidate_caches()
    except Exception:
        pass


def start(mode: str, datasets: list[str] | None = None, wait: bool = False) -> dict:
    """Start a background run. Refuses to start while another run is active (no simultaneous full imports)."""
    if mode not in ("full", "incremental", "enrichment", "resume"):
        raise ValueError("unknown mode")
    if not _lock.acquire(blocking=False):
        return {"started": False, "reason": "already_running"}
    try:
        with db.connect() as con:
            run = con.execute("SELECT id,heartbeat FROM intel_import_run WHERE status='running'").fetchone()
            if run and run["heartbeat"] and _now() - datetime.fromisoformat(run["heartbeat"]) < timedelta(minutes=3):
                _lock.release()
                return {"started": False, "reason": "already_running"}
            ds = datasets or {"full": list(DATASETS), "incremental": ["cve"], "enrichment": ["kev", "epss"]}.get(mode) or [
                d for d in DATASETS if dataset_info(con, d)["status"] in ("partial", "failed", "importing")]
            ds = [d for d in DATASETS if d in ds]
            if not ds:
                _lock.release()
                return {"started": False, "reason": "nothing_to_do"}
            run_mode = "incremental" if mode == "resume" else mode
            run_id = con.execute("INSERT INTO intel_import_run(mode,datasets,status,started_at,heartbeat) VALUES(?,?,?,?,?)", (mode, json.dumps(ds), "running", _iso(), _iso())).lastrowid
    except Exception:
        _lock.release()
        raise
    _stop.clear()
    if mode == "resume":   # resuming continues whatever a dataset still needs: full-mode unit lists for datasets that never completed
        run_mode = "full"
    t = threading.Thread(target=_run, args=(run_id, run_mode, ds), name="intel-import", daemon=True)
    _thread["t"] = t
    t.start()
    if wait:
        t.join()
    return {"started": True, "run_id": run_id, "datasets": ds, "mode": mode}


def request_stop() -> None:
    _stop.set()


_est_cache: dict = {"t": 0.0, "v": None}


def estimate() -> dict:
    """Sizes from the official .meta files (network, fetched in parallel and cached for 10 minutes), free disk space, and an honest warning. Nothing is downloaded."""
    from concurrent.futures import ThreadPoolExecutor
    if _est_cache["v"] and time.monotonic() - _est_cache["t"] < 600:
        return {**_est_cache["v"], "disk_free_bytes": shutil.disk_usage(Path(settings.db_path).parent).free}
    year = _now().year
    metas = {"cve": [f"cve/2.0/nvdcve-2.0-{y}" for y in range(FIRST_YEAR, year + 1)] + ["cve/2.0/nvdcve-2.0-modified"], "cpe": ["cpe/2.0/nvdcpe-2.0"], "cpematch": ["cpematch/2.0/nvdcpematch-2.0"]}

    def one(path: str) -> dict:
        try:
            return intel_io.parse_meta(intel_io.fetch_text(f"{NVD_FEEDS}/{path}.meta"))
        except FeedError:
            return {}
    allp = [(ds, p) for ds, paths in metas.items() for p in paths]
    with ThreadPoolExecutor(max_workers=6) as ex:
        results = list(ex.map(lambda x: one(x[1]), allp))
    out, total_dl, total_unc = [], 0, 0
    for ds in metas:
        ms = [m for (d, _), m in zip(allp, results) if d == ds]
        dl, unc = sum(m.get("gzSize", 0) for m in ms), sum(m.get("size", 0) for m in ms)
        out.append({"dataset": ds, "download_bytes": dl, "uncompressed_bytes": unc})
        total_dl += dl
        total_unc += unc
    out += [{"dataset": "kev", "download_bytes": 1_500_000, "uncompressed_bytes": 1_500_000}, {"dataset": "epss", "download_bytes": 3_000_000, "uncompressed_bytes": 10_000_000}]
    free = shutil.disk_usage(Path(settings.db_path).parent).free
    est_db = int(total_unc * 0.55)        # rule of thumb measured on real samples: SQLite (normalised rows + indexes) is roughly half the raw JSON; shown as an estimate only
    need = int(est_db + total_dl * 1.1 + settings.intel_min_free_gb * 1e9 * 0.1)
    v = {"datasets": out, "download_bytes": total_dl, "uncompressed_bytes": total_unc, "estimated_db_bytes": est_db, "temp_dir_peak_bytes": max((o["download_bytes"] for o in out), default=0),
         "disk_free_bytes": free, "disk_needed_bytes": need, "enough_space": free >= need,
         "warning": "The full import downloads several GB, can take hours on a home connection and uses CPU, disk and bandwidth. The app stays usable; progress is saved and can be resumed. "
                    "Size figures are estimates from the official .meta files, not measurements."}
    _est_cache.update(t=time.monotonic(), v=v)
    return v


# ----------------------------------------------------------------------------- scheduling (never a full import)
SYNC_HOURS = 6
ENRICH_HOURS = 20


def bootstrap_enrichment() -> dict | None:
    """CISA KEV and FIRST EPSS are small daily files: when they are missing or stale they are fetched automatically, even before the optional NVD import.
    NVD CVE / CPE / CPE Match are never started here (that stays an explicit action). Failures keep older data and are retried on the next tick."""
    if not settings.auto_enrich:
        return None
    with db.connect() as con:
        if dataset_info(con, "cve")["units_done"]:
            return None                                       # an initialised database is handled by scheduled_tick()
        want = []
        for d in ("kev", "epss"):
            r = con.execute("SELECT last_success FROM intel_dataset WHERE key=?", (d,)).fetchone()
            if not (r and r[0]) or (_now() - datetime.fromisoformat(r[0])).total_seconds() / 3600 >= ENRICH_HOURS:
                want.append(d)
    return start("enrichment", want) if want else None


def scheduled_tick() -> dict | None:
    """Called periodically by the app: keeps an INITIALISED database current (incremental CVE feeds, daily KEV/EPSS). It never starts a full import."""
    with db.connect() as con:
        cve = dataset_info(con, "cve")
        if not cve["units_done"]:
            return None

        def age(key: str) -> float:
            r = con.execute("SELECT last_success FROM intel_dataset WHERE key=?", (key,)).fetchone()
            return (_now() - datetime.fromisoformat(r[0])).total_seconds() / 3600 if r and r[0] else 1e9
        due_cve = not cve["resumable"] and age("cve") >= SYNC_HOURS
        want = [d for d in ("kev", "epss") if age(d) >= ENRICH_HOURS]
    if due_cve:
        return start("incremental", ["cve"] + want)
    return start("enrichment", want) if want else None
