"""Vulnerability Explorer service over the LOCAL catalogue (never the whole of NVD).

Local catalogue = CVEs cached from NVD for monitored technologies + the full CISA KEV catalogue + CVEs cited in news
(enriched into `intel_cve`) + CVEs fetched on demand. On-demand NVD lookups are user-triggered, rate limited and
stored in `intel_cve` / `cve_detail`, never in the tables that feed the pyramid Threat Signal Score.
"""
from __future__ import annotations

import json
import re
import threading
import time
from collections import Counter, deque

from . import db
from .catalog import BY_ID
from .config import settings
from .connectors import nvd as nvd_c
from .connectors.http import SourceError
from .news.classify import CVE_RE

SORTS = {"published": "published", "cvss": "cvss", "epss": "epss", "kev_date": "kev_date"}
BASE_SQL = """
SELECT i.cve_id AS id, COALESCE(n.published, ic.published, k.date_added) AS published,
  COALESCE(n.cvss, ic.cvss) AS cvss, COALESCE(n.cvss_version, ic.cvss_version) AS cvss_version,
  COALESCE(e.score, ic.epss) AS epss, COALESCE(e.percentile, ic.epss_pct) AS epss_pct, COALESCE(e.score_date, ic.epss_date) AS epss_date,
  CASE WHEN k.cve_id IS NULL THEN 0 ELSE 1 END AS in_kev, k.date_added AS kev_date, COALESCE(k.ransomware,0) AS ransomware,
  COALESCE(n.description, ic.description, k.name) AS description, LOWER(COALESCE(NULLIF(n.cpes,''), ic.cpes, '')) AS cpes,
  LOWER(COALESCE(k.vendor,'')) AS kv, LOWER(COALESCE(k.product,'')) AS kp, k.vendor AS kev_vendor, k.product AS kev_product,
  CASE WHEN n.cve_id IS NOT NULL OR ic.nvd_fetched_at IS NOT NULL THEN 1 ELSE 0 END AS has_nvd, n.vuln_status AS vuln_status
FROM (SELECT cve_id FROM nvd_cve
      UNION ALL
      SELECT cve_id FROM (SELECT cve_id FROM kev_entry UNION SELECT cve_id FROM news_cve UNION SELECT cve_id FROM intel_cve WHERE nvd_fetched_at IS NOT NULL)
      WHERE cve_id NOT IN (SELECT cve_id FROM nvd_cve)) i
LEFT JOIN nvd_cve n ON n.cve_id=i.cve_id LEFT JOIN intel_cve ic ON ic.cve_id=i.cve_id
LEFT JOIN kev_entry k ON k.cve_id=i.cve_id LEFT JOIN epss e ON e.cve_id=i.cve_id
"""


def severity(cvss: float | None) -> str:
    if cvss is None: return "unrated"
    return "critical" if cvss >= 9 else "high" if cvss >= 7 else "medium" if cvss >= 4 else "low" if cvss > 0 else "none"


def _like(s: str) -> str:
    return '%' + _esc(s) + '%'


def _esc(s: str) -> str:
    return s.replace('!', '!!').replace('%', '!%').replace('_', '!_')


def norm(s: str) -> str:
    return re.sub(r"[^a-z0-9_.\-]", "_", s.strip().lower())[:60]


def _products(cpes: str, kev_vendor, kev_product) -> list[str]:
    out = [" / ".join(c.split(":")[1:]) for c in cpes.split(",") if c.count(":") >= 2][:4]
    if not out and kev_vendor:
        out = [f"{kev_vendor} / {kev_product}".strip(" /")]
    return out


def _shape(r) -> dict:
    return {"id": r["id"], "published": r["published"], "cvss": r["cvss"], "cvss_version": r["cvss_version"], "severity": severity(r["cvss"]),
            "epss": r["epss"], "epss_percentile": r["epss_pct"], "in_kev": bool(r["in_kev"]), "kev_date_added": r["kev_date"],
            "epss_date": r["epss_date"], "kev_ransomware": bool(r["ransomware"]), "description": (r["description"] or "")[:300] or None,
            "products": _products(r["cpes"], r["kev_vendor"], r["kev_product"]), "news_count": r["news_count"] if "news_count" in r.keys() else 0, "has_nvd_record": bool(r["has_nvd"])}


def index_ready(con) -> bool:
    """The denormalised `cve_index` (built after imports) is used for listing when present; otherwise the live view (small / legacy databases)."""
    return con.execute("SELECT 1 FROM cve_index LIMIT 1").fetchone() is not None


def refresh_index(con) -> int:
    """Rebuild the listing index from the live view in one statement (id, date, CVSS, EPSS, KEV flags only: no text, no JSON)."""
    con.execute("DELETE FROM cve_index")
    con.execute("INSERT INTO cve_index(id,published,cvss,epss,in_kev,kev_date,ransomware,has_nvd) SELECT id,published,cvss,epss,in_kev,kev_date,ransomware,has_nvd FROM (" + BASE_SQL + ")")
    return con.execute("SELECT COUNT(*) FROM cve_index").fetchone()[0]


def refresh_derived(chunk: int = 20000) -> dict:
    """Rebuild cve_product_stats and cve_index. The heavy scans (millions of rows) run as READS on their own connection; the tables are then updated in
    short chunked transactions (upsert, then removal of stale rows), so no writer ever waits minutes for this job."""
    with db.maintenance:
        with db.connect() as rd:
            rd.row_factory = None
            stats = rd.execute("SELECT vendor,product,COUNT(DISTINCT cve_id) FROM cve_cpe GROUP BY vendor,product").fetchall()
            rows = rd.execute("SELECT id,published,cvss,epss,in_kev,kev_date,ransomware,has_nvd FROM (" + BASE_SQL + ")").fetchall()
        for i in range(0, len(stats), chunk):
            with db.connect(timeout=120) as wr:
                wr.executemany("INSERT OR REPLACE INTO cve_product_stats(vendor,product,cves) VALUES(?,?,?)", stats[i:i + chunk])
        for i in range(0, len(rows), chunk):
            with db.connect(timeout=120) as wr:
                wr.executemany("INSERT OR REPLACE INTO cve_index(id,published,cvss,epss,in_kev,kev_date,ransomware,has_nvd) VALUES(?,?,?,?,?,?,?,?)", rows[i:i + chunk])
        keep_idx, keep_stats = {r[0] for r in rows}, {(r[0], r[1]) for r in stats}
        with db.connect() as rd:
            rd.row_factory = None
            stale_idx = [(r[0],) for r in rd.execute("SELECT id FROM cve_index") if r[0] not in keep_idx]
            stale_stats = [(r[0], r[1]) for r in rd.execute("SELECT vendor,product FROM cve_product_stats") if (r[0], r[1]) not in keep_stats]
        for i in range(0, len(stale_idx), chunk):
            with db.connect(timeout=120) as wr:
                wr.executemany("DELETE FROM cve_index WHERE id=?", stale_idx[i:i + chunk])
        for i in range(0, len(stale_stats), chunk):
            with db.connect(timeout=120) as wr:
                wr.executemany("DELETE FROM cve_product_stats WHERE vendor=? AND product=?", stale_stats[i:i + chunk])
    return {"products": len(stats), "index_rows": len(rows)}


def refresh_index_ids(con, ids: list[str]) -> int:
    """Targeted upkeep: re-read the listing-index rows of specific CVEs (e.g. after a KEV update) instead of rebuilding the whole index."""
    n = 0
    for i in range(0, len(ids), 400):
        part = ids[i:i + 400]
        ph = ",".join("?" * len(part))
        n += con.execute("INSERT OR REPLACE INTO cve_index(id,published,cvss,epss,in_kev,kev_date,ransomware,has_nvd) SELECT id,published,cvss,epss,in_kev,kev_date,ransomware,has_nvd FROM (" + BASE_SQL + f") WHERE id IN ({ph})", part).rowcount
    return n


def index_add_missing(con) -> int:
    """Cheap incremental upkeep of the listing index: CVEs that appeared since the last rebuild (news, KEV) are added; nothing is rewritten."""
    if not index_ready(con):
        return 0
    con.execute("INSERT OR IGNORE INTO cve_index(id,published,cvss,epss,in_kev,kev_date,ransomware,has_nvd) SELECT id,published,cvss,epss,in_kev,kev_date,ransomware,has_nvd FROM (" + BASE_SQL +
                ") WHERE id IN (SELECT cve_id FROM news_cve UNION SELECT cve_id FROM kev_entry) AND id NOT IN (SELECT id FROM cve_index)")
    return con.execute("SELECT changes()").fetchone()[0]


def search(con, *, q=None, vendor=None, product=None, techs: list[str] | None = None, cvss_min=None, cvss_max=None, epss_min=None,
           kev=None, has_news=None, date_from=None, date_to=None, sort="published", order="desc", page=1, page_size=25, history: bool = False) -> dict:
    fast = index_ready(con)
    where, args = [], []
    if q:
        q = q.strip()[:100]
        if CVE_RE.fullmatch(q):
            where.append("id=?"); args.append(q.upper())
        elif fast:   # free text: id prefix or description (scans descriptions: explicit search only)
            where.append("(id LIKE ? ESCAPE '!' OR id IN (SELECT cve_id FROM nvd_cve WHERE description LIKE ? ESCAPE '!') OR id IN (SELECT cve_id FROM kev_entry WHERE name LIKE ? ESCAPE '!'))")
            args += [_like(q.upper()) if q.upper().startswith("CVE") else _like(q), _like(q), _like(q)]
        else:
            where.append("(id LIKE ? ESCAPE '!' OR description LIKE ? ESCAPE '!')"); args += [_like(q.upper()) if q.upper().startswith("CVE") else _like(q), _like(q)]
    v = norm(vendor) if vendor else None
    pr = norm(product) if product else None
    has_cpe = (v or pr) and con.execute("SELECT 1 FROM cve_cpe LIMIT 1").fetchone() is not None
    if has_cpe:   # local intelligence database: indexed vendor/product lookup over the structured vulnerable-CPE rows (+ the CISA KEV product names)
        cond, a = ("vendor=? AND product=?", [v, pr]) if (v and pr) else (("vendor=?", [v]) if v else ("product=?", [pr]))
        kcond = "REPLACE(LOWER(vendor),' ','_')=? AND REPLACE(LOWER(product),' ','_')=?" if (v and pr) else ("REPLACE(LOWER(vendor),' ','_')=?" if v else "REPLACE(LOWER(product),' ','_')=?")
        where.append(f"(id IN (SELECT cve_id FROM cve_cpe WHERE {cond}) OR id IN (SELECT cve_id FROM kev_entry WHERE {kcond}))"); args += a + a
    elif v and pr:
        where.append("((',' || cpes || ',') LIKE ? ESCAPE '!' OR (REPLACE(kv,' ','_')=? AND REPLACE(kp,' ','_')=?))"); args += [f"%,_:{_esc(v)}:{_esc(pr)},%", v, pr]
    elif v:
        where.append("((',' || cpes) LIKE ? ESCAPE '!' OR REPLACE(kv,' ','_')=?)"); args += [f"%,_:{_esc(v)}:%", v]
    elif pr:
        where.append("((',' || cpes || ',') LIKE ? ESCAPE '!' OR REPLACE(kp,' ','_')=?)"); args += [f"%:{_esc(pr)},%", pr]
    if techs is not None:
        if techs:
            ph = ','.join('?' * len(techs))
            if history:   # a single technology: recent AND historical correlated CVEs (history is never scored)
                where.append(f"id IN (SELECT cve_id FROM tech_cve WHERE tech_id IN ({ph}) UNION SELECT cve_id FROM tech_cve_hist WHERE tech_id IN ({ph}))"); args += techs + techs
            else:
                where.append(f"id IN (SELECT cve_id FROM tech_cve WHERE tech_id IN ({ph}))"); args += techs
        else:
            where.append("0")
    if cvss_min is not None: where.append("cvss>=?"); args.append(cvss_min)
    if cvss_max is not None: where.append("cvss<=?"); args.append(cvss_max)
    if epss_min is not None: where.append("epss>=?"); args.append(epss_min)
    if kev is not None: where.append("in_kev=?"); args.append(1 if kev else 0)
    if has_news: where.append("EXISTS (SELECT 1 FROM news_cve nc WHERE nc.cve_id=id)")
    if date_from: where.append("published>=?"); args.append(date_from)
    if date_to: where.append("published<?"); args.append(date_to + "T99")
    w = (" WHERE " + " AND ".join(where)) if where else ""
    col = SORTS.get(sort, "published")
    direction = "ASC" if order == "asc" else "DESC"
    src = "cve_index" if fast else f"({BASE_SQL})"
    total = con.execute(f"SELECT COUNT(*) FROM {src}{w}", args).fetchone()[0]
    if fast:   # ids from the lean index (sorted/limited there), full detail only for the page
        ids = [r[0] for r in con.execute(f"SELECT id FROM cve_index{w} ORDER BY {col} IS NULL, {col} {direction}, id LIMIT ? OFFSET ?", [*args, page_size, (page - 1) * page_size])]
        by = {r["id"]: r for r in con.execute(f"SELECT * FROM ({BASE_SQL}) WHERE id IN ({','.join('?' * len(ids))})", ids)} if ids else {}
        rows = [by[i] for i in ids if i in by]
    else:
        rows = con.execute(f"SELECT * FROM {src}{w} ORDER BY {col} IS NULL, {col} {direction}, id LIMIT ? OFFSET ?", [*args, page_size, (page - 1) * page_size]).fetchall()
    counts = _news_counts(con, [r["id"] for r in rows])
    items = []
    for r in rows:
        it = _shape(r)
        it["news_count"] = counts.get(r["id"], 0)
        items.append(it)
    return {"items": items, "total": total, "page": page, "page_size": page_size, "pages": max(1, -(-total // page_size)),
            "scope": "Local intelligence database (NVD, CISA KEV, FIRST EPSS)." if fast else "Local catalogue only — not the complete NVD database."}


def _news_counts(con, ids: list[str]) -> dict[str, int]:
    if not ids:
        return {}
    return {r[0]: r[1] for r in con.execute(f"SELECT cve_id,COUNT(*) FROM news_cve WHERE cve_id IN ({','.join('?' * len(ids))}) GROUP BY cve_id", ids)}


def refresh_product_stats(con) -> int:
    """Precompute CVE counts per vendor/product after an import (one GROUP BY) so facets never scan millions of rows per request."""
    con.execute("DELETE FROM cve_product_stats")
    con.execute("INSERT INTO cve_product_stats(vendor,product,cves) SELECT vendor,product,COUNT(DISTINCT cve_id) FROM cve_cpe GROUP BY vendor,product")
    return con.execute("SELECT COUNT(*) FROM cve_product_stats").fetchone()[0]


def facets(con, vendor: str | None = None, limit: int = 60) -> dict:
    v0 = norm(vendor) if vendor else None
    if con.execute("SELECT 1 FROM cve_product_stats LIMIT 1").fetchone():
        if v0:
            prods = con.execute("SELECT product AS name, cves FROM cve_product_stats WHERE vendor=? ORDER BY cves DESC LIMIT ?", (v0, limit)).fetchall()
            return {"vendors": [], "products": [dict(r) for r in prods]}
        vend = con.execute("SELECT vendor AS name, SUM(cves) AS cves FROM cve_product_stats GROUP BY vendor ORDER BY cves DESC LIMIT ?", (limit,)).fetchall()
        return {"vendors": [dict(r) for r in vend], "products": []}
    vend: Counter = Counter(); prod: Counter = Counter()
    v = norm(vendor) if vendor else None
    for r in con.execute(f"SELECT cpes, kv, kp FROM ({BASE_SQL})"):
        seen_v: set[str] = set()
        for c in (r["cpes"] or "").split(","):
            parts = c.split(":")
            if len(parts) < 3: continue
            cv, cp = parts[1], parts[2]
            seen_v.add(cv)
            if v and cv == v: prod[cp] += 1
        if r["kv"]:
            seen_v.add(r["kv"].replace(" ", "_"))
            if v and r["kv"].replace(" ", "_") == v: prod[r["kp"].replace(" ", "_")] += 1
        vend.update(seen_v)
    return {"vendors": [{"name": k, "cves": n} for k, n in vend.most_common(limit)], "products": [{"name": k, "cves": n} for k, n in prod.most_common(limit)]}


def coverage(con) -> dict:
    one = lambda q: con.execute(q).fetchone()[0]  # noqa: E731
    rng = con.execute("SELECT MIN(published), MAX(published) FROM nvd_cve").fetchone()
    status = {r["source"]: {"ok": bool(r["ok"]), "last_success": r["last_success"], "error": r["error"]} for r in con.execute("SELECT * FROM source_status")}
    return {
        "explorer_total": one(f"SELECT COUNT(*) FROM ({BASE_SQL})"), "nvd_cached": one("SELECT COUNT(*) FROM nvd_cve"),
        "kev_catalog": one("SELECT COUNT(*) FROM kev_entry"), "epss_cached": one("SELECT COUNT(*) FROM epss") + one("SELECT COUNT(*) FROM intel_cve WHERE epss IS NOT NULL"),
        "news_cves": one("SELECT COUNT(DISTINCT cve_id) FROM news_cve"), "on_demand_or_enriched": one("SELECT COUNT(*) FROM intel_cve WHERE nvd_fetched_at IS NOT NULL"),
        "detail_cached": one("SELECT COUNT(*) FROM cve_detail"), "nvd_published_range": {"from": rng[0], "to": rng[1]},
        "nvd_window_days": settings.nvd_window_days if hasattr(settings, "nvd_window_days") else None, "sources": status,
        "note": "The local catalogue holds CVEs cached for monitored technologies, the full CISA KEV catalogue, CVEs cited in news and CVEs you fetched on demand. It is NOT every CVE in NVD; use “Look up in NVD” for a specific id.",
    }


# ---------------------------------------------------------------- detail
def _loads(s):
    try:
        return json.loads(s) if s else []
    except ValueError:
        return []


def detail(con, cve_id: str) -> dict | None:
    row = con.execute(f"SELECT * FROM ({BASE_SQL}) WHERE id=?", (cve_id,)).fetchone()
    if not row:
        return None
    out = _shape(row)
    out["news_count"] = _news_counts(con, [cve_id]).get(cve_id, 0)
    out["description"] = row["description"]
    out["kev"] = ({"date_added": row["kev_date"], "ransomware": bool(row["ransomware"]), "vendor": row["kev_vendor"], "product": row["kev_product"]}
                  if row["in_kev"] else None)
    d = con.execute("SELECT * FROM cve_detail WHERE cve_id=?", (cve_id,)).fetchone()
    out["detail"] = {"status": d["status"], "cwes": _loads(d["cwes"]), "references": _loads(d["refs"]), "versions": _loads(d["versions"]), "fetched_at": d["fetched_at"]} if d else None
    out["techs"] = [{"id": r["tech_id"], "name": BY_ID[r["tech_id"]].name if r["tech_id"] in BY_ID else r["tech_id"], "product": r["product"], "match_source": r["match_source"]}
                    for r in con.execute("SELECT * FROM tech_cve WHERE cve_id=?", (cve_id,))]
    out["news"] = [{"id": r["id"], "title": r["title"], "url": r["url"], "source": r["source_name"], "published": r["published"] or r["collected_at"]} for r in con.execute(
        "SELECT n.id,n.title,n.url,n.published,n.collected_at,s.name AS source_name FROM news_cve c JOIN news_item n ON n.id=c.news_id "
        "JOIN news_source s ON s.id=n.source_id WHERE c.cve_id=? ORDER BY n.sort_ts DESC LIMIT 15", (cve_id,))]
    nvd = con.execute("SELECT vuln_status,source_identifier,cvss_vector,cvss_severity,last_modified,config_json,complex_config,origin,imported_at FROM nvd_cve WHERE cve_id=?", (cve_id,)).fetchone()
    if nvd:
        out["nvd"] = {"status": nvd["vuln_status"], "source": nvd["source_identifier"], "vector": nvd["cvss_vector"], "severity": nvd["cvss_severity"], "last_modified": nvd["last_modified"],
                      "complex_configuration": bool(nvd["complex_config"]), "has_configuration": bool(nvd["config_json"]), "from_local_database": bool(nvd["origin"])}
    out["cwes"] = [{"id": r[0], "source": r[1]} for r in con.execute("SELECT cwe_id,source FROM cve_cwe WHERE cve_id=? ORDER BY cwe_id LIMIT 20", (cve_id,))]
    out["references"] = [{"url": r[0], "source": r[1], "tags": _loads(r[2])} for r in con.execute("SELECT url,source,tags FROM cve_ref WHERE cve_id=? LIMIT 40", (cve_id,))]
    out["affected"] = [{"vendor": r[0], "product": r[1], "version": r[2], "from_incl": r[3], "from_excl": r[4], "to_incl": r[5], "to_excl": r[6]}
                       for r in con.execute("SELECT vendor,product,version,vsi,vse,vei,vee FROM cve_cpe WHERE cve_id=? ORDER BY vendor,product LIMIT 60", (cve_id,))]
    if row["in_kev"]:
        k = con.execute("SELECT description,required_action,due_date,notes FROM kev_entry WHERE cve_id=?", (cve_id,)).fetchone()
        out["kev"] = {**(out["kev"] or {}), "description": k["description"], "required_action": k["required_action"], "due_date": k["due_date"], "notes": k["notes"]}
    out["historical_techs"] = [{"id": r["tech_id"], "name": BY_ID[r["tech_id"]].name if r["tech_id"] in BY_ID else r["tech_id"], "applicability": r["applicability"]}
                               for r in con.execute("SELECT * FROM tech_cve_hist WHERE cve_id=?", (cve_id,))]
    out["links"] = {"nvd": f"https://nvd.nist.gov/vuln/detail/{cve_id}", "kev": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog" if row["in_kev"] else None,
                    "epss": f"https://api.first.org/data/v1/epss?cve={cve_id}"}
    out["cache"] = {"nvd_record": bool(row["has_nvd"]), "in_kev": bool(row["in_kev"]), "epss": row["epss"] is not None, "full_detail": d is not None}
    return out


# ---------------------------------------------------------------- on-demand NVD lookup (rate limited)
_gate = threading.Lock()
_recent: deque = deque(maxlen=50)
_cooldown: dict[str, float] = {}
MAX_PER_HOUR = 20
COOLDOWN_S = 600


class LookupError_(Exception):
    def __init__(self, status: int, msg: str):
        super().__init__(msg); self.status, self.msg = status, msg


def parse_detail(item: dict) -> dict:
    cve = item["cve"]
    cwes = sorted({d["value"] for w in cve.get("weaknesses") or [] for d in w.get("description") or [] if d.get("lang") == "en" and d.get("value")})
    refs, seen = [], set()
    for r in cve.get("references") or []:
        u = str(r.get("url", ""))
        if re.match(r"^https?://", u) and u not in seen:
            seen.add(u); refs.append({"url": u[:500], "source": str(r.get("source", ""))[:80], "tags": [str(t)[:30] for t in (r.get("tags") or [])][:6]})
    vers = []
    for conf in cve.get("configurations") or []:
        for node in conf.get("nodes") or []:
            for m in node.get("cpeMatch") or []:
                if m.get("vulnerable") is not True: continue
                parts = str(m.get("criteria", "")).split(":")
                if len(parts) < 6: continue
                v = {"product": f"{parts[3]} / {parts[4]}", "version": parts[5] if parts[5] not in ("*", "-") else None,
                     "from_incl": m.get("versionStartIncluding"), "from_excl": m.get("versionStartExcluding"),
                     "to_incl": m.get("versionEndIncluding"), "to_excl": m.get("versionEndExcluding")}
                if v not in vers: vers.append(v)
    return {"status": cve.get("vulnStatus"), "cwes": cwes, "refs": refs[:30], "versions": vers[:40]}


def lookup(cve_id: str) -> dict:
    """Fetch one CVE from NVD (user-triggered). Raises LookupError_ with an HTTP-ish status on limits/failures."""
    if not CVE_RE.fullmatch(cve_id):
        raise LookupError_(422, "Invalid CVE id")
    now = time.monotonic()
    if _cooldown.get(cve_id, 0) > now:
        raise LookupError_(429, "This CVE was looked up recently; try again in a few minutes")
    while _recent and now - _recent[0] > 3600:
        _recent.popleft()
    if len(_recent) >= MAX_PER_HOUR:
        raise LookupError_(429, f"On-demand NVD lookups are limited to {MAX_PER_HOUR} per hour")
    if not _gate.acquire(blocking=False):
        raise LookupError_(429, "Another NVD lookup is in progress")
    try:
        _recent.append(now); _cooldown[cve_id] = now + COOLDOWN_S
        try:
            payload = nvd_c._call({"cveId": cve_id})
        except SourceError as e:
            raise LookupError_(502, f"NVD request failed: {str(e)[:120]}")
        vulns = payload.get("vulnerabilities") or []
        if not vulns:
            raise LookupError_(404, "NVD has no record for this CVE id")
        item = vulns[0]
        parsed = nvd_c.parse_item(item)
        if not parsed:
            raise LookupError_(404, "NVD record is missing or rejected")
        ts = db.now_iso()
        d = parse_detail(item)
        with db.connect() as con:
            con.execute("INSERT INTO intel_cve(cve_id,cvss,cvss_version,published,description,cpes,nvd_fetched_at) VALUES(?,?,?,?,?,?,?) "
                        "ON CONFLICT(cve_id) DO UPDATE SET cvss=excluded.cvss,cvss_version=excluded.cvss_version,published=excluded.published,"
                        "description=excluded.description,cpes=excluded.cpes,nvd_fetched_at=excluded.nvd_fetched_at",
                        (cve_id, parsed["cvss"], parsed["cvss_version"], parsed["published"], parsed["description"], parsed["cpes"], ts))
            con.execute("INSERT INTO cve_detail(cve_id,status,cwes,refs,versions,fetched_at) VALUES(?,?,?,?,?,?) "
                        "ON CONFLICT(cve_id) DO UPDATE SET status=excluded.status,cwes=excluded.cwes,refs=excluded.refs,versions=excluded.versions,fetched_at=excluded.fetched_at",
                        (cve_id, d["status"], json.dumps(d["cwes"]), json.dumps(d["refs"]), json.dumps(d["versions"]), ts))
        _cooldown.pop(cve_id, None)
        return {"ok": True}
    finally:
        _gate.release()
