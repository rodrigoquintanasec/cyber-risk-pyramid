"""Correlation engine over the LOCAL intelligence database.

Technology -> verified CPE identifiers (catalogue) -> cve_cpe (vulnerable matches) -> CVE -> CVSS / KEV / EPSS, all by SQL on indexed tables:
no external call, so adding a technology anywhere shows its known CVEs immediately. Correlation is by exact vendor/product ids only (never by
vendor alone). Recent CVEs (the Threat Signal Score window) go to tech_cve; every older correlated CVE goes to tech_cve_hist and is never scored.
"""
from __future__ import annotations

import logging
import re
from datetime import datetime, timezone

from . import catalog, db
from .config import settings

log = logging.getLogger("intel")
CHUNK = 400


def _now() -> datetime:
    return datetime.now(timezone.utc)


# ----------------------------------------------------------------------------- local dataset state
def local_state(con) -> dict:
    """{'cve': status, 'initialized': bool, 'recent_covered': bool}. Imported lazily to avoid a cycle."""
    from . import intel_import as ii
    info = ii.dataset_info(con, "cve")
    done = {r[0] for r in con.execute("SELECT unit FROM intel_unit WHERE dataset='cve'")}
    y = _now().year
    need = {f"nvdcve-2.0-{y}"} | ({f"nvdcve-2.0-{y - 1}"} if _now().month <= 4 else set())
    covered = need <= done
    return {"cve": info["status"], "initialized": bool(done), "recent_covered": covered, "complete": info["status"] in ("complete", "stale", "updating") and ii._is_complete(con, "cve"),
            "last_success": info["last_success"], "dataset_date": info["dataset_date"]}


def local_coverage(con, tech) -> dict | None:
    """Coverage numbers for service._coverage when the local database serves this technology; None = use the legacy per-query logs."""
    st = local_state(con)
    if not st["initialized"] or not tech.nvd_queries:
        return None
    ok = len(tech.nvd_queries) if st["recent_covered"] else 0
    return {"nvd_queries_ok": ok, "nvd_queries_total": len(tech.nvd_queries), "truncated_queries": 0, "fraction": 1.0 if ok else 0.0, "oldest_query": st["last_success"], "newest_query": st["last_success"],
            "source": "local", "history_complete": st["complete"]}


# ----------------------------------------------------------------------------- technology -> products
def tech_products(con, tech) -> list[tuple[str, list[str]]]:
    """[(vendor, [exact products])] from the technology's verified CPE matchers. Regex matchers are resolved against the products that actually exist in
    the local CVE data (an exact list), so a family technology only receives the products it declares."""
    out = []
    for vendor, rx in tech.cpe_matchers:
        try:
            pat = re.compile(rx)
        except re.error:
            continue
        prods = [r[0] for r in con.execute("SELECT DISTINCT product FROM cve_cpe WHERE vendor=?", (vendor,)) if pat.fullmatch(r[0])]
        if prods:
            out.append((vendor, prods))
    return out


def _rows(con, vendor: str, prods: list[str]):
    for i in range(0, len(prods), CHUNK):
        ch = prods[i:i + CHUNK]
        ph = ",".join("?" * len(ch))
        yield from con.execute(
            f"SELECT m.cve_id AS cve_id, n.published AS published, n.complex_config AS cx, MAX(m.version IS NOT NULL OR m.vsi IS NOT NULL OR m.vse IS NOT NULL OR m.vei IS NOT NULL OR m.vee IS NOT NULL) AS versioned, "
            f"GROUP_CONCAT(DISTINCT m.product) AS prods FROM cve_cpe m JOIN nvd_cve n ON n.cve_id=m.cve_id WHERE m.vendor=? AND m.product IN ({ph}) GROUP BY m.cve_id", [vendor, *ch])


def _correlate(con, tech, kev: dict, nvd_cut: str, kev_cut: str, recent: dict, hist: dict) -> None:
    for vendor, prods in tech_products(con, tech):
        for r in _rows(con, vendor, prods):
            key = (tech.id, r["cve_id"])
            label = f"{vendor} {sorted((r['prods'] or '').split(','))[0]}"
            in_scope = (r["published"] or "") >= nvd_cut[:19] or (r["cve_id"] in kev and (kev[r["cve_id"]]["date_added"] or "") >= kev_cut)
            if in_scope:
                recent[key] = (label, "nvd-cpe")
            else:
                hist[key] = (label, "nvd-cpe", "review" if r["cx"] else ("versioned" if r["versioned"] else "product"))


def _kev_links(kev: dict, techs, kev_cut: str, recent: dict, hist: dict) -> None:
    from .correlation import correlate_kev
    for cve_id, k in kev.items():
        t = correlate_kev(k["vendor"], k["product"])
        if not t or not t.enabled:
            continue
        key = (t.id, cve_id)
        if (k["date_added"] or "") >= kev_cut:
            recent.setdefault(key, (f'{k["vendor"]} {k["product"]}', "kev-product"))
        elif key not in recent and key not in hist:
            hist[key] = (f'{k["vendor"]} {k["product"]}', "kev-product", "product")


def rebuild(derived: bool | None = None) -> dict:
    """Recompute tech_cve / tech_cve_hist for every enabled technology from the local database.

    Everything is computed from READS; the two tables are then replaced in ONE SHORT write transaction (and only if the result changed). The heavy derived
    tables (cve_product_stats, cve_index) are refreshed only after an import (`derived=True`) or when they have never been built; the periodic sync passes
    nothing, so it no longer rewrites ~400k index rows every cycle."""
    from . import sync, vulns
    with db.maintenance:
        with db.connect() as con:
            local = bool(con.execute("SELECT 1 FROM cve_cpe LIMIT 1").fetchone())
            if local:
                nvd_cut, kev_cut = sync._cutoffs()
                kev = {r["cve_id"]: r for r in con.execute("SELECT cve_id,vendor,product,date_added FROM kev_entry")}
                recent: dict = {}
                hist: dict = {}
                for t in list(catalog.CATALOG):
                    if t.cpe_matchers:
                        _correlate(con, t, kev, nvd_cut, kev_cut, recent, hist)
                _kev_links(kev, catalog.CATALOG, kev_cut, recent, hist)
                new_recent = sorted((t, c, p, s) for (t, c), (p, s) in recent.items())
                new_hist = sorted((t, c, p, s, a) for (t, c), (p, s, a) in hist.items() if (t, c) not in recent)
                old_recent = sorted(tuple(r) for r in con.execute("SELECT tech_id,cve_id,product,match_source FROM tech_cve"))
                old_hist = sorted(tuple(r) for r in con.execute("SELECT tech_id,cve_id,product,match_source,applicability FROM tech_cve_hist"))
        if not local:
            with db.connect(timeout=120) as con:
                sync._legacy_recompute(con)             # local database not initialised yet: previous behaviour
            return {"mode": "legacy"}
        if new_recent != old_recent or new_hist != old_hist:
            with db.connect(timeout=120) as wr:
                if new_recent != old_recent:
                    wr.execute("DELETE FROM tech_cve")
                    wr.executemany("INSERT INTO tech_cve(tech_id,cve_id,product,match_source) VALUES(?,?,?,?)", new_recent)
                if new_hist != old_hist:
                    wr.execute("DELETE FROM tech_cve_hist")
                    wr.executemany("INSERT INTO tech_cve_hist(tech_id,cve_id,product,match_source,applicability) VALUES(?,?,?,?,?)", new_hist)
        out = {"mode": "local", "recent": len(new_recent), "historical": len(new_hist)}
        with db.connect() as con:
            need = derived if derived is not None else not vulns.index_ready(con)
        if need:
            out.update(vulns.refresh_derived())
        return out


def correlate_tech(con, tid: str) -> dict:
    """Instant correlation of ONE technology (e.g. just created with a verified CPE): no external request."""
    from . import sync
    t = catalog.BY_ID.get(tid)
    if not t:
        return {"recent": 0, "historical": 0}
    nvd_cut, kev_cut = sync._cutoffs()
    kev = {r["cve_id"]: r for r in con.execute("SELECT cve_id,vendor,product,date_added FROM kev_entry")}
    recent: dict = {}
    hist: dict = {}
    if t.enabled and t.cpe_matchers:
        _correlate(con, t, kev, nvd_cut, kev_cut, recent, hist)
    _kev_links({k: v for k, v in kev.items()}, [t], kev_cut, recent, hist)
    recent = {k: v for k, v in recent.items() if k[0] == tid}
    hist = {k: v for k, v in hist.items() if k[0] == tid}
    con.execute("DELETE FROM tech_cve WHERE tech_id=?", (tid,))
    con.execute("DELETE FROM tech_cve_hist WHERE tech_id=?", (tid,))
    con.executemany("INSERT INTO tech_cve(tech_id,cve_id,product,match_source) VALUES(?,?,?,?)", [(t_, c, p, s) for (t_, c), (p, s) in recent.items()])
    con.executemany("INSERT INTO tech_cve_hist(tech_id,cve_id,product,match_source,applicability) VALUES(?,?,?,?,?)", [(t_, c, p, s, a) for (t_, c), (p, s, a) in hist.items() if (t_, c) not in recent])
    return {"recent": len(recent), "historical": len(hist)}


# ----------------------------------------------------------------------------- CPE search for new / custom technologies
def search_cpe(con, q: str, limit: int = 15) -> dict:
    """Candidate vendor/product pairs for a name. Candidates are suggestions to be validated by a person: nothing is confirmed automatically."""
    q = (q or "").strip().lower()[:60]
    if len(q) < 2:
        return {"items": [], "source": None}
    like = "%" + q.replace("!", "!!").replace("%", "!%").replace("_", "!_").replace(" ", "_") + "%"
    have_dict = con.execute("SELECT 1 FROM cpe_dictionary LIMIT 1").fetchone() is not None
    if have_dict:
        rows = con.execute("SELECT vendor,product,MIN(part) part,COUNT(*) versions,MAX(title) title,SUM(deprecated=0) active FROM cpe_dictionary WHERE (product LIKE ? ESCAPE '!' OR vendor LIKE ? ESCAPE '!') "
                           "GROUP BY vendor,product ORDER BY (product=?) DESC, (vendor=?) DESC, versions DESC LIMIT ?", (like, like, q.replace(" ", "_"), q.replace(" ", "_"), limit)).fetchall()
        src = "cpe_dictionary"
    else:
        rows = con.execute("SELECT vendor,product,MIN(part) part,COUNT(DISTINCT cve_id) versions,NULL title,1 active FROM cve_cpe WHERE product LIKE ? ESCAPE '!' OR vendor LIKE ? ESCAPE '!' GROUP BY vendor,product ORDER BY versions DESC LIMIT ?",
                           (like, like, limit)).fetchall()
        src = "cve_cpe"
    out = []
    for r in rows:
        cves = con.execute("SELECT COUNT(DISTINCT cve_id) FROM cve_cpe WHERE vendor=? AND product=?", (r["vendor"], r["product"])).fetchone()[0]
        owner = next((t.id for t in catalog.CATALOG if any(v == r["vendor"] and re.fullmatch(rx, r["product"]) for v, rx in t.cpe_matchers)), None)
        out.append({"vendor": r["vendor"], "product": r["product"], "part": r["part"], "dictionary_versions": r["versions"] if src == "cpe_dictionary" else None, "title": r["title"], "cves": cves,
                    "already_in_catalog": owner})
    return {"items": out, "source": src, "note": "Suggestions only: pick the exact vendor/product yourself. Ambiguous names are never confirmed automatically."}


def cpe_exists(con, vendor: str, product: str) -> bool | None:
    """True/False when the local CPE dictionary (or CVE data) can answer, None when no local data exists to verify against."""
    if con.execute("SELECT 1 FROM cpe_dictionary LIMIT 1").fetchone():
        return con.execute("SELECT 1 FROM cpe_dictionary WHERE vendor=? AND product=? LIMIT 1", (vendor, product)).fetchone() is not None
    if con.execute("SELECT 1 FROM cve_cpe LIMIT 1").fetchone():
        return con.execute("SELECT 1 FROM cve_cpe WHERE vendor=? AND product=? LIMIT 1", (vendor, product)).fetchone() is not None
    return None
