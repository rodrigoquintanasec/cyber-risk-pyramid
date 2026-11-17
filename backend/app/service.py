"""Read model: builds API payloads from the SQLite cache."""
from __future__ import annotations

from datetime import datetime, timezone

from . import db
from . import catalog as catalog_mod
from .catalog import BY_ID, CATALOG
from .config import settings
from .config import scoring_config
from .scoring import CveSignal, level_for, score_technology
from . import sync as sync_mod

NOTE = ("Score reflects published threat signals and vulnerabilities for this technology; "
        "it is not the actual risk of any organisation. Missing data is not evidence of safety.")


def _signals(con, tech_id: str) -> list[dict]:
    rows = con.execute(
        "SELECT t.cve_id,t.product,t.match_source,n.published,n.cvss,n.cvss_version,n.description,"
        "k.date_added,k.ransomware,k.name AS kev_name,e.score AS epss,e.percentile AS epss_pct "
        "FROM tech_cve t LEFT JOIN nvd_cve n ON n.cve_id=t.cve_id LEFT JOIN kev_entry k ON k.cve_id=t.cve_id "
        "LEFT JOIN epss e ON e.cve_id=t.cve_id WHERE t.tech_id=?", (tech_id,)).fetchall()
    return [dict(r) for r in rows]


def _coverage(con, tech_id: str) -> dict:
    from . import intel_corr
    loc = intel_corr.local_coverage(con, BY_ID[tech_id])
    if loc is not None:
        return loc
    qs = BY_ID[tech_id].nvd_queries
    ok = trunc = 0
    stamps: list[str] = []
    for q in qs:
        r = con.execute("SELECT truncated,last_success FROM query_log WHERE key=?", (q,)).fetchone()
        if r:
            ok += 1
            trunc += r["truncated"]
            stamps.append(r["last_success"])
    return {"nvd_queries_ok": ok, "nvd_queries_total": len(qs), "truncated_queries": trunc,
            "fraction": ok / len(qs) if qs else 0.0, "oldest_query": min(stamps) if stamps else None, "newest_query": max(stamps) if stamps else None}


COVERAGE_LABELS = {"monitored": "Monitored", "partial": "Partial Coverage", "catalog_only": "Catalog Only"}


def coverage_state(tech, cov: dict, cve_count: int, kev_count: int, monitored: bool, sync: dict | None = None) -> dict:
    """Monitored (all product queries synced) / Partial Coverage (some data) / Catalog Only (listed, nothing collected). Absence of CVEs never means safety."""
    lim = ["The absence of related CVEs is not evidence of the absence of vulnerabilities."]
    if not tech.nvd_queries:
        state = "partial" if (kev_count or cve_count) else "catalog_only"
        lim.append("No official CPE identifier: CVEs are linked only through CISA KEV product names, so coverage is incomplete and no Threat Signal Score is computed.")
    elif monitored and cov["fraction"] == 1 and not cov["truncated_queries"] and (sync is None or sync["status"] == "completed"):
        state = "monitored"
    elif (monitored and cov["nvd_queries_ok"] > 0) or cve_count > 0 or (sync and sync["status"] not in ("not_started", "pending")):
        state = "partial"
        lim.append(f"Recent NVD queries synced: {cov['nvd_queries_ok']} of {cov['nvd_queries_total']}." + (" Some results were truncated by the page limit." if cov["truncated_queries"] else ""))
        if sync and sync["status"] != "completed":
            lim.append(f"Historical backfill: {sync['label']} ({sync.get('queries_completed', 0)}/{sync.get('queries_required', 0)} queries). Counts are lower bounds until it completes.")
    else:
        state = "catalog_only"
        lim.append("Not monitored: NVD data is only collected for technologies on the dashboard, in a watchlist or in a company inventory." if not monitored else "Monitored, first synchronisation pending.")
    if sync and sync.get("history_limited"):
        lim.append(f"Historical CVEs are limited to the last {settings.nvd_backfill_years} years for this large product.")
    if tech.kind == "family":
        lim.append("Family of products: CVEs are linked per listed product identifier; unlisted members of the family are not covered.")
    return {"state": state, "label": COVERAGE_LABELS[state], "limitations": lim}


def _reasons(r: dict, bd: dict) -> list[str]:
    out = []
    ev = bd["evidence"]
    if ev == "recent_exploitation":
        out.append(f"Exploitation confirmed recently (CISA KEV, added {r['date_added']})")
    elif ev == "known_exploited":
        out.append(f"Known exploited (CISA KEV, added {r['date_added']})")
    if r["ransomware"]:
        out.append("Used in ransomware campaigns")
    if r["epss"] is not None:
        out.append(f"EPSS {r['epss'] * 100:.1f}%")
    out.append(f"CVSS {r['cvss']}" if r["cvss"] is not None else "CVSS not yet published")
    if r["published"]:
        out.append(f"Published {r['published'][:10]}")
    return out


def _quality(cov: dict, srcs: dict, top: list[dict]) -> dict:
    reasons = []
    if cov["fraction"] < 1:
        reasons.append(f"NVD coverage {cov['nvd_queries_ok']}/{cov['nvd_queries_total']} product queries")
    if cov["truncated_queries"]:
        reasons.append("Some NVD results truncated by page limit")
    for k, v in srcs.items():
        if v["ok"] is False:
            reasons.append(f"{k.upper()} source failing: showing last valid data")
        elif v["last_success"] is None:
            reasons.append(f"{k.upper()} not collected yet")
    miss_cvss = sum(1 for r in top if r["cvss"] is None)
    miss_epss = sum(1 for r in top if r["epss"] is None)
    if miss_cvss:
        reasons.append(f"{miss_cvss} of top CVEs have no CVSS yet")
    if miss_epss:
        reasons.append(f"{miss_epss} of top CVEs have no EPSS")
    limited = cov["fraction"] < settings_min_cov() or srcs["kev"]["last_success"] is None
    level = "limited" if limited else ("partial" if reasons else "good")
    return {"level": level, "reasons": reasons}


def settings_min_cov() -> float:
    return scoring_config.min_coverage


def build_technology(con, tech_id: str, detail: bool = False, srcs: dict | None = None, monitored: set | None = None) -> dict:
    tech = BY_ID[tech_id]
    srcs = srcs or _sources(con)
    rows = _signals(con, tech_id)
    sigs = [CveSignal(r["cve_id"], r["published"], r["cvss"], r["epss"], r["date_added"] is not None,
                      r["date_added"], bool(r["ransomware"])) for r in rows]
    res = score_technology(sigs)
    score = res["score"]
    cov = _coverage(con, tech_id)
    kev_count = sum(1 for s in sigs if s.kev)
    reason = None
    if score is None:
        reason = ("NVD/KEV data has not been collected for this technology yet." if cov["nvd_queries_ok"] == 0
                  else "No confirmed CVEs correlated in the analysis window. This is insufficient information, not evidence of no vulnerabilities.")
    elif cov["fraction"] < scoring_config.min_coverage and kev_count == 0:
        score, reason = None, "NVD coverage is too low to assess this technology. Insufficient information, not evidence of safety."
    if not tech.nvd_queries:   # no official product identifiers (cloud service / platform): never a score
        score, reason = None, "Threat Score Unavailable: this technology has no official product identifiers (CPE), so CVE coverage cannot be established."
    w = res["weights"]
    ranked = sorted(rows, key=lambda r: -w.get(r["cve_id"], 0.0))
    top = ranked[:5]
    drivers = [{
        "id": r["cve_id"], "relevance": round(100 * w[r["cve_id"]], 1), "evidence": res["breakdowns"][r["cve_id"]]["evidence"],
        "cvss": r["cvss"], "epss": r["epss"], "kev": r["date_added"] is not None, "product": r["product"],
        "reasons": _reasons(r, res["breakdowns"][r["cve_id"]]),
        "link": f"https://nvd.nist.gov/vuln/detail/{r['cve_id']}",
    } for r in top] if score is not None else []
    q = _quality(cov, srcs, top)
    stamps = [x for x in (cov["oldest_query"], srcs["kev"]["last_success"]) if x]
    key, label, color = level_for(score)
    if monitored is None:
        from . import catalog_db
        monitored = catalog_db.monitored_ids(con)
    from . import techsync
    sync_st = techsync.tech_status(con, tech_id, monitored)
    hist = [dict(r) for r in con.execute("SELECT h.cve_id,h.product,h.match_source,h.applicability,n.published,n.cvss,k.date_added AS kev_date,e.score AS epss FROM tech_cve_hist h LEFT JOIN nvd_cve n ON n.cve_id=h.cve_id "
                                         "LEFT JOIN kev_entry k ON k.cve_id=h.cve_id LEFT JOIN epss e ON e.cve_id=h.cve_id WHERE h.tech_id=? ORDER BY (k.cve_id IS NULL), n.published DESC LIMIT 500", (tech_id,))]
    hist_total = con.execute("SELECT COUNT(*) FROM tech_cve_hist WHERE tech_id=?", (tech_id,)).fetchone()[0]
    if score is None and sync_st["applicable"] and sync_st["status"] in ("partial", "completed") and reason and "has not been collected" in reason:
        reason = "No CVE falls inside the recent analysis window (or the recent-window query has not run yet). This is insufficient information, not evidence of no vulnerabilities."
    if score is None and hist_total and reason and "Threat Score Unavailable" not in reason:
        reason += f" {hist_total} older (historical) CVE(s) are correlated and listed separately; they are not recent signals and are not scored."
    cs = coverage_state(tech, cov, len(sigs) + hist_total, kev_count, tech.id in monitored, sync_st)
    out = {
        "sync": {k: v for k, v in sync_st.items() if k != "jobs"}, "historical": {"count": hist_total, "kev": sum(1 for h in hist if h["kev_date"]), "scored": False,
                 "note": "Older than the recent analysis window: shown for context, never used as a recent signal in the score.", "items": hist[:25] if detail else []},
        "cves_known": len(sigs) + hist_total, "cves_complete": sync_st["status"] == "completed" or not sync_st["applicable"],
        "vendor": tech.vendor, "product": tech.product, "category": tech.category, "kind": tech.kind, "monitored": tech.id in monitored,
        "coverage_state": cs["state"], "coverage_label": cs["label"], "limitations": cs["limitations"], "last_sync": cov["newest_query"],
        "correlation": {"kind": catalog_mod.match_kind(tech), "source": tech.correlation_source},
        "id": tech.id, "name": tech.name, "score": score,
        "level": {"key": key, "label": label, "color": color},
        "cve_count": len(sigs), "kev_count": kev_count,
        "recent_exploited_count": sum(1 for r in rows if res["breakdowns"][r["cve_id"]]["evidence"] == "recent_exploitation"),
        "insufficient_reason": reason,
        "updated_at": min(stamps) if stamps else None,
        "coverage": {k: cov[k] for k in ("nvd_queries_ok", "nvd_queries_total", "truncated_queries")},
        "quality": q, "drivers": drivers,
        "explanation": {"formula": "100 × (peak + 0.25·(1−peak)·mean(next 3 CVEs)) — volume of CVEs is not summed",
                        "components": res["components"], "notes": [NOTE], "window_days": settings.nvd_window_days,
                        "recent_days": scoring_config.recent_days},
    }
    if detail:
        out["aliases"] = list(tech.aliases)
        out["cves"] = [{
            "id": r["cve_id"], "product": r["product"], "match_source": r["match_source"],
            "published": r["published"], "cvss": r["cvss"], "cvss_version": r["cvss_version"],
            "epss": r["epss"], "epss_percentile": r["epss_pct"],
            "kev": r["date_added"] is not None, "kev_date_added": r["date_added"],
            "kev_ransomware": bool(r["ransomware"]), "description": r["description"] or r["kev_name"],
            "evidence": res["breakdowns"][r["cve_id"]]["evidence"],
            "relevance": round(100 * w.get(r["cve_id"], 0.0), 1),
            "links": {
                "nvd": f"https://nvd.nist.gov/vuln/detail/{r['cve_id']}",
                "kev": f"https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext={r['cve_id']}"
                if r["date_added"] else None,
                "epss": f"https://api.first.org/data/v1/epss?cve={r['cve_id']}" if r["epss"] is not None else None,
            },
        } for r in ranked[:100]]
    return out


def _sources(con) -> dict:
    src = {r["source"]: dict(r) for r in con.execute("SELECT * FROM source_status")}
    return {k: {"ok": bool(src[k]["ok"]) if k in src else None,
                "last_success": src[k]["last_success"] if k in src else None,
                "error": src[k]["error"] if k in src else None} for k in ("kev", "nvd", "epss")}


def status() -> dict:
    with db.connect() as con:
        src = {r["source"]: dict(r) for r in con.execute("SELECT * FROM source_status")}
        has_data = con.execute("SELECT 1 FROM tech_cve LIMIT 1").fetchone() is not None
        last = max((s["last_success"] for s in src.values() if s["last_success"]), default=None)
    sources = {k: {"ok": bool(src[k]["ok"]) if k in src else None, "last_success": src[k]["last_success"] if k in src else None,
                   "error": src[k]["error"] if k in src else None} for k in ("kev", "nvd", "epss")}
    running = sync_mod.state["running"]
    failed = [k for k, v in sources.items() if v["ok"] is False]
    ever_ok = [k for k, v in sources.items() if v["last_success"]]
    if not has_data and not ever_ok:
        overall = "loading" if running or not failed else "error"
    elif len(failed) == 3 or (failed and not ever_ok):
        overall = "error"
    elif failed:
        overall = "stale"
    elif any(v["ok"] is None for v in sources.values()):
        overall = "loading" if running else "stale"
    else:
        overall = "live"
    if overall in ("live", "stale") and last:
        age = (datetime.now(timezone.utc) - datetime.fromisoformat(last)).total_seconds() / 60
        if age > 2 * settings.sync_interval_minutes:
            overall = "stale"
    return {"state": overall, "syncing": running, "phase": sync_mod.state["phase"],
            "last_success": last, "sources": sources, "interval_minutes": settings.sync_interval_minutes}


def overview() -> dict:
    with db.connect() as con:
        from . import catalog_db
        srcs = _sources(con)
        mon = catalog_db.monitored_ids(con)
        order = {t.id: i for i, t in enumerate(catalog_mod.LEGACY)}
        shown = sorted((t for t in CATALOG if t.dashboard), key=lambda t: (order.get(t.id, 999), t.name.lower()))   # the six original pyramids keep their order
        techs = [build_technology(con, t.id, srcs=srcs, monitored=mon) for t in shown]
        uniq = con.execute("SELECT COUNT(DISTINCT cve_id) FROM tech_cve").fetchone()[0]
        kev_uniq = con.execute("SELECT COUNT(DISTINCT t.cve_id) FROM tech_cve t JOIN kev_entry k ON k.cve_id=t.cve_id").fetchone()[0]
    st = status()
    return {"technologies": techs, "totals": {"unique_cves": uniq, "kev_cves": kev_uniq, "security_news": None},
            "status": st, "updated_at": st["last_success"]}


def technology(tech_id: str) -> dict | None:
    if tech_id not in BY_ID:
        return None
    with db.connect() as con:
        return build_technology(con, tech_id, detail=True)
