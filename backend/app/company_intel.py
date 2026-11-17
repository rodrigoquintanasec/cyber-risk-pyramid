"""Company dashboards, analytics, "What Changed?", snapshots, reports and comparison.

Everything global (technology Threat Signal Score, CVE data, news clusters, comparable coverage) is REUSED read-only:
service.build_technology, intel corpus clusters, analytics windows. Nothing here recalculates or alters a score.
"""
from __future__ import annotations

import hashlib
import json
import uuid
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone

from . import analytics, company, company_expo as expo_m, db, service
from .catalog import BY_ID
from .company import CompanyError
from .config import settings
from .exposure import CONFIRMED, LABELS, NOT_APPLICABLE, POTENTIAL, REVIEW, INSUFFICIENT, STATUSES
from .news import repo as news_repo
from .news.sources import BY_ID as SOURCES, is_verified_official
from .scoring import level_for

SNAP_MIN_MINUTES = 5
SYNC_SNAP_MIN_MINUTES = 360
MAX_SNAPSHOTS = 200
PERIODS = ("24h", "7d", "30d", "90d", "custom")


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(d) -> str | None:
    return d.isoformat(timespec="seconds") if d else None


# ----------------------------------------------------------------------------- shared helpers
def tech_ids(expo: dict) -> set[str]:
    return {t["tech_id"] for t in expo["products"].values() if t["tech_id"] and t["active_assets"]}


def _tech_payload(con, ct: dict, srcs: dict) -> dict:
    """Global Threat Signal payload for a catalog technology (unchanged scoring), or an explicit 'unavailable' for custom products."""
    if ct["tech_id"]:
        t = service.build_technology(con, ct["tech_id"], srcs=srcs)
        t["score_available"] = t["score"] is not None
        return t
    key, label, color = level_for(None)
    return {"id": f"custom:{ct['id']}", "name": ct["label"], "score": None, "level": {"key": key, "label": "Threat Score Unavailable", "color": color}, "cve_count": 0, "kev_count": 0,
            "recent_exploited_count": 0, "insufficient_reason": "This product is not part of the global technology catalogue, so no Threat Signal Score exists for it. Related CVEs are matched by exact vendor/product only.",
            "updated_at": None, "coverage": {"nvd_queries_ok": 0, "nvd_queries_total": 0, "truncated_queries": 0}, "quality": {"level": "limited", "reasons": ["Threat Score Unavailable"]}, "drivers": [],
            "explanation": {"formula": "n/a", "components": {}, "notes": ["No global score for custom products."], "window_days": settings.nvd_window_days, "recent_days": 0}, "score_available": False,
            "coverage_state": "unavailable", "coverage_label": "Score Unavailable", "category": "Other", "vendor": ct["vendor"] or "", "kind": "product", "monitored": False, "limitations": ["Not part of the global catalogue: no Threat Signal Score and no news linkage."]}


def _events(f_period: str, date_from=None, date_to=None, mode="all", techset: set[str] | None = None):
    ctx = analytics.get_ctx()
    f = analytics.Filters(period=f_period, date_from=date_from, date_to=date_to, mode=mode)
    win = analytics.resolve_window(f, ctx.now)
    allowed, comp = analytics.allowed_sources(ctx, f, win)
    def pick(lo, hi):
        evs = analytics.active_events(ctx, f, lo, hi, allowed)
        return [e for e in evs if techset and set(e[0]["techs"]) & techset] if techset is not None else evs
    return ctx, f, win, allowed, comp, pick


def _is_official_adv(m: dict) -> bool:
    return m["source_type"] == "official" and bool(m["official"])


# ----------------------------------------------------------------------------- dashboard
def dashboard(con, cid: str, period: str = "30d") -> dict:
    prof = company.profile(con, cid)
    expo = expo_m.company_exposure(con, cid)
    inv_assets = [a for t in expo["products"].values() for a in t["assets"]]
    cov = company.coverage(inv_assets)
    c = expo_m.counts(expo)
    ts = tech_ids(expo)
    srcs = service._sources(con)
    ctx, f, win, allowed, comp, pick = _events(period, techset=ts)
    evs = pick(win.start, win.end)
    per_tech_events: Counter = Counter(); per_tech_official: Counter = Counter()
    for cl, mem, _ in evs:
        off = any(_is_official_adv(m) for m in mem)
        for t in set(cl["techs"]) & ts:
            per_tech_events[t] += 1; per_tech_official[t] += off
    techs = []
    for ct in expo["products"].values():
        if not ct["active_assets"]:
            continue
        p = _tech_payload(con, ct, srcs)
        cvs = [r for r in expo["cves"].values() if ct["id"] in r["per_tech"]]
        stc = Counter(r["per_tech"][ct["id"]]["effective"] for r in cvs if r["per_tech"][ct["id"]]["effective"])
        act = [a for a in ct["assets"] if a["status"] == "active"]
        techs.append({**p, "company_tech_id": ct["id"], "catalog": bool(ct["tech_id"]), "assets": len(act), "retired_assets": len(ct["assets"]) - len(act),
                      "versions": sorted({a["version"] or f"{a['version_min'] or '*'}–{a['version_max'] or '*'}" for a in act if a["version"] or a["version_min"] or a["version_max"]})[:8],
                      "assets_without_version": sum(1 for a in act if not (a["version"] or a["version_min"] or a["version_max"])),
                      "related_cves": len(cvs), "related_kev": sum(1 for r in cvs if r["in_kev"]),
                      "exposure": {"potential": stc.get(POTENTIAL, 0), "confirmed": stc.get(CONFIRMED, 0), "needs_review": stc.get(REVIEW, 0), "insufficient": stc.get(INSUFFICIENT, 0)},
                      "news_events": per_tech_events.get(ct["tech_id"], 0) if ct["tech_id"] else None, "official_advisories": per_tech_official.get(ct["tech_id"], 0) if ct["tech_id"] else None,
                      "data_availability": "unavailable" if not ct["tech_id"] else ("full" if p["score"] is not None else p["coverage_state"])})
    techs.sort(key=lambda t: (t["name"].lower()))
    st = c["statuses"]
    kpis = [
        {"key": "technologies", "label": "Monitored Technologies", "value": len(techs), "scope": "coverage"},
        {"key": "assets", "label": "Registered Assets", "value": cov["active_assets"], "scope": "coverage", "hint": f"{prof['retired_assets']} retired"},
        {"key": "related_cves", "label": "Related CVEs", "value": c["related"], "scope": "signal", "hint": "unique CVE ids across products"},
        {"key": "kev", "label": "KEV-Listed CVEs", "value": c["kev"], "scope": "signal", "hint": "catalogue listing, not proof of exposure"},
        {"key": "potential", "label": "Potentially Applicable CVEs", "value": st[POTENTIAL], "scope": "potential", "hint": f"{st[REVIEW]} need review · {st[INSUFFICIENT]} insufficient data"},
        {"key": "confirmed", "label": "Confirmed Applicable CVEs", "value": st[CONFIRMED], "scope": "confirmed", "hint": "analyst-validated with evidence"},
        {"key": "events", "label": "Related News Events", "value": len(evs), "scope": "attention", "hint": f"distinct events, {period}"},
        {"key": "advisories", "label": "Official Advisories", "value": sum(1 for _, mem, _ in evs if any(_is_official_adv(m) for m in mem)), "scope": "attention", "hint": f"events with a verified vendor/agency advisory, {period}"},
        {"key": "coverage", "label": "Inventory Coverage", "value": cov["inventory_coverage"], "unit": "%", "scope": "coverage", "hint": "version known + verified within 90 days"},
    ]
    return {"company": prof, "period": period, "since": _iso(win.start), "until": _iso(win.end), "kpis": kpis, "technologies": techs, "exposure": c, "inventory": cov, "truncated": expo["truncated"],
            "status": service.status(), "concepts": {"signal": "Threat Signal: external signals for a technology (not this company's risk)", "potential": "Potential Exposure: product and version may match",
                                                    "confirmed": "Confirmed Exposure: validated by an analyst with evidence", "attention": "Intelligence Attention: news and advisories", "coverage": "Data Coverage: inventory completeness"},
            "notes": ["Threat Signal Scores are the global scores of each technology; they do not reflect this company's asset count or actual risk.",
                      "A related CVE does not mean the company is vulnerable: applicability depends on versions and configuration."]}


def tech_detail(con, cid: str, ctid: int) -> dict:
    expo = expo_m.company_exposure(con, cid)
    ct = expo["products"].get(ctid)
    if not ct:
        raise CompanyError(404, "Technology not found for this company")
    srcs = service._sources(con)
    p = _tech_payload(con, ct, srcs)
    cves = sorted((r for r in expo["cves"].values() if ctid in r["per_tech"]), key=lambda r: (not r["in_kev"], -(r["epss"] or 0), -(r["cvss"] or 0), r["id"]))
    ctx, f, win, allowed, comp, pick = _events("30d", techset={ct["tech_id"]} if ct["tech_id"] else set())
    evs = pick(win.start, win.end) if ct["tech_id"] else []
    rows = lambda it: [{"id": cl["id"], "title": cl["title"], "last_published": _iso(mem[-1]["ts"]), "sources": len({m["source_id"] for m in mem}), "priority": ctx.corpus.prio[cl["id"]]["score"],  # noqa: E731
                        "url": mem[-1]["url"], "official": any(_is_official_adv(m) for m in mem)} for cl, mem, _ in it]
    ev_sorted = sorted(evs, key=lambda e: -ctx.corpus.prio[e[0]["id"]]["score"])
    return {"company_tech_id": ctid, "technology": p, "catalog": bool(ct["tech_id"]), "vendor": ct["vendor"], "product": ct["product"], "assets": ct["assets"],
            "cves": [{"id": r["id"], "cvss": r["cvss"], "epss": r["epss"], "kev": r["in_kev"], "published": r["published"], "effective_status": r["per_tech"][ctid]["effective"],
                      "automatic_status": r["per_tech"][ctid]["auto"], "assets_flagged": sum(1 for a in r["per_tech"][ctid]["assets"] if a["status"] in (POTENTIAL, REVIEW))} for r in cves[:60]],
            "cve_total": len(cves), "advisories": rows([e for e in ev_sorted if any(_is_official_adv(m) for m in e[1])][:10]), "news": rows([e for e in ev_sorted if not any(_is_official_adv(m) for m in e[1])][:10]),
            "graph_node": f"tech:{ct['tech_id']}" if ct["tech_id"] else None, "explorer": {"tech": ct["tech_id"]} if ct["tech_id"] else {"vendor": ct["vendor"], "product": ct["product"]},
            "news_available": bool(ct["tech_id"]),
            "note": None if ct["tech_id"] else "Custom product: news are not linked (no vague name matching) and no Threat Signal Score exists."}


# ----------------------------------------------------------------------------- vulnerabilities list
def vulnerabilities(con, cid: str, *, status=None, ctid=None, kev=None, q=None, sort="priority", page=1, page_size=25) -> dict:
    page, page_size = max(1, page), max(1, min(50, page_size))
    expo = expo_m.company_exposure(con, cid)
    rows = list(expo["cves"].values())
    if ctid is not None:
        rows = [r for r in rows if ctid in r["per_tech"]]
    if status == "unassessed":
        rows = [r for r in rows if not r["effective"]]
    elif status:
        rows = [r for r in rows if r["effective"] == status]
    if kev is not None:
        rows = [r for r in rows if r["in_kev"] == kev]
    if q:
        qq = q.strip().upper()[:60]
        rows = [r for r in rows if qq in r["id"] or qq.lower() in (r["description"] or "").lower()]
    key = {"priority": lambda r: (not r["in_kev"], -(r["epss"] or 0), -(r["cvss"] or 0), r["id"]), "cvss": lambda r: (-(r["cvss"] or 0), r["id"]),
           "epss": lambda r: (-(r["epss"] or 0), r["id"]), "published": lambda r: (r["published"] or "") and "", "status": lambda r: (r["effective"] or "z", r["id"])}[sort]
    if sort == "published":
        rows.sort(key=lambda r: r["published"] or "", reverse=True)
    else:
        rows.sort(key=key)
    chunk = rows[(page - 1) * page_size: page * page_size]
    items = [{"id": r["id"], "description": (r["description"] or "")[:260] or None, "cvss": r["cvss"], "epss": r["epss"], "kev": r["in_kev"], "published": r["published"],
              "effective_status": r["effective"], "products": [{"company_tech_id": t["company_tech_id"], "label": t["label"], "status": t["effective"], "assessed": bool(t["manual"])} for t in r["per_tech"].values()],
              "assets_flagged": r["assets_flagged"]} for r in chunk]
    return {"items": items, "total": len(rows), "page": page, "page_size": page_size, "pages": max(1, -(-len(rows) // page_size)), "counts": expo_m.counts(expo), "truncated": expo["truncated"],
            "note": "CVEs are listed once per identifier, even when several products or assets relate to them."}


def news(con, cid: str, *, official=None, page=1, page_size=20) -> dict:
    expo = expo_m.company_exposure(con, cid)
    ts = sorted(tech_ids(expo))
    out = news_repo.search_news(con, techs=ts, source_type="official" if official else None, page=page, page_size=page_size)
    if official is False:
        out = news_repo.search_news(con, techs=ts, page=page, page_size=page_size)
    return {**out, "technologies": ts, "note": "News are linked only to catalogue technologies with structured evidence; custom products have no news linkage."}


# ----------------------------------------------------------------------------- snapshots (append-only)
def take_snapshot(con, cid: str, reason: str, min_minutes: int = SNAP_MIN_MINUTES) -> int | None:
    company.get(con, cid)
    last = con.execute("SELECT taken_at FROM company_snapshot WHERE company_id=? ORDER BY id DESC LIMIT 1", (cid,)).fetchone()
    if last and (_now() - datetime.fromisoformat(last[0])).total_seconds() < min_minutes * 60:
        return None
    expo = expo_m.company_exposure(con, cid)
    inv_assets = [a for t in expo["products"].values() for a in t["assets"]]
    if not inv_assets and not last:
        return None                                    # no baseline for an empty inventory
    cov = company.coverage(inv_assets)
    c = expo_m.counts(expo)
    ts = tech_ids(expo)
    ctx, f, win, allowed, comp, pick = _events("30d", techset=ts)
    evs = pick(win.start, win.end)
    cur = con.execute("INSERT INTO company_snapshot(company_id,taken_at,reason,technologies,assets,related_cves,kev_cves,status_counts,news_events,official_advisories,inventory_coverage,cve_ids,kev_ids,epss) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                      (cid, db.now_iso(), reason, sum(1 for t in expo["products"].values() if t["active_assets"]), cov["active_assets"], c["related"], c["kev"], json.dumps(c["statuses"]), len(evs),
                       sum(1 for _, mem, _ in evs if any(_is_official_adv(m) for m in mem)), cov["inventory_coverage"], json.dumps(sorted(expo["cves"])),
                       json.dumps(sorted(k for k, r in expo["cves"].items() if r["in_kev"])), json.dumps({k: round(r["epss"], 4) for k, r in expo["cves"].items() if r["epss"] is not None})))
    con.execute("DELETE FROM company_snapshot WHERE company_id=? AND id NOT IN (SELECT id FROM company_snapshot WHERE company_id=? ORDER BY id DESC LIMIT ?)", (cid, cid, MAX_SNAPSHOTS))
    return cur.lastrowid


def snapshot_all_after_sync() -> None:
    with db.connect() as con:
        for (cid,) in con.execute("SELECT id FROM company WHERE status='active' AND owner_id=?", (company.OWNER,)).fetchall():
            try:
                take_snapshot(con, cid, "sync", SYNC_SNAP_MIN_MINUTES)
            except Exception:
                pass


def _snaps(con, cid: str, limit=200) -> list[dict]:
    rows = [dict(r) for r in con.execute("SELECT * FROM company_snapshot WHERE company_id=? ORDER BY id DESC LIMIT ?", (cid, limit))]
    rows.reverse()
    for r in rows:
        r["status_counts"] = json.loads(r["status_counts"] or "{}")
    return rows


# ----------------------------------------------------------------------------- analytics
def _series(win, items_ts: list[datetime]) -> list[int]:
    s = [0] * win.nb
    for t in items_ts:
        if win.start <= t < win.end:
            s[win.bucket(t)] += 1
    return s


def _d(s: str | None) -> datetime | None:
    if not s:
        return None
    try:
        d = datetime.fromisoformat(s)
        return d if d.tzinfo else d.replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def company_analytics(con, cid: str, period="30d", date_from=None, date_to=None, mode="all") -> dict:
    prof = company.profile(con, cid)
    expo = expo_m.company_exposure(con, cid)
    ts = tech_ids(expo)
    ctx, f, win, allowed, comp, pick = _events(period, date_from, date_to, mode, techset=ts)
    base = {"company": {"id": cid, "name": prof["name"]}, "filters": analytics._filters_echo(f, win, ctx, comp), "mode": mode}
    if comp is not None and not comp["sufficient"]:
        return {**base, "status": "insufficient_comparable", "message": analytics.INSUFFICIENT}
    a = analytics.window_assessment(ctx, f, win, allowed)
    cur, prev = pick(win.start, win.end), pick(win.prev_start, win.start)
    # 1 timeline
    bs = win.labels()
    ev_s = [set() for _ in range(win.nb)]; art_s = [0] * win.nb; off_s = [0] * win.nb
    for cl, mem, _ in cur:
        for m in mem:
            b = win.bucket(m["ts"]); ev_s[b].add(cl["id"]); art_s[b] += 1; off_s[b] += _is_official_adv(m)
    timeline = {"bucket_starts": bs, "events": [len(x) for x in ev_s], "articles": art_s, "official_advisory_articles": off_s, "compare": analytics.compare(len(cur), len(prev), a)}
    # 2 vulnerability discovery (NVD publication date)
    rows = list(expo["cves"].values())
    oldest_local = ctx.now - timedelta(days=settings.nvd_window_days)
    pub = [(_d(r["published"]), r) for r in rows if _d(r["published"])]
    n_cur = [r for d, r in pub if win.start <= d < win.end]
    n_prev = [r for d, r in pub if win.prev_start <= d < win.start]
    disc_ok = win.prev_start >= oldest_local
    disc_cmp = analytics.compare(len(n_cur), len(n_prev), {**a, "history_ok": disc_ok, "coverage_changed": False, "previous_articles": len(n_prev), "previous_density": 1}) if disc_ok else \
        {"current": len(n_cur), "previous": None, "delta": None, "pct": None, "status": "insufficient", "reason": f"The local NVD catalogue only covers the last {settings.nvd_window_days} days"}
    discovery = {"bucket_starts": bs, "new_cves": _series(win, [d for d, _ in pub]), "kev_related_new": _series(win, [d for d, r in pub if r["in_kev"]]), "compare": disc_cmp,
                 "note": "Counts CVEs by NVD publication date among this company's related CVEs (unique ids)."}
    # 3 KEV watch
    kv = [(r, _d(r["kev_date"])) for r in rows if r["in_kev"]]
    kev_cur = [(r, d) for r, d in kv if d and win.start <= d < win.end]
    kev_prev = [(r, d) for r, d in kv if d and win.prev_start <= d < win.start]
    kev_ok = win.prev_start >= ctx.now - timedelta(days=settings.kev_lookback_days)
    kev_watch = {"bucket_starts": bs, "series": _series(win, [d for _, d in kv if d]), "total_related": len(kv),
                 "compare": analytics.compare(len(kev_cur), len(kev_prev), {**a, "history_ok": kev_ok, "coverage_changed": False, "previous_articles": len(kev_prev), "previous_density": 1}, analytics.MIN_BASE_SMALL) if kev_ok else
                 {"current": len(kev_cur), "previous": None, "delta": None, "pct": None, "status": "insufficient", "reason": "Outside the KEV lookback kept locally"},
                 "added": [{"cve": r["id"], "kev_added": r["kev_date"], "cvss": r["cvss"], "epss": r["epss"], "status": r["effective"], "products": [t["label"] for t in r["per_tech"].values()]}
                           for r, d in sorted(kev_cur, key=lambda x: x[1], reverse=True)[:30]],
                 "note": "KEV lists vulnerabilities exploited in the wild somewhere; a listing is not evidence about this company."}
    # 4 media attention per technology
    def per_tech(evs):
        c: Counter = Counter()
        for cl, mem, _ in evs:
            for t in set(cl["techs"]) & ts:
                c[t] += 1
        return c
    pc, pp = per_tech(cur), per_tech(prev)
    attention = [{"tech_id": t, "name": BY_ID[t].name, "events": pc.get(t, 0), "compare": analytics.compare(pc.get(t, 0), pp.get(t, 0), a, analytics.MIN_BASE_SMALL)} for t in sorted(ts)]
    attention.sort(key=lambda x: (-x["events"], x["name"]))
    # 5 exposure status + history
    snaps = _snaps(con, cid)
    in_win = [s for s in snaps if win.start <= _d(s["taken_at"]) < win.end]
    c = expo_m.counts(expo)
    exposure_status = {"current": c["statuses"], "unassessed": c["unassessed"], "related": c["related"],
                       "history": [{"taken_at": s["taken_at"], **s["status_counts"]} for s in in_win],
                       "history_note": None if len(in_win) >= 2 else (f"History starts at the first snapshot ({snaps[0]['taken_at']}); fewer than two snapshots fall in this period." if snaps else "No snapshot has been recorded yet; history begins when the first one is taken.")}
    # 6 inventory quality
    assets = [x for t in expo["products"].values() for x in t["assets"]]
    cov = company.coverage(assets)
    by_tech = [{"label": t["label"], "assets": t["active_assets"], "with_version": sum(1 for x in t["assets"] if x["status"] == "active" and (x["version"] or x["version_min"] or x["version_max"]))}
               for t in expo["products"].values() if t["active_assets"]]
    ages = Counter()
    today = _now().date()
    for x in assets:
        if x["status"] != "active": continue
        if not x["last_verified"]: ages["never verified"] += 1
        else:
            d = (today - datetime.fromisoformat(x["last_verified"]).date()).days
            ages["≤30 days" if d <= 30 else "31–90 days" if d <= 90 else ">90 days"] += 1
    inv_events = [dict(r) for r in con.execute("SELECT kind,COUNT(*) n FROM company_event WHERE company_id=? AND occurred_at>=? AND occurred_at<? AND kind IN ('asset_added','asset_updated','asset_retired','technology_added') GROUP BY kind", (cid, _iso(win.start), _iso(win.end)))]
    quality = {"coverage": cov, "by_technology": by_tech, "verification_age": dict(ages), "inventory_changes": inv_events}
    # EPSS movement between the two latest snapshots
    epss = {"available": False, "movers": [], "note": "EPSS changes need at least two snapshots; none are fabricated."}
    if len(snaps) >= 2:
        two = [json.loads(con.execute("SELECT epss FROM company_snapshot WHERE id=?", (s["id"],)).fetchone()[0] or "{}") for s in snaps[-2:]]
        mv = [{"cve": k, "from": two[0][k], "to": v, "delta": round(v - two[0][k], 4)} for k, v in two[1].items() if k in two[0] and abs(v - two[0][k]) >= 0.05]
        epss = {"available": True, "between": [snaps[-2]["taken_at"], snaps[-1]["taken_at"]], "movers": sorted(mv, key=lambda x: -abs(x["delta"]))[:15], "note": "Movements between the two most recent snapshots (|Δ| ≥ 0.05)."}
    return {**base, "status": "ok", "message": None, "assessment": a, "timeline": timeline, "discovery": discovery, "kev_watch": kev_watch, "attention": attention, "exposure_status": exposure_status,
            "inventory_quality": quality, "epss": epss, "snapshots": {"count": len(snaps), "first": snaps[0]["taken_at"] if snaps else None},
            "notes": ["Intelligence Attention counts media/advisory coverage of the company's technologies, not incidents affecting the company.",
                      "Comparable Sources mode restricts news metrics to sources with demonstrable history in both periods."]}


# ----------------------------------------------------------------------------- What changed?
def changes(con, cid: str, period="7d", date_from=None, date_to=None, page=1, page_size=30) -> dict:
    page, page_size = max(1, page), max(1, min(50, page_size))
    company.get(con, cid)
    expo = expo_m.company_exposure(con, cid)
    ctx = analytics.get_ctx()
    win = analytics.resolve_window(analytics.Filters(period=period, date_from=date_from, date_to=date_to), ctx.now)
    lo, hi = _iso(win.start), _iso(win.end)
    if period != "custom":      # knowledge times are real wall-clock times: do not anchor on the (cached) corpus clock
        now = _now()
        lo, hi = _iso(now - timedelta(hours=analytics.PRESETS[period])), _iso(now + timedelta(seconds=1))
    items: list[dict] = []
    ts = sorted(tech_ids(expo))
    if ts:
        ph = ",".join("?" * len(ts))
        for r in con.execute(f"SELECT DISTINCT n.id,n.title,n.url,n.published,n.collected_at,n.source_id,s.name sname,s.type stype FROM news_item n JOIN news_tech nt ON nt.news_id=n.id JOIN news_source s ON s.id=n.source_id "
                             f"WHERE nt.tech_id IN ({ph}) AND n.collected_at>=? AND n.collected_at<? ORDER BY n.collected_at DESC LIMIT 400", [*ts, lo, hi]):
            src = SOURCES.get(r["source_id"])
            off = r["stype"] == "official" and bool(src and is_verified_official(src, r["url"]))
            pub, known = _d(r["published"]), _d(r["collected_at"])
            late = bool(pub and known and (known - pub) > timedelta(hours=48))
            items.append({"kind": "official_advisory" if off else "news", "title": r["title"], "source": r["sname"], "url": r["url"], "published_at": r["published"], "known_at": r["collected_at"],
                          "historical": late, "note": "Published earlier; first collected by Cyber Risk Pyramid on this date." if late else (None if pub else "No publication date in the feed")})
    snaps = _snaps(con, cid)
    pubd = {k: r["published"] for k, r in expo["cves"].items()}
    kevd = {k: r["kev_date"] for k, r in expo["cves"].items()}
    cvss = {k: r["cvss"] for k, r in expo["cves"].items()}
    for prev, cur in zip(snaps, snaps[1:]):
        t = cur["taken_at"]
        if not (lo <= t < hi):
            continue
        pset = set(json.loads(con.execute("SELECT cve_ids FROM company_snapshot WHERE id=?", (prev["id"],)).fetchone()[0] or "[]"))
        cset = set(json.loads(con.execute("SELECT cve_ids FROM company_snapshot WHERE id=?", (cur["id"],)).fetchone()[0] or "[]"))
        pk = set(json.loads(con.execute("SELECT kev_ids FROM company_snapshot WHERE id=?", (prev["id"],)).fetchone()[0] or "[]"))
        ck = set(json.loads(con.execute("SELECT kev_ids FROM company_snapshot WHERE id=?", (cur["id"],)).fetchone()[0] or "[]"))
        for cve in sorted(cset - pset)[:100]:
            p = pubd.get(cve)
            hist = bool(p and p < prev["taken_at"])
            items.append({"kind": "new_cve", "title": f"{cve} is now associated with a monitored product", "cve": cve, "published_at": p, "known_at": t, "historical": hist,
                          "note": "Published before the previous snapshot: newly associated or newly cached, not newly disclosed." if hist else None})
        for cve in sorted(ck - pk)[:100]:
            p = kevd.get(cve)
            hist = bool(p and p < prev["taken_at"][:10])
            items.append({"kind": "kev_added", "title": f"{cve} listed in CISA KEV", "cve": cve, "published_at": p, "known_at": t, "historical": hist,
                          "note": "KEV date precedes the previous snapshot: discovered late by this system." if hist else None})
    for r in con.execute("SELECT kind,ref,detail,occurred_at FROM company_event WHERE company_id=? AND occurred_at>=? AND occurred_at<? AND kind IN ('technology_added','asset_added','asset_updated','asset_retired','assessment_changed') ORDER BY id DESC LIMIT 200", (cid, lo, hi)):
        label = {"technology_added": "Product added to the inventory", "asset_added": "Asset added", "asset_updated": "Asset updated", "asset_retired": "Asset retired", "assessment_changed": "Applicability assessment changed"}[r["kind"]]
        items.append({"kind": {"assessment_changed": "assessment_change"}.get(r["kind"], "inventory"), "title": f"{label}: {r['detail'] or r['ref']}", "cve": r["ref"] if r["kind"] == "assessment_changed" else None,
                      "published_at": None, "known_at": r["occurred_at"], "historical": False, "note": "Recorded by an analyst in this application."})
    items.sort(key=lambda x: x["known_at"], reverse=True)
    counts = Counter(i["kind"] for i in items)
    return {"items": items[(page - 1) * page_size: page * page_size], "total": len(items), "page": page, "pages": max(1, -(-len(items) // page_size)), "counts": dict(counts),
            "since": lo, "until": hi, "snapshots": len(snaps),
            "notes": ["'Published' is when the fact became public; 'known' is when Cyber Risk Pyramid first recorded it. Items marked historical were published earlier and discovered or associated later.",
                      "CVE and KEV changes are derived from company snapshots; there is no history before the first snapshot." if len(snaps) < 2 else "CVE and KEV changes are derived from consecutive company snapshots."]}


# ----------------------------------------------------------------------------- reports
PERIOD_LABELS = {"24h": "Last 24 Hours", "7d": "Last 7 Days", "30d": "Last 30 Days", "90d": "Last 90 Days"}


def generate_report(con, cid: str, period: str) -> dict:
    if period not in PERIOD_LABELS:
        raise CompanyError(422, "period must be one of 24h, 7d, 30d, 90d")
    dash = dashboard(con, cid, period)
    prof = dash["company"]
    expo = expo_m.company_exposure(con, cid)
    an = company_analytics(con, cid, period)
    ch = changes(con, cid, period, page_size=50)
    ctx = analytics.get_ctx()
    win = analytics.resolve_window(analytics.Filters(period=period), ctx.now)
    rows = list(expo["cves"].values())
    k = {x["key"]: x["value"] for x in dash["kpis"]}
    st = dash["exposure"]["statuses"]
    top = sorted(rows, key=lambda r: (not r["in_kev"], -(r["epss"] or 0), -(r["cvss"] or 0), r["id"]))
    cv = lambda r: {"cve": r["id"], "cvss": r["cvss"], "epss": r["epss"], "kev": r["in_kev"], "published": r["published"], "status": LABELS.get(r["effective"], "Unassessed"), "products": [t["label"] for t in r["per_tech"].values()]}  # noqa: E731
    pub_cur = [r for r in rows if (d := _d(r["published"])) and win.start <= d < win.end]
    kev_new = [r for r in rows if r["in_kev"] and (d := _d(r["kev_date"])) and win.start <= d < win.end]
    ts = tech_ids(expo)
    _, _, _, _, _, pick = _events(period, techset=ts)
    evs = sorted(pick(win.start, win.end), key=lambda e: -ctx.corpus.prio[e[0]["id"]]["score"])
    ev_row = lambda e: {"title": e[0]["title"], "priority": ctx.corpus.prio[e[0]["id"]]["score"], "sources": len({m["source_id"] for m in e[1]}), "last": _iso(e[1][-1]["ts"]), "url": e[1][-1]["url"], "official": any(_is_official_adv(m) for m in e[1])}  # noqa: E731
    news_status = service.status()
    nsrc = [s for s in ctx.sources.values() if s["enabled"]]
    sections = {
        "A_executive_summary": {"title": "Executive Summary", "lines": [
            f"{prof['name']} has {k['technologies']} monitored technology(ies) and {k['assets']} registered asset(s) in its manually maintained inventory.",
            f"{k['related_cves']} unique CVE(s) are related to those products, {k['kev']} of them listed in CISA KEV (a listing is not evidence about this company).",
            f"Applicability: {st[POTENTIAL]} potentially applicable, {st[CONFIRMED]} confirmed by an analyst, {st[REVIEW]} need review, {st[INSUFFICIENT]} have insufficient data (mostly missing versions).",
            f"Intelligence attention in the {PERIOD_LABELS[period].lower()}: {k['events']} distinct news event(s), {k['advisories']} with an official advisory.",
            f"Inventory coverage is {k['coverage'] if k['coverage'] is not None else 'N/A'}%."]},
        "B_technologies": {"title": "Monitored Technology Overview", "rows": [{"name": t["name"], "assets": t["assets"], "versions": t["versions"], "assets_without_version": t["assets_without_version"],
                                                                              "threat_signal": t["score"], "level": t["level"]["label"], "score_available": t["score_available"], "related_cves": t["related_cves"], "kev": t["related_kev"],
                                                                              "news_events": t["news_events"]} for t in dash["technologies"]],
                           "note": "Threat Signal is the global score of each technology, independent of this company's asset count."},
        "C_vulnerabilities": {"title": "Vulnerability Intelligence", "total_related": len(rows), "published_in_period": len(pub_cur), "top": [cv(r) for r in top[:15]], "discovery": an.get("discovery", {}).get("compare") if an["status"] == "ok" else None},
        "D_kev": {"title": "CISA KEV Watch", "related_total": dash["exposure"]["kev"], "added_in_period": [cv(r) | {"kev_added": r["kev_date"]} for r in kev_new[:25]]},
        "E_exposure": {"title": "Potential & Confirmed Exposure", "counts": st, "unassessed": dash["exposure"]["unassessed"],
                       "confirmed": [cv(r) | {"evidence": [t["manual"]["evidence"] for t in r["per_tech"].values() if t["manual"]]} for r in rows if r["effective"] == CONFIRMED][:25],
                       "potential": [cv(r) for r in top if r["effective"] == POTENTIAL][:25], "note": "Potential means product and version may match; only an analyst-validated assessment is Confirmed."},
        "F_news": {"title": "Related Security News", "events": [ev_row(e) for e in evs if not any(_is_official_adv(m) for m in e[1])][:12]},
        "G_advisories": {"title": "Official Security Advisories", "events": [ev_row(e) for e in evs if any(_is_official_adv(m) for m in e[1])][:12]},
        "H_trends": {"title": "Intelligence Trends", "status": an["status"], "events": an.get("timeline", {}).get("compare"), "attention": an.get("attention", [])[:8], "changes": ch["counts"],
                     "note": "Comparisons appear only with sufficient comparable history."},
        "I_inventory": {"title": "Inventory Coverage & Data Quality", "coverage": dash["inventory"], "by_technology": an.get("inventory_quality", {}).get("by_technology", [])},
        "J_sources": {"title": "Sources & Limitations", "sources": ["NVD (CVE records, CVSS)", "CISA KEV catalogue", "FIRST EPSS", f"{len(nsrc)} enabled RSS/Atom news sources", "Manually maintained company inventory and analyst assessments"],
                      "last_sync": news_status["last_success"], "limitations": [
                          "Based exclusively on external intelligence and a manually maintained inventory; it says nothing about whether the organisation is secure or compromised.",
                          "Threat Signal Scores are global per technology and are not this company's risk.",
                          "Automatic applicability uses vendor/product and numeric version ranges only; unknown or complex cases are Needs Review / Insufficient Data.",
                          "Affected-version ranges are available only for CVEs whose configurations were cached after versions began to be stored.",
                          "News linkage exists only for catalogue technologies; custom products have none.",
                          "Percent changes appear only when the previous period has comparable data."]},
    }
    return {"company": {"id": cid, "name": prof["name"], "industry": prof["industry"]}, "period": period, "period_label": PERIOD_LABELS[period], "since": _iso(win.start), "until": _iso(win.end),
            "generated_at": db.now_iso(), "last_sync": news_status["last_success"], "sections": sections}


def report_text(r: dict) -> str:
    s = r["sections"]
    out = [f"Company Threat Intelligence Report — {r['company']['name']}", f"Period: {r['period_label']} ({r['since']} to {r['until']} UTC)", f"Generated: {r['generated_at']} · Last sync: {r['last_sync']}", ""]
    out.append("Executive Summary"); out += [f"- {x}" for x in s["A_executive_summary"]["lines"]]
    out += ["", "Monitored technologies:"] + [f"- {t['name']}: {t['assets']} asset(s), Threat Signal {t['threat_signal'] if t['threat_signal'] is not None else 'Insufficient Data / unavailable'}, {t['related_cves']} CVE(s), {t['kev']} KEV" for t in s["B_technologies"]["rows"]]
    out += ["", "Limitations:"] + [f"- {x}" for x in s["J_sources"]["limitations"]]
    return "\n".join(out)


def save_report(con, cid: str, period: str) -> dict:
    company.get(con, cid)
    rep = generate_report(con, cid, period)
    rid = "rep_" + uuid.uuid4().hex[:14]
    text = report_text(rep)
    con.execute("INSERT INTO company_report(id,company_id,period,generated_at,last_sync,content,summary) VALUES(?,?,?,?,?,?,?)", (rid, cid, period, rep["generated_at"], rep["last_sync"], json.dumps(rep), "\n".join(text.splitlines()[4:11])))
    return {"id": rid, **rep}


def list_reports(con, cid: str, limit=30) -> list[dict]:
    company.get(con, cid)
    return [dict(r) for r in con.execute("SELECT id,period,generated_at,last_sync,summary FROM company_report WHERE company_id=? ORDER BY generated_at DESC, id DESC LIMIT ?", (cid, max(1, min(100, limit))))]


def get_report(con, cid: str, rid: str) -> dict:
    company.get(con, cid)
    r = con.execute("SELECT * FROM company_report WHERE id=? AND company_id=?", (rid, cid)).fetchone()
    if not r:
        raise CompanyError(404, "Report not found")
    return {"id": r["id"], **json.loads(r["content"])}


# ----------------------------------------------------------------------------- comparison
def compare(con, ids: list[str]) -> dict:
    ids = list(dict.fromkeys(ids))
    if not 2 <= len(ids) <= 5:
        raise CompanyError(422, "Select between 2 and 5 companies")
    rows = []
    for cid in ids:
        dash = dashboard(con, cid, "30d")
        k = {x["key"]: x["value"] for x in dash["kpis"]}
        cov = dash["inventory"]
        n, tn = k["assets"] or 0, k["technologies"] or 0
        rows.append({"id": cid, "name": dash["company"]["name"], "status": dash["company"]["status"], "technologies": tn, "assets": n, "related_cves": k["related_cves"], "kev": k["kev"],
                     "potential": k["potential"], "confirmed": k["confirmed"], "events_30d": k["events"], "advisories_30d": k["advisories"], "inventory_coverage": k["coverage"],
                     "with_version_pct": cov["with_version_pct"], "median_verification_age_days": cov["median_verification_age_days"], "oldest_verification_days": cov["oldest_verification_days"],
                     "normalised": {"cves_per_technology": round(k["related_cves"] / tn, 1) if tn else None, "potential_per_100_assets": round(100 * k["potential"] / n, 1) if n else None,
                                    "kev_share_pct": round(100 * k["kev"] / k["related_cves"], 1) if k["related_cves"] else None}})
    return {"companies": rows, "notes": ["This is a side-by-side description, not a ranking: a larger or better-documented inventory naturally shows more related CVEs.",
                                         "Compare inventory coverage and size before reading any CVE count. Potential means product/version may match, not that the company is vulnerable.",
                                         "No company is scored or ordered by 'insecurity'."]}
