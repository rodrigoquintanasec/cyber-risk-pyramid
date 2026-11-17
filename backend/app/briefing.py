"""Morning Cyber Briefing generator — a reusable service, independent of the UI and of any delivery channel.

Layers (kept separate on purpose):
  1. gather()   data retrieval        (stored news, local NVD/KEV/EPSS signals, source status)
  2. select()   event selection       (clusters + News Priority Score)
  3. build()    structured briefing   (deterministic templates -> JSON contract, schema_version 1)
  4. to_markdown()  one presentation  (the web view renders the JSON itself; print uses the browser)
  5. delivery   NOT implemented. Future email/Telegram/push senders consume the same JSON / markdown.
No AI: every sentence is a template filled with stored facts. Missing data stays null and is reported.
"""
from __future__ import annotations

import hashlib
import json
import re
import secrets
from urllib.parse import urlsplit
from collections import Counter
from datetime import datetime, timedelta, timezone

from . import db, service
from .catalog import BY_ID
from .config import settings
from .news import enrich, intel
from .news.classify import FALLBACK_CATEGORY
from .news.sources import SOURCES

ALLOWED_HOURS = {24, 48, 168}
SCHEMA_VERSION = 1
FORMAT = 2                       # editorial layout revision: part of the data hash so an old-format stored briefing is not served as if it were the new one
SRC_LIMIT = 12
_BAD_URL = re.compile(r"[\x00-\x20\x7f<>\"'`\\]")
KIND_ORDER = {"news": 0, "advisory": 1, "nvd": 2, "kev": 3}
TOP_STORIES = 10
VULN_LIMIT = 15
THEME_LIMIT = 4
SECTIONS = [("executive_summary", "A. Executive Summary"), ("top_stories", "B. Top 10 Security Stories"),
            ("vulnerability_watch", "C. Critical Vulnerability Watch"), ("threat_landscape", "D. Threat Landscape"),
            ("technology_watchlist", "E. Technology Watchlist"), ("sources_quality", "F. Sources & Data Quality")]
WATCH = [("windows-server", "Microsoft Windows Server"), ("linux", "Linux"), ("vmware", "VMware"), ("fortinet", "Fortinet"),
         ("docker", "Docker"), ("kubernetes", "Kubernetes")]


METHOD = ["Events are grouped from stored articles with fixed, deterministic rules; no AI or language model is used.",
          "News Priority Score ranks reading priority. It is not a measure of business risk.",
          "A technology mention does not imply that an organisation or product is exposed or vulnerable.",
          "CISA KEV indicates known exploitation, not necessarily recent exploitation."]


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(d) -> str | None:
    return d.isoformat(timespec="seconds") if d else None


def safe_url(u) -> str | None:
    """Only absolute http(s) URLs without credentials, whitespace or control/markup characters. javascript:, data:, file:, relative links and anything odd are dropped (never repaired or invented)."""
    if not isinstance(u, str):
        return None
    u = u.strip()
    if not u or len(u) > 2000 or _BAD_URL.search(u):
        return None
    try:
        p = urlsplit(u)
    except ValueError:
        return None
    if p.scheme.lower() not in ("https", "http") or not p.hostname or p.username or p.password:
        return None
    return u


def _article_ref(m: dict) -> dict | None:
    url = safe_url(m.get("url"))
    if not url:
        return None
    return {"name": m["source_name"], "title": (m.get("title") or "")[:300], "url": url, "published": m.get("published"), "kind": "advisory" if m.get("source_type") == "official" else "news"}


def _article_refs(members: list[dict], limit: int = SRC_LIMIT) -> list[dict]:
    """Original article links of an event: one per distinct URL, never the outlet's home page, nothing invented."""
    out, seen = [], set()
    for m in members:
        r = _article_ref(m)
        if r and r["url"] not in seen:
            seen.add(r["url"])
            out.append(r)
        if len(out) >= limit:
            break
    return out


def _fmt(d: datetime) -> str:
    return d.strftime("%Y-%m-%d %H:%M UTC")


# ------------------------------------------------------------------ 1. gather
def gather(hours: int, now: datetime | None = None, enrich_epss: bool = True) -> dict:
    now = now or _now()
    since = now - timedelta(hours=hours)
    with db.connect() as con:
        corpus = intel.get_corpus(con)
        window_cves = sorted({c for cl in corpus.clusters if cl.get("last_dated") and cl["last_dated"] >= since for c in cl["cves"]})
    if enrich_epss and window_cves:
        try:
            if enrich.enrich_epss(window_cves[:300]):
                intel.reset_cache()
                corpus = intel.get_corpus()
        except Exception:  # best effort, bounded by the HTTP timeout
            pass
    with db.connect() as con:
        srcs = [dict(r) for r in con.execute("SELECT id,name,status,last_success,error,enabled FROM news_source")]
        added = con.execute("SELECT COUNT(*) FROM news_source WHERE enabled=1 AND enabled_at>=?", (since.isoformat(timespec="seconds"),)).fetchone()[0]
        sig_status = {r["source"]: dict(r) for r in con.execute("SELECT * FROM source_status")}
    return {"now": now, "since": since, "hours": hours, "corpus": corpus, "sources": srcs, "sources_added": added, "signal_status": sig_status}


# ------------------------------------------------------------------ 2. select
def select(g: dict) -> dict:
    corpus, since = g["corpus"], g["since"]
    events = [c for c in corpus.clusters if c.get("last_dated") and c["last_dated"] >= since]
    events.sort(key=lambda c: (-corpus.prio[c["id"]]["score"], c["id"]))
    arts = [m for c in events for m in c["members"] if m["ts"] >= since and not m.get("undated")]
    relevant = [c for c in events if corpus.prio[c["id"]]["score"] >= intel.PRIORITY.relevant_threshold]
    return {"events": events, "top": _pick_top(events), "relevant": relevant, "articles": arts}


MAX_ADVISORY_ONLY_IN_TOP = 4


def _pick_top(events: list[dict]) -> list[dict]:
    """Top stories are unique events ranked by News Priority Score. Events reported ONLY by official-advisory feeds
    (e.g. a stream of vendor bulletins) are capped so they cannot crowd out the rest; a leftover slot is still filled by them."""
    top, held, adv = [], [], 0
    for c in events:
        if len(top) >= TOP_STORIES:
            break
        if c.get("advisory_only") and adv >= MAX_ADVISORY_ONLY_IN_TOP:
            held.append(c)
            continue
        adv += 1 if c.get("advisory_only") else 0
        top.append(c)
    for c in held:
        if len(top) < TOP_STORIES:
            top.append(c)
    return sorted(top, key=lambda c: events.index(c))


# ------------------------------------------------------------------ 3. build
def _story_why(p: dict) -> list[str]:
    return [f"{c['label']}: +{c['points']} pts — {c['detail']}" for c in p["components"] if c["points"] > 0]


def _desc(cl: dict) -> str:
    rep = next((m for m in cl["members"] if m["title"] == cl["title"]), cl["members"][0])
    s = (rep["summary"] or "").strip()
    if s:
        return s if len(s) <= 260 else s[:259].rstrip() + "…"
    return f"Reported by {len(cl['source_ids'])} publisher(s) in the category {cl['categories'][0]}; no excerpt is available in the feed."


def _sig_line(s: dict | None) -> str:
    if not s:
        return "no local signals"
    parts = []
    if s.get("kev"): parts.append("CISA KEV" + (" (ransomware use)" if s["kev"]["ransomware"] else ""))
    if s.get("epss") is not None: parts.append(f"EPSS {s['epss']:.2f}")
    if s.get("cvss") is not None: parts.append(f"CVSS {s['cvss']}")
    return ", ".join(parts) or "no KEV/EPSS/CVSS data available"


def build(g: dict, sel: dict, bid: str, data_hash: str) -> dict:
    corpus, now, since, hours = g["corpus"], g["now"], g["since"], g["hours"]
    prio, sigs = corpus.prio, corpus.signals
    events, top = sel["events"], sel["top"]
    rank = {c["id"]: i + 1 for i, c in enumerate(top)}
    ev_ref = lambda c: {"id": c["id"], "title": c["title"], "priority": prio[c["id"]]["score"]}  # noqa: E731

    # --- Top stories
    stories = []
    for c in top:
        p = prio[c["id"]]
        stories.append({
            "rank": rank[c["id"]], "event_id": c["id"], "title": c["title"], "description": _desc(c),
            "description_origin": "feed excerpt (publisher metadata)", "category": c["categories"][0],
            "first_published": _iso(c["first_ts"]), "last_published": _iso(c["last_ts"]),
            "articles": c["article_count"], "publishers": len(c["source_ids"]),
            "sources": _article_refs(c["members"]),
            "cves": c["cves"][:10], "technologies": [BY_ID[t].name for t in c["techs"] if t in BY_ID],
            "priority": {"score": p["score"], "label": "News Priority Score", "why": _story_why(p), "components": p["components"]},
        })

    # --- Vulnerability watch (all window events, ranked by verifiable signals)
    cve_events: dict[str, list[dict]] = {}
    for c in events:
        for cv in c["cves"]:
            cve_events.setdefault(cv, []).append(ev_ref(c))
    def vkey(cv):
        s = sigs.get(cv) or {}
        return (0 if s.get("kev") else 1, -(s.get("epss") or 0), -(s.get("cvss") or 0), cv)
    cve_clusters: dict[str, list[dict]] = {}
    for c in events:
        for cv in c["cves"]:
            cve_clusters.setdefault(cv, []).append(c)
    kinds = {"NVD": "nvd", "CISA KEV catalog": "kev", "FIRST EPSS": "epss"}

    def cve_refs(cv: str, s: dict) -> list[dict]:
        refs = [{**r, "kind": kinds.get(r["label"], "other")} for r in intel.cve_urls(cv, s)]
        adv = []
        for cl in cve_clusters[cv]:        # official-feed articles (vendor / government advisories) in events that cite this CVE
            for m in cl["members"]:
                r = _article_ref(m)
                if r and r["kind"] == "advisory" and r["url"] not in {a["url"] for a in adv}:
                    adv.append({"label": r["name"], "url": r["url"], "kind": "advisory", "title": r["title"], "published": r["published"]})
        return refs + adv[:3]
    watch = []
    for cv in sorted(cve_events, key=vkey)[:VULN_LIMIT]:
        s = sigs.get(cv) or {}
        miss = [k for k, v in (("cvss", s.get("cvss")), ("epss", s.get("epss"))) if v is None]
        watch.append({"cve": cv, "cvss": s.get("cvss"), "cvss_version": s.get("cvss_version"), "epss": s.get("epss"), "epss_percentile": s.get("epss_percentile"),
                      "in_kev": bool(s.get("kev")), "kev": s.get("kev"), "products": s.get("products", []),
                      "products_origin": ("NVD CPE" if s.get("sources") and "NVD" in s["sources"] else "CISA KEV" if s.get("kev") else None),
                      "unavailable": miss, "signal_sources": s.get("sources", []), "events": cve_events[cv][:4],
                      "references": cve_refs(cv, s)})

    # --- Threat landscape: each event appears under a single theme
    used: set[str] = set()
    landscape = []
    for theme in intel.THEMES:
        evs = [c for c in events if theme in c["categories"] and c["id"] not in used]
        used.update(c["id"] for c in evs)
        fam = Counter(f for c in evs for f in (c["entities"]["ransomware"] + c["entities"]["malware"]))
        landscape.append({"theme": theme, "events": len(evs),
                          "named_families": [{"name": k, "events": v} for k, v in fam.most_common(5)],
                          "items": [{**ev_ref(c), "articles": c["article_count"], "publishers": len(c["source_ids"]), "also_in_top": rank.get(c["id"]),
                                     "first_url": safe_url(c["members"][0]["url"]), "sources": _article_refs(c["members"], 6), "last_published": _iso(c["last_ts"])} for c in evs[:THEME_LIMIT]],
                          "more": max(0, len(evs) - THEME_LIMIT)})

    # --- Technology watchlist (media signals kept separate from verified vulnerability signals)
    overview = {}
    try:
        overview = {t["id"]: t for t in service.overview()["technologies"]}
    except Exception:
        pass
    tech_rows = []
    for tid, label in WATCH:
        evs = [c for c in events if tid in c["techs"]]
        if not evs:
            continue
        cves = sorted({cv for c in evs for cv in c["cves"]}, key=vkey)
        t = overview.get(tid) or {}
        tech_rows.append({
            "id": tid, "name": label, "events": len(evs), "articles": sum(1 for c in evs for m in c["members"] if m["ts"] >= since and not m.get("undated")),
            "media_signal": f"{len(evs)} event(s) mention {label}; media attention is not confirmed risk.",
            "verified_signals": [{"cve": cv, "summary": _sig_line(sigs.get(cv))} for cv in cves[:5] if (sigs.get(cv) or {}).get("kev") or (sigs.get(cv) or {}).get("epss") is not None or (sigs.get(cv) or {}).get("cvss") is not None],
            "kev_cves": [cv for cv in cves if (sigs.get(cv) or {}).get("kev")][:6],
            "pyramid_threat_signal": {"score": t.get("score"), "level": t.get("level"), "note": "Separate metric from vulnerability data; unchanged by news."} if t else None,
            "top_events": [{**ev_ref(c), "url": safe_url(c["members"][0]["url"])} for c in evs[:3]],
            "news": [{**r, "event": c["title"]} for c in evs[:4] for r in _article_refs(c["members"], 2)][:6],
            "cves": [{"cve": cv, "in_kev": bool((sigs.get(cv) or {}).get("kev")), "url": f"https://nvd.nist.gov/vuln/detail/{cv}"} for cv in cves[:8]],
            "signals": {"media_attention": f"{len(evs)} event(s) mention {label} in the period (media mentions, not exposure).",
                        "threat_signal": ("Pyramid Threat Signal " + (str(t.get("score")) if t.get("score") is not None else "N/A") + " (separate metric)") if t else "Not available for this technology.",
                        "vulnerability_applicability": "Not assessed here: a CVE mentioned in the news is not confirmed to apply to any version or company asset."},
            "coverage": t.get("coverage_label") or t.get("coverage_state") or None,
        })

    # --- Sources & data quality
    src, ssum = g["sources"], {}
    contributing = Counter(m["source_id"] for m in sel["articles"])
    enabled = [s for s in src if s["enabled"]]            # intentionally disabled feeds never count as failures or missing coverage
    ok = [s for s in enabled if s["status"] == "ok"]
    failed = [{"id": s["id"], "name": s["name"], "error": s["error"]} for s in enabled if s["status"] == "error"]
    last_sync = max((s["last_success"] for s in enabled if s["last_success"]), default=None)
    age_h = (now - datetime.fromisoformat(last_sync)).total_seconds() / 3600 if last_sync else None
    warnings = []
    if not last_sync: warnings.append("No news synchronisation has completed yet.")
    elif age_h > 2 * settings.news_interval_minutes / 60: warnings.append(f"News were last synchronised {age_h:.1f}h ago; newer articles may be missing.")
    if failed: warnings.append(f"{len(failed)} feed(s) failed in the latest sync: {', '.join(f['name'] for f in failed)}.")
    if len(sel["articles"]) < 10: warnings.append("Fewer than 10 articles in the period; the briefing may not be representative.")
    if g.get("sources_added"): warnings.append(f"{g['sources_added']} source(s) were enabled during this period: more articles reflect wider coverage, not necessarily more attacks.")
    unsig = [w["cve"] for w in watch if w["unavailable"]]
    if unsig: warnings.append(f"CVSS/EPSS missing for {len(unsig)} CVE(s) (not yet in local NVD/EPSS caches): {', '.join(unsig[:6])}{'…' if len(unsig) > 6 else ''}.")
    kev_st = g["signal_status"].get("kev")
    if not kev_st or not kev_st.get("ok"): warnings.append("CISA KEV data is unavailable or stale; KEV flags may be missing.")
    # a healthy feed that simply published nothing in the period is NOT a failure
    status = "insufficient" if len(sel["articles"]) < 10 or not ok else "stale" if age_h is None or age_h > 6 else "partial" if failed else "complete"
    coverage = {"status": status, "articles": len(sel["articles"]), "events": len(events), "sources_configured": len(src), "sources_enabled": len(enabled),
                "sources_disabled": len(src) - len(enabled), "sources_operational": len(ok), "sources_quiet": len([s for s in ok if not contributing.get(s["id"])]),
                "sources_failed": len(failed), "sources_contributing": len(contributing), "last_sync": last_sync,
                "hours_since_sync": None if age_h is None else round(age_h, 1), "warnings": warnings}
    used_sources = [{"id": s["id"], "name": s["name"], "articles": contributing[s["id"]]} for s in src if contributing.get(s["id"])]
    used_sources.sort(key=lambda x: (-x["articles"], x["name"]))

    # --- Executive summary (templates over verified facts)
    cats = Counter(c["categories"][0] for c in events if c["categories"][0] != FALLBACK_CATEGORY)
    tech_cnt = Counter(BY_ID[t].name for c in events for t in c["techs"] if t in BY_ID)
    vend_cnt = Counter(v for c in events for v in c["entities"]["vendors"])
    bullets = [f"{len(sel['relevant'])} relevant event(s) (News Priority Score ≥ {intel.PRIORITY.relevant_threshold:.0f}) out of {len(events)} distinct event(s) built from {len(sel['articles'])} article(s) by {len(contributing)} publisher(s), {_fmt(since)} → {_fmt(now)}."]
    if cats: bullets.append("Main categories (events): " + ", ".join(f"{k} ({v})" for k, v in cats.most_common(4)) + ".")
    if tech_cnt or vend_cnt:
        bullets.append("Most mentioned technologies: " + ", ".join(f"{k} ({v})" for k, v in tech_cnt.most_common(4)) + ("; " if tech_cnt else "") +
                       "vendors: " + ", ".join(f"{k} ({v})" for k, v in vend_cnt.most_common(4)) + ". Mentions measure media attention, not risk.")
    if watch:
        kev_n = sum(1 for w in watch if w["in_kev"])
        bullets.append(f"{len(cve_events)} CVE(s) cited; {kev_n} of the top {len(watch)} listed in CISA KEV. Notable: " +
                       "; ".join(f"{w['cve']} ({_sig_line(sigs.get(w['cve']))})" for w in watch[:3]) + ".")
    else:
        bullets.append("No CVE identifiers were cited in the period.")
    attn = [s for s in stories[:3]]
    if attn:
        bullets.append("Events worth attention: " + "; ".join(f"“{s['title']}” (priority {s['priority']['score']})" for s in attn) + ".")
    if status != "complete":
        bullets.append(f"Coverage is {status}: " + (warnings[0] if warnings else "see Sources & Data Quality") )
    summary = {"relevant_events": len(sel["relevant"]), "total_events": len(events), "articles": len(sel["articles"]),
               "top_categories": [{"name": k, "events": v} for k, v in cats.most_common(5)],
               "top_technologies": [{"name": k, "events": v} for k, v in tech_cnt.most_common(5)],
               "top_vendors": [{"name": k, "events": v} for k, v in vend_cnt.most_common(5)],
               "notable_cves": [w["cve"] for w in watch[:5]], "bullets": bullets}

    kev_listed = sum(1 for cv in cve_events if (sigs.get(cv) or {}).get("kev"))
    label = {24: "last 24 hours", 48: "last 48 hours", 168: "last 7 days"}[hours]
    blocks = [{"id": "overview", "title": "Overview", "text": (
        f"This briefing covers the {label} ({_fmt(since)} to {_fmt(now)}). Stored news were grouped into {len(events)} distinct event(s) built from {len(sel['articles'])} article(s) by "
        f"{len(contributing)} publisher(s); {len(sel['relevant'])} of them reach the relevance threshold (News Priority Score ≥ {intel.PRIORITY.relevant_threshold:.0f}). "
        "Events are media reports; they are not confirmed incidents." + (" Most frequent categories: " + ", ".join(f"{k} ({v})" for k, v in cats.most_common(4)) + "." if cats else ""))}]
    if stories:
        blocks.append({"id": "key_events", "title": "Key events", "items": [f"“{s['title']}” — {s['category']}, priority {s['priority']['score']}, {s['publishers']} publisher(s)" for s in stories[:3]]})
    blocks.append({"id": "vulnerabilities", "title": "Vulnerabilities cited", "text": (
        f"{len(cve_events)} CVE identifier(s) appear in the period's reporting; {kev_listed} of them are listed in CISA KEV (known exploitation, not necessarily recent)." if cve_events else "No CVE identifiers were cited in the period."),
        "items": [f"{w['cve']}: {_sig_line(sigs.get(w['cve']))}" for w in watch[:3]]})
    blocks.append({"id": "technologies", "title": "Technologies mentioned", "text": (
        ("Most mentioned: " + ", ".join(f"{k} ({v})" for k, v in tech_cnt.most_common(4)) + ". " if tech_cnt else "No catalogued technology stands out in the period. ") +
        "Mentions measure media attention; they do not show exposure or that a product is vulnerable.")})
    blocks.append({"id": "coverage", "title": "Coverage and limitations", "text": (
        f"Coverage is {status}. " + (" ".join(warnings[:2]) if warnings else "No coverage warnings were raised.") + " Only data already stored locally is used; nothing is fetched while generating.")})
    summary["blocks"] = blocks

    cover = {"title": "CYBER RISK PYRAMID", "subtitle": "MORNING CYBER BRIEFING", "period_label": {24: "Last 24 hours", 48: "Last 48 hours", 168: "Last 7 days"}[hours],
             "since": _iso(since), "until": _iso(now), "generated_at": _iso(now),
             "scope": f"Open-source cybersecurity news from {len(contributing)} publisher(s) of {len(enabled)} enabled feed(s), cross-referenced with local NVD, CISA KEV and EPSS data, for the {label}.",
             "unique_events": len(events), "contributing_sources": len(contributing), "cves_identified": len(cve_events), "cves_in_kev": kev_listed, "coverage_status": status,
             "note": "Open-source cybersecurity intelligence compiled from verified data sources."}

    bib: dict[str, dict] = {}

    def cite(kind, outlet, title, published, url, supports):
        url = safe_url(url)
        if not url:
            return
        e = bib.setdefault(url, {"kind": kind, "outlet": outlet, "title": title or url, "published": published, "url": url, "supports": []})
        if supports and supports not in e["supports"]:
            e["supports"].append(supports)
    for s in stories:
        for x in s["sources"]:
            cite(x["kind"], x["name"], x["title"], x["published"], x["url"], f"Story {s['rank']}")
    for t in landscape:
        for i in t["items"]:
            for x in i["sources"]:
                cite(x["kind"], x["name"], x["title"], x["published"], x["url"], f"Landscape: {t['theme']}")
    for w in watch:
        for r in w["references"]:
            if r["kind"] in ("nvd", "advisory", "kev"):
                cite(r["kind"], "NVD" if r["kind"] == "nvd" else "CISA" if r["kind"] == "kev" else r["label"], r.get("title") or (w["cve"] if r["kind"] == "nvd" else "Known Exploited Vulnerabilities Catalog"), r.get("published"), r["url"], w["cve"])
    for t in tech_rows:
        for x in t["news"]:
            cite(x["kind"], x["name"], x["title"], x["published"], x["url"], f"Watchlist: {t['name']}")
    bibliography = sorted(bib.values(), key=lambda e: (KIND_ORDER.get(e["kind"], 9), e["outlet"].lower(), e["published"] or "", e["title"]))
    for n, e in enumerate(bibliography, 1):
        e["id"] = f"R{n}"
    refs = [e["url"] for e in bibliography]
    return {
        "schema_version": SCHEMA_VERSION, "kind": "morning_cyber_briefing", "id": bid, "title": "MORNING CYBER BRIEFING",
        "generated_at": _iso(now), "period": {"hours": hours, "label": {24: "Last 24 hours", 48: "Last 48 hours", 168: "Last 7 days"}[hours], "since": _iso(since), "until": _iso(now)},
        "coverage": coverage, "data_hash": data_hash, "format": FORMAT, "cover": cover, "bibliography": bibliography,
        "disclaimer": "Generated from stored RSS/Atom metadata and local NVD, CISA KEV and EPSS data using fixed templates. The News Priority Score ranks reading priority; it is not a risk measurement.",
        "sections": [{"id": "executive_summary", "title": SECTIONS[0][1], **summary},
                     {"id": "top_stories", "title": SECTIONS[1][1], "items": stories},
                     {"id": "vulnerability_watch", "title": SECTIONS[2][1], "items": watch, "note": "Only CVEs cited in the period's news. null = not available locally."},
                     {"id": "threat_landscape", "title": SECTIONS[3][1], "themes": landscape},
                     {"id": "technology_watchlist", "title": SECTIONS[4][1], "items": tech_rows, "note": "Only technologies with events in the period."},
                     {"id": "sources_quality", "title": SECTIONS[5][1], "used_sources": used_sources, "failed_sources": failed,
                      "signal_sources": {k: {"ok": bool(v.get("ok")), "last_success": v.get("last_success")} for k, v in g["signal_status"].items()}, "coverage": coverage,
                      "methodology": METHOD}],
        "references": refs, "event_ids": [c["id"] for c in events[:50]],
    }


def compute_hash(g: dict, sel: dict) -> str:
    """Identity of the underlying data (not of time-decayed scores): same data -> same hash -> no duplicate briefing."""
    sigs = g["corpus"].signals
    cves = sorted({c for ev in sel["events"] for c in ev["cves"]})
    payload = {"f2": FORMAT, "h": g["hours"], "a": sorted(m["id"] for m in sel["articles"]),
               "s": [(c, bool((sigs.get(c) or {}).get("kev")), (sigs.get(c) or {}).get("cvss"), round((sigs.get(c) or {}).get("epss") or 0, 3)) for c in cves],
               "f": sorted(s["id"] for s in g["sources"] if s["status"] == "error")}
    return hashlib.sha1(json.dumps(payload, sort_keys=True, default=str).encode()).hexdigest()


# ------------------------------------------------------------------ persistence + entry point
def _row_to_briefing(r) -> dict:
    b = json.loads(r["content"])
    b["reused"] = False
    return b


def generate(hours: int = 24, force: bool = False, now: datetime | None = None, enrich_epss: bool = True) -> dict:
    g = gather(hours, now, enrich_epss)
    sel = select(g)
    h = compute_hash(g, sel)
    with db.connect() as con:
        if not force:
            r = con.execute("SELECT * FROM briefing WHERE period_hours=? AND data_hash=? ORDER BY generated_at DESC LIMIT 1", (hours, h)).fetchone()
            if r:
                b = _row_to_briefing(r)
                b["reused"] = True
                return b
        bid = f"brf_{g['now'].strftime('%Y%m%d%H%M%S')}{secrets.token_hex(2)}{h[:4]}"
        b = build(g, sel, bid, h)
        con.execute("INSERT INTO briefing(id,generated_at,period_hours,since,until,coverage_status,data_hash,event_ids,refs,content) VALUES(?,?,?,?,?,?,?,?,?,?)",
                    (bid, b["generated_at"], hours, b["period"]["since"], b["period"]["until"], b["coverage"]["status"], h,
                     json.dumps(b["event_ids"]), json.dumps(b["references"]), json.dumps(b)))
    b["reused"] = False
    return b


def get(bid: str) -> dict | None:
    with db.connect() as con:
        r = con.execute("SELECT * FROM briefing WHERE id=?", (bid,)).fetchone()
    return _row_to_briefing(r) if r else None


def list_recent(limit: int = 10) -> list[dict]:
    with db.connect() as con:
        return [{"id": r["id"], "generated_at": r["generated_at"], "period_hours": r["period_hours"], "coverage_status": r["coverage_status"],
                 "events": len(json.loads(r["event_ids"] or "[]"))} for r in
                con.execute("SELECT * FROM briefing ORDER BY generated_at DESC LIMIT ?", (limit,))]


# ------------------------------------------------------------------ 4. presentation: markdown (copy / future channels)
def to_markdown(b: dict) -> str:
    L = [f"# {b['title']}", f"{b['period']['label']} · {b['period']['since']} → {b['period']['until']} · generated {b['generated_at']}", ""]
    for s in b["sections"]:
        L += [f"## {s['title']}", ""]
        if s["id"] == "executive_summary":
            if s.get("blocks"):
                for blk in s["blocks"]:
                    L += [f"**{blk['title']}**"] + ([blk["text"]] if blk.get("text") else []) + [f"- {x}" for x in blk.get("items", [])] + [""]
            else:
                L += [f"- {x}" for x in s["bullets"]]
        elif s["id"] == "top_stories":
            for i in s["items"]:
                L += [f"{i['rank']}. **{i['title']}** — {i['category']} · priority {i['priority']['score']} · {i['publishers']} publisher(s)/{i['articles']} article(s)",
                      f"   {i['description']}"]
                L += [f"   - {x['name']}: {x['url']}" for x in i["sources"][:4]]
                L += ["   - Why: " + "; ".join(w.split(" — ")[0] for w in i["priority"]["why"])]
        elif s["id"] == "vulnerability_watch":
            for w in s["items"]:
                L += [f"- **{w['cve']}** — CVSS {w['cvss'] if w['cvss'] is not None else 'n/a'} · EPSS {('%.2f' % w['epss']) if w['epss'] is not None else 'n/a'} · "
                      f"{'IN CISA KEV' if w['in_kev'] else 'not in KEV'}" + (f" · {', '.join(w['products'][:3])}" if w["products"] else "") + f" · https://nvd.nist.gov/vuln/detail/{w['cve']}"]
            if not s["items"]: L += ["No CVEs cited in the period."]
        elif s["id"] == "threat_landscape":
            for t in s["themes"]:
                L += [f"### {t['theme']} ({t['events']})"] + [f"- {i['title']} (priority {i['priority']})" for i in t["items"]]
                if not t["items"]: L += ["- No events."]
        elif s["id"] == "technology_watchlist":
            for t in s["items"]:
                L += [f"- **{t['name']}** — {t['events']} event(s), {t['articles']} article(s). " + (f"KEV CVEs: {', '.join(t['kev_cves'])}." if t["kev_cves"] else "No KEV-listed CVE cited.")]
            if not s["items"]: L += ["No watched technology appears in the period."]
        elif s["id"] == "sources_quality":
            c = s["coverage"]
            L += [f"- Coverage: {c['status']} · {c['articles']} articles · {c['sources_contributing']}/{c['sources_operational']} operational sources contributed · last sync {c['last_sync'] or 'never'}"]
            L += [f"- Failed feeds: {', '.join(f['name'] for f in s['failed_sources']) or 'none'}"] + [f"- Warning: {w}" for w in c["warnings"]]
        L.append("")
    if b.get("bibliography"):
        L += ["## Sources & References", ""] + [f"[{e['id']}] {e['outlet']} — {e['title']}" + (f" ({e['published'][:10]})" if e.get("published") else "") + f" {e['url']}" for e in b["bibliography"]] + [""]
    L += ["---", b["disclaimer"]]
    return "\n".join(L)
