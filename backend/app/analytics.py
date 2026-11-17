"""Intelligence Analytics engine: read-only aggregations over the existing news corpus (intel.get_corpus clusters).

Design rules
  * Counts are of media coverage (articles) and distinct EVENTS (existing clusters) - never of real incidents.
  * No second clustering algorithm and no new risk score: events, News Priority Score, KEV/EPSS/CVSS are reused as stored.
  * Articles without a publication date never enter a time window (they are timestamped at collection only for display).
  * Period comparisons are shown only when the previous window has enough data AND coverage did not change; otherwise the
    result says why (`status`), never 0 or a made-up percentage.
  * "Comparable Sources" keeps only sources that can be shown to have been collected over both windows (see `comparable`).
  * Aggregations are memoised per corpus build; a sync that changes the data rebuilds the corpus and drops the memo.
All timestamps are UTC.
"""
from __future__ import annotations

import hashlib
import json
import math
import threading
import time
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone

from . import db
from .catalog import BY_ID as TECH
from .news import entities as ent, intel, repo
from .news.classify import CATEGORIES, FALLBACK_CATEGORY
from .news.sources import SOURCE_TYPES

ANALYTICS_VERSION = "1"
PRESETS = {"24h": 24, "7d": 168, "30d": 720, "90d": 2160}
MAX_RANGE_DAYS = 90
MIN_BASE_EVENTS = 5            # previous value below this -> no percentage
MIN_BASE_SMALL = 3             # per entity / category rows
MIN_COMPARABLE_SOURCES = 3
MIN_ATTACK_ARTICLES = 10
UNDATED_MAX_SHARE = 0.20       # a comparable source may not have more than this share of undated articles
COVERAGE_CHANGE_SHARE = 0.25   # share of articles from sources collected only since the previous window began
DENSITY_DAY, DENSITY_HOUR = 0.6, 0.25
MAX_POINTS = 1500
MAX_PAGE = 50
FRESH_SECONDS = 30


class AnalyticsError(ValueError):
    """Invalid filter combination (mapped to HTTP 422 by the API)."""


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(d: datetime | None) -> str | None:
    return d.isoformat(timespec="seconds") if d else None


def _parse_dt(s: str | None) -> datetime | None:
    if not s:
        return None
    try:
        d = datetime.fromisoformat(s)
        return d if d.tzinfo else d.replace(tzinfo=timezone.utc)
    except ValueError:
        return None


# ----------------------------------------------------------------------------- filters & windows
@dataclass(frozen=True)
class Filters:
    period: str = "7d"
    date_from: str | None = None
    date_to: str | None = None
    category: str | None = None
    source: str | None = None
    vendor: str | None = None
    tech: str | None = None
    mode: str = "all"            # all | comparable

    def key(self) -> tuple:
        return (self.period, self.date_from, self.date_to, self.category, self.source, self.vendor, self.tech, self.mode)


@dataclass(frozen=True)
class Window:
    start: datetime
    end: datetime
    prev_start: datetime
    bucket_hours: int
    custom: bool

    @property
    def span(self) -> timedelta:
        return self.end - self.start

    @property
    def nb(self) -> int:
        return max(1, math.ceil(self.span.total_seconds() / 3600 / self.bucket_hours))

    def bucket(self, ts: datetime) -> int:
        return min(self.nb - 1, max(0, int((ts - self.start).total_seconds() // (3600 * self.bucket_hours))))

    def labels(self) -> list[str]:
        return [_iso(self.start + timedelta(hours=self.bucket_hours * i)) for i in range(self.nb)]


def resolve_window(f: Filters, now: datetime) -> Window:
    if f.period == "custom":
        if not f.date_from or not f.date_to:
            raise AnalyticsError("A custom period needs date_from and date_to")
        try:
            a, b = date.fromisoformat(f.date_from), date.fromisoformat(f.date_to)
        except ValueError:
            raise AnalyticsError("Invalid date")
        if a > b:
            raise AnalyticsError("date_from must not be after date_to")
        if (b - a).days + 1 > MAX_RANGE_DAYS:
            raise AnalyticsError(f"Range too large (max {MAX_RANGE_DAYS} days)")
        start = datetime(a.year, a.month, a.day, tzinfo=timezone.utc)
        end = min(now, datetime(b.year, b.month, b.day, tzinfo=timezone.utc) + timedelta(days=1))
        if end <= start:
            raise AnalyticsError("The period must start in the past")
    elif f.period in PRESETS:
        end, start = now, now - timedelta(hours=PRESETS[f.period])
    else:
        raise AnalyticsError("Unknown period")
    span = end - start
    return Window(start, end, start - span, 1 if span <= timedelta(hours=48) else 24, f.period == "custom")


# ----------------------------------------------------------------------------- context (per corpus build)
class Ctx:
    def __init__(self, corpus: intel.Corpus, con):
        self.corpus = corpus
        self.now = corpus.now
        self.sources = {s["id"]: s for s in repo.list_sources(con)}
        first = {r[0]: (r[1], r[2], r[3]) for r in con.execute("SELECT source_id,MIN(collected_at),COUNT(*),SUM(published IS NULL) FROM news_item GROUP BY source_id")}
        for sid, s in self.sources.items():
            fc, total, und = first.get(sid, (None, 0, 0))
            s["first_collected"], s["total"], s["undated_total"] = fc, total, und or 0
        self.dated = [i for i in corpus.items if not i.get("undated")]
        self.memo: dict = {}
        self.lock = threading.Lock()
        self._monitored: dict | None = None

    def monitored_cves(self, con) -> dict[str, list[str]]:
        if self._monitored is None:
            m: dict[str, list[str]] = defaultdict(list)
            for r in con.execute("SELECT cve_id,tech_id FROM tech_cve"):
                m[r[0]].append(r[1])
            self._monitored = dict(m)
        return self._monitored


_state: dict = {"corpus": None, "ctx": None}
_state_lock = threading.Lock()


_build_lock = threading.Lock()


def get_ctx() -> Ctx:
    """Corpus + derived context. Builds are serialised so parallel panel requests share one rebuild instead of each doing their own."""
    with _state_lock:   # fast path: the corpus signature (several table scans) is re-checked at most every FRESH_SECONDS
        if _state["ctx"] is not None and time.monotonic() - _state.get("checked", 0) < FRESH_SECONDS:
            return _state["ctx"]
    with _build_lock:
        corpus = intel.get_corpus()
        with _state_lock:
            if _state["corpus"] is corpus and _state["ctx"] is not None:
                _state["checked"] = time.monotonic()
                return _state["ctx"]
        with db.connect() as con:
            ctx = Ctx(corpus, con)
        with _state_lock:
            _state.update(corpus=corpus, ctx=ctx, checked=time.monotonic())
        return ctx


def reset() -> None:
    """Invalidate every derived aggregation (corpus is rebuilt on the next request)."""
    intel.reset_cache()
    with _state_lock:
        _state.update(corpus=None, ctx=None, checked=0)


def memo(ctx: Ctx, key: tuple, fn):
    with ctx.lock:
        if key in ctx.memo:
            return ctx.memo[key]
    val = fn()
    with ctx.lock:
        if len(ctx.memo) > 300:
            ctx.memo.clear()
        ctx.memo[key] = val
    return val


# ----------------------------------------------------------------------------- comparable coverage
def comparable(ctx: Ctx, win: Window) -> dict:
    """Sources whose coverage can be defended across BOTH windows. Conservative, based on recorded facts only:
      1. enabled and not currently failing;
      2. first article collected at or before the start of the previous window (being enabled today proves nothing);
      3. at least one dated article, and no more than 20% of its stored articles lacking a publication date.
    Zero in a window is then a real zero for that source. Needs at least MIN_COMPARABLE_SOURCES sources."""
    ok, excluded = [], {}
    for sid, s in ctx.sources.items():
        fc = _parse_dt(s["first_collected"])
        dated = s["total"] - s["undated_total"]
        if not s["enabled"]:
            why = "disabled"
        elif s["health"] == "failed":
            why = "currently failing"
        elif fc is None:
            why = "no articles collected yet"
        elif fc > win.prev_start:
            why = "collected too recently (first article after the previous period began)"
        elif dated < 1 or s["undated_total"] / max(1, s["total"]) > UNDATED_MAX_SHARE:
            why = "publication dates missing"
        else:
            ok.append(sid)
            continue
        excluded[sid] = why
    reasons = Counter(w.split(" (")[0] for w in excluded.values())
    return {"sources": set(ok), "count": len(ok), "excluded": len(excluded), "excluded_reasons": dict(reasons), "sufficient": len(ok) >= MIN_COMPARABLE_SOURCES,
            "criteria": ["Enabled and not failing", "First article collected before the previous period began (not merely enabled today)",
                         "At least one dated article and <= 20% of articles without a publication date", f"At least {MIN_COMPARABLE_SOURCES} such sources"],
            "excluded_detail": dict(list(excluded.items())[:80])}


def allowed_sources(ctx: Ctx, f: Filters, win: Window) -> tuple[set | None, dict | None]:
    if f.mode != "comparable":
        return None, None
    comp = memo(ctx, ("comparable", win.start, win.end), lambda: comparable(ctx, win))
    return comp["sources"], comp


# ----------------------------------------------------------------------------- event views
def active_events(ctx: Ctx, f: Filters, lo: datetime, hi: datetime, allowed: set | None) -> list[tuple[dict, list[dict], datetime]]:
    """[(cluster, members published in [lo,hi) that pass the filters, first dated filtered publication ever)]."""
    key = ("ev", f.key()[3:7], lo, hi, None if allowed is None else tuple(sorted(allowed)))
    def build():
        out = []
        for c in ctx.corpus.clusters:
            if f.category and c["categories"][0] != f.category: continue
            if f.vendor and f.vendor not in c["entities"]["vendors"]: continue
            if f.tech and f.tech not in c["techs"]: continue
            if f.source and f.source not in c["source_ids"]: continue
            if allowed is not None and not (set(c["source_ids"]) & allowed): continue
            ok = [m for m in c["members"] if not m["undated"] and (allowed is None or m["source_id"] in allowed) and (not f.source or m["source_id"] == f.source)]
            mem = [m for m in ok if lo <= m["ts"] < hi]
            if mem:
                out.append((c, mem, ok[0]["ts"]))
        return out
    return memo(ctx, key, build)


def metrics(ctx: Ctx, evs: list) -> dict:
    sig = ctx.corpus.signals
    arts, srcs, cves = 0, set(), set()
    multi = official = adv_events = 0
    for c, mem, _ in evs:
        arts += len(mem)
        s = {m["source_id"] for m in mem}
        srcs |= s
        multi += len(s) >= 2
        official += sum(1 for m in mem if m["source_type"] == "official" and m["official"])
        adv_events += all(m["source_type"] == "official" for m in mem)
        for m in mem:
            cves.update(m["cves"])
    kev = sum(1 for x in cves if (sig.get(x) or {}).get("kev"))
    return {"events": len(evs), "articles": arts, "sources": len(srcs), "cves": len(cves), "kev_cves": kev, "multi_source_events": multi,
            "official_advisories": official, "advisory_only_events": adv_events}


def _density(items_ts: list[datetime], lo: datetime, hi: datetime, bucket_hours: int) -> float:
    nb = max(1, math.ceil((hi - lo).total_seconds() / 3600 / bucket_hours))
    seen = {min(nb - 1, int((t - lo).total_seconds() // (3600 * bucket_hours))) for t in items_ts if lo <= t < hi}
    return len(seen) / nb


def window_assessment(ctx: Ctx, f: Filters, win: Window, allowed: set | None) -> dict:
    """Can the previous window be compared with the current one? Returns flags + the human-readable reason."""
    def build():
        ts_prev = [m["ts"] for m in ctx.dated if win.prev_start <= m["ts"] < win.start and (allowed is None or m["source_id"] in allowed)]
        need = DENSITY_HOUR if win.bucket_hours == 1 else DENSITY_DAY
        dens = _density(ts_prev, win.prev_start, win.start, win.bucket_hours)
        history_ok = len(ts_prev) >= 20 and dens >= need
        cur = [m for m in ctx.dated if win.start <= m["ts"] < win.end and (allowed is None or m["source_id"] in allowed) and (not f.source or m["source_id"] == f.source)]
        late = 0
        for m in cur:
            fc = _parse_dt((ctx.sources.get(m["source_id"]) or {}).get("first_collected"))
            if fc is None or fc > win.prev_start:
                late += 1
        share = late / len(cur) if cur else 0.0
        changed = f.mode != "comparable" and share >= COVERAGE_CHANGE_SHARE
        late_src = sum(1 for sid in {m["source_id"] for m in cur} if (_parse_dt(ctx.sources.get(sid, {}).get("first_collected")) or win.end) > win.prev_start)
        return {"history_ok": history_ok, "previous_articles": len(ts_prev), "previous_density": round(dens, 2), "coverage_changed": changed,
                "late_source_share": round(share, 3), "late_sources": late_src, "contributing": len({m["source_id"] for m in cur})}
    return memo(ctx, ("assess", f.key()[3:8], win.start, win.end), build)


def compare(cur: float | None, prev: float | None, a: dict, min_base: int = MIN_BASE_EVENTS) -> dict:
    """Period comparison that never invents a baseline. status: ok | insufficient | coverage_changed | no_data."""
    out = {"current": cur, "previous": None, "delta": None, "pct": None, "status": "ok", "reason": None}
    if cur is None:
        return {**out, "status": "no_data", "reason": "Insufficient comparable coverage"}
    if not a["history_ok"]:
        return {**out, "status": "insufficient", "reason": f"Previous period has too little data ({a['previous_articles']} dated articles, {int(a['previous_density'] * 100)}% of its time slots covered)"}
    out["previous"] = prev
    out["delta"] = cur - (prev or 0)
    if a["coverage_changed"]:
        out.update(status="coverage_changed", reason=f"{a['late_sources']} of {a['contributing']} contributing sources were first collected after the previous period began, so the change may reflect coverage, not activity")
    elif (prev or 0) < min_base:
        out.update(status="insufficient", reason=f"Previous value ({prev or 0}) is below the minimum base ({min_base}) for a percentage")
    else:
        out["pct"] = round(100 * (cur - prev) / prev, 1)
    return out


# ----------------------------------------------------------------------------- coverage status
def coverage_status(ctx: Ctx) -> dict:
    src = ctx.sources.values()
    enabled = [s for s in src if s["enabled"]]
    failed = [s for s in enabled if s["health"] == "failed"]
    quiet = [s for s in enabled if s["health"] == "quiet"]
    operational = [s for s in enabled if s["operational"]]
    undated = sum(1 for i in ctx.corpus.items if i.get("undated"))
    if not enabled:
        status = "insufficient"
    elif not failed:
        status = "complete"
    elif len(failed) / len(enabled) <= 0.15:
        status = "partial"
    else:
        status = "degraded"
    return {"status": status, "configured": len(ctx.sources), "enabled": len(enabled), "operational": len(operational), "healthy": sum(1 for s in enabled if s["health"] == "healthy"),
            "failed": len(failed), "quiet": len(quiet), "disabled": len(ctx.sources) - len(enabled), "undated_articles": undated,
            "failed_sources": [s["name"] for s in failed][:20]}


def _filters_echo(f: Filters, win: Window, ctx: Ctx, comp: dict | None) -> dict:
    return {"period": f.period, "since": _iso(win.start), "until": _iso(win.end), "previous_since": _iso(win.prev_start), "bucket_hours": win.bucket_hours,
            "mode": f.mode, "category": f.category, "source": f.source, "vendor": f.vendor, "tech": f.tech, "timezone": "UTC",
            "comparable": None if comp is None else {k: comp[k] for k in ("count", "excluded", "excluded_reasons", "sufficient", "criteria")},
            "generated_at": _iso(ctx.now)}


INSUFFICIENT = "Insufficient comparable coverage"


def _prepare(f: Filters):
    ctx = get_ctx()
    win = resolve_window(f, ctx.now)
    allowed, comp = allowed_sources(ctx, f, win)
    insufficient = comp is not None and not comp["sufficient"]
    return ctx, win, allowed, comp, insufficient


# ----------------------------------------------------------------------------- overview KPIs
KPIS = [("events", "Distinct Events", "events"), ("articles", "Published Articles", "articles"), ("sources", "Contributing Sources", "sources"),
        ("cves", "CVEs Mentioned", "cves"), ("kev_cves", "KEV-Listed CVEs Mentioned", "kev_cves"), ("multi_source_events", "Multi-Source Events", "events"),
        ("official_advisories", "Official Advisories", "articles")]


def overview(f: Filters) -> dict:
    ctx, win, allowed, comp, insufficient = _prepare(f)
    def build():
        base = {"filters": _filters_echo(f, win, ctx, comp), "coverage": coverage_status(ctx)}
        if insufficient:
            return {**base, "status": "insufficient_comparable", "message": INSUFFICIENT, "kpis": [], "assessment": None}
        cur = metrics(ctx, active_events(ctx, f, win.start, win.end, allowed))
        prev = metrics(ctx, active_events(ctx, f, win.prev_start, win.start, allowed))
        a = window_assessment(ctx, f, win, allowed)
        kpis = []
        for key, label, unit in KPIS:
            c = compare(cur[key], prev[key], a, MIN_BASE_SMALL if key in ("kev_cves", "official_advisories", "sources") else MIN_BASE_EVENTS)
            kpis.append({"key": key, "label": label, "unit": unit, **c, "scope": "news" if key in ("events", "articles", "sources", "multi_source_events", "official_advisories") else "vulnerability"})
        cov = base["coverage"]
        enabled = max(1, cov["enabled"])
        share = round(100 * cov["operational"] / enabled, 1)
        kpis.append({"key": "data_coverage", "label": "Data Coverage", "unit": "% of enabled sources operational", "current": share, "previous": None, "delta": None, "pct": None,
                     "status": "ok", "reason": f"{cov['operational']} of {cov['enabled']} enabled sources operational; {cov['quiet']} quiet (not failed); {cov['undated_articles']} articles without publication date excluded from time windows", "scope": "quality"})
        return {**base, "status": "ok", "message": None, "kpis": kpis, "assessment": a,
                "notes": ["Counts describe media coverage, not real incidents.", "KEV = inclusion in CISA's known-exploited catalogue; a CVE appearing in a recent article is not evidence of recent exploitation."]}
    return memo(ctx, ("overview", f.key()), build)


# ----------------------------------------------------------------------------- Panel A: threat trends
def trends(f: Filters) -> dict:
    ctx, win, allowed, comp, insufficient = _prepare(f)
    def build():
        base = {"filters": _filters_echo(f, win, ctx, comp)}
        if insufficient:
            return {**base, "status": "insufficient_comparable", "message": INSUFFICIENT, "categories": [], "series": {}, "bucket_starts": []}
        a = window_assessment(ctx, f, win, allowed)
        cur = active_events(ctx, f, win.start, win.end, allowed)
        prev = active_events(ctx, f, win.prev_start, win.start, allowed)
        nb = win.nb
        series: dict[str, dict] = {}
        def slot(cat):
            return series.setdefault(cat, {"events": [set() for _ in range(nb)], "new_events": [0] * nb, "articles": [0] * nb})
        tot = {"events": [set() for _ in range(nb)], "new_events": [0] * nb, "articles": [0] * nb}
        for c, mem, first in cur:
            cat = c["categories"][0]
            s = slot(cat)
            for m in mem:
                b = win.bucket(m["ts"])
                s["events"][b].add(c["id"]); s["articles"][b] += 1
                tot["events"][b].add(c["id"]); tot["articles"][b] += 1
            if win.start <= first < win.end:
                b = win.bucket(first)
                s["new_events"][b] += 1; tot["new_events"][b] += 1
        prev_by = Counter(c["categories"][0] for c, _, _ in prev)
        cur_by = Counter(c["categories"][0] for c, _, _ in cur)
        art_by = Counter(c["categories"][0] for c, mem, _ in cur for _ in mem)
        new_by = Counter(c["categories"][0] for c, _, first in cur if win.start <= first < win.end)
        rows = []
        for cat in CATEGORIES:
            if cat not in cur_by and cat not in prev_by:
                continue
            rows.append({"category": cat, "events": cur_by.get(cat, 0), "new_events": new_by.get(cat, 0), "articles": art_by.get(cat, 0),
                         "compare": compare(cur_by.get(cat, 0), prev_by.get(cat, 0), a, MIN_BASE_SMALL)})
        rows.sort(key=lambda r: (-r["events"], r["category"]))
        out_series = {k: {"events": [len(x) for x in v["events"]], "new_events": v["new_events"], "articles": v["articles"]} for k, v in series.items()}
        out_series["__total"] = {"events": [len(x) for x in tot["events"]], "new_events": tot["new_events"], "articles": tot["articles"]}
        return {**base, "status": "ok", "message": None, "bucket_starts": win.labels(), "categories": rows, "series": out_series,
                "total": compare(len(cur), len(prev), a), "assessment": a,
                "notes": ["Each event is counted once, under its primary category. 'Events' = events with at least one article in the bucket; 'New events' = events whose first known publication falls in the bucket; 'Articles' = publications.",
                          "More coverage is not evidence of more attacks."]}
    return memo(ctx, ("trends", f.key()), build)


# ----------------------------------------------------------------------------- drill-down: events list
def _event_row(ctx: Ctx, c: dict, mem: list[dict]) -> dict:
    corpus = ctx.corpus
    arts = sorted(mem, key=lambda m: m["ts"], reverse=True)
    return {"id": c["id"], "title": c["title"], "category": c["categories"][0], "first_published": _iso(mem[0]["ts"]) if mem else None,
            "last_published": _iso(arts[0]["ts"]) if arts else None, "articles_in_period": len(mem), "article_count": c["article_count"],
            "source_count": len({m["source_id"] for m in mem}), "cves": c["cves"][:8], "priority": corpus.prio[c["id"]]["score"], "official": c["official"],
            "advisory_only": c["advisory_only"],
            "articles": [{"title": m["title"], "url": m["url"], "source": m["source_name"], "published": m["published"]} for m in arts[:5]]}


def events_list(f: Filters, *, at: str | None = None, span_hours: int = 24, cve: str | None = None, sort: str = "priority", page: int = 1, page_size: int = 20) -> dict:
    ctx, win, allowed, comp, insufficient = _prepare(f)
    page_size = max(1, min(MAX_PAGE, page_size)); page = max(1, page)
    lo, hi = win.start, win.end
    if at:
        a0 = _parse_dt(at)
        if a0 is None or span_hours not in (1, 24):
            raise AnalyticsError("Invalid bucket")
        lo, hi = a0, a0 + timedelta(hours=span_hours)
    if insufficient:
        return {"items": [], "total": 0, "page": page, "page_size": page_size, "pages": 1, "message": INSUFFICIENT}
    evs = active_events(ctx, f, lo, hi, allowed)
    if cve:
        evs = [e for e in evs if cve in e[0]["cves"]]
    keyf = {"priority": lambda e: (-ctx.corpus.prio[e[0]["id"]]["score"], e[0]["id"]), "recent": lambda e: (-max(m["ts"] for m in e[1]).timestamp(), e[0]["id"]),
            "sources": lambda e: (-len({m["source_id"] for m in e[1]}), e[0]["id"])}[sort]
    evs = sorted(evs, key=keyf)
    chunk = evs[(page - 1) * page_size: page * page_size]
    return {"items": [_event_row(ctx, c, m) for c, m, _ in chunk], "total": len(evs), "page": page, "page_size": page_size, "pages": max(1, -(-len(evs) // page_size)),
            "since": _iso(lo), "until": _iso(hi), "message": None}


# ----------------------------------------------------------------------------- Panel B: vulnerabilities
def vulnerabilities(f: Filters, *, cvss_min=None, cvss_max=None, epss_min=None, epss_max=None, kev_only=False, q: str | None = None) -> dict:
    ctx, win, allowed, comp, insufficient = _prepare(f)
    key = ("vuln", f.key(), cvss_min, cvss_max, epss_min, epss_max, kev_only, (q or "").upper())
    def build():
        base = {"filters": _filters_echo(f, win, ctx, comp)}
        if insufficient:
            return {**base, "status": "insufficient_comparable", "message": INSUFFICIENT, "points": [], "totals": {}}
        mentioned: dict[str, dict] = {}
        for c, mem, _ in active_events(ctx, f, win.start, win.end, allowed):
            for m in mem:
                for x in m["cves"]:
                    d = mentioned.setdefault(x, {"articles": 0, "events": set(), "sources": set()})
                    d["articles"] += 1; d["events"].add(c["id"]); d["sources"].add(m["source_id"])
        with db.connect() as con:
            mon = ctx.monitored_cves(con)
            use_mon = not (f.category or f.source or f.vendor)
            mon_ids = [x for x, t in mon.items() if use_mon and (not f.tech or f.tech in t)]
            sig = dict(ctx.corpus.signals)
            missing = [x for x in mon_ids if x not in sig]
            if missing:
                sig.update(intel.load_signals(con, missing))
        ids = set(mentioned) | set(mon_ids)
        qq = (q or "").strip().upper()
        pts = []
        for x in ids:
            if qq and qq not in x: continue
            s = sig.get(x) or {}
            cvss, epss, kev = s.get("cvss"), s.get("epss"), bool(s.get("kev"))
            if kev_only and not kev: continue
            if cvss_min is not None and (cvss is None or cvss < cvss_min): continue
            if cvss_max is not None and (cvss is None or cvss > cvss_max): continue
            if epss_min is not None and (epss is None or epss < epss_min): continue
            if epss_max is not None and (epss is None or epss > epss_max): continue
            m = mentioned.get(x)
            pts.append({"cve": x, "cvss": cvss, "epss": None if epss is None else round(epss, 5), "epss_percentile": s.get("epss_percentile"), "kev": kev,
                        "kev_added": (s.get("kev") or {}).get("date_added"), "articles": m["articles"] if m else 0, "events": len(m["events"]) if m else 0,
                        "mentioned": bool(m), "monitored": sorted(mon.get(x, [])) if use_mon else [], "published": s.get("published")})
        pts.sort(key=lambda p: (-p["kev"], -p["articles"], -(p["epss"] or 0), p["cve"]))
        truncated = len(pts) > MAX_POINTS
        totals = {"cves": len(pts), "plottable": sum(1 for p in pts if p["cvss"] is not None and p["epss"] is not None), "missing_cvss": sum(1 for p in pts if p["cvss"] is None),
                  "missing_epss": sum(1 for p in pts if p["epss"] is None), "kev": sum(p["kev"] for p in pts), "mentioned": sum(p["mentioned"] for p in pts),
                  "monitored": sum(1 for p in pts if p["monitored"]), "truncated": truncated, "shown": min(len(pts), MAX_POINTS)}
        return {**base, "status": "ok", "message": None, "points": pts[:MAX_POINTS], "totals": totals,
                "notes": ["EPSS is the estimated probability of exploitation activity within its prediction horizon (about 30 days); KEV means CISA lists the CVE as exploited in the wild. They are different signals.",
                          "Missing CVSS/EPSS are shown as N/A and not plotted; no CVE is assigned a score of zero. A CVE in a recent article is not necessarily recently exploited. No new risk score is computed."]}
    return memo(ctx, key, build)


# ----------------------------------------------------------------------------- Panel C: vendors & technologies
def _entity_keys(kind: str, c: dict, m: dict) -> list[tuple[str, str]]:
    if kind == "vendor":
        return [(v, v) for v in m["entities"]["vendors"]]
    return [(t["id"], TECH[t["id"]].name) for t in m["techs"] if t["id"] in TECH]


def entities(f: Filters, kind: str, sort: str = "events", page: int = 1, page_size: int = 15) -> dict:
    ctx, win, allowed, comp, insufficient = _prepare(f)
    page_size = max(1, min(MAX_PAGE, page_size)); page = max(1, page)
    def build():
        base = {"filters": _filters_echo(f, win, ctx, comp), "kind": kind, "label": "Media Attention"}
        if insufficient:
            return {**base, "status": "insufficient_comparable", "message": INSUFFICIENT, "items": [], "total": 0}
        a = window_assessment(ctx, f, win, allowed)
        sig = ctx.corpus.signals
        def agg(lo, hi):
            d: dict[str, dict] = {}
            for c, mem, _ in active_events(ctx, f, lo, hi, allowed):
                for m in mem:
                    for k, name in _entity_keys(kind, c, m):
                        g = d.setdefault(k, {"id": k, "name": name, "events": set(), "articles": 0, "cves": set(), "sources": set()})
                        g["events"].add(c["id"]); g["articles"] += 1; g["cves"].update(m["cves"]); g["sources"].add(m["source_id"])
            return d
        cur, prev = agg(win.start, win.end), agg(win.prev_start, win.start)
        rows = []
        for k, g in cur.items():
            kev = sum(1 for x in g["cves"] if (sig.get(x) or {}).get("kev"))
            rows.append({"id": k, "name": g["name"], "events": len(g["events"]), "articles": g["articles"], "cves": len(g["cves"]), "kev_cves": kev, "sources": len(g["sources"]),
                         "compare": compare(len(g["events"]), len(prev[k]["events"]) if k in prev else 0, a, MIN_BASE_SMALL)})
        sk = {"events": lambda r: (-r["events"], -r["articles"], r["name"]), "articles": lambda r: (-r["articles"], -r["events"], r["name"]),
              "cves": lambda r: (-r["cves"], -r["events"], r["name"]), "kev": lambda r: (-r["kev_cves"], -r["events"], r["name"]),
              "sources": lambda r: (-r["sources"], -r["events"], r["name"])}[sort]
        rows.sort(key=sk)
        return {**base, "status": "ok", "message": None, "total": len(rows), "all": [r["id"] for r in rows[:200]], "rows": rows[:200], "assessment": a,
                "notes": ["Media Attention counts distinct events and publications that mention the entity. It is not a risk level, vulnerability rate or incident count."]}
    full = memo(ctx, ("entities", kind, sort, f.key()), build)
    if full.get("status") != "ok":
        return full
    rows = full["rows"]
    return {**{k: v for k, v in full.items() if k not in ("rows", "all")}, "items": rows[(page - 1) * page_size: page * page_size], "page": page, "page_size": page_size,
            "pages": max(1, -(-len(rows) // page_size))}


def entity_detail(f: Filters, kind: str, eid: str) -> dict:
    ctx, win, allowed, comp, insufficient = _prepare(f)
    def build():
        base = {"filters": _filters_echo(f, win, ctx, comp), "kind": kind, "id": eid}
        if insufficient:
            return {**base, "status": "insufficient_comparable", "message": INSUFFICIENT}
        f2 = Filters(**{**f.__dict__, "vendor": eid if kind == "vendor" else f.vendor, "tech": eid if kind == "technology" else f.tech})
        name = eid if kind == "vendor" else (TECH[eid].name if eid in TECH else eid)
        evs = active_events(ctx, f2, win.start, win.end, allowed)
        nb = win.nb
        ser_e = [set() for _ in range(nb)]; ser_a = [0] * nb
        arts, cves = [], Counter()
        for c, mem, _ in evs:
            for m in mem:
                if kind == "vendor" and eid not in m["entities"]["vendors"]: continue
                if kind == "technology" and eid not in {t["id"] for t in m["techs"]}: continue
                b = win.bucket(m["ts"]); ser_e[b].add(c["id"]); ser_a[b] += 1
                arts.append(m)
                cves.update(m["cves"])
        arts.sort(key=lambda m: m["ts"], reverse=True)
        sig = ctx.corpus.signals
        cve_rows = [{"cve": x, "articles": n, "kev": bool((sig.get(x) or {}).get("kev")), "cvss": (sig.get(x) or {}).get("cvss"), "epss": (sig.get(x) or {}).get("epss")}
                    for x, n in sorted(cves.items(), key=lambda kv: (-bool((sig.get(kv[0]) or {}).get("kev")), -kv[1], kv[0]))[:25]]
        watch, graph_id = [], None
        with db.connect() as con:
            if kind == "technology":
                watch = [{"id": r[0], "name": r[1]} for r in con.execute("SELECT w.id,w.name FROM watchlist w JOIN watchlist_item i ON i.watchlist_id=w.id WHERE i.kind='technology' AND i.ref_id=? ORDER BY w.name LIMIT 20", (eid,))]
                graph_id = f"tech:{eid}" if eid in TECH else None
            else:
                from . import graph
                gid = "vendor:" + graph.slug(eid)
                try:
                    graph_id = gid if graph.get_node(con, gid) else None
                except Exception:
                    graph_id = None
        return {**base, "status": "ok", "name": name, "bucket_starts": win.labels(), "series": {"events": [len(s) for s in ser_e], "articles": ser_a},
                "events": len(evs), "articles": len(arts), "cves": cve_rows, "watchlists": watch, "graph_node": graph_id,
                "news": [{"title": m["title"], "url": m["url"], "source": m["source_name"], "published": m["published"], "event_id": ctx.corpus.cluster_of[m["id"]]["id"]} for m in arts[:10]],
                "note": "A graph node is offered only when verifiable relationships exist for the entity."}
    return memo(ctx, ("entity", kind, eid, f.key()), build)


# ----------------------------------------------------------------------------- Panel D: emerging stories
def emerging(f: Filters, sort: str = "growth", page: int = 1, page_size: int = 15) -> dict:
    ctx, win, allowed, comp, insufficient = _prepare(f)
    page_size = max(1, min(MAX_PAGE, page_size)); page = max(1, page)
    def build():
        base = {"filters": _filters_echo(f, win, ctx, comp)}
        if insufficient:
            return {**base, "status": "insufficient_comparable", "message": INSUFFICIENT, "rows": []}
        half = min(win.span / 2, timedelta(hours=72))
        mid = win.end - half
        rows = []
        for c, mem, first in active_events(ctx, f, win.start, win.end, allowed):
            recent = [m for m in mem if m["ts"] >= mid]
            earlier = [m for m in c["members"] if not m["undated"] and win.end - 2 * half <= m["ts"] < mid and (allowed is None or m["source_id"] in allowed)]
            srcs_recent = {m["source_id"] for m in recent}
            srcs_before = {m["source_id"] for m in c["members"] if not m["undated"] and m["ts"] < mid and (allowed is None or m["source_id"] in allowed)}
            new_sources = len(srcs_recent - srcs_before)
            all_dated = [m for m in c["members"] if not m["undated"] and (allowed is None or m["source_id"] in allowed)]
            span_h = (all_dated[-1]["ts"] - all_dated[0]["ts"]).total_seconds() / 3600 if len(all_dated) > 1 else 0
            history_ok = len(all_dated) >= 2 and (win.end - first) >= half and span_h > 0
            growth = len(recent) - len(earlier)
            seen: set[str] = set(); cum = []
            day0 = all_dated[0]["ts"]
            nd = min(14, max(1, int((all_dated[-1]["ts"] - day0).days) + 1))
            buckets = [set() for _ in range(nd)]; abuckets = [0] * nd
            for m in all_dated:
                b = min(nd - 1, int((m["ts"] - day0).days)); buckets[b].add(m["source_id"]); abuckets[b] += 1
            for b in buckets:
                seen |= b; cum.append(len(seen))
            r = _event_row(ctx, c, mem)
            r.update({"first_published": _iso(all_dated[0]["ts"]), "last_published": _iso(all_dated[-1]["ts"]), "growth": growth if history_ok else None,
                      "recent_articles": len(recent), "earlier_articles": len(earlier), "new_sources": new_sources, "independent_sources": len({m["source_id"] for m in all_dated}),
                      "series": {"sources_cumulative": cum, "articles": abuckets, "start": _iso(day0)}, "history_sufficient": history_ok,
                      "technologies": [TECH[t].name for t in c["techs"] if t in TECH], "vendors": c["entities"]["vendors"][:5],
                      "_recent": max(m["ts"] for m in mem).timestamp()})
            rows.append(r)
        sk = {"growth": lambda r: (r["growth"] is None, -(r["growth"] or 0), -r["new_sources"], r["id"]),
              "sources": lambda r: (-r["independent_sources"], -r["articles_in_period"], r["id"]),
              "recency": lambda r: (-r["_recent"], r["id"]),
              "priority": lambda r: (-r["priority"], r["id"])}[sort]
        rows.sort(key=sk)
        for r in rows:
            r.pop("_recent", None)
        return {**base, "status": "ok", "message": None, "rows": rows[:300], "total": len(rows), "half_window_hours": round(half.total_seconds() / 3600),
                "notes": ["Growth = articles in the latest half of the window minus the half before it (halves capped at 72 h). Shown only when the event has enough history; otherwise 'insufficient history'.",
                          "More outlets covering a story signals rising media attention, not a rising threat. Several outlets repeating one disclosure are not independent confirmations."]}
    full = memo(ctx, ("emerging", sort, f.key()), build)
    if full.get("status") != "ok":
        return full
    rows = full["rows"]
    return {**{k: v for k, v in full.items() if k != "rows"}, "items": rows[(page - 1) * page_size: page * page_size], "page": page, "page_size": page_size,
            "pages": max(1, -(-len(rows) // page_size))}


# ----------------------------------------------------------------------------- Panel E: ATT&CK
def attack_intel(f: Filters) -> dict:
    ctx, win, allowed, comp, insufficient = _prepare(f)
    def build():
        base = {"filters": _filters_echo(f, win, ctx, comp)}
        if insufficient:
            return {**base, "status": "insufficient_comparable", "message": INSUFFICIENT, "techniques": []}
        cat = ent.mitre_catalog()
        techs = cat["techniques"]
        total = with_t = 0
        by_t: dict[str, dict] = {}
        for c, mem, _ in active_events(ctx, f, win.start, win.end, allowed):
            for m in mem:
                total += 1
                ids = {t["id"] for t in m["entities"]["mitre"]}
                if not ids: continue
                with_t += 1
                for tid in ids:
                    g = by_t.setdefault(tid, {"articles": 0, "events": set(), "series": [0] * win.nb})
                    g["articles"] += 1; g["events"].add(c["id"]); g["series"][win.bucket(m["ts"])] += 1
        sufficient = with_t >= MIN_ATTACK_ARTICLES
        rows = [{"id": k, "name": techs.get(k, {}).get("n", k), "tactics": techs.get(k, {}).get("t", []), "url": ent.mitre_url(k), "articles": g["articles"], "events": len(g["events"])}
                for k, g in sorted(by_t.items(), key=lambda kv: (-kv[1]["articles"], kv[0]))]
        tactics: Counter = Counter()
        for r in rows:
            for t in r["tactics"] or ["(no tactic in catalogue)"]:
                tactics[t] += r["articles"]
        top = rows[:5]
        out = {**base, "status": "ok", "message": None, "label": "News Mentions", "articles_total": total, "articles_with_attack": with_t,
               "coverage_pct": round(100 * with_t / total, 1) if total else None, "sufficient": sufficient,
               "insufficient_message": None if sufficient else "Insufficient explicit ATT&CK coverage",
               "techniques": rows[:100], "technique_count": len(rows),
               "tactics": [{"tactic": k, "mentions": v} for k, v in tactics.most_common()],
               "trend": {"bucket_starts": win.labels(), "series": [{"id": r["id"], "name": r["name"], "mentions": by_t[r["id"]]["series"]} for r in top]} if sufficient else None,
               "catalog": {"source": cat.get("source"), "version": cat.get("version"), "size": len(techs)},
               "notes": ["News Mentions = techniques whose ATT&CK id is written explicitly in an article title or excerpt. No technique is inferred from keywords.",
                         "A tactic count adds the mentions of every technique mapped to it; a technique with several tactics counts under each.",
                         "Documented Relationships (groups/campaigns using a technique) are historical MITRE data and do not imply recent activity."]}
        return out
    return memo(ctx, ("attack", f.key()), build)


def attack_technique(f: Filters, tid: str) -> dict | None:
    from . import attack
    ctx, win, allowed, comp, insufficient = _prepare(f)
    techs = ent.mitre_catalog()["techniques"]
    if tid not in techs:
        return None
    mentions = []
    if not insufficient:
        for c, mem, _ in active_events(ctx, f, win.start, win.end, allowed):
            for m in mem:
                if tid in {t["id"] for t in m["entities"]["mitre"]}:
                    mentions.append(m)
    mentions.sort(key=lambda m: m["ts"], reverse=True)
    with db.connect() as con:
        d = attack.technique_detail(con, tid)
        graph_ok = False
        try:
            from . import graph
            graph_ok = bool(graph.get_node(con, "attack:" + tid))
        except Exception:
            pass
    def brief(lst):
        return [{"id": x.get("attack_id") or x.get("id"), "name": x.get("name")} for x in (lst or [])[:12]]
    return {"id": tid, "name": techs[tid]["n"], "tactics": techs[tid]["t"], "url": ent.mitre_url(tid),
            "news_mentions": {"label": "News Mentions", "articles": len(mentions),
                              "items": [{"title": m["title"], "url": m["url"], "source": m["source_name"], "published": m["published"]} for m in mentions[:10]]},
            "documented": {"label": "Documented Relationships (MITRE, historical)", "actors": brief(d.get("actors") if d else None), "actor_total": len(d.get("actors") or []) if d else 0,
                           "campaigns": brief(d.get("campaigns") if d else None), "campaign_total": len(d.get("campaigns") or []) if d else 0,
                           "software_total": len(d.get("software") or []) if d else 0,
                           "note": "Relationships published by MITRE ATT&CK. They are not evidence of recent activity."},
            "graph_node": ("attack:" + tid) if graph_ok else None, "filters": _filters_echo(f, win, ctx, comp)}


# ----------------------------------------------------------------------------- Panel F: coverage & quality
def quality(f: Filters) -> dict:
    ctx, win, allowed, comp, insufficient = _prepare(f)
    def build():
        cov = coverage_status(ctx)
        evs = [] if insufficient else active_events(ctx, f, win.start, win.end, allowed)
        m = metrics(ctx, evs)
        items = [i for i in ctx.corpus.items if win.start <= i["ts"] < win.end]   # undated items are timestamped at collection and counted only as 'missing date'
        dated = [i for i in items if not i.get("undated")]
        n = len(items)
        pct = lambda x, d: None if not d else round(100 * x / d, 1)  # noqa: E731
        vuln = [i for i in dated if "Vulnerabilities" in i["categories"]]
        art_src = Counter(i["source_id"] for i in dated)
        by_cat = Counter(c["categories"][0] for c, _, _ in evs)
        by_type = Counter(SOURCE_TYPES.get(i["source_type"], i["source_type"]) for i in dated)
        official_n = sum(1 for i in dated if i["source_type"] == "official")
        nb = win.nb
        d_art = [0] * nb; d_src = [set() for _ in range(nb)]
        for i in dated:
            b = win.bucket(i["ts"]); d_art[b] += 1; d_src[b].add(i["source_id"])
        quality_rows = [("Publication date present", pct(len(dated), n)), ("CVE id extracted (all articles)", pct(sum(1 for i in dated if i["cves"]), len(dated))),
                        ("CVE id extracted (Vulnerabilities articles)", pct(sum(1 for i in vuln if i["cves"]), len(vuln))),
                        ("Specific category assigned", pct(sum(1 for i in dated if any(c != FALLBACK_CATEGORY for c in i["categories"])), len(dated))),
                        ("Monitored technology matched", pct(sum(1 for i in dated if i["techs"]), len(dated))),
                        ("Explicit ATT&CK technique id", pct(sum(1 for i in dated if i["entities"]["mitre"]), len(dated))),
                        ("Vendor recognised", pct(sum(1 for i in dated if i["entities"]["vendors"]), len(dated)))]
        with db.connect() as con:
            logs = [dict(r) for r in con.execute("SELECT id,started_at,finished_at,forced,only_due,ok,failed,new_items,updated_items,resighted FROM news_sync_log ORDER BY id DESC LIMIT 10")]
            nlogs = con.execute("SELECT COUNT(*),MIN(started_at),COALESCE(SUM(resighted),0) FROM news_sync_log").fetchone()
        srcs = []
        for s in ctx.sources.values():
            srcs.append({"id": s["id"], "name": s["name"], "type": s["type_label"], "health": s["health"], "enabled": s["enabled"], "articles_period": art_src.get(s["id"], 0),
                         "stored": s["items_stored"], "undated": s["undated_total"], "first_collected": s["first_collected"], "last_success": s["last_success"], "error": s["error"] if s["health"] == "failed" else None})
        srcs.sort(key=lambda x: (-x["articles_period"], x["name"]))
        return {"filters": _filters_echo(f, win, ctx, comp), "status": "insufficient_comparable" if insufficient else "ok", "message": INSUFFICIENT if insufficient else None,
                "coverage": cov,
                "metrics": {"configured": cov["configured"], "enabled": cov["enabled"], "healthy": cov["healthy"], "failed": cov["failed"], "quiet": cov["quiet"], "disabled": cov["disabled"],
                            "undated_articles": cov["undated_articles"], "unique_events": m["events"], "multi_source_events": m["multi_source_events"],
                            "official_share_pct": pct(official_n, len(dated)), "cve_extraction_pct": pct(sum(1 for i in vuln if i["cves"]), len(vuln)),
                            "attack_mapping_pct": pct(sum(1 for i in dated if i["entities"]["mitre"]), len(dated)),
                            "duplicates_prevented": None},
                "duplicates": {"available": False, "note": "Cross-source duplicates are not counted separately. The sync log started recording on first use and counts only re-sightings of already-stored articles.",
                               "resighted_since_logging": nlogs[2], "logging_since": nlogs[1], "syncs_logged": nlogs[0]},
                "charts": {"articles_by_source": [{"id": s["id"], "name": s["name"], "value": s["articles_period"]} for s in srcs if s["articles_period"]][:20],
                           "events_by_category": [{"name": k, "value": v} for k, v in by_cat.most_common()],
                           "articles_by_source_type": [{"name": k, "value": v} for k, v in by_type.most_common()],
                           "daily": {"bucket_starts": win.labels(), "articles": d_art, "sources": [len(s) for s in d_src]},
                           "metadata_quality": [{"name": k, "value": v} for k, v in quality_rows]},
                "sources": srcs, "sync_history": logs,
                "notes": ["A quiet source (healthy, no article in 24 h) is not a failed source. Coverage counts failures of enabled sources only.",
                          "Sync history and snapshots begin when this module was introduced; earlier periods were not recorded and are not reconstructed."]}
    return memo(ctx, ("quality", f.key()), build)


# ----------------------------------------------------------------------------- metadata for filters
def meta() -> dict:
    ctx = get_ctx()
    def build():
        corpus = ctx.corpus
        facets = intel.facets(corpus, limit=60)
        dts = [i["ts"] for i in ctx.dated]
        with db.connect() as con:
            snaps = con.execute("SELECT COUNT(*),MIN(taken_at),MAX(taken_at) FROM analytics_snapshot").fetchone()
        return {"generated_at": _iso(ctx.now), "timezone": "UTC", "analytics_version": ANALYTICS_VERSION, "max_range_days": MAX_RANGE_DAYS,
                "periods": [{"id": k, "hours": v} for k, v in PRESETS.items()] + [{"id": "custom", "hours": None}],
                "categories": CATEGORIES, "modes": [{"id": "all", "label": "All Available Sources"}, {"id": "comparable", "label": "Comparable Sources"}],
                "sources": [{"id": s["id"], "name": s["name"], "type": s["type_label"], "enabled": s["enabled"], "health": s["health"]} for s in ctx.sources.values()],
                "vendors": [v["name"] for v in facets["vendors"]], "technologies": facets["technologies"],
                "data_range": {"oldest_dated": _iso(min(dts)) if dts else None, "newest_dated": _iso(max(dts)) if dts else None, "undated_articles": sum(1 for i in corpus.items if i.get("undated")),
                               "articles": len(corpus.items), "events": len(corpus.clusters), "window_days": 90},
                "coverage": coverage_status(ctx),
                "snapshots": {"count": snaps[0], "first": snaps[1], "last": snaps[2]}}
    return memo(ctx, ("meta",), build)


# ----------------------------------------------------------------------------- snapshots & history
def config_hash() -> str:
    blob = json.dumps([ANALYTICS_VERSION, CATEGORIES, intel.CLUSTER.__dict__, intel.PRIORITY.__dict__, intel.PERIODS], sort_keys=True, default=str)
    return hashlib.sha1(blob.encode()).hexdigest()[:12]


def take_snapshot(min_interval_min: int = 25, note: str | None = None) -> int | None:
    """Append-only record of coverage/quality at this moment. Previous snapshots are never edited; nothing is back-filled."""
    ctx = get_ctx()
    corpus = ctx.corpus
    cov = coverage_status(ctx)
    fp = hashlib.sha1(",".join(f"{c['id']}:{c['article_count']}" for c in sorted(corpus.clusters, key=lambda c: c["id"])).encode()).hexdigest()[:16]
    cfg = config_hash()
    with db.connect() as con:
        last = con.execute("SELECT taken_at,cluster_fingerprint,config_hash FROM analytics_snapshot ORDER BY id DESC LIMIT 1").fetchone()
        if last:
            age = (_now() - _parse_dt(last["taken_at"])).total_seconds() / 60
            if age < min_interval_min:
                return None
        dated = [i for i in corpus.items if not i.get("undated")]
        quality_blob = {"cve_pct": round(100 * sum(1 for i in dated if i["cves"]) / max(1, len(dated)), 1),
                        "attack_pct": round(100 * sum(1 for i in dated if i["entities"]["mitre"]) / max(1, len(dated)), 1),
                        "category_pct": round(100 * sum(1 for i in dated if any(c != FALLBACK_CATEGORY for c in i["categories"])) / max(1, len(dated)), 1)}
        ls = con.execute("SELECT id,finished_at,ok,failed,new_items FROM news_sync_log ORDER BY id DESC LIMIT 1").fetchone()
        n = note
        if last and last["config_hash"] != cfg:
            n = ((n + "; ") if n else "") + "classification/clustering configuration changed since the previous snapshot: series are not directly comparable"
        cur = con.execute(
            "INSERT INTO analytics_snapshot(taken_at,analytics_version,config_hash,cluster_fingerprint,sources_configured,sources_enabled,sources_operational,sources_failed,sources_quiet,"
            "articles,dated_articles,undated_articles,events,multi_source_events,quality,sync_state,last_sync_id,note) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (db.now_iso(), ANALYTICS_VERSION, cfg, fp, cov["configured"], cov["enabled"], cov["operational"], cov["failed"], cov["quiet"], len(corpus.items), len(dated),
             len(corpus.items) - len(dated), len(corpus.clusters), sum(1 for c in corpus.clusters if len(c["source_ids"]) >= 2), json.dumps(quality_blob),
             json.dumps(dict(ls) if ls else None), ls["id"] if ls else None, n))
        return cur.lastrowid


def after_sync() -> None:
    """Called after a news sync: rebuild the corpus once (so the first request is fast) and record a snapshot."""
    reset()
    get_ctx()
    take_snapshot(min_interval_min=20)
    try:   # listing index upkeep for the local intelligence database
        from . import vulns
        with db.connect() as con:
            vulns.index_add_missing(con)
    except Exception:
        pass
    try:   # company snapshots (append-only, at most every 6 h per company)
        from . import company_intel
        company_intel.snapshot_all_after_sync()
    except Exception:
        pass


def warm() -> None:
    get_ctx()
    take_snapshot(min_interval_min=25)


def history(limit: int = 60, since: str | None = None) -> dict:
    limit = max(1, min(200, limit))
    q, args = "SELECT * FROM analytics_snapshot", []
    if since:
        q += " WHERE taken_at>=?"; args.append(since)
    q += " ORDER BY id DESC LIMIT ?"; args.append(limit)
    with db.connect() as con:
        rows = [dict(r) for r in con.execute(q, args)]
        syncs = [dict(r) for r in con.execute("SELECT id,started_at,finished_at,forced,only_due,ok,failed,new_items,updated_items,resighted FROM news_sync_log ORDER BY id DESC LIMIT 20")]
    for r in rows:
        r["quality"] = json.loads(r["quality"]) if r["quality"] else None
        r["sync_state"] = json.loads(r["sync_state"]) if r["sync_state"] else None
    rows.reverse()
    prev = None
    for r in rows:
        r["config_changed"] = bool(prev and prev["config_hash"] != r["config_hash"])
        r["delta"] = None if not prev else {k: r[k] - prev[k] for k in ("articles", "events", "multi_source_events", "sources_enabled", "sources_operational") if r.get(k) is not None and prev.get(k) is not None}
        prev = r
    return {"snapshots": rows, "sync_log": syncs, "analytics_version": ANALYTICS_VERSION, "config_hash": config_hash(),
            "dates": {"publication": "article's own date, UTC (undated articles excluded)", "collection": "when this app first stored the article", "sync": "when a feed refresh ran (news_sync_log)", "snapshot": "when metrics were recorded (analytics_snapshot)"},
            "note": "History starts at the first snapshot; no earlier history exists or is fabricated. Event ids are stable (derived from the earliest article); a changed config_hash flags a reclassification."}
