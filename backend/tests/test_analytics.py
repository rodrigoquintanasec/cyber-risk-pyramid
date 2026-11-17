import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app import analytics as an, db  # noqa: E402
from app.config import settings  # noqa: E402
from app.main import app  # noqa: E402
from app.news import entities as ent, intel, repo  # noqa: E402
from app.news.sources import SOURCES  # noqa: E402

NOW = datetime.now(timezone.utc)
NEWS = [s.id for s in SOURCES if s.type == "news" and s.enabled][:8]
OFFICIAL = next(s.id for s in SOURCES if s.type == "official" and s.enabled)
WORDS = "alpha bravo charlie delta echo foxtrot golf hotel india juliet kilo lima mike november oscar papa quebec romeo sierra tango".split()


def mk(i, hours_ago, source=None, cves=(), cats=("Malware",), title=None, undated=False, stype="news", mitre=(), vendors=()):
    ts = NOW - timedelta(hours=hours_ago)
    t = title or f"Headline {WORDS[i % 20]}{i} unique{i}x zeta{i}y topic{i}z"
    e = ent.extract(t, "")
    e["mitre"] = [{"id": m, "field": "title"} for m in mitre]
    e["vendors"] = list(vendors) or e["vendors"]
    return {"id": f"{i:012d}" + "0" * 12, "title": t, "summary": "", "url": f"https://x.test/{i}", "source_id": source or NEWS[i % len(NEWS)], "source_name": source or NEWS[i % len(NEWS)],
            "source_type": stype, "published": None if undated else ts.isoformat(), "collected_at": ts.isoformat(), "updated_at": None, "ts": ts, "undated": undated,
            "categories": list(cats), "techs": [], "cves": sorted(cves), "entities": e, "tokens": intel.tokens(t), "topics": list(cats),
            "official": stype == "official"}


@pytest.fixture()
def env(tmp_path, monkeypatch):
    object.__setattr__(settings, "db_path", str(tmp_path / "a.sqlite"))
    intel.reset_cache()
    db.init_db()
    with db.connect() as c:
        repo.sync_source_rows(c)
    holder = {}

    def load(items, signals=None, first_collected=None, old=True):
        corpus = intel.Corpus(items, intel.build_clusters(items), signals or {}, NOW)
        monkeypatch.setattr(intel, "get_corpus", lambda con=None: corpus)
        holder["corpus"] = corpus
        an._state.update(corpus=None, ctx=None)
        ctx = an.get_ctx()
        for sid, s in ctx.sources.items():
            n = sum(1 for i in items if i["source_id"] == sid)
            s["total"], s["undated_total"] = n, sum(1 for i in items if i["source_id"] == sid and i["undated"])
            s["first_collected"] = (first_collected or {}).get(sid, (NOW - timedelta(days=120)).isoformat() if old else NOW.isoformat())
        ctx.memo.clear()
        return ctx
    yield load
    an._state.update(corpus=None, ctx=None)
    object.__setattr__(settings, "db_path", str(tmp_path / "unused.sqlite"))


def spread(n, per_day_start=0, days=14, **kw):
    """n independent events (distinct sources/titles) spread over `days` days."""
    return [mk(per_day_start + i, 6 + (i % days) * 24 + (i % 5), **kw) for i in range(n)]


# ---------------------------------------------------------------- counting rules
def test_one_cve_in_ten_articles_is_one_cve_and_one_event(env):
    items = [mk(i, 3 + i, cves=["CVE-2026-9001"], source=NEWS[i % len(NEWS)], title=f"Fix released for flaw variant{i} CVE-2026-9001 patch{i}") for i in range(10)]
    env(items)
    o = an.overview(an.Filters(period="7d"))
    k = {x["key"]: x for x in o["kpis"]}
    assert k["cves"]["current"] == 1 and k["events"]["current"] == 1 and k["articles"]["current"] == 10
    assert k["multi_source_events"]["current"] == 1


def test_events_by_category_count_each_event_once_under_primary_category(env):
    items = [mk(i, 5 + i, cats=("Ransomware", "Malware")) for i in range(4)] + [mk(10 + i, 5 + i, cats=("Malware",)) for i in range(3)]
    env(items)
    t = an.trends(an.Filters(period="7d"))
    by = {r["category"]: r["events"] for r in t["categories"]}
    assert by == {"Ransomware": 4, "Malware": 3} and sum(by.values()) == t["total"]["current"] == 7
    assert sum(t["series"]["__total"]["events"]) == 7


def test_temporal_grouping_hourly_for_24h_daily_otherwise_and_new_vs_active(env):
    older = mk(1, 30, title="Shared story gamma delta epsilon zeta eta theta", cves=["CVE-2026-1111"])
    again = mk(2, 2, title="Shared story gamma delta epsilon zeta eta theta follow up", cves=["CVE-2026-1111"], source=NEWS[1])
    env([older, again, mk(3, 1)])
    t24 = an.trends(an.Filters(period="24h"))
    assert t24["filters"]["bucket_hours"] == 1 and len(t24["bucket_starts"]) == 24
    tot = t24["series"]["__total"]
    assert sum(tot["articles"]) == 2 and sum(tot["events"]) == 2          # the older article is outside 24h
    assert sum(tot["new_events"]) == 1                                     # the shared story began before the window: active, not new
    t7 = an.trends(an.Filters(period="7d"))
    assert t7["filters"]["bucket_hours"] == 24 and len(t7["bucket_starts"]) == 7 and sum(t7["series"]["__total"]["new_events"]) == 2


def test_undated_articles_are_never_recent(env):
    env([mk(1, 1), mk(2, 1, undated=True), mk(3, 1, undated=True)])
    k = {x["key"]: x for x in an.overview(an.Filters(period="24h"))["kpis"]}
    assert k["articles"]["current"] == 1 and k["events"]["current"] == 1
    assert an.overview(an.Filters(period="24h"))["coverage"]["undated_articles"] == 2


def test_period_with_zero_articles_is_zero_not_unknown_and_never_crashes(env):
    env([mk(1, 200)])
    o = an.overview(an.Filters(period="24h"))
    k = {x["key"]: x for x in o["kpis"]}
    assert k["events"]["current"] == 0 and k["articles"]["pct"] is None and o["status"] == "ok"
    assert an.trends(an.Filters(period="24h"))["categories"] == []
    assert an.events_list(an.Filters(period="24h"))["total"] == 0


# ---------------------------------------------------------------- comparisons & coverage
def test_comparison_needs_a_real_baseline_and_unchanged_coverage(env):
    cur = spread(40, 0, days=7)
    prev = [mk(100 + i, 7 * 24 + 6 + (i % 7) * 24 + (i % 5), source=NEWS[i % len(NEWS)]) for i in range(20)]
    env(cur + prev)
    k = {x["key"]: x for x in an.overview(an.Filters(period="7d"))["kpis"]}["events"]
    assert k["status"] == "ok" and k["previous"] == 20 and k["delta"] == 20 and k["pct"] == 100.0


def test_no_percentage_when_previous_period_has_no_data(env):
    env(spread(30, 0, days=7))
    k = {x["key"]: x for x in an.overview(an.Filters(period="7d"))["kpis"]}["events"]
    assert k["status"] == "insufficient" and k["pct"] is None and k["previous"] is None and k["delta"] is None and "too little data" in k["reason"]


def test_new_sources_do_not_create_an_artificial_trend(env):
    cur = spread(40, 0, days=7)
    prev = [mk(100 + i, 7 * 24 + 6 + (i % 7) * 24 + (i % 5), source=NEWS[i % 2]) for i in range(20)]
    fresh = {s: (NOW - timedelta(days=2)).isoformat() for s in NEWS[2:]}      # six sources only started being collected 2 days ago
    env(cur + prev, first_collected=fresh)
    k = {x["key"]: x for x in an.overview(an.Filters(period="7d"))["kpis"]}["events"]
    assert k["status"] == "coverage_changed" and k["pct"] is None and "first collected after" in k["reason"]
    comp = an.overview(an.Filters(period="7d", mode="comparable"))
    assert comp["status"] == "insufficient_comparable" and comp["message"] == "Insufficient comparable coverage" and comp["kpis"] == []


def test_comparable_mode_keeps_only_sources_with_demonstrable_history(env):
    items = [mk(i, 6 + (i % 7) * 24, source=NEWS[i % 5]) for i in range(30)] + [mk(100 + i, 7 * 24 + 6 + (i % 7) * 24, source=NEWS[i % 5]) for i in range(30)]
    items += [mk(300 + i, 6 + i * 12, source=NEWS[6]) for i in range(5)]
    fresh = {NEWS[6]: (NOW - timedelta(days=1)).isoformat()}
    ctx = env(items, first_collected=fresh)
    win = an.resolve_window(an.Filters(period="7d"), ctx.now)
    comp = an.comparable(ctx, win)
    assert comp["sufficient"] and set(NEWS[:5]) <= comp["sources"] and NEWS[6] not in comp["sources"] and "disabled" in comp["excluded_reasons"]
    o = an.overview(an.Filters(period="7d", mode="comparable"))
    k = {x["key"]: x for x in o["kpis"]}["events"]
    assert o["status"] == "ok" and k["status"] == "ok" and k["current"] == 30 and k["previous"] == 30      # new source's articles are excluded from both windows


def test_enabled_today_is_not_proof_of_history(env):
    ctx = env(spread(30, 0, days=7), old=False)
    comp = an.comparable(ctx, an.resolve_window(an.Filters(period="7d"), ctx.now))
    assert comp["count"] == 0 and not comp["sufficient"]


def test_quiet_source_is_not_failed(env):
    ctx = env([mk(1, 100)])
    with db.connect() as c:
        c.execute("UPDATE news_source SET status='ok', last_success=? WHERE enabled=1", (db.now_iso(),))
    ctx = env([mk(1, 100)])
    cov = an.coverage_status(ctx)
    assert cov["failed"] == 0 and cov["quiet"] > 0 and cov["status"] == "complete"
    with db.connect() as c:
        c.execute("UPDATE news_source SET status='error', error='boom' WHERE id=?", (NEWS[0],))
    ctx = env([mk(1, 100)])
    cov = an.coverage_status(ctx)
    assert cov["failed"] == 1 and cov["status"] == "partial" and NEWS[0] in {s for s in ctx.sources if ctx.sources[s]["name"] in cov["failed_sources"]}


# ---------------------------------------------------------------- vulnerabilities
def _sig(cve, cvss=None, epss=None, kev=None):
    return {"cve": cve, "cvss": cvss, "epss": epss, "epss_percentile": None, "kev": {"date_added": "2026-01-01"} if kev else None, "published": None, "products": []}


def test_cve_with_missing_scores_is_na_and_never_zero_and_kev_differs_from_epss(env):
    items = [mk(1, 3, cves=["CVE-2026-0001"]), mk(2, 4, cves=["CVE-2026-0002"]), mk(3, 5, cves=["CVE-2026-0003"]), mk(4, 6, cves=["CVE-2026-0004"])]
    sig = {"CVE-2026-0001": _sig("CVE-2026-0001", 9.8, 0.9, True), "CVE-2026-0002": _sig("CVE-2026-0002", 5.0, 0.002, False),
           "CVE-2026-0003": _sig("CVE-2026-0003", None, None, False), "CVE-2026-0004": _sig("CVE-2026-0004", 7.0, None, True)}
    env(items, sig)
    v = an.vulnerabilities(an.Filters(period="7d"))
    p = {x["cve"]: x for x in v["points"]}
    assert p["CVE-2026-0003"]["cvss"] is None and p["CVE-2026-0003"]["epss"] is None
    assert p["CVE-2026-0004"]["kev"] is True and p["CVE-2026-0004"]["epss"] is None            # KEV without EPSS: not plotted, not zero
    assert p["CVE-2026-0002"]["kev"] is False and p["CVE-2026-0002"]["epss"] == 0.002           # low EPSS and not KEV
    t = v["totals"]
    assert t["plottable"] == 2 and t["missing_cvss"] == 1 and t["missing_epss"] == 2 and t["kev"] == 2
    assert {x["cve"] for x in an.vulnerabilities(an.Filters(period="7d"), kev_only=True)["points"]} == {"CVE-2026-0001", "CVE-2026-0004"}
    assert {x["cve"] for x in an.vulnerabilities(an.Filters(period="7d"), epss_min=0.001)["points"]} == {"CVE-2026-0001", "CVE-2026-0002"}
    assert {x["cve"] for x in an.vulnerabilities(an.Filters(period="7d"), q="0003")["points"]} == {"CVE-2026-0003"}


def test_official_advisory_does_not_imply_exploitation(env):
    items = [mk(1, 3, cves=["CVE-2026-0100"], source=OFFICIAL, stype="official", title="Security advisory covering flaw CVE-2026-0100 in product")]
    env(items, {"CVE-2026-0100": _sig("CVE-2026-0100", 8.8, 0.01, False)})
    p = an.vulnerabilities(an.Filters(period="7d"))["points"][0]
    assert p["kev"] is False and p["mentioned"] is True
    k = {x["key"]: x for x in an.overview(an.Filters(period="7d"))["kpis"]}
    assert k["official_advisories"]["current"] == 1 and k["kev_cves"]["current"] == 0


# ---------------------------------------------------------------- ATT&CK
def test_attack_needs_explicit_ids_and_reports_insufficient_coverage(env):
    env([mk(1, 3, mitre=["T1059"]), mk(2, 4), mk(3, 5)])
    a = an.attack_intel(an.Filters(period="7d"))
    assert a["articles_with_attack"] == 1 and a["sufficient"] is False and a["insufficient_message"] == "Insufficient explicit ATT&CK coverage" and a["trend"] is None
    items = [mk(i, 3 + i, mitre=["T1059" if i % 2 else "T1566"]) for i in range(12)]
    env(items)
    a = an.attack_intel(an.Filters(period="7d"))
    assert a["sufficient"] and a["trend"]["series"] and {t["id"] for t in a["techniques"]} == {"T1059", "T1566"} and a["label"] == "News Mentions"


def test_technique_detail_separates_news_mentions_from_documented_relationships(env):
    env([mk(1, 3, mitre=["T1059"])])
    d = an.attack_technique(an.Filters(period="7d"), "T1059")
    assert d["news_mentions"]["articles"] == 1 and "historical" in d["documented"]["label"] and "not evidence of recent activity" in d["documented"]["note"]
    assert an.attack_technique(an.Filters(period="7d"), "T9999") is None


# ---------------------------------------------------------------- vendors, emerging, quality
def test_vendor_ranking_counts_events_not_articles(env):
    items = [mk(i, 3 + i, cves=["CVE-2026-0500"], vendors=["Contoso"], title=f"Contoso flaw story variant{i} CVE-2026-0500 detail{i}") for i in range(5)] + [mk(20, 4, vendors=["Fabrikam"])]
    env(items)
    rows = {r["name"]: r for r in an.entities(an.Filters(period="7d"), "vendor")["items"]}
    assert rows["Contoso"]["events"] == 1 and rows["Contoso"]["articles"] == 5 and rows["Fabrikam"]["events"] == 1
    assert an.entities(an.Filters(period="7d"), "vendor")["label"] == "Media Attention"
    d = an.entity_detail(an.Filters(period="7d"), "vendor", "Contoso")
    assert d["articles"] == 5 and d["events"] == 1 and d["graph_node"] is None


def test_emerging_story_flags_missing_history_and_sorts(env):
    story = [mk(i, 100 - i * 12, source=NEWS[i % 6], cves=["CVE-2026-7000"], title=f"Zero day story phase{i} CVE-2026-7000 note{i}") for i in range(8)]
    fresh = mk(50, 1, title="Brand new unique headline sigma tau upsilon phi")
    env(story + [fresh])
    r = an.emerging(an.Filters(period="7d"), "sources")
    top = r["items"][0]
    assert top["independent_sources"] == 6 and top["history_sufficient"] is True
    f = next(x for x in r["items"] if x["articles"][0]["title"].startswith("Brand new"))
    assert f["history_sufficient"] is False and f["growth"] is None
    assert an.emerging(an.Filters(period="7d"), "priority")["total"] == 2


def test_quality_panel_distinguishes_states_and_duplicates_not_invented(env):
    env([mk(i, 3 + i) for i in range(5)] + [mk(9, 2, undated=True)])
    q = an.quality(an.Filters(period="7d"))
    m = q["metrics"]
    assert m["configured"] == len(SOURCES) and m["undated_articles"] == 1 and m["duplicates_prevented"] is None and q["duplicates"]["available"] is False
    assert {x["name"] for x in q["charts"]["metadata_quality"]} >= {"Publication date present", "Explicit ATT&CK technique id"}
    assert q["sync_history"] == []


# ---------------------------------------------------------------- cache, snapshots, clusters changing
def test_results_are_cached_and_invalidated_on_reset(env):
    env([mk(1, 3)])
    a = an.overview(an.Filters(period="7d"))
    assert an.overview(an.Filters(period="7d")) is a                         # memoised
    assert an.overview(an.Filters(period="30d")) is not a                    # different filters
    env([mk(1, 3), mk(2, 4)])                                                # corpus rebuilt -> new context -> memo gone
    assert {x["key"]: x for x in an.overview(an.Filters(period="7d"))["kpis"]}["events"]["current"] == 2


def test_cluster_ids_are_stable_when_articles_join_and_snapshots_are_append_only(env):
    base = mk(1, 30, cves=["CVE-2026-8000"], title="Stable event alpha CVE-2026-8000 first report")
    env([base])
    s1 = an.take_snapshot(0)
    id1 = intel.build_clusters([base])[0]["id"]
    joined = mk(2, 3, cves=["CVE-2026-8000"], source=NEWS[1], title="Follow up beta CVE-2026-8000 second report")
    env([base, joined])
    assert [c["id"] for c in intel.build_clusters([base, joined])] == [id1]
    s2 = an.take_snapshot(0)
    assert s1 and s2 and s2 > s1 and an.take_snapshot(25) is None            # minimum interval prevents duplicate snapshots
    h = an.history()
    snaps = h["snapshots"]
    assert len(snaps) == 2 and snaps[0]["cluster_fingerprint"] != snaps[1]["cluster_fingerprint"] and snaps[1]["events"] == 1 and snaps[1]["delta"]["articles"] == 1
    assert snaps[0]["delta"] is None and snaps[1]["config_changed"] is False and "no earlier history" in h["note"]


def test_snapshot_flags_configuration_changes(env, monkeypatch):
    env([mk(1, 3)])
    an.take_snapshot(0)
    monkeypatch.setattr(an, "config_hash", lambda: "changed00000")
    an.take_snapshot(0)
    snaps = an.history()["snapshots"]
    assert snaps[1]["config_changed"] is True and "not directly comparable" in snaps[1]["note"]


# ---------------------------------------------------------------- API: validation, limits, pagination, compatibility
def test_api_validation_limits_and_pagination(env):
    env(spread(30, 0, days=7))
    c = TestClient(app)
    assert c.get("/api/v1/analytics/overview?period=7d").status_code == 200
    assert c.get("/api/v1/analytics/overview?period=99d").status_code == 422
    assert c.get("/api/v1/analytics/overview?category=Nope").status_code == 422
    assert c.get("/api/v1/analytics/overview?source=nope").status_code == 422
    assert c.get("/api/v1/analytics/overview?mode=weird").status_code == 422
    assert c.get("/api/v1/analytics/overview?period=custom").status_code == 422
    assert c.get("/api/v1/analytics/overview?period=custom&date_from=2026-01-01&date_to=2026-09-01").status_code == 422     # > 90 days
    assert c.get("/api/v1/analytics/overview?period=custom&date_from=2026-05-02&date_to=2026-05-01").status_code == 422
    d0 = (NOW - timedelta(days=5)).date().isoformat()
    assert c.get(f"/api/v1/analytics/overview?period=custom&date_from={d0}&date_to={NOW.date().isoformat()}").status_code == 200
    assert c.get("/api/v1/analytics/events?page_size=500").status_code == 422
    assert c.get("/api/v1/analytics/emerging?page_size=51").status_code == 422
    assert c.get("/api/v1/analytics/vulnerabilities?cvss_min=11").status_code == 422
    p1 = c.get("/api/v1/analytics/events?page_size=10&page=1").json()
    p2 = c.get("/api/v1/analytics/events?page_size=10&page=2").json()
    assert p1["total"] == 30 and p1["pages"] == 3 and len(p1["items"]) == 10 and {x["id"] for x in p1["items"]}.isdisjoint({x["id"] for x in p2["items"]})
    assert c.get("/api/v1/analytics/attack/technique/notanid").status_code == 422
    assert c.get("/api/v1/analytics/entity?kind=technology&id=nope").status_code == 404


def test_vulnerability_points_are_capped(env, monkeypatch):
    monkeypatch.setattr(an, "MAX_POINTS", 5)
    items = [mk(i, 3 + i, cves=[f"CVE-2026-{3000 + i}"]) for i in range(12)]
    env(items)
    v = an.vulnerabilities(an.Filters(period="7d"))
    assert len(v["points"]) == 5 and v["totals"]["truncated"] is True and v["totals"]["cves"] == 12


def test_endpoints_work_on_an_empty_existing_database(env):
    env([])
    c = TestClient(app)
    for path in ("meta", "overview", "trends", "events", "vulnerabilities", "vendors", "technologies", "emerging", "attack", "quality", "history"):
        r = c.get(f"/api/v1/analytics/{path}")
        assert r.status_code == 200, path
    assert c.get("/api/v1/analytics/meta").json()["data_range"]["articles"] == 0
