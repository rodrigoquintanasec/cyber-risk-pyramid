"""Custom Intelligence Dashboards: CRUD, matching rules, time windows, counting policy, attention scale, coverage and the original dashboard staying untouched."""
import hashlib
import inspect
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app import db, intel_dash as idash  # noqa: E402
from app.config import settings  # noqa: E402
from app.main import app  # noqa: E402
from app.news import intel, repo  # noqa: E402
from app.news.sources import SOURCES  # noqa: E402

NOW = datetime.now(timezone.utc)
ISO = lambda d: d.isoformat(timespec="seconds")  # noqa: E731
N = [0]


def add_article(source, title, summary="", hours=2.0, cves=(), published=True, url=None, collected_hours=None):
    N[0] += 1
    nid = hashlib.md5(f"{N[0]}".encode()).hexdigest()[:24]
    pub = ISO(NOW - timedelta(hours=hours))
    coll = ISO(NOW - timedelta(hours=collected_hours if collected_hours is not None else hours))
    with db.connect() as c:
        c.execute("INSERT INTO news_item(id,source_id,guid,url,url_canon,title,summary,published,collected_at,content_hash,sort_ts) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                  (nid, source, f"g{N[0]}", url or f"https://news.example.test/{source}/{N[0]}", url or f"https://news.example.test/{source}/{N[0]}", title, summary, pub if published else None, coll, "h", pub if published else coll))
        for cv in cves:
            c.execute("INSERT INTO news_cve VALUES(?,?)", (nid, cv))
    intel.reset_cache()
    idash.invalidate()
    return nid


SRC = ["bleepingcomputer", "securityweek", "krebs", "thehackernews", "talos", "therecord"]


@pytest.fixture()
def env(tmp_path):
    object.__setattr__(settings, "db_path", str(tmp_path / "d.sqlite"))
    intel.reset_cache()
    idash.invalidate()
    db.init_db()
    with db.connect() as c:
        repo.sync_source_rows(c)
        for s in SOURCES:
            c.execute("UPDATE news_source SET status='ok', last_success=? WHERE id=?", (ISO(NOW), s.id))
    add_article("krebs", "Old background story", "history marker", hours=24 * 9)            # history older than a 7-day window
    yield
    intel.reset_cache()
    idash.invalidate()


@pytest.fixture()
def api(env):
    return TestClient(app, client=("127.0.0.1", 9))


def mk(api, name="Ransomware Intelligence", keywords=None, **kw):
    r = api.post("/api/v1/intelligence-dashboards", json={"name": name, "keywords": keywords if keywords is not None else [], **kw})
    assert r.status_code == 201, r.text
    return r.json()


def kw(name, *terms, exclude=(), mt="word", enabled=True):
    return {"display_name": name, "enabled": enabled, "terms": [{"term": t, "match_type": mt} for t in terms], "excluded_terms": [{"term": t, "match_type": mt} for t in exclude]}


def stats(api, did, period="7d", **q):
    r = api.get(f"/api/v1/intelligence-dashboards/{did}/statistics", params={"period": period, **q})
    assert r.status_code == 200, r.text
    return r.json()


def by_name(st):
    return {k["display_name"]: k for k in st["keywords"]}


def fill_feed(n=12):
    """Enough unrelated recent articles for the period to count as covered."""
    for i in range(n):
        add_article(SRC[i % len(SRC)], f"Unrelated routine bulletin number {i}", "nothing to see", hours=3 + i)


# ---------------------------------------------------------------- 1-9 administration & persistence
def test_dashboard_crud_duplicate_and_independence(api):
    d = mk(api, keywords=[kw("Ransomware", "ransomware"), kw("LockBit", "lockbit", "lock bit", mt="phrase")], description="d1")
    assert d["keyword_count"] == 2 and d["default_period"] == "7d" and d["keywords"][1]["terms"][1]["match_type"] == "phrase"
    assert api.post("/api/v1/intelligence-dashboards", json={"name": "ransomware intelligence"}).status_code == 409              # unique name, case-insensitive
    p = api.patch(f"/api/v1/intelligence-dashboards/{d['id']}", json={"name": "Ransomware & Actors", "description": "new", "default_period": "30d"}).json()
    assert (p["name"], p["description"], p["default_period"]) == ("Ransomware & Actors", "new", "30d")
    assert api.patch(f"/api/v1/intelligence-dashboards/{d['id']}", json={"default_period": "custom"}).status_code == 422
    c = api.post(f"/api/v1/intelligence-dashboards/{d['id']}/duplicate").json()
    assert c["name"] == "Ransomware & Actors Copy" and c["id"] != d["id"] and c["default_period"] == "30d" and c["description"] == "new"
    assert [k["display_name"] for k in c["keywords"]] == ["Ransomware", "LockBit"] and {k["id"] for k in c["keywords"]}.isdisjoint({k["id"] for k in d["keywords"]})
    assert [t["term"] for t in c["keywords"][1]["terms"]] == ["lockbit", "lock bit"]
    assert api.post(f"/api/v1/intelligence-dashboards/{d['id']}/duplicate").json()["name"] == "Ransomware & Actors Copy 2"
    api.patch(f"/api/v1/intelligence-dashboards/{c['id']}/keywords/{c['keywords'][0]['id']}", json={"display_name": "Changed"})          # editing the copy leaves the original alone
    assert api.get(f"/api/v1/intelligence-dashboards/{d['id']}").json()["keywords"][0]["display_name"] == "Ransomware"
    assert api.delete(f"/api/v1/intelligence-dashboards/{d['id']}").json()["deleted"] is True and api.get(f"/api/v1/intelligence-dashboards/{d['id']}").status_code == 404
    with db.connect() as con:
        assert con.execute("SELECT COUNT(*) FROM intelligence_dashboard_keyword WHERE dashboard_id=?", (d["id"],)).fetchone()[0] == 0           # cascade
        assert con.execute("SELECT COUNT(*) FROM intelligence_keyword_term t LEFT JOIN intelligence_dashboard_keyword k ON k.id=t.keyword_id WHERE k.id IS NULL").fetchone()[0] == 0
    assert api.get(f"/api/v1/intelligence-dashboards/{c['id']}").status_code == 200


def test_keyword_crud_order_enable_and_period_persistence(api):
    d = mk(api, "Cloud")
    did = d["id"]
    for name, t in (("AWS", "aws"), ("Azure", "azure"), ("Docker", "docker")):
        r = api.post(f"/api/v1/intelligence-dashboards/{did}/keywords", json=kw(name, t))
        assert r.status_code == 201
    d = api.get(f"/api/v1/intelligence-dashboards/{did}").json()
    ids = [k["id"] for k in d["keywords"]]
    assert api.post(f"/api/v1/intelligence-dashboards/{did}/keywords", json=kw("aws", "x1")).status_code == 409                       # duplicate display name
    u = api.patch(f"/api/v1/intelligence-dashboards/{did}/keywords/{ids[0]}", json={"display_name": "Amazon", "terms": [{"term": "aws"}, {"term": "amazon web services", "match_type": "phrase"}], "excluded_terms": [{"term": "podcast"}]}).json()
    k = u["keywords"][0]
    assert k["display_name"] == "Amazon" and len(k["terms"]) == 2 and k["excluded_terms"][0]["term"] == "podcast"
    assert api.patch(f"/api/v1/intelligence-dashboards/{did}/keywords/{ids[1]}", json={"enabled": False}).json()["enabled_keywords"] == 2
    r = api.put(f"/api/v1/intelligence-dashboards/{did}/keywords/order", json={"ids": [ids[2], ids[0], ids[1]]}).json()
    assert [k["id"] for k in r["keywords"]] == [ids[2], ids[0], ids[1]]
    assert api.put(f"/api/v1/intelligence-dashboards/{did}/keywords/order", json={"ids": [ids[2], 99999]}).status_code == 422
    assert api.delete(f"/api/v1/intelligence-dashboards/{did}/keywords/{ids[2]}").json()["keyword_count"] == 2
    assert api.patch(f"/api/v1/intelligence-dashboards/{did}", json={"default_period": "90d"}).json()["default_period"] == "90d"
    with db.connect() as con:                                                                                                       # persistence: a fresh connection sees everything
        got = idash.get_dashboard(con, did)
    assert got["default_period"] == "90d" and [k["display_name"] for k in got["keywords"]] == ["Amazon", "Azure"] and got["keywords"][1]["enabled"] is False
    a = mk(api, "A"); b = mk(api, "B")
    assert [x["id"] for x in api.put("/api/v1/intelligence-dashboards/order", json={"ids": [b["id"], a["id"]]}).json()["items"]][:2] == [b["id"], a["id"]]


def test_validation_and_write_protection(api):
    base = "/api/v1/intelligence-dashboards"
    assert api.post(base, json={"name": ""}).status_code == 422 and api.post(base, json={"name": "x" * 200}).status_code == 422
    assert api.post(base, json={"name": "Ctl\x01"}).status_code == 422
    d = mk(api, "V")
    for bad in (kw("K", "a"), kw("K", ""), kw("K", "!!"), kw("K", "x" * 100), kw("K", "ab", mt="exact"), kw("", "term"), {"display_name": "K", "terms": []},
                {"display_name": "K", "terms": [{"term": "okay", "match_type": "regex"}]}, kw("K", *[f"term{i}" for i in range(25)])):
        assert api.post(f"{base}/{d['id']}/keywords", json=bad).status_code in (422,), bad
    assert api.get(f"{base}/abc").status_code == 422 and api.get(f"{base}/99999").status_code == 404
    remote = TestClient(app, client=("203.0.113.9", 1))
    assert remote.post(base, json={"name": "x"}).status_code == 403 and remote.delete(f"{base}/{d['id']}").status_code == 403 and remote.get(base).status_code == 200
    assert api.get(f"{base}/{d['id']}/statistics", params={"period": "7d; DROP TABLE news_item"}).status_code == 422
    with db.connect() as con:
        assert con.execute("SELECT COUNT(*) FROM news_item").fetchone()[0] >= 1


def test_limits(api):
    d = mk(api, "Big")
    for i in range(idash.MAX_KEYWORDS):
        assert api.post(f"/api/v1/intelligence-dashboards/{d['id']}/keywords", json=kw(f"K{i}", f"term{i}")).status_code == 201
    assert api.post(f"/api/v1/intelligence-dashboards/{d['id']}/keywords", json=kw("Over", "overterm")).status_code == 409


# ---------------------------------------------------------------- 10-15 matching rules
def test_whole_word_exact_phrase_and_text_matching():
    m = lambda t, mt, text: idash.Matcher([{"term": t, "match_type": mt, "is_exclusion": False}]).matches(idash.norm(text))  # noqa: E731
    assert m("Akira", "word", "New Akira ransomware wave") and m("akira", "word", "AKIRA, again") and m("Akira", "word", "(Akira)") and m("Akira", "word", "the akira-style attack")
    assert not m("Akira", "word", "Akiranet reports") and not m("Akira", "word", "preakira") and not m("AWS", "word", "paws and laws")
    assert m("remote code execution", "phrase", "A Remote   Code\nExecution bug") and not m("remote code execution", "phrase", "remote execution of code")
    assert not m("remote code execution", "phrase", "remote code executions") and not m("sql injection", "phrase", "nosql injection")
    assert m("CVE-2021-44", "exact", "Patch for cve-2021-44228 released") and not m("CVE-2021-44", "word", "Patch for cve-2021-44228 released")
    assert m("C++", "word", "written in C++ today") and m("Zero-day", "word", "a zero-day exploit") and m("ÁRBOL", "word", "el árbol cae")
    assert not m("Qilin", "word", "title ¦ in¦lin") and idash.norm("  A\tB \n C ") == "a b c"
    r = idash.Matcher([{"term": "a.b", "match_type": "exact", "is_exclusion": False}])
    assert r.matches("xa.by") and not r.matches("xaxby")                                     # user text is a literal, never a pattern
    assert idash.Matcher([{"term": ".*", "match_type": "word", "is_exclusion": False}]).matches("plain text") is False


def test_exclusions_case_and_multiple_terms_count_once(api):
    add_article("krebs", "Microsoft Exchange zero-day exploited", "Windows Server also hit by Microsoft bug", hours=5)           # three terms, one article
    add_article("talos", "Microsoft hiring podcast episode", "podcast about careers", hours=6)                                  # excluded
    add_article("talos", "MICROSOFT patches things", "", hours=7)
    fill_feed()
    d = mk(api, keywords=[kw("Microsoft", "Microsoft", "Windows Server", "Microsoft Exchange", exclude=["podcast"])])
    k = by_name(stats(api, d["id"]))["Microsoft"]
    assert k["article_count"] == 2                                                                                                # case-insensitive, exclusion applied, multi-term article counted once
    items = api.get(f"/api/v1/intelligence-dashboards/{d['id']}/keywords/{k['id']}/articles", params={"period": "7d"}).json()["items"]
    assert {i["title"] for i in items} == {"Microsoft Exchange zero-day exploited", "MICROSOFT patches things"}


def test_source_name_is_never_searched_and_cves_are(api):
    add_article("securityweek", "Something happened", "nothing", hours=4)                                                         # outlet name 'SecurityWeek' must not match a keyword 'securityweek'
    add_article("krebs", "Patch Tuesday roundup", "details", hours=4, cves=["CVE-2026-1234"])
    fill_feed()
    d = mk(api, keywords=[kw("Outlet", "SecurityWeek"), kw("CVE", "CVE"), kw("OneCVE", "CVE-2026-1234", mt="exact")])
    k = by_name(stats(api, d["id"]))
    assert k["Outlet"]["article_count"] == 0 and k["CVE"]["article_count"] == 1 and k["OneCVE"]["article_count"] == 1


def test_same_story_reposted_by_one_outlet_is_counted_once(api):
    add_article("krebs", "LockBit claims new victim", "x", hours=3)
    add_article("krebs", "  lockbit CLAIMS new   victim ", "x", hours=2)                                                       # re-post with a new guid/url
    add_article("securityweek", "LockBit claims new victim", "x", hours=3)                                                      # another outlet: a separate article
    fill_feed()
    d = mk(api, keywords=[kw("LockBit", "lockbit")])
    st = stats(api, d["id"])
    assert by_name(st)["LockBit"]["article_count"] == 2 and by_name(st)["LockBit"]["source_count"] == 2 and st["coverage"]["duplicates_collapsed"] == 1


# ---------------------------------------------------------------- 16-19 events, windows, global totals
def test_articles_events_sources_and_global_count_without_double_counting(api):
    for src, hrs in (("krebs", 3), ("securityweek", 4), ("thehackernews", 5)):                                                   # ten-style: several outlets, one event (shared CVE)
        add_article(src, f"Attackers exploit FortiGate flaw CVE-2026-7001 ({src})", "Ransomware gangs are using it", hours=hrs, cves=["CVE-2026-7001"])
    add_article("talos", "Qilin ransomware claims hospital attack", "", hours=6)
    add_article("therecord", "Microsoft patches exchange servers", "", hours=7)
    add_article("talos", "Ransomware crew abuses Microsoft tooling", "", hours=8)                                                 # in two pyramids
    fill_feed()
    d = mk(api, keywords=[kw("Ransomware", "ransomware"), kw("Microsoft", "microsoft"), kw("Qilin", "qilin")])
    st = stats(api, d["id"])
    k = by_name(st)
    assert k["Ransomware"]["article_count"] == 5 and k["Ransomware"]["source_count"] == 4
    assert k["Ransomware"]["unique_events"] < k["Ransomware"]["article_count"] and k["Ransomware"]["unique_events"] == 3          # CVE cluster + Qilin + Microsoft tooling
    assert k["Microsoft"]["article_count"] == 2 and k["Qilin"]["article_count"] == 1 and k["Qilin"]["latest_publication"]
    t = st["totals"]
    assert sum(x["article_count"] for x in st["keywords"]) == 8 and t["matching_articles"] == 6                                    # two articles sit in two pyramids but are counted once globally
    assert t["keywords_monitored"] == 3 and t["contributing_sources"] == 5 and t["unique_events"] <= t["matching_articles"]


def test_time_windows_use_publication_date_not_download_date(api):
    add_article("krebs", "Akira activity inside 24h", "", hours=5)
    add_article("krebs", "Akira activity two days ago", "", hours=40)
    add_article("krebs", "Akira activity last month", "", hours=24 * 20, collected_hours=1)                                     # old news, downloaded a minute ago: must NOT count as recent
    add_article("krebs", "Akira without a date", "", hours=1, published=False)                                                  # unknown date: excluded and reported
    fill_feed()
    d = mk(api, keywords=[kw("Akira", "akira")])
    c = lambda p: by_name(stats(api, d["id"], p))["Akira"]["article_count"]  # noqa: E731
    assert (c("24h"), c("48h"), c("7d"), c("30d")) == (1, 2, 2, 3)
    st = stats(api, d["id"], "30d")
    assert st["coverage"]["undated_excluded"] == 1 and any("without a valid publication date" in w for w in st["coverage"]["warnings"])
    assert st["window"]["timezone"] == "UTC" and st["window"]["label"] == "Last 30 Days" and st["window"]["start"] < st["window"]["end"]


def test_custom_ranges_are_whole_utc_days_and_validated(api):
    day = lambda h: (NOW - timedelta(hours=h)).date()  # noqa: E731
    add_article("krebs", "Qilin day A", "", hours=30)
    add_article("krebs", "Qilin day B", "", hours=100)
    fill_feed()
    d = mk(api, keywords=[kw("Qilin", "qilin")])
    one = stats(api, d["id"], "custom", start=day(30).isoformat(), end=day(30).isoformat())
    assert by_name(one)["Qilin"]["article_count"] == 1 and one["window"]["custom"] and one["window"]["start"].endswith("T00:00:00+00:00") and "UTC" in one["window"]["effective"]
    both = stats(api, d["id"], "custom", start=day(100).isoformat(), end=NOW.date().isoformat())
    assert by_name(both)["Qilin"]["article_count"] == 2
    base = f"/api/v1/intelligence-dashboards/{d['id']}/statistics"
    assert api.get(base, params={"period": "custom"}).status_code == 422
    assert api.get(base, params={"period": "custom", "start": "2026-02-01", "end": "2026-01-01"}).status_code == 422
    assert api.get(base, params={"period": "custom", "start": "2020-01-01", "end": "2026-01-01"}).status_code == 422
    assert api.get(base, params={"period": "custom", "start": "2999-01-01", "end": "2999-01-02"}).status_code == 422
    assert api.get(base, params={"period": "custom", "start": "not-a-date", "end": "2026-01-01"}).status_code == 422
    with db.connect() as con:                                                                                                    # changing the period never changes the saved default
        assert idash.get_dashboard(con, d["id"])["default_period"] == "7d"


# ---------------------------------------------------------------- 20 colour scale
def lv(counts, ok=True):
    return {k: v["key"] for k, v in idash.attention_levels(counts, ok).items()}


def test_attention_scale_rules_and_safeguards():
    assert lv({}) == {} and lv({"a": 0, "b": 0}) == {"a": "none", "b": "none"}                                                  # all zero: neutral, nothing coloured
    assert lv({"a": 1}) == {"a": "low"}                                                                                          # a single matching pyramid with one article is NOT red
    assert lv({"a": 1, "b": 0}) == {"a": "low", "b": "none"} and lv({"a": 2, "b": 2, "c": 2}) == {"a": "low", "b": "low", "c": "low"}
    assert lv({"a": 7}) == {"a": "moderate"} and lv({"a": 20}) == {"a": "high"} and lv({"a": 60}) == {"a": "very_high"}          # flat/single: absolute scale only
    assert lv({"a": 30, "b": 30}) == {"a": "very_high", "b": "very_high"}
    r = lv({"ransomware": 40, "lockbit": 12, "akira": 3, "qilin": 1})
    assert r == {"ransomware": "very_high", "lockbit": "moderate", "akira": "low", "qilin": "low"}
    assert lv({"a": 2, "b": 1}) == {"a": "low", "b": "low"}                                                                      # small samples never climb above the absolute caps
    big = lv({"a": 1000, "b": 30, "c": 12, "d": 3})                                                                             # extreme outlier: the others still spread
    assert big["a"] == "very_high" and big["b"] in ("moderate", "high") and big["c"] in ("low", "moderate") and big["d"] == "low"
    order = ["none", "low", "moderate", "high", "very_high"]
    seq = lv({str(i): i for i in range(0, 60, 4)})
    assert all(order.index(seq[str(a)]) <= order.index(seq[str(b)]) for a, b in zip(range(0, 56, 4), range(4, 60, 4)))        # monotonic: more articles never means a cooler colour
    assert lv({"a": 5, "b": 0}, ok=False) == {"a": "insufficient", "b": "insufficient"}
    assert lv({"a": 40, "b": 12}) == lv({"b": 12, "a": 40})                                                                      # deterministic
    assert idash.level("insufficient")["label"] == "Insufficient Feed Coverage" and idash.level("none")["label"] == "No Matches"


def test_levels_are_served_with_absolute_counts_and_a_legend(api):
    for i in range(14):
        add_article(SRC[i % 6], f"Ransomware report {i}", "", hours=2 + i)
    for i in range(3):
        add_article(SRC[i], f"LockBit post {i}", "", hours=2 + i)
    add_article("krebs", "Qilin post", "", hours=3)
    fill_feed()
    d = mk(api, keywords=[kw("Ransomware", "ransomware"), kw("LockBit", "lockbit"), kw("Qilin", "qilin"), kw("Akira", "akira")])
    st = stats(api, d["id"])
    k = by_name(st)
    assert (k["Ransomware"]["article_count"], k["LockBit"]["article_count"], k["Qilin"]["article_count"], k["Akira"]["article_count"]) == (14, 3, 1, 0)
    assert k["Akira"]["level"]["key"] == "none" and k["Qilin"]["level"]["key"] == "low" and k["Ransomware"]["level"]["key"] == "high"          # 14 articles: capped at High by the absolute gate
    assert k["LockBit"]["level"]["key"] in ("low", "moderate") and "not cybersecurity risk" in st["scale"]["legend"] and "relative news coverage" in st["scale"]["legend"]
    assert {l["key"] for l in st["scale"]["levels"]} == {"low", "moderate", "high", "very_high", "none", "insufficient"} and "percentile" in st["scale"]["method"]


# ---------------------------------------------------------------- 21-22 empty and insufficient coverage
def test_zero_matches_with_valid_coverage_is_a_plain_zero(api):
    fill_feed(14)
    d = mk(api, keywords=[kw("Nonexistent", "zzzzqqq")])
    st = stats(api, d["id"])
    assert st["coverage"]["status"] == "sufficient" and by_name(st)["Nonexistent"]["article_count"] == 0 and by_name(st)["Nonexistent"]["level"]["key"] == "none"
    assert api.get(f"/api/v1/intelligence-dashboards/{d['id']}/keywords/{st['keywords'][0]['id']}/articles").json()["items"] == []


def test_insufficient_feed_coverage_is_a_distinct_state(api):
    d = mk(api, keywords=[kw("Ransomware", "ransomware")])                                                                       # nothing recent in the feed: not "zero attacks"
    st = stats(api, d["id"])
    k = by_name(st)["Ransomware"]
    assert st["coverage"]["status"] == "insufficient" and k["level"]["key"] == "insufficient" and k["level"]["label"] == "Insufficient Feed Coverage" and k["article_count"] == 0
    fill_feed(12)
    add_article("krebs", "Ransomware gang hits hospital", "", hours=3)
    assert by_name(stats(api, d["id"]))["Ransomware"]["level"]["key"] == "low"
    with db.connect() as con:                                                                                                    # a window longer than the stored history is flagged
        con.execute("UPDATE news_item SET sort_ts=?,published=? WHERE summary='history marker'", (ISO(NOW - timedelta(days=12)), ISO(NOW - timedelta(days=12))))
    idash.invalidate()
    s90 = stats(api, d["id"], "90d")
    assert s90["coverage"]["status"] == "insufficient" and any("cover only" in w for w in s90["coverage"]["warnings"])
    with db.connect() as con:
        con.execute("UPDATE news_source SET last_success=NULL")
    idash.invalidate()
    assert stats(api, d["id"])["coverage"]["status"] == "insufficient" and any("No news synchronisation" in w for w in stats(api, d["id"])["coverage"]["warnings"])


def test_failed_sources_make_coverage_partial_with_a_warning(api):
    fill_feed(14)
    with db.connect() as con:
        con.execute("UPDATE news_source SET status='error', error='HTTP 403' WHERE id='cyberwire'")
    d = mk(api, keywords=[kw("X", "routine")])
    st = stats(api, d["id"])
    assert st["coverage"]["status"] == "partial" and any("failed" in w for w in st["coverage"]["warnings"]) and "not confirmed incidents" in st["coverage"]["note"]
    with db.connect() as con:                                                                                                    # disabled feeds are not failures
        con.execute("UPDATE news_source SET enabled=0 WHERE id='cyberwire'")
    idash.invalidate()
    assert stats(api, d["id"])["coverage"]["status"] == "sufficient"


# ---------------------------------------------------------------- 23-26 pyramid panel: selection, links, sorting, paging
def test_panel_lists_only_the_selected_pyramid_with_safe_original_links(api):
    add_article("krebs", "LockBit leak site returns", "excerpt about lockbit " + "y" * 400, hours=3, url="https://krebsonsecurity.com/2026/11/lockbit-returns/", cves=["CVE-2026-1111"])
    add_article("talos", "Akira targets VPN appliances", "", hours=4, url="https://blog.talosintelligence.com/akira-vpn")
    add_article("therecord", "LockBit affiliate arrested", "", hours=30, url="javascript:alert(1)")
    fill_feed()
    d = mk(api, keywords=[kw("LockBit", "lockbit"), kw("Akira", "akira")])
    st = stats(api, d["id"])
    lb = by_name(st)["LockBit"]["id"]
    r = api.get(f"/api/v1/intelligence-dashboards/{d['id']}/keywords/{lb}/articles", params={"period": "7d"}).json()
    assert r["total"] == 2 and [i["title"] for i in r["items"]] == ["LockBit leak site returns", "LockBit affiliate arrested"]       # newest first, only this keyword
    first, second = r["items"]
    assert first["url"] == "https://krebsonsecurity.com/2026/11/lockbit-returns/" and first["source"] and first["published"] and first["cves"] == ["CVE-2026-1111"] and len(first["excerpt"]) <= 301
    assert second["url"] is None                                                                                                     # an unsafe or missing link is never invented or repaired
    assert r["summary"]["article_count"] == 2 and r["summary"]["unique_events"] >= 1 and r["summary"]["source_count"] == 2 and r["keyword"]["display_name"] == "LockBit"
    assert "Akira" not in str(r["items"])
    assert api.get(f"/api/v1/intelligence-dashboards/{d['id']}/keywords/{lb}/articles", params={"period": "24h"}).json()["total"] == 1      # panel follows the period
    other = mk(api, "Other", keywords=[kw("Z", "zzz")])
    assert api.get(f"/api/v1/intelligence-dashboards/{other['id']}/keywords/{lb}/articles").status_code == 404                     # keyword ids are scoped to their dashboard


def test_panel_sorting_source_filter_event_filter_and_pagination(api):
    add_article("krebs", "Qilin A", "", hours=10, cves=["CVE-2026-5000"])
    add_article("securityweek", "Qilin A again CVE-2026-5000", "", hours=9, cves=["CVE-2026-5000"])
    for i in range(23):
        add_article(SRC[(i + 2) % 6], f"Qilin story {i:02d}", "", hours=11 + i)
    fill_feed()
    d = mk(api, keywords=[kw("Qilin", "qilin")])
    kid = by_name(stats(api, d["id"]))["Qilin"]["id"]
    url = f"/api/v1/intelligence-dashboards/{d['id']}/keywords/{kid}/articles"
    page1 = api.get(url, params={"page_size": 10}).json()
    assert page1["total"] == 25 and page1["pages"] == 3 and len(page1["items"]) == 10
    seen = [i["id"] for p in (1, 2, 3) for i in api.get(url, params={"page_size": 10, "page": p}).json()["items"]]
    assert len(seen) == 25 == len(set(seen))                                                                                      # pagination neither repeats nor drops
    old = api.get(url, params={"sort": "oldest", "page_size": 50}).json()["items"]
    new = api.get(url, params={"sort": "newest", "page_size": 50}).json()["items"]
    assert [i["id"] for i in old] == [i["id"] for i in reversed(new)]
    src = api.get(url, params={"sort": "source", "page_size": 50}).json()["items"]
    assert [i["source"].lower() for i in src] == sorted(i["source"].lower() for i in src)
    pr = api.get(url, params={"sort": "priority", "page_size": 50}).json()["items"]
    assert pr[0]["event"] and pr[0]["priority"] is not None and [i["priority"] for i in pr] == sorted((i["priority"] for i in pr), reverse=True)
    f = api.get(url, params={"source": "krebs", "page_size": 50}).json()
    assert f["total"] >= 1 and all(i["source_id"] == "krebs" for i in f["items"])
    cl = next(i for i in new if i["title"] == "Qilin A")
    ev = api.get(url, params={"event": cl["event"]["id"], "page_size": 50}).json()
    assert ev["total"] == 2 and {i["source_id"] for i in ev["items"]} == {"krebs", "securityweek"} and cl["event"]["articles"] >= 2           # grouped publications of one event
    assert api.get(url, params={"page_size": 51}).status_code == 422 and api.get(url, params={"sort": "bogus"}).status_code == 422 and api.get(url, params={"page": 0}).status_code == 422
    assert api.patch(f"/api/v1/intelligence-dashboards/{d['id']}/keywords/{kid}", json={"enabled": False}).status_code == 200
    assert api.get(url).status_code == 409


# ---------------------------------------------------------------- performance & caching
def test_statistics_use_one_consolidated_pass_and_a_cache_that_is_invalidated(api, monkeypatch):
    for i in range(60):
        add_article(SRC[i % 6], f"Story {i} about LockBit and Akira", "", hours=2 + i / 10)
    fill_feed()
    d = mk(api, keywords=[kw(f"K{i}", f"term{i}") for i in range(10)] + [kw("LockBit", "lockbit")])
    calls = []
    real = idash._window_articles
    monkeypatch.setattr(idash, "_window_articles", lambda *a, **k: (calls.append(1), real(*a, **k))[1])
    stats(api, d["id"])
    assert len(calls) == 1                                                                                                       # 11 keywords, a single article scan
    stats(api, d["id"])
    assert len(calls) == 1                                                                                                       # cached
    api.post(f"/api/v1/intelligence-dashboards/{d['id']}/keywords", json=kw("Akira", "akira"))
    assert by_name(stats(api, d["id"]))["Akira"]["article_count"] == 60 and len(calls) == 2                                      # keyword change invalidates
    stats(api, d["id"], "30d")
    assert len(calls) == 3                                                                                                       # period change invalidates
    add_article("krebs", "Fresh LockBit item", "", hours=0.5)
    assert by_name(stats(api, d["id"], "30d"))["LockBit"]["article_count"] == 61 and len(calls) == 4                             # new news invalidates


# ---------------------------------------------------------------- 28 the technology dashboard is untouched
def test_technology_dashboard_and_scores_are_independent_of_this_module(api):
    from app import scoring, service
    src = inspect.getsource(scoring) + inspect.getsource(service)
    assert "intel_dash" not in src and "intelligence_dashboard" not in src
    assert api.get("/api/technologies").status_code == 200 and "technologies" in api.get("/api/technologies").json() or isinstance(api.get("/api/technologies").json(), (list, dict))
    r = api.get("/api/technologies").json()
    items = r["technologies"] if isinstance(r, dict) else r
    assert {t["id"] for t in items} >= {"windows-server", "linux", "docker", "kubernetes", "vmware", "fortinet"}
    sig = inspect.getsource(idash)
    assert "epss" not in sig.lower().replace("never uses cvss / epss / kev", "") and "threat_signal" not in sig
    with db.connect() as con:
        before = [con.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0] for t in ("technology", "tech_cve", "nvd_cve", "news_item")]
    d = mk(api, keywords=[kw("Anything", "anything")])
    stats(api, d["id"])
    with db.connect() as con:
        assert before == [con.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0] for t in ("technology", "tech_cve", "nvd_cve", "news_item")]
