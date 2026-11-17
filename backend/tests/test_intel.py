import dataclasses
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app import briefing, db  # noqa: E402
from app.config import settings  # noqa: E402
from app.news import entities as ent, intel, repo  # noqa: E402
from app.news.sources import SOURCES  # noqa: E402

NOW = datetime(2026, 11, 16, 12, tzinfo=timezone.utc)


def mk(i, title, cves=(), hours_ago=2, source="bleepingcomputer", summary="", cats=("Vulnerabilities",), techs=()):
    ts = NOW - timedelta(hours=hours_ago)
    return {"id": f"id{i:04d}xxxxxxxxxxxxxxxx", "title": title, "summary": summary, "url": f"https://x.test/{i}", "source_id": source,
            "source_name": source, "source_type": "news", "published": ts.isoformat(), "collected_at": ts.isoformat(), "updated_at": None,
            "ts": ts, "categories": list(cats), "techs": [{"id": t, "basis": "name"} for t in techs], "cves": sorted(cves),
            "entities": ent.extract(title, summary), "tokens": intel.tokens(title), "topics": list(cats), "official": source in intel.OFFICIAL_SOURCES}


def ncl(items):
    return sorted(len(c["members"]) for c in intel.build_clusters(items))


# ---------------------------------------------------------------- clustering
def test_shared_cve_merges_across_sources_and_keeps_all_articles():
    a = mk(1, "Exploit seen for FortiGate flaw", ["CVE-2026-1001"], source="krebs")
    b = mk(2, "Hackers target Fortinet firewalls", ["CVE-2026-1001"], source="securityweek", hours_ago=5)
    cl = intel.build_clusters([a, b])
    assert len(cl) == 1 and cl[0]["article_count"] == 2 and len(cl[0]["source_ids"]) == 2


def test_same_vendor_alone_does_not_merge():
    a = mk(1, "Microsoft patches Outlook bug used by spies", ["CVE-2026-2001"])
    b = mk(2, "Microsoft fixes Teams bug leaking tokens", ["CVE-2026-2002"], source="krebs")
    c = mk(3, "Microsoft announces new Copilot security dashboard", source="darkreading")
    assert ncl([a, b, c]) == [1, 1, 1]


def test_same_ransomware_name_alone_does_not_merge():
    a = mk(1, "LockBit hits hospital network in Spain", cats=("Ransomware",))
    b = mk(2, "LockBit affiliate arrested after bank intrusion", cats=("Ransomware",), source="krebs")
    assert ncl([a, b]) == [1, 1]


def test_similar_titles_merge_and_disjoint_cves_block_it():
    a = mk(1, "Lego takes BrickLink marketplace offline after unusual activity", source="infosecurity")
    b = mk(2, "Lego marketplace BrickLink offline after unusual activity", source="theregister", hours_ago=3)
    assert ncl([a, b]) == [2]
    c = mk(3, "Critical remote code execution flaw in Acme Router firmware exploited", ["CVE-2026-3001"])
    d = mk(4, "Critical remote code execution flaw in Acme Router firmware exploited now", ["CVE-2026-3002"], source="krebs")
    assert ncl([c, d]) == [1, 1]


def test_different_advisory_ids_not_merged_and_time_window_respected():
    a = mk(1, "ZDI-26-923: Meta fairseq YAML File Parsing Code Injection Remote Code Execution")
    b = mk(2, "ZDI-26-931: Meta fairseq YAML File Parsing Code Injection Remote Code Execution", source="zdi")
    assert ncl([a, b]) == [1, 1]
    c = mk(3, "Lego takes BrickLink marketplace offline after unusual activity", hours_ago=1)
    d = mk(4, "Lego takes BrickLink marketplace offline after unusual activity", hours_ago=400, source="krebs")
    assert ncl([c, d]) == [1, 1]


def test_roundup_with_many_cves_does_not_chain_events():
    many = [f"CVE-2026-{5000 + i}" for i in range(8)]
    r = mk(1, "Patch Tuesday roundup", many, source="krebs")
    a = mk(2, "Attackers exploit Exchange bug", ["CVE-2026-5001"], source="securityweek")
    b = mk(3, "Windows zero-day under attack", ["CVE-2026-5002"], source="darkreading")
    assert ncl([r, a, b]) == [1, 1, 1]


def test_cluster_ids_are_stable_and_ordering_deterministic():
    items = [mk(1, "Exploit seen for FortiGate flaw", ["CVE-2026-1001"]), mk(2, "Hackers target Fortinet firewalls", ["CVE-2026-1001"], source="krebs", hours_ago=4)]
    a = intel.build_clusters(items)[0]["id"]
    assert a == intel.build_clusters(list(reversed(items)))[0]["id"] and a.startswith("evt_")


# ---------------------------------------------------------------- priority
def _prio(items, sigs=None, now=NOW):
    return intel.priority(intel.build_clusters(items)[0], sigs or {}, now)


def test_priority_components_sum_and_are_explained():
    p = _prio([mk(1, "FortiGate flaw exploited", ["CVE-2026-1001"], techs=["fortinet"])],
              {"CVE-2026-1001": {"kev": {"x": 1}, "epss": 0.9, "cvss": 9.8}})
    assert abs(sum(c["points"] for c in p["components"]) - p["score"]) < 0.3
    assert {c["key"] for c in p["components"]} == {"recency", "cves", "official", "tech", "breadth"} and p["note"]
    assert all(c["detail"] for c in p["components"]) and 0 <= p["score"] <= 100


def test_kev_beats_no_signal_and_volume_alone_does_not_win():
    kev = _prio([mk(1, "Exploited flaw in Acme gateway", ["CVE-2026-9001"])], {"CVE-2026-9001": {"kev": {"x": 1}, "epss": None, "cvss": None}})
    plain = _prio([mk(1, "Exploited flaw in Acme gateway", ["CVE-2026-9001"])], {"CVE-2026-9001": {"kev": None, "epss": None, "cvss": None}})
    srcs = ["krebs", "securityweek", "darkreading", "theregister", "infosecurity", "csoonline", "helpnetsecurity"]
    vol = _prio([mk(i, "Lego marketplace BrickLink offline after unusual activity", source=s) for i, s in enumerate(srcs)])
    assert kev["score"] > plain["score"] and kev["score"] > vol["score"]
    assert "missing" in kev["components"][1]["detail"]


def test_priority_decays_with_age_and_is_configurable():
    def it(h):
        return [mk(1, "Some story about bugs", ["CVE-2026-1"], hours_ago=h)]
    assert _prio(it(2))["score"] > _prio(it(120))["score"]
    cl = intel.build_clusters(it(2))[0]
    off = intel.priority(cl, {}, NOW, dataclasses.replace(intel.PRIORITY, w_recency=0.0))
    assert off["score"] < _prio(it(2))["score"]


def test_official_and_monitored_tech_add_points():
    base = _prio([mk(1, "Some post", source="krebs")])["score"]
    assert _prio([mk(1, "Some post", source="talos")])["score"] > base
    assert _prio([mk(1, "Some post", source="krebs", techs=["vmware"])])["score"] > base


# ---------------------------------------------------------------- entities / MITRE
def test_mitre_only_explicit_valid_ids():
    r = ent.extract("Attackers use T1059.001 PowerShell and T1566", "Also mentions T9999 and T1")
    assert {t["id"] for t in r["mitre"]} == {"T1059.001", "T1566"} and all(t["origin"].startswith("explicit id in") for t in r["mitre"])
    assert ent.extract("Generic phishing and powershell abuse", "credential theft campaign")["mitre"] == []
    assert ent.mitre_catalog()["techniques"]["T1059"]["n"] == "Command and Scripting Interpreter"
    assert ent.mitre_url("T1059.001").endswith("/techniques/T1059/001/")


def test_entities_malware_ransomware_and_ambiguous_names():
    r = ent.extract("New Qilin ransomware attack hits firm", "Operators used Cobalt Strike and SocGholish")
    assert "Qilin" in r["ransomware"] and "Cobalt Strike" in r["malware"] and "SocGholish" in r["malware"]
    assert ent.extract("We play with Medusa and Royal families", "")["ransomware"] == []
    assert "Medusa" in ent.extract("Medusa ransomware gang claims attack", "")["ransomware"]
    assert "APT29" not in str(ent.extract("APT29 targets embassies", ""))  # threat actors are never extracted


# ---------------------------------------------------------------- corpus-level
def corpus_from(items, signals=None):
    return intel.Corpus(items, intel.build_clusters(items), signals or {}, NOW)


def test_trending_counts_unique_events_and_hides_trend_without_history():
    items = [mk(i, "Lego marketplace BrickLink offline after unusual activity", source=s, cats=("Data Breaches",))
             for i, s in enumerate(["krebs", "securityweek", "darkreading"])]
    items.append(mk(9, "Ransom gang strikes", cats=("Ransomware",), hours_ago=3))
    t = intel.trending(corpus_from(items), "24h")
    row = {r["topic"]: r for r in t["topics"]}
    assert row["Data Breaches"]["articles"] == 3 and row["Data Breaches"]["events"] == 1
    assert t["history_sufficient"] is False and row["Data Breaches"]["change_pct"] is None and t["note"]


def test_trending_shows_change_with_enough_history():
    items = [mk(i, f"Different story number {i} alpha{i} beta{i} gamma{i}", cats=("Malware",), hours_ago=30 + i) for i in range(30)]
    items += [mk(100 + i, f"Another unrelated headline {i} delta{i} omega{i} sigma{i}", cats=("Malware",), hours_ago=2 + i) for i in range(12)]
    items += [mk(300, "Oldest marker", hours_ago=47)]
    t = intel.trending(corpus_from(items), "24h")
    m = next(r for r in t["topics"] if r["topic"] == "Malware")
    assert t["history_sufficient"] and m["change_pct"] is not None and m["trend"] in ("up", "down", "flat")


def test_search_filters_combine_and_paginate():
    items = [mk(1, "Qilin ransomware hits Fortinet customers", ["CVE-2026-1001"], cats=("Ransomware",), techs=["fortinet"]),
             mk(2, "Emotet returns with new loader", cats=("Malware",), source="krebs"),
             mk(3, "FortiOS bug T1190 exploited", ["CVE-2026-1002"], source="talos")]
    c = corpus_from(items)
    assert intel.search(c, ransomware="Qilin")["total"] == 1
    assert intel.search(c, malware="Emotet", source="krebs")["total"] == 1
    assert intel.search(c, malware="Emotet", source="talos")["total"] == 0
    assert intel.search(c, vendor="Fortinet")["total"] == 2 and intel.search(c, vendor="Fortinet", cve="CVE-2026-1002")["total"] == 1
    assert intel.search(c, mitre="T1190")["items"][0]["mitre"][0]["id"] == "T1190"
    assert intel.search(c, tech="fortinet", category="Ransomware")["total"] == 1
    assert intel.search(c, page_size=2)["pages"] == 2 and intel.search(c, q="emotet")["total"] == 1


def test_cluster_listing_filters_and_sort():
    items = [mk(1, "Exploit seen for FortiGate flaw", ["CVE-2026-1001"], techs=["fortinet"]),
             mk(2, "Hackers target Fortinet firewalls", ["CVE-2026-1001"], source="krebs"),
             mk(3, "Unrelated story about cloud misconfig", cats=("Cloud Security",), source="darkreading")]
    c = corpus_from(items)
    assert intel.list_clusters(c, period="all", min_sources=2)["total"] == 1
    assert intel.list_clusters(c, period="all", tech="fortinet")["items"][0]["article_count"] == 2
    assert intel.list_clusters(c, period="all", category="Cloud Security")["total"] == 1
    assert intel.list_clusters(c, period="all", sort="size")["items"][0]["article_count"] == 2


def test_coverage_distinguishes_articles_from_publishers_and_timeline_order():
    items = [mk(1, "Exploit seen for FortiGate flaw", ["CVE-2026-1001"], source="krebs", hours_ago=10),
             mk(2, "Exploit seen for FortiGate flaw again", ["CVE-2026-1001", "CVE-2026-1002"], source="krebs", hours_ago=5),
             mk(3, "Hackers target Fortinet firewalls", ["CVE-2026-1001"], source="securityweek", hours_ago=1)]
    cl = intel.build_clusters(items)[0]
    cov = intel.coverage(cl)
    assert cov["articles"] == 3 and cov["publishers"] == 2 and cov["first_source"]["name"] == "krebs" and cov["last_source"]["name"] == "securityweek"
    assert "independent" in cov["note"]
    tl = intel.timeline(cl)["entries"]
    assert [e["at"] for e in tl] == sorted(e["at"] for e in tl) and tl[0]["is_first"] and tl[0]["date_basis"] == "published"
    assert any("CVE-2026-1002" in " ".join(e["new_information"]) for e in tl)


def test_observatory_counts_unique_events_not_articles():
    items = [mk(i, "Exploit seen for FortiGate flaw", ["CVE-2026-1001"], source=s, techs=["fortinet"]) for i, s in enumerate(["krebs", "securityweek"])]
    o = intel.observatory(corpus_from(items), "7d")
    f = next(r for r in o["vendors"] if r["name"] == "Fortinet")
    assert f["events"] == 1 and f["articles"] == 2 and "not a measure of risk" in o["note"]
    assert o["technologies"][0]["id"] == "fortinet"


# ---------------------------------------------------------------- briefing (service + persistence)
@pytest.fixture()
def bdb(tmp_path):
    object.__setattr__(settings, "db_path", str(tmp_path / "t.sqlite"))
    intel.reset_cache()
    db.init_db()
    now = datetime.now(timezone.utc)
    with db.connect() as con:
        repo.sync_source_rows(con)
        for s in SOURCES:
            con.execute("UPDATE news_source SET status='ok', last_success=? WHERE id=?", (now.isoformat(timespec="seconds"), s.id))
        con.execute("UPDATE news_source SET status='error', error='HTTP 403' WHERE id='cyberwire'")
        rows = [("thehackernews", "Attackers exploit FortiGate flaw CVE-2026-7001 in the wild", ["CVE-2026-7001"], "Vulnerabilities"),
                ("securityweek", "FortiGate flaw CVE-2026-7001 exploited by attackers", ["CVE-2026-7001"], "Vulnerabilities"),
                ("krebs", "Qilin ransomware gang claims hospital attack", [], "Ransomware"),
                ("talos", "Cloud misconfiguration exposes storage buckets", [], "Cloud Security")]
        for n, (src, title, cves, cat) in enumerate(rows, 1):
            nid = f"{n:02d}" + "a" * 22
            ts = (now - timedelta(hours=n)).isoformat(timespec="seconds")
            con.execute("INSERT INTO news_item(id,source_id,guid,url,url_canon,title,summary,published,collected_at,content_hash,sort_ts) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                        (nid, src, f"g{n}", f"https://x.test/{n}", f"https://x.test/{n}", title, "excerpt", ts, ts, "h", ts))
            con.execute("INSERT INTO news_cat VALUES(?,?)", (nid, cat))
            for c in cves:
                con.execute("INSERT INTO news_cve VALUES(?,?)", (nid, c))
                con.execute("INSERT INTO news_tech VALUES(?,?,?)", (nid, "fortinet", "name"))
        con.execute("INSERT INTO kev_entry(cve_id,vendor,product,name,date_added,ransomware) VALUES('CVE-2026-7001','Fortinet','FortiOS','x','2026-11-16',1)")
        con.execute("INSERT INTO source_status(source,last_attempt,last_success,ok) VALUES('kev',?,?,1)", (now.isoformat(), now.isoformat()))
    yield
    intel.reset_cache()


def test_briefing_structure_and_contract(bdb):
    b = briefing.generate(24, enrich_epss=False)
    assert b["schema_version"] == 1 and b["title"] == "MORNING CYBER BRIEFING" and b["period"]["hours"] == 24
    assert [s["id"] for s in b["sections"]] == ["executive_summary", "top_stories", "vulnerability_watch", "threat_landscape", "technology_watchlist", "sources_quality"]
    top = b["sections"][1]["items"]
    assert top[0]["cves"] == ["CVE-2026-7001"] and top[0]["publishers"] == 2 and top[0]["priority"]["why"]
    w = b["sections"][2]["items"][0]
    assert w["cve"] == "CVE-2026-7001" and w["in_kev"] and w["cvss"] is None and "cvss" in w["unavailable"]  # never invented
    themes = {t["theme"]: t for t in b["sections"][3]["themes"]}
    assert themes["Ransomware"]["events"] == 1 and "Qilin" in [f["name"] for f in themes["Ransomware"]["named_families"]]
    assert [t["name"] for t in b["sections"][4]["items"]] == ["Fortinet"]  # only technologies with events
    q = b["sections"][5]
    assert q["failed_sources"][0]["id"] == "cyberwire" and b["coverage"]["status"] in {"partial", "insufficient"} and b["coverage"]["warnings"]
    assert all(u.startswith("http") for u in b["references"])


def test_briefing_persistence_dedup_and_listing(bdb):
    a = briefing.generate(24, enrich_epss=False)
    again = briefing.generate(24, enrich_epss=False)
    assert again["reused"] and again["id"] == a["id"]
    forced = briefing.generate(24, force=True, enrich_epss=False)
    assert forced["id"] != a["id"]
    assert briefing.get(a["id"])["data_hash"] == a["data_hash"] and len(briefing.list_recent()) == 2
    assert briefing.generate(168, enrich_epss=False)["id"] != a["id"]
    md = briefing.to_markdown(a)
    assert "MORNING CYBER BRIEFING" in md and "CVE-2026-7001" in md and "IN CISA KEV" in md


def test_briefing_does_not_touch_pyramid_tables(bdb):
    def counts():
        with db.connect() as con:
            return [con.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0] for t in ("nvd_cve", "epss", "tech_cve")]
    before = counts()
    briefing.generate(24, force=True, enrich_epss=False)
    assert before == counts()


# ---------------------------------------------------------------- professional briefing: links, cover, references, safety
def _add_item(src, title, url, n, cves=(), cat="Malware", hours=2):
    now = datetime.now(timezone.utc)
    ts = (now - timedelta(hours=hours)).isoformat(timespec="seconds")
    nid = f"{n:02d}" + "a" * 22
    with db.connect() as con:
        con.execute("INSERT INTO news_item(id,source_id,guid,url,url_canon,title,summary,published,collected_at,content_hash,sort_ts) VALUES(?,?,?,?,?,?,?,?,?,?,?)", (nid, src, f"g{n}", url, url, title, "excerpt", ts, ts, "h", ts))
        con.execute("INSERT INTO news_cat VALUES(?,?)", (nid, cat))
        for c in cves:
            con.execute("INSERT INTO news_cve VALUES(?,?)", (nid, c))
    intel.reset_cache()


def test_safe_url_accepts_only_plain_http_and_https():
    ok = ["https://x.test/a?b=1#c", "http://x.test/a"]
    bad = ["javascript:alert(1)", "data:text/html,x", "//x.test/a", "ftp://x.test", "https://u:p@x.test", 'https://x.test/"x', "https://x.test/a b", "https://x.test/<s>", "", None, 5, "https://" + "a" * 2100]
    assert all(briefing.safe_url(u) == u for u in ok) and all(briefing.safe_url(u) is None for u in bad)


def test_story_sources_are_original_article_links_and_unsafe_ones_are_dropped(bdb):
    _add_item("bleepingcomputer", "Ghost malware campaign hits banks", "javascript:alert(1)", 20)
    _add_item("securityweek", "Ghost malware campaign hits banks again", "https://x.test/ghost-2", 21)
    b = briefing.generate(24, force=True, enrich_epss=False)
    forti = next(i for i in b["sections"][1]["items"] if "CVE-2026-7001" in i["cves"])
    assert {s["url"] for s in forti["sources"]} == {"https://x.test/1", "https://x.test/2"} and len(forti["sources"]) == forti["publishers"]
    assert all(s["kind"] in ("news", "advisory") and s["name"] for s in forti["sources"])
    assert "javascript:" not in json.dumps(b) and all(u.startswith(("http://", "https://")) for u in b["references"])


def test_vulnerability_references_are_typed_and_official_advisories_are_only_real_ones(bdb):
    _add_item("cisa-alerts", "CISA adds FortiGate flaw CVE-2026-7001 to catalog", "https://www.cisa.gov/news-events/alerts/2026/11/16/cisa-adds-fortigate", 22, cves=["CVE-2026-7001"], cat="Vulnerabilities")
    b = briefing.generate(24, force=True, enrich_epss=False)
    w = b["sections"][2]["items"][0]
    assert {"nvd", "epss", "kev"} <= {r["kind"] for r in w["references"]}
    adv = [r for r in w["references"] if r["kind"] == "advisory"]
    assert adv and adv[0]["url"].startswith("https://www.cisa.gov/") and adv[0]["label"]
    assert next(r for r in w["references"] if r["kind"] == "nvd")["url"] == "https://nvd.nist.gov/vuln/detail/CVE-2026-7001"


def test_no_advisory_is_invented_when_no_official_feed_covers_the_cve(bdb):
    b = briefing.generate(24, force=True, enrich_epss=False)
    assert all(r["kind"] != "advisory" for r in b["sections"][2]["items"][0]["references"])


def test_cover_executive_blocks_and_methodology(bdb):
    b = briefing.generate(24, force=True, enrich_epss=False)
    c = b["cover"]
    assert (c["title"], c["subtitle"]) == ("CYBER RISK PYRAMID", "MORNING CYBER BRIEFING") and c["unique_events"] == b["coverage"]["events"] and c["contributing_sources"] == b["coverage"]["sources_contributing"]
    assert c["cves_identified"] == 1 and c["cves_in_kev"] == 1 and c["coverage_status"] == b["coverage"]["status"] and c["note"] == "Open-source cybersecurity intelligence compiled from verified data sources."
    blocks = {k["id"]: k for k in b["sections"][0]["blocks"]}
    assert {"overview", "key_events", "vulnerabilities", "technologies", "coverage"} <= set(blocks) and b["sections"][0]["bullets"]
    assert "not confirmed incidents" in blocks["overview"]["text"] and "do not show exposure" in blocks["technologies"]["text"] and "known exploitation, not necessarily recent" in blocks["vulnerabilities"]["text"]
    assert not any(w in json.dumps(blocks).lower() for w in ("attack surge", "increase in attacks", "you should", "we recommend"))
    m = b["sections"][5]["methodology"]
    assert any("deterministic" in x for x in m) and any("not a measure of business risk" in x for x in m) and any("exposed or vulnerable" in x for x in m) and any("not necessarily recent" in x for x in m)


def test_bibliography_is_deduplicated_ordered_and_traceable(bdb):
    b = briefing.generate(24, force=True, enrich_epss=False)
    bib = b["bibliography"]
    assert len({e["url"] for e in bib}) == len(bib) and [e["id"] for e in bib] == [f"R{i}" for i in range(1, len(bib) + 1)]
    assert [e["kind"] for e in bib] == sorted((e["kind"] for e in bib), key=lambda k: briefing.KIND_ORDER[k])
    hn = next(e for e in bib if e["url"] == "https://x.test/1")
    krebs = next(e for e in bib if e["url"] == "https://x.test/3")
    assert any(s.startswith("Story ") for s in hn["supports"]) and any(s.startswith("Watchlist") for s in hn["supports"]) and "Landscape: Ransomware" in krebs["supports"]
    assert any(e["kind"] == "nvd" and e["supports"] == ["CVE-2026-7001"] for e in bib) and b["references"] == [e["url"] for e in bib]
    assert "## Sources & References" in briefing.to_markdown(b)


def test_landscape_and_watchlist_carry_their_supporting_links_and_separate_signals(bdb):
    b = briefing.generate(24, force=True, enrich_epss=False)
    th = {t["theme"]: t for t in b["sections"][3]["themes"]}
    assert th["Ransomware"]["items"][0]["sources"][0]["url"] == "https://x.test/3"
    t = b["sections"][4]["items"][0]
    assert t["news"] and all(n["url"].startswith("https://") for n in t["news"]) and t["cves"][0]["url"] == "https://nvd.nist.gov/vuln/detail/CVE-2026-7001"
    assert set(t["signals"]) == {"media_attention", "threat_signal", "vulnerability_applicability"} and "not confirmed" in t["signals"]["vulnerability_applicability"]


@pytest.mark.parametrize("hours", [24, 48, 168])
def test_all_three_periods_use_the_same_structure(bdb, hours):
    b = briefing.generate(hours, force=True, enrich_epss=False)
    assert b["format"] == briefing.FORMAT and b["cover"]["period_label"] == b["period"]["label"] and b["bibliography"] and b["sections"][0]["blocks"]
    assert [s["id"] for s in b["sections"]] == ["executive_summary", "top_stories", "vulnerability_watch", "threat_landscape", "technology_watchlist", "sources_quality"]
    assert briefing.get(b["id"])["cover"]["unique_events"] == b["cover"]["unique_events"]


def test_previously_stored_briefings_still_load_and_are_not_reused_as_new_format(bdb):
    old = briefing.generate(24, force=True, enrich_epss=False)
    legacy = {k: v for k, v in old.items() if k not in ("cover", "bibliography", "format", "reused")}
    legacy["sections"] = [{k: v for k, v in s.items() if k not in ("blocks", "methodology")} for s in legacy["sections"]]
    with db.connect() as con:
        con.execute("UPDATE briefing SET content=?, data_hash='legacy-hash' WHERE id=?", (json.dumps(legacy), old["id"]))
    loaded = briefing.get(old["id"])
    assert loaded and "cover" not in loaded and "MORNING CYBER BRIEFING" in briefing.to_markdown(loaded)
    fresh = briefing.generate(24, enrich_epss=False)
    assert fresh["id"] != old["id"] and fresh["format"] == briefing.FORMAT and not fresh["reused"]


def test_briefing_without_news_has_no_references_and_invents_none(tmp_path):
    object.__setattr__(settings, "db_path", str(tmp_path / "e.sqlite"))
    intel.reset_cache()
    db.init_db()
    b = briefing.generate(24, enrich_epss=False)
    assert b["bibliography"] == [] and b["references"] == [] and b["cover"]["unique_events"] == 0 and b["cover"]["cves_identified"] == 0
    assert b["sections"][0]["blocks"][0]["id"] == "overview" and "No CVE identifiers were cited" in json.dumps(b["sections"][0]["blocks"])
    intel.reset_cache()


def test_disabled_sources_are_not_counted_as_failed_in_the_new_report(bdb):
    with db.connect() as con:
        con.execute("UPDATE news_source SET enabled=0, status='error', error='x' WHERE id='talos'")
    b = briefing.generate(24, force=True, enrich_epss=False)
    assert "talos" not in [f["id"] for f in b["sections"][5]["failed_sources"]] and b["coverage"]["sources_disabled"] >= 1
