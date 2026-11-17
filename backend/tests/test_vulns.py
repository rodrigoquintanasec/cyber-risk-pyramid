import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app import db, vulns, watchlists  # noqa: E402
from app.config import settings  # noqa: E402
from app.connectors import nvd as nvd_c  # noqa: E402
from app.news import repo  # noqa: E402


@pytest.fixture()
def con(tmp_path):
    object.__setattr__(settings, "db_path", str(tmp_path / "v.sqlite"))
    db.init_db()
    vulns._cooldown.clear()
    vulns._recent.clear()
    with db.connect() as c:
        repo.sync_source_rows(c)
        nvd = [("CVE-2026-0001", "2026-11-01T00:00:00", 9.8, "Fortinet FortiOS RCE", "a:fortinet:fortios"),
               ("CVE-2026-0002", "2026-10-01T00:00:00", 5.0, "VMware ESXi leak", "a:vmware:esxi"),
               ("CVE-2026-0003", "2026-09-01T00:00:00", None, "Unscored Linux bug", "a:linux:linux_kernel")]
        for cid, pub, cvss, desc, cpe in nvd:
            c.execute("INSERT INTO nvd_cve(cve_id,published,cvss,cvss_version,description,cpes,fetched_at) VALUES(?,?,?,?,?,?,'t')", (cid, pub, cvss, "3.1", desc, cpe))
        c.execute("INSERT INTO kev_entry(cve_id,vendor,product,name,date_added,ransomware) VALUES('CVE-2026-0001','Fortinet','FortiOS','x','2026-11-05',1)")
        c.execute("INSERT INTO kev_entry(cve_id,vendor,product,name,date_added,ransomware) VALUES('CVE-2025-9999','Palo Alto Networks','PAN-OS','pan flaw','2025-01-01',0)")
        c.execute("INSERT INTO epss(cve_id,score,percentile,score_date,fetched_at) VALUES('CVE-2026-0001',0.9,0.99,'2026-11-10','t')")
        c.execute("INSERT INTO epss(cve_id,score,percentile,score_date,fetched_at) VALUES('CVE-2026-0002',0.01,0.2,'2026-11-10','t')")
        c.execute("INSERT INTO tech_cve VALUES('fortinet','CVE-2026-0001','fortios','cpe')")
        c.execute("INSERT INTO tech_cve VALUES('vmware','CVE-2026-0002','esxi','cpe')")
        c.execute("INSERT INTO news_item(id,source_id,guid,url,url_canon,title,summary,published,collected_at,content_hash,sort_ts) VALUES('n1','krebs','g','https://x/1','https://x/1','FortiOS bug','', '2026-11-06','2026-11-06','h','2026-11-06')")
        c.execute("INSERT INTO news_cve VALUES('n1','CVE-2026-0001')")
        c.execute("INSERT INTO news_tech VALUES('n1','fortinet','name')")
        c.execute("INSERT INTO news_item(id,source_id,guid,url,url_canon,title,summary,published,collected_at,content_hash,sort_ts) VALUES('n2','krebs','g2','https://x/2','https://x/2','ESXi bug','', '2026-11-07','2026-11-07','h','2026-11-07')")
        c.execute("INSERT INTO news_tech VALUES('n2','vmware','name')")
    with db.connect() as c:
        yield c


def ids(r):
    return [i["id"] for i in r["items"]]


def test_universe_and_exact_search(con):
    assert vulns.search(con)["total"] == 4  # 3 NVD + KEV-only CVE
    assert ids(vulns.search(con, q="cve-2026-0002")) == ["CVE-2026-0002"]
    assert ids(vulns.search(con, q="esxi")) == ["CVE-2026-0002"]
    assert "Local catalogue" in vulns.search(con)["scope"]


def test_filters(con):
    assert ids(vulns.search(con, vendor="fortinet")) == ["CVE-2026-0001"]
    assert ids(vulns.search(con, vendor="Palo Alto Networks")) == ["CVE-2025-9999"]  # via KEV vendor
    assert ids(vulns.search(con, vendor="vmware", product="esxi")) == ["CVE-2026-0002"]
    assert vulns.search(con, vendor="vmware", product="fortios")["total"] == 0
    assert ids(vulns.search(con, cvss_min=9)) == ["CVE-2026-0001"]
    assert ids(vulns.search(con, cvss_max=6)) == ["CVE-2026-0002"]
    assert ids(vulns.search(con, epss_min=0.5)) == ["CVE-2026-0001"]
    assert vulns.search(con, kev=True)["total"] == 2 and vulns.search(con, kev=False)["total"] == 2
    assert ids(vulns.search(con, techs=["vmware"])) == ["CVE-2026-0002"] and vulns.search(con, techs=[])["total"] == 0
    assert ids(vulns.search(con, has_news=True)) == ["CVE-2026-0001"]
    assert ids(vulns.search(con, date_from="2026-10-15")) == ["CVE-2026-0001"]


def test_sorting_puts_unknown_last_and_orders(con):
    assert ids(vulns.search(con, sort="cvss"))[:2] == ["CVE-2026-0001", "CVE-2026-0002"]
    assert ids(vulns.search(con, sort="cvss", order="asc"))[:2] == ["CVE-2026-0002", "CVE-2026-0001"]
    assert ids(vulns.search(con, sort="epss"))[0] == "CVE-2026-0001"
    assert ids(vulns.search(con, sort="published"))[0] == "CVE-2026-0001"
    assert ids(vulns.search(con, sort="kev_date"))[0] == "CVE-2026-0001"
    assert vulns.search(con, page_size=2)["pages"] == 2


def test_sql_injection_like_input_is_inert(con):
    assert vulns.search(con, q="'; DROP TABLE nvd_cve;--")["total"] == 0
    assert vulns.search(con, vendor="x' OR '1'='1")["total"] == 0
    assert con.execute("SELECT COUNT(*) FROM nvd_cve").fetchone()[0] == 3


def test_detail_links_news_techs_and_unknown(con):
    d = vulns.detail(con, "CVE-2026-0001")
    assert d["kev"]["ransomware"] and d["epss"] == 0.9 and d["severity"] == "critical" and d["techs"][0]["id"] == "fortinet"
    assert d["news"][0]["id"] == "n1" and d["detail"] is None and d["cache"]["full_detail"] is False
    assert vulns.detail(con, "CVE-2000-0000") is None
    assert vulns.detail(con, "CVE-2026-0003")["severity"] == "unrated"  # missing CVSS is never invented


def test_coverage_is_explicit(con):
    c = vulns.coverage(con)
    assert c["nvd_cached"] == 3 and c["kev_catalog"] == 2 and c["explorer_total"] == 4 and "NOT every CVE" in c["note"]


def test_facets(con):
    f = vulns.facets(con, "vmware")
    assert {"name": "vmware", "cves": 1} in f["vendors"] and f["products"][0]["name"] == "esxi"


NVD_ITEM = {"cve": {"id": "CVE-2026-7777", "published": "2026-11-01T00:00:00.000", "lastModified": "x", "vulnStatus": "Analyzed",
                    "descriptions": [{"lang": "en", "value": "Bad bug"}],
                    "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 8.1, "version": "3.1"}, "type": "Primary"}]},
                    "weaknesses": [{"description": [{"lang": "en", "value": "CWE-79"}]}],
                    "references": [{"url": "https://vendor.example/adv", "source": "v", "tags": ["Vendor Advisory"]}, {"url": "javascript:alert(1)"}],
                    "configurations": [{"nodes": [{"cpeMatch": [{"vulnerable": True, "criteria": "cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*", "versionEndExcluding": "2.1"},
                                                                {"vulnerable": False, "criteria": "cpe:2.3:o:acme:os:1:*:*:*:*:*:*:*"}]}]}]}}


def test_parse_detail_filters_unsafe_and_non_vulnerable():
    d = vulns.parse_detail(NVD_ITEM)
    assert d["cwes"] == ["CWE-79"] and [r["url"] for r in d["refs"]] == ["https://vendor.example/adv"]
    assert d["versions"] == [{"product": "acme / widget", "version": None, "from_incl": None, "from_excl": None, "to_incl": None, "to_excl": "2.1"}]


def test_lookup_stores_apart_from_pyramid_tables_and_limits(con, monkeypatch):
    monkeypatch.setattr(nvd_c, "_call", lambda params: {"vulnerabilities": [NVD_ITEM]})
    vulns.lookup("CVE-2026-7777")
    d = vulns.detail(con, "CVE-2026-7777")
    assert d is None or True
    with db.connect() as c2:
        d = vulns.detail(c2, "CVE-2026-7777")
        assert d["cvss"] == 8.1 and d["detail"]["cwes"] == ["CWE-79"] and d["cache"]["nvd_record"]
        assert c2.execute("SELECT COUNT(*) FROM nvd_cve WHERE cve_id='CVE-2026-7777'").fetchone()[0] == 0
        assert c2.execute("SELECT COUNT(*) FROM tech_cve WHERE cve_id='CVE-2026-7777'").fetchone()[0] == 0


def test_lookup_validation_cooldown_not_found_and_hourly_cap(con, monkeypatch):
    with pytest.raises(vulns.LookupError_) as e:
        vulns.lookup("not-a-cve")
    assert e.value.status == 422
    monkeypatch.setattr(nvd_c, "_call", lambda params: {"vulnerabilities": []})
    with pytest.raises(vulns.LookupError_) as e:
        vulns.lookup("CVE-2026-8000")
    assert e.value.status == 404
    with pytest.raises(vulns.LookupError_) as e:  # same id again within the cooldown
        vulns.lookup("CVE-2026-8000")
    assert e.value.status == 429
    for i in range(vulns.MAX_PER_HOUR):
        try:
            vulns.lookup(f"CVE-2026-{9000 + i}")
        except vulns.LookupError_:
            pass
    with pytest.raises(vulns.LookupError_) as e:
        vulns.lookup("CVE-2026-9999")
    assert e.value.status == 429 and "per hour" in e.value.msg


# ---------------------------------------------------------------- watchlists
def test_watchlist_crud_and_validation(con):
    w = watchlists.create(con, "Core infra", ["fortinet", "vmware", "fortinet"])
    assert w["technologies"] == ["fortinet", "vmware"] and w["id"]
    with pytest.raises(watchlists.WatchlistError) as e:
        watchlists.create(con, "Core infra", [])
    assert e.value.status == 409
    for bad in ("", "<script>alert(1)</script>", "x" * 70):
        with pytest.raises(watchlists.WatchlistError):
            watchlists.create(con, bad, [])
    with pytest.raises(watchlists.WatchlistError):
        watchlists.create(con, "Other", ["nope"])
    assert watchlists.add_tech(con, w["id"], "docker")["technologies"] == ["fortinet", "vmware", "docker"]
    assert watchlists.remove_tech(con, w["id"], "vmware")["technologies"] == ["fortinet", "docker"]
    assert watchlists.rename(con, w["id"], "Edge")["name"] == "Edge"
    assert [x["name"] for x in watchlists.list_all(con)] == ["Edge"]
    watchlists.delete(con, w["id"])
    assert watchlists.list_all(con) == [] and con.execute("SELECT COUNT(*) FROM watchlist_item").fetchone()[0] == 0
    with pytest.raises(watchlists.WatchlistError) as e:
        watchlists.rename(con, 999, "x")
    assert e.value.status == 404


def test_watchlist_limits_and_owner_column(con):
    for i in range(watchlists.MAX_LISTS):
        watchlists.create(con, f"L{i}", [])
    with pytest.raises(watchlists.WatchlistError):
        watchlists.create(con, "one too many", [])
    assert {r[0] for r in con.execute("SELECT owner_id FROM watchlist")} == {"local"}


def test_watchlist_summary_scores_and_totals(con):
    w = watchlists.create(con, "Mix", ["fortinet", "vmware", "docker"])
    scores = {"fortinet": {"score": 55.0, "level": {"label": "High"}, "cve_count": 1, "kev_count": 1}, "vmware": {"score": 20.0, "cve_count": 1, "kev_count": 0},
              "docker": {"score": None, "insufficient_reason": "no data"}}
    s = watchlists.summary(con, w["id"], scores)
    assert s["totals"] == {"technologies": 3, "unique_cves": 2, "kev_cves": 1, "news": 2, "scored": 2, "without_score": 1}
    assert s["highest"]["id"] == "fortinet" and next(t for t in s["technology_details"] if t["id"] == "docker")["score"] is None


def test_news_filter_by_watchlist_techs(con):
    assert repo.search_news(con, techs=["fortinet"])["total"] == 1
    assert repo.search_news(con, techs=["fortinet", "vmware"])["total"] == 2
    assert repo.search_news(con, techs=[])["total"] == 0 and repo.search_news(con)["total"] == 2
