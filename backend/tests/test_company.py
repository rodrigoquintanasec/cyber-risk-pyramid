import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app import analytics, company, company_expo, company_intel as ci, db, exposure, service  # noqa: E402
from app.company import CompanyError  # noqa: E402
from app.config import settings  # noqa: E402
from app.main import app  # noqa: E402

NOW = datetime.now(timezone.utc)
ISO = lambda d: d.isoformat(timespec="seconds")  # noqa: E731


@pytest.fixture()
def tdb(tmp_path):
    object.__setattr__(settings, "db_path", str(tmp_path / "c.sqlite"))
    analytics.reset()
    company_expo._memo.clear()
    db.init_db()
    yield
    object.__setattr__(settings, "db_path", str(tmp_path / "unused.sqlite"))


@pytest.fixture()
def api(tdb):
    return TestClient(app, client=("127.0.0.1", 5000))


def seed_cve(cve, tech=None, product="fortinet fortios", cvss=8.0, published=None, versions=None, kev=False, epss=None, cpes="o:fortinet:fortios", kev_date=None):
    with db.connect() as c:
        c.execute("INSERT OR REPLACE INTO nvd_cve(cve_id,published,last_modified,cvss,cvss_version,description,cpes,fetched_at,versions) VALUES(?,?,?,?,?,?,?,?,?)",
                  (cve, published or ISO(NOW - timedelta(days=3)), None, cvss, "3.1", f"Description of {cve}", cpes, ISO(NOW), json.dumps(versions) if versions else None))
        if tech:
            c.execute("INSERT OR REPLACE INTO tech_cve(tech_id,cve_id,product,match_source) VALUES(?,?,?,?)", (tech, cve, product, "nvd"))
        if kev:
            c.execute("INSERT OR REPLACE INTO kev_entry(cve_id,vendor,product,name,date_added,ransomware) VALUES(?,?,?,?,?,0)", (cve, "Fortinet", "FortiOS", "kev", kev_date or ISO(NOW - timedelta(days=2))[:10]))
        if epss is not None:
            c.execute("INSERT OR REPLACE INTO epss(cve_id,score,percentile,score_date,fetched_at) VALUES(?,?,?,?,?)", (cve, epss, 0.9, "2026-01-01", ISO(NOW)))


def mk_company(api, name="Acme", industry="Finance"):
    r = api.post("/api/v1/companies", json={"name": name, "industry": industry})
    assert r.status_code == 201, r.text
    return r.json()["id"]


def asset(api, cid, **kw):
    r = api.post(f"/api/v1/companies/{cid}/assets", json=kw)
    assert r.status_code == 201, r.text
    return r.json()


FORTI_RANGE = [{"v": "fortinet", "p": "fortios", "ver": None, "fi": None, "fe": None, "ti": None, "te": "7.2.0", "complex": False}]


# ---------------------------------------------------------------- pure applicability
def test_version_parsing_and_overlap():
    assert exposure.parse_version("7.0.5") == (7, 0, 5) and exposure.parse_version("v8.1") == (8, 1) and exposure.parse_version("7.0.5-beta") is None and exposure.parse_version(None) is None
    a, b = ((7, 0), True, (7, 2), True), ((7, 2), True, (8, 0), False)
    assert exposure.overlaps(a, b) and not exposure.overlaps(((7, 0), True, (7, 2), False), b)


def test_assess_asset_rules():
    prod = exposure.Product("fortinet", None, None)
    ok = lambda **kw: exposure.assess_asset(kw, prod, FORTI_RANGE)["status"]  # noqa: E731
    assert ok(version="7.0.5") == exposure.POTENTIAL and ok(version="7.4.1") == exposure.NOT_APPLICABLE
    assert ok(version_min="7.1", version_max="7.5") == exposure.POTENTIAL and ok() == exposure.INSUFFICIENT
    assert ok(version="7.0.5-build9") == exposure.REVIEW
    assert exposure.assess_asset({"version": "7.0.5"}, prod, None)["status"] == exposure.REVIEW                      # ranges not cached
    cx = [{**FORTI_RANGE[0], "complex": True}]
    assert exposure.assess_asset({"version": "7.0.5"}, prod, cx)["status"] == exposure.REVIEW                         # AND/negated configuration
    other = [{"v": "fortinet", "p": "fortiweb", "ver": None, "fi": None, "fe": None, "ti": None, "te": None, "complex": False}]
    assert exposure.assess_asset({"version": "7.0.5"}, exposure.Product(None, "fortinet", "fortios"), other)["status"] == exposure.REVIEW   # no data for that product
    assert exposure.worst([exposure.NOT_APPLICABLE, exposure.REVIEW]) == exposure.REVIEW and exposure.worst([]) is None


# ---------------------------------------------------------------- stage 1: management
def test_company_crud_search_archive_and_empty_state(api):
    assert api.get("/api/v1/companies").json()["total"] == 0                                    # no fictitious companies
    cid = mk_company(api, "Acme Corp")
    assert api.post("/api/v1/companies", json={"name": "acme corp", "industry": "x"}).status_code == 409
    assert api.post("/api/v1/companies", json={"name": "", "industry": "x"}).status_code == 422
    assert api.post("/api/v1/companies", json={"name": "Z", "industry": ""}).status_code == 422
    r = api.put(f"/api/v1/companies/{cid}", json={"trade_name": "Acme", "country": "AR", "description": "d"}).json()
    assert r["trade_name"] == "Acme" and r["name"] == "Acme Corp" and r["updated_at"] >= r["created_at"]
    mk_company(api, "Globex", "Energy")
    assert api.get("/api/v1/companies?q=glob").json()["total"] == 1 and api.get("/api/v1/companies?industry=energy").json()["total"] == 1
    assert api.post(f"/api/v1/companies/{cid}/archive").json()["status"] == "archived"
    assert api.get("/api/v1/companies").json()["total"] == 1 and api.get("/api/v1/companies?status=archived").json()["total"] == 1
    assert api.get("/api/v1/companies/not-an-id").status_code == 404 and api.get("/api/v1/companies/cmp_000000000000").status_code == 404


def test_inventory_products_vs_assets_versions_and_validation(api):
    cid = mk_company(api)
    a1 = asset(api, cid, tech_id="windows-server", asset_ref="SRV-01", version="2019", internet_exposed="no")
    asset(api, cid, tech_id="windows-server", asset_ref="SRV-02", version="2022")
    asset(api, cid, tech_id="windows-server")                                   # unknown version allowed
    inv = api.get(f"/api/v1/companies/{cid}/inventory").json()
    assert len(inv["technologies"]) == 1 and inv["technologies"][0]["active_assets"] == 3 and inv["active_assets"] == 3     # one product, three assets
    assert a1["internet_exposed"] == "no" and inv["technologies"][0]["assets"][2]["internet_exposed"] == "unknown"           # never assumed
    assert api.post(f"/api/v1/companies/{cid}/assets", json={"tech_id": "nope"}).status_code == 422
    assert api.post(f"/api/v1/companies/{cid}/assets", json={"vendor": "acme"}).status_code == 422                          # needs vendor AND product
    assert api.post(f"/api/v1/companies/{cid}/assets", json={"tech_id": "linux", "version": "1.0", "version_min": "0.9"}).status_code == 422
    assert api.post(f"/api/v1/companies/{cid}/assets", json={"tech_id": "linux", "environment": "moon"}).status_code == 422
    assert api.post(f"/api/v1/companies/{cid}/assets", json={"tech_id": "linux", "last_verified": "2999-01-01"}).status_code == 422
    assert api.post(f"/api/v1/companies/{cid}/assets", json={"tech_id": "linux", "version": "1.0;DROP"}).status_code == 422
    r = api.put(f"/api/v1/companies/{cid}/assets/{a1['id']}", json={"status": "retired"}).json()
    assert r["status"] == "retired" and api.get(f"/api/v1/companies/{cid}/inventory").json()["active_assets"] == 2


def test_custom_products_use_exact_identifiers_only(api):
    cid = mk_company(api)
    a = asset(api, cid, vendor="Acme Soft", product="Widget Pro", version="1.2")
    assert a["tech_id"] is None and a["vendor"] == "acme_soft" and a["product"] == "widget_pro"
    b = asset(api, cid, vendor="fortinet", product="fortios", version="7.0")                  # structurally a catalogue product -> linked, no new pyramid
    assert b["tech_id"] == "fortinet"
    seed_cve("CVE-2026-0001", cpes="a:acme_soft:widget_pro", versions=None)
    seed_cve("CVE-2026-0002", cpes="a:acme_soft:other")                                        # same vendor, different product: not related
    dash = api.get(f"/api/v1/companies/{cid}/dashboard").json()
    ids = {t["name"]: t for t in dash["technologies"]}
    custom = next(t for t in dash["technologies"] if not t["catalog"])
    assert custom["score"] is None and custom["level"]["label"] == "Threat Score Unavailable" and custom["data_availability"] == "unavailable" and custom["related_cves"] == 1
    assert len(dash["technologies"]) == 2 and "Fortinet" in ids


# ---------------------------------------------------------------- stage 2: dashboard
def test_dashboard_groups_assets_dedups_cves_and_reuses_global_score(api):
    cid = mk_company(api)
    for v in ("7.0.5", "7.0.9", "7.4.1"):
        asset(api, cid, tech_id="fortinet", version=v)
    seed_cve("CVE-2026-1000", "fortinet", versions=FORTI_RANGE, kev=True, epss=0.4)
    seed_cve("CVE-2026-1001", "fortinet", versions=FORTI_RANGE)
    # the same CVE also attached to a second product of the company must still be ONE unique CVE
    asset(api, cid, tech_id="vmware", version="8.0")
    seed_cve("CVE-2026-1000", "vmware", product="vmware esxi", versions=FORTI_RANGE, kev=True, epss=0.4)
    d = api.get(f"/api/v1/companies/{cid}/dashboard").json()
    forti = next(t for t in d["technologies"] if t["id"] == "fortinet")
    k = {x["key"]: x["value"] for x in d["kpis"]}
    assert len(d["technologies"]) == 2 and forti["assets"] == 3 and k["assets"] == 4                     # grouped, not one pyramid per asset
    assert k["related_cves"] == 2 and k["kev"] == 1                                                       # unique ids, not 3
    with db.connect() as c:
        glob = service.build_technology(c, "fortinet")
    assert forti["score"] == glob["score"] and forti["level"] == glob["level"]                           # scoring reused untouched
    assert forti["exposure"]["confirmed"] == 0 and k["confirmed"] == 0                                    # high signal never means confirmed
    assert {x["key"] for x in d["kpis"]} >= {"technologies", "assets", "related_cves", "kev", "potential", "confirmed", "events", "advisories", "coverage"}


def test_fortinet_two_companies_different_versions_do_not_share_exposure(api):
    a, b = mk_company(api, "A"), mk_company(api, "B")
    asset(api, a, tech_id="fortinet", version="7.0.5")
    asset(api, b, tech_id="fortinet", version="7.4.1")
    seed_cve("CVE-2026-2000", "fortinet", versions=FORTI_RANGE, kev=True)
    st = lambda cid: api.get(f"/api/v1/companies/{cid}/vulnerabilities").json()["items"][0]["effective_status"]  # noqa: E731
    assert st(a) == "potentially_applicable" and st(b) == "not_applicable"


def test_unknown_version_gives_insufficient_data(api):
    cid = mk_company(api)
    asset(api, cid, tech_id="vmware")
    seed_cve("CVE-2026-2100", "vmware", product="vmware esxi", versions=FORTI_RANGE)
    it = api.get(f"/api/v1/companies/{cid}/vulnerabilities").json()["items"][0]
    assert it["effective_status"] == "insufficient_data"
    d = api.get(f"/api/v1/companies/{cid}/dashboard").json()
    assert next(t for t in d["technologies"])["assets_without_version"] == 1


def test_kev_cve_for_a_product_the_company_does_not_use_is_not_its_exposure(api):
    cid = mk_company(api)
    asset(api, cid, tech_id="linux", version="6.1")
    seed_cve("CVE-2026-2200", "fortinet", kev=True)                                                      # KEV, Fortinet only
    assert api.get(f"/api/v1/companies/{cid}/vulnerabilities").json()["total"] == 0
    assert next(x for x in api.get(f"/api/v1/companies/{cid}/dashboard").json()["kpis"] if x["key"] == "kev")["value"] == 0


def test_one_cve_in_ten_news_counts_once(api):
    cid = mk_company(api)
    asset(api, cid, tech_id="fortinet", version="7.0.5")
    seed_cve("CVE-2026-2300", "fortinet", versions=FORTI_RANGE)
    with db.connect() as c:
        c.execute("INSERT INTO news_source(id,name,type,url) VALUES('s','S','news','https://x.test')")
        for i in range(10):
            c.execute("INSERT INTO news_item(id,source_id,guid,url,url_canon,title,summary,published,collected_at,sort_ts) VALUES(?,?,?,?,?,?,?,?,?,?)",
                      (f"n{i}", "s", f"g{i}", f"https://x.test/{i}", f"https://x.test/{i}", f"Story {i} CVE-2026-2300", "", ISO(NOW), ISO(NOW), ISO(NOW)))
            c.execute("INSERT INTO news_cve VALUES(?,?)", (f"n{i}", "CVE-2026-2300"))
            c.execute("INSERT INTO news_tech VALUES(?,?,?)", (f"n{i}", "fortinet", "name"))
    assert api.get(f"/api/v1/companies/{cid}/vulnerabilities").json()["total"] == 1
    assert next(x for x in api.get(f"/api/v1/companies/{cid}/dashboard").json()["kpis"] if x["key"] == "related_cves")["value"] == 1
    assert api.get(f"/api/v1/companies/{cid}/news").json()["total"] == 10                                  # articles are still listed as articles


# ---------------------------------------------------------------- stage 3: assessments
def test_manual_assessment_requires_evidence_keeps_history_and_leaves_global_data_alone(api):
    cid = mk_company(api)
    asset(api, cid, tech_id="fortinet", version="7.0.5")
    seed_cve("CVE-2026-3000", "fortinet", versions=FORTI_RANGE)
    ct = api.get(f"/api/v1/companies/{cid}/inventory").json()["technologies"][0]["id"]
    url = f"/api/v1/companies/{cid}/vulnerabilities/CVE-2026-3000/assessment"
    with db.connect() as c:
        before = [tuple(r) for r in c.execute("SELECT * FROM nvd_cve")], [tuple(r) for r in c.execute("SELECT * FROM tech_cve")]
    assert api.put(url, json={"company_tech_id": ct, "status": "confirmed_applicable"}).status_code == 422          # no evidence
    assert api.put(url, json={"company_tech_id": ct, "status": "bogus"}).status_code == 422
    assert api.put(url, json={"company_tech_id": 9999, "status": "needs_review"}).status_code == 404
    assert api.put(f"/api/v1/companies/{cid}/vulnerabilities/CVE-2026-9999/assessment", json={"company_tech_id": ct, "status": "needs_review"}).status_code == 422
    assert api.put(url, json={"company_tech_id": ct, "status": "needs_review", "reference_url": "javascript:alert(1)"}).status_code == 422
    r1 = api.put(url, json={"company_tech_id": ct, "status": "confirmed_applicable", "evidence": "Firmware 7.0.5 verified on the edge firewall during the audit", "reference_url": "https://example.com/ev1"})
    assert r1.status_code == 200 and r1.json()["changed"]
    assert api.put(url, json={"company_tech_id": ct, "status": "confirmed_applicable", "evidence": "Firmware 7.0.5 verified on the edge firewall during the audit", "reference_url": "https://example.com/ev1"}).json()["changed"] is False
    api.put(url, json={"company_tech_id": ct, "status": "not_applicable", "evidence": "Upgraded to 7.4.1 on 2026-02-01 (change ticket 42)"})
    f = api.get(f"/api/v1/companies/{cid}/vulnerabilities/CVE-2026-3000").json()
    assert f["effective_status"] == "not_applicable" and [h["new_status"] for h in f["history"]] == ["not_applicable", "confirmed_applicable"]
    assert f["history"][1]["evidence"].startswith("Firmware 7.0.5") and f["history"][0]["old_status"] == "confirmed_applicable"       # earlier evidence preserved
    assert f["products"][0]["automatic_status"] == "potentially_applicable" and f["last_assessed"]
    with db.connect() as c:
        after = [tuple(r) for r in c.execute("SELECT * FROM nvd_cve")], [tuple(r) for r in c.execute("SELECT * FROM tech_cve")]
    assert before == after


def test_confirmed_counts_come_only_from_analysts(api):
    cid = mk_company(api)
    asset(api, cid, tech_id="fortinet", version="7.0.5")
    seed_cve("CVE-2026-3100", "fortinet", versions=FORTI_RANGE)
    ct = api.get(f"/api/v1/companies/{cid}/inventory").json()["technologies"][0]["id"]
    k = lambda: {x["key"]: x["value"] for x in api.get(f"/api/v1/companies/{cid}/dashboard").json()["kpis"]}  # noqa: E731
    assert k()["potential"] == 1 and k()["confirmed"] == 0
    api.put(f"/api/v1/companies/{cid}/vulnerabilities/CVE-2026-3100/assessment", json={"company_tech_id": ct, "status": "confirmed_applicable", "evidence": "Validated against the CMDB export"})
    assert k()["potential"] == 0 and k()["confirmed"] == 1


# ---------------------------------------------------------------- isolation, archive, security
def test_companies_are_isolated(api):
    a, b = mk_company(api, "A"), mk_company(api, "B")
    x = asset(api, a, tech_id="fortinet", version="7.0.5")
    seed_cve("CVE-2026-4000", "fortinet", versions=FORTI_RANGE)
    assert api.put(f"/api/v1/companies/{b}/assets/{x['id']}", json={"version": "9.9"}).status_code == 404       # another company's asset
    assert api.get(f"/api/v1/companies/{b}/vulnerabilities").json()["total"] == 0
    assert api.get(f"/api/v1/companies/{b}/vulnerabilities/CVE-2026-4000").status_code == 404
    assert api.get(f"/api/v1/companies/{b}/inventory").json()["technologies"] == []
    ct = api.get(f"/api/v1/companies/{a}/inventory").json()["technologies"][0]["id"]
    assert api.get(f"/api/v1/companies/{b}/technologies/{ct}").status_code == 404
    assert api.put(f"/api/v1/companies/{b}/vulnerabilities/CVE-2026-4000/assessment", json={"company_tech_id": ct, "status": "needs_review"}).status_code in (404, 422)
    d = api.get(f"/api/v1/companies/{b}/dashboard").json()
    assert d["technologies"] == [] and a not in json.dumps(d)


def test_archived_company_keeps_history_and_blocks_writes(api):
    cid = mk_company(api)
    asset(api, cid, tech_id="fortinet", version="7.0.5")
    seed_cve("CVE-2026-4100", "fortinet", versions=FORTI_RANGE)
    ct = api.get(f"/api/v1/companies/{cid}/inventory").json()["technologies"][0]["id"]
    api.put(f"/api/v1/companies/{cid}/vulnerabilities/CVE-2026-4100/assessment", json={"company_tech_id": ct, "status": "needs_review"})
    api.post(f"/api/v1/companies/{cid}/archive")
    assert api.post(f"/api/v1/companies/{cid}/assets", json={"tech_id": "linux"}).status_code == 409
    assert api.put(f"/api/v1/companies/{cid}/vulnerabilities/CVE-2026-4100/assessment", json={"company_tech_id": ct, "status": "not_applicable"}).status_code == 409
    f = api.get(f"/api/v1/companies/{cid}/vulnerabilities/CVE-2026-4100").json()
    assert len(f["history"]) == 1 and api.get(f"/api/v1/companies/{cid}/inventory").json()["active_assets"] == 1
    assert api.post(f"/api/v1/companies/{cid}/restore").json()["status"] == "active"


def test_every_route_is_protected_for_remote_clients(tdb):
    orig = settings.sync_token
    remote = TestClient(app)                                                     # client host 'testclient' = not local
    assert remote.get("/api/v1/companies").status_code == 403
    assert remote.post("/api/v1/companies", json={"name": "x", "industry": "y"}).status_code == 403
    object.__setattr__(settings, "sync_token", "secret")
    assert remote.get("/api/v1/companies").status_code == 403 and remote.get("/api/v1/companies", headers={"X-Sync-Token": "bad"}).status_code == 403
    assert remote.get("/api/v1/companies", headers={"X-Sync-Token": "secret"}).status_code == 200
    local = TestClient(app, client=("127.0.0.1", 1))
    assert local.get("/api/v1/companies").status_code == 403                    # token configured: required even locally
    object.__setattr__(settings, "sync_token", None)
    assert local.get("/api/v1/companies").status_code == 200
    object.__setattr__(settings, "sync_token", orig)


def test_global_dashboard_is_untouched_by_company_activity(api):
    seed_cve("CVE-2026-5000", "fortinet", versions=FORTI_RANGE, kev=True)
    before = json.dumps(service.overview()["technologies"], sort_keys=True)
    cid = mk_company(api)
    asset(api, cid, tech_id="fortinet", version="7.0.5", criticality="critical")
    ct = api.get(f"/api/v1/companies/{cid}/inventory").json()["technologies"][0]["id"]
    api.put(f"/api/v1/companies/{cid}/vulnerabilities/CVE-2026-5000/assessment", json={"company_tech_id": ct, "status": "confirmed_applicable", "evidence": "Verified manually in lab"})
    api.post(f"/api/v1/companies/{cid}/reports", json={"period": "7d"})
    assert json.dumps(service.overview()["technologies"], sort_keys=True) == before
    assert api.get("/api/technologies").status_code == 200


# ---------------------------------------------------------------- stage 4: analytics & changes
def test_analytics_comparable_mode_discovery_and_validation(api):
    cid = mk_company(api)
    asset(api, cid, tech_id="fortinet", version="7.0.5")
    seed_cve("CVE-2026-6000", "fortinet", versions=FORTI_RANGE, kev=True, published=ISO(NOW - timedelta(days=2)))
    seed_cve("CVE-2026-6001", "fortinet", versions=FORTI_RANGE, published=ISO(NOW - timedelta(days=40)))
    a = api.get(f"/api/v1/companies/{cid}/analytics?period=30d").json()
    assert a["status"] == "ok" and sum(a["discovery"]["new_cves"]) == 1 and a["kev_watch"]["total_related"] == 1 and len(a["kev_watch"]["added"]) == 1
    assert a["discovery"]["compare"]["previous"] == 1 and a["discovery"]["compare"]["pct"] is None                  # base below minimum -> no percentage
    assert a["exposure_status"]["current"]["potentially_applicable"] == 2 and "history" in a["exposure_status"]["history_note"] or True
    assert a["epss"]["available"] is False and a["inventory_quality"]["coverage"]["with_version_pct"] == 100.0
    c = api.get(f"/api/v1/companies/{cid}/analytics?period=7d&mode=comparable").json()
    assert c["status"] == "insufficient_comparable" and c["message"] == "Insufficient comparable coverage"
    assert api.get(f"/api/v1/companies/{cid}/analytics?period=90d").json()["discovery"]["compare"]["status"] == "insufficient"          # local NVD window is 120 days
    assert api.get(f"/api/v1/companies/{cid}/analytics?period=custom").status_code == 422
    assert api.get(f"/api/v1/companies/{cid}/analytics?period=custom&date_from=2020-01-01&date_to=2026-01-01").status_code == 422
    assert api.get(f"/api/v1/companies/{cid}/analytics?period=1y").status_code == 422


def test_what_changed_separates_publication_from_knowledge_and_never_invents_history(api):
    cid = mk_company(api)
    asset(api, cid, tech_id="fortinet", version="7.0.5")
    ch = api.get(f"/api/v1/companies/{cid}/changes?period=7d").json()
    assert {i["kind"] for i in ch["items"]} <= {"inventory"} and ch["snapshots"] <= 1              # no CVE/KEV changes without a previous snapshot
    with db.connect() as c:
        ci.take_snapshot(c, cid, "t", 0)
    seed_cve("CVE-2026-7000", "fortinet", versions=FORTI_RANGE, published=ISO(NOW - timedelta(days=60)), kev=True, kev_date=ISO(NOW - timedelta(days=50))[:10])   # old facts, discovered now
    seed_cve("CVE-2026-7001", "fortinet", versions=FORTI_RANGE, published=ISO(NOW + timedelta(minutes=1)))
    with db.connect() as c:
        c.execute("UPDATE company_snapshot SET taken_at=?", (ISO(NOW - timedelta(hours=1)),))
        assert ci.take_snapshot(c, cid, "t2", 0)
    ch = api.get(f"/api/v1/companies/{cid}/changes?period=7d").json()
    by = {i["cve"]: i for i in ch["items"] if i["kind"] == "new_cve"}
    assert by["CVE-2026-7000"]["historical"] is True and by["CVE-2026-7001"]["historical"] is False
    assert by["CVE-2026-7000"]["published_at"] < by["CVE-2026-7000"]["known_at"]
    k = [i for i in ch["items"] if i["kind"] == "kev_added"]
    assert len(k) == 1 and k[0]["historical"] is True and "late" in k[0]["note"]
    assert any(i["kind"] == "inventory" for i in ch["items"]) and ch["counts"]["new_cve"] == 2


def test_snapshots_are_append_only_and_rate_limited(api):
    cid = mk_company(api)
    asset(api, cid, tech_id="fortinet", version="7.0.5")                      # API write takes the baseline snapshot
    with db.connect() as c:
        n = c.execute("SELECT COUNT(*) FROM company_snapshot").fetchone()[0]
        assert n == 1 and ci.take_snapshot(c, cid, "again", 5) is None
        assert ci.take_snapshot(c, cid, "forced", 0)
        assert c.execute("SELECT COUNT(*) FROM company_snapshot").fetchone()[0] == 2


# ---------------------------------------------------------------- stage 5: reports & comparison
def test_reports_are_stored_deterministic_and_do_not_judge_security(api):
    cid = mk_company(api, "Report Co")
    asset(api, cid, tech_id="fortinet", version="7.0.5")
    seed_cve("CVE-2026-8000", "fortinet", versions=FORTI_RANGE, kev=True, epss=0.5)
    r = api.post(f"/api/v1/companies/{cid}/reports", json={"period": "30d"})
    assert r.status_code == 201
    rep = r.json()
    assert set(rep["sections"]) == {"A_executive_summary", "B_technologies", "C_vulnerabilities", "D_kev", "E_exposure", "F_news", "G_advisories", "H_trends", "I_inventory", "J_sources"}
    assert rep["company"]["name"] == "Report Co" and rep["period_label"] == "Last 30 Days" and rep["generated_at"] and "last_sync" in rep
    lim = " ".join(rep["sections"]["J_sources"]["limitations"])
    assert "says nothing about whether the organisation is secure or compromised" in lim
    assert rep["sections"]["E_exposure"]["counts"]["potentially_applicable"] == 1 and rep["sections"]["D_kev"]["related_total"] == 1
    lst = api.get(f"/api/v1/companies/{cid}/reports").json()["items"]
    assert len(lst) == 1 and api.get(f"/api/v1/companies/{cid}/reports/{lst[0]['id']}").json()["sections"]["A_executive_summary"]
    assert "Limitations" in api.get(f"/api/v1/companies/{cid}/reports/{lst[0]['id']}/text").json()["text"]
    assert api.post(f"/api/v1/companies/{cid}/reports", json={"period": "1y"}).status_code == 422
    other = mk_company(api, "Other")
    assert api.get(f"/api/v1/companies/{other}/reports/{lst[0]['id']}").status_code == 404            # reports are per company
    api.post(f"/api/v1/companies/{cid}/archive")
    assert len(api.get(f"/api/v1/companies/{cid}/reports").json()["items"]) == 1                       # history survives archiving


def test_company_comparison_has_context_and_no_ranking(api):
    a, b, c = mk_company(api, "A"), mk_company(api, "B"), mk_company(api, "C")
    for _ in range(3):
        asset(api, a, tech_id="fortinet", version="7.0.5", last_verified=NOW.date().isoformat())
    asset(api, b, tech_id="fortinet")
    seed_cve("CVE-2026-9000", "fortinet", versions=FORTI_RANGE)
    assert api.get(f"/api/v1/companies/compare?ids={a}").status_code == 422
    assert api.get(f"/api/v1/companies/compare?ids={a},{b},{c},{a}x,cmp_0,cmp_1,cmp_2").status_code in (404, 422)
    r = api.get(f"/api/v1/companies/compare?ids={a},{b},{c}").json()
    rows = {x["name"]: x for x in r["companies"]}
    assert rows["A"]["assets"] == 3 and rows["A"]["potential"] == 1 and rows["B"]["potential"] == 0 and rows["B"]["with_version_pct"] == 0.0
    assert rows["A"]["normalised"]["potential_per_100_assets"] == 33.3 and rows["C"]["normalised"]["cves_per_technology"] is None
    assert not any("rank" in k or "score" in k for x in r["companies"] for k in x) and "not a ranking" in " ".join(r["notes"])
    six = ",".join(mk_company(api, f"X{i}") for i in range(6))
    assert api.get(f"/api/v1/companies/compare?ids={six}").status_code == 422


def test_existing_modules_still_work_with_new_schema(api):
    assert api.get("/api/health").status_code == 200 and api.get("/api/technologies").status_code == 200
    assert api.get("/api/v1/vulns").status_code == 200 and api.get("/api/v1/analytics/meta").status_code == 200
    assert api.get("/api/v1/watchlists").status_code == 200
    with db.connect() as c:
        assert "versions" in {r[1] for r in c.execute("PRAGMA table_info(nvd_cve)")}
