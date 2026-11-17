import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app import catalog, catalog_db, db, service, sync  # noqa: E402
from app.catalog_seed import CATEGORIES, NEW  # noqa: E402
from app.config import settings  # noqa: E402
from app.correlation import correlate_cpes, correlate_kev, match_cpe  # noqa: E402
from app.main import app  # noqa: E402
from app.news import classify  # noqa: E402

NOW = datetime.now(timezone.utc).isoformat(timespec="seconds")
LEGACY_IDS = ["windows-server", "linux", "docker", "kubernetes", "vmware", "fortinet"]


@pytest.fixture()
def tdb(tmp_path):
    object.__setattr__(settings, "db_path", str(tmp_path / "k.sqlite"))
    db.init_db()
    yield
    catalog.set_registry(catalog.seed_technologies())
    classify.refresh_patterns()
    object.__setattr__(settings, "db_path", str(tmp_path / "unused.sqlite"))


@pytest.fixture()
def api(tdb):
    return TestClient(app, client=("127.0.0.1", 5000))


# ---------------------------------------------------------------- migration & seed integrity
def test_six_original_technologies_migrate_unchanged(tdb):
    with db.connect() as c:
        rows = {r["id"]: r for r in c.execute("SELECT * FROM technology")}
    for t in catalog.LEGACY:
        r = rows[t.id]
        assert r["name"] == t.name and tuple(tuple(x) for x in json.loads(r["cpe_matchers"])) == t.cpe_matchers and tuple(json.loads(r["nvd_queries"])) == t.nvd_queries
        assert tuple(tuple(x) for x in json.loads(r["kev_matchers"])) == t.kev_matchers and tuple(json.loads(r["ambiguous_kev_vendors"])) == t.ambiguous_kev_vendors
        assert r["dashboard"] == 1 and r["custom"] == 0
    shown = [t["id"] for t in service.overview()["technologies"]]
    assert shown == LEGACY_IDS                                               # the dashboard still shows exactly the original six, in the original order


def test_catalogue_has_at_least_100_unique_verified_style_entries():
    ids = [r[0] for r in NEW] + LEGACY_IDS
    assert len(ids) == len(set(ids)) >= 100
    names = [catalog.BY_ID[i].name.lower() for i in ids]
    assert len(set(names)) == len(names)
    assert {catalog.BY_ID[i].category for i in ids} == set(CATEGORIES)    # all fifteen categories are populated
    seen = {}
    for t in catalog.BY_ID.values():
        for v, rx in t.cpe_matchers:
            for q in t.nvd_queries:
                assert q.startswith("cpe:2.3:")
            seen.setdefault((v, rx), []).append(t.id)
    assert all(len(v) == 1 for v in seen.values())                             # no identifier claimed by two technologies
    for t in catalog.BY_ID.values():
        if t.kind == "cloud":
            assert not t.nvd_queries and not t.cpe_matchers                    # no invented CPE for cloud services
        else:
            assert t.nvd_queries or t.kev_matchers
    assert {"Microsoft", "Cisco", "Fortinet", "Palo Alto Networks", "Check Point", "VMware", "Red Hat", "Canonical", "Debian", "Docker", "Kubernetes", "Oracle", "PostgreSQL", "MongoDB",
            "GitLab", "Jenkins", "Atlassian", "Veeam"} <= {t.vendor for t in catalog.BY_ID.values()}


def test_sync_is_idempotent_and_preserves_user_choices(tdb):
    with db.connect() as c:
        catalog_db.set_monitor(c, "jenkins", "on")
        catalog_db.set_dashboard(c, "jenkins", True)
        before = c.execute("SELECT COUNT(*) FROM technology").fetchone()[0]
        r = catalog_db.sync(c)
        assert r["added"] == 0 and c.execute("SELECT COUNT(*) FROM technology").fetchone()[0] == before
        row = c.execute("SELECT monitor,dashboard FROM technology WHERE id='jenkins'").fetchone()
        assert (row["monitor"], row["dashboard"]) == ("on", 1)
        c.execute("UPDATE technology SET description='stale' WHERE id='gitlab'")        # an unedited built-in row follows the seed again
        catalog_db.sync(c)
        assert c.execute("SELECT description FROM technology WHERE id='gitlab'").fetchone()[0] != "stale"


# ---------------------------------------------------------------- correlation
def test_cpe_correlation_is_exact_never_by_vendor():
    assert set(correlate_cpes(["a:jenkins:jenkins"])) == {"jenkins"}
    assert correlate_cpes(["a:microsoft:paint", "o:microsoft:windows_95"]) == {}                      # vendor alone
    assert set(correlate_cpes(["o:cisco:ios_xe"])) == {"cisco-ios-xe"} and set(correlate_cpes(["o:cisco:ios"])) == {"cisco-ios"}   # exact product, not prefix
    assert correlate_cpes(["a:cisco:webex"]) == {}
    assert set(correlate_cpes(["a:f5:big-ip_local_traffic_manager"])) == {"f5-big-ip"}              # family member listed explicitly
    assert correlate_cpes(["a:f5:big-ip_unlisted_module"]) == {}
    assert match_cpe("fortinet", "fortios").id == "fortinet" and match_cpe("fortinet", "forticlient") is None
    assert correlate_cpes(["a:veeam:backup_\\&_replication"]) == {"veeam-backup-replication": {"veeam backup_\\&_replication"}}


def test_kev_and_cloud_correlation(tdb):
    assert correlate_kev("Palo Alto Networks", "PAN-OS").id == "palo-alto-pan-os"
    assert correlate_kev("Palo Alto Networks", "Expedition") is None                                  # same vendor, different product
    assert correlate_kev("ServiceNow", "Utah, Vancouver and Washington DC Now Platform").id == "servicenow"
    assert catalog.match_kind(catalog.BY_ID["servicenow"]) == "cloud" and catalog.match_kind(catalog.BY_ID["jenkins"]) == "exact" and catalog.match_kind(catalog.BY_ID["vmware"]) == "family"
    assert not catalog.BY_ID["aws"].nvd_queries and correlate_cpes(["a:amazon:aws"]) == {}


# ---------------------------------------------------------------- scores & coverage states
def test_products_without_cpe_never_get_a_score_and_catalog_only_is_not_a_zero(tdb):
    with db.connect() as c:
        c.execute("INSERT INTO kev_entry(cve_id,vendor,product,name,date_added,ransomware) VALUES('CVE-2026-0001','ServiceNow','Now Platform','x',date('now'),0)")
        c.execute("INSERT INTO tech_cve(tech_id,cve_id,product,match_source) VALUES('servicenow','CVE-2026-0001','ServiceNow','kev-product')")
        cloud = service.build_technology(c, "servicenow")
        plain = service.build_technology(c, "jenkins")
    assert cloud["score"] is None and cloud["coverage_state"] == "partial" and "no official product identifiers" in cloud["insufficient_reason"] and cloud["correlation"]["kind"] == "cloud"
    assert plain["score"] is None and plain["coverage_state"] == "catalog_only" and plain["monitored"] is False
    assert any("absence of related CVEs" in x for x in plain["limitations"])


def test_monitoring_follows_usage_and_nvd_sync_is_prioritised_and_budgeted(tdb, monkeypatch):
    calls = []

    def fake(q, days, pages):
        calls.append(q)
        return [], 0, False
    monkeypatch.setattr(sync.nvd_c, "fetch_by_cpe", fake)
    monkeypatch.setattr(sync, "_nvd_lookups", lambda f: None)
    with db.connect() as c:
        mon = catalog_db.monitored_ids(c)
    assert mon == set(LEGACY_IDS)                                                                       # only the dashboard six at first
    sync.sync_nvd(False)
    assert calls and all(any(q in catalog.BY_ID[t].nvd_queries for t in LEGACY_IDS) for q in calls) and not any("jenkins" in q for q in calls)
    assert len(calls) <= settings.nvd_query_budget
    n1 = len(calls)
    with db.connect() as c:                                                                             # a watchlist adds a technology to monitoring
        c.execute("INSERT INTO watchlist(owner_id,name,created_at,updated_at) VALUES('local','W',?,?)", (NOW, NOW))
        c.execute("INSERT INTO watchlist_item(watchlist_id,kind,ref_id,added_at) VALUES(1,'technology','jenkins',?)", (NOW,))
    for _ in range(3):
        sync.sync_nvd(False)
    assert any("jenkins" in q for q in calls[n1:])
    with db.connect() as c:
        assert c.execute("SELECT last_sync FROM technology WHERE id='jenkins'").fetchone()[0]
        total = len(calls)
    sync.sync_nvd(False)
    assert len(calls) == total                                                                          # cached: nothing is re-queried inside the TTL


# ---------------------------------------------------------------- API: search, filters, pagination
def test_catalog_search_filters_and_pagination(api):
    r = api.get("/api/v1/catalog?q=esxi").json()
    assert [x["id"] for x in r["items"]] == ["vmware"]                                                  # alias search
    assert api.get("/api/v1/catalog?q=PALO").json()["total"] >= 2
    cat = api.get("/api/v1/catalog?category=Databases&page_size=50").json()
    assert cat["total"] >= 8 and {x["category"] for x in cat["items"]} == {"Databases"}
    assert api.get("/api/v1/catalog?vendor=cisco").json()["total"] >= 4
    assert api.get("/api/v1/catalog?monitored=true").json()["total"] == 6 and api.get("/api/v1/catalog?pinned=true").json()["total"] == 6
    fresh = {x["id"]: x for x in api.get("/api/v1/catalog?page_size=50&q=fortinet").json()["items"]}["fortinet"]
    assert fresh["monitored"] and fresh["coverage_state"] == "catalog_only" and any("first synchronisation pending" in l for l in fresh["limitations"])   # monitored but nothing synced yet is not "Monitored"
    p1, p2 = api.get("/api/v1/catalog?page_size=20&page=1").json(), api.get("/api/v1/catalog?page_size=20&page=2").json()
    assert p1["total"] >= 100 and len(p1["items"]) == 20 and not {x["id"] for x in p1["items"]} & {x["id"] for x in p2["items"]} and p1["pages"] >= 5
    assert api.get("/api/v1/catalog?page_size=500").status_code == 422 and api.get("/api/v1/catalog?category=Nope").status_code == 422 and api.get("/api/v1/catalog?coverage=x").status_code == 422
    f = api.get("/api/v1/catalog/facets").json()
    assert f["enabled"] >= 100 and sum(c["count"] for c in f["categories"]) == f["enabled"] and f["pinned"] == 6
    d = api.get("/api/v1/catalog/jenkins").json()
    assert d["coverage_state"] == "catalog_only" and d["monitoring_reasons"] == [] and d["identifiers"]["nvd_queries"] == ["cpe:2.3:a:jenkins:jenkins"] and d["score"] is None
    assert api.get("/api/v1/catalog/nope").status_code == 404
    assert api.get("/api/v1/catalog?q=%25%27%3B--").json()["total"] == 0                                 # hostile input is just text


# ---------------------------------------------------------------- admin: custom technologies
def test_custom_technology_lifecycle_dedup_and_guard(api, tdb):
    body = {"id": "acme-gateway", "name": "Acme Gateway", "vendor": "Acme", "product": "Gateway", "category": "Network Security", "kind": "product", "aliases": ["AcmeGW"],
            "cpe_part": "o", "cpe_vendor": "acme", "cpe_product": "gateway_os", "news_terms": ["acme gateway"]}
    remote = TestClient(app)
    assert remote.post("/api/v1/catalog", json=body).status_code == 403                                  # admin operations are protected
    assert api.post("/api/v1/catalog", json=body).status_code == 201
    assert api.post("/api/v1/catalog", json=body).status_code == 409                                     # same id
    assert api.post("/api/v1/catalog", json={**body, "id": "acme-2", "name": "ACME gateway "}).status_code == 409                    # same name (normalised)
    assert api.post("/api/v1/catalog", json={**body, "id": "acme-3", "name": "Other", "aliases": ["acmegw"]}).status_code == 409        # alias clash
    assert api.post("/api/v1/catalog", json={**body, "id": "acme-4", "name": "Other 4", "aliases": [], "cpe_vendor": "fortinet", "cpe_product": "fortios"}).status_code == 409   # CPE clash
    assert api.post("/api/v1/catalog", json={**body, "id": "Bad Id", "name": "X"}).status_code == 422
    assert api.post("/api/v1/catalog", json={**body, "id": "acme-5", "name": "X5", "aliases": [], "category": "Nope"}).status_code == 422
    assert api.post("/api/v1/catalog", json={**body, "id": "acme-6", "name": "X6", "aliases": [], "cpe_product": ""}).status_code == 422          # half a CPE
    assert api.post("/api/v1/catalog", json={**body, "id": "acme-7", "name": "X7", "aliases": [], "cpe_vendor": "a b", "cpe_product": "c"}).status_code == 422
    assert api.post("/api/v1/catalog", json={**body, "id": "acme-8", "name": "X8", "aliases": [], "cpe_vendor": "x8", "cpe_product": "x8", "news_terms": ["ab"]}).status_code == 422
    assert set(correlate_cpes(["o:acme:gateway_os"])) == {"acme-gateway"} and classify.detect_technologies("Acme Gateway flaw") == {"acme-gateway": "name"}
    assert api.put("/api/v1/catalog/acme-gateway", json={"description": "edited", "name": "Acme Gateway"}).status_code == 200
    assert api.get("/api/v1/catalog/acme-gateway").json()["description"] == "edited"
    assert api.put("/api/v1/catalog/jenkins", json={"name": "Hacked"}).status_code == 403              # built-in entries are read-only
    assert api.post("/api/v1/catalog/jenkins/disable").status_code == 403
    assert api.post("/api/v1/catalog/acme-gateway/disable").status_code == 200
    assert "acme-gateway" not in {t.id for t in catalog.CATALOG} and "acme-gateway" in catalog.BY_ID    # excluded from correlation, still resolvable
    assert correlate_cpes(["o:acme:gateway_os"]) == {} and api.get("/api/v1/catalog?q=acme").json()["total"] == 0 and api.get("/api/v1/catalog?q=acme&status=disabled").json()["total"] == 1
    assert api.post("/api/v1/catalog/acme-gateway/enable").status_code == 200
    with db.connect() as c:                                                                              # persisted: survives a restart
        catalog_db.load(c)
    assert "acme-gateway" in {t.id for t in catalog.CATALOG}


def test_news_backfill_links_old_articles_to_new_technologies(tdb):
    with db.connect() as c:
        c.execute("INSERT INTO news_source(id,name,type,url) VALUES('s','S','news','https://x.test')")
        c.execute("INSERT INTO news_item(id,source_id,guid,url,url_canon,title,summary,published,collected_at,sort_ts) VALUES('n1','s','g','https://x.test/1','https://x.test/1','Jenkins plugin flaw lets attackers run code','',?,?,?)", (NOW, NOW, NOW))
        c.execute("INSERT INTO news_item(id,source_id,guid,url,url_canon,title,summary,published,collected_at,sort_ts) VALUES('n2','s','g2','https://x.test/2','https://x.test/2','Microsoft patches a bug','',?,?,?)", (NOW, NOW, NOW))
        c.execute("UPDATE technology SET backfilled=0")
        n = catalog_db.backfill_news(c)
        rows = {(r[0], r[1]) for r in c.execute("SELECT news_id,tech_id FROM news_tech")}
    assert ("n1", "jenkins") in rows and not any(r[0] == "n2" for r in rows) and n >= 1


# ---------------------------------------------------------------- global dashboard pyramids
def test_dashboard_selection_limits_and_unpinned_technologies_still_load(api):
    assert [t["id"] for t in api.get("/api/technologies").json()["technologies"]] == LEGACY_IDS
    assert api.put("/api/v1/catalog/jenkins/dashboard", json={"pinned": True}).status_code == 200
    ids = [t["id"] for t in api.get("/api/technologies").json()["technologies"]]
    assert ids[-1] == "jenkins" and ids[:6] == LEGACY_IDS and len(ids) == 7
    assert api.get("/api/technologies/gitlab").status_code == 200                                         # any catalogue technology can be opened on demand
    for t in [r[0] for r in NEW if r[0] not in ("jenkins",)][:30]:
        r = api.put(f"/api/v1/catalog/{t}/dashboard", json={"pinned": True})
        if r.status_code == 409:
            break
    assert r.status_code == 409 and len(api.get("/api/technologies").json()["technologies"]) == 24     # never hundreds of pyramids
    assert api.put("/api/v1/catalog/jenkins/dashboard", json={"pinned": False}).status_code == 200
    assert TestClient(app).put("/api/v1/catalog/jenkins/dashboard", json={"pinned": True}).status_code == 403
    assert api.put("/api/v1/catalog/nope/dashboard", json={"pinned": True}).status_code == 404
    assert api.put("/api/v1/catalog/jenkins/monitoring", json={"monitor": "bogus"}).status_code == 422


# ---------------------------------------------------------------- companies, watchlists, integrity
def _company(api, name="Acme"):
    return api.post("/api/v1/companies", json={"name": name, "industry": "x"}).json()["id"]


def test_company_inventory_uses_catalogue_custom_techs_and_stays_isolated(api, tdb):
    api.post("/api/v1/catalog", json={"id": "acme-erp", "name": "Acme ERP", "category": "Enterprise Applications", "kind": "platform"})
    a, b = _company(api, "A"), _company(api, "B")
    for tid in ("jenkins", "acme-erp", "aws"):
        assert api.post(f"/api/v1/companies/{a}/assets", json={"tech_id": tid, "version": "1.0" if tid == "jenkins" else None}).status_code == 201
    assert api.post(f"/api/v1/companies/{a}/assets", json={"tech_id": "jenkins", "version": "2.0"}).status_code == 201                 # many assets, one product
    inv = api.get(f"/api/v1/companies/{a}/inventory").json()
    assert {t["tech_id"] for t in inv["technologies"]} == {"jenkins", "acme-erp", "aws"} and next(t for t in inv["technologies"] if t["tech_id"] == "jenkins")["active_assets"] == 2
    ci = {t["tech_id"]: t["catalog_info"] for t in inv["technologies"]}
    assert ci["jenkins"]["category"] == "DevOps & Development" and ci["aws"]["score_possible"] is False and ci["acme-erp"]["score_possible"] is False
    assert api.get(f"/api/v1/companies/{b}/inventory").json()["technologies"] == []
    d = api.get(f"/api/v1/companies/{a}/dashboard").json()
    by = {t["id"]: t for t in d["technologies"]}
    assert set(by) == {"jenkins", "acme-erp", "aws"} and by["aws"]["score"] is None and by["jenkins"]["data_availability"] == "catalog_only" and by["jenkins"]["monitored"] is True      # monitored now (it is in an inventory), first sync still pending
    with db.connect() as c:
        assert {"jenkins", "acme-erp", "aws"} <= catalog_db.monitored_ids(c)
        glob = service.build_technology(c, "jenkins")
    assert by["jenkins"]["score"] == glob["score"] and by["jenkins"]["level"] == glob["level"]                       # company pyramids reuse the global scoring
    assert api.get(f"/api/v1/companies/{b}/dashboard").json()["technologies"] == []


def test_watchlists_and_references_stay_valid(api, tdb):
    w = api.post("/api/v1/watchlists", json={"name": "Edge"}).json()
    for tid in ("fortinet", "jenkins"):
        assert api.post(f"/api/v1/watchlists/{w['id']}/technologies", json={"tech_id": tid}).status_code in (200, 201)
    lists = api.get("/api/v1/watchlists").json()
    assert {"fortinet", "jenkins"} <= set(next(x for x in lists["items"] if x["id"] == w["id"])["technologies"])
    avail = lists["available_technologies"]
    assert len(avail) >= 100 and all("category" in a for a in avail)
    cid = _company(api)
    api.post(f"/api/v1/companies/{cid}/assets", json={"tech_id": "vmware", "version": "8.0"})
    with db.connect() as c:
        c.execute("INSERT INTO tech_cve(tech_id,cve_id,product,match_source) VALUES('linux','CVE-2026-1','x','nvd')")
        c.execute("INSERT INTO news_source(id,name,type,url) VALUES('s','S','news','https://x')")
        c.execute("INSERT INTO news_item(id,source_id,guid,url,url_canon,title,summary,published,collected_at,sort_ts) VALUES('n','s','g','https://x/1','https://x/1','t','',?,?,?)", (NOW, NOW, NOW))
        c.execute("INSERT INTO news_tech VALUES('n','docker','name')")
        known = {r[0] for r in c.execute("SELECT id FROM technology")}
        refs = [r[0] for r in c.execute("SELECT ref_id FROM watchlist_item WHERE kind='technology'")] + [r[0] for r in c.execute("SELECT tech_id FROM company_technology WHERE tech_id IS NOT NULL")] \
            + [r[0] for r in c.execute("SELECT tech_id FROM tech_cve")] + [r[0] for r in c.execute("SELECT tech_id FROM news_tech")]
    assert refs and set(refs) <= known                                                                     # no dangling technology reference


def test_existing_modules_keep_working_with_the_dynamic_catalogue(api):
    for path in ("/api/health", "/api/technologies", "/api/v1/vulns", "/api/v1/vulns/facets", "/api/v1/news/stats", "/api/v1/intel/facets", "/api/v1/analytics/meta", "/api/v1/graph/meta"):
        assert api.get(path).status_code == 200, path
    assert api.get("/api/v1/vulns/facets").json()["technologies"] and len(api.get("/api/v1/intel/facets").json()["technologies"]) >= 100
    assert api.get("/api/v1/graph/search?q=jenkins").status_code == 200


def test_every_seed_cpe_was_verified_against_the_official_nvd_dictionary():
    v = json.loads((Path(__file__).resolve().parent / "data" / "cpe_verification_2026-11-17.json").read_text())
    tokens = {t for r in NEW for t in r[8].split()}
    assert tokens and all(v.get(t, 0) > 0 for t in tokens), sorted(t for t in tokens if v.get(t, 0) <= 0)
