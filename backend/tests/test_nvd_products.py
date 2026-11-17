"""Dynamic NVD product catalogue: categories, product discovery from the LOCAL CPE dictionary, technology incorporation and integrations."""
import sys
from datetime import timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app import catalog, catalog_db, db, intel_import as ii, nvd_products, service, techsync  # noqa: E402
from app.main import app  # noqa: E402
from test_intel_db import LOG4J, NOW, Y, conf, cve, env, match, q1, run  # noqa: E402,F401  (env = temp DB + fake official hosts)

SIX = ["windows-server", "linux", "docker", "kubernetes", "vmware", "fortinet"]


def rec(part, vendor, product, ver="*", title=None, dep=False, dep_by=None, edition="*", sw_edition="*", target_sw="*", refs=None, n=[0]):
    n[0] += 1
    name = f"cpe:2.3:{part}:{vendor}:{product}:{ver}:*:{edition}:*:{sw_edition}:{target_sw}:*:*"
    c = {"deprecated": dep, "cpeName": name, "cpeNameId": f"ID-{n[0]:07d}", "lastModified": "2024-01-01T00:00:00.000", "created": "2019-01-01T00:00:00.000",
         "titles": [{"title": title or f"{vendor.title()} {product} {ver}", "lang": "en"}]}
    if refs:
        c["refs"] = [{"ref": r, "type": "Vendor"} for r in refs]
    if dep_by:
        c["deprecatedBy"] = [{"cpeName": d, "cpeNameId": "X"} for d in dep_by]
    return {"cpe": c}


def dictionary():
    out = [rec("a", "apache", "log4j", v, "Apache Log4j " + v) for v in ("1.2.17", "2.0", "2.14.1", "2.15.0")]
    out += [rec("a", "acme", "widget", f"1.{i}", f"Acme Widget 1.{i}", refs=["https://acme.example/widget"]) for i in range(100)]
    out += [rec("a", "acme", "widget", "2.0", "Acme Widget 2.0", target_sw="node.js"), rec("a", "acme", "widget", "2.0", "Acme Widget 2.0 Enterprise", edition="enterprise")]
    out += [rec("a", "acme", "widget_pro", f"3.{i}", f"Acme Widget Pro 3.{i}") for i in range(3)]
    out += [rec("a", "acme", "oldthing", "1.0", "Acme Oldthing 1.0", dep=True, dep_by=["cpe:2.3:a:acme:widget:1.0:*:*:*:*:*:*:*"])]
    out += [rec("o", "acme", "acmeos", "9", "Acme OS 9"), rec("h", "acme", "router_x", "1", "Acme Router X")]
    return out


def load(net, with_cve=True, with_cpe=True, extra_cves=()):
    ii.FIRST_YEAR = Y - 1
    if with_cve:
        net.add_cve_unit(f"nvdcve-2.0-{Y - 1}", [cve(1, Y - 1)])
        net.add_cve_unit(f"nvdcve-2.0-{Y}", [cve(7, Y, pub=NOW - timedelta(days=5), confs=[conf(match("acme", "widget", vee="2.0"))]), cve(8, Y, pub=NOW - timedelta(days=5), confs=[conf(match("acme", "widget_pro"))]),
                                              cve(9, 2016, confs=[conf(match("acme", "widget", vee="1.5"))]), *extra_cves])
        net.add_cve_unit("nvdcve-2.0-modified", [])
    if with_cpe:
        net.add_tar("cpe/2.0", "nvdcpe-2.0", "products", dictionary())
    run("full", [d for d, on in (("cve", with_cve), ("cpe", with_cpe)) if on])


@pytest.fixture()
def api(env):
    return TestClient(app, client=("127.0.0.1", 7))


def add(api, product="widget", vendor="acme", part="a", category="Enterprise Applications", **kw):
    return api.post("/api/v1/products/add", json={"part": part, "vendor": vendor, "product": product, "category": category, **kw})


# ---------------------------------------------------------------- categories
def test_fifteen_categories_and_153_technologies_migrate_with_their_links(env):
    with db.connect() as c:
        cats = c.execute("SELECT id,name,active FROM technology_category ORDER BY sort_order").fetchall()
        assert len(cats) == 15 and all(r["active"] for r in cats)
        assert c.execute("SELECT COUNT(*) FROM technology").fetchone()[0] == 153 and c.execute("SELECT COUNT(*) FROM technology WHERE category_id IS NULL").fetchone()[0] == 0
        assert c.execute("SELECT COUNT(*) FROM technology t JOIN technology_category g ON g.id=t.category_id WHERE g.name=t.category").fetchone()[0] == 153
        assert [r["id"] for r in c.execute("SELECT id FROM technology WHERE dashboard=1 ORDER BY rowid")][:6] == SIX or set(SIX) <= {r["id"] for r in c.execute("SELECT id FROM technology")}
        before = c.execute("SELECT id,category,aliases,cpe_matchers,nvd_queries FROM technology WHERE id IN (%s)" % ",".join("?" * 6), SIX).fetchall()
        db.init_db()                                                                                                   # idempotent
        assert c.execute("SELECT COUNT(*) FROM technology_category").fetchone()[0] == 15 and len(before) == 6


def test_categories_are_user_managed_without_touching_code(api):
    r = api.post("/api/v1/categories", json={"name": "Data Platforms", "description": "x"})
    assert r.status_code == 200 and r.json()["active"] and api.post("/api/v1/categories", json={"name": "data platforms"}).status_code == 409
    cid = r.json()["id"]
    assert "Data Platforms" in [c["name"] for c in api.get("/api/v1/catalog/facets").json()["categories"]]            # filters update by themselves
    assert api.post("/api/v1/catalog", json={"id": "acme-x", "name": "Acme X", "category": "Data Platforms", "kind": "product"}).status_code == 201
    assert api.post("/api/v1/catalog", json={"id": "acme-y", "name": "Acme Y", "category": "Not A Category", "kind": "product"}).status_code == 422
    assert api.get(f"/api/v1/categories/{cid}/technologies").json()["items"][0]["id"] == "acme-x"
    assert api.delete(f"/api/v1/categories/{cid}").status_code == 409                                                  # still referenced
    assert api.put(f"/api/v1/categories/{cid}", json={"name": "Data & Analytics"}).json()["name"] == "Data & Analytics"
    assert api.get("/api/v1/catalog/acme-x").json()["category"] == "Data & Analytics"                                 # rename follows the stable id
    assert api.post("/api/v1/categories/assign", json={"tech_ids": ["acme-x", "windows-10"], "category": "Data & Analytics"}).json()["moved"] == 2
    with db.connect() as c:
        catalog_db.sync(c)                                                                                              # a seed sync never moves them back
        assert c.execute("SELECT category FROM technology WHERE id='windows-10'").fetchone()[0] == "Data & Analytics"
    assert api.put(f"/api/v1/categories/{cid}", json={"active": False}).json()["active"] is False
    assert api.post("/api/v1/categories/assign", json={"tech_ids": ["linux"], "category": "Data & Analytics"}).status_code == 422     # inactive: no new assignments
    assert api.get("/api/v1/catalog/windows-10").json()["category"] == "Data & Analytics"                              # existing links are kept
    order = [c["id"] for c in api.get("/api/v1/categories").json()["items"]]
    assert api.put("/api/v1/categories/order", json={"ids": list(reversed(order))}).json()["items"][0]["id"] == order[-1]
    api.post("/api/v1/categories/assign", json={"tech_ids": ["acme-x", "windows-10"], "category": "Operating Systems"})
    assert api.delete(f"/api/v1/categories/{cid}").json()["deleted"] is True                                           # deletable once nothing references it


def test_category_writes_are_protected():
    remote = TestClient(app, client=("203.0.113.5", 1))
    assert remote.post("/api/v1/categories", json={"name": "x"}).status_code == 403
    assert remote.post("/api/v1/products/add", json={"part": "a", "vendor": "acme", "product": "w", "category": "x"}).status_code == 403


# ---------------------------------------------------------------- foundation: grouping, variants, deprecation, originals
def test_cpe_dictionary_groups_versions_and_keeps_variants_and_originals(env):
    load(env)
    c = TestClient(app, client=("127.0.0.1", 7))
    items = c.get("/api/v1/products/search?q=widget").json()["items"]
    w = next(i for i in items if i["product"] == "widget")
    assert w["version_count"] == 101 and w["cpe_count"] == 102 and not w["deprecated"] and len([i for i in items if i["product"] == "widget"]) == 1
    assert {i["product"] for i in items} == {"widget", "widget_pro"}                       # similar names are different products
    d = c.get("/api/v1/products/detail?part=a&vendor=acme&product=widget").json()
    assert d["version_count"] == 101 and d["variant_count"] == 2 and {v["target_sw"] or v["edition"] for v in d["variants"]} == {"node.js", "enterprise"}
    assert d["references"][0]["url"] == "https://acme.example/widget" and d["type"] == "application" and len(d["cpe_identifiers"]) == 12
    assert c.get("/api/v1/products/versions?part=a&vendor=acme&product=widget&q=2.").json()["items"][0]["version"] == "2.0"
    with db.connect() as con:                                                              # originals preserved, refresh is idempotent
        assert con.execute("SELECT COUNT(*) FROM cpe_dictionary WHERE vendor='acme' AND product='widget'").fetchone()[0] == 102
        assert con.execute("SELECT refs FROM cpe_dictionary WHERE cpe_name LIKE 'cpe:2.3:a:acme:widget:1.7:%'").fetchone()[0].count("acme.example") == 1
        a = nvd_products.refresh(con)
        assert a == nvd_products.refresh(con) and a["products"] == 6


def test_deprecated_products_are_hidden_by_default_and_keep_their_relation(env):
    load(env)
    c = TestClient(app, client=("127.0.0.1", 7))
    assert c.get("/api/v1/products/search?q=oldthing").json()["items"] == []
    it = c.get("/api/v1/products/search?q=oldthing&deprecated=show").json()["items"]
    assert len(it) == 1 and it[0]["deprecated"] is True
    d = c.get("/api/v1/products/detail?part=a&vendor=acme&product=oldthing").json()
    assert d["deprecated"] and d["deprecated_by"] == ["cpe:2.3:a:acme:widget:1.0:*:*:*:*:*:*:*"]
    assert [i["product"] for i in c.get("/api/v1/products/search?q=acme&deprecated=only").json()["items"]] == ["oldthing"]
    assert {i["type"] for i in c.get("/api/v1/products/search?vendor=acme&part=o").json()["items"]} == {"operating system"}
    assert c.get("/api/v1/products/vendors?q=acm").json()["items"][0]["vendor"] == "acme"


def test_search_is_parameterised_and_paginated(env):
    load(env)
    c = TestClient(app, client=("127.0.0.1", 7))
    assert c.get("/api/v1/products/search", params={"q": "' OR 1=1; DROP TABLE nvd_product;--"}).status_code == 200
    assert c.get("/api/v1/products/search", params={"q": "100%_"}).json()["items"] == []
    assert q1("SELECT COUNT(*) FROM nvd_product") == 6
    p = c.get("/api/v1/products/search?page_size=3&page=2").json()
    assert p["total"] == 5 and len(p["items"]) == 2 and p["pages"] == 2
    assert c.get("/api/v1/products/search?page_size=500").status_code == 422


# ---------------------------------------------------------------- incorporation
def test_selecting_an_existing_product_never_creates_a_duplicate(env):
    load(env)
    c = TestClient(app, client=("127.0.0.1", 7))
    before = q1("SELECT COUNT(*) FROM technology")
    r = add(c, "log4j", "apache", category="DevOps & Development").json()
    assert r["created"] is False and r["already_in_catalog"] and r["technology"]["id"] == "apache-log4j"
    assert q1("SELECT COUNT(*) FROM technology") == before
    s = c.get("/api/v1/products/search?q=log4j").json()["items"][0]
    assert s["already_in_catalog"]["id"] == "apache-log4j"                                 # "Already in Technology Catalog"


def test_adding_an_nvd_product_correlates_locally_and_is_immediately_selectable(env, monkeypatch):
    load(env)
    for name in ("fetch_page", "fetch_by_cpe", "fetch_cve", "_call"):
        monkeypatch.setattr(techsync.nvd_c, name, lambda *a, **k: (_ for _ in ()).throw(AssertionError("external NVD call")))
    c = TestClient(app, client=("127.0.0.1", 7))
    assert add(c, category="Nope").status_code == 422 and add(c, product="nothere").status_code == 404
    r = add(c).json()
    tid = r["technology"]["id"]
    assert r["created"] and r["correlated_cves"] == {"recent": 1, "historical": 1} and r["technology"]["category"] == "Enterprise Applications"
    det = c.get(f"/api/v1/catalog/{tid}").json()
    assert det["recent_cve_count"] == 1 and det["historical_cve_count"] == 1 and "dictionary" in det["correlation"]["source"]
    ids = {x["id"] for x in det["cves"]} | {x["cve_id"] for x in det["historical"]["items"]}
    assert ids == {f"CVE-{Y}-0007", "CVE-2016-0009"}                                       # widget_pro's CVE is not attributed to widget (same vendor, other product)
    assert any(i["id"] == tid for i in c.get("/api/v1/catalog?q=acme").json()["items"])
    with db.connect() as con:
        catalog_db.set_dashboard(con, tid, True)                                           # selectable for the 3D dashboard right away
        assert service.build_technology(con, tid)["id"] == tid
        assert con.execute("SELECT COUNT(*) FROM technology_product WHERE tech_id=?", (tid,)).fetchone()[0] == 1
    again = add(c).json()                                                                  # second selection: reuse, no duplicate
    assert again["created"] is False and again["technology"]["id"] == tid and q1("SELECT COUNT(*) FROM technology_product WHERE part='a' AND vendor='acme' AND product='widget'") == 1
    assert c.get("/api/v1/products/search?q=widget").json()["items"][0]["already_in_catalog"]["id"] == tid
    assert c.get("/api/v1/products/monitored").json()["added_from_nvd"] == 1


def test_explicit_family_groups_products_without_merging_others(env):
    load(env)
    c = TestClient(app, client=("127.0.0.1", 7))
    r = add(c, name="Acme Widgets", family=[{"part": "a", "vendor": "acme", "product": "widget_pro"}]).json()
    tid = r["technology"]["id"]
    assert r["created"] and r["correlated_cves"]["recent"] == 2
    assert c.get(f"/api/v1/catalog/{tid}").json()["kind"] == "family"
    assert q1("SELECT COUNT(*) FROM technology_product WHERE tech_id=?", tid) == 2
    assert add(c, product="widget_pro").json()["already_in_catalog"] is True              # a member of an existing family is not duplicated


# ---------------------------------------------------------------- coverage honesty
def test_incomplete_datasets_never_look_complete_and_never_score(env):
    c = TestClient(app, client=("127.0.0.1", 7))
    s = c.get("/api/v1/products/status").json()
    assert s["state"] == "not_initialized" and s["label"] == "Dataset Not Initialized" and not s["dictionary_ready"]
    r = add(c)
    assert r.status_code == 409 and "not imported" in r.json()["detail"]                    # no dictionary: nothing to resolve, nothing invented
    assert c.get("/api/v1/products/search?q=widget").json()["total"] == 0
    load(env, with_cve=False)                                                               # dictionary only: CVE data missing
    st = c.get("/api/v1/products/status").json()
    assert st["state"] == "partial" and not st["cve_counts_reliable"] and any("CPE Match" in x for x in st["limitations"]) and any("CVE" in x for x in st["limitations"])
    d = c.get("/api/v1/products/detail?part=a&vendor=acme&product=widget").json()
    assert d["cve_count"] is None and d["cve_count_reliable"] is False and d["coverage"]["state"] == "partial"        # zero is never shown as "no vulnerabilities"
    tid = add(c).json()["technology"]["id"]
    with db.connect() as con:
        t = service.build_technology(con, tid, detail=True)
        assert t["score"] is None and t["historical"]["count"] == 0                         # no false score from an incomplete import
        assert ii.dataset_info(con, "cpematch")["status"] != "complete"


def test_complete_cve_data_exposes_counts_and_kev(env):
    load(env)
    c = TestClient(app, client=("127.0.0.1", 7))
    s = c.get("/api/v1/products/search?q=widget&sort=cves").json()
    assert s["items"][0]["cve_count"] == 2 and s["items"][1]["cve_count"] == 1 and s["items"][0]["cve_count_reliable"]
    assert c.get("/api/v1/products/status").json()["limitations"] and c.get("/api/v1/products/detail?part=a&vendor=acme&product=widget_pro").json()["cve_count"] == 1


# ---------------------------------------------------------------- inventory / watchlists / scoring
def test_company_inventory_registers_the_version_of_an_added_product(env):
    load(env)
    c = TestClient(app, client=("127.0.0.1", 7))
    tid = add(c).json()["technology"]["id"]
    sug = c.get(f"/api/v1/products/tech/{tid}/versions?q=1.5").json()
    assert sug["source"] == "NVD CPE dictionary" and [x["version"] for x in sug["items"]][0] == "1.5"
    cid = c.post("/api/v1/companies", json={"name": "Acme Corp", "industry": "Finance"}).json()["id"]
    a1 = c.post(f"/api/v1/companies/{cid}/assets", json={"tech_id": tid, "version": "1.5", "asset_ref": "SRV-1"}).json()
    a2 = c.post(f"/api/v1/companies/{cid}/assets", json={"tech_id": tid, "version": "2.1", "asset_ref": "SRV-2"}).json()
    inv = c.get(f"/api/v1/companies/{cid}/inventory").json()
    assert len(inv["technologies"]) == 1 and {a["version"] for a in inv["technologies"][0]["assets"]} == {"1.5", "2.1"} and a1["id"] != a2["id"]
    assert inv["technologies"][0]["catalog"] is True


def test_added_product_can_join_a_watchlist_and_scoring_is_untouched(env):
    load(env)
    c = TestClient(app, client=("127.0.0.1", 7))
    tid = add(c).json()["technology"]["id"]
    w = c.post("/api/v1/watchlists", json={"name": "Mine"})
    assert w.status_code in (200, 201), w.text
    wid = w.json()["id"]
    assert tid in [t["id"] for t in c.get("/api/v1/watchlists").json()["available_technologies"]]        # selectable right away
    r = c.post(f"/api/v1/watchlists/{wid}/technologies", json={"tech_id": tid})
    assert r.status_code in (200, 201), r.text
    with db.connect() as con:
        assert catalog_db.monitored_reasons(con, tid) and "in a watchlist" in catalog_db.monitored_reasons(con, tid)
    import inspect
    from app import scoring
    assert "nvd_products" not in inspect.getsource(scoring) and "technology_product" not in inspect.getsource(scoring)      # the algorithm does not know about this module


def test_tampered_cpe_archive_is_still_rejected(env):
    env.add_tar("cpe/2.0", "nvdcpe-2.0", "products", dictionary())
    k = f"{ii.NVD_FEEDS}/cpe/2.0/nvdcpe-2.0.meta"
    env.text[k] = env.text[k].replace("sha256:", "sha256:00")
    ii.start("full", ["cpe"], wait=True)
    with db.connect() as con:
        assert ii.dataset_info(con, "cpe")["status"] == "failed" and q1("SELECT COUNT(*) FROM nvd_product") == 0
