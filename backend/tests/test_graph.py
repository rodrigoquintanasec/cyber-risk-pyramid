import copy
import sys
from pathlib import Path

import pytest
from fastapi import HTTPException

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from app import attack, db, graph, graph_api  # noqa: E402
from app.config import settings  # noqa: E402
from app.news import intel, repo  # noqa: E402
from test_attack import BUNDLE  # noqa: E402


@pytest.fixture()
def con(tmp_path):
    object.__setattr__(settings, "db_path", str(tmp_path / "g.sqlite"))
    attack.reset_catalog_cache()
    graph.reset_index()
    intel.reset_cache()
    db.init_db()
    with db.connect() as c:
        attack.import_bundle(c, copy.deepcopy(BUNDLE))
        repo.sync_source_rows(c)
        c.execute("INSERT INTO nvd_cve(cve_id,published,cvss,cvss_version,description,cpes,fetched_at) VALUES('CVE-2026-0001','2026-11-01',9.8,'3.1','Forti RCE','a:fortinet:fortios,a:fortinet:fortigate','2026-11-02')")
        c.execute("INSERT INTO nvd_cve(cve_id,published,cvss,cvss_version,description,cpes,fetched_at) VALUES('CVE-2026-0002','2026-10-01',5.0,'3.1','Other','a:fortinet:fortios','2026-11-02')")
        c.execute("INSERT INTO kev_entry(cve_id,vendor,product,name,date_added,ransomware) VALUES('CVE-2026-0001','Fortinet','FortiOS','x','2026-11-05',1)")
        c.execute("INSERT INTO kev_entry(cve_id,vendor,product,name,date_added,ransomware) VALUES('CVE-2025-7777','Acme Corp','Widget Pro','y','2025-01-01',0)")
        c.execute("INSERT INTO tech_cve VALUES('fortinet','CVE-2026-0001','fortios','cpe')")
        c.execute("INSERT INTO news_item(id,source_id,guid,url,url_canon,title,summary,published,collected_at,content_hash,sort_ts) VALUES('aaaaaaaaaaaaaaaaaaaaaaaa','krebs','g','https://x/1','https://x/1','FortiOS bug CVE-2026-0001','', '2026-11-06','2026-11-06','h','2026-11-06')")
        c.execute("INSERT INTO news_cve VALUES('aaaaaaaaaaaaaaaaaaaaaaaa','CVE-2026-0001')")
        c.execute("INSERT INTO news_tech VALUES('aaaaaaaaaaaaaaaaaaaaaaaa','fortinet','name')")
    with db.connect() as c:
        yield c
    attack.reset_catalog_cache()
    object.__setattr__(settings, "db_path", str(tmp_path / "unused.sqlite"))


def ids(r, key="nodes"):
    return {x["id"] for x in r[key]}


def test_search_entities_by_type_alias_id(con):
    assert [n["id"] for n in graph.search(con, "iridium")] == ["attack:G0034"]
    assert graph.search(con, "sandworm", "threat_actor")[0]["type"] == "threat_actor"
    assert graph.search(con, "sandworm", "campaign") == []
    assert {n["id"] for n in graph.search(con, "T1059")} == {"attack:T1059", "attack:T1059.001"}
    assert [n["id"] for n in graph.search(con, "mimikatz", "tool")] == ["attack:S0002"]
    assert [n["id"] for n in graph.search(con, "CVE-2026-0001")] == ["cve:CVE-2026-0001"]
    assert "tech:fortinet" in [n["id"] for n in graph.search(con, "fortinet")] and "vendor:fortinet" in [n["id"] for n in graph.search(con, "fortinet")]
    assert [n["id"] for n in graph.search(con, "fortios", "product")] == ["product:fortinet:fortios"]
    assert [n["id"] for n in graph.search(con, "bug", "news")] == ["news:aaaaaaaaaaaaaaaaaaaaaaaa"]
    assert graph.search(con, "x") == [] and graph.search(con, "zzzzzz-none") == []
    assert graph.search(con, "Old Group") == []  # revoked never offered


def test_node_ids_and_structure_use_real_identifiers(con):
    n = graph.get_node(con, "attack:G0034")
    assert n["id"] == "attack:G0034" and n["type"] == "threat_actor" and n["label"] == "Sandworm Team" and n["source"] == "MITRE ATT&CK"
    assert n["stix_id"].startswith("intrusion-set--") and n["ref"] == {"kind": "actor", "id": "G0034"}
    assert graph.get_node(con, "attack:G4040") is None and graph.get_node(con, "cve:CVE-2000-0000") is None and graph.get_node(con, "tech:nope") is None
    assert graph.get_node(con, "attack:G0999")["revoked"] is True
    for bad in ("G0034", "attack:", "attack:G12", "cve:xyz", "tech:A B", "news:123", "x:y", "attack:G0034;DROP"):
        with pytest.raises(ValueError):
            graph.parse(bad)


def test_actor_neighbourhood_is_verified_stix_only_with_original_ids(con):
    r = graph.neighborhood(con, "attack:G0034")
    assert r["center"] == "attack:G0034"
    assert ids(r) == {"attack:G0034", "attack:T1059.001", "attack:S0368", "attack:S0002", "attack:C0001", "attack:T1059"} or ids(r) >= {"attack:G0034", "attack:T1059.001", "attack:S0368", "attack:S0002", "attack:C0001"}
    assert "attack:T1566" not in ids(r)  # deprecated technique never shown
    for e in r["edges"]:
        assert e["status"] == "verified" and e["id"].startswith("relationship--") and e["dataset"].startswith("MITRE ATT&CK") and e["modified"] and e["evidence"]
        assert e["source"] in ids(r) and e["target"] in ids(r)
    uses = {(e["source"], e["target"]) for e in r["edges"] if e["type"] == "uses"}
    assert ("attack:G0034", "attack:T1059.001") in uses and ("attack:G0034", "attack:S0368") in uses
    assert ("attack:C0001", "attack:G0034") in {(e["source"], e["target"]) for e in r["edges"] if e["type"] == "attributed-to"}
    assert not any(e["id"] == "relationship--" + "0" * 8 for e in r["edges"])


def test_no_duplicates_and_induced_relationships(con):
    r = graph.neighborhood(con, "attack:G0034", depth=2)
    assert len(r["nodes"]) == len(ids(r)) and len(r["edges"]) == len(ids(r, "edges"))
    assert ("attack:C0001", "attack:T1059") in {(e["source"], e["target"]) for e in r["edges"] if e["type"] == "uses"}  # real STIX edge between loaded nodes


def test_depth_two_reaches_further_than_one(con):
    d1 = graph.neighborhood(con, "attack:S0368", depth=1)
    d2 = graph.neighborhood(con, "attack:S0368", depth=2)
    assert "attack:G0034" in ids(d1) and "attack:C0001" not in ids(d1)
    assert "attack:C0001" in ids(d2)  # malware -> actor -> campaign


def test_relation_and_node_type_filters(con):
    r = graph.neighborhood(con, "attack:G0034", rels={"attributed-to"})
    assert {e["type"] for e in r["edges"]} == {"attributed-to"} and ids(r) == {"attack:G0034", "attack:C0001"}
    r = graph.neighborhood(con, "attack:G0034", node_types={"malware"})
    assert {n["type"] for n in r["nodes"]} == {"threat_actor", "malware"}


def test_limits_paging_and_truncation_flags(con):
    r = graph.neighborhood(con, "attack:G0034", limit=2)
    assert len(r["nodes"]) == 3 and r["page"]["has_more"] and r["truncated"] and r["page"]["total_neighbors"] >= 4
    r2 = graph.neighborhood(con, "attack:G0034", limit=2, offset=2)
    assert not (ids(r) - {"attack:G0034"}) & (ids(r2) - {"attack:G0034"})  # next page is disjoint
    r3 = graph.neighborhood(con, "attack:G0034", max_nodes=5, depth=2)
    assert len(r3["nodes"]) <= 5 and graph.limits(10**6, 10**6) == (settings.graph_max_nodes, settings.graph_max_edges)
    r4 = graph.neighborhood(con, "attack:G0034", depth=2, max_edges=10)
    assert len(r4["edges"]) <= 10


def test_unknown_entity_returns_none(con):
    assert graph.neighborhood(con, "attack:G4040") is None and graph.node_detail(con, "attack:S9999") is None


def test_cve_technology_product_vendor_relations_have_evidence(con):
    r = graph.neighborhood(con, "cve:CVE-2026-0001")
    assert {"tech:fortinet", "product:fortinet:fortios", "product:fortinet:fortigate", "news:aaaaaaaaaaaaaaaaaaaaaaaa"} <= ids(r)
    ev = {e["type"] + ":" + e["target"]: e for e in r["edges"]}
    assert ev["affects:tech:fortinet"]["status"] == "verified" and "CPE" in ev["affects:tech:fortinet"]["evidence"]
    assert ev["mentions:cve:CVE-2026-0001"]["evidence"].startswith("Article text contains the CVE id")
    pv = graph.neighborhood(con, "product:fortinet:fortios")
    assert {"vendor:fortinet", "cve:CVE-2026-0001", "cve:CVE-2026-0002"} <= ids(pv)
    assert {n["id"] for n in graph.neighborhood(con, "vendor:fortinet")["nodes"]} >= {"product:fortinet:fortios", "product:fortinet:fortigate"}
    t = graph.neighborhood(con, "tech:fortinet")
    assert "cve:CVE-2026-0001" in ids(t) and not any(n["type"] == "news" for n in t["nodes"])  # name-only news is a candidate


def test_kev_only_product_from_catalog_not_invented(con):
    r = graph.neighborhood(con, "cve:CVE-2025-7777")
    assert ids(r) == {"cve:CVE-2025-7777", "product:acme_corp:widget_pro"}
    assert [e["dataset"] for e in r["edges"]] == ["CISA KEV catalog"]


def test_candidates_hidden_by_default_and_flagged_when_requested(con):
    r = graph.neighborhood(con, "tech:fortinet", include_candidates=True)
    cand = [e for e in r["edges"] if e["status"] == "candidate"]
    assert len(cand) == 1 and cand[0]["source"] == "news:aaaaaaaaaaaaaaaaaaaaaaaa" and "unverified" in cand[0]["evidence"]
    assert all(e["status"] == "verified" for e in graph.neighborhood(con, "tech:fortinet")["edges"])


def test_news_node_links_only_explicit_ids(con):
    r = graph.neighborhood(con, "news:aaaaaaaaaaaaaaaaaaaaaaaa")
    assert ids(r) == {"news:aaaaaaaaaaaaaaaaaaaaaaaa", "cve:CVE-2026-0001"}  # no actor/technology invented
    assert graph.neighborhood(con, "news:aaaaaaaaaaaaaaaaaaaaaaaa", include_candidates=True)["edges"][-1]["status"] in ("verified", "candidate")


def test_edge_detail_stix_and_derived(con):
    r = graph.neighborhood(con, "attack:G0034")
    e = next(x for x in r["edges"] if x["type"] == "uses" and x["target"] == "attack:T1059.001")
    d = graph.edge_detail(con, e["id"])
    assert d["source"]["id"] == "attack:G0034" and d["target"]["id"] == "attack:T1059.001" and d["edge"]["type"] == "uses" and d["evidence_id"] == e["id"]
    assert d["edge"]["modified"] and d["references"][0]["url"] == "https://example.com/r" and "not confirmation of attribution" in d["interpretation"]
    c = graph.neighborhood(con, "cve:CVE-2026-0001")
    de = next(x for x in c["edges"] if x["target"] == "tech:fortinet")
    dd = graph.edge_detail(con, de["id"])
    assert dd["source"]["id"] == "cve:CVE-2026-0001" and dd["target"]["id"] == "tech:fortinet" and dd["edge"]["status"] == "verified"
    assert graph.edge_detail(con, "relationship--" + "0" * 8 + "-0000-4000-8000-" + "0" * 12) is None
    assert graph.edge_detail(con, "derived:affects:cve:CVE-2026-0002|tech:fortinet") is None  # relation does not exist -> not invented
    for bad in ("nope", "derived:x:y", "relationship--zzz"):
        with pytest.raises(ValueError):
            graph.edge_detail(con, bad)


def test_node_detail_lists_available_relations(con):
    d = graph.node_detail(con, "attack:G0034")
    assert d["aliases"] == ["IRIDIUM", "Seashell Blizzard"] and "Citation" not in d["description"] and d["url"].endswith("/groups/G0034/")
    rel = {x["relation"]: x["counts"] for x in d["available_relations"]}
    assert rel["uses (outgoing)"]["malware"] == 1 and rel["attributed-to (incoming)"]["campaign"] == 1
    assert graph.node_detail(con, "cve:CVE-2026-0001")["details"]["in_kev"] is True


def test_api_validation_and_errors(con):
    with pytest.raises(HTTPException) as e:
        graph_api.graph_neighbors(node="attack:G4040", depth=1, rel=None, node_types=None, include_candidates=False, limit=40, offset=0, max_nodes=None, max_edges=None)
    assert e.value.status_code == 404
    for kw in ({"node": "bogus"}, {"node": "attack:G0034", "rel": "owns"}, {"node": "attack:G0034", "node_types": "alien"}):
        with pytest.raises(HTTPException) as e:
            graph_api.graph_neighbors(**{"depth": 1, "rel": None, "node_types": None, "include_candidates": False, "limit": 40, "offset": 0, "max_nodes": None, "max_edges": None, **kw})
        assert e.value.status_code == 422
    out = graph_api.graph_neighbors(node="attack:g0034", depth=1, rel="uses,attributed-to", node_types=None, include_candidates=False, limit=40, offset=0, max_nodes=None, max_edges=None)
    assert out["center"] == "attack:G0034"  # id normalised
    with pytest.raises(HTTPException):
        graph_api.graph_edge(id="garbage")
    with pytest.raises(HTTPException):
        graph_api.graph_search(q="x", type="alien", limit=5)


def test_graph_is_read_only(con):
    tables = ("stix_object", "stix_rel", "nvd_cve", "tech_cve", "news_item", "news_cve")
    before = [con.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0] for t in tables]
    graph.neighborhood(con, "attack:G0034", depth=2)
    graph.neighborhood(con, "cve:CVE-2026-0001", depth=2, include_candidates=True)
    assert before == [con.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0] for t in tables]
