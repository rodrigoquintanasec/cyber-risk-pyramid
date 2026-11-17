import copy
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app import attack, attack_news, db  # noqa: E402
from app.config import settings  # noqa: E402
from app.news import entities as ent, intel, repo  # noqa: E402


def sid(t, n):
    return f"{t}--{n:08x}-0000-4000-8000-{n:012x}"


def ref(aid, src="mitre-attack"):
    return [{"source_name": src, "external_id": aid, "url": "https://attack.mitre.org/x/"}]


def obj(t, n, name, aid, **kw):
    return {"type": t, "id": sid(t, n), "name": name, "description": kw.pop("description", f"{name} desc (Citation: Foo) see [T1059](https://attack.mitre.org/techniques/T1059)"),
            "created": "2020-01-01T00:00:00.000Z", "modified": kw.pop("modified", "2025-01-01T00:00:00.000Z"),
            "external_references": ref(aid) + kw.pop("extra_refs", []), **kw}


def rel(n, s, t, rt, **kw):
    return {"type": "relationship", "id": sid("relationship", n), "relationship_type": rt, "source_ref": s, "target_ref": t,
            "modified": "2025-02-01T00:00:00.000Z", "external_references": [{"source_name": "rep", "description": "Report", "url": "https://example.com/r"}], **kw}


G1, G2, G3, C1, C2, T1, T2, T3, M1, TL1 = (sid("intrusion-set", 1), sid("intrusion-set", 2), sid("intrusion-set", 3), sid("campaign", 1), sid("campaign", 2),
                                             sid("attack-pattern", 1), sid("attack-pattern", 2), sid("attack-pattern", 3), sid("malware", 1), sid("tool", 1))
BUNDLE = {"type": "bundle", "id": "bundle--1", "objects": [
    {"type": "x-mitre-collection", "id": "x-mitre-collection--1", "x_mitre_version": "99.0"},
    obj("intrusion-set", 1, "Sandworm Team", "G0034", aliases=["Sandworm Team", "IRIDIUM", "Seashell Blizzard"]),
    obj("intrusion-set", 2, "Cozy Group", "G0100", aliases=["Cozy Group", "Shared Alias"]),
    obj("intrusion-set", 3, "Other Group", "G0101", aliases=["Other Group", "Shared Alias"]),
    obj("intrusion-set", 4, "Old Group", "G0999", revoked=True),
    obj("campaign", 1, "Operation Skyfall", "C0001", first_seen="2022-02-01T00:00:00.000Z", last_seen="2022-03-01T00:00:00.000Z"),
    obj("campaign", 2, "Orphan Campaign Thing", "C0002"),
    obj("attack-pattern", 1, "Command and Scripting Interpreter", "T1059", kill_chain_phases=[{"kill_chain_name": "mitre-attack", "phase_name": "execution"}], x_mitre_is_subtechnique=False),
    obj("attack-pattern", 2, "PowerShell", "T1059.001", kill_chain_phases=[{"kill_chain_name": "mitre-attack", "phase_name": "execution"}], x_mitre_is_subtechnique=True),
    obj("attack-pattern", 3, "Phishing", "T1566", x_mitre_deprecated=True),
    obj("malware", 1, "NotPetya", "S0368", x_mitre_aliases=["NotPetya", "ExPetr"]),
    obj("tool", 1, "Mimikatz", "S0002", x_mitre_aliases=["Mimikatz"]),
    rel(1, G1, T2, "uses"), rel(2, G1, M1, "uses"), rel(3, G1, TL1, "uses"), rel(4, C1, G1, "attributed-to"), rel(5, C1, T1, "uses"),
    rel(6, T2, T1, "subtechnique-of"), rel(7, G2, T1, "uses"), rel(8, G1, T3, "uses"),
    rel(9, G2, T2, "uses", revoked=True), rel(10, M1, T2, "uses"),
    rel(11, G1, sid("attack-pattern", 99), "uses"),           # unknown endpoint -> skipped
    rel(12, G1, M1, "mitigates"),                              # unsupported type -> skipped
    {"type": "attack-pattern", "id": "bad", "name": "Broken"},                                  # invalid -> skipped
    {**obj("malware", 2, "NoId", "X1"), "external_references": [{"source_name": "mitre-attack", "external_id": "S12"}]},  # invalid ATT&CK id
]}


@pytest.fixture()
def con(tmp_path):
    object.__setattr__(settings, "db_path", str(tmp_path / "a.sqlite"))
    attack.reset_catalog_cache()
    db.init_db()
    with db.connect() as c:
        attack.import_bundle(c, copy.deepcopy(BUNDLE))
    with db.connect() as c:
        yield c
    attack.reset_catalog_cache()
    object.__setattr__(settings, "db_path", str(tmp_path / "unused.sqlite"))


def test_import_counts_validation_and_skips(tmp_path):
    object.__setattr__(settings, "db_path", str(tmp_path / "b.sqlite"))
    db.init_db()
    with db.connect() as c:
        r = attack.import_bundle(c, copy.deepcopy(BUNDLE))
        assert r["objects_imported"] == 11 and r["objects_skipped"] == 2 and r["relationships_imported"] == 10 and r["relationships_skipped"] == 2
    with pytest.raises(ValueError):
        with db.connect() as c:
            attack.import_bundle(c, {"type": "nope"})


def test_idempotent_import_and_stable_update(con):
    n = lambda t: con.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]  # noqa: E731
    before = (n("stix_object"), n("stix_rel"))
    b = copy.deepcopy(BUNDLE)
    b["objects"][1]["name"] = "Sandworm Team (renamed)"
    b["objects"][1]["modified"] = "2026-01-01T00:00:00.000Z"
    attack.import_bundle(con, b)
    assert (n("stix_object"), n("stix_rel")) == before
    a = attack.actor_detail(con, "G0034")
    assert a["name"] == "Sandworm Team (renamed)" and a["modified"].startswith("2026")


def test_revoked_and_deprecated_excluded_but_kept(con):
    assert attack.list_actors(con)["total"] == 3
    assert attack.actor_detail(con, "G0999")["revoked"] is True  # still resolvable
    assert attack.list_actors(con, q="Old Group")["total"] == 0
    a = attack.actor_detail(con, "G0034")
    assert "T1566" not in [t["id"] for t in a["techniques"]]  # deprecated technique hidden
    st = attack.status(con)
    assert st["counts"]["actors"] == 3 and st["counts"]["techniques"] == 2 and st["counts"]["revoked_or_deprecated_objects"] == 2


def test_actor_detail_relations_evidence_and_clean_description(con):
    a = attack.actor_detail(con, "G0034")
    assert a["aliases"] == ["IRIDIUM", "Seashell Blizzard"] and "Citation" not in a["description"] and "](" not in a["description"]
    assert [t["id"] for t in a["techniques"]] == ["T1059.001"]
    rel_ = a["techniques"][0]["relationship"]
    assert rel_["status"] == "confirmed" and rel_["evidence_id"].startswith("relationship--") and rel_["source"].startswith("MITRE ATT&CK STIX") and rel_["modified"]
    assert {s["id"] for s in a["software"]} == {"S0368", "S0002"} and {s["type"] for s in a["software"]} == {"malware", "tool"}
    assert [c["id"] for c in a["campaigns"]] == ["C0001"] and a["url"].endswith("/groups/G0034/")
    assert attack.actor_detail(con, "G0034")["stix_id"] == attack.actor_detail(con, sid("intrusion-set", 1))["stix_id"]
    assert attack.actor_detail(con, "T1059") is None  # wrong type
    assert attack.actor_detail(con, "G4040") is None


def test_campaign_detail_and_unattributed(con):
    c = attack.campaign_detail(con, "C0001")
    assert c["first_seen"].startswith("2022-02") and [a["id"] for a in c["actors"]] == ["G0034"] and [t["id"] for t in c["techniques"]] == ["T1059"]
    assert attack.campaign_detail(con, "C0002")["actors"] == []  # no invented attribution


def test_technique_and_software_navigation(con):
    t = attack.technique_detail(con, "T1059")
    assert [s["id"] for s in t["subtechniques"]] == ["T1059.001"] and {a["id"] for a in t["actors"]} == {"G0100"} and [c["id"] for c in t["campaigns"]] == ["C0001"]
    sub = attack.technique_detail(con, "T1059.001")
    assert sub["parent"]["id"] == "T1059" and [a["id"] for a in sub["actors"]] == ["G0034"]  # revoked G2 link excluded
    assert [x["id"] for x in sub["software"]] == ["S0368"]
    sw = attack.software_detail(con, "S0368")
    assert [a["id"] for a in sw["actors"]] == ["G0034"] and [t["id"] for t in sw["techniques"]] == ["T1059.001"]


def test_filters(con):
    assert [a["id"] for a in attack.list_actors(con, q="iridium")["items"]] == ["G0034"]  # alias search
    assert [a["id"] for a in attack.list_actors(con, q="G0100")["items"]] == ["G0100"]
    assert [a["id"] for a in attack.list_actors(con, technique="T1059.001")["items"]] == ["G0034"]
    assert {a["id"] for a in attack.list_actors(con, technique="T1059")["items"]} == {"G0100", "G0034"}  # parent id includes sub-techniques
    assert [a["id"] for a in attack.list_actors(con, software="S0002")["items"]] == ["G0034"]
    assert [a["id"] for a in attack.list_actors(con, campaign="C0001")["items"]] == ["G0034"]
    assert [c["id"] for c in attack.list_campaigns(con, group="G0034")["items"]] == ["C0001"]
    assert [c["id"] for c in attack.list_campaigns(con, technique="T1059")["items"]] == ["C0001"]
    assert attack.list_campaigns(con, q="orphan")["total"] == 1
    assert attack.list_actors(con, page_size=2)["pages"] == 2 and [a["counts"]["techniques"] for a in attack.list_actors(con, sort="techniques")["items"]] == [1, 1, 0]
    assert attack.list_actors(con, q="'; DROP TABLE stix_object;--")["total"] == 0 and con.execute("SELECT COUNT(*) FROM stix_object").fetchone()[0] == 11


def test_relationship_listing_has_graph_ready_fields(con):
    r = attack.relationships(con, source="G0034", rel_type="uses")
    assert r["total"] == 3
    x = r["items"][0]
    assert x["source"]["id"] == "G0034" and x["type"] == "uses" and x["evidence_id"] and x["dataset"] and x["modified"] and x["status"] == "confirmed" and x["target"]["stix_id"]
    assert attack.relationships(con, target="T1059.001", source="G0034")["total"] == 1
    assert attack.relationships(con, source="G9999")["total"] == 0


def test_catalog_reuses_imported_techniques(con):
    cat = ent.mitre_catalog()
    assert set(cat["techniques"]) == {"T1059", "T1059.001"}  # deprecated T1566 excluded
    assert [t["id"] for t in ent.extract("Abuse of T1059.001 seen", "")["mitre"]] == ["T1059.001"]


def test_fetch_rejects_untrusted_urls():
    for u in ("http://raw.githubusercontent.com/x.json", "https://evil.example.com/a.json", "https://127.0.0.1/a.json"):
        with pytest.raises(ValueError):
            attack.fetch_bundle(u, None, None)


def test_needs_sync_rules(con):
    assert attack.needs_sync(con) is True
    old = (datetime.now(timezone.utc) - timedelta(hours=500)).isoformat(timespec="seconds")
    con.execute("INSERT INTO stix_sync(key,last_success,status) VALUES('enterprise-attack',?,'ok')", (old,))
    assert attack.needs_sync(con) is True
    con.execute("UPDATE stix_sync SET last_success=?", (db.now_iso(),))
    assert attack.needs_sync(con) is False


# ---------------------------------------------------------------- news linking
def _item(i, title, summary=""):
    ts = datetime.now(timezone.utc) - timedelta(hours=i)
    return {"id": f"id{i:04d}xxxxxxxxxxxxxxxx", "title": title, "summary": summary, "url": f"https://x/{i}", "source_id": "krebs", "source_name": "Krebs",
            "source_type": "news", "published": ts.isoformat(), "collected_at": ts.isoformat(), "updated_at": None, "ts": ts, "categories": [], "techs": [], "cves": [],
            "entities": ent.extract(title, summary), "tokens": intel.tokens(title), "topics": [], "official": False}


def test_news_links_only_on_explicit_evidence(con, monkeypatch):
    items = [_item(1, "Report cites G0034 in new wiper campaign"), _item(2, "Details at attack.mitre.org/groups/G0034 for the intrusion"),
             _item(3, "Sandworm Team blamed for outage"), _item(4, "Shared Alias is mentioned here"), _item(5, "The silence of the lambs"),
             _item(6, "Cozy Group exploits router"), _item(7, "Unrelated G9999 id and T1059 mention"), _item(8, "Sandworm Team mentioned only in summary", "details")]
    items.append(_item(9, "Weekly roundup", "Sandworm Team appears in the body only"))
    corpus = intel.Corpus(items, intel.build_clusters(items), {}, datetime.now(timezone.utc))
    monkeypatch.setattr(intel, "get_corpus", lambda con=None: corpus)
    attack_news._cache.update(key=None)
    n = attack_news.news_for("G0034")
    assert {a["id"] for a in n["confirmed"]} == {items[0]["id"], items[1]["id"]}
    assert {a["id"] for a in n["candidates"]} == {items[2]["id"], items[7]["id"]}  # title name mention = candidate only; body-only not linked
    assert "not attribution" in n["rule"]
    assert attack_news.news_for("G0101")["confirmed_total"] == 0 and attack_news.news_for("G0101")["candidates_total"] == 0  # ambiguous alias never linked
    assert [a["id"] for a in attack_news.news_for("G0100")["candidates"]] == [items[5]["id"]]
