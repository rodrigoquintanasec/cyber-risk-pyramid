"""Threat Relationship Graph service. Builds bounded neighbourhoods on demand from tables that already exist in SQLite.

Nothing is stored or invented here: every edge is read from (or re-derived from) a real record and carries its type, dataset,
evidence, date and validation status.
  verified  : documented explicitly by a structured source — MITRE ATT&CK STIX relationships; NVD CPE / CISA KEV product data;
              tech_cve (CPE/KEV correlation); an article that writes a CVE id, an ATT&CK id or a technique id explicitly.
  candidate : keyword/name mentions only (name in a headline, product name in text). Hidden unless include_candidates=true.
Node ids: attack:<ATT&CK id> · cve:<CVE> · tech:<catalog id> · vendor:<slug> · product:<vendor>:<product> · news:<id>.
Edge ids: the STIX relationship id for ATT&CK edges, otherwise derived:<rel>:<source node>|<target node>.
"""
from __future__ import annotations

import json
import re
import threading
from collections import Counter, defaultdict

from . import attack, attack_news, db
from .catalog import BY_ID, CATALOG
from .config import settings
from .news import intel

NODE_TYPES = ["threat_actor", "campaign", "technique", "malware", "tool", "cve", "technology", "product", "vendor", "news"]
REL_TYPES = ["uses", "attributed-to", "subtechnique-of", "affects", "belongs_to", "mentions"]
STIX_TYPE = {"intrusion-set": "threat_actor", "campaign": "campaign", "attack-pattern": "technique", "malware": "malware", "tool": "tool"}
TYPE_STIX = {v: k for k, v in STIX_TYPE.items()}
ORDER = {t: i for i, t in enumerate(["campaign", "threat_actor", "malware", "tool", "technique", "technology", "cve", "product", "vendor", "news"])}
NODE_ID_RE = re.compile(r"^(attack:(?:[GCS]\d{4}|T\d{4}(?:\.\d{3})?)|cve:CVE-\d{4}-\d{4,7}|tech:[a-z0-9\-]{1,40}|vendor:[a-z0-9_.\-+]{1,80}|product:[a-z0-9_.\-+]{1,80}:[a-z0-9_.\-+]{1,120}|news:[0-9a-f]{24})$")
EDGE_ID_RE = re.compile(r"^(relationship--[0-9a-f\-]{36}|derived:[a-z\-]+:[A-Za-z0-9:_.\-+]{3,300}\|[A-Za-z0-9:_.\-+]{3,300})$")
NOTES = {
    "uses": "MITRE documents that the source uses the target (capability or tooling). It is not confirmation of attribution for any specific incident.",
    "attributed-to": "MITRE attributes the campaign to the group in its published STIX relationship, with the references listed as evidence.",
    "subtechnique-of": "Hierarchy inside the ATT&CK matrix.",
    "affects": "The CVE record lists the target product/technology as affected (NVD CPE configuration, CISA KEV entry or the catalogue correlation).",
    "belongs_to": "The product identifier is published under this vendor in the CPE dictionary.",
    "mentions": "The article names the target explicitly. A mention is not an attribution or confirmation of the event.",
}
_idx_lock = threading.Lock()
_idx: dict = {"sig": None, "v": None}


def slug(s: str) -> str:
    return re.sub(r"[^a-z0-9_.\-+]", "_", (s or "").strip().lower())[:100] or "unknown"


def pretty(s: str) -> str:
    return s.replace("_", " ")


# ---------------------------------------------------------------- nodes
def attack_node(r) -> dict:
    t = STIX_TYPE[r["type"]]
    return {"id": f"attack:{r['attack_id']}", "type": t, "label": r["name"], "source": "MITRE ATT&CK", "stix_id": r["stix_id"], "external_id": r["attack_id"],
            "ref": {"kind": attack.KIND[r["type"]], "id": r["attack_id"]}, "revoked": bool(r["revoked"] or r["deprecated"])}


def cve_node(cve_id: str, in_kev: bool = False) -> dict:
    return {"id": f"cve:{cve_id}", "type": "cve", "label": cve_id, "source": "NVD / CISA KEV", "external_id": cve_id, "ref": {"kind": "cve", "id": cve_id}, "in_kev": in_kev}


def tech_node(tid: str) -> dict:
    return {"id": f"tech:{tid}", "type": "technology", "label": BY_ID[tid].name, "source": "Monitored catalogue", "external_id": tid, "ref": {"kind": "technology", "id": tid}}


def vendor_node(v: str) -> dict:
    return {"id": f"vendor:{v}", "type": "vendor", "label": pretty(v), "source": "NVD CPE", "external_id": v, "ref": {"kind": "vendor", "id": v}}


def product_node(v: str, p: str) -> dict:
    return {"id": f"product:{v}:{p}", "type": "product", "label": f"{pretty(v)} {pretty(p)}", "source": "NVD CPE", "external_id": f"{v}:{p}", "ref": {"kind": "product", "id": f"{v}:{p}", "vendor": v}}


def news_node(r) -> dict:
    return {"id": f"news:{r['id']}", "type": "news", "label": r["title"][:120], "source": r["source_name"], "external_id": r["id"], "url": r["url"],
            "published": r["published"] or r["collected_at"], "ref": {"kind": "news", "id": r["id"]}}


def edge(eid, src, dst, rel, evidence, status="verified", dataset="", modified=None, **extra) -> dict:
    return {"id": eid, "source": src, "target": dst, "type": rel, "evidence": evidence, "status": "verified" if status in ("confirmed", "verified") else status, "dataset": dataset, "modified": modified, **extra}


def dedge(rel, src, dst, evidence, dataset, status="verified", modified=None, **extra) -> dict:
    return edge(f"derived:{rel}:{src}|{dst}", src, dst, rel, evidence, status, dataset, modified, **extra)


# ---------------------------------------------------------------- product / vendor index (from CPE data)
def _index(con) -> dict:
    sig = (con.execute("SELECT COUNT(*), MAX(fetched_at) FROM nvd_cve").fetchone()[:], con.execute("SELECT COUNT(*), MAX(nvd_fetched_at) FROM intel_cve").fetchone()[:],
           con.execute("SELECT COUNT(*) FROM kev_entry").fetchone()[0])
    with _idx_lock:
        if _idx["sig"] == sig:
            return _idx["v"]
    by_prod: dict[tuple[str, str], dict[str, str]] = defaultdict(dict)   # (vendor, product) -> {cve: published}
    cve_prods: dict[str, list[tuple[str, str]]] = {}
    for table in ("nvd_cve", "intel_cve"):
        for r in con.execute(f"SELECT cve_id, published, cpes FROM {table} WHERE cpes IS NOT NULL AND cpes!=''"):
            if r["cve_id"] in cve_prods:
                continue
            prods = []
            for c in r["cpes"].split(","):
                parts = c.split(":")
                if len(parts) >= 3 and parts[1] and parts[2]:
                    prods.append((parts[1], parts[2]))
                    by_prod[(parts[1], parts[2])][r["cve_id"]] = r["published"] or ""
            cve_prods[r["cve_id"]] = sorted(set(prods))
    kev_only: dict[str, tuple[str, str]] = {}
    for r in con.execute("SELECT cve_id, vendor, product, date_added FROM kev_entry"):
        if r["cve_id"] not in cve_prods and r["vendor"]:
            vp = (slug(r["vendor"]), slug(r["product"] or "unknown"))
            kev_only[r["cve_id"]] = vp
            by_prod[vp][r["cve_id"]] = r["date_added"] or ""
    vendors: dict[str, Counter] = defaultdict(Counter)
    for (v, p), cves in by_prod.items():
        vendors[v][p] = len(cves)
    val = {"by_prod": by_prod, "cve_prods": cve_prods, "kev_only": kev_only, "vendors": vendors}
    with _idx_lock:
        _idx.update(sig=sig, v=val)
    return val


class _LegacyIx:
    """In-memory product index (small / not-yet-imported databases)."""
    def __init__(self, ix: dict):
        self.ix = ix

    def has_vendor(self, v): return v in self.ix["vendors"]
    def has_product(self, v, p): return (v, p) in self.ix["by_prod"]
    def cve_products(self, cve):
        return self.ix["cve_prods"].get(cve) or ([self.ix["kev_only"][cve]] if cve in self.ix["kev_only"] else []), ("NVD CPE" if cve in self.ix["cve_prods"] else "CISA KEV catalog")
    def product_cves(self, v, p, n=25): return sorted(self.ix["by_prod"].get((v, p), {}).items(), key=lambda kv: kv[1], reverse=True)[:n]
    def vendor_products(self, v, n=40): return self.ix["vendors"].get(v, Counter()).most_common(n)
    def search_vendors(self, ql, n=5): return [v for v in sorted(self.ix["vendors"], key=lambda v: (-sum(self.ix["vendors"][v].values()), v)) if ql in v][:n]
    def search_products(self, ql, n=6): return [k for k in sorted(self.ix["by_prod"], key=lambda k: (-len(self.ix["by_prod"][k]), k)) if ql in k[1] or ql in f"{k[0]}_{k[1]}"][:n]


class _SqlIx:
    """Product index over the LOCAL intelligence database (indexed SQL; nothing is loaded into memory)."""
    def __init__(self, con):
        self.con = con

    def has_vendor(self, v): return self.con.execute("SELECT 1 FROM cve_product_stats WHERE vendor=? LIMIT 1", (v,)).fetchone() is not None
    def has_product(self, v, p): return self.con.execute("SELECT 1 FROM cve_product_stats WHERE vendor=? AND product=?", (v, p)).fetchone() is not None
    def cve_products(self, cve):
        rows = [(r[0], r[1]) for r in self.con.execute("SELECT DISTINCT vendor,product FROM cve_cpe WHERE cve_id=? ORDER BY vendor,product LIMIT 12", (cve,))]
        if rows:
            return rows, "NVD CPE"
        k = self.con.execute("SELECT vendor,product FROM kev_entry WHERE cve_id=?", (cve,)).fetchone()
        return ([(slug(k["vendor"]), slug(k["product"] or "unknown"))] if k and k["vendor"] else []), "CISA KEV catalog"
    def product_cves(self, v, p, n=25):
        return [(r[0], r[1] or "") for r in self.con.execute("SELECT m.cve_id, n.published FROM (SELECT DISTINCT cve_id FROM cve_cpe WHERE vendor=? AND product=?) m LEFT JOIN nvd_cve n ON n.cve_id=m.cve_id "
                                                            "ORDER BY n.published DESC LIMIT ?", (v, p, n))]
    def vendor_products(self, v, n=40): return [(r[0], r[1]) for r in self.con.execute("SELECT product,cves FROM cve_product_stats WHERE vendor=? ORDER BY cves DESC LIMIT ?", (v, n))]
    def search_vendors(self, ql, n=5):
        return [r[0] for r in self.con.execute("SELECT vendor FROM cve_product_stats WHERE vendor LIKE ? ESCAPE '!' GROUP BY vendor ORDER BY SUM(cves) DESC LIMIT ?", ("%" + ql.replace("!", "!!").replace("%", "!%").replace("_", "!_") + "%", n))]
    def search_products(self, ql, n=6):
        like = "%" + ql.replace("!", "!!").replace("%", "!%").replace("_", "!_") + "%"
        return [(r[0], r[1]) for r in self.con.execute("SELECT vendor,product FROM cve_product_stats WHERE product LIKE ? ESCAPE '!' OR (vendor || '_' || product) LIKE ? ESCAPE '!' ORDER BY cves DESC LIMIT ?", (like, like, n))]


def _ix(con):
    if con.execute("SELECT 1 FROM cve_product_stats LIMIT 1").fetchone():
        return _SqlIx(con)
    return _LegacyIx(_index(con))


def reset_index() -> None:
    with _idx_lock:
        _idx.update(sig=None, v=None)


# ---------------------------------------------------------------- node lookup
def parse(nid: str) -> tuple[str, str]:
    if not isinstance(nid, str) or not NODE_ID_RE.match(nid):
        raise ValueError("Invalid node id")
    k, _, v = nid.partition(":")
    return k, v


def get_node(con, nid: str) -> dict | None:
    kind, key = parse(nid)
    if kind == "attack":
        r = attack.resolve(con, key)
        return attack_node(r) if r else None
    if kind == "cve":
        row = con.execute("SELECT 1 FROM (SELECT cve_id FROM nvd_cve UNION SELECT cve_id FROM kev_entry UNION SELECT cve_id FROM news_cve UNION SELECT cve_id FROM intel_cve WHERE nvd_fetched_at IS NOT NULL) WHERE cve_id=?", (key,)).fetchone()
        return cve_node(key, bool(con.execute("SELECT 1 FROM kev_entry WHERE cve_id=?", (key,)).fetchone())) if row else None
    if kind == "tech":
        return tech_node(key) if key in BY_ID else None
    if kind == "vendor":
        return vendor_node(key) if _ix(con).has_vendor(key) else None
    if kind == "product":
        v, _, p = key.partition(":")
        return product_node(v, p) if _ix(con).has_product(v, p) else None
    r = con.execute("SELECT n.*, s.name AS source_name FROM news_item n JOIN news_source s ON s.id=n.source_id WHERE n.id=?", (key,)).fetchone()
    return news_node(r) if r else None


# ---------------------------------------------------------------- neighbours (all candidates for one node; caller pages them)
CAP = 600  # absolute SQL-level bound per node


def _stix_pairs(con, node, rels):
    out = []
    wanted = [r for r in ("uses", "attributed-to", "subtechnique-of") if r in rels]
    if not wanted:
        return out
    ph = ",".join("?" * len(wanted))
    r0 = attack.resolve(con, node["external_id"])
    sid = r0["stix_id"]
    for outgoing in (True, False):
        a, b = ("source_ref", "target_ref") if outgoing else ("target_ref", "source_ref")
        rows = con.execute(
            f"SELECT o.*, r.stix_id AS rid, r.rel_type AS rt, r.modified AS rmod, r.evidence_refs AS rrefs, r.status AS rstatus, r.source AS rsrc, r.source_ref AS rs, r.target_ref AS rtg "
            f"FROM stix_rel r JOIN stix_object o ON o.stix_id=r.{b} WHERE r.{a}=? AND r.rel_type IN ({ph}) AND r.revoked=0 AND r.deprecated=0 AND o.revoked=0 AND o.deprecated=0 "
            f"ORDER BY o.name COLLATE NOCASE LIMIT ?", (sid, *wanted, CAP)).fetchall()
        for r in rows:
            other = attack_node(r)
            s_id, t_id = (node["id"], other["id"]) if outgoing else (other["id"], node["id"])
            out.append((other, edge(r["rid"], s_id, t_id, r["rt"], "MITRE ATT&CK STIX relationship", r["rstatus"], r["rsrc"], r["rmod"], stix_id=r["rid"])))
    return out


def _news_rows(con, ids):
    if not ids:
        return {}
    ph = ",".join("?" * len(ids))
    return {r["id"]: r for r in con.execute(f"SELECT n.*, s.name AS source_name FROM news_item n JOIN news_source s ON s.id=n.source_id WHERE n.id IN ({ph})", list(ids))}


def _news_edge(nrow, target, rel_evidence, status, dataset):
    n = news_node(nrow)
    return n, dedge("mentions", n["id"], target, rel_evidence, dataset, status, nrow["published"] or nrow["collected_at"])


def neighbors(con, node: dict, rels: set[str], include_candidates: bool = False, news_limit: int = 6) -> list[tuple[dict, dict]]:
    kind, key = parse(node["id"])
    out: list[tuple[dict, dict]] = []
    if kind == "attack":
        out += _stix_pairs(con, node, rels)
        if "mentions" in rels:
            corpus = intel.get_corpus(con)
            items = []
            if node["type"] in ("threat_actor", "campaign"):
                d = attack_news._scan(corpus, con).get(key, {"confirmed": [], "candidates": []})
                items += [(m, "verified", "Article cites the ATT&CK id or MITRE page explicitly") for m in d["confirmed"]]
                if include_candidates:
                    items += [(m, "candidate", "Distinctive name in the headline (unverified, not attribution)") for m in d["candidates"]]
            elif node["type"] == "technique":
                items += [(m, "verified", "Article writes the ATT&CK technique id explicitly") for m in attack_news.technique_mentions(corpus).get(key, [])]
            items.sort(key=lambda x: x[0]["ts"], reverse=True)
            rows = _news_rows(con, [m["id"] for m, _, _ in items[:news_limit]])
            for m, status, ev in items[:news_limit]:
                if m["id"] in rows:
                    n, e = _news_edge(rows[m["id"]], node["id"], ev, status, "Intelligence Feed (RSS)")
                    out.append((n, e))
    elif kind == "cve":
        if "affects" in rels:
            for r in con.execute("SELECT t.tech_id, t.match_source, n.fetched_at FROM tech_cve t LEFT JOIN nvd_cve n ON n.cve_id=t.cve_id WHERE t.cve_id=?", (key,)):
                ev = "CISA KEV vendor/product match" if r["match_source"] and "kev" in r["match_source"] else "NVD CPE configuration match"
                tn = tech_node(r["tech_id"])
                out.append((tn, dedge("affects", node["id"], tn["id"], ev, "NVD / CISA KEV correlation", modified=r["fetched_at"])))
            prods, ds = _ix(con).cve_products(key)
            for v, p in prods[:12]:
                pn = product_node(v, p)
                out.append((pn, dedge("affects", node["id"], pn["id"], f"{ds}: {v}:{p}", ds)))
        if "mentions" in rels:
            for r in con.execute("SELECT n.*, s.name AS source_name FROM news_cve c JOIN news_item n ON n.id=c.news_id JOIN news_source s ON s.id=n.source_id WHERE c.cve_id=? ORDER BY n.sort_ts DESC LIMIT ?", (key, news_limit)):
                out.append(_news_edge(r, node["id"], "Article text contains the CVE id explicitly", "verified", "Intelligence Feed (RSS)"))
    elif kind == "tech":
        if "affects" in rels:
            for r in con.execute("SELECT t.cve_id, t.match_source, n.fetched_at, k.cve_id AS kev FROM tech_cve t LEFT JOIN nvd_cve n ON n.cve_id=t.cve_id LEFT JOIN kev_entry k ON k.cve_id=t.cve_id "
                                 "WHERE t.tech_id=? ORDER BY k.cve_id IS NULL, n.published DESC LIMIT 40", (key,)):
                ev = "CISA KEV vendor/product match" if r["match_source"] and "kev" in r["match_source"] else "NVD CPE configuration match"
                cn = cve_node(r["cve_id"], bool(r["kev"]))
                out.append((cn, dedge("affects", cn["id"], node["id"], ev, "NVD / CISA KEV correlation", modified=r["fetched_at"])))
        if "mentions" in rels and include_candidates:
            for r in con.execute("SELECT n.*, s.name AS source_name FROM news_tech t JOIN news_item n ON n.id=t.news_id JOIN news_source s ON s.id=n.source_id WHERE t.tech_id=? AND t.basis='name' ORDER BY n.sort_ts DESC LIMIT ?", (key, news_limit)):
                out.append(_news_edge(r, node["id"], "Product name appears in the article text (keyword match, unverified)", "candidate", "Intelligence Feed (RSS)"))
    elif kind == "product":
        v, _, p = key.partition(":")
        ix = _ix(con)
        if "belongs_to" in rels:
            vn = vendor_node(v)
            out.append((vn, dedge("belongs_to", node["id"], vn["id"], f"CPE identifier {v}:{p}", "NVD CPE")))
        if "affects" in rels:
            cves = ix.product_cves(v, p, 25)
            kev = {r[0] for r in con.execute("SELECT cve_id FROM kev_entry")} if cves else set()
            for c, _pub in cves:
                cn = cve_node(c, c in kev)
                out.append((cn, dedge("affects", cn["id"], node["id"], f"CPE configuration lists {v}:{p}", "NVD CPE", modified=_pub or None)))
    elif kind == "vendor":
        if "belongs_to" in rels:
            for p, n in _ix(con).vendor_products(key, 40):
                pn = product_node(key, p)
                out.append((pn, dedge("belongs_to", pn["id"], node["id"], f"CPE identifier {key}:{p} ({n} CVE)", "NVD CPE")))
    elif kind == "news":
        row = con.execute("SELECT n.*, s.name AS source_name FROM news_item n JOIN news_source s ON s.id=n.source_id WHERE n.id=?", (key,)).fetchone()
        if row and "mentions" in rels:
            when = row["published"] or row["collected_at"]
            for (c,) in con.execute("SELECT cve_id FROM news_cve WHERE news_id=?", (key,)):
                cn = cve_node(c)
                out.append((cn, dedge("mentions", node["id"], cn["id"], "Article text contains the CVE id explicitly", "Intelligence Feed (RSS)", modified=when)))
            corpus = intel.get_corpus(con)
            rev = attack_news.reverse(con, corpus).get(key, {"confirmed": [], "candidates": []})
            for kindk, status, ev in (("confirmed", "verified", "Article cites the ATT&CK id or MITRE page explicitly"), ("candidates", "candidate", "Distinctive name in the headline (unverified, not attribution)")):
                if kindk == "candidates" and not include_candidates:
                    continue
                for aid in rev[kindk]:
                    r = attack.resolve(con, aid)
                    if r:
                        an = attack_node(r)
                        out.append((an, dedge("mentions", node["id"], an["id"], ev, "Intelligence Feed (RSS)", status, when)))
            item = next((m for m in corpus.items if m["id"] == key), None)
            for t in (item["entities"]["mitre"] if item else []):
                r = attack.resolve(con, t["id"])
                if r and not r["revoked"] and not r["deprecated"]:
                    an = attack_node(r)
                    out.append((an, dedge("mentions", node["id"], an["id"], "Article writes the ATT&CK technique id explicitly", "Intelligence Feed (RSS)", "verified", when)))
            if include_candidates:
                for (t,) in con.execute("SELECT tech_id FROM news_tech WHERE news_id=? AND basis='name'", (key,)):
                    tn = tech_node(t)
                    out.append((tn, dedge("mentions", node["id"], tn["id"], "Product name appears in the text (keyword match, unverified)", "Intelligence Feed (RSS)", "candidate", when)))
    seen, res = set(), []
    for n, e in out:
        if e["id"] not in seen and (include_candidates or e["status"] == "verified"):
            seen.add(e["id"])
            res.append((n, e))
    return res


def _interleave(pairs):
    """Stable, type-balanced order so a limited page shows campaigns, software and techniques together."""
    groups: dict[str, list] = defaultdict(list)
    for p in sorted(pairs, key=lambda x: (ORDER.get(x[0]["type"], 99), x[0]["label"].lower(), x[0]["id"])):
        groups[p[0]["type"]].append(p)
    order = sorted(groups, key=lambda t: ORDER.get(t, 99))
    out, i = [], 0
    while any(i < len(groups[t]) for t in order):
        out += [groups[t][i] for t in order if i < len(groups[t])]
        i += 1
    return out


# ---------------------------------------------------------------- neighbourhood
def limits(max_nodes: int | None = None, max_edges: int | None = None) -> tuple[int, int]:
    return (min(max(5, max_nodes or settings.graph_max_nodes), settings.graph_max_nodes), min(max(10, max_edges or settings.graph_max_edges), settings.graph_max_edges))


def neighborhood(con, center: str, *, depth: int = 1, rels: set[str] | None = None, node_types: set[str] | None = None, include_candidates: bool = False,
                 limit: int = 40, offset: int = 0, max_nodes: int | None = None, max_edges: int | None = None, second_level: int = 12) -> dict | None:
    rels = (rels or set(REL_TYPES)) & set(REL_TYPES)
    mn, me = limits(max_nodes, max_edges)
    c = get_node(con, center)
    if not c:
        return None
    nodes = {c["id"]: c}
    edges: dict[str, dict] = {}
    omitted = 0
    first = [(n, e) for n, e in neighbors(con, c, rels, include_candidates) if not node_types or n["type"] in node_types]
    first = _interleave(first)
    page = first[offset: offset + limit]
    frontier = []
    for n, e in page:
        if n["id"] not in nodes:
            if len(nodes) >= mn:
                omitted += 1
                continue
            nodes[n["id"]] = n
            frontier.append(n)
        if len(edges) < me:
            edges[e["id"]] = e
    if depth >= 2:
        for fn in frontier[:60]:
            more = [(n, e) for n, e in _interleave(neighbors(con, fn, rels, include_candidates)) if not node_types or n["type"] in node_types]
            for n, e in more[:second_level]:
                if n["id"] not in nodes:
                    if len(nodes) >= mn:
                        omitted += 1
                        continue
                    nodes[n["id"]] = n
                if len(edges) < me:
                    edges[e["id"]] = e
    # real STIX relationships among the loaded ATT&CK nodes
    sx = {n["stix_id"]: n["id"] for n in nodes.values() if n.get("stix_id")}
    wanted = [r for r in ("uses", "attributed-to", "subtechnique-of") if r in rels]
    if len(sx) > 1 and wanted:
        ph, rp = ",".join("?" * len(sx)), ",".join("?" * len(wanted))
        for r in con.execute(f"SELECT * FROM stix_rel WHERE source_ref IN ({ph}) AND target_ref IN ({ph}) AND rel_type IN ({rp}) AND revoked=0 AND deprecated=0 LIMIT ?",
                             (*sx, *sx, *wanted, me)):
            if r["stix_id"] not in edges and len(edges) < me:
                edges[r["stix_id"]] = edge(r["stix_id"], sx[r["source_ref"]], sx[r["target_ref"]], r["rel_type"], "MITRE ATT&CK STIX relationship", r["status"], r["source"], r["modified"], stix_id=r["stix_id"])
    total = len(first)
    return {"center": c["id"], "nodes": list(nodes.values()), "edges": list(edges.values()), "depth": depth,
            "page": {"total_neighbors": total, "offset": offset, "limit": limit, "returned": len(page), "has_more": offset + limit < total},
            "truncated": omitted > 0 or offset + limit < total or len(edges) >= me, "omitted_nodes": omitted,
            "limits": {"max_nodes": mn, "max_edges": me}, "include_candidates": include_candidates,
            "types_available": dict(Counter(n["type"] for n, _ in first))}


# ---------------------------------------------------------------- search
def search(con, q: str, node_type: str | None = None, limit: int = 15) -> list[dict]:
    q = (q or "").strip()[:80]
    if len(q) < 2:
        return []
    like = attack._like(q.lower())
    out: list[dict] = []
    if not node_type or node_type in TYPE_STIX:
        types = (TYPE_STIX[node_type],) if node_type in TYPE_STIX else tuple(STIX_TYPE)
        ph = ",".join("?" * len(types))
        rows = con.execute(f"SELECT * FROM stix_object WHERE type IN ({ph}) AND revoked=0 AND deprecated=0 AND (LOWER(name) LIKE ? ESCAPE '!' OR LOWER(aliases) LIKE ? ESCAPE '!' OR UPPER(attack_id) LIKE ? ESCAPE '!') "
                           "ORDER BY (LOWER(name)=?) DESC, (UPPER(attack_id)=?) DESC, name COLLATE NOCASE LIMIT ?", (*types, like, like, attack._esc_prefix(q.upper()), q.lower(), q.upper(), limit * 2)).fetchall()
        out += sorted((attack_node(r) for r in rows), key=lambda n: (n["label"].lower() != q.lower(), ORDER[n["type"]], n["label"].lower()))
    if not node_type or node_type == "cve":
        if q.upper().startswith("CVE") or node_type == "cve":
            for (c,) in con.execute("SELECT cve_id FROM (SELECT cve_id FROM nvd_cve UNION SELECT cve_id FROM kev_entry UNION SELECT cve_id FROM news_cve UNION SELECT cve_id FROM intel_cve WHERE nvd_fetched_at IS NOT NULL) "
                                    "WHERE cve_id LIKE ? ESCAPE '!' ORDER BY cve_id DESC LIMIT ?", (attack._like(q.upper()), limit)):
                out.append(cve_node(c))
    if not node_type or node_type == "technology":
        out += [tech_node(t.id) for t in CATALOG if q.lower() in t.name.lower() or q.lower() == t.id]
    if node_type in (None, "vendor", "product") and len(q) >= 3:
        ix = _ix(con)
        ql = slug(q)
        if node_type in (None, "vendor"):
            out += [vendor_node(v) for v in ix.search_vendors(ql, 5)]
        if node_type in (None, "product"):
            out += [product_node(v, p) for (v, p) in ix.search_products(ql, 6)]
    if node_type == "news":
        for r in con.execute("SELECT n.*, s.name AS source_name FROM news_item n JOIN news_source s ON s.id=n.source_id WHERE LOWER(n.title) LIKE ? ESCAPE '!' ORDER BY n.sort_ts DESC LIMIT ?", (like, limit)):
            out.append(news_node(r))
    seen, res = set(), []
    for n in out:
        if n["id"] not in seen:
            seen.add(n["id"])
            res.append(n)
    return res[:limit]


# ---------------------------------------------------------------- node & edge detail
def node_detail(con, nid: str) -> dict | None:
    n = get_node(con, nid)
    if not n:
        return None
    kind, key = parse(nid)
    d: dict = {**n, "description": "", "aliases": [], "references": [], "details": {}}
    if kind == "attack":
        fn = {"threat_actor": attack.actor_detail, "campaign": attack.campaign_detail, "technique": attack.technique_detail}.get(n["type"], attack.software_detail)
        e = fn(con, key)
        if e:
            d.update(description=e["description"][:1500], aliases=e["aliases"], references=e.get("references", [])[:8], modified=e["modified"], url=e["url"])
            d["details"] = {k: e[k] for k in ("tactics", "platforms", "first_seen", "last_seen", "is_subtechnique") if k in e and e[k] not in (None, [], "")}
    elif kind == "cve":
        from . import vulns
        v = vulns.detail(con, key)
        if v:
            d.update(description=(v["description"] or "")[:1500], modified=v["published"], url=v["links"]["nvd"], references=[{"source_name": "NVD", "url": v["links"]["nvd"]}])
            d["details"] = {"cvss": v["cvss"], "epss": v["epss"], "in_kev": v["in_kev"], "published": v["published"]}
    elif kind == "tech":
        d["description"] = f"Monitored technology in the Cyber Risk Pyramid catalogue. Aliases: {', '.join(BY_ID[key].aliases)}" if BY_ID[key].aliases else "Monitored technology in the Cyber Risk Pyramid catalogue."
    elif kind == "vendor":
        d["description"] = "Vendor identifier from the CPE dictionary used by NVD."
    elif kind == "product":
        d["description"] = "Product identifier from the CPE dictionary used by NVD."
    elif kind == "news":
        r = con.execute("SELECT summary FROM news_item WHERE id=?", (key,)).fetchone()
        d.update(description=r["summary"] or "", references=[{"source_name": n["source"], "url": n["url"]}], modified=n["published"], label=con.execute("SELECT title FROM news_item WHERE id=?", (key,)).fetchone()[0])
    rels = defaultdict(Counter)
    for o, e in neighbors(con, n, set(REL_TYPES), False):
        rels[e["type"] + (" (incoming)" if e["target"] == nid else " (outgoing)")][o["type"]] += 1
    d["available_relations"] = [{"relation": r, "counts": dict(c)} for r, c in sorted(rels.items())]
    return d


def edge_detail(con, eid: str) -> dict | None:
    if not EDGE_ID_RE.match(eid or ""):
        raise ValueError("Invalid edge id")
    if eid.startswith("relationship--"):
        r = con.execute("SELECT * FROM stix_rel WHERE stix_id=?", (eid,)).fetchone()
        if not r:
            return None
        so = con.execute("SELECT * FROM stix_object WHERE stix_id=?", (r["source_ref"],)).fetchone()
        to = con.execute("SELECT * FROM stix_object WHERE stix_id=?", (r["target_ref"],)).fetchone()
        if not so or not to:
            return None
        sn, tn = attack_node(so), attack_node(to)
        e = edge(eid, sn["id"], tn["id"], r["rel_type"], "MITRE ATT&CK STIX relationship", r["status"], r["source"], r["modified"], stix_id=eid)
        refs = [x for x in json.loads(r["evidence_refs"] or "[]") if x.get("url") or x.get("description")]
        desc = attack.clean_desc(r["description"], 1500)
        return {"edge": e, "source": sn, "target": tn, "description": desc, "references": refs[:10], "evidence_id": eid, "revoked": bool(r["revoked"] or r["deprecated"]),
                "interpretation": NOTES.get(r["rel_type"], "")}
    rest = eid.split(":", 2)[2]
    src, _, dst = rest.partition("|")
    sn = get_node(con, src)
    if not sn:
        return None
    for n, e in neighbors(con, sn, set(REL_TYPES), True):
        if e["id"] == eid:
            refs = [{"source_name": e["dataset"], "description": e["evidence"], "url": n.get("url") if n.get("type") == "news" else (f"https://nvd.nist.gov/vuln/detail/{n['external_id']}" if n["type"] == "cve" else None)}]
            return {"edge": e, "source": get_node(con, e["source"]), "target": get_node(con, e["target"]), "description": "", "references": refs,
                    "evidence_id": eid, "revoked": False, "interpretation": NOTES.get(e["type"], "") + (" This relationship is a candidate and has not been verified." if e["status"] == "candidate" else "")}
    return None


def meta(con) -> dict:
    st = attack.status(con)
    return {"dataset": {"name": "MITRE ATT&CK Enterprise", "version": st["collection_version"], "imported": st["imported"], "last_success": st["last_success"], "counts": st["counts"]},
            "node_types": NODE_TYPES, "relation_types": REL_TYPES, "limits": {"max_nodes": settings.graph_max_nodes, "max_edges": settings.graph_max_edges},
            "relation_notes": NOTES}
