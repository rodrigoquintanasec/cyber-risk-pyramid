"""News intelligence engine: clustering, News Priority Score, trending, coverage, timeline, observatory, search.

Read-only over stored news. It never writes to the tables used by the pyramid Threat Signal Score.

CLUSTERING (deterministic, conservative). Two articles are linked only on verifiable evidence:
  1. a shared CVE / explicit advisory id (GHSA, ZDI, VMSA, FG-IR, CISA AA, KB ...) within `cve_window_days`.
     Roundups (> `roundup_cves` CVEs) never link through single CVEs; and
  2. title similarity (token Jaccard) within `title_window_hours`: >= 0.70, or >= 0.50 together with a shared named
     entity (vendor/product/malware/ransomware). >= 3 shared significant tokens are always required and two articles
     citing disjoint CVE sets are never merged by title. A shared vendor or ransomware name alone never links.

NEWS PRIORITY SCORE (0-100, reading priority — NOT a risk measure; independent of the pyramid score):
  recency .25 (36h half-life of the latest article) + CVE signals .35 (0.25 base for any CVE, plus KEV .60, EPSS .25
  (full share at EPSS >= 0.30), CVSS .15 of the best CVE; missing data counts as 0 and is reported) + official source/advisory .12
  + monitored-technology relevance .18 + coverage breadth .10 (distinct publishers, capped at 5). Weights in PriorityConfig.
"""
from __future__ import annotations

import hashlib
import math
import re
import threading
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from .. import db
from ..catalog import BY_ID, CATALOG
from . import entities as ent
from .classify import CATEGORIES, FALLBACK_CATEGORY
from .sources import BY_ID as SOURCE_BY_ID, SOURCE_TYPES, is_verified_official

PERIODS = {"24h": 24, "48h": 48, "7d": 168, "30d": 720}
OFFICIAL_SOURCES = frozenset({"microsoft-security", "project-zero", "talos", "unit42", "aws-security",
                              "cloudflare", "checkpoint", "crowdstrike", "zdi"})
ADVISORY_ID_RE = re.compile(r"^(GHSA-|ZDI-|VMSA-|FG-IR-|AA\d|ICSA-|ADV\d|PSIRT-|SA-)", re.I)
THEMES = ("Ransomware", "Malware", "Data Breaches", "Threat Intelligence", "Cloud Security")
ZERO_DAY = re.compile(r"\bzero[- ]?days?\b|\b0[- ]days?\b", re.I)
TOPICS = [c for c in CATEGORIES if c != FALLBACK_CATEGORY] + ["Zero-Day"]
STOP = set("a an the of in on at to for and or with by from as is are was were be been it its this that these those how what why who "
           "new via after over into about up out more than not no can may will has have had says say said could would should "
           "security cyber cybersecurity attack attacks attackers hackers hacker hackers hacked flaw flaws bug bugs vulnerability "
           "vulnerabilities critical high report reports researchers researcher warns warn warning update updates patch patches "
           "latest now week day today users user data your you our their".split())
TOKEN = re.compile(r"[a-z0-9][a-z0-9\-\.]{1,}")


@dataclass(frozen=True)
class PriorityConfig:
    w_recency: float = 0.25
    w_cve: float = 0.35
    w_official: float = 0.12
    w_tech: float = 0.18
    w_breadth: float = 0.10
    recency_half_life_h: float = 36.0
    cve_base: float = 0.25          # share of the CVE component given for merely referencing a CVE
    kev: float = 0.60
    epss: float = 0.25
    cvss: float = 0.15
    epss_cap: float = 0.30          # EPSS >= cap gives the full EPSS share
    breadth_cap: int = 5
    relevant_threshold: float = 40.0


PRIORITY = PriorityConfig()


@dataclass(frozen=True)
class ClusterConfig:
    cve_window_days: int = 10
    title_window_hours: int = 72
    roundup_cves: int = 5
    jaccard_strong: float = 0.70
    jaccard_with_entity: float = 0.50
    min_shared_tokens: int = 3
    min_title_tokens: int = 4
    max_df_ratio: float = 0.06


CLUSTER = ClusterConfig()


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _dt(s: str | None) -> datetime | None:
    if not s:
        return None
    try:
        d = datetime.fromisoformat(s)
        return d if d.tzinfo else d.replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def tokens(title: str) -> frozenset[str]:
    out = set()
    for t in TOKEN.findall((title or "").lower()):
        t = t.strip(".-")
        if len(t) < 3 or t in STOP:
            continue
        if len(t) > 4 and t.endswith("s") and not t.endswith("ss"):
            t = t[:-1]
        out.add(t)
    return frozenset(out)


# ----------------------------------------------------------------------------- loading
def load_items(con, days: int = 90, limit: int = 6000) -> list[dict]:
    since = (_now() - timedelta(days=days)).isoformat(timespec="seconds")
    rows = con.execute(
        "SELECT n.*, s.name AS source_name, s.type AS source_type FROM news_item n JOIN news_source s ON s.id=n.source_id "
        "WHERE n.sort_ts>=? ORDER BY n.sort_ts DESC LIMIT ?", (since, limit)).fetchall()
    by: dict[str, dict] = {}
    items = []
    for r in rows:
        it = {
            "id": r["id"], "title": r["title"], "summary": r["summary"] or "", "url": r["url"],
            "source_id": r["source_id"], "source_name": r["source_name"], "source_type": r["source_type"],
            "published": r["published"], "collected_at": r["collected_at"], "updated_at": r["updated_at"],
            "ts": _dt(r["sort_ts"]), "undated": not r["published"], "categories": [], "techs": [], "cves": [],
        }
        by[it["id"]] = it
        items.append(it)
    if items:
        for i in range(0, len(items), 400):
            ids = [x["id"] for x in items[i:i + 400]]
            ph = ",".join("?" * len(ids))
            for r in con.execute(f"SELECT news_id,category FROM news_cat WHERE news_id IN ({ph})", ids):
                by[r[0]]["categories"].append(r[1])
            for r in con.execute(f"SELECT news_id,tech_id,basis FROM news_tech WHERE news_id IN ({ph})", ids):
                by[r[0]]["techs"].append({"id": r[1], "basis": r[2]})
            for r in con.execute(f"SELECT news_id,cve_id FROM news_cve WHERE news_id IN ({ph})", ids):
                by[r[0]]["cves"].append(r[1])
    for it in items:
        it["cves"].sort()
        e = ent.extract(it["title"], it["summary"])
        it["entities"] = e
        it["tokens"] = tokens(it["title"])
        it["topics"] = [c for c in it["categories"] if c != FALLBACK_CATEGORY]
        if ZERO_DAY.search(it["title"] + " " + it["summary"]):
            it["topics"].append("Zero-Day")
        src = SOURCE_BY_ID.get(it["source_id"])
        # official = first-party publisher, or an Official Security Advisory whose feed host AND item link sit on the vendor/agency domain
        it["official"] = it["source_id"] in OFFICIAL_SOURCES or bool(src and is_verified_official(src, it["url"])) or any(ADVISORY_ID_RE.match(x) for x in e["incident_ids"])
    return items


def load_signals(con, cves: list[str]) -> dict[str, dict]:
    """Verifiable per-CVE signals from local caches. Missing data stays None (never invented)."""
    out: dict[str, dict] = {}
    cves = list(dict.fromkeys(cves))
    for i in range(0, len(cves), 400):
        chunk = cves[i:i + 400]
        ph = ",".join("?" * len(chunk))
        for c in chunk:
            out[c] = {"cve": c, "cvss": None, "cvss_version": None, "epss": None, "epss_percentile": None, "epss_date": None,
                      "kev": None, "published": None, "products": [], "description": None, "sources": []}
        for r in con.execute(f"SELECT * FROM intel_cve WHERE cve_id IN ({ph})", chunk):
            s = out[r["cve_id"]]
            if r["cvss"] is not None:
                s["cvss"], s["cvss_version"] = r["cvss"], r["cvss_version"]; s["sources"].append("NVD")
            s["published"], s["description"] = r["published"], r["description"]
            s["products"] = _products(r["cpes"])
            if r["epss"] is not None:
                s["epss"], s["epss_percentile"], s["epss_date"] = r["epss"], r["epss_pct"], r["epss_date"]; s["sources"].append("EPSS")
        for r in con.execute(f"SELECT * FROM nvd_cve WHERE cve_id IN ({ph})", chunk):
            s = out[r["cve_id"]]
            if r["cvss"] is not None:
                s["cvss"], s["cvss_version"] = r["cvss"], r["cvss_version"]
                if "NVD" not in s["sources"]: s["sources"].append("NVD")
            s["published"] = r["published"] or s["published"]; s["description"] = r["description"] or s["description"]
            s["products"] = _products(r["cpes"]) or s["products"]
        for r in con.execute(f"SELECT * FROM epss WHERE cve_id IN ({ph})", chunk):
            s = out[r["cve_id"]]
            s["epss"], s["epss_percentile"], s["epss_date"] = r["score"], r["percentile"], r["score_date"]
            if "EPSS" not in s["sources"]: s["sources"].append("EPSS")
        for r in con.execute(f"SELECT * FROM kev_entry WHERE cve_id IN ({ph})", chunk):
            s = out[r["cve_id"]]
            s["kev"] = {"date_added": r["date_added"], "ransomware": bool(r["ransomware"]), "vendor": r["vendor"], "product": r["product"], "name": r["name"]}
            s["sources"].append("CISA KEV")
            if not s["products"] and r["vendor"]:
                s["products"] = [f"{r['vendor']} {r['product']}".strip()]
    return out


def _products(cpes: str | None) -> list[str]:
    seen: dict[str, None] = {}
    for c in (cpes or "").split(","):
        parts = c.strip().split(":")
        if len(parts) >= 3:
            seen[" / ".join(parts[1:])] = None
    return list(seen)[:6]


def cve_urls(cve: str, sig: dict | None = None) -> list[dict]:
    refs = [{"label": "NVD", "url": f"https://nvd.nist.gov/vuln/detail/{cve}"},
            {"label": "FIRST EPSS", "url": f"https://api.first.org/data/v1/epss?cve={cve}"}]
    if sig and sig.get("kev"):
        refs.append({"label": "CISA KEV catalog", "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"})
    return refs


# ----------------------------------------------------------------------------- clustering
class _UF:
    def __init__(self, n): self.p = list(range(n))
    def find(self, x):
        while self.p[x] != x:
            self.p[x] = self.p[self.p[x]]; x = self.p[x]
        return x
    def union(self, a, b):
        a, b = self.find(a), self.find(b)
        if a != b: self.p[max(a, b)] = min(a, b)


def _ents(it) -> set[str]:
    e = it["entities"]
    return {*e["vendors"], *e["products"], *e["malware"], *e["ransomware"]}


def _event_keys(it, cfg: ClusterConfig) -> set[str]:
    keys = {f"id:{x}" for x in it["entities"]["incident_ids"]}
    if len(it["cves"]) > cfg.roundup_cves:
        keys.add("roundup:" + hashlib.sha1(",".join(it["cves"]).encode()).hexdigest()[:12])
    else:
        keys |= {f"cve:{c}" for c in it["cves"]}
    return keys


def build_clusters(items: list[dict], cfg: ClusterConfig = CLUSTER) -> list[dict]:
    items = sorted(items, key=lambda x: (x["ts"], x["id"]))
    n = len(items)
    uf = _UF(n)
    by_key: dict[str, list[int]] = defaultdict(list)
    for i, it in enumerate(items):
        for k in _event_keys(it, cfg):
            by_key[k].append(i)
    cve_gap = timedelta(days=cfg.cve_window_days)
    for idxs in by_key.values():
        for a, b in zip(idxs, idxs[1:]):
            if items[b]["ts"] - items[a]["ts"] <= cve_gap:
                uf.union(a, b)
    # title similarity through an inverted index of rare-enough tokens
    df = Counter(t for it in items for t in it["tokens"])
    max_df = max(8, int(cfg.max_df_ratio * n))
    inv: dict[str, list[int]] = defaultdict(list)
    gap = timedelta(hours=cfg.title_window_hours)
    for j, it in enumerate(items):
        if len(it["tokens"]) < cfg.min_title_tokens:
            continue
        cand = Counter()
        for t in it["tokens"]:
            if df[t] <= max_df:
                for i in inv[t]:
                    cand[i] += 1
        for i, shared_rare in cand.items():
            a = items[i]
            if shared_rare < 2 or it["ts"] - a["ts"] > gap or uf.find(i) == uf.find(j):
                continue
            ta, tb = a["tokens"], it["tokens"]
            shared = ta & tb
            if len(shared) < cfg.min_shared_tokens:
                continue
            if a["cves"] and it["cves"] and not set(a["cves"]) & set(it["cves"]):
                continue  # different vulnerabilities
            ia, ib = a["entities"]["incident_ids"], it["entities"]["incident_ids"]
            if ia and ib and not set(ia) & set(ib):
                continue  # different advisories (e.g. ZDI-26-923 vs ZDI-26-931)
            jac = len(shared) / len(ta | tb)
            if jac >= cfg.jaccard_strong or (jac >= cfg.jaccard_with_entity and _ents(a) & _ents(it)):
                uf.union(i, j)
        for t in it["tokens"]:
            if df[t] <= max_df:
                inv[t].append(j)
    groups: dict[int, list[dict]] = defaultdict(list)
    for i, it in enumerate(items):
        groups[uf.find(i)].append(it)
    clusters = [_make_cluster(g) for g in groups.values()]
    clusters.sort(key=lambda c: c["last_ts"], reverse=True)
    return clusters


def _make_cluster(members: list[dict]) -> dict:
    members = sorted(members, key=lambda x: (x["ts"], x["id"]))
    rep = max(members, key=lambda m: (m["official"], len(m["cves"]), -members.index(m)))
    cats = Counter(c for m in members for c in m["categories"] if c != FALLBACK_CATEGORY)
    cat_list = [c for c, _ in sorted(cats.items(), key=lambda kv: (-kv[1], CATEGORIES.index(kv[0])))] or [FALLBACK_CATEGORY]
    techs: dict[str, str] = {}
    for m in members:
        for t in m["techs"]:
            if techs.get(t["id"]) != "name":
                techs[t["id"]] = t["basis"]
    agg = {k: sorted({x for m in members for x in m["entities"][k]}) for k in ("vendors", "products", "malware", "ransomware", "incident_ids")}
    mitre: dict[str, dict] = {}
    for m in members:
        for t in m["entities"]["mitre"]:
            mitre.setdefault(t["id"], t)
    return {
        "id": "evt_" + members[0]["id"][:12], "title": rep["title"], "members": members, "categories": cat_list,
        "first_ts": members[0]["ts"], "last_ts": members[-1]["ts"],
        # time-window analytics only trust real publication dates; entries without one are timestamped at collection and ignored there
        "last_dated": max((m["ts"] for m in members if not m.get("undated")), default=None),
        "article_count": len(members), "source_ids": sorted({m["source_id"] for m in members}),
        "cves": sorted({c for m in members for c in m["cves"]}), "techs": techs, "entities": agg,
        "mitre": list(mitre.values()), "topics": sorted({t for m in members for t in m["topics"]}),
        "official": any(m["official"] for m in members),
        "advisory_only": all(m["source_type"] == "official" for m in members),
    }


# ----------------------------------------------------------------------------- priority
def priority(cl: dict, signals: dict[str, dict], now: datetime | None = None, cfg: PriorityConfig = PRIORITY) -> dict:
    now = now or _now()
    comps = []
    if cl.get("last_dated") is None:
        rec, rdet = 0.0, "No publication date in the feed, so no recency is assumed"
    else:
        age_h = max(0.0, (now - cl["last_dated"]).total_seconds() / 3600)
        rec, rdet = 0.5 ** (age_h / cfg.recency_half_life_h), f"Latest article {_ago(age_h)} (half-life {cfg.recency_half_life_h:.0f}h)"
    comps.append(("recency", "Recency", cfg.w_recency, rec, rdet))
    best, best_cve, miss = 0.0, None, set()
    for c in cl["cves"][:25]:
        s = signals.get(c) or {}
        kev = 1.0 if s.get("kev") else 0.0
        epss = min(1.0, (s["epss"] or 0) / cfg.epss_cap) if s.get("epss") is not None else 0.0
        cvss = (s["cvss"] or 0) / 10 if s.get("cvss") is not None else 0.0
        v = cfg.kev * kev + cfg.epss * epss + cfg.cvss * cvss
        if v >= best:
            best, best_cve = v, c
    if cl["cves"]:
        s = signals.get(best_cve) or {}
        parts = ["CISA KEV" if s.get("kev") else None, f"EPSS {s['epss']:.2f}" if s.get("epss") is not None else None,
                 f"CVSS {s['cvss']}" if s.get("cvss") is not None else None]
        have = [p for p in parts if p]
        if s.get("epss") is None: miss.add("EPSS")
        if s.get("cvss") is None: miss.add("CVSS")
        val = cfg.cve_base + (1 - cfg.cve_base) * best
        det = f"{len(cl['cves'])} CVE(s); strongest {best_cve}: " + (", ".join(have) if have else "no local KEV/EPSS/CVSS data") + (f" (missing: {', '.join(sorted(miss))})" if miss else "")
    else:
        val, det = 0.0, "No CVE referenced"
    comps.append(("cves", "CVE signals", cfg.w_cve, val, det))
    adv = [x for x in cl["entities"]["incident_ids"] if ADVISORY_ID_RE.match(x)]
    off_src = sorted({m["source_name"] for m in cl["members"] if m["source_id"] in OFFICIAL_SOURCES})
    comps.append(("official", "Official source / advisory", cfg.w_official, 1.0 if cl["official"] else 0.0,
                  ("; ".join(filter(None, [f"First-party publisher: {', '.join(off_src)}" if off_src else "", f"Advisory id: {', '.join(adv[:3])}" if adv else ""]))) or "No official source or advisory id"))
    tn = [BY_ID[t].name for t in cl["techs"] if t in BY_ID]
    comps.append(("tech", "Monitored technology", cfg.w_tech, 1.0 if tn else 0.0, f"Relates to {', '.join(sorted(tn))}" if tn else "No monitored technology"))
    pubs = len(cl["source_ids"])
    br = min(1.0, (pubs - 1) / max(1, cfg.breadth_cap - 1))
    comps.append(("breadth", "Coverage breadth", cfg.w_breadth, br, f"{pubs} distinct publisher(s) — breadth only, not independent confirmation"))
    total = round(100 * sum(w * v for _, _, w, v, _ in comps), 1)
    return {"score": total, "label": "News Priority Score", "note": "Reading priority for analysts — not a risk measurement.",
            "components": [{"key": k, "label": lb, "weight": w, "value": round(v, 3), "points": round(100 * w * v, 1), "detail": d} for k, lb, w, v, d in comps]}


def _ago(h: float) -> str:
    return f"{int(h * 60)}m ago" if h < 1 else f"{h:.0f}h ago" if h < 48 else f"{h / 24:.0f}d ago"


# ----------------------------------------------------------------------------- corpus cache
class Corpus:
    def __init__(self, items, clusters, signals, now):
        self.items, self.clusters, self.signals, self.now = items, clusters, signals, now
        self.cluster_of = {m["id"]: c for c in clusters for m in c["members"]}
        self.by_cluster = {c["id"]: c for c in clusters}
        self.prio = {c["id"]: priority(c, signals, now) for c in clusters}


_cache: dict = {"sig": None, "corpus": None}
_lock = threading.Lock()


def _signature(con) -> tuple:
    r = con.execute("SELECT COUNT(*), MAX(collected_at), MAX(COALESCE(updated_at,'')) FROM news_item").fetchone()
    k = con.execute("SELECT COUNT(*) FROM kev_entry").fetchone()[0]
    e = con.execute("SELECT COUNT(*), MAX(epss_fetched_at), MAX(nvd_fetched_at) FROM intel_cve").fetchone()
    e2 = con.execute("SELECT COUNT(*), MAX(fetched_at) FROM epss").fetchone()
    return (tuple(r), k, tuple(e), tuple(e2), _now().strftime("%Y%m%d%H") + str(_now().minute // 10))


def get_corpus(con=None) -> Corpus:
    def build(c):
        sig = _signature(c)
        with _lock:
            if _cache["sig"] == sig:
                return _cache["corpus"]
        items = load_items(c)
        clusters = build_clusters(items)
        signals = load_signals(c, [x for cl in clusters for x in cl["cves"]])
        corpus = Corpus(items, clusters, signals, _now())
        with _lock:
            _cache.update(sig=sig, corpus=corpus)
        return corpus
    if con is not None:
        return build(con)
    with db.connect() as c:
        return build(c)


def reset_cache() -> None:
    with _lock:
        _cache.update(sig=None, corpus=None)


# ----------------------------------------------------------------------------- shaping
def _iso(d: datetime | None) -> str | None:
    return d.isoformat(timespec="seconds") if d else None


def shape_cluster(corpus: Corpus, cl: dict, detail: bool = False) -> dict:
    out = {
        "id": cl["id"], "title": cl["title"], "category": cl["categories"][0], "categories": cl["categories"],
        "first_published": _iso(cl["first_ts"]), "last_published": _iso(cl["last_ts"]),
        "article_count": cl["article_count"], "source_count": len(cl["source_ids"]),
        "sources": sorted({m["source_name"] for m in cl["members"]}),
        "cves": cl["cves"], "technologies": [{"id": t, "name": BY_ID[t].name if t in BY_ID else t, "basis": b} for t, b in sorted(cl["techs"].items())],
        "vendors": cl["entities"]["vendors"], "products": cl["entities"]["products"], "malware": cl["entities"]["malware"],
        "ransomware": cl["entities"]["ransomware"], "mitre": cl["mitre"], "official": cl["official"],
        "priority": corpus.prio[cl["id"]] if detail else {"score": corpus.prio[cl["id"]]["score"]},
    }
    if detail:
        out["articles"] = [article(m, corpus) for m in reversed(cl["members"])]
        out["coverage"] = coverage(cl)
        out["timeline"] = timeline(cl)
        out["cve_signals"] = [corpus.signals[c] for c in cl["cves"] if c in corpus.signals]
    return out


def article(m: dict, corpus: Corpus | None = None) -> dict:
    return {"id": m["id"], "title": m["title"], "summary": m["summary"], "url": m["url"],
            "source": {"id": m["source_id"], "name": m["source_name"], "type": m["source_type"], "type_label": SOURCE_TYPES.get(m["source_type"], m["source_type"])},
            "published": m["published"], "collected_at": m["collected_at"], "updated_at": m["updated_at"],
            "categories": m["categories"], "cves": m["cves"], "technologies": m["techs"],
            "vendors": m["entities"]["vendors"], "products": m["entities"]["products"], "malware": m["entities"]["malware"],
            "ransomware": m["entities"]["ransomware"], "mitre": m["entities"]["mitre"],
            "event_id": corpus.cluster_of[m["id"]]["id"] if corpus and m["id"] in corpus.cluster_of else None,
            "priority": corpus.prio[corpus.cluster_of[m["id"]]["id"]]["score"] if corpus and m["id"] in corpus.cluster_of else None}


# ----------------------------------------------------------------------------- coverage & timeline
def coverage(cl: dict) -> dict:
    mem = cl["members"]
    pubs: dict[str, dict] = {}
    for m in mem:
        p = pubs.setdefault(m["source_id"], {"source_id": m["source_id"], "name": m["source_name"], "type_label": SOURCE_TYPES.get(m["source_type"], m["source_type"]),
                                             "articles": [], "first": m["ts"], "last": m["ts"]})
        p["articles"].append({"title": m["title"], "url": m["url"], "published": m["published"]})
        p["first"], p["last"] = min(p["first"], m["ts"]), max(p["last"], m["ts"])
    plist = sorted(pubs.values(), key=lambda p: (p["first"], p["source_id"]))
    daily = Counter(m["ts"].date().isoformat() for m in mem)
    return {
        "articles": len(mem), "publishers": len(plist),
        "first_source": {"name": mem[0]["source_name"], "at": _iso(mem[0]["ts"]), "url": mem[0]["url"]},
        "last_source": {"name": mem[-1]["source_name"], "at": _iso(mem[-1]["ts"]), "url": mem[-1]["url"]},
        "by_publisher": [{**{k: v for k, v in p.items() if k not in ("first", "last")}, "first": _iso(p["first"]), "last": _iso(p["last"]), "article_count": len(p["articles"])} for p in plist],
        "by_source_type": dict(Counter(SOURCE_TYPES.get(m["source_type"], m["source_type"]) for m in mem)),
        "daily": [{"date": d, "articles": n} for d, n in sorted(daily.items())],
        "note": "Distinct publishers are counted by identifiable outlet. Several outlets repeating the same disclosure are not independent confirmations.",
    }


def timeline(cl: dict) -> dict:
    seen_cve: set[str] = set(); seen_ent: set[str] = set()
    out = []
    for m in cl["members"]:
        new_cves = [c for c in m["cves"] if c not in seen_cve]
        ents = sorted(_ents(m)); new_ents = [e for e in ents if e not in seen_ent]
        info = []
        if out and new_cves: info.append("Adds CVE: " + ", ".join(new_cves))
        if out and new_ents: info.append("Adds entities: " + ", ".join(new_ents))
        seen_cve.update(m["cves"]); seen_ent.update(ents)
        upd = m["updated_at"] if m["updated_at"] and m["updated_at"][:16] != (m["published"] or "")[:16] else None
        out.append({"article_id": m["id"], "title": m["title"], "url": m["url"], "source": m["source_name"],
                    "published": m["published"], "collected_at": m["collected_at"], "known_update": upd,
                    "date_basis": "published" if m["published"] else "collected", "at": _iso(m["ts"]),
                    "new_information": info, "is_first": not out})
    return {"entries": out, "note": "Dates are article publication/collection times, not incident dates. 'Known update' is a revision reported by the feed or detected on re-collection."}


# ----------------------------------------------------------------------------- listing & search
def list_clusters(corpus: Corpus, *, period="30d", category=None, tech=None, vendor=None, cve=None, source=None, q=None,
                  min_sources=1, sort="priority", page=1, page_size=20) -> dict:
    now = corpus.now
    cut = now - timedelta(hours=PERIODS[period]) if period in PERIODS else None
    ql = q.strip().lower()[:100] if q else None
    sel = []
    for c in corpus.clusters:
        if cut and (c.get("last_dated") is None or c["last_dated"] < cut): continue
        if category and category not in c["categories"]: continue
        if tech and tech not in c["techs"]: continue
        if vendor and vendor not in c["entities"]["vendors"]: continue
        if cve and cve not in c["cves"]: continue
        if source and source not in c["source_ids"]: continue
        if len(c["source_ids"]) < min_sources: continue
        if ql and not any(ql in m["title"].lower() for m in c["members"]): continue
        sel.append(c)
    key = {"priority": lambda c: (-corpus.prio[c["id"]]["score"], c["id"]), "recent": lambda c: (-c["last_ts"].timestamp(), c["id"]),
           "size": lambda c: (-c["article_count"], c["id"])}[sort]
    sel.sort(key=key)
    return _page([shape_cluster(corpus, c) for c in sel[(page - 1) * page_size: page * page_size]], len(sel), page, page_size)


def _page(items, total, page, page_size):
    return {"items": items, "total": total, "page": page, "page_size": page_size, "pages": max(1, -(-total // page_size))}


def search(corpus: Corpus, *, q=None, cve=None, vendor=None, product=None, tech=None, malware=None, ransomware=None, mitre=None,
           category=None, source=None, period="all", date_from=None, date_to=None, page=1, page_size=20) -> dict:
    now = corpus.now
    cut = now - timedelta(hours=PERIODS[period]) if period in PERIODS else None
    ql = q.strip().lower()[:100] if q else None
    dfrom = datetime.fromisoformat(date_from).replace(tzinfo=timezone.utc) if date_from else None
    dto = datetime.fromisoformat(date_to).replace(tzinfo=timezone.utc) + timedelta(days=1) if date_to else None
    res = []
    for it in corpus.items:
        e = it["entities"]
        if (cut or dfrom or dto) and it.get("undated"): continue
        if cut and it["ts"] < cut: continue
        if dfrom and it["ts"] < dfrom: continue
        if dto and it["ts"] >= dto: continue
        if cve and cve not in it["cves"]: continue
        if vendor and vendor not in e["vendors"]: continue
        if product and product not in e["products"]: continue
        if tech and tech not in {t["id"] for t in it["techs"]}: continue
        if malware and malware not in e["malware"]: continue
        if ransomware and ransomware not in e["ransomware"]: continue
        if mitre and mitre not in {t["id"] for t in e["mitre"]}: continue
        if category and category not in it["categories"]: continue
        if source and source != it["source_id"]: continue
        if ql and ql not in it["title"].lower() and ql not in it["summary"].lower(): continue
        res.append(it)
    start = (page - 1) * page_size
    return _page([article(m, corpus) for m in res[start:start + page_size]], len(res), page, page_size)


def facets(corpus: Corpus, limit: int = 40) -> dict:
    c = {k: Counter() for k in ("vendors", "products", "malware", "ransomware")}
    mt: Counter = Counter(); cats: Counter = Counter()
    for it in corpus.items:
        for k in c:
            c[k].update(it["entities"][k])
        mt.update(t["id"] for t in it["entities"]["mitre"])
        cats.update(it["categories"])
    top = lambda cn: [{"name": k, "articles": v} for k, v in cn.most_common(limit)]  # noqa: E731
    cat = ent.mitre_catalog()["techniques"]
    return {**{k: top(v) for k, v in c.items()}, "categories": [{"name": k, "articles": cats.get(k, 0)} for k in CATEGORIES],
            "mitre": [{"id": k, "name": cat.get(k, {}).get("n", k), "articles": v} for k, v in mt.most_common(limit)],
            "technologies": [{"id": t.id, "name": t.name, "category": t.category} for t in CATALOG]}


# ----------------------------------------------------------------------------- trending
def trending(corpus: Corpus, period: str) -> dict:
    hours = PERIODS[period]
    now = corpus.now
    cur0, prev0 = now - timedelta(hours=hours), now - timedelta(hours=2 * hours)
    dated = [i for i in corpus.items if not i.get("undated")]
    oldest = min((i["ts"] for i in dated), default=now)
    prev_total = sum(1 for i in dated if prev0 <= i["ts"] < cur0)
    sufficient = oldest <= prev0 + timedelta(hours=hours * 0.1) and prev_total >= 20

    def count(lo, hi):
        art, ev = Counter(), defaultdict(set)
        fam = defaultdict(lambda: [0, set()])
        for it in dated:
            if not (lo <= it["ts"] < hi): continue
            cid = corpus.cluster_of[it["id"]]["id"]
            for t in it["topics"]:
                art[t] += 1; ev[t].add(cid)
            for kind in ("malware", "ransomware"):
                for f in it["entities"][kind]:
                    fam[(f, kind)][0] += 1; fam[(f, kind)][1].add(cid)
        return art, ev, fam
    ca, ce, cf = count(cur0, now + timedelta(seconds=1))
    pa, pe, _ = count(prev0, cur0)
    topics = []
    for t in TOPICS:
        cur, prv = len(ce.get(t, ())), len(pe.get(t, ()))
        chg = None
        if sufficient and prv >= 3:
            chg = round(100 * (cur - prv) / prv, 1)
        topics.append({"topic": t, "articles": ca.get(t, 0), "events": cur, "previous_events": prv if sufficient else None,
                       "previous_articles": pa.get(t, 0) if sufficient else None, "change_pct": chg,
                       "trend": None if chg is None else "up" if chg >= 10 else "down" if chg <= -10 else "flat"})
    topics.sort(key=lambda x: (-x["events"], -x["articles"], x["topic"]))
    fams = sorted(({"name": k[0], "kind": k[1], "articles": v[0], "events": len(v[1])} for k, v in cf.items()), key=lambda x: (-x["events"], -x["articles"], x["name"]))[:8]
    total_art = sum(1 for i in dated if i["ts"] >= cur0)
    return {"period": period, "since": _iso(cur0), "until": _iso(now), "total_articles": total_art,
            "total_events": len({corpus.cluster_of[i["id"]]["id"] for i in dated if i["ts"] >= cur0}),
            "history_sufficient": sufficient, "previous_articles": prev_total, "topics": topics, "families": fams,
            "note": None if sufficient else "Not enough history for the previous period to show a trend (needs coverage of the full previous window and at least 20 articles)."}


# ----------------------------------------------------------------------------- observatory
def observatory(corpus: Corpus, period: str, limit: int = 10) -> dict:
    hours = PERIODS[period]
    cut = corpus.now - timedelta(hours=hours)
    nb = 6 if hours <= 48 else min(30, hours // 24)
    step = timedelta(hours=hours / nb)

    def bucket(ts): return min(nb - 1, max(0, int((ts - cut) / step)))
    groups: dict[str, dict[str, dict]] = {"vendors": {}, "technologies": {}}
    for it in corpus.items:
        if it["ts"] < cut or it.get("undated"): continue
        cid = corpus.cluster_of[it["id"]]["id"]
        keys = [("vendors", v, v) for v in it["entities"]["vendors"]] + [("technologies", t["id"], BY_ID[t["id"]].name) for t in it["techs"] if t["id"] in BY_ID]
        for kind, key, name in keys:
            g = groups[kind].setdefault(key, {"name": name, "id": key, "articles": 0, "events": set(), "cves": set(), "series": [set() for _ in range(nb)], "latest": []})
            g["articles"] += 1; g["events"].add(cid); g["cves"].update(it["cves"]); g["series"][bucket(it["ts"])].add(cid)
            if len(g["latest"]) < 3: g["latest"].append({"title": it["title"], "url": it["url"], "source": it["source_name"], "published": it["published"], "event_id": cid})
    out = {}
    for kind, d in groups.items():
        rows = sorted(d.values(), key=lambda g: (-len(g["events"]), -g["articles"], g["name"]))[:limit]
        out[kind] = [{"id": g["id"], "name": g["name"], "events": len(g["events"]), "articles": g["articles"], "cves": sorted(g["cves"])[:12],
                      "cve_count": len(g["cves"]), "series": [len(s) for s in g["series"]], "latest": g["latest"]} for g in rows]
    labels = [_iso(cut + step * i) for i in range(nb)]
    return {"period": period, "since": _iso(cut), "bucket_starts": labels, **out,
            "note": "Counts media mentions of unique events. Attention is not a measure of risk."}
