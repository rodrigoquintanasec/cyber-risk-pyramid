"""Persistent technology catalogue (SQLite) + admin operations.

* `sync(con)` (start-up): inserts missing seed technologies, refreshes metadata/matchers of seed rows nobody edited, never touches
  user choices (enabled/monitor/dashboard) or custom technologies, loads the registry, and back-fills news links for NEW technologies only.
* Monitoring is explicit: a technology is synchronised with NVD only when it is monitored (dashboard, watchlist, company inventory
  or forced 'on'); everything else is Catalog Only.
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone

from . import catalog
from .catalog import Technology
from .catalog_seed import CATEGORIES

KINDS = ("product", "family", "platform", "cloud")
MONITOR = ("auto", "on", "off")
ID_RE = re.compile(r"^[a-z0-9][a-z0-9\-]{1,48}$")
CPE_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_.\-+]{0,79}$")
MAX_PINNED = 24
CTRL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")

INSERT = ("INSERT INTO technology(id,name,vendor,product,category,kind,description,aliases,cpe_matchers,nvd_queries,kev_matchers,ambiguous_kev_vendors,news_patterns,"
          "enabled,monitor,dashboard,custom,source,correlation_source,edited,backfilled,created_at,updated_at) VALUES(:id,:name,:vendor,:product,:category,:kind,:description,:aliases,"
          ":cpe_matchers,:nvd_queries,:kev_matchers,:ambiguous_kev_vendors,:news_patterns,1,'auto',:dashboard,:custom,:source,:correlation_source,:edited,0,:now,:now)")


class CatalogError(Exception):
    def __init__(self, status: int, msg: str):
        super().__init__(msg)
        self.status, self.msg = status, msg


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _row_to_tech(r) -> Technology:
    j = lambda k: json.loads(r[k] or "[]")  # noqa: E731
    return Technology(id=r["id"], name=r["name"], aliases=tuple(j("aliases")), cpe_matchers=tuple(tuple(x) for x in j("cpe_matchers")), nvd_queries=tuple(j("nvd_queries")),
                      kev_matchers=tuple(tuple(x) for x in j("kev_matchers")), ambiguous_kev_vendors=tuple(j("ambiguous_kev_vendors")), news_patterns=tuple(j("news_patterns")),
                      vendor=r["vendor"], product=r["product"], category=r["category"], kind=r["kind"], description=r["description"], custom=bool(r["custom"]), enabled=bool(r["enabled"]),
                      monitor=r["monitor"], dashboard=bool(r["dashboard"]), correlation_source=r["correlation_source"] or "")


def _vals(t: Technology) -> dict:
    return {"name": t.name, "vendor": t.vendor, "product": t.product, "category": t.category, "kind": t.kind, "description": t.description, "aliases": json.dumps(list(t.aliases)),
            "cpe_matchers": json.dumps([list(x) for x in t.cpe_matchers]), "nvd_queries": json.dumps(list(t.nvd_queries)), "kev_matchers": json.dumps([list(x) for x in t.kev_matchers]),
            "ambiguous_kev_vendors": json.dumps(list(t.ambiguous_kev_vendors)), "news_patterns": json.dumps(list(t.news_patterns)), "correlation_source": t.correlation_source}


def load(con) -> list[Technology]:
    techs = [_row_to_tech(r) for r in con.execute("SELECT * FROM technology ORDER BY name COLLATE NOCASE")]
    catalog.set_registry(techs)
    from .news import classify
    classify.refresh_patterns()
    return techs


def sync(con) -> dict:
    now = _now()
    have = {r["id"]: r for r in con.execute("SELECT id,source,edited,name,vendor,product,kind,description,aliases,cpe_matchers,nvd_queries,kev_matchers,news_patterns FROM technology")}
    added, updated = 0, 0
    for t in catalog.seed_technologies():
        v = _vals(t)
        if t.id not in have:
            con.execute(INSERT, {**v, "id": t.id, "dashboard": int(t.dashboard), "custom": 0, "source": "seed", "edited": 0, "now": now})
            added += 1
        elif have[t.id]["source"] != "custom" and not have[t.id]["edited"] and any(have[t.id][k] != v[k] for k in ("name", "vendor", "product", "kind", "description", "aliases", "cpe_matchers", "nvd_queries", "kev_matchers", "news_patterns")):
            cur = con.execute("UPDATE technology SET name=:name,vendor=:vendor,product=:product,kind=:kind,description=:description,aliases=:aliases,cpe_matchers=:cpe_matchers,"
                              "nvd_queries=:nvd_queries,kev_matchers=:kev_matchers,ambiguous_kev_vendors=:ambiguous_kev_vendors,news_patterns=:news_patterns,correlation_source=:correlation_source,"
                              "updated_at=:now WHERE id=:id AND (name!=:name OR cpe_matchers!=:cpe_matchers OR kev_matchers!=:kev_matchers OR news_patterns!=:news_patterns OR description!=:description "
                              "OR aliases!=:aliases OR nvd_queries!=:nvd_queries OR vendor!=:vendor OR kind!=:kind)", {**v, "id": t.id, "now": now})
            updated += cur.rowcount
    from . import categories, nvd_products
    categories.link(con)               # categories are user-managed: seeds only link NEW rows, they never move or rename anything
    nvd_products.link_existing(con)
    load(con)
    return {"added": added, "updated": updated, "backfilled_articles": backfill_news(con), "total": len(catalog.BY_ID)}


def backfill_news(con, limit: int = 20000) -> int:
    """One-time linking of already stored articles to technologies added after they were collected (explicit patterns only)."""
    ids = [r[0] for r in con.execute("SELECT id FROM technology WHERE backfilled=0 AND enabled=1")]
    if not ids:
        return 0
    pats = {t: [re.compile(p, re.I) for p in catalog.BY_ID[t].news_patterns] for t in ids if t in catalog.BY_ID}
    n = 0
    if any(pats.values()) and con.execute("SELECT 1 FROM sqlite_master WHERE name='news_item'").fetchone():
        for r in con.execute("SELECT id,title,summary FROM news_item ORDER BY sort_ts DESC LIMIT ?", (limit,)).fetchall():
            title, text = r["title"], f"{r['title']} {r['summary'] or ''}"
            for tid, ps in pats.items():
                if ps and (any(p.search(title) for p in ps) or sum(len(p.findall(text)) for p in ps) >= 2):
                    n += con.execute("INSERT OR IGNORE INTO news_tech(news_id,tech_id,basis) VALUES(?,?,'name')", (r["id"], tid)).rowcount
    con.executemany("UPDATE technology SET backfilled=1 WHERE id=?", [(i,) for i in ids])
    return n


# ----------------------------------------------------------------------------- monitoring
def monitored_ids(con) -> set[str]:
    """Technologies that are actively synchronised: dashboard-pinned, in a watchlist, in an active company inventory, or forced on."""
    rows = con.execute(
        "SELECT t.id FROM technology t WHERE t.enabled=1 AND t.monitor!='off' AND (t.monitor='on' OR t.dashboard=1 "
        "OR t.id IN (SELECT ref_id FROM watchlist_item WHERE kind='technology') "
        "OR t.id IN (SELECT ct.tech_id FROM company_technology ct JOIN company c ON c.id=ct.company_id AND c.status='active' "
        "JOIN company_asset a ON a.company_tech_id=ct.id AND a.status='active' WHERE ct.tech_id IS NOT NULL))").fetchall()
    return {r[0] for r in rows}


def monitored_reasons(con, tid: str) -> list[str]:
    t = con.execute("SELECT monitor,dashboard,enabled FROM technology WHERE id=?", (tid,)).fetchone()
    if not t or not t["enabled"] or t["monitor"] == "off":
        return []
    out = []
    if t["monitor"] == "on":
        out.append("forced on by an administrator")
    if t["dashboard"]:
        out.append("shown on the global dashboard")
    if con.execute("SELECT 1 FROM watchlist_item WHERE kind='technology' AND ref_id=? LIMIT 1", (tid,)).fetchone():
        out.append("in a watchlist")
    if con.execute("SELECT 1 FROM company_technology ct JOIN company c ON c.id=ct.company_id AND c.status='active' JOIN company_asset a ON a.company_tech_id=ct.id AND a.status='active' "
                   "WHERE ct.tech_id=? LIMIT 1", (tid,)).fetchone():
        out.append("used in a company inventory")
    return out


def mark_synced(con, tids) -> None:
    con.executemany("UPDATE technology SET last_sync=? WHERE id=?", [(_now(), t) for t in tids])


# ----------------------------------------------------------------------------- admin operations
def _txt(v, name, maxlen, required=False) -> str:
    v = (v or "").strip() if isinstance(v, str) or v is None else str(v).strip()
    if CTRL.search(v):
        raise CatalogError(422, f"{name} contains control characters")
    if required and not v:
        raise CatalogError(422, f"{name} is required")
    if len(v) > maxlen:
        raise CatalogError(422, f"{name} must be at most {maxlen} characters")
    return v


def _norm(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", " ", (s or "").lower()).strip()


def _pairs(t: Technology) -> list[tuple[str, str]]:
    return [(q.split(":")[3], q.split(":", 4)[4]) for q in t.nvd_queries]


def _check_duplicates(t: Technology) -> None:
    names = {_norm(t.name), *(_norm(a) for a in t.aliases)}
    for o in catalog.BY_ID.values():
        if o.id == t.id:
            continue
        if names & {_norm(o.name), *(_norm(a) for a in o.aliases)}:
            raise CatalogError(409, f"Name or alias already used by '{o.id}'")
        for v, p in _pairs(t):
            for vv, rx in o.cpe_matchers:
                if vv == v and re.fullmatch(rx, p):
                    raise CatalogError(409, f"CPE {v}:{p} is already covered by '{o.id}'")


def _build(d: dict, tid: str, existing: Technology | None = None, con=None) -> Technology:
    name = _txt(d.get("name", existing.name if existing else None), "Name", 100, True)
    raw = d["aliases"] if "aliases" in d else (existing.aliases if existing else [])
    aliases = [a for a in dict.fromkeys(_txt(x, "Alias", 60) for x in raw or []) if a][:15]
    category = d.get("category", existing.category if existing else None)
    if con is not None and not (existing and category == existing.category):
        from . import categories
        try:
            category = categories.resolve_active(con, category or "")["name"]
        except categories.CategoryError as e:
            raise CatalogError(e.status, e.msg)
    elif con is None and category not in CATEGORIES:
        raise CatalogError(422, f"category must be one of: {', '.join(CATEGORIES)}")
    kind = d.get("kind", existing.kind if existing else "product")
    if kind not in KINDS:
        raise CatalogError(422, f"kind must be one of: {', '.join(KINDS)}")
    matchers, queries, source = (existing.cpe_matchers, existing.nvd_queries, existing.correlation_source) if existing else ((), (), "none (no CPE)")
    if existing is None or "cpe_vendor" in d or "cpe_product" in d:
        vendor, product, part = (d.get("cpe_vendor") or "").strip().lower(), (d.get("cpe_product") or "").strip().lower(), (d.get("cpe_part") or "a").strip().lower()
        if vendor or product:
            if not (vendor and product) or not CPE_ID_RE.match(vendor) or not CPE_ID_RE.match(product) or part not in ("a", "o", "h"):
                raise CatalogError(422, "Give both cpe_vendor and cpe_product as CPE identifiers (letters, digits, _ . - +) and cpe_part a/o/h")
            matchers, queries = catalog.build_matchers(f"{part}:{vendor}:{product}")
            source = "user-declared CPE (not verified against the NVD dictionary)"
        else:
            matchers, queries, source = (), (), "none (no CPE)"
    patterns = existing.news_patterns if existing else ()
    if d.get("news_terms") is not None:
        out = []
        for x in d["news_terms"][:5]:
            x = _txt(x, "News term", 60)
            if len(x) < 4:
                raise CatalogError(422, "News terms need at least 4 characters (no vague matching)")
            out.append(r"\b" + re.escape(x.lower()) + r"\b")
        patterns = tuple(out)
    return Technology(id=tid, name=name, aliases=tuple(aliases), cpe_matchers=matchers, nvd_queries=queries, kev_matchers=existing.kev_matchers if existing else (), news_patterns=patterns,
                      vendor=_txt(d.get("vendor", existing.vendor if existing else ""), "Vendor", 80), product=_txt(d.get("product", existing.product if existing else ""), "Product", 80),
                      category=category, kind=kind, description=_txt(d.get("description", existing.description if existing else ""), "Description", 300), custom=True, correlation_source=source)


def create_custom(con, d: dict) -> Technology:
    tid = (d.get("id") or "").strip().lower()
    if not ID_RE.match(tid):
        raise CatalogError(422, "id must be 2-49 characters: lowercase letters, digits and dashes")
    if tid in catalog.BY_ID:
        raise CatalogError(409, "A technology with this id already exists")
    t = _build(d, tid, con=con)
    _check_duplicates(t)
    con.execute(INSERT, {**_vals(t), "id": tid, "dashboard": 0, "custom": 1, "source": "custom", "edited": 1, "now": _now()})
    from . import categories
    categories.link(con)
    load(con)
    backfill_news(con)
    _after_cpe_change(con, tid)
    return catalog.BY_ID[tid]


def update_custom(con, tid: str, d: dict) -> Technology:
    cur = catalog.BY_ID.get(tid)
    if not cur:
        raise CatalogError(404, "Technology not found")
    if not cur.custom:
        raise CatalogError(403, "Built-in technologies cannot be edited; change their monitoring or dashboard visibility instead")
    t = _build(d, tid, cur, con)
    _check_duplicates(t)
    v = _vals(t)
    con.execute("UPDATE technology SET name=:name,vendor=:vendor,product=:product,category=:category,kind=:kind,description=:description,aliases=:aliases,cpe_matchers=:cpe_matchers,nvd_queries=:nvd_queries,"
                "news_patterns=:news_patterns,correlation_source=:correlation_source,category_id=NULL,edited=1,backfilled=0,updated_at=:now WHERE id=:id", {**v, "id": tid, "now": _now()})
    from . import categories
    categories.link(con)
    load(con)
    backfill_news(con)
    _after_cpe_change(con, tid)
    return catalog.BY_ID[tid]


def _after_cpe_change(con, tid: str) -> None:
    """A new/edited technology is correlated IMMEDIATELY against the local database (no external request) and its CPE is checked against the local dictionary."""
    from . import intel_corr
    t = catalog.BY_ID[tid]
    pairs = _pairs(t)
    verified = [intel_corr.cpe_exists(con, v, p) for v, p in pairs]
    if pairs and t.correlation_source.startswith("user-declared"):
        src = "user-declared CPE, found in the local NVD data" if all(x is True for x in verified) else \
            "user-declared CPE: NOT found in the local NVD data (check the identifier)" if any(x is False for x in verified) else "user-declared CPE (not verified: no local CPE data yet)"
        con.execute("UPDATE technology SET correlation_source=? WHERE id=?", (src, tid))
        load(con)
    intel_corr.correlate_tech(con, tid)


def set_enabled(con, tid: str, enabled: bool) -> Technology:
    t = catalog.BY_ID.get(tid)
    if not t:
        raise CatalogError(404, "Technology not found")
    if not t.custom:
        raise CatalogError(403, "Only custom technologies can be disabled")
    con.execute("UPDATE technology SET enabled=?,updated_at=? WHERE id=?", (int(enabled), _now(), tid))
    load(con)
    return catalog.BY_ID[tid]


def set_monitor(con, tid: str, mode: str) -> Technology:
    if tid not in catalog.BY_ID:
        raise CatalogError(404, "Technology not found")
    if mode not in MONITOR:
        raise CatalogError(422, f"monitor must be one of {', '.join(MONITOR)}")
    con.execute("UPDATE technology SET monitor=?,updated_at=? WHERE id=?", (mode, _now(), tid))
    load(con)
    return catalog.BY_ID[tid]


def set_dashboard(con, tid: str, pinned: bool) -> Technology:
    t = catalog.BY_ID.get(tid)
    if not t or not t.enabled:
        raise CatalogError(404, "Technology not found")
    if pinned and not t.dashboard and con.execute("SELECT COUNT(*) FROM technology WHERE dashboard=1").fetchone()[0] >= MAX_PINNED:
        raise CatalogError(409, f"At most {MAX_PINNED} pyramids can be shown at once")
    con.execute("UPDATE technology SET dashboard=?,updated_at=? WHERE id=?", (int(pinned), _now(), tid))
    load(con)
    return catalog.BY_ID[tid]
