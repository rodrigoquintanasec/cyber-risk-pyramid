"""Dynamic NVD product catalogue (/api/v1/products) + user-managed categories (/api/v1/categories).

Reads come from the LOCAL SQLite copy of the NVD CPE dictionary (no network). Writes (adding a technology, managing categories) need the existing administrative policy.
A product found here is only a candidate: nothing becomes a monitored technology until the user adds it and chooses its category."""
from __future__ import annotations

import re
from collections import Counter

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request
from pydantic import BaseModel, Field

from . import catalog, catalog_db, categories, db, intel_import, nvd_products
from .catalog_db import CatalogError
from .security import authorize_sync

router = APIRouter(prefix="/api/v1/products", tags=["nvd-products"])
cat_router = APIRouter(prefix="/api/v1/categories", tags=["categories"])

PART_RE = "^[aoh]$"
ID_PART = re.compile(r"^[a-z0-9][a-z0-9_.\-+]{0,99}$")


def admin(request: Request, x_sync_token: str | None = Header(default=None)) -> None:
    authorize_sync(request, x_sync_token)


def _like(s: str) -> str:
    return s.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _vkey(v: str | None):
    return [(0, int(x)) if x.isdigit() else (1, x) for x in re.findall(r"\d+|[A-Za-z]+", v or "")]


# ----------------------------------------------------------------------------- coverage
def coverage(con) -> dict:
    """Which official datasets back the product catalogue, and what the user may (not) conclude from them. Never claims completeness the data does not have."""
    ds = {k: intel_import.dataset_info(con, k) for k in ("cpe", "cpematch", "cve", "kev", "epss")}
    st = {k: v["status"] for k, v in ds.items()}
    ok = ("complete", "updating", "stale")
    dict_ready = st["cpe"] in ok
    cve_ready = st["cve"] in ok
    missing = []
    if not dict_ready:
        missing.append("NVD CPE Dictionary " + ("is not imported" if st["cpe"] == "not_initialized" else f"is {st['cpe']}") + ": product discovery is unavailable or incomplete.")
    if st["cpematch"] not in ok:
        missing.append(f"NVD CPE Match Criteria is {st['cpematch'].replace('_', ' ')}: the match-criteria registry is missing; CVE applicability relies on the NVD configurations stored with each CVE.")
    if not cve_ready:
        missing.append(f"NVD CVE data is {st['cve'].replace('_', ' ')}: CVE counts are not reliable and must not be read as 'no vulnerabilities'.")
    if "stale" in st.values():
        missing.append("At least one dataset is stale: refresh it from Settings.")
    state = "not_initialized" if st["cpe"] == "not_initialized" else "complete" if not missing else "partial"
    label = {"not_initialized": "Dataset Not Initialized", "complete": "Vulnerability Data Available", "partial": "Partial Coverage"}[state]
    dates = {k: ds[k].get("dataset_date") or ds[k].get("last_success") for k in ds}
    return {"state": state, "label": label, "datasets": st, "dataset_dates": dates, "dictionary_ready": dict_ready, "cve_counts_reliable": cve_ready and dict_ready,
            "limitations": missing, "products_indexed": con.execute("SELECT COUNT(*) FROM nvd_product").fetchone()[0], "vendors_indexed": con.execute("SELECT COUNT(*) FROM nvd_vendor").fetchone()[0]}


def _existing(con, part: str, vendor: str, product: str):
    """The technology already covering this exact NVD product identity (explicit link, or a declared CPE matcher). Never matched by similar names."""
    r = con.execute("SELECT t.id,t.name,t.category,t.enabled,t.custom,tp.role FROM technology_product tp JOIN technology t ON t.id=tp.tech_id "
                    "WHERE tp.part=? AND tp.vendor=? AND tp.product=? ORDER BY (tp.role='primary') DESC LIMIT 1", (part, vendor, product)).fetchone()
    if r:
        return dict(r)
    for t in catalog.BY_ID.values():
        for v, rx in t.cpe_matchers:
            if v == vendor and re.fullmatch(rx, product):
                x = con.execute("SELECT id,name,category,enabled,custom FROM technology WHERE id=?", (t.id,)).fetchone()
                if x:
                    return {**dict(x), "role": "matcher"}
    return None


def _shape(con, r, cov: dict, cves: dict) -> dict:
    ex = _existing(con, r["part"], r["vendor"], r["product"])
    n = cves.get((r["vendor"], r["product"]))
    return {"part": r["part"], "type": nvd_products.PARTS.get(r["part"], r["part"]), "vendor": r["vendor"], "product": r["product"], "name": r["display_name"], "cpe_count": r["cpe_count"],
            "version_count": r["version_count"], "deprecated": r["active_count"] == 0, "deprecated_records": r["cpe_count"] - r["active_count"], "last_modified": r["last_modified"],
            "cve_count": n if cov["cve_counts_reliable"] else None, "cve_count_reliable": cov["cve_counts_reliable"], "already_in_catalog": ex}


# ----------------------------------------------------------------------------- read API
@router.get("/status")
def status():
    with db.connect() as con:
        return coverage(con)


@router.get("/vendors")
def vendors(q: str = Query("", max_length=60), limit: int = Query(12, ge=1, le=50)):
    qn = re.sub(r"[^a-z0-9]+", "_", q.lower()).strip("_")
    with db.connect() as con:
        if qn:
            rows = con.execute("SELECT vendor,products,active_products,cpe_count FROM nvd_vendor WHERE vendor LIKE ? ESCAPE '\\' OR vendor LIKE ? ESCAPE '\\' "
                               "ORDER BY (vendor=?) DESC, (vendor LIKE ? ESCAPE '\\') DESC, products DESC LIMIT ?", (_like(qn) + "%", "%" + _like(qn) + "%", qn, _like(qn) + "%", limit)).fetchall()
        else:
            rows = con.execute("SELECT vendor,products,active_products,cpe_count FROM nvd_vendor ORDER BY products DESC LIMIT ?", (limit,)).fetchall()
    return {"items": [dict(r) for r in rows]}


@router.get("/search")
def search(q: str = Query("", max_length=80), vendor: str | None = Query(None, max_length=100), part: str | None = Query(None, pattern=PART_RE),
           deprecated: str = Query("hide", pattern="^(hide|show|only)$"), sort: str = Query("relevance", pattern="^(relevance|name|cves|versions)$"),
           page: int = Query(1, ge=1, le=500), page_size: int = Query(20, ge=1, le=50)):
    toks = [t for t in re.split(r"[^a-z0-9]+", q.lower()) if t][:6]
    where, args = [], []
    for t in toks:
        where.append("p.search_text LIKE ? ESCAPE '\\'")
        args.append("%" + _like(t) + "%")
    if vendor:
        where.append("p.vendor=?")
        args.append(vendor.strip().lower())
    if part:
        where.append("p.part=?")
        args.append(part)
    if deprecated == "hide":
        where.append("p.active_count>0")
    elif deprecated == "only":
        where.append("p.active_count=0")
    w = ("WHERE " + " AND ".join(where)) if where else ""
    qn = "_".join(toks)
    rank = "CASE WHEN p.product=? THEN 0 WHEN p.vendor=? THEN 1 WHEN p.product LIKE ? ESCAPE '\\' THEN 2 WHEN p.vendor LIKE ? ESCAPE '\\' THEN 3 ELSE 4 END" if toks else "(0)"
    rank_args = [qn, qn, _like(qn) + "%", _like(qn) + "%"] if toks else []
    order = {"relevance": f"{rank}, p.active_count DESC, p.product" if toks else "p.active_count DESC, p.product", "name": "p.display_name COLLATE NOCASE, p.vendor", "cves": "COALESCE(s.cves,0) DESC, p.product", "versions": "p.version_count DESC, p.product"}[sort]
    with db.connect() as con:
        cov = coverage(con)
        total = con.execute(f"SELECT COUNT(*) FROM nvd_product p {w}", args).fetchone()[0]
        join = "LEFT JOIN cve_product_stats s ON s.vendor=p.vendor AND s.product=p.product" if sort == "cves" else ""
        rows = con.execute(f"SELECT p.* FROM nvd_product p {join} {w} ORDER BY {order} LIMIT ? OFFSET ?", [*args, *(rank_args if sort == "relevance" and toks else []), page_size, (page - 1) * page_size]).fetchall()
        cves = {}
        if rows and cov["cve_counts_reliable"]:
            for r in rows:
                x = con.execute("SELECT cves FROM cve_product_stats WHERE vendor=? AND product=?", (r["vendor"], r["product"])).fetchone()
                cves[(r["vendor"], r["product"])] = x[0] if x else 0
        items = [_shape(con, r, cov, cves) for r in rows]
    return {"items": items, "total": total, "page": page, "page_size": page_size, "pages": max(1, -(-total // page_size)), "coverage": {k: cov[k] for k in ("state", "label", "limitations", "dictionary_ready")},
            "note": "Candidates from the local NVD CPE dictionary. A product is not monitored until you add it to the Technology Catalog."}


def _split(name: str) -> list[str]:
    return [x.replace("\\:", ":") for x in re.split(r"(?<!\\):", name)]


def _identity(con, part: str, vendor: str, product: str):
    r = con.execute("SELECT * FROM nvd_product WHERE part=? AND vendor=? AND product=?", (part, vendor, product)).fetchone()
    if not r:
        raise HTTPException(404, "Product not found in the local NVD CPE dictionary")
    return r


@router.get("/detail")
def detail(part: str = Query(..., pattern=PART_RE), vendor: str = Query(..., max_length=100), product: str = Query(..., max_length=100)):
    with db.connect() as con:
        cov = coverage(con)
        r = _identity(con, part, vendor, product)
        recs = con.execute("SELECT cpe_name,version,deprecated,deprecated_by,refs,last_modified FROM cpe_dictionary WHERE part=? AND vendor=? AND product=? LIMIT 60000", (part, vendor, product)).fetchall()
        variants: Counter = Counter()
        vers: dict[str, dict] = {}
        refs: dict[str, str | None] = {}
        dep_by: set[str] = set()
        for x in recs:
            c = _split(x["cpe_name"])
            v = x["version"] or "any"
            e = vers.setdefault(v, {"version": v, "records": 0, "active": 0})
            e["records"] += 1
            e["active"] += 0 if x["deprecated"] else 1
            vk = tuple(c[i] if len(c) > i and c[i] not in ("*", "-") else "" for i in (7, 9, 10, 11, 12))
            if any(vk):
                variants[vk] += 1
            if x["refs"] and len(refs) < 8:
                try:
                    for ref in __import__("json").loads(x["refs"]):
                        refs.setdefault(ref["ref"] if isinstance(ref, dict) else ref, ref.get("type") if isinstance(ref, dict) else None)
                except ValueError:
                    pass
            if x["deprecated"] and x["deprecated_by"] and len(dep_by) < 10:
                dep_by.update(__import__("json").loads(x["deprecated_by"]))
        ex = _existing(con, part, vendor, product)
        cves = kev = None
        if cov["cve_counts_reliable"]:
            s = con.execute("SELECT cves FROM cve_product_stats WHERE vendor=? AND product=?", (vendor, product)).fetchone()
            cves = s[0] if s else 0
            kev = con.execute("SELECT COUNT(DISTINCT c.cve_id) FROM cve_cpe c JOIN kev_entry k ON k.cve_id=c.cve_id WHERE c.vendor=? AND c.product=?", (vendor, product)).fetchone()[0]
        related = [dict(x) for x in con.execute("SELECT product,display_name,cpe_count FROM nvd_product WHERE part=? AND vendor=? AND product!=? AND (product LIKE ? ESCAPE '\\' OR product LIKE ? ESCAPE '\\') ORDER BY cpe_count DESC LIMIT 8",
                                                (part, vendor, product, _like(product) + "\\_%", _like(product.split("_")[0]) + "%"))]
        ids = [x["cpe_name"] for x in recs[:12]]
    ordered = sorted(vers.values(), key=lambda e: _vkey(e["version"]), reverse=True)
    return {**_shape_min(r), "cpe_identifiers": ids, "cpe_identifier_count": r["cpe_count"], "versions_preview": ordered[:30], "version_count": len(vers),
            "variants": [{"edition": k[0], "sw_edition": k[1], "target_sw": k[2], "target_hw": k[3], "other": k[4], "records": n} for k, n in variants.most_common(30)], "variant_count": len(variants),
            "references": [{"url": u, "type": t} for u, t in refs.items()], "deprecated_by": sorted(dep_by), "truncated": len(recs) >= 60000,
            "cve_count": cves, "kev_count": kev, "cve_count_reliable": cov["cve_counts_reliable"], "coverage": cov, "already_in_catalog": ex, "related_products": related,
            "note": "Versions identify what exists in the CPE dictionary. Whether a CVE applies to a version is decided from the CVE's own NVD configuration, not from this list."}


def _shape_min(r) -> dict:
    return {"part": r["part"], "type": nvd_products.PARTS.get(r["part"], r["part"]), "vendor": r["vendor"], "product": r["product"], "name": r["display_name"], "cpe_count": r["cpe_count"],
            "deprecated": r["active_count"] == 0, "deprecated_records": r["cpe_count"] - r["active_count"], "last_modified": r["last_modified"]}


@router.get("/versions")
def versions(part: str = Query(..., pattern=PART_RE), vendor: str = Query(..., max_length=100), product: str = Query(..., max_length=100), q: str = Query("", max_length=40),
             deprecated: str = Query("hide", pattern="^(hide|show)$"), page: int = Query(1, ge=1, le=500), page_size: int = Query(50, ge=1, le=200)):
    with db.connect() as con:
        _identity(con, part, vendor, product)
        rows = con.execute("SELECT version,COUNT(*) n,MAX(deprecated=0) active FROM cpe_dictionary WHERE part=? AND vendor=? AND product=? AND version LIKE ? ESCAPE '\\' GROUP BY version",
                           (part, vendor, product, _like(q.lower()) + "%")).fetchall()
    items = [{"version": r["version"] or "any", "records": r["n"], "deprecated": not r["active"]} for r in rows if deprecated == "show" or r["active"]]
    items.sort(key=lambda e: _vkey(e["version"]), reverse=True)
    return {"items": items[(page - 1) * page_size: page * page_size], "total": len(items), "page": page, "page_size": page_size}


@router.get("/tech/{tid}/versions")
def tech_versions(tid: str, q: str = Query("", max_length=40), limit: int = Query(40, ge=1, le=100)):
    """Version suggestions for registering a company asset of a catalogue technology (from its linked NVD products; free text is always accepted)."""
    with db.connect() as con:
        links = con.execute("SELECT part,vendor,product FROM technology_product WHERE tech_id=?", (tid,)).fetchall()
        if not links:
            return {"items": [], "source": None}
        out: dict[str, str] = {}
        for ln in links[:8]:
            for r in con.execute("SELECT DISTINCT version FROM cpe_dictionary WHERE part=? AND vendor=? AND product=? AND deprecated=0 AND version IS NOT NULL AND version LIKE ? ESCAPE '\\' LIMIT 400",
                                 (ln["part"], ln["vendor"], ln["product"], _like(q.lower()) + "%")):
                out[r[0]] = ln["product"]
    ql = q.strip().lower()
    ordered = sorted(out.items(), key=lambda kv: _vkey(kv[0]), reverse=True)
    ordered = [kv for kv in ordered if kv[0] == ql] + [kv for kv in ordered if kv[0] != ql]          # an exact match is offered first
    return {"items": [{"version": v, "product": p} for v, p in ordered[:limit]], "source": "NVD CPE dictionary"}


@router.get("/monitored")
def monitored():
    """Technologies linked to NVD products (explicitly added or built-in with declared CPEs)."""
    with db.connect() as con:
        rows = con.execute("SELECT t.id,t.name,t.category,t.source,t.enabled,tp.part,tp.vendor,tp.product,tp.role FROM technology_product tp JOIN technology t ON t.id=tp.tech_id ORDER BY t.name COLLATE NOCASE").fetchall()
    return {"items": [dict(r) for r in rows], "added_from_nvd": sum(1 for r in rows if r["source"] == "nvd" and r["role"] == "primary")}


# ----------------------------------------------------------------------------- add a technology
class Ident(BaseModel):
    part: str = Field(..., pattern=PART_RE)
    vendor: str = Field(..., max_length=100)
    product: str = Field(..., max_length=100)


class AddIn(Ident):
    category: str = Field(..., min_length=1, max_length=60)
    name: str | None = Field(None, max_length=100)
    description: str | None = Field(None, max_length=300)
    family: list[Ident] | None = Field(None, max_length=12)
    news_terms: list[str] | None = Field(None, max_length=5)


def _slug_id(con, vendor: str, product: str) -> str:
    base = re.sub(r"[^a-z0-9]+", "-", f"{vendor}-{product}".lower()).strip("-")[:44] or "product"
    tid, n = base, 2
    while con.execute("SELECT 1 FROM technology WHERE id=?", (tid,)).fetchone() or not catalog_db.ID_RE.match(tid):
        tid, n = f"{base[:44]}-{n}", n + 1
    return tid


@router.post("/add", dependencies=[Depends(admin)])
def add(body: AddIn):
    idents = [body, *(body.family or [])]
    seen, uniq = set(), []
    for i in idents:
        k = (i.part, i.vendor.strip().lower(), i.product.strip().lower())
        if k not in seen and ID_PART.match(k[1]) and ID_PART.match(k[2]):
            seen.add(k)
            uniq.append(k)
    if len(uniq) != len({(i.part, i.vendor.strip().lower(), i.product.strip().lower()) for i in idents}):
        raise HTTPException(422, "Invalid CPE identifier")
    try:
        with db.connect() as con:
            if not con.execute("SELECT 1 FROM nvd_product LIMIT 1").fetchone():
                raise HTTPException(409, "The NVD CPE dictionary is not imported yet: products cannot be resolved. Initialize it from Settings → Local Intelligence Database.")
            rows = [_identity(con, *k) for k in uniq]
            for k in uniq:
                ex = _existing(con, *k)
                if ex:
                    return {"created": False, "already_in_catalog": True, "technology": ex, "message": f"Already in Technology Catalog: {ex['name']}"}
            cat = categories.resolve_active(con, body.category)
            main = rows[0]
            name = (body.name or main["display_name"] or main["product"]).strip()
            tid = _slug_id(con, main["vendor"], main["product"])
            tokens = " ".join(f"{k[0]}:{k[1]}:{k[2]}" for k in uniq)
            matchers, queries = catalog.build_matchers(tokens)
            vend_name = main["vendor"].replace("_", " ").title()
            news = []
            for x in (body.news_terms or [])[:5]:
                x = catalog_db._txt(x, "News term", 60)
                if len(x) < 4:
                    raise CatalogError(422, "News terms need at least 4 characters (no vague matching)")
                news.append(r"\b" + re.escape(x.lower()) + r"\b")
            t = catalog.Technology(id=tid, name=name, aliases=(), cpe_matchers=matchers, nvd_queries=queries, kev_matchers=(), news_patterns=tuple(news), vendor=vend_name,
                                   product=main["display_name"] or main["product"], category=cat["name"], kind="family" if len(uniq) > 1 else "product",
                                   description=catalog_db._txt(body.description, "Description", 300), custom=True, correlation_source="NVD CPE dictionary (selected by the user, verified in the local dictionary)")
            catalog_db._check_duplicates(t)
            con.execute(catalog_db.INSERT, {**catalog_db._vals(t), "id": tid, "dashboard": 0, "custom": 1, "source": "nvd", "edited": 1, "now": catalog_db._now()})
            for i, k in enumerate(uniq):
                con.execute("INSERT OR IGNORE INTO technology_product(tech_id,part,vendor,product,role,added_at) VALUES(?,?,?,?,?,?)", (tid, *k, "primary" if i == 0 else "related", catalog_db._now()))
            categories.link(con)
            catalog_db.load(con)
            catalog_db.backfill_news(con)
            catalog_db._after_cpe_change(con, tid)
            counts = {"recent": con.execute("SELECT COUNT(*) FROM tech_cve WHERE tech_id=?", (tid,)).fetchone()[0], "historical": con.execute("SELECT COUNT(*) FROM tech_cve_hist WHERE tech_id=?", (tid,)).fetchone()[0]}
            cov = coverage(con)
        return {"created": True, "already_in_catalog": False, "technology": {"id": tid, "name": name, "category": cat["name"]}, "correlated_cves": counts,
                "coverage": {k: cov[k] for k in ("state", "label", "limitations")}, "message": f"{name} added to the Technology Catalog"}
    except CatalogError as e:
        raise HTTPException(e.status, e.msg)
    except categories.CategoryError as e:
        raise HTTPException(e.status, e.msg)


# ----------------------------------------------------------------------------- categories
class CatIn(BaseModel):
    name: str | None = Field(None, max_length=60)
    description: str | None = Field(None, max_length=300)
    sort_order: int | None = Field(None, ge=0, le=100000)
    active: bool | None = None


class OrderIn(BaseModel):
    ids: list[str] = Field(..., max_length=200)


class AssignIn(BaseModel):
    tech_ids: list[str] = Field(..., min_length=1, max_length=200)
    category: str = Field(..., max_length=60)


def _cat(fn, *a):
    try:
        with db.connect() as con:
            out = fn(con, *a)
            if fn in (categories.update, categories.create, categories.assign, categories.reorder, categories.delete):
                catalog_db.load(con)          # names may have changed: refresh the registry
            return out
    except categories.CategoryError as e:
        raise HTTPException(e.status, e.msg)


@cat_router.get("")
def cat_list(include_inactive: bool = True):
    return {"items": _cat(categories.list_all, include_inactive)}


@cat_router.post("", dependencies=[Depends(admin)])
def cat_create(b: CatIn):
    return _cat(categories.create, b.model_dump(exclude_none=True))


@cat_router.put("/order", dependencies=[Depends(admin)])
def cat_order(b: OrderIn):
    return {"items": _cat(categories.reorder, b.ids)}


@cat_router.post("/assign", dependencies=[Depends(admin)])
def cat_assign(b: AssignIn):
    return {"moved": _cat(categories.assign, b.tech_ids, b.category)}


@cat_router.put("/{cid}", dependencies=[Depends(admin)])
def cat_update(cid: str, b: CatIn):
    return _cat(categories.update, cid, b.model_dump(exclude_none=True))


@cat_router.delete("/{cid}", dependencies=[Depends(admin)])
def cat_delete(cid: str):
    _cat(categories.delete, cid)
    return {"deleted": True}


@cat_router.get("/{cid}/technologies")
def cat_techs(cid: str):
    return {"items": _cat(categories.technologies, cid)}
