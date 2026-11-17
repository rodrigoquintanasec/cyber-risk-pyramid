"""Company profiles and manually-maintained technology inventories (SQLite).

Concepts kept apart: a PRODUCT (company_technology: catalog technology or an explicit vendor/product CPE identity) and an ASSET
(company_asset: one concrete instance/system with its own version). Every query is scoped by company_id.
`owner_id` is reserved for a future multi-user model; today this is a local administrative tool (see security notes in company_api).
"""
from __future__ import annotations

import re
import sqlite3
import uuid
from datetime import date, datetime, timezone

from . import db
from .catalog import BY_ID
from .correlation import match_cpe
from .exposure import has_version_info, norm

OWNER = "local"
ENVS = ("production", "development", "testing", "other")
CRITS = ("low", "medium", "high", "critical")
EXPOSED = ("yes", "no", "unknown")
ASSET_STATUS = ("active", "retired")
CID_RE = re.compile(r"^cmp_[0-9a-f]{12}$")
IDENT_RE = re.compile(r"^[a-z0-9][a-z0-9_.\-+]{0,79}$")
VER_FIELD_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._\-+]{0,39}$")
CTRL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")
MAX_COMPANIES = 200
MAX_ASSETS = 5000


class CompanyError(Exception):
    def __init__(self, status: int, msg: str):
        super().__init__(msg)
        self.status, self.msg = status, msg


_ver = [0]


def touch() -> int:
    """Bumped on every inventory/assessment write so cached exposure is never stale (timestamps only have 1 s resolution)."""
    _ver[0] += 1
    return _ver[0]


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _txt(v, name: str, maxlen: int, required=False) -> str | None:
    v = (v or "").strip() if isinstance(v, str) or v is None else str(v).strip()
    if CTRL.search(v):
        raise CompanyError(422, f"{name} contains control characters")
    if required and not v:
        raise CompanyError(422, f"{name} is required")
    if len(v) > maxlen:
        raise CompanyError(422, f"{name} must be at most {maxlen} characters")
    return v or None


def log_event(con, company_id: str, kind: str, ref: str | None = None, detail: str | None = None) -> None:
    touch()
    con.execute("INSERT INTO company_event(company_id,kind,ref,detail,occurred_at) VALUES(?,?,?,?,?)", (company_id, kind, ref, (detail or "")[:300] or None, _now()))


# ----------------------------------------------------------------------------- companies
def valid_id(cid: str) -> str:
    if not CID_RE.match(cid or ""):
        raise CompanyError(404, "Company not found")
    return cid


def get(con, cid: str, *, writable=False) -> dict:
    r = con.execute("SELECT * FROM company WHERE id=? AND owner_id=?", (valid_id(cid), OWNER)).fetchone()
    if not r:
        raise CompanyError(404, "Company not found")
    if writable and r["status"] != "active":
        raise CompanyError(409, "The company is archived: restore it before changing its inventory")
    return dict(r)


def _profile(con, r) -> dict:
    a = con.execute("SELECT COUNT(*) FILTER (WHERE status='active'), COUNT(*) FILTER (WHERE status='retired'), MAX(last_verified) FROM company_asset WHERE company_id=?", (r["id"],)).fetchone()
    t = con.execute("SELECT COUNT(*) FROM company_technology ct WHERE company_id=? AND EXISTS (SELECT 1 FROM company_asset a WHERE a.company_tech_id=ct.id AND a.status='active')", (r["id"],)).fetchone()[0]
    return {"id": r["id"], "name": r["name"], "trade_name": r["trade_name"], "industry": r["industry"], "country": r["country"], "description": r["description"],
            "status": r["status"], "created_at": r["created_at"], "updated_at": r["updated_at"], "archived_at": r["archived_at"],
            "technologies": t, "assets": a[0], "retired_assets": a[1], "last_verified": a[2]}


def profile(con, cid: str) -> dict:
    return _profile(con, get(con, cid))


def create(con, d: dict) -> dict:
    name = _txt(d.get("name"), "Name", 120, True)
    if con.execute("SELECT COUNT(*) FROM company WHERE owner_id=?", (OWNER,)).fetchone()[0] >= MAX_COMPANIES:
        raise CompanyError(409, "Company limit reached")
    cid, now = "cmp_" + uuid.uuid4().hex[:12], _now()
    try:
        con.execute("INSERT INTO company(id,name,trade_name,industry,country,description,status,owner_id,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
                    (cid, name, _txt(d.get("trade_name"), "Trade name", 120), _txt(d.get("industry"), "Industry", 80, True), _txt(d.get("country"), "Country", 80),
                     _txt(d.get("description"), "Description", 1000), "active", OWNER, now, now))
    except sqlite3.IntegrityError:
        raise CompanyError(409, "A company with this name already exists")
    log_event(con, cid, "company_created", cid, name)
    return profile(con, cid)


def update(con, cid: str, d: dict) -> dict:
    cur = get(con, cid)
    fields = {"name": ("Name", 120, True), "trade_name": ("Trade name", 120, False), "industry": ("Industry", 80, True), "country": ("Country", 80, False), "description": ("Description", 1000, False)}
    vals = {k: (_txt(d[k], lbl, ml, req) if k in d else cur[k]) for k, (lbl, ml, req) in fields.items()}
    status = d.get("status", cur["status"])
    if status not in ("active", "archived"):
        raise CompanyError(422, "status must be active or archived")
    try:
        con.execute("UPDATE company SET name=?,trade_name=?,industry=?,country=?,description=?,status=?,updated_at=?,archived_at=? WHERE id=?",
                    (vals["name"], vals["trade_name"], vals["industry"], vals["country"], vals["description"], status, _now(),
                     _now() if status == "archived" and cur["status"] != "archived" else (None if status == "active" else cur["archived_at"]), cid))
    except sqlite3.IntegrityError:
        raise CompanyError(409, "A company with this name already exists")
    if status != cur["status"]:
        log_event(con, cid, "company_archived" if status == "archived" else "company_restored", cid)
    return profile(con, cid)


def list_companies(con, *, q=None, status="active", industry=None, page=1, page_size=25) -> dict:
    page, page_size = max(1, page), max(1, min(50, page_size))
    where, args = ["owner_id=?"], [OWNER]
    if status in ("active", "archived"):
        where.append("status=?"); args.append(status)
    if q:
        like = "%" + q.strip()[:80].replace("!", "!!").replace("%", "!%").replace("_", "!_") + "%"
        where.append("(name LIKE ? ESCAPE '!' OR trade_name LIKE ? ESCAPE '!')"); args += [like, like]
    if industry:
        where.append("industry=? COLLATE NOCASE"); args.append(industry)
    w = " WHERE " + " AND ".join(where)
    total = con.execute(f"SELECT COUNT(*) FROM company{w}", args).fetchone()[0]
    rows = con.execute(f"SELECT * FROM company{w} ORDER BY name COLLATE NOCASE LIMIT ? OFFSET ?", [*args, page_size, (page - 1) * page_size]).fetchall()
    inds = [r[0] for r in con.execute("SELECT DISTINCT industry FROM company WHERE owner_id=? ORDER BY industry COLLATE NOCASE", (OWNER,))]
    return {"items": [_profile(con, r) for r in rows], "total": total, "page": page, "page_size": page_size, "pages": max(1, -(-total // page_size)), "industries": inds}


# ----------------------------------------------------------------------------- products (company_technology) and assets
def resolve_product(d: dict) -> tuple[str | None, str | None, str | None, str]:
    """(tech_id, vendor, product, label). Catalog id, or explicit CPE vendor+product. A custom pair that structurally matches a catalog
    technology is linked to it; nothing is matched by name similarity."""
    tid = (d.get("tech_id") or "").strip() or None
    if tid:
        if tid not in BY_ID:
            raise CompanyError(422, f"Unknown catalog technology: {tid}")
        return tid, None, None, BY_ID[tid].name
    v, p = norm(d.get("vendor")), norm(d.get("product"))
    if not v or not p:
        raise CompanyError(422, "Choose a catalog technology, or give both vendor and product (CPE identifiers, e.g. fortinet / fortios)")
    if not IDENT_RE.match(v) or not IDENT_RE.match(p):
        raise CompanyError(422, "Vendor and product must be CPE-style identifiers (letters, numbers, _ . - +)")
    t = match_cpe(v, p)
    if t:
        return t.id, v, p, t.name
    label = _txt(d.get("label"), "Label", 100) or f"{v} {p}".replace("_", " ")
    return None, v, p, label


def _find_or_create_product(con, cid: str, d: dict) -> int:
    tid, v, p, label = resolve_product(d)
    if tid and not (v and p):
        r = con.execute("SELECT id FROM company_technology WHERE company_id=? AND tech_id=?", (cid, tid)).fetchone()
    elif tid:
        r = con.execute("SELECT id FROM company_technology WHERE company_id=? AND tech_id=?", (cid, tid)).fetchone()
    else:
        r = con.execute("SELECT id FROM company_technology WHERE company_id=? AND tech_id IS NULL AND vendor=? AND product=?", (cid, v, p)).fetchone()
    if r:
        return r[0]
    cur = con.execute("INSERT INTO company_technology(company_id,tech_id,vendor,product,label,created_at) VALUES(?,?,?,?,?,?)",
                      (cid, tid, None if tid else v, None if tid else p, label, _now()))   # catalog rows stay family-level: no per-asset product guess
    log_event(con, cid, "technology_added", str(cur.lastrowid), label)
    return cur.lastrowid


def _asset_fields(d: dict, cur: dict | None = None) -> dict:
    g = lambda k, dflt=None: d[k] if k in d else (cur[k] if cur else dflt)  # noqa: E731
    out = {"asset_ref": _txt(g("asset_ref"), "Asset id", 80), "notes": _txt(g("notes"), "Notes", 500)}
    for k in ("version", "version_min", "version_max"):
        v = _txt(g(k), k, 40)
        if v and not VER_FIELD_RE.match(v):
            raise CompanyError(422, f"{k} contains invalid characters")
        out[k] = v
    if out["version"] and (out["version_min"] or out["version_max"]):
        raise CompanyError(422, "Give either an exact version or a range, not both")
    for k, allowed, dflt in (("environment", ENVS, "production"), ("criticality", CRITS, "medium"), ("internet_exposed", EXPOSED, "unknown"), ("status", ASSET_STATUS, "active")):
        v = g(k, dflt) or dflt
        if v not in allowed:
            raise CompanyError(422, f"{k} must be one of {', '.join(allowed)}")
        out[k] = v
    lv = g("last_verified")
    if lv:
        try:
            lv = date.fromisoformat(str(lv)[:10]).isoformat()
        except ValueError:
            raise CompanyError(422, "last_verified must be a date (YYYY-MM-DD)")
        if lv > date.today().isoformat():
            raise CompanyError(422, "last_verified cannot be in the future")
    out["last_verified"] = lv or None
    return out


def add_asset(con, cid: str, d: dict) -> dict:
    get(con, cid, writable=True)
    if con.execute("SELECT COUNT(*) FROM company_asset WHERE company_id=?", (cid,)).fetchone()[0] >= MAX_ASSETS:
        raise CompanyError(409, "Asset limit reached")
    f = _asset_fields(d)
    ctid = _find_or_create_product(con, cid, d)
    now = _now()
    cur = con.execute("INSERT INTO company_asset(company_id,company_tech_id,asset_ref,version,version_min,version_max,environment,criticality,internet_exposed,status,last_verified,notes,created_at,updated_at) "
                      "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)", (cid, ctid, f["asset_ref"], f["version"], f["version_min"], f["version_max"], f["environment"], f["criticality"],
                                                              f["internet_exposed"], f["status"], f["last_verified"], f["notes"], now, now))
    log_event(con, cid, "asset_added", str(cur.lastrowid), con.execute("SELECT label FROM company_technology WHERE id=?", (ctid,)).fetchone()[0])
    return asset(con, cid, cur.lastrowid)


def asset(con, cid: str, aid: int) -> dict:
    r = con.execute("SELECT a.*, t.label, t.tech_id, t.vendor, t.product FROM company_asset a JOIN company_technology t ON t.id=a.company_tech_id WHERE a.id=? AND a.company_id=?", (aid, cid)).fetchone()
    if not r:
        raise CompanyError(404, "Asset not found")
    return dict(r)


def update_asset(con, cid: str, aid: int, d: dict) -> dict:
    get(con, cid, writable=True)
    cur = asset(con, cid, aid)
    f = _asset_fields(d, cur)
    con.execute("UPDATE company_asset SET asset_ref=?,version=?,version_min=?,version_max=?,environment=?,criticality=?,internet_exposed=?,status=?,last_verified=?,notes=?,updated_at=? WHERE id=? AND company_id=?",
                (f["asset_ref"], f["version"], f["version_min"], f["version_max"], f["environment"], f["criticality"], f["internet_exposed"], f["status"], f["last_verified"], f["notes"], _now(), aid, cid))
    changed = [k for k in f if f[k] != cur[k]]
    if changed:
        log_event(con, cid, "asset_retired" if f["status"] == "retired" and cur["status"] != "retired" else "asset_updated", str(aid), f"{cur['label']}: {', '.join(changed)}")
    return asset(con, cid, aid)


def inventory(con, cid: str, *, include_retired=True) -> dict:
    get(con, cid)
    techs = [dict(r) for r in con.execute("SELECT * FROM company_technology WHERE company_id=? ORDER BY label COLLATE NOCASE", (cid,))]
    assets = [dict(r) for r in con.execute("SELECT * FROM company_asset WHERE company_id=? ORDER BY id", (cid,))
              if include_retired or True]
    by: dict[int, list] = {}
    for a in assets:
        by.setdefault(a["company_tech_id"], []).append(a)
    for t in techs:
        t["assets"] = by.get(t["id"], [])
        t["active_assets"] = sum(1 for a in t["assets"] if a["status"] == "active")
        t["catalog"] = bool(t["tech_id"])
        t["score_available"] = bool(t["tech_id"])
    return {"technologies": techs, "assets": len(assets), "active_assets": sum(1 for a in assets if a["status"] == "active")}


def coverage(assets: list[dict]) -> dict:
    """Inventory completeness (data quality), not security posture."""
    act = [a for a in assets if a["status"] == "active"]
    n = len(act)
    today = date.today()
    def pct(c): return None if not n else round(100 * c / n, 1)
    ages = []
    for a in act:
        if a["last_verified"]:
            ages.append((today - date.fromisoformat(a["last_verified"])).days)
    return {"active_assets": n, "with_version_pct": pct(sum(1 for a in act if has_version_info(a))), "exposure_known_pct": pct(sum(1 for a in act if a["internet_exposed"] != "unknown")),
            "verified_pct": pct(len(ages)), "verified_90d_pct": pct(sum(1 for x in ages if x <= 90)), "median_verification_age_days": sorted(ages)[len(ages) // 2] if ages else None,
            "oldest_verification_days": max(ages) if ages else None,
            "inventory_coverage": None if not n else round((pct(sum(1 for a in act if has_version_info(a))) + pct(sum(1 for x in ages if x <= 90))) / 2, 1)}
