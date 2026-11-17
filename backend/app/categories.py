"""User-managed technology categories (SQLite). Categories belong to Cyber Risk Pyramid: NVD updates and seed syncs never create, rename or reassign them.

`technology.category` keeps the category NAME (the rest of the platform reads it) and `technology.category_id` is the stable reference; a rename rewrites the name copy.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone

from .catalog_seed import CATEGORIES as SEED

SCHEMA = """
CREATE TABLE IF NOT EXISTS technology_category(
  id TEXT PRIMARY KEY, name TEXT NOT NULL, description TEXT NOT NULL DEFAULT '', sort_order INTEGER NOT NULL DEFAULT 0,
  active INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL, modified_at TEXT NOT NULL);
CREATE UNIQUE INDEX IF NOT EXISTS ux_tcat_name ON technology_category(name COLLATE NOCASE);
CREATE INDEX IF NOT EXISTS ix_tech_catid ON technology(category_id);
"""
CTRL = re.compile(r"[\x00-\x1f\x7f]")


class CategoryError(Exception):
    def __init__(self, status: int, msg: str):
        super().__init__(msg)
        self.status, self.msg = status, msg


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def slug(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")[:48] or "category"


def migrate(con) -> None:
    """Idempotent: create the table, import the 15 built-in categories once, and link every technology by name (unknown names become categories, never lost)."""
    if "category_id" not in {r[1] for r in con.execute("PRAGMA table_info(technology)")}:
        con.execute("ALTER TABLE technology ADD COLUMN category_id TEXT")
    con.executescript(SCHEMA)
    now = _now()
    if con.execute("SELECT COUNT(*) FROM technology_category").fetchone()[0] == 0:
        for i, name in enumerate(SEED):
            con.execute("INSERT OR IGNORE INTO technology_category(id,name,description,sort_order,active,created_at,modified_at) VALUES(?,?,?,?,1,?,?)", (slug(name), name, "", (i + 1) * 10, now, now))
    link(con)


def link(con) -> int:
    """Attach category_id to technologies that have none (new seed rows, legacy rows). Names without a category get one so no link is ever dropped."""
    if not con.execute("SELECT 1 FROM technology WHERE category_id IS NULL LIMIT 1").fetchone():
        return 0                            # nothing to link: do not even start a write transaction
    for (name,) in con.execute("SELECT DISTINCT category FROM technology WHERE category_id IS NULL AND category IS NOT NULL").fetchall():
        if not con.execute("SELECT 1 FROM technology_category WHERE name=? COLLATE NOCASE", (name,)).fetchone():
            _insert(con, name, "", None)
    return con.execute("UPDATE technology SET category_id=(SELECT c.id FROM technology_category c WHERE c.name=technology.category COLLATE NOCASE) WHERE category_id IS NULL").rowcount


def _insert(con, name: str, desc: str, order: int | None) -> str:
    base, cid, n = slug(name), slug(name), 2
    while con.execute("SELECT 1 FROM technology_category WHERE id=?", (cid,)).fetchone():
        cid, n = f"{base}-{n}", n + 1
    if order is None:
        order = (con.execute("SELECT COALESCE(MAX(sort_order),0) FROM technology_category").fetchone()[0] or 0) + 10
    now = _now()
    con.execute("INSERT INTO technology_category(id,name,description,sort_order,active,created_at,modified_at) VALUES(?,?,?,?,1,?,?)", (cid, name, desc, order, now, now))
    return cid


def _text(v, field: str, maxlen: int, required: bool = False) -> str:
    v = (v or "").strip() if isinstance(v, str) or v is None else str(v).strip()
    if CTRL.search(v):
        raise CategoryError(422, f"{field} contains control characters")
    if required and not v:
        raise CategoryError(422, f"{field} is required")
    if len(v) > maxlen:
        raise CategoryError(422, f"{field} must be at most {maxlen} characters")
    return v


def list_all(con, include_inactive: bool = True) -> list[dict]:
    counts = {r[0]: r[1] for r in con.execute("SELECT category_id,COUNT(*) FROM technology GROUP BY category_id")}
    enabled = {r[0]: r[1] for r in con.execute("SELECT category_id,COUNT(*) FROM technology WHERE enabled=1 GROUP BY category_id")}
    q = "SELECT * FROM technology_category" + ("" if include_inactive else " WHERE active=1") + " ORDER BY sort_order, name COLLATE NOCASE"
    return [{"id": r["id"], "name": r["name"], "description": r["description"], "sort_order": r["sort_order"], "active": bool(r["active"]), "created_at": r["created_at"],
             "modified_at": r["modified_at"], "technologies": counts.get(r["id"], 0), "enabled_technologies": enabled.get(r["id"], 0)} for r in con.execute(q)]


def get(con, cid: str):
    r = con.execute("SELECT * FROM technology_category WHERE id=?", (cid,)).fetchone()
    if not r:
        raise CategoryError(404, "Category not found")
    return r


def resolve_active(con, ref: str):
    """A category usable for NEW assignments: by id or exact name, and active."""
    r = con.execute("SELECT * FROM technology_category WHERE id=? OR name=? COLLATE NOCASE", (ref, ref)).fetchone()
    if not r:
        raise CategoryError(422, "Unknown category")
    if not r["active"]:
        raise CategoryError(422, f"Category '{r['name']}' is inactive: activate it or choose another one")
    return r


def create(con, d: dict) -> dict:
    name = _text(d.get("name"), "Name", 60, True)
    if con.execute("SELECT 1 FROM technology_category WHERE name=? COLLATE NOCASE", (name,)).fetchone():
        raise CategoryError(409, "A category with this name already exists")
    cid = _insert(con, name, _text(d.get("description"), "Description", 300), d.get("sort_order") if isinstance(d.get("sort_order"), int) else None)
    return next(c for c in list_all(con) if c["id"] == cid)


def update(con, cid: str, d: dict) -> dict:
    cur = get(con, cid)
    name = _text(d["name"], "Name", 60, True) if "name" in d else cur["name"]
    if name.lower() != cur["name"].lower() and con.execute("SELECT 1 FROM technology_category WHERE name=? COLLATE NOCASE", (name,)).fetchone():
        raise CategoryError(409, "A category with this name already exists")
    desc = _text(d["description"], "Description", 300) if "description" in d else cur["description"]
    order = d["sort_order"] if isinstance(d.get("sort_order"), int) and not isinstance(d.get("sort_order"), bool) else cur["sort_order"]
    active = cur["active"] if d.get("active") is None else int(bool(d["active"]))
    con.execute("UPDATE technology_category SET name=?,description=?,sort_order=?,active=?,modified_at=? WHERE id=?", (name, desc, order, active, _now(), cid))
    if name != cur["name"]:
        con.execute("UPDATE technology SET category=? WHERE category_id=?", (name, cid))
    return next(c for c in list_all(con) if c["id"] == cid)


def reorder(con, ids: list[str]) -> list[dict]:
    known = {r[0] for r in con.execute("SELECT id FROM technology_category")}
    if len(set(ids)) != len(ids) or any(i not in known for i in ids):
        raise CategoryError(422, "Invalid category list")
    rest = [r[0] for r in con.execute("SELECT id FROM technology_category WHERE id NOT IN (%s) ORDER BY sort_order" % ",".join("?" * len(ids)), ids)] if ids else []
    now = _now()
    for i, cid in enumerate([*ids, *rest]):
        con.execute("UPDATE technology_category SET sort_order=?,modified_at=? WHERE id=?", ((i + 1) * 10, now, cid))
    return list_all(con)


def delete(con, cid: str) -> None:
    get(con, cid)
    n = con.execute("SELECT COUNT(*) FROM technology WHERE category_id=?", (cid,)).fetchone()[0]
    if n:
        raise CategoryError(409, f"{n} technologies still use this category: reassign them first (or deactivate the category)")
    con.execute("DELETE FROM technology_category WHERE id=?", (cid,))


def technologies(con, cid: str) -> list[dict]:
    get(con, cid)
    return [dict(r) for r in con.execute("SELECT id,name,vendor,product,enabled,custom,dashboard FROM technology WHERE category_id=? ORDER BY name COLLATE NOCASE", (cid,))]


def assign(con, tech_ids: list[str], category_ref: str) -> int:
    """Move technologies (built-in or custom) to another ACTIVE category. Category is a user decision, so seed syncs never undo it."""
    cat = resolve_active(con, category_ref)
    n = 0
    for tid in dict.fromkeys(tech_ids):
        n += con.execute("UPDATE technology SET category=?,category_id=?,updated_at=? WHERE id=?", (cat["name"], cat["id"], _now(), tid)).rowcount
    return n
