"""NVD product catalogue built from the LOCAL CPE dictionary (never from the network).

Product identity = (cpe part, vendor, product). Every CPE record (versions, editions, variants, deprecated ones) stays in `cpe_dictionary` untouched;
`nvd_product` / `nvd_vendor` are derived indexes for fast search. A product here is only a discovery candidate: it becomes a monitored technology
solely when the user adds it (technology_product links the two)."""
from __future__ import annotations

import re
from datetime import datetime, timezone

SCHEMA = """
CREATE TABLE IF NOT EXISTS nvd_product(
  part TEXT NOT NULL, vendor TEXT NOT NULL, product TEXT NOT NULL, display_name TEXT, search_text TEXT NOT NULL, cpe_count INTEGER NOT NULL, active_count INTEGER NOT NULL,
  version_count INTEGER NOT NULL, last_modified TEXT, PRIMARY KEY(part, vendor, product)) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS ix_nvdp_vendor ON nvd_product(vendor, product);
CREATE INDEX IF NOT EXISTS ix_nvdp_product ON nvd_product(product);
CREATE TABLE IF NOT EXISTS nvd_vendor(vendor TEXT PRIMARY KEY, products INTEGER NOT NULL, active_products INTEGER NOT NULL, cpe_count INTEGER NOT NULL) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS technology_product(
  tech_id TEXT NOT NULL REFERENCES technology(id), part TEXT NOT NULL, vendor TEXT NOT NULL, product TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'primary', added_at TEXT NOT NULL,
  PRIMARY KEY(tech_id, part, vendor, product)) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS ix_techprod_ident ON technology_product(part, vendor, product);
"""
PARTS = {"a": "application", "o": "operating system", "h": "hardware"}
_COMP = re.compile(r"(?<!\\):")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def migrate(con) -> None:
    con.executescript(SCHEMA)
    link_existing(con)


def link_existing(con) -> int:
    """Relate the built-in/custom technologies to NVD product identities through their declared CPE matchers (exact vendor + product alternatives, nothing guessed)."""
    import json
    n = 0
    have = {tuple(r) for r in con.execute("SELECT tech_id,part,vendor,product FROM technology_product")}
    for r in con.execute("SELECT id,nvd_queries FROM technology").fetchall():
        try:
            qs = json.loads(r["nvd_queries"] or "[]")
        except ValueError:
            continue
        for q in qs:
            p = _COMP.split(q)            # cpe:2.3:<part>:<vendor>:<product>:*...
            if len(p) < 5 or p[2] not in PARTS:
                continue
            if (r["id"], p[2], p[3], p[4]) in have:
                continue                    # already linked: no write
            n += con.execute("INSERT OR IGNORE INTO technology_product(tech_id,part,vendor,product,role,added_at) VALUES(?,?,?,?,'primary',?)", (r["id"], p[2], p[3], p[4], _now())).rowcount
    return n


def display_name(title: str | None, version: str | None, product: str) -> str:
    t = (title or "").strip()
    if version and t.lower().endswith(version.lower()):
        t = t[: -len(version)].strip(" -,")
    return t or product.replace("_", " ").title()


def refresh(con=None) -> dict:
    """Rebuild the derived product index from cpe_dictionary. The 1.9M-row GROUP BY runs as a plain read (WAL readers never block writers); only the final
    swap of the derived rows takes the write lock, in a few seconds. Original CPE records are never modified."""
    from . import db
    with db.maintenance:
        with db.connect() as rd:
            rd.row_factory = None
            rows = rd.execute(
                "SELECT part,vendor,product,COUNT(*),SUM(deprecated=0),COUNT(DISTINCT version),MAX(last_modified),title,version,MIN(length(title)) FROM cpe_dictionary "
                "WHERE part IN ('a','o','h') AND vendor!='' AND product!='' GROUP BY part,vendor,product").fetchall()
        out, vendors = [], {}
        for part, vendor, product, n, act, vers, lm, title, version, _ in rows:
            name = display_name(title, version, product)
            text = re.sub(r"[_\-]+", " ", f"{vendor} {product} {name}").lower()
            out.append((part, vendor, product, name, text, n, act or 0, vers, lm))
            v = vendors.setdefault(vendor, [0, 0, 0])
            v[0] += 1
            v[1] += 1 if (act or 0) > 0 else 0
            v[2] += n
        with db.connect(timeout=120) as wr:
            wr.execute("DELETE FROM nvd_product")
            wr.execute("DELETE FROM nvd_vendor")
            wr.executemany("INSERT INTO nvd_product(part,vendor,product,display_name,search_text,cpe_count,active_count,version_count,last_modified) VALUES(?,?,?,?,?,?,?,?,?)", out)
            wr.executemany("INSERT INTO nvd_vendor(vendor,products,active_products,cpe_count) VALUES(?,?,?,?)", [(k, *v) for k, v in vendors.items()])
        return {"products": len(out), "vendors": len(vendors)}
