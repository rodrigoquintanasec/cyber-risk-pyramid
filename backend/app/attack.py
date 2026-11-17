"""MITRE ATT&CK (STIX 2.1) import and queries: intrusion sets (actors), campaigns, techniques, malware, tools, relationships.

Source: https://github.com/mitre-attack/attack-stix-data (Enterprise ATT&CK). Objects are stored once under their STIX id
(stable key -> idempotent updates, no duplicates). Revoked/deprecated objects are kept (flagged) so references stay
resolvable, but are excluded from active views. Every relationship keeps source, target, type, source dataset,
evidence id (the STIX relationship id), evidence references and modification date, so a graph can reuse it later.
Nothing is inferred: an association exists only if MITRE publishes the STIX relationship.
"""
from __future__ import annotations

import json
import logging
import re
import threading
from datetime import datetime, timezone
from urllib.parse import urlparse

import httpx

from . import db
from .config import settings

log = logging.getLogger("attack")
KEY = "enterprise-attack"
SOURCE_LABEL = "MITRE ATT&CK STIX 2.1 (enterprise-attack)"
ALLOWED_HOSTS = {"raw.githubusercontent.com"}
MAX_BYTES = 200 * 1024 * 1024
UA = "cyber-risk-pyramid/0.4 (ATT&CK STIX importer)"
STIX_ID_RE = re.compile(r"^[a-z][a-z0-9\-]+--[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
ID_RES = {"intrusion-set": re.compile(r"^G\d{4}$"), "campaign": re.compile(r"^C\d{4}$"), "attack-pattern": re.compile(r"^T\d{4}(\.\d{3})?$"),
          "malware": re.compile(r"^S\d{4}$"), "tool": re.compile(r"^S\d{4}$")}
ATTACK_SOURCES = {"mitre-attack", "mitre-mobile-attack", "mitre-ics-attack"}
REL_TYPES = {"uses", "attributed-to", "subtechnique-of", "revoked-by"}
URL_PATH = {"intrusion-set": "groups", "campaign": "campaigns", "attack-pattern": "techniques", "malware": "software", "tool": "software"}
KIND = {"intrusion-set": "actor", "campaign": "campaign", "attack-pattern": "technique", "malware": "malware", "tool": "tool"}
CITATION_RE = re.compile(r"\s*\(Citation: [^)]*\)")
MDLINK_RE = re.compile(r"\[([^\]]+)\]\((?:[^)]*)\)")
_lock = threading.Lock()
state = {"running": False}


def clean_desc(text: str | None, limit: int = 6000) -> str:
    """Plain text: drop STIX citation markers and markdown link targets (keeps the visible text)."""
    t = MDLINK_RE.sub(r"\1", CITATION_RE.sub("", text or ""))
    t = re.sub(r"</?code>", "", t)
    return t.strip()[:limit]


def attack_url(type_: str, attack_id: str) -> str:
    return f"https://attack.mitre.org/{URL_PATH[type_]}/" + attack_id.replace(".", "/") + "/"


def _iso(v) -> str | None:
    if not isinstance(v, str):
        return None
    try:
        datetime.fromisoformat(v.replace("Z", "+00:00"))
        return v
    except ValueError:
        return None


def _refs(o: dict) -> list[dict]:
    out = []
    for r in (o.get("external_references") or [])[:60]:
        if not isinstance(r, dict) or not isinstance(r.get("source_name"), str):
            continue
        url = r.get("url")
        out.append({"source_name": r["source_name"][:120], "external_id": str(r.get("external_id", ""))[:40] or None,
                    "url": url[:500] if isinstance(url, str) and re.match(r"^https?://", url) else None,
                    "description": clean_desc(r.get("description"), 400) or None})
    return out


def _strs(v, n=40) -> list[str]:
    return [x.strip()[:120] for x in v if isinstance(x, str) and x.strip()][:n] if isinstance(v, list) else []


def parse_object(o: dict) -> dict | None:
    """Validate one STIX object; None if it is not an importable, well-formed object."""
    t = o.get("type")
    if t not in ID_RES or not isinstance(o.get("id"), str) or not STIX_ID_RE.match(o["id"]) or not o["id"].startswith(t + "--"):
        return None
    name = o.get("name")
    if not isinstance(name, str) or not name.strip():
        return None
    refs = _refs(o)
    aid = next((r["external_id"] for r in refs if r["source_name"] in ATTACK_SOURCES and r["external_id"]), None)
    if not aid or not ID_RES[t].match(aid):
        return None
    extra: dict = {"version": o.get("x_mitre_version") if isinstance(o.get("x_mitre_version"), str) else None,
                   "domains": _strs(o.get("x_mitre_domains"), 6), "platforms": _strs(o.get("x_mitre_platforms"), 12)}
    if t == "attack-pattern":
        extra["tactics"] = [p["phase_name"] for p in (o.get("kill_chain_phases") or []) if isinstance(p, dict) and p.get("kill_chain_name") == "mitre-attack" and isinstance(p.get("phase_name"), str)]
        extra["is_subtechnique"] = bool(o.get("x_mitre_is_subtechnique"))
    if t == "campaign":
        extra["first_seen"], extra["last_seen"] = _iso(o.get("first_seen")), _iso(o.get("last_seen"))
    aliases = _strs(o.get("aliases")) if t in ("intrusion-set", "campaign") else _strs(o.get("x_mitre_aliases"))
    return {"stix_id": o["id"], "type": t, "attack_id": aid, "name": name.strip()[:300], "description": (o.get("description") or "")[:20000] if isinstance(o.get("description"), str) else "",
            "aliases": aliases, "created": _iso(o.get("created")), "modified": _iso(o.get("modified")), "revoked": bool(o.get("revoked")),
            "deprecated": bool(o.get("x_mitre_deprecated")), "refs": refs, "extra": extra}


def parse_relationship(o: dict, known: set[str]) -> dict | None:
    if o.get("type") != "relationship" or not isinstance(o.get("id"), str) or not STIX_ID_RE.match(o["id"]):
        return None
    s, d, rt = o.get("source_ref"), o.get("target_ref"), o.get("relationship_type")
    if rt not in REL_TYPES or s not in known or d not in known:
        return None
    return {"stix_id": o["id"], "source_ref": s, "target_ref": d, "rel_type": rt, "description": clean_desc(o.get("description"), 2000),
            "modified": _iso(o.get("modified")), "revoked": bool(o.get("revoked")), "deprecated": bool(o.get("x_mitre_deprecated")), "refs": _refs(o)}


def import_bundle(con, bundle: dict) -> dict:
    """Upsert a STIX bundle (idempotent). Returns import counters."""
    if not isinstance(bundle, dict) or bundle.get("type") != "bundle" or not isinstance(bundle.get("objects"), list):
        raise ValueError("Not a STIX 2.1 bundle")
    objs = [parse_object(o) for o in bundle["objects"] if isinstance(o, dict) and o.get("type") in ID_RES]
    good = [o for o in objs if o]
    known = {o["stix_id"] for o in good}
    rels = [parse_relationship(o, known) for o in bundle["objects"] if isinstance(o, dict) and o.get("type") == "relationship"]
    rels_ok = [r for r in rels if r]
    ts = db.now_iso()
    con.executemany(
        "INSERT INTO stix_object(stix_id,type,attack_id,name,description,aliases,created,modified,revoked,deprecated,external_refs,extra,domain,imported_at) "
        "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(stix_id) DO UPDATE SET type=excluded.type,attack_id=excluded.attack_id,name=excluded.name,"
        "description=excluded.description,aliases=excluded.aliases,created=excluded.created,modified=excluded.modified,revoked=excluded.revoked,"
        "deprecated=excluded.deprecated,external_refs=excluded.external_refs,extra=excluded.extra,domain=excluded.domain,imported_at=excluded.imported_at",
        [(o["stix_id"], o["type"], o["attack_id"], o["name"], o["description"], json.dumps(o["aliases"]), o["created"], o["modified"], int(o["revoked"]),
          int(o["deprecated"]), json.dumps(o["refs"]), json.dumps(o["extra"]), KEY, ts) for o in good])
    con.executemany(
        "INSERT INTO stix_rel(stix_id,source_ref,target_ref,rel_type,description,modified,revoked,deprecated,evidence_refs,source,status,imported_at) "
        "VALUES(?,?,?,?,?,?,?,?,?,?, 'confirmed', ?) ON CONFLICT(stix_id) DO UPDATE SET source_ref=excluded.source_ref,target_ref=excluded.target_ref,"
        "rel_type=excluded.rel_type,description=excluded.description,modified=excluded.modified,revoked=excluded.revoked,deprecated=excluded.deprecated,"
        "evidence_refs=excluded.evidence_refs,source=excluded.source,imported_at=excluded.imported_at",
        [(r["stix_id"], r["source_ref"], r["target_ref"], r["rel_type"], r["description"], r["modified"], int(r["revoked"]), int(r["deprecated"]),
          json.dumps(r["refs"]), SOURCE_LABEL, ts) for r in rels_ok])
    return {"objects_seen": len(objs), "objects_imported": len(good), "objects_skipped": len(objs) - len(good),
            "relationships_seen": len(rels), "relationships_imported": len(rels_ok), "relationships_skipped": len(rels) - len(rels_ok)}


# ---------------------------------------------------------------- download / sync
def fetch_bundle(url: str, etag: str | None, last_modified: str | None) -> tuple[int, dict | None, str | None, str | None]:
    p = urlparse(url)
    if p.scheme != "https" or p.hostname not in ALLOWED_HOSTS:
        raise ValueError("ATT&CK source URL must be https on raw.githubusercontent.com")
    h = {"User-Agent": UA, "Accept": "application/json"}
    if etag: h["If-None-Match"] = etag
    elif last_modified: h["If-Modified-Since"] = last_modified
    with httpx.Client(timeout=120, follow_redirects=False, headers=h) as c, c.stream("GET", url) as r:
        if r.status_code == 304:
            return 304, None, etag, last_modified
        if r.status_code != 200:
            raise ValueError(f"HTTP {r.status_code} from {p.hostname}")
        buf = bytearray()
        for chunk in r.iter_bytes(1 << 20):
            buf += chunk
            if len(buf) > MAX_BYTES:
                raise ValueError("ATT&CK bundle exceeds the size limit")
        return 200, json.loads(bytes(buf)), r.headers.get("etag"), r.headers.get("last-modified")


def sync(force: bool = False) -> dict | None:
    """Download (conditional GET) and import. Never raises; the outcome is stored in stix_sync."""
    if not _lock.acquire(blocking=False):
        return None
    try:
        state["running"] = True
        url = settings.attack_url
        with db.connect() as con:
            row = con.execute("SELECT * FROM stix_sync WHERE key=?", (KEY,)).fetchone()
        ts = db.now_iso()
        try:
            status, bundle, etag, lm = fetch_bundle(url, None if force or not row else row["etag"], None if force or not row else row["last_modified"])
            with db.connect() as con:
                if status == 304:
                    con.execute("UPDATE stix_sync SET last_attempt=?,last_success=?,status='ok',error=NULL WHERE key=?", (ts, ts, KEY))
                    return {"unchanged": True}
                counts = import_bundle(con, bundle)
                coll = next((o for o in bundle["objects"] if isinstance(o, dict) and o.get("type") == "x-mitre-collection"), {})
                con.execute(
                    "INSERT INTO stix_sync(key,url,etag,last_modified,last_attempt,last_success,status,error,counts,collection_version,spec_version) VALUES(?,?,?,?,?,?, 'ok', NULL, ?,?,?) "
                    "ON CONFLICT(key) DO UPDATE SET url=excluded.url,etag=excluded.etag,last_modified=excluded.last_modified,last_attempt=excluded.last_attempt,"
                    "last_success=excluded.last_success,status='ok',error=NULL,counts=excluded.counts,collection_version=excluded.collection_version,spec_version=excluded.spec_version",
                    (KEY, url, etag, lm, ts, ts, json.dumps(counts), coll.get("x_mitre_version"), bundle.get("spec_version") or "2.1"))
            reset_catalog_cache()
            return counts
        except Exception as e:  # keep serving previously imported data
            log.warning("ATT&CK sync failed: %s", e)
            with db.connect() as con:
                con.execute("INSERT INTO stix_sync(key,url,last_attempt,status,error) VALUES(?,?,?, 'error', ?) ON CONFLICT(key) DO UPDATE SET last_attempt=excluded.last_attempt,status='error',error=excluded.error",
                            (KEY, url, ts, str(e)[:300]))
            return {"error": str(e)[:200]}
    finally:
        state["running"] = False
        _lock.release()


def needs_sync(con) -> bool:
    """Startup rule: import only if never imported or older than the configured interval (0 = never automatically after the first import)."""
    row = con.execute("SELECT last_success FROM stix_sync WHERE key=?", (KEY,)).fetchone()
    if not row or not row["last_success"]:
        return True
    if settings.attack_interval_hours <= 0:
        return False
    return (datetime.now(timezone.utc) - datetime.fromisoformat(row["last_success"])).total_seconds() > settings.attack_interval_hours * 3600


def status(con) -> dict:
    row = con.execute("SELECT * FROM stix_sync WHERE key=?", (KEY,)).fetchone()
    act = "revoked=0 AND deprecated=0"
    n = lambda q, *a: con.execute(q, a).fetchone()[0]  # noqa: E731
    return {
        "source": "https://github.com/mitre-attack/attack-stix-data", "dataset": KEY, "syncing": state["running"],
        "imported": bool(row and row["last_success"]), "last_attempt": row["last_attempt"] if row else None, "last_success": row["last_success"] if row else None,
        "status": row["status"] if row else "never", "error": row["error"] if row else None, "collection_version": row["collection_version"] if row else None,
        "spec_version": row["spec_version"] if row else None, "last_import": json.loads(row["counts"]) if row and row["counts"] else None,
        "interval_hours": settings.attack_interval_hours,
        "counts": {"actors": n(f"SELECT COUNT(*) FROM stix_object WHERE type='intrusion-set' AND {act}"), "campaigns": n(f"SELECT COUNT(*) FROM stix_object WHERE type='campaign' AND {act}"),
                   "techniques": n(f"SELECT COUNT(*) FROM stix_object WHERE type='attack-pattern' AND {act}"), "malware": n(f"SELECT COUNT(*) FROM stix_object WHERE type='malware' AND {act}"),
                   "tools": n(f"SELECT COUNT(*) FROM stix_object WHERE type='tool' AND {act}"), "relationships": n(f"SELECT COUNT(*) FROM stix_rel WHERE {act}"),
                   "revoked_or_deprecated_objects": n("SELECT COUNT(*) FROM stix_object WHERE revoked=1 OR deprecated=1")},
    }


# ---------------------------------------------------------------- shared technique catalogue (reused by news MITRE mapping)
_cat: dict = {"v": None}


def reset_catalog_cache() -> None:
    _cat["v"] = None


def catalog_from_db() -> dict | None:
    if _cat["v"] is not None:
        return _cat["v"] or None
    try:
        with db.connect() as con:
            rows = con.execute("SELECT attack_id,name,extra FROM stix_object WHERE type='attack-pattern' AND revoked=0 AND deprecated=0").fetchall()
            ver = con.execute("SELECT collection_version FROM stix_sync WHERE key=?", (KEY,)).fetchone()
    except Exception:
        return None
    if not rows:
        _cat["v"] = {}
        return None
    cat = {"source": "https://github.com/mitre-attack/attack-stix-data (imported)", "version": ver[0] if ver else None,
           "techniques": {r["attack_id"]: {"n": r["name"], "t": json.loads(r["extra"] or "{}").get("tactics", [])} for r in rows}}
    _cat["v"] = cat
    return cat


# ---------------------------------------------------------------- queries
def _like(s: str) -> str:
    return "%" + s.replace("!", "!!").replace("%", "!%").replace("_", "!_") + "%"


def _esc_prefix(s: str) -> str:
    return s.replace('!', '!!').replace('%', '!%').replace('_', '!_') + '%'


def _j(s, default):
    try:
        return json.loads(s) if s else default
    except ValueError:
        return default


def _obj(r) -> dict:
    extra = _j(r["extra"], {})
    base = {"id": r["attack_id"], "stix_id": r["stix_id"], "type": KIND[r["type"]], "name": r["name"],
            "aliases": [a for a in _j(r["aliases"], []) if a != r["name"]], "description": clean_desc(r["description"]),
            "created": r["created"], "modified": r["modified"], "url": attack_url(r["type"], r["attack_id"])}
    if r["type"] == "attack-pattern":
        base.update(tactics=extra.get("tactics", []), is_subtechnique=extra.get("is_subtechnique", False), platforms=extra.get("platforms", []))
    elif r["type"] == "campaign":
        base.update(first_seen=extra.get("first_seen"), last_seen=extra.get("last_seen"))
    elif r["type"] in ("malware", "tool"):
        base.update(platforms=extra.get("platforms", []))
    return base


def _brief(o: dict) -> dict:
    return {k: o[k] for k in ("id", "stix_id", "type", "name", "aliases", "url", "modified", "tactics", "is_subtechnique", "first_seen", "last_seen") if k in o}


def resolve(con, ident: str, types: tuple[str, ...] | None = None):
    """Find an active-or-historic object by ATT&CK id (G0016) or STIX id."""
    ident = (ident or "").strip()[:80]
    if STIX_ID_RE.match(ident):
        r = con.execute("SELECT * FROM stix_object WHERE stix_id=?", (ident,)).fetchone()
    else:
        r = con.execute("SELECT * FROM stix_object WHERE attack_id=? ORDER BY revoked, deprecated LIMIT 1", (ident.upper(),)).fetchone()
    if r and types and r["type"] not in types:
        return None
    return r


def related(con, stix_id: str, *, outgoing: bool, rel_type: str, types: tuple[str, ...], limit: int = 500) -> list[dict]:
    a, b = ("source_ref", "target_ref") if outgoing else ("target_ref", "source_ref")
    ph = ",".join("?" * len(types))
    rows = con.execute(
        f"SELECT o.*, r.stix_id AS rel_id, r.description AS rel_desc, r.modified AS rel_modified, r.evidence_refs AS rel_refs, r.source AS rel_source, r.status AS rel_status "
        f"FROM stix_rel r JOIN stix_object o ON o.stix_id=r.{b} WHERE r.{a}=? AND r.rel_type=? AND r.revoked=0 AND r.deprecated=0 "
        f"AND o.revoked=0 AND o.deprecated=0 AND o.type IN ({ph}) ORDER BY o.name COLLATE NOCASE LIMIT ?", (stix_id, rel_type, *types, limit)).fetchall()
    out = []
    for r in rows:
        o = _brief(_obj(r))
        o["relationship"] = {"id": r["rel_id"], "type": rel_type, "status": r["rel_status"], "source": r["rel_source"], "evidence_id": r["rel_id"],
                             "modified": r["rel_modified"], "description": r["rel_desc"] or None, "evidence": [x for x in _j(r["rel_refs"], []) if x.get("url") or x.get("description")][:5]}
        out.append(o)
    return out


def _page(items, total, page, page_size):
    return {"items": items, "total": total, "page": page, "page_size": page_size, "pages": max(1, -(-total // page_size))}


USES = "SELECT r.source_ref FROM stix_rel r JOIN stix_object t ON t.stix_id=r.target_ref WHERE r.rel_type='uses' AND r.revoked=0 AND r.deprecated=0 AND ({cond})"


def _filters(q, technique, software, where, args):
    if q:
        where.append("(LOWER(o.name) LIKE ? ESCAPE '!' OR LOWER(o.aliases) LIKE ? ESCAPE '!' OR UPPER(o.attack_id)=?)")
        args += [_like(q.strip().lower()[:80]), _like(q.strip().lower()[:80]), q.strip().upper()[:12]]
    if technique:
        where.append("o.stix_id IN (" + USES.format(cond="t.attack_id=? OR t.attack_id LIKE ?") + ")")
        args += [technique.upper(), technique.upper() + ".%"]
    if software:
        where.append("o.stix_id IN (" + USES.format(cond="t.attack_id=? AND t.type IN ('malware','tool')") + ")")
        args += [software.upper()]


def list_actors(con, *, q=None, technique=None, software=None, campaign=None, sort="name", page=1, page_size=25) -> dict:
    where, args = ["o.type='intrusion-set'", "o.revoked=0", "o.deprecated=0"], []
    _filters(q, technique, software, where, args)
    if campaign:
        where.append("o.stix_id IN (SELECT r.target_ref FROM stix_rel r JOIN stix_object c ON c.stix_id=r.source_ref WHERE r.rel_type='attributed-to' AND r.revoked=0 AND c.attack_id=?)")
        args.append(campaign.upper())
    w = " WHERE " + " AND ".join(where)
    total = con.execute(f"SELECT COUNT(*) FROM stix_object o{w}", args).fetchone()[0]
    order = {"name": "o.name COLLATE NOCASE", "techniques": "tech DESC, o.name COLLATE NOCASE", "modified": "o.modified DESC"}[sort]
    rows = con.execute(
        "SELECT o.*, (SELECT COUNT(*) FROM stix_rel r JOIN stix_object t ON t.stix_id=r.target_ref WHERE r.source_ref=o.stix_id AND r.rel_type='uses' AND r.revoked=0 AND t.type='attack-pattern' AND t.revoked=0 AND t.deprecated=0) AS tech,"
        " (SELECT COUNT(*) FROM stix_rel r JOIN stix_object t ON t.stix_id=r.target_ref WHERE r.source_ref=o.stix_id AND r.rel_type='uses' AND r.revoked=0 AND t.type IN ('malware','tool') AND t.revoked=0 AND t.deprecated=0) AS soft,"
        " (SELECT COUNT(*) FROM stix_rel r JOIN stix_object c ON c.stix_id=r.source_ref WHERE r.target_ref=o.stix_id AND r.rel_type='attributed-to' AND r.revoked=0 AND c.revoked=0 AND c.deprecated=0) AS camp"
        f" FROM stix_object o{w} ORDER BY {order} LIMIT ? OFFSET ?", [*args, page_size, (page - 1) * page_size]).fetchall()
    items = []
    for r in rows:
        o = _obj(r)
        o["description"] = o["description"][:260]
        o["counts"] = {"techniques": r["tech"], "software": r["soft"], "campaigns": r["camp"]}
        items.append(o)
    return _page(items, total, page, page_size)


def list_campaigns(con, *, q=None, group=None, technique=None, software=None, sort="name", page=1, page_size=25) -> dict:
    where, args = ["o.type='campaign'", "o.revoked=0", "o.deprecated=0"], []
    _filters(q, technique, software, where, args)
    if group:
        where.append("o.stix_id IN (SELECT r.source_ref FROM stix_rel r JOIN stix_object g ON g.stix_id=r.target_ref WHERE r.rel_type='attributed-to' AND r.revoked=0 AND g.attack_id=?)")
        args.append(group.upper())
    w = " WHERE " + " AND ".join(where)
    total = con.execute(f"SELECT COUNT(*) FROM stix_object o{w}", args).fetchone()[0]
    seen = "json_extract(o.extra,'$.first_seen')"
    order = {"name": "o.name COLLATE NOCASE", "first_seen": f"{seen} IS NULL, {seen} DESC", "modified": "o.modified DESC"}[sort]
    rows = con.execute(
        "SELECT o.*, (SELECT COUNT(*) FROM stix_rel r JOIN stix_object t ON t.stix_id=r.target_ref WHERE r.source_ref=o.stix_id AND r.rel_type='uses' AND r.revoked=0 AND t.type='attack-pattern' AND t.revoked=0 AND t.deprecated=0) AS tech"
        f" FROM stix_object o{w} ORDER BY {order} LIMIT ? OFFSET ?", [*args, page_size, (page - 1) * page_size]).fetchall()
    items = []
    for r in rows:
        o = _obj(r)
        o["description"] = o["description"][:260]
        o["actors"] = [{"id": a["id"], "name": a["name"]} for a in related(con, r["stix_id"], outgoing=True, rel_type="attributed-to", types=("intrusion-set",))]
        o["counts"] = {"techniques": r["tech"]}
        items.append(o)
    return _page(items, total, page, page_size)


def _detail_common(con, r) -> dict:
    o = _obj(r)
    o["references"] = [x for x in _j(r["external_refs"], []) if x["source_name"] not in ATTACK_SOURCES][:40]
    o["revoked"], o["deprecated"] = bool(r["revoked"]), bool(r["deprecated"])
    o["source"] = {"dataset": SOURCE_LABEL, "stix_id": r["stix_id"], "imported_at": r["imported_at"]}
    return o


def actor_detail(con, ident: str) -> dict | None:
    r = resolve(con, ident, ("intrusion-set",))
    if not r:
        return None
    o = _detail_common(con, r)
    o["techniques"] = related(con, r["stix_id"], outgoing=True, rel_type="uses", types=("attack-pattern",))
    o["software"] = related(con, r["stix_id"], outgoing=True, rel_type="uses", types=("malware", "tool"))
    o["campaigns"] = related(con, r["stix_id"], outgoing=False, rel_type="attributed-to", types=("campaign",))
    return o


def campaign_detail(con, ident: str) -> dict | None:
    r = resolve(con, ident, ("campaign",))
    if not r:
        return None
    o = _detail_common(con, r)
    o["actors"] = related(con, r["stix_id"], outgoing=True, rel_type="attributed-to", types=("intrusion-set",))
    o["techniques"] = related(con, r["stix_id"], outgoing=True, rel_type="uses", types=("attack-pattern",))
    o["software"] = related(con, r["stix_id"], outgoing=True, rel_type="uses", types=("malware", "tool"))
    return o


def technique_detail(con, ident: str) -> dict | None:
    r = resolve(con, ident, ("attack-pattern",))
    if not r:
        return None
    o = _detail_common(con, r)
    o["parent"] = (related(con, r["stix_id"], outgoing=True, rel_type="subtechnique-of", types=("attack-pattern",)) or [None])[0]
    o["subtechniques"] = related(con, r["stix_id"], outgoing=False, rel_type="subtechnique-of", types=("attack-pattern",))
    o["actors"] = related(con, r["stix_id"], outgoing=False, rel_type="uses", types=("intrusion-set",))
    o["campaigns"] = related(con, r["stix_id"], outgoing=False, rel_type="uses", types=("campaign",))
    o["software"] = related(con, r["stix_id"], outgoing=False, rel_type="uses", types=("malware", "tool"))
    return o


def software_detail(con, ident: str) -> dict | None:
    r = resolve(con, ident, ("malware", "tool"))
    if not r:
        return None
    o = _detail_common(con, r)
    o["techniques"] = related(con, r["stix_id"], outgoing=True, rel_type="uses", types=("attack-pattern",))
    o["actors"] = related(con, r["stix_id"], outgoing=False, rel_type="uses", types=("intrusion-set",))
    o["campaigns"] = related(con, r["stix_id"], outgoing=False, rel_type="uses", types=("campaign",))
    return o


def lookup(con, q: str, kind: str, limit: int = 15) -> list[dict]:
    types = {"technique": ("attack-pattern",), "software": ("malware", "tool"), "actor": ("intrusion-set",), "campaign": ("campaign",)}[kind]
    ph = ",".join("?" * len(types))
    rows = con.execute(f"SELECT * FROM stix_object WHERE type IN ({ph}) AND revoked=0 AND deprecated=0 AND (LOWER(name) LIKE ? ESCAPE '!' OR UPPER(attack_id)=? OR LOWER(aliases) LIKE ? ESCAPE '!') "
                       "ORDER BY name COLLATE NOCASE LIMIT ?", (*types, _like(q.strip().lower()[:60]), q.strip().upper()[:12], _like(q.strip().lower()[:60]), limit)).fetchall()
    return [_brief(_obj(r)) for r in rows]


def relationships(con, *, source=None, target=None, rel_type=None, page=1, page_size=50) -> dict:
    where, args = ["r.revoked=0", "r.deprecated=0"], []
    for col, ident in (("source_ref", source), ("target_ref", target)):
        if ident:
            o = resolve(con, ident)
            where.append(f"r.{col}=?"); args.append(o["stix_id"] if o else "-")
    if rel_type:
        where.append("r.rel_type=?"); args.append(rel_type)
    where += ["s.revoked=0", "s.deprecated=0", "t.revoked=0", "t.deprecated=0"]
    w = " WHERE " + " AND ".join(where)
    join = "FROM stix_rel r JOIN stix_object s ON s.stix_id=r.source_ref JOIN stix_object t ON t.stix_id=r.target_ref"
    total = con.execute(f"SELECT COUNT(*) {join}{w}", args).fetchone()[0]
    rows = con.execute(f"SELECT r.*, s.attack_id AS sid, s.name AS sname, s.type AS stype, t.attack_id AS tid, t.name AS tname, t.type AS ttype {join}{w} ORDER BY r.stix_id LIMIT ? OFFSET ?",
                       [*args, page_size, (page - 1) * page_size]).fetchall()
    items = [{"id": r["stix_id"], "type": r["rel_type"], "source": {"id": r["sid"], "name": r["sname"], "type": KIND[r["stype"]], "stix_id": r["source_ref"]},
              "target": {"id": r["tid"], "name": r["tname"], "type": KIND[r["ttype"]], "stix_id": r["target_ref"]}, "dataset": r["source"], "evidence_id": r["stix_id"],
              "status": r["status"], "modified": r["modified"], "description": r["description"] or None, "evidence": [x for x in _j(r["evidence_refs"], []) if x.get("url") or x.get("description")][:5]}
             for r in rows]
    return _page(items, total, page, page_size)
