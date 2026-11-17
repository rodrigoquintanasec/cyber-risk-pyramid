"""News persistence and queries (parameterised SQL only)."""
from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone

from .classify import CATEGORIES, canonical_url, classify, detect_technologies, extract_cves
from .sources import BY_ID, SOURCE_TYPES, SOURCES, FeedSource, is_verified_official

MAX_PAGE_SIZE = 50
PERIODS = {"24h": timedelta(hours=24), "7d": timedelta(days=7), "30d": timedelta(days=30)}


def _now() -> datetime:
    return datetime.now(timezone.utc)


STATIC_COLS = "name,type,url,note,publisher,site_url,category,country,origin,batch"


def load_manual_sources(con) -> None:
    """Sources added from the UI live only in the database: register them so every process sees the same registry."""
    import json
    from .sources import BY_ID as _by, from_row, register
    for r in con.execute("SELECT * FROM news_source WHERE origin='manual'").fetchall():
        if r["id"] not in _by:
            register(from_row({"id": r["id"], "name": r["name"], "type": r["type"], "url": r["url"], "note": r["note"], "publisher": r["publisher"], "site": r["site_url"],
                               "category": r["category"], "country": r["country"], "extra_hosts": json.loads(r["extra_hosts"] or "[]"),
                               "official_domains": json.loads(r["official_domains"] or "[]")}, "manual", bool(r["enabled"])))


def sync_source_rows(con) -> None:
    """Keep news_source in line with the configured sources. Called by many GET endpoints, so it only WRITES when a row is missing or its configured
    fields changed (a write transaction per page view would queue behind every long writer and fail with "database is locked")."""
    from .sources import CATALOG_VALIDATION, SOURCES as _live
    load_manual_sources(con)
    have = {r[0]: tuple(r[1:]) for r in con.execute(f"SELECT id,{STATIC_COLS} FROM news_source")}
    for s in list(_live):
        if s.origin == "manual":
            continue
        static = (s.name, s.type, s.url, s.note, s.publisher, s.site, s.category, s.country, s.origin, s.batch)
        if have.get(s.id) == static:
            continue
        v = CATALOG_VALIDATION.get(s.id) or {}
        # `enabled` and the validation columns are only set on first insert: later changes belong to the user / to the validator and survive restarts.
        con.execute(
            "INSERT INTO news_source(id,name,type,url,enabled,note,publisher,site_url,category,country,origin,batch,validation_status,validated_at,validation_note,extra_hosts,official_domains) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) "
            "ON CONFLICT(id) DO UPDATE SET name=excluded.name,type=excluded.type,url=excluded.url,note=excluded.note,publisher=excluded.publisher,site_url=excluded.site_url,"
            "category=excluded.category,country=excluded.country,origin=excluded.origin,batch=excluded.batch,extra_hosts=excluded.extra_hosts,official_domains=excluded.official_domains",
            (s.id, s.name, s.type, s.url, int(s.enabled), s.note, s.publisher, s.site, s.category, s.country, s.origin, s.batch, v.get("status"), v.get("validated_at"), v.get("note"),
             __import__("json").dumps(list(s.extra_hosts)), __import__("json").dumps(list(s.official_domains))))
    configured = {s.id for s in _live}
    if any(i not in configured for i in have):
        prune_orphan_sources(con)


def prune_orphan_sources(con) -> None:
    """Rows of sources no longer configured AND with no stored articles (nothing to preserve) are dropped."""
    ids = [s.id for s in SOURCES]
    con.execute(f"DELETE FROM news_source WHERE origin!='manual' AND id NOT IN ({','.join('?' * len(ids))}) AND id NOT IN (SELECT DISTINCT source_id FROM news_item)", ids)


def item_id(source_id: str, guid: str | None, canon: str) -> str:
    return hashlib.sha1(f"{source_id}|{guid or canon}".encode()).hexdigest()[:24]


def _write_children(con, nid: str, cats, techs: dict, cves) -> None:
    for t in ("news_cat", "news_tech", "news_cve"):
        con.execute(f"DELETE FROM {t} WHERE news_id=?", (nid,))
    con.executemany("INSERT OR IGNORE INTO news_cat VALUES(?,?)", [(nid, c) for c in cats])
    con.executemany("INSERT OR IGNORE INTO news_tech VALUES(?,?,?)", [(nid, t, b) for t, b in techs.items()])
    con.executemany("INSERT OR IGNORE INTO news_cve VALUES(?,?)", [(nid, c) for c in cves])


def upsert_item(con, src: FeedSource, it: dict, cve_techs: dict[str, set[str]], now: datetime | None = None) -> str:
    """Returns 'new' | 'updated' | 'duplicate'. Dedup by (source, guid), canonical URL and internal id."""
    now = now or _now()
    canon = canonical_url(it["url"])
    nid = item_id(src.id, it.get("guid"), canon)
    chash = hashlib.sha1(f"{it['title']}|{it['summary']}".encode()).hexdigest()
    row = con.execute(
        "SELECT id,content_hash FROM news_item WHERE id=? OR url_canon=? OR (source_id=? AND guid IS NOT NULL AND guid=?) LIMIT 1",
        (nid, canon, src.id, it.get("guid"))).fetchone()
    text = f"{it['title']} {it['summary']} {' '.join(it.get('tags', []))}"
    cves = extract_cves(it["title"] + " " + it["summary"])
    cats = classify(text)
    techs = detect_technologies(f"{it['title']} {it['summary']}", cve_techs, cves, title=it["title"])
    if row:
        if row["id"] != nid or row["content_hash"] == chash:
            return "duplicate"
        con.execute("UPDATE news_item SET title=?,summary=?,content_hash=?,updated_at=? WHERE id=?",
                    (it["title"], it["summary"], chash, now.isoformat(timespec="seconds"), nid))
        _write_children(con, nid, cats, techs, cves)
        return "updated"
    published = it.get("published")
    if published and datetime.fromisoformat(published) > now + timedelta(days=1):
        published = None  # implausible future date
    collected = now.isoformat(timespec="seconds")
    con.execute(
        "INSERT INTO news_item(id,source_id,guid,url,url_canon,title,summary,published,collected_at,updated_at,content_hash,sort_ts) "
        "VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
        (nid, src.id, it.get("guid"), it["url"], canon, it["title"], it["summary"], published, collected,
         it.get("feed_updated"), chash, published or collected))
    _write_children(con, nid, cats, techs, cves)
    return "new"


def recorrelate(con) -> None:
    """Additive: link news to technologies via CVEs correlated by structured NVD/KEV data."""
    con.execute("INSERT OR IGNORE INTO news_tech(news_id,tech_id,basis) "
                "SELECT nc.news_id, tc.tech_id, 'cve' FROM news_cve nc JOIN tech_cve tc ON tc.cve_id=nc.cve_id")


def load_cve_techs(con) -> dict[str, set[str]]:
    out: dict[str, set[str]] = {}
    for r in con.execute("SELECT cve_id,tech_id FROM tech_cve"):
        out.setdefault(r["cve_id"], set()).add(r["tech_id"])
    return out


def _like(s: str) -> str:
    return "%" + s.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"


def search_news(con, *, q=None, source=None, source_type=None, category=None, tech=None, techs=None, cve=None, period="all",
                date_from=None, date_to=None, page=1, page_size=20) -> dict:
    page = max(1, page)
    page_size = max(1, min(MAX_PAGE_SIZE, page_size))
    where, args = [], []
    if q:
        where.append("n.title LIKE ? ESCAPE '\\'"); args.append(_like(q.strip()[:100]))
    if source:
        where.append("n.source_id=?"); args.append(source)
    if source_type:
        where.append("n.source_id IN (SELECT id FROM news_source WHERE type=?)"); args.append(source_type)
    if category:
        where.append("n.id IN (SELECT news_id FROM news_cat WHERE category=?)"); args.append(category)
    if tech:
        where.append("n.id IN (SELECT news_id FROM news_tech WHERE tech_id=?)"); args.append(tech)
    if techs is not None:
        if not techs:
            where.append("0")
        else:
            where.append(f"n.id IN (SELECT news_id FROM news_tech WHERE tech_id IN ({','.join('?' * len(techs))}))"); args.extend(techs)
    if cve:
        where.append("n.id IN (SELECT news_id FROM news_cve WHERE cve_id=?)"); args.append(cve.upper())
    if period in PERIODS:
        where.append("n.sort_ts>=?"); args.append((_now() - PERIODS[period]).isoformat(timespec="seconds"))
    if date_from:
        where.append("n.sort_ts>=?"); args.append(date_from)
    if date_to:
        where.append("n.sort_ts<?"); args.append((datetime.fromisoformat(date_to) + timedelta(days=1)).date().isoformat())
    w = (" WHERE " + " AND ".join(where)) if where else ""
    total = con.execute(f"SELECT COUNT(*) FROM news_item n{w}", args).fetchone()[0]
    rows = con.execute(
        f"SELECT n.*, s.name AS source_name, s.type AS source_type FROM news_item n JOIN news_source s ON s.id=n.source_id{w} "
        "ORDER BY n.sort_ts DESC, n.id LIMIT ? OFFSET ?", [*args, page_size, (page - 1) * page_size]).fetchall()
    items = [_shape(r) for r in rows]
    _attach_children(con, items)
    return {"items": items, "total": total, "page": page, "page_size": page_size, "pages": max(1, -(-total // page_size))}


def _shape(r) -> dict:
    return {
        "id": r["id"], "title": r["title"], "summary": r["summary"], "url": r["url"], "guid": r["guid"],
        "source": {"id": r["source_id"], "name": r["source_name"], "type": r["source_type"],
                   "type_label": SOURCE_TYPES.get(r["source_type"], r["source_type"])},
        "published": r["published"], "collected_at": r["collected_at"], "updated_at": r["updated_at"],
        "categories": [], "technologies": [], "cves": [],
    }


def _attach_children(con, items: list[dict]) -> None:
    if not items:
        return
    ids = [i["id"] for i in items]
    ph = ",".join("?" * len(ids))
    by = {i["id"]: i for i in items}
    for r in con.execute(f"SELECT news_id,category FROM news_cat WHERE news_id IN ({ph}) ORDER BY category", ids):
        by[r["news_id"]]["categories"].append(r["category"])
    for r in con.execute(f"SELECT news_id,tech_id,basis FROM news_tech WHERE news_id IN ({ph}) ORDER BY tech_id", ids):
        by[r["news_id"]]["technologies"].append({"id": r["tech_id"], "basis": r["basis"]})
    for r in con.execute(f"SELECT news_id,cve_id FROM news_cve WHERE news_id IN ({ph}) ORDER BY cve_id", ids):
        by[r["news_id"]]["cves"].append(r["cve_id"])


def get_item(con, nid: str) -> dict | None:
    r = con.execute("SELECT n.*, s.name AS source_name, s.type AS source_type FROM news_item n JOIN news_source s ON s.id=n.source_id WHERE n.id=?", (nid,)).fetchone()
    if not r:
        return None
    it = _shape(r)
    _attach_children(con, [it])
    return it


def _health(r, items_24h: int) -> str:
    if not r["enabled"]:
        return "disabled"
    if r["status"] == "error":
        return "failed"
    if r["status"] == "pending":
        return "pending"
    return "quiet" if items_24h == 0 else "healthy"


def list_sources(con) -> list[dict]:
    day = (_now() - timedelta(hours=24)).isoformat(timespec="seconds")
    counts = {r[0]: r[1] for r in con.execute("SELECT source_id,COUNT(*) FROM news_item GROUP BY source_id")}
    recent = {r[0]: r[1] for r in con.execute("SELECT source_id,COUNT(*) FROM news_item WHERE sort_ts>=? GROUP BY source_id", (day,))}
    out = []
    for r in con.execute("SELECT * FROM news_source"):
        n24 = recent.get(r["id"], 0)
        src = BY_ID.get(r["id"])
        out.append({"id": r["id"], "name": r["name"], "type": r["type"], "type_label": SOURCE_TYPES.get(r["type"], r["type"]),
                    "url": r["url"], "enabled": bool(r["enabled"]), "status": r["status"], "health": _health(r, n24),
                    "operational": bool(r["enabled"]) and r["status"] == "ok" and r["validation_status"] in (None, "verified"), "last_attempt": r["last_attempt"],
                    "last_success": r["last_success"], "error": r["error"], "consecutive_failures": r["consecutive_failures"],
                    "items_stored": counts.get(r["id"], 0), "items_24h": n24, "note": r["note"], "language": r["language"],
                    "last_http": r["last_http"], "final_url": r["final_url"], "redirects": r["redirects"], "newest_item": r["newest_item"],
                    "undated": r["undated"], "backoff_until": r["backoff_until"],
                    "official_verified": bool(src and is_verified_official(src)), "publisher": r["publisher"], "site": r["site_url"], "category": r["category"] or (src.category if src else None),
                    "country": r["country"], "origin": r["origin"] or "builtin", "batch": r["batch"], "validation_status": r["validation_status"], "validation_note": r["validation_note"],
                    "validated_at": r["validated_at"], "last_items": r["last_items"]})
    order = {s.id: i for i, s in enumerate(SOURCES)}
    return sorted(out, key=lambda x: order.get(x["id"], 999))


def set_source_enabled(con, source_id: str, enabled: bool) -> bool:
    """User toggle. Re-enabling clears failure state so the next sync tries the source immediately."""
    cur = con.execute("UPDATE news_source SET enabled=?,enabled_at=CASE WHEN ?=1 AND enabled=0 THEN ? ELSE enabled_at END WHERE id=?", (int(enabled), int(enabled), _now().isoformat(timespec="seconds"), source_id))
    if cur.rowcount and enabled:
        con.execute("UPDATE news_source SET backoff_until=NULL, consecutive_failures=0, status='pending', error=NULL WHERE id=? AND status='error'", (source_id,))
    return bool(cur.rowcount)


def stats(con) -> dict:
    day = (_now() - timedelta(hours=24)).isoformat(timespec="seconds")
    src = list_sources(con)
    last = max((s["last_success"] for s in src if s["last_success"]), default=None)
    cats = {r[0]: r[1] for r in con.execute("SELECT category,COUNT(*) FROM news_cat GROUP BY category")}
    return {
        "total_news": con.execute("SELECT COUNT(*) FROM news_item").fetchone()[0],
        "last_24h": con.execute("SELECT COUNT(*) FROM news_item WHERE sort_ts>=?", (day,)).fetchone()[0],
        "cve_references": con.execute("SELECT COUNT(DISTINCT cve_id) FROM news_cve").fetchone()[0],
        "correlated_news": con.execute("SELECT COUNT(DISTINCT news_id) FROM news_tech").fetchone()[0],
        "sources_configured": len(src),
        "sources_enabled": sum(1 for s in src if s["enabled"]),
        "sources_disabled": sum(1 for s in src if not s["enabled"]),
        "sources_active": sum(1 for s in src if s["operational"]),          # enabled and fetched OK = healthy
        "sources_failed": sum(1 for s in src if s["health"] == "failed"),   # enabled and failing (disabled sources never count)
        "sources_quiet": sum(1 for s in src if s["health"] == "quiet"),     # healthy but no article in 24h: NOT a failure
        "sources_pending": sum(1 for s in src if s["health"] == "pending"),
        "categories": {c: cats.get(c, 0) for c in CATEGORIES},
        "last_success": last,
    }


def sources_enabled_since(con, since_iso: str) -> int:
    """Sources switched on after `since`: more sources means more articles, which is a coverage change, not a change in attacker activity."""
    return con.execute("SELECT COUNT(*) FROM news_source WHERE enabled=1 AND enabled_at>=?", (since_iso,)).fetchone()[0]
