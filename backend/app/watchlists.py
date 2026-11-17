"""Named technology watchlists (SQLite). `owner_id` is reserved for future multi-user support ("local" for now)."""
from __future__ import annotations

import re
import sqlite3

from . import db, service
from .catalog import BY_ID

OWNER = "local"
MAX_LISTS = 20
NAME_RE = re.compile(r"^\w[\w .,&()\-+/]{0,59}$", re.UNICODE)


class WatchlistError(Exception):
    def __init__(self, status: int, msg: str):
        super().__init__(msg)
        self.status, self.msg = status, msg


def _valid_name(name: str) -> str:
    name = (name or "").strip()
    if not NAME_RE.match(name):
        raise WatchlistError(422, "Name must be 1-60 characters (letters, numbers, spaces and . , & ( ) - + /)")
    return name


def _tech(tid: str) -> str:
    if tid not in BY_ID:
        raise WatchlistError(422, f"Unknown technology: {tid}")
    return tid


def _row(con, r) -> dict:
    items = [x[0] for x in con.execute("SELECT ref_id FROM watchlist_item WHERE watchlist_id=? AND kind='technology' ORDER BY added_at, rowid", (r["id"],))]
    return {"id": r["id"], "name": r["name"], "technologies": items, "created_at": r["created_at"], "updated_at": r["updated_at"]}


def list_all(con) -> list[dict]:
    return [_row(con, r) for r in con.execute("SELECT * FROM watchlist WHERE owner_id=? ORDER BY name COLLATE NOCASE", (OWNER,))]


def _get(con, wid: int):
    r = con.execute("SELECT * FROM watchlist WHERE id=? AND owner_id=?", (wid, OWNER)).fetchone()
    if not r:
        raise WatchlistError(404, "Watchlist not found")
    return r


def tech_ids(con, wid: int) -> list[str] | None:
    r = con.execute("SELECT id FROM watchlist WHERE id=? AND owner_id=?", (wid, OWNER)).fetchone()
    if not r:
        return None
    return [x[0] for x in con.execute("SELECT ref_id FROM watchlist_item WHERE watchlist_id=? AND kind='technology'", (wid,))]


def create(con, name: str, techs: list[str]) -> dict:
    name = _valid_name(name)
    techs = list(dict.fromkeys(_tech(t) for t in techs))
    if con.execute("SELECT COUNT(*) FROM watchlist WHERE owner_id=?", (OWNER,)).fetchone()[0] >= MAX_LISTS:
        raise WatchlistError(422, f"At most {MAX_LISTS} watchlists")
    ts = db.now_iso()
    try:
        cur = con.execute("INSERT INTO watchlist(owner_id,name,created_at,updated_at) VALUES(?,?,?,?)", (OWNER, name, ts, ts))
    except sqlite3.IntegrityError:
        raise WatchlistError(409, "A watchlist with this name already exists")
    con.executemany("INSERT INTO watchlist_item(watchlist_id,kind,ref_id,added_at) VALUES(?,?,?,?)", [(cur.lastrowid, "technology", t, ts) for t in techs])
    return _row(con, _get(con, cur.lastrowid))


def rename(con, wid: int, name: str) -> dict:
    _get(con, wid)
    try:
        con.execute("UPDATE watchlist SET name=?, updated_at=? WHERE id=?", (_valid_name(name), db.now_iso(), wid))
    except sqlite3.IntegrityError:
        raise WatchlistError(409, "A watchlist with this name already exists")
    return _row(con, _get(con, wid))


def delete(con, wid: int) -> None:
    _get(con, wid)
    con.execute("DELETE FROM watchlist_item WHERE watchlist_id=?", (wid,))
    con.execute("DELETE FROM watchlist WHERE id=?", (wid,))


def add_tech(con, wid: int, tid: str) -> dict:
    _get(con, wid)
    _tech(tid)
    con.execute("INSERT OR IGNORE INTO watchlist_item(watchlist_id,kind,ref_id,added_at) VALUES(?,?,?,?)", (wid, "technology", tid, db.now_iso()))
    con.execute("UPDATE watchlist SET updated_at=? WHERE id=?", (db.now_iso(), wid))
    return _row(con, _get(con, wid))


def remove_tech(con, wid: int, tid: str) -> dict:
    _get(con, wid)
    con.execute("DELETE FROM watchlist_item WHERE watchlist_id=? AND kind='technology' AND ref_id=?", (wid, tid))
    con.execute("UPDATE watchlist SET updated_at=? WHERE id=?", (db.now_iso(), wid))
    return _row(con, _get(con, wid))


def summary(con, wid: int, scores: dict[str, dict] | None = None) -> dict:
    wl = _row(con, _get(con, wid))
    ids = wl["technologies"]
    if scores is None:   # any catalogue technology can be in a watchlist, not only the dashboard ones: build exactly the ones listed
        srcs = service._sources(con)
        scores = {tid: service.build_technology(con, tid, srcs=srcs) for tid in ids if tid in BY_ID}
    ph = ",".join("?" * len(ids)) or "''"
    techs = []
    for tid in ids:
        t = scores.get(tid) or {}
        news = con.execute("SELECT COUNT(DISTINCT news_id) FROM news_tech WHERE tech_id=?", (tid,)).fetchone()[0]
        techs.append({"id": tid, "name": BY_ID[tid].name, "score": t.get("score"), "level": t.get("level"), "cve_count": t.get("cve_count", 0),
                      "kev_count": t.get("kev_count", 0), "recent_exploited_count": t.get("recent_exploited_count", 0),
                      "insufficient_reason": t.get("insufficient_reason"), "quality": (t.get("quality") or {}).get("level"), "news_count": news,
                      "coverage_state": t.get("coverage_state"), "coverage_label": t.get("coverage_label"), "cves_complete": t.get("cves_complete", True), "sync_status": (t.get("sync") or {}).get("label")})
    uniq = con.execute(f"SELECT COUNT(DISTINCT cve_id) FROM tech_cve WHERE tech_id IN ({ph})", ids).fetchone()[0]
    kev = con.execute(f"SELECT COUNT(DISTINCT t.cve_id) FROM tech_cve t JOIN kev_entry k ON k.cve_id=t.cve_id WHERE t.tech_id IN ({ph})", ids).fetchone()[0]
    news = con.execute(f"SELECT COUNT(DISTINCT news_id) FROM news_tech WHERE tech_id IN ({ph})", ids).fetchone()[0]
    scored = [t for t in techs if t["score"] is not None]
    top = max(scored, key=lambda t: t["score"], default=None)
    return {**wl, "technology_details": techs,
            "totals": {"technologies": len(ids), "unique_cves": uniq, "kev_cves": kev, "news": news, "scored": len(scored), "without_score": len(ids) - len(scored)},
            "highest": {"id": top["id"], "name": top["name"], "score": top["score"]} if top else None,
            "note": "Threat Signal Scores come from the vulnerability engine and are not changed by watchlists or news."}
