"""Source registry administration: listing/filtering/pagination, manual sources, validation, bulk actions, coverage report. Reuses the existing registry
(news_source rows + news.sources) and the existing collector: there is no second synchronisation system."""
from __future__ import annotations

import json
import re
from collections import Counter
from datetime import datetime, timedelta, timezone

from .. import db
from . import repo, source_validation as sv
from .sources import CATEGORIES, DEFAULT_CATEGORY, SOURCE_TYPES, BY_ID, FeedSource, from_row, register, unregister

CATEGORY_TYPE = {"news": "news", "threat_intel": "threat_intel", "vuln_research": "vuln_research", "vendor_advisory": "official", "cert": "official", "cloud": "cloud",
                 "appsec": "appsec", "malware": "malware", "privacy": "privacy", "ics": "ics"}
VALIDATION = ("verified", "temporarily_unavailable", "unsupported", "invalid", "duplicate")
CTRL = re.compile(r"[\x00-\x1f\x7f]")
BULK_MAX = 50
VALIDATE_MAX = 15                     # each validation is a real network fetch: bigger selections are validated in several requests
SORTS = ("name", "category", "country", "status", "articles", "last_sync", "newest")


class AdminError(Exception):
    def __init__(self, status: int, msg: str):
        super().__init__(msg)
        self.status, self.msg = status, msg


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(d=None) -> str:
    return (d or _now()).isoformat(timespec="seconds")


def _text(v, field: str, maxlen: int, required: bool = False) -> str | None:
    v = re.sub(r"\s+", " ", v).strip() if isinstance(v, str) else ("" if v is None else str(v).strip())
    if CTRL.search(v):
        raise AdminError(422, f"{field} contains control characters")
    if required and not v:
        raise AdminError(422, f"{field} is required")
    if len(v) > maxlen:
        raise AdminError(422, f"{field} must be at most {maxlen} characters")
    return v or None


def _slug(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")[:40] or "source"


# ----------------------------------------------------------------------------- listing
def _extra(con) -> tuple[dict, dict, dict]:
    week = _iso(_now() - timedelta(days=7))
    month = _iso(_now() - timedelta(days=30))
    w = {r[0]: r[1] for r in con.execute("SELECT source_id,COUNT(*) FROM news_item WHERE sort_ts>=? GROUP BY source_id", (week,))}
    m = {r[0]: r[1] for r in con.execute("SELECT source_id,COUNT(*) FROM news_item WHERE sort_ts>=? GROUP BY source_id", (month,))}
    newest = {r[0]: r[1] for r in con.execute("SELECT source_id,MAX(published) FROM news_item GROUP BY source_id")}
    return w, m, newest


def _state(s: dict) -> str:
    if not s["enabled"]:
        return "disabled"
    if s["validation_status"] in ("invalid", "unsupported"):
        return "failed"
    return s["health"]


def indicators(items: list[dict], week: dict) -> dict:
    en = [s for s in items if s["enabled"]]
    last = max((s["last_success"] for s in en if s["last_success"]), default=None)
    return {"total": len(items), "enabled": len(en), "verified": sum(1 for s in items if s["validation_status"] == "verified"),
            "failed": sum(1 for s in en if _state(s) == "failed"),                              # disabled sources are never failures
            "with_recent_articles": sum(1 for s in en if week.get(s["id"], 0) > 0), "last_successful_sync": last,
            "operational": sum(1 for s in items if s["operational"])}


def query(con, *, q=None, category=None, country=None, language=None, status=None, enabled=None, origin=None, batch=None, sort="name", order="asc", page=1, page_size=25) -> dict:
    repo.sync_source_rows(con)
    items = repo.list_sources(con)
    week, month, newest = _extra(con)
    for s in items:
        s["state"] = _state(s)
        s["articles_7d"], s["articles_30d"], s["latest_publication"] = week.get(s["id"], 0), month.get(s["id"], 0), newest.get(s["id"])
        s["category_label"] = CATEGORIES.get(s["category"] or "", None)
    facets = {"categories": Counter(s["category"] for s in items if s["category"]), "countries": Counter(s["country"] for s in items if s["country"]),
              "languages": Counter(s["language"] for s in items if s["language"] and s["language"] != "unknown"), "states": Counter(s["state"] for s in items),
              "validation": Counter(s["validation_status"] or "unvalidated" for s in items), "origins": Counter(s["origin"] for s in items)}
    ql = (q or "").strip().lower()

    def ok(s):
        if ql and ql not in s["name"].lower() and ql not in (s["publisher"] or "").lower() and ql not in (s["url"] or "").lower():
            return False
        if category and s["category"] != category: return False
        if country and s["country"] != country: return False
        if language and s["language"] != language: return False
        if origin and s["origin"] != origin: return False
        if batch is not None and s["batch"] != batch: return False
        if enabled is not None and s["enabled"] != enabled: return False
        if status:
            if status in VALIDATION or status == "unvalidated":
                if (s["validation_status"] or "unvalidated") != status: return False
            elif s["state"] != status: return False
        return True
    rows = [s for s in items if ok(s)]
    key = {"name": lambda s: s["name"].lower(), "category": lambda s: (s["category"] or "~", s["name"].lower()), "country": lambda s: (s["country"] or "~", s["name"].lower()),
           "status": lambda s: (s["state"], s["name"].lower()), "articles": lambda s: s["items_stored"], "last_sync": lambda s: s["last_success"] or "", "newest": lambda s: s["latest_publication"] or ""}[sort]
    rows.sort(key=key, reverse=(order == "desc"))
    total = len(rows)
    return {"items": rows[(page - 1) * page_size: page * page_size], "total": total, "page": page, "page_size": page_size, "pages": max(1, -(-total // page_size)),
            "indicators": indicators(items, week), "facets": {k: dict(v) for k, v in facets.items()},
            "categories": [{"id": k, "label": v} for k, v in CATEGORIES.items()], "types": [{"id": k, "label": v} for k, v in SOURCE_TYPES.items()]}


def coverage(con) -> dict:
    """Source Coverage: what each source contributes, what stopped working, what is merely quiet (never counted as failed)."""
    repo.sync_source_rows(con)
    items = repo.list_sources(con)
    week, month, newest = _extra(con)
    now = _now()
    out = []
    for s in items:
        st = _state(s)
        nw = newest.get(s["id"])
        inactive = bool(s["enabled"] and st in ("healthy", "quiet") and week.get(s["id"], 0) == 0 and (not nw or datetime.fromisoformat(nw) < now - timedelta(days=14)))
        out.append({"id": s["id"], "name": s["name"], "category": s["category"], "country": s["country"], "language": s["language"], "state": st, "enabled": s["enabled"],
                    "articles_total": s["items_stored"], "articles_30d": month.get(s["id"], 0), "articles_7d": week.get(s["id"], 0), "last_success": s["last_success"],
                    "last_attempt": s["last_attempt"], "latest_publication": nw, "no_recent_activity": inactive, "error": s["error"] if st == "failed" else None,
                    "validation_status": s["validation_status"]})
    en = [s for s in out if s["enabled"]]
    by = lambda k: dict(Counter(s[k] or "unknown" for s in out))  # noqa: E731
    return {"indicators": indicators(items, week), "by_category": by("category"), "by_country": by("country"), "by_language": by("language"),
            "operational": sum(1 for s in en if s["state"] in ("healthy", "quiet")), "failed": [s for s in out if s["enabled"] and s["state"] == "failed"],
            "no_recent_activity": [s for s in out if s["no_recent_activity"]], "sources": sorted(out, key=lambda s: -s["articles_30d"]),
            "note": "A source with no recent article is only 'no recent activity': it is not a failure unless its fetch or validation failed."}


# ----------------------------------------------------------------------------- validation & changes
def apply_validation(con, sid: str, r: dict) -> None:
    status = "verified" if r["status"] == "verified" else r["status"]
    con.execute("UPDATE news_source SET validation_status=?,validated_at=?,validation_note=?,language=COALESCE(?,language) WHERE id=?",
                (status, r["validated_at"], (r.get("note") or None) and r["note"][:200], r.get("language"), sid))


def validate_source(sid: str) -> dict:
    """Real fetch + parse of the configured URL (network first, then one short write)."""
    with db.connect() as con:
        row = con.execute("SELECT url FROM news_source WHERE id=?", (sid,)).fetchone()
    if not row:
        raise AdminError(404, "Source not found")
    r = sv.assess(row["url"], require_relevance=False)
    with db.connect() as con:
        apply_validation(con, sid, r)
        if r["status"] == "verified":
            s = BY_ID.get(sid)
            hosts = [h for h in dict.fromkeys(r["hosts"]) if s is None or h not in s.hosts][:3]
            if s is not None and s.origin == "manual" and hosts:
                con.execute("UPDATE news_source SET extra_hosts=? WHERE id=?", (json.dumps(sorted(set(hosts) | set(s.extra_hosts))), sid))
                register(FeedSource(s.id, s.name, s.type, s.url, tuple(sorted(set(hosts) | set(s.extra_hosts))), s.enabled, s.note, s.official_domains, s.publisher, s.site, s.category, s.country, s.origin, s.batch))
    return {k: r[k] for k in ("status", "http", "note", "entries", "newest", "language", "title", "relevance", "final_url", "validated_at")}


def _fields(d: dict, cur: dict | None = None) -> dict:
    cat = d.get("category", cur["category"] if cur else None)
    if cat not in CATEGORIES:
        raise AdminError(422, f"category must be one of: {', '.join(CATEGORIES)}")
    country = d.get("country", cur["country"] if cur else None)
    if country not in (None, "") and not re.fullmatch(r"[A-Z]{2}", str(country)):
        raise AdminError(422, "country must be a two-letter ISO code (or empty when unknown)")
    lang = d.get("language", cur["language"] if cur else None)
    if lang not in (None, "", "unknown") and not re.fullmatch(r"[a-z]{2,3}", str(lang)):
        raise AdminError(422, "language must be a 2-3 letter code (or empty when unknown)")
    site = _text(d.get("site", cur["site_url"] if cur else None), "Site URL", 300)
    if site and not re.match(r"^https?://[^\s]+$", site):
        raise AdminError(422, "Site URL must be an http(s) URL")
    return {"name": _text(d.get("name", cur["name"] if cur else None), "Name", 100, True), "publisher": _text(d.get("publisher", cur["publisher"] if cur else None), "Publisher", 100),
            "site": site, "category": cat, "type": CATEGORY_TYPE[cat], "country": country or None, "language": None if lang in ("", "unknown") else lang}


def add_manual(d: dict) -> dict:
    f = _fields(d)
    url = _text(d.get("url"), "Feed URL", 500, True)
    if not re.match(r"^https?://[^\s<>\"']+$", url):
        raise AdminError(422, "Feed URL must be an absolute http(s) URL")
    norm = sv.normalize_feed_url(url)
    with db.connect() as con:
        repo.sync_source_rows(con)
        for r in con.execute("SELECT id,url FROM news_source"):
            if sv.normalize_feed_url(r["url"]) == norm:
                raise AdminError(409, f"This feed is already registered as '{r['id']}'")
        base, sid, n = _slug(f["name"]), _slug(f["name"]), 2
        while con.execute("SELECT 1 FROM news_source WHERE id=?", (sid,)).fetchone() or sid in BY_ID:
            sid, n = f"{base}-{n}", n + 1
    r = sv.assess(url, require_relevance=True)                                  # real fetch + parse + relevance, outside any transaction
    hosts = [h for h in dict.fromkeys(r["hosts"])]
    feed_host = hosts[0] if hosts else ""
    extra = hosts[1:4] if r["status"] == "verified" else []
    dom = (sv.registrable(feed_host),) if f["type"] == "official" and feed_host else ()
    with db.connect() as con:
        enabled = 1 if r["status"] == "verified" else 0                       # only verified sources start enabled
        con.execute("INSERT INTO news_source(id,name,type,url,enabled,note,publisher,site_url,category,country,origin,validation_status,validated_at,validation_note,extra_hosts,official_domains,language,enabled_at) "
                    "VALUES(?,?,?,?,?,?,?,?,?,?,'manual',?,?,?,?,?,?,?)",
                    (sid, f["name"], f["type"], url, enabled, None, f["publisher"], f["site"], f["category"], f["country"], r["status"], r["validated_at"], (r.get("note") or None),
                     json.dumps(extra), json.dumps(list(dom)), f["language"] or r.get("language"), _iso() if enabled else None))
    register(from_row({"id": sid, "name": f["name"], "type": f["type"], "url": url, "publisher": f["publisher"], "site": f["site"], "category": f["category"], "country": f["country"],
                       "extra_hosts": extra, "official_domains": list(dom)}, "manual", bool(enabled)))
    return {"id": sid, "validation": {k: r[k] for k in ("status", "http", "note", "entries", "newest", "language", "title", "relevance")}, "enabled": bool(enabled)}


def edit(sid: str, d: dict) -> dict:
    with db.connect() as con:
        row = con.execute("SELECT * FROM news_source WHERE id=?", (sid,)).fetchone()
        if not row:
            raise AdminError(404, "Source not found")
        cur = dict(row)
    s = BY_ID.get(sid)
    if s is None or s.origin != "manual":
        # built-in and catalogue sources keep their configured identity (name/url/type): only descriptive fields may change
        allowed = {k: d[k] for k in ("publisher", "site", "country", "language") if k in d}
        if set(d) - set(allowed) - {"category"}:
            raise AdminError(403, "Built-in and catalogue sources can only change publisher, site, country, language and category")
        d = {**allowed, **({"category": d["category"]} if "category" in d else {})}
        f = _fields({**d}, {**cur, "category": cur["category"] or DEFAULT_CATEGORY.get(cur["type"])})
        f.pop("name"), f.pop("type")
        f["name"], f["type"] = cur["name"], cur["type"]
    else:
        f = _fields(d, cur)
    url_changed = False
    new_url = cur["url"]
    if s is not None and s.origin == "manual" and "url" in d and d["url"] != cur["url"]:
        new_url = _text(d["url"], "Feed URL", 500, True)
        if not re.match(r"^https?://[^\s<>\"']+$", new_url):
            raise AdminError(422, "Feed URL must be an absolute http(s) URL")
        url_changed = True
    with db.connect() as con:
        con.execute("UPDATE news_source SET name=?,publisher=?,site_url=?,category=?,type=?,country=?,language=COALESCE(?,language),url=? WHERE id=?",
                    (f["name"], f["publisher"], f["site"], f["category"], f["type"], f["country"], f["language"], new_url, sid))
        if url_changed:
            con.execute("UPDATE news_source SET validation_status=NULL,validated_at=NULL,validation_note='URL changed: validate again',enabled=0,etag=NULL,last_modified=NULL,extra_hosts='[]',status='pending',error=NULL WHERE id=?", (sid,))
    if s is not None:
        register(FeedSource(s.id, f["name"], f["type"], new_url, () if url_changed else s.extra_hosts, False if url_changed else s.enabled, s.note,
                            s.official_domains if not url_changed else (), f["publisher"], f["site"], f["category"], f["country"], s.origin, s.batch))
    if url_changed:
        validate_source(sid)
    return {"id": sid}


def delete_manual(sid: str) -> None:
    s = BY_ID.get(sid)
    if s is None or s.origin != "manual":
        raise AdminError(403, "Only manually added sources can be deleted (built-in and catalogue sources can be disabled)")
    with db.connect() as con:
        if con.execute("SELECT 1 FROM news_item WHERE source_id=? LIMIT 1", (sid,)).fetchone():
            raise AdminError(409, "This source has stored articles, which are kept: disable it instead of deleting it")
        con.execute("DELETE FROM news_source WHERE id=?", (sid,))
    unregister(sid)


def set_enabled(sid: str, enabled: bool) -> tuple[bool, str | None]:
    with db.connect() as con:
        r = con.execute("SELECT validation_status FROM news_source WHERE id=?", (sid,)).fetchone()
        if not r:
            raise AdminError(404, "Source not found")
        if enabled and r["validation_status"] in ("invalid", "unsupported", "duplicate"):
            return False, f"validation is '{r['validation_status']}': validate it again first"
        repo.set_source_enabled(con, sid, enabled)
    return True, None


def bulk(ids: list[str], action: str) -> dict:
    if action not in ("enable", "disable", "validate"):
        raise AdminError(422, "action must be enable, disable or validate")
    if not ids or len(ids) > BULK_MAX or len(set(ids)) != len(ids):
        raise AdminError(422, f"Select between 1 and {BULK_MAX} different sources")
    if action == "validate" and len(ids) > VALIDATE_MAX:
        raise AdminError(422, f"Validate at most {VALIDATE_MAX} sources per request")
    done, skipped = [], []
    for sid in ids:
        try:
            if action == "validate":
                done.append({"id": sid, **validate_source(sid)})
            else:
                ok, why = set_enabled(sid, action == "enable")
                (done if ok else skipped).append({"id": sid} if ok else {"id": sid, "reason": why})
        except AdminError as e:
            skipped.append({"id": sid, "reason": e.msg})
    return {"action": action, "done": done, "skipped": skipped}
