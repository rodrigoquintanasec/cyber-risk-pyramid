"""Custom Intelligence Dashboards: user-defined keyword pyramids over the EXISTING Intelligence Feed articles.

* No article is copied: dashboards store only their configuration; every number is derived from `news_item` (+ `news_cve`, and the existing clustering for "unique events").
* Matching is deterministic and safe: user terms are escaped literals (never regular expressions), compared case-insensitively on normalised text.
* The colour is a MEDIA ATTENTION level computed from the dashboard's own article counts (relative scale with absolute safeguards). It is never a risk measure and
  never uses CVSS / EPSS / KEV / Threat Signal Score.
"""
from __future__ import annotations

import re
import threading
import time
import unicodedata
from datetime import date, datetime, timedelta, timezone

from . import db
from .briefing import safe_url
from .config import settings
from .news import intel, repo

# ----------------------------------------------------------------------------- limits & vocabulary
MAX_DASHBOARDS = 50
MAX_KEYWORDS = 24                      # one pyramid per keyword; same cap as the technology dashboard
MAX_INCLUDE, MAX_EXCLUDE = 20, 10
TERM_MIN, TERM_MAX = 2, 80
NAME_MAX, KEYWORD_MAX, DESC_MAX = 80, 60, 300
MATCH_TYPES = ("word", "phrase", "exact")
PERIODS = {"24h": (timedelta(hours=24), "Last 24 Hours"), "48h": (timedelta(hours=48), "Last 48 Hours"), "7d": (timedelta(days=7), "Last 7 Days"),
           "30d": (timedelta(days=30), "Last 30 Days"), "90d": (timedelta(days=90), "Last 90 Days")}
MAX_CUSTOM_DAYS = 366
MIN_COVERAGE_ARTICLES = 10             # fewer dated articles than this in the window = the feed cannot say anything about the period
CTRL = re.compile(r"[\x00-\x1f\x7f]")
SEP = " ¦ "                       # joins title / excerpt / CVE ids so a phrase can never span two fields

SCHEMA = """
CREATE TABLE IF NOT EXISTS intelligence_dashboard(
  id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, description TEXT NOT NULL DEFAULT '', default_period TEXT NOT NULL DEFAULT '7d'
  CHECK(default_period IN ('24h','48h','7d','30d','90d')), display_order INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
CREATE UNIQUE INDEX IF NOT EXISTS ux_idash_name ON intelligence_dashboard(name COLLATE NOCASE);
CREATE TABLE IF NOT EXISTS intelligence_dashboard_keyword(
  id INTEGER PRIMARY KEY AUTOINCREMENT, dashboard_id INTEGER NOT NULL REFERENCES intelligence_dashboard(id) ON DELETE CASCADE, display_name TEXT NOT NULL,
  enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0,1)), display_order INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
CREATE UNIQUE INDEX IF NOT EXISTS ux_idash_kw_name ON intelligence_dashboard_keyword(dashboard_id, display_name COLLATE NOCASE);
CREATE INDEX IF NOT EXISTS ix_idash_kw_order ON intelligence_dashboard_keyword(dashboard_id, display_order);
CREATE TABLE IF NOT EXISTS intelligence_keyword_term(
  id INTEGER PRIMARY KEY AUTOINCREMENT, keyword_id INTEGER NOT NULL REFERENCES intelligence_dashboard_keyword(id) ON DELETE CASCADE, term TEXT NOT NULL,
  match_type TEXT NOT NULL DEFAULT 'word' CHECK(match_type IN ('word','phrase','exact')), is_exclusion INTEGER NOT NULL DEFAULT 0 CHECK(is_exclusion IN (0,1)));
CREATE UNIQUE INDEX IF NOT EXISTS ux_idash_term ON intelligence_keyword_term(keyword_id, term COLLATE NOCASE, is_exclusion);
CREATE INDEX IF NOT EXISTS ix_news_published ON news_item(published);
"""


class DashError(Exception):
    def __init__(self, status: int, msg: str):
        super().__init__(msg)
        self.status, self.msg = status, msg


def migrate(con) -> None:
    con.executescript(SCHEMA)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(d: datetime | None) -> str | None:
    return d.isoformat(timespec="seconds") if d else None


# ----------------------------------------------------------------------------- text normalisation & matching
def norm(s: str | None) -> str:
    """Case-insensitive, width/compatibility-normalised, whitespace collapsed."""
    return re.sub(r"\s+", " ", unicodedata.normalize("NFKC", s or "").casefold()).strip()


_NOT_ALNUM_BEFORE, _NOT_ALNUM_AFTER = r"(?<![^\W_])", r"(?![^\W_])"


def term_pattern(term: str, match_type: str) -> str:
    """Escaped literal -> regex source. word/phrase: bounded by non-alphanumerics (so 'Akira' never matches 'Akiranet'); exact: literal substring. User text is never used as a regex."""
    t = re.escape(norm(term))
    return t if match_type == "exact" else f"{_NOT_ALNUM_BEFORE}{t}{_NOT_ALNUM_AFTER}"


class Matcher:
    def __init__(self, terms: list[dict]):
        inc = [term_pattern(t["term"], t["match_type"]) for t in terms if not t["is_exclusion"]]
        exc = [term_pattern(t["term"], t["match_type"]) for t in terms if t["is_exclusion"]]
        self.inc = re.compile("|".join(inc)) if inc else None
        self.exc = re.compile("|".join(exc)) if exc else None

    def matches(self, text: str) -> bool:
        return bool(self.inc and self.inc.search(text) and not (self.exc and self.exc.search(text)))


def validate_term(t: dict) -> dict:
    term = re.sub(r"\s+", " ", str(t.get("term") or "")).strip()
    mt = t.get("match_type") or "word"
    if CTRL.search(term):
        raise DashError(422, "Terms cannot contain control characters")
    if mt not in MATCH_TYPES:
        raise DashError(422, f"match_type must be one of {', '.join(MATCH_TYPES)}")
    if not (TERM_MIN <= len(term) <= TERM_MAX):
        raise DashError(422, f"Each term needs {TERM_MIN}-{TERM_MAX} characters")
    if not re.search(r"[^\W_]", term):
        raise DashError(422, "A term must contain at least one letter or digit")
    if mt == "exact" and len(norm(term)) < 3:
        raise DashError(422, "Exact-text terms need at least 3 characters (shorter ones match inside unrelated words)")
    return {"term": term, "match_type": mt, "is_exclusion": 1 if t.get("is_exclusion") else 0}


def _clean_terms(terms) -> list[dict]:
    if not isinstance(terms, list):
        raise DashError(422, "terms must be a list")
    out, seen = [], set()
    for raw in terms:
        t = validate_term(raw if isinstance(raw, dict) else {"term": raw})
        k = (norm(t["term"]), t["is_exclusion"])
        if k not in seen:
            seen.add(k)
            out.append(t)
    inc, exc = sum(1 for t in out if not t["is_exclusion"]), sum(1 for t in out if t["is_exclusion"])
    if inc < 1:
        raise DashError(422, "A keyword needs at least one search term")
    if inc > MAX_INCLUDE or exc > MAX_EXCLUDE:
        raise DashError(422, f"At most {MAX_INCLUDE} search terms and {MAX_EXCLUDE} excluded terms per keyword")
    return out


def _text(v, field: str, maxlen: int, required: bool = False) -> str:
    v = re.sub(r"[ \t]+", " ", v).strip() if isinstance(v, str) else ("" if v is None else str(v).strip())
    if CTRL.search(v):
        raise DashError(422, f"{field} contains control characters")
    if required and not v:
        raise DashError(422, f"{field} is required")
    if len(v) > maxlen:
        raise DashError(422, f"{field} must be at most {maxlen} characters")
    return v


# ----------------------------------------------------------------------------- CRUD
def _kw_rows(con, did: int) -> list[dict]:
    kws = [dict(r) for r in con.execute("SELECT * FROM intelligence_dashboard_keyword WHERE dashboard_id=? ORDER BY display_order, id", (did,))]
    terms: dict[int, list[dict]] = {}
    for r in con.execute("SELECT t.* FROM intelligence_keyword_term t JOIN intelligence_dashboard_keyword k ON k.id=t.keyword_id WHERE k.dashboard_id=? ORDER BY t.is_exclusion, t.id", (did,)):
        terms.setdefault(r["keyword_id"], []).append({"id": r["id"], "term": r["term"], "match_type": r["match_type"], "is_exclusion": bool(r["is_exclusion"])})
    return [{"id": k["id"], "display_name": k["display_name"], "enabled": bool(k["enabled"]), "display_order": k["display_order"],
             "terms": [t for t in terms.get(k["id"], []) if not t["is_exclusion"]], "excluded_terms": [t for t in terms.get(k["id"], []) if t["is_exclusion"]],
             "updated_at": k["updated_at"]} for k in kws]


def _dash_row(con, did: int):
    r = con.execute("SELECT * FROM intelligence_dashboard WHERE id=?", (did,)).fetchone()
    if not r:
        raise DashError(404, "Dashboard not found")
    return r


def _shape(r, kws: list[dict]) -> dict:
    return {"id": r["id"], "name": r["name"], "description": r["description"], "default_period": r["default_period"], "display_order": r["display_order"],
            "created_at": r["created_at"], "updated_at": r["updated_at"], "keywords": kws, "keyword_count": len(kws), "enabled_keywords": sum(1 for k in kws if k["enabled"])}


def list_dashboards(con) -> list[dict]:
    out = []
    for r in con.execute("SELECT * FROM intelligence_dashboard ORDER BY display_order, id").fetchall():
        n, e = con.execute("SELECT COUNT(*), COALESCE(SUM(enabled),0) FROM intelligence_dashboard_keyword WHERE dashboard_id=?", (r["id"],)).fetchone()
        out.append({**_shape(r, []), "keyword_count": n, "enabled_keywords": e})
    return out


def get_dashboard(con, did: int) -> dict:
    r = _dash_row(con, did)
    return _shape(r, _kw_rows(con, did))


def _touch(con, did: int) -> None:
    con.execute("UPDATE intelligence_dashboard SET updated_at=? WHERE id=?", (_now().isoformat(), did))     # microseconds: the cache key must change on every edit


def _check_period(p) -> str:
    if p not in PERIODS:
        raise DashError(422, f"default_period must be one of {', '.join(PERIODS)} (a custom range is not saved as default)")
    return p


def create_dashboard(con, d: dict) -> dict:
    if con.execute("SELECT COUNT(*) FROM intelligence_dashboard").fetchone()[0] >= MAX_DASHBOARDS:
        raise DashError(409, f"At most {MAX_DASHBOARDS} dashboards")
    name = _text(d.get("name"), "Name", NAME_MAX, True)
    if con.execute("SELECT 1 FROM intelligence_dashboard WHERE name=? COLLATE NOCASE", (name,)).fetchone():
        raise DashError(409, "A dashboard with this name already exists")
    kws = d.get("keywords") or []
    if len(kws) > MAX_KEYWORDS:
        raise DashError(422, f"At most {MAX_KEYWORDS} keywords per dashboard")
    prepared = [_prepare_keyword(k) for k in kws]
    if len({norm(k["display_name"]) for k in prepared}) != len(prepared):
        raise DashError(409, "Duplicate keyword names")
    now = _iso(_now())
    order = (con.execute("SELECT COALESCE(MAX(display_order),0) FROM intelligence_dashboard").fetchone()[0] or 0) + 10
    did = con.execute("INSERT INTO intelligence_dashboard(name,description,default_period,display_order,created_at,updated_at) VALUES(?,?,?,?,?,?)",
                      (name, _text(d.get("description"), "Description", DESC_MAX), _check_period(d.get("default_period") or "7d"), order, now, now)).lastrowid
    for i, k in enumerate(prepared):
        _insert_keyword(con, did, k, (i + 1) * 10, now)
    return get_dashboard(con, did)


def update_dashboard(con, did: int, d: dict) -> dict:
    cur = _dash_row(con, did)
    name = _text(d["name"], "Name", NAME_MAX, True) if "name" in d else cur["name"]
    if name.lower() != cur["name"].lower() and con.execute("SELECT 1 FROM intelligence_dashboard WHERE name=? COLLATE NOCASE", (name,)).fetchone():
        raise DashError(409, "A dashboard with this name already exists")
    desc = _text(d["description"], "Description", DESC_MAX) if "description" in d else cur["description"]
    period = _check_period(d["default_period"]) if "default_period" in d else cur["default_period"]
    con.execute("UPDATE intelligence_dashboard SET name=?,description=?,default_period=?,updated_at=? WHERE id=?", (name, desc, period, _now().isoformat(), did))
    return get_dashboard(con, did)


def delete_dashboard(con, did: int) -> None:
    _dash_row(con, did)
    con.execute("DELETE FROM intelligence_dashboard WHERE id=?", (did,))        # keywords and terms follow through ON DELETE CASCADE


def reorder_dashboards(con, ids: list[int]) -> list[dict]:
    known = {r[0] for r in con.execute("SELECT id FROM intelligence_dashboard")}
    if len(set(ids)) != len(ids) or any(i not in known for i in ids):
        raise DashError(422, "Invalid dashboard list")
    rest = [i for i in sorted(known) if i not in ids]
    for n, did in enumerate([*ids, *rest]):
        con.execute("UPDATE intelligence_dashboard SET display_order=? WHERE id=?", ((n + 1) * 10, did))
    return list_dashboards(con)


def duplicate_dashboard(con, did: int) -> dict:
    src = get_dashboard(con, did)
    base = f"{src['name']} Copy"[:NAME_MAX]
    name, n = base, 2
    while con.execute("SELECT 1 FROM intelligence_dashboard WHERE name=? COLLATE NOCASE", (name,)).fetchone():
        name, n = f"{base[:NAME_MAX - 4]} {n}", n + 1
    if con.execute("SELECT COUNT(*) FROM intelligence_dashboard").fetchone()[0] >= MAX_DASHBOARDS:
        raise DashError(409, f"At most {MAX_DASHBOARDS} dashboards")
    now = _iso(_now())
    order = (con.execute("SELECT COALESCE(MAX(display_order),0) FROM intelligence_dashboard").fetchone()[0] or 0) + 10
    new = con.execute("INSERT INTO intelligence_dashboard(name,description,default_period,display_order,created_at,updated_at) VALUES(?,?,?,?,?,?)",
                      (name, src["description"], src["default_period"], order, now, now)).lastrowid
    for k in src["keywords"]:             # new independent ids; no article is copied (there are none to copy)
        kid = con.execute("INSERT INTO intelligence_dashboard_keyword(dashboard_id,display_name,enabled,display_order,created_at,updated_at) VALUES(?,?,?,?,?,?)",
                          (new, k["display_name"], int(k["enabled"]), k["display_order"], now, now)).lastrowid
        for t in [*k["terms"], *k["excluded_terms"]]:
            con.execute("INSERT INTO intelligence_keyword_term(keyword_id,term,match_type,is_exclusion) VALUES(?,?,?,?)", (kid, t["term"], t["match_type"], int(t["is_exclusion"])))
    return get_dashboard(con, new)


def _prepare_keyword(k: dict) -> dict:
    terms = [*(k.get("terms") or []), *[{**(t if isinstance(t, dict) else {"term": t}), "is_exclusion": True} for t in (k.get("excluded_terms") or [])]]
    return {"display_name": _text(k.get("display_name"), "Display name", KEYWORD_MAX, True), "enabled": 1 if k.get("enabled", True) else 0, "terms": _clean_terms(terms)}


def _insert_keyword(con, did: int, k: dict, order: int, now: str) -> int:
    kid = con.execute("INSERT INTO intelligence_dashboard_keyword(dashboard_id,display_name,enabled,display_order,created_at,updated_at) VALUES(?,?,?,?,?,?)", (did, k["display_name"], k["enabled"], order, now, now)).lastrowid
    for t in k["terms"]:
        con.execute("INSERT INTO intelligence_keyword_term(keyword_id,term,match_type,is_exclusion) VALUES(?,?,?,?)", (kid, t["term"], t["match_type"], t["is_exclusion"]))
    return kid


def add_keyword(con, did: int, d: dict) -> dict:
    _dash_row(con, did)
    if con.execute("SELECT COUNT(*) FROM intelligence_dashboard_keyword WHERE dashboard_id=?", (did,)).fetchone()[0] >= MAX_KEYWORDS:
        raise DashError(409, f"At most {MAX_KEYWORDS} pyramids per dashboard")
    k = _prepare_keyword(d)
    if con.execute("SELECT 1 FROM intelligence_dashboard_keyword WHERE dashboard_id=? AND display_name=? COLLATE NOCASE", (did, k["display_name"])).fetchone():
        raise DashError(409, "This dashboard already has a keyword with that name")
    order = (con.execute("SELECT COALESCE(MAX(display_order),0) FROM intelligence_dashboard_keyword WHERE dashboard_id=?", (did,)).fetchone()[0] or 0) + 10
    _insert_keyword(con, did, k, order, _iso(_now()))
    _touch(con, did)
    return get_dashboard(con, did)


def _kw_check(con, did: int, kid: int):
    r = con.execute("SELECT * FROM intelligence_dashboard_keyword WHERE id=? AND dashboard_id=?", (kid, did)).fetchone()
    if not r:
        raise DashError(404, "Keyword not found in this dashboard")
    return r


def update_keyword(con, did: int, kid: int, d: dict) -> dict:
    cur = _kw_check(con, did, kid)
    name = _text(d["display_name"], "Display name", KEYWORD_MAX, True) if "display_name" in d else cur["display_name"]
    if name.lower() != cur["display_name"].lower() and con.execute("SELECT 1 FROM intelligence_dashboard_keyword WHERE dashboard_id=? AND display_name=? COLLATE NOCASE", (did, name)).fetchone():
        raise DashError(409, "This dashboard already has a keyword with that name")
    enabled = cur["enabled"] if d.get("enabled") is None else int(bool(d["enabled"]))
    con.execute("UPDATE intelligence_dashboard_keyword SET display_name=?,enabled=?,updated_at=? WHERE id=?", (name, enabled, _iso(_now()), kid))
    if "terms" in d or "excluded_terms" in d:
        existing = _kw_rows(con, did)
        old = next(k for k in existing if k["id"] == kid)
        terms = [*(d["terms"] if "terms" in d else old["terms"]), *[{**(t if isinstance(t, dict) else {"term": t}), "is_exclusion": True} for t in (d["excluded_terms"] if "excluded_terms" in d else old["excluded_terms"])]]
        clean = _clean_terms(terms)
        con.execute("DELETE FROM intelligence_keyword_term WHERE keyword_id=?", (kid,))
        for t in clean:
            con.execute("INSERT INTO intelligence_keyword_term(keyword_id,term,match_type,is_exclusion) VALUES(?,?,?,?)", (kid, t["term"], t["match_type"], t["is_exclusion"]))
    _touch(con, did)
    return get_dashboard(con, did)


def delete_keyword(con, did: int, kid: int) -> dict:
    _kw_check(con, did, kid)
    con.execute("DELETE FROM intelligence_dashboard_keyword WHERE id=?", (kid,))
    _touch(con, did)
    return get_dashboard(con, did)


def reorder_keywords(con, did: int, ids: list[int]) -> dict:
    _dash_row(con, did)
    known = [r[0] for r in con.execute("SELECT id FROM intelligence_dashboard_keyword WHERE dashboard_id=? ORDER BY display_order, id", (did,))]
    if len(set(ids)) != len(ids) or any(i not in known for i in ids):
        raise DashError(422, "Invalid keyword list")
    for n, kid in enumerate([*ids, *[i for i in known if i not in ids]]):
        con.execute("UPDATE intelligence_dashboard_keyword SET display_order=? WHERE id=?", ((n + 1) * 10, kid))
    _touch(con, did)
    return get_dashboard(con, did)


# ----------------------------------------------------------------------------- time window
def resolve_window(period: str | None, start: str | None = None, end: str | None = None, now: datetime | None = None) -> dict:
    """Presets end 'now' (UTC). A custom range is whole UTC days, start 00:00:00 inclusive to end 23:59:59 inclusive (clipped to now). Everything is UTC."""
    now = now or _now()
    if period == "custom":
        try:
            s, e = date.fromisoformat(start or ""), date.fromisoformat(end or "")
        except ValueError:
            raise DashError(422, "A custom range needs start and end dates (YYYY-MM-DD)")
        if e < s:
            raise DashError(422, "The end date cannot be before the start date")
        if (e - s).days + 1 > MAX_CUSTOM_DAYS:
            raise DashError(422, f"A custom range can span at most {MAX_CUSTOM_DAYS} days")
        a = datetime(s.year, s.month, s.day, tzinfo=timezone.utc)
        b = min(datetime(e.year, e.month, e.day, tzinfo=timezone.utc) + timedelta(days=1), now)
        if b <= a:
            raise DashError(422, "The custom range lies in the future")
        label = f"{s.isoformat()} to {e.isoformat()} (UTC)"
        return {"period": "custom", "label": "Custom Range", "start": a, "end": b, "effective": label, "custom": True}
    if period not in PERIODS:
        raise DashError(422, f"period must be one of {', '.join(PERIODS)} or custom")
    delta, label = PERIODS[period]
    return {"period": period, "label": label, "start": now - delta, "end": now, "effective": f"{(now - delta).strftime('%Y-%m-%d %H:%M')} to {now.strftime('%Y-%m-%d %H:%M')} UTC", "custom": False}


# ----------------------------------------------------------------------------- media attention scale
LEVELS = {"none": ("No Matches", "#6B7280"), "low": ("Low Attention", "#22C55E"), "moderate": ("Moderate Attention", "#EAB308"), "high": ("High Attention", "#F97316"),
          "very_high": ("Very High Attention", "#EF4444"), "insufficient": ("Insufficient Feed Coverage", "#475569")}
ORDER = ["low", "moderate", "high", "very_high"]
ABS_GATES = ((3, "low"), (10, "moderate"), (25, "high"))        # below 3 articles at most Low, below 10 at most Moderate, below 25 at most High
METHOD = ("Colours show relative news coverage inside this dashboard and period, not cybersecurity risk. Pyramids with matches are placed on a four-step scale by combining their "
          "percentile among the pyramids that matched and their count relative to the largest one. Absolute safeguards cap small samples: fewer than 3 articles is at most Low, fewer than 10 at most "
          "Moderate, fewer than 25 at most High. With a single matching pyramid, or equal counts everywhere, only the absolute scale applies. No match is grey.")


def level(key: str) -> dict:
    label, color = LEVELS[key]
    return {"key": key, "label": label, "color": color}


def abs_level(c: int) -> str:
    for gate, key in ABS_GATES:
        if c < gate:
            return key
    return "very_high"


def attention_levels(counts: dict, coverage_ok: bool = True) -> dict:
    """counts: {keyword_id: article_count}. Deterministic: same counts -> same levels."""
    if not coverage_ok:
        return {k: level("insufficient") for k in counts}
    pos = {k: c for k, c in counts.items() if c > 0}
    out = {k: level("none") for k, c in counts.items() if c <= 0}
    if not pos:
        return out
    vals = sorted(pos.values())
    mx, n = vals[-1], len(vals)
    flat = n == 1 or vals[0] == vals[-1]
    for k, c in pos.items():
        cap = abs_level(c)
        if flat:
            out[k] = level(cap)
            continue
        below, equal = sum(1 for v in vals if v < c), sum(1 for v in vals if v == c)
        r = ((below + equal / 2) / n + c / mx) / 2
        rel = "low" if r < 0.25 else "moderate" if r < 0.5 else "high" if r < 0.75 else "very_high"
        out[k] = level(ORDER[min(ORDER.index(rel), ORDER.index(cap))])
    return out


# ----------------------------------------------------------------------------- matching engine
_cache: dict = {}
_lock = threading.Lock()
CACHE_TTL = 60.0


def invalidate() -> None:
    with _lock:
        _cache.clear()


def _data_version(con) -> tuple:
    r = con.execute("SELECT MAX(rowid), MAX(collected_at) FROM news_item").fetchone()
    return (r[0], r[1])


def _parse(s: str | None) -> datetime | None:
    if not s:
        return None
    try:
        d = datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        return None
    return d if d.tzinfo else d.replace(tzinfo=timezone.utc)


def _window_articles(con, win: dict) -> tuple[list[dict], dict]:
    """Articles PUBLISHED inside the window (publication date, never download date). Undated articles are excluded and reported; future-dated ones were already nulled at ingestion."""
    lo = _iso(win["start"] - timedelta(days=1))
    hi = _iso(win["end"] + timedelta(days=1))
    rows = con.execute("SELECT n.id,n.source_id,n.title,n.summary,n.published,s.name AS source_name FROM news_item n JOIN news_source s ON s.id=n.source_id "
                       "WHERE n.published IS NOT NULL AND n.published>=? AND n.published<?", (lo, hi)).fetchall()
    cves: dict[str, list[str]] = {}
    for r in con.execute("SELECT c.news_id,c.cve_id FROM news_cve c JOIN news_item n ON n.id=c.news_id WHERE n.published IS NOT NULL AND n.published>=? AND n.published<?", (lo, hi)):
        cves.setdefault(r[0], []).append(r[1])
    items, seen, dup = [], {}, 0
    for r in rows:
        ts = _parse(r["published"])
        if not ts or not (win["start"] <= ts < win["end"]):
            continue
        key = (r["source_id"], norm(r["title"]))                       # one article per (outlet, title): a re-posted item is not counted twice
        if key in seen:
            dup += 1
            if ts > seen[key]["ts"]:
                seen[key].update(id=r["id"], ts=ts, published=r["published"], summary=r["summary"] or "")
            continue
        it = {"id": r["id"], "source_id": r["source_id"], "source_name": r["source_name"], "title": r["title"], "summary": r["summary"] or "", "published": r["published"], "ts": ts}
        seen[key] = it
        items.append(it)
    for it in items:
        it["cves"] = sorted(cves.get(it["id"], []))
        it["text"] = norm(SEP.join([it["title"], it["summary"], " ".join(it["cves"])]))
    undated = con.execute("SELECT COUNT(*) FROM news_item WHERE published IS NULL AND sort_ts>=? AND sort_ts<?", (_iso(win["start"]), _iso(win["end"]))).fetchone()[0]
    return items, {"duplicates_collapsed": dup, "undated_excluded": undated}


def coverage(con, win: dict, n_dated: int, extra: dict) -> dict:
    st = repo.stats(con)
    hist = con.execute("SELECT MIN(sort_ts) FROM news_item").fetchone()[0]
    hist_start = _parse(hist)
    span = (win["end"] - win["start"]).total_seconds()
    covered = 1.0 if not hist_start else max(0.0, min(1.0, (win["end"] - max(win["start"], hist_start)).total_seconds() / span)) if span > 0 else 0.0
    now = _now()
    age_min = (now - _parse(st["last_success"])).total_seconds() / 60 if st["last_success"] else None
    stale = age_min is None or age_min > 2 * settings.news_interval_minutes
    warn = []
    if age_min is None:
        warn.append("No news synchronisation has completed yet.")
    elif stale:
        warn.append(f"News were last synchronised {age_min / 60:.1f} h ago; newer articles may be missing.")
    if st["sources_failed"]:
        warn.append(f"{st['sources_failed']} enabled feed(s) failed in the latest synchronisation.")
    if covered < 0.95:
        warn.append(f"Stored news cover only {covered * 100:.0f}% of this period (history starts {hist_start.strftime('%Y-%m-%d') if hist_start else 'never'}).")
    if extra["undated_excluded"]:
        warn.append(f"{extra['undated_excluded']} article(s) without a valid publication date were excluded from this period.")
    if n_dated < MIN_COVERAGE_ARTICLES:
        warn.append(f"Only {n_dated} dated article(s) in this period: not enough to judge coverage.")
    added = repo.sources_enabled_since(con, _iso(win["start"]))
    if added:
        warn.append(f"{added} source(s) were enabled during this period: article counts can rise because coverage grew, not because attacker activity did. "
                    "Compare Unique Events and Contributing Sources, and read colours as relative news coverage only.")
    status = "insufficient" if (age_min is None or n_dated < MIN_COVERAGE_ARTICLES or covered < 0.5 or st["sources_active"] == 0) else "partial" if (stale or st["sources_failed"] or covered < 0.95) else "sufficient"
    return {"status": status, "label": {"sufficient": "Coverage OK", "partial": "Partial Coverage", "insufficient": "Insufficient Feed Coverage"}[status], "warnings": warn,
            "articles_in_period": n_dated, "history_covered_pct": round(covered * 100), "last_sync": st["last_success"], "sources_enabled": st["sources_enabled"],
            "sources_failed": st["sources_failed"], "sources_enabled_in_period": added, "undated_excluded": extra["undated_excluded"], "duplicates_collapsed": extra["duplicates_collapsed"],
            "note": "These are news-coverage metrics, not confirmed incidents or a trend of attacks."}


def compute(con, did: int, win: dict) -> dict:
    """One pass over the period's articles for ALL enabled keywords of the dashboard (no per-keyword query)."""
    dash = get_dashboard(con, did)
    items, extra = _window_articles(con, win)
    corpus = intel.get_corpus(con)
    cluster_of = corpus.cluster_of
    active = [k for k in dash["keywords"] if k["enabled"]]
    matchers = {k["id"]: Matcher([*[{**t, "is_exclusion": False} for t in k["terms"]], *[{**t, "is_exclusion": True} for t in k["excluded_terms"]]]) for k in active}
    per: dict[int, list[dict]] = {k["id"]: [] for k in active}
    for it in items:
        for kid, m in matchers.items():
            if m.matches(it["text"]):
                per[kid].append(it)
    cov = coverage(con, win, len(items), extra)
    ev_of = lambda it: (cluster_of[it["id"]]["id"] if it["id"] in cluster_of else f"single:{it['id']}")      # noqa: E731
    stats, union = {}, {}
    for k in active:
        arts = per[k["id"]]
        stats[k["id"]] = {"article_count": len(arts), "unique_events": len({ev_of(a) for a in arts}), "source_count": len({a["source_id"] for a in arts}),
                          "latest_publication": _iso(max((a["ts"] for a in arts), default=None))}
        for a in arts:
            union[a["id"]] = a
    lv = attention_levels({k["id"]: stats[k["id"]]["article_count"] for k in active}, cov["status"] != "insufficient")
    totals = {"keywords_monitored": len(active), "matching_articles": len(union), "unique_events": len({ev_of(a) for a in union.values()}),
              "contributing_sources": len({a["source_id"] for a in union.values()}), "articles_in_period": len(items)}
    unclustered = sum(1 for a in union.values() if a["id"] not in cluster_of)
    empty = {"article_count": None, "unique_events": None, "source_count": None, "latest_publication": None, "level": None}
    keywords = []
    for k in dash["keywords"]:
        base = {x: k[x] for x in ("id", "display_name", "enabled", "display_order", "terms", "excluded_terms")}
        keywords.append({**base, **({**stats[k["id"]], "level": lv[k["id"]]} if k["enabled"] else empty)})
    matches = {kid: sorted(((a["id"], a["ts"], a["source_name"], corpus.prio[cluster_of[a["id"]]["id"]]["score"] if a["id"] in cluster_of else 0.0, ev_of(a), a["source_id"]) for a in arts),
                           key=lambda x: (-x[1].timestamp(), x[0])) for kid, arts in per.items()}
    return {"dashboard": {k2: dash[k2] for k2 in ("id", "name", "description", "default_period", "updated_at", "keyword_count", "enabled_keywords")},
            "window": {"period": win["period"], "label": win["label"], "start": _iso(win["start"]), "end": _iso(win["end"]), "timezone": "UTC", "effective": win["effective"], "custom": win["custom"]},
            "keywords": keywords, "totals": totals, "coverage": cov,
            "events_note": ("Some matching articles are older than the clustering window, so they count as one event each." if unclustered else None),
            "scale": {"method": METHOD, "levels": [level(k) for k in ("low", "moderate", "high", "very_high", "none", "insufficient")], "legend": "Colors represent relative news coverage, not cybersecurity risk."},
            "_matches": matches}


def statistics(con, did: int, period: str | None, start: str | None = None, end: str | None = None, now: datetime | None = None) -> dict:
    """Cached per (dashboard version, window, feed version). Invalidated by any keyword/dashboard change, a new window or newly collected articles."""
    d = _dash_row(con, did)
    win = resolve_window(period or d["default_period"], start, end, now)
    key = (did, d["updated_at"], win["period"], int(win["start"].timestamp() // 60) if not win["custom"] else _iso(win["start"]), None if not win["custom"] else _iso(win["end"]), _data_version(con))
    t = time.monotonic()
    with _lock:
        hit = _cache.get(key)
        if hit and t - hit[0] < CACHE_TTL:
            return hit[1]
    out = compute(con, did, win)
    with _lock:
        if len(_cache) > 64:
            _cache.clear()
        _cache[key] = (t, out)
    return out


def public(stats: dict) -> dict:
    return {k: v for k, v in stats.items() if not k.startswith("_")}


# ----------------------------------------------------------------------------- articles of one pyramid
SORTS = ("newest", "oldest", "priority", "source")


def articles(con, did: int, kid: int, period: str | None, start: str | None = None, end: str | None = None, sort: str = "newest", source: str | None = None,
             event: str | None = None, page: int = 1, page_size: int = 20, now: datetime | None = None) -> dict:
    if sort not in SORTS:
        raise DashError(422, f"sort must be one of {', '.join(SORTS)}")
    if not (1 <= page_size <= 50) or page < 1:
        raise DashError(422, "page must be >= 1 and page_size 1-50")
    kw = _kw_check(con, did, kid)
    st = statistics(con, did, period, start, end, now)
    if not kw["enabled"]:
        raise DashError(409, "This keyword is disabled")
    rows = st["_matches"].get(kid, [])
    if source:
        rows = [r for r in rows if r[5] == source]
    if event:
        rows = [r for r in rows if r[4] == event]
    if sort == "oldest":
        rows = sorted(rows, key=lambda r: (r[1].timestamp(), r[0]))
    elif sort == "priority":
        rows = sorted(rows, key=lambda r: (-r[3], -r[1].timestamp(), r[0]))
    elif sort == "source":
        rows = sorted(rows, key=lambda r: (r[2].lower(), -r[1].timestamp(), r[0]))
    total = len(rows)
    chunk = rows[(page - 1) * page_size: page * page_size]
    ids = [r[0] for r in chunk]
    det: dict[str, dict] = {}
    if ids:
        ph = ",".join("?" * len(ids))
        for r in con.execute(f"SELECT n.id,n.title,n.summary,n.url,n.published,n.source_id,s.name AS source_name FROM news_item n JOIN news_source s ON s.id=n.source_id WHERE n.id IN ({ph})", ids):
            det[r["id"]] = dict(r)
        cv: dict[str, list[str]] = {}
        for r in con.execute(f"SELECT news_id,cve_id FROM news_cve WHERE news_id IN ({ph}) ORDER BY cve_id", ids):
            cv.setdefault(r[0], []).append(r[1])
        corpus = intel.get_corpus(con)
        items = []
        for r in chunk:
            d = det.get(r[0])
            if not d:
                continue
            cl = corpus.cluster_of.get(r[0])
            ex = (d["summary"] or "").strip()
            items.append({"id": d["id"], "title": d["title"], "source": d["source_name"], "source_id": d["source_id"], "published": d["published"], "excerpt": (ex[:300] + "…") if len(ex) > 300 else ex or None,
                          "cves": cv.get(d["id"], []), "url": safe_url(d["url"]), "priority": r[3] if cl else None,
                          "event": {"id": r[4], "title": cl["title"], "articles": cl["article_count"], "publishers": len(cl["source_ids"])} if cl else None})
    else:
        items = []
    srcs = [{"id": i, "name": n} for n, i in sorted({(r[2], r[5]) for r in st["_matches"].get(kid, [])}, key=lambda x: x[0].lower())]
    k_stats = next((k for k in st["keywords"] if k["id"] == kid), {})
    return {"keyword": {"id": kid, "display_name": kw["display_name"]}, "window": st["window"], "items": items, "total": total, "page": page, "page_size": page_size, "pages": max(1, -(-total // page_size)),
            "summary": {x: k_stats.get(x) for x in ("article_count", "unique_events", "source_count", "latest_publication")}, "sources": srcs, "coverage": {x: st["coverage"][x] for x in ("status", "label", "warnings")}}
