import sqlite3
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlparse

import pytest
from fastapi import HTTPException

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app import db  # noqa: E402
from app.config import settings  # noqa: E402
from app.news import api as news_api, collector, intel, repo  # noqa: E402
from app.news.safefetch import FetchError, FetchResult, parse_retry_after, validate_url  # noqa: E402
from app.news.sources import BUILTIN, BY_ID, REJECTED, SOURCE_TYPES, SOURCES, host_in, is_verified_official  # noqa: E402

ORIGINAL_26 = ["bleepingcomputer", "thehackernews", "securityweek", "krebs", "helpnetsecurity", "theregister", "darkreading", "scmedia", "infosecurity", "csoonline",
               "sans-isc", "talos", "unit42", "crowdstrike", "microsoft-security", "project-zero", "dfir-report", "checkpoint", "securelist", "eset", "malwarebytes",
               "aws-security", "cloudflare", "rapid7", "tenable", "zdi"]
NOW = datetime.now(timezone.utc)


# ---------------------------------------------------------------- configuration integrity
def test_catalogue_has_no_duplicates_and_keeps_the_original_26():
    assert len(BUILTIN) == 65 and len({s.id for s in BUILTIN}) == 65          # the 65 original sources are untouched
    assert set(ORIGINAL_26) <= set(BY_ID)
    norm = lambda u: (urlparse(u).hostname.replace("www.", ""), urlparse(u).path.rstrip("/"), urlparse(u).query)  # noqa: E731
    assert len({norm(s.url) for s in SOURCES}) == len(SOURCES), "two sources point at the same feed (built-in + catalogue)"
    assert len({s.name.lower() for s in BUILTIN}) == len(BUILTIN) and len({s.id for s in SOURCES}) == len(SOURCES)
    assert all(urlparse(s.url).scheme == "https" for s in BUILTIN)


def test_types_notes_and_rejections_are_documented():
    assert {s.type for s in SOURCES} <= set(SOURCE_TYPES)
    BUILTIN_ = BUILTIN
    assert set(SOURCE_TYPES.values()) >= {"Cybersecurity News", "Threat Intelligence", "Malware Research", "Vulnerability Research", "Official Security Advisories", "Cloud Security", "DFIR"}
    off = [s for s in BUILTIN if not s.enabled]
    assert len(off) == 8 and all(s.note and len(s.note) > 20 for s in off)  # every inactive source documents why
    assert "mandiant" not in BY_ID and "mandiant" in REJECTED and "gcloud-threatintel" in BY_ID  # equivalent feed is not configured twice
    assert sum(1 for s in BUILTIN if s.type == "official") == 15


def test_official_status_requires_verified_domain_and_provenance():
    for s in SOURCES:
        if s.type == "official":
            assert s.official_domains and is_verified_official(s), s.id  # feed host is on the vendor/agency domain
        else:
            assert not s.official_domains and not is_verified_official(s)
    ubuntu = BY_ID["ubuntu-usn"]
    assert is_verified_official(ubuntu, "https://ubuntu.com/security/notices/USN-1") and not is_verified_official(ubuntu, "https://evil.example/usn")
    assert not is_verified_official(BY_ID["krebs"], "https://krebsonsecurity.com/x")  # a news outlet is never an advisory
    assert host_in("kb.cert.org", ("cert.org",)) and not host_in("notcert.org", ("cert.org",))


def test_redirect_hosts_are_allow_listed_per_source():
    assert "feeds.feedburner.com" in BY_ID["chrome-releases"].hosts and "www.intel471.com" in BY_ID["intel471"].hosts
    resolver = lambda *a, **k: [(0, 0, 0, "", ("93.184.216.34", 0))]  # noqa: E731
    validate_url("https://www.intel471.com/blog/feed", BY_ID["intel471"].hosts, resolver)
    with pytest.raises(FetchError):
        validate_url("https://evil.example/feed", BY_ID["intel471"].hosts, resolver)
    with pytest.raises(FetchError):
        validate_url("https://www.intel471.com/feed", BY_ID["krebs"].hosts, resolver)  # allow-list is per source


# ---------------------------------------------------------------- parsing
RSS = b"""<?xml version="1.0"?><rss version="2.0"><channel><title>t</title><language>en-US</language>
<item><title>Newer post about CVE-2026-1111</title><link>https://a.example/2</link><guid>g2</guid><pubDate>Tue, 17 Nov 2026 10:00:00 GMT</pubDate><description>&lt;b&gt;x&lt;/b&gt;</description></item>
<item><title>Older post</title><link>https://a.example/1</link><guid>g1</guid><pubDate>Mon, 16 Nov 2026 10:00:00 GMT</pubDate></item>
<item><title>Bad date post</title><link>https://a.example/3</link><guid>g3</guid><pubDate>not a date</pubDate></item></channel></rss>"""
ATOM = b"""<?xml version="1.0"?><feed xmlns="http://www.w3.org/2005/Atom"><title>t</title><updated>2026-11-17T10:00:00Z</updated>
<entry><title>Atom entry</title><id>tag:x,1</id><link href="https://b.example/1"/><updated>2026-11-17T09:00:00Z</updated><summary>Body</summary></entry></feed>"""


def test_parse_rss_sorted_newest_first_with_invalid_date_handled():
    items, meta = collector.parse_feed_ex(RSS)
    assert [i["title"] for i in items][:2] == ["Newer post about CVE-2026-1111", "Older post"]
    bad = next(i for i in items if i["title"] == "Bad date post")
    assert bad["published"] is None and meta["undated"] == 1 and meta["entries"] == 3 and meta["newest"].startswith("2026-11-17T10:00")
    assert items[0]["summary"] == "x" and meta["language"] == "en"


def test_parse_atom_empty_and_invalid():
    items, meta = collector.parse_feed_ex(ATOM)
    assert items[0]["url"] == "https://b.example/1" and items[0]["published"].startswith("2026-11-17T09:00") and meta["undated"] == 0
    empty, emeta = collector.parse_feed_ex(b'<?xml version="1.0"?><rss version="2.0"><channel><title>empty</title></channel></rss>')
    assert empty == [] and emeta["entries"] == 0 and emeta["newest"] is None  # valid feed without posts is not an error
    for junk in (b"<html><body>Forbidden</body></html>", b"", b"\x1b\xc3\xb0\x8cHM\xea\x01"):
        with pytest.raises(ValueError):
            collector.parse_feed_ex(junk)


def test_huge_feed_keeps_the_newest_entries_only():
    body = "".join(f"<item><title>Post {i}</title><link>https://h.example/{i}</link><pubDate>{(NOW - timedelta(hours=i)).strftime('%a, %d %b %Y %H:%M:%S GMT')}</pubDate></item>" for i in range(400))
    items, meta = collector.parse_feed_ex(f'<?xml version="1.0"?><rss version="2.0"><channel><title>t</title>{body}</channel></rss>'.encode())
    assert len(items) == collector.MAX_ENTRIES and meta["entries"] == 400 and items[0]["title"] == "Post 0" and items[-1]["title"] == "Post 299"


def test_language_detection_is_conservative():
    assert collector.detect_language("de-DE", []) == "de" and collector.detect_language(None, ["How the new attack hits the network and what to do about it in the cloud"]) == "en"
    assert collector.detect_language(None, ["USN-1", "USN-2"]) == "unknown"


def test_retry_after_and_backoff():
    assert parse_retry_after("120") == 120 and parse_retry_after("999999") == 86400 and parse_retry_after("junk") is None and parse_retry_after(None) is None
    t0 = datetime(2026, 11, 17, 12, tzinfo=timezone.utc)
    mins = [(datetime.fromisoformat(collector.backoff_until(n, None, t0)) - t0).total_seconds() / 60 for n in (1, 2, 3, 4, 5, 9)]
    assert mins == [30, 60, 120, 240, 360, 360]  # exponential, capped at 6 h
    assert (datetime.fromisoformat(collector.backoff_until(1, 7200, t0)) - t0).total_seconds() == 7200  # provider's Retry-After wins


# ---------------------------------------------------------------- persistence, scheduling, health
@pytest.fixture()
def tdb(tmp_path):
    object.__setattr__(settings, "db_path", str(tmp_path / "s.sqlite"))
    intel.reset_cache()
    db.init_db()
    with db.connect() as c:
        repo.sync_source_rows(c)
    yield
    object.__setattr__(settings, "db_path", str(tmp_path / "unused.sqlite"))


def _fake_fetch(monkeypatch, behaviour):
    calls = []

    def fake(src, etag=None, lm=None):
        calls.append(src.id)
        r = behaviour(src)
        if isinstance(r, Exception):
            raise r
        return r
    monkeypatch.setattr(collector, "fetch_feed", fake)
    return calls


def test_sync_skips_disabled_isolates_errors_and_records_backoff(tdb, monkeypatch):
    mini = tuple(BY_ID[i] for i in ("krebs", "securityweek", "scmedia", "anyrun"))
    calls = _fake_fetch(monkeypatch, lambda s: FetchError("HTTP 429", 429, 3600) if s.id == "securityweek" else FetchResult(200, RSS, "etag1", None, s.url, 1))
    out = collector.run_news_sync(True, mini)
    assert "scmedia" not in calls and out["skipped"]["disabled"] == 1 and out["ok"] == 2 and out["failed"] == 1
    with db.connect() as c:
        rows = {r["id"]: r for r in c.execute("SELECT * FROM news_source")}
        assert rows["krebs"]["status"] == "ok" and rows["krebs"]["last_http"] == 200 and rows["krebs"]["redirects"] == 1 and rows["krebs"]["language"] == "en" and rows["krebs"]["undated"] == 1
        assert rows["securityweek"]["status"] == "error" and rows["securityweek"]["last_http"] == 429 and rows["securityweek"]["consecutive_failures"] == 1
        wait = (datetime.fromisoformat(rows["securityweek"]["backoff_until"]) - datetime.now(timezone.utc)).total_seconds()
        assert 3500 < wait < 3700  # Retry-After (1 h) beats the 30 min base
        assert rows["scmedia"]["status"] == "pending"  # never touched
    calls.clear()
    collector.run_news_sync(False, mini)  # normal (non-forced) run respects the backoff
    assert "securityweek" not in calls and {"krebs", "anyrun"} <= set(calls)


def test_incremental_sync_does_not_duplicate_and_only_due_skips_recent(tdb, monkeypatch):
    mini = (BY_ID["krebs"], BY_ID["anyrun"])
    calls = _fake_fetch(monkeypatch, lambda s: FetchResult(200, RSS, None, None, s.url))
    first = collector.run_news_sync(True, mini)
    assert first["new"] >= 3
    calls.clear()
    second = collector.run_news_sync(True, mini)
    assert second["new"] == 0 and second["duplicate"] >= 3
    with db.connect() as c:
        assert c.execute("SELECT COUNT(*) - COUNT(DISTINCT url_canon) FROM news_item").fetchone()[0] == 0
    calls.clear()
    due = collector.run_news_sync(False, mini, only_due=True)  # scheduler / restart: fetched moments ago -> nothing to do
    assert calls == [] and due["skipped"]["not_due"] == 2


def test_304_keeps_source_healthy(tdb, monkeypatch):
    _fake_fetch(monkeypatch, lambda s: FetchResult(304, None, "e", None, s.url))
    out = collector.run_news_sync(False, (BY_ID["krebs"],))
    assert out["ok"] == 1 and out["new"] == 0
    with db.connect() as c:
        assert c.execute("SELECT status FROM news_source WHERE id='krebs'").fetchone()[0] == "ok"


def test_health_distinguishes_failed_quiet_disabled_and_healthy(tdb):
    with db.connect() as c:
        ts = NOW.isoformat(timespec="seconds")
        old = (NOW - timedelta(days=3)).isoformat(timespec="seconds")
        c.execute("UPDATE news_source SET status='ok', last_success=? WHERE enabled=1", (ts,))
        c.execute("UPDATE news_source SET status='error', error='HTTP 500' WHERE id='darkreading'")
        c.execute("UPDATE news_source SET enabled=0 WHERE id='eset'")
        for sid, when in (("krebs", ts), ("securelist", old)):
            c.execute("INSERT INTO news_item(id,source_id,guid,url,url_canon,title,summary,published,collected_at,content_hash,sort_ts) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                      (sid * 2, sid, "g", f"https://x/{sid}", f"https://x/{sid}", "t", "", when, when, "h", when))
        by = {s["id"]: s for s in repo.list_sources(c)}
        st = repo.stats(c)
    assert by["krebs"]["health"] == "healthy" and by["securelist"]["health"] == "quiet"
    assert by["darkreading"]["health"] == "failed" and by["eset"]["health"] == "disabled" and by["scmedia"]["health"] == "disabled"
    assert st["sources_failed"] == 1 and st["sources_configured"] == len(SOURCES) and st["sources_enabled"] == 56 and st["sources_disabled"] == len(SOURCES) - 56
    assert st["sources_active"] == 56 - 1 and st["sources_quiet"] == st["sources_active"] - 1  # only krebs published today; quiet != failed


def test_user_toggle_survives_restart_and_keeps_articles(tdb):
    with db.connect() as c:
        c.execute("INSERT INTO news_item(id,source_id,guid,url,url_canon,title,summary,published,collected_at,content_hash,sort_ts) VALUES('x1','krebs','g','https://x/1','https://x/1','t','','2026-11-01','2026-11-01','h','2026-11-01')")
        assert repo.set_source_enabled(c, "krebs", False) and repo.set_source_enabled(c, "scmedia", True)
        repo.sync_source_rows(c)  # what happens on every restart/sync
        en = {r["id"]: r["enabled"] for r in c.execute("SELECT id,enabled FROM news_source")}
        assert en["krebs"] == 0 and en["scmedia"] == 1  # the user's choice wins over the code default
        assert c.execute("SELECT COUNT(*) FROM news_item").fetchone()[0] == 1
        assert not repo.set_source_enabled(c, "nope", True)


def test_orphan_sources_without_articles_are_pruned_but_those_with_articles_kept(tdb):
    with db.connect() as c:
        c.execute("INSERT INTO news_source(id,name,type,url) VALUES('gone1','Gone','news','https://x')")
        c.execute("INSERT INTO news_source(id,name,type,url) VALUES('gone2','Gone2','news','https://y')")
        c.execute("INSERT INTO news_item(id,source_id,guid,url,url_canon,title,summary,published,collected_at,content_hash,sort_ts) VALUES('i','gone2','g','https://y/1','https://y/1','t','','2026-11-01','2026-11-01','h','2026-11-01')")
        repo.sync_source_rows(c)
        ids = {r[0] for r in c.execute("SELECT id FROM news_source")}
    assert "gone1" not in ids and "gone2" in ids


def test_migration_is_additive_and_preserves_existing_data(tmp_path):
    object.__setattr__(settings, "db_path", str(tmp_path / "old.sqlite"))
    raw = sqlite3.connect(settings.db_path)
    raw.executescript("""CREATE TABLE news_source(id TEXT PRIMARY KEY, name TEXT, type TEXT, url TEXT, status TEXT DEFAULT 'pending', last_attempt TEXT, last_success TEXT,
        error TEXT, consecutive_failures INTEGER DEFAULT 0, last_items INTEGER DEFAULT 0, etag TEXT, last_modified TEXT);
        INSERT INTO news_source(id,name,type,url,status) VALUES('krebs','Krebs','news','https://krebsonsecurity.com/feed/','ok'),('scmedia','SC','news','https://x','error');""")
    raw.commit(); raw.close()
    db.init_db()
    with db.connect() as c:
        cols = {r[1] for r in c.execute("PRAGMA table_info(news_source)")}
        assert {"enabled", "note", "language", "last_http", "backoff_until", "final_url", "undated", "newest_item"} <= cols
        en = {r["id"]: r["enabled"] for r in c.execute("SELECT id,enabled FROM news_source")}
        assert en == {"krebs": 1, "scmedia": 0} and c.execute("SELECT status FROM news_source WHERE id='krebs'").fetchone()[0] == "ok"
        c.execute("UPDATE news_source SET enabled=1 WHERE id='scmedia'")
    db.init_db()  # second run must not reapply defaults over the user's choice
    with db.connect() as c:
        assert c.execute("SELECT enabled FROM news_source WHERE id='scmedia'").fetchone()[0] == 1


# ---------------------------------------------------------------- API + listing
class _Req:
    class client:  # noqa: N801
        host = "127.0.0.1"


def test_patch_source_api(tdb):
    out = news_api.patch_source("scmedia", news_api.SourcePatch(enabled=True), _Req(), None)
    assert out["enabled"] is True and out["id"] == "scmedia"
    assert news_api.patch_source("scmedia", news_api.SourcePatch(enabled=False), _Req(), None)["health"] == "disabled"
    with pytest.raises(HTTPException) as e:
        news_api.patch_source("nope", news_api.SourcePatch(enabled=True), _Req(), None)
    assert e.value.status_code == 404

    class Remote:
        class client:  # noqa: N801
            host = "10.0.0.5"
    with pytest.raises(HTTPException) as e:
        news_api.patch_source("krebs", news_api.SourcePatch(enabled=False), Remote(), None)
    assert e.value.status_code == 403


def test_filter_by_source_type_and_pagination(tdb):
    with db.connect() as c:
        for i in range(45):
            sid = "msrc" if i % 3 == 0 else "krebs"
            ts = (NOW - timedelta(minutes=i)).isoformat(timespec="seconds")
            c.execute("INSERT INTO news_item(id,source_id,guid,url,url_canon,title,summary,published,collected_at,content_hash,sort_ts) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                      (f"{i:024d}", sid, f"g{i}", f"https://x/{i}", f"https://x/{i}", f"Title {i}", "", ts, ts, "h", ts))
        all_off = repo.search_news(c, source_type="official", page_size=10)
        assert all_off["total"] == 15 and all_off["pages"] == 2 and all(x["source"]["type_label"] == "Official Security Advisories" for x in all_off["items"])
        p2 = repo.search_news(c, source_type="official", page=2, page_size=10)
        assert not {x["id"] for x in all_off["items"]} & {x["id"] for x in p2["items"]}
        assert repo.search_news(c, source_type="news")["total"] == 30


def test_undated_items_never_count_as_recent_in_analytics(tdb):
    now = datetime.now(timezone.utc)
    mk = lambda i, pub: {"id": f"{i:024d}", "title": f"Distinct headline number {i} alpha{i} beta{i}", "summary": "", "url": f"https://x/{i}", "source_id": "krebs", "source_name": "Krebs",  # noqa: E731
                         "source_type": "news", "published": pub, "collected_at": now.isoformat(), "updated_at": None, "ts": now, "undated": pub is None, "categories": ["Malware"],
                         "techs": [], "cves": [], "entities": {"vendors": [], "products": [], "malware": [], "ransomware": [], "mitre": [], "incident_ids": []},
                         "tokens": intel.tokens(f"Distinct headline number {i} alpha{i} beta{i}"), "topics": ["Malware"], "official": False}
    items = [mk(1, now.isoformat()), mk(2, None)]
    corpus = intel.Corpus(items, intel.build_clusters(items), {}, now)
    dated = [c for c in corpus.clusters if c["last_dated"]]
    assert len(dated) == 1 and corpus.prio[next(c["id"] for c in corpus.clusters if not c["last_dated"])]["components"][0]["points"] == 0
    assert intel.trending(corpus, "24h")["total_articles"] == 1
    assert intel.list_clusters(corpus, period="24h")["total"] == 1 and intel.list_clusters(corpus, period="all")["total"] == 2
