"""Source expansion: validation, registry, duplicates, administration, scalable sync, onboarding, integrity. No test touches the network (probe/fetch are mocked)."""
import json
import sys
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlparse

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app import db, intel_dash as idash  # noqa: E402
from app.config import settings  # noqa: E402
from app.main import app  # noqa: E402
from app.news import collector, intel, repo, source_admin as sa, source_onboarding as ob, source_validation as sv  # noqa: E402
from app.news.safefetch import FetchError, FetchResult  # noqa: E402
from app.news.sources import BUILTIN, BY_ID, CATEGORIES, SOURCES, register, unregister  # noqa: E402

NOW = datetime.now(timezone.utc)
RFC = lambda d: d.strftime("%a, %d %b %Y %H:%M:%S +0000")  # noqa: E731
CATALOG = json.loads((Path(__file__).resolve().parent.parent / "app" / "news" / "sources_catalog.json").read_text(encoding="utf-8"))


def rss(n=5, title="Critical vulnerability exploited in the wild", hours=2, base="https://news.example.test/a", dated=True, cve=1000):
    items = "".join(f"<item><title>{title} {i}</title><link>{base}{i}</link><guid>g{i}</guid>" + (f"<pubDate>{RFC(NOW - timedelta(hours=hours + i))}</pubDate>" if dated else "") +
                    f"<description>Ransomware and malware advisory CVE-2026-{cve + i} security</description></item>" for i in range(n))
    return f'<?xml version="1.0"?><rss version="2.0"><channel><title>Sec Feed</title><language>en</language>{items}</channel></rss>'.encode()


def atom(n=3):
    ents = "".join(f'<entry><title>Security patch {i} for exploit</title><link href="https://news.example.test/at{i}"/><id>urn:{i}</id><updated>{(NOW - timedelta(hours=i + 1)).strftime("%Y-%m-%dT%H:%M:%SZ")}</updated><summary>vulnerability</summary></entry>' for i in range(n))
    return f'<?xml version="1.0"?><feed xmlns="http://www.w3.org/2005/Atom"><title>Atom Sec</title>{ents}</feed>'.encode()


def fake_probe(table):
    """table: url -> dict(status/http/content/note/hosts)"""
    def probe(url, **k):
        r = table.get(url) or {"status": "invalid", "http": 404, "note": "HTTP 404", "content": None}
        return {"status": r.get("status", "ok"), "http": r.get("http", 200), "final_url": r.get("final_url", url), "hosts": r.get("hosts", [urlparse(url).hostname]), "content": r.get("content"),
                "note": r.get("note"), "redirects": r.get("redirects", 0), "etag": r.get("etag"), "last_modified": r.get("last_modified")}
    return probe


@pytest.fixture()
def env(tmp_path, monkeypatch):
    object.__setattr__(settings, "db_path", str(tmp_path / "s.sqlite"))
    intel.reset_cache()
    idash.invalidate()
    db.init_db()
    with db.connect() as c:
        repo.sync_source_rows(c)
    yield
    for s in [s for s in SOURCES if s.origin == "manual"]:
        unregister(s.id)
    intel.reset_cache()
    object.__setattr__(settings, "db_path", str(tmp_path / "unused.sqlite"))


@pytest.fixture()
def api(env):
    return TestClient(app, client=("127.0.0.1", 11))


# ---------------------------------------------------------------- catalogue & registry (integrity, duplicates)
def test_catalogue_adds_250_verified_sources_disabled_and_keeps_the_65(env):
    assert len(BUILTIN) == 65 and len(CATALOG) == 250 and len(SOURCES) == 315
    with db.connect() as c:
        assert c.execute("SELECT COUNT(*) FROM news_source WHERE origin='builtin'").fetchone()[0] == 65
        cat = c.execute("SELECT COUNT(*),SUM(enabled),SUM(validation_status='verified') FROM news_source WHERE origin='catalog'").fetchone()
        assert tuple(cat) == (250, 0, 250)                      # registered disabled; every one carries a verified validation record
        assert c.execute("SELECT COUNT(*) FROM news_source WHERE origin='builtin' AND enabled=1").fetchone()[0] == 57 or c.execute("SELECT COUNT(*) FROM news_source WHERE origin='builtin' AND enabled=1").fetchone()[0] == 56
    assert {e["batch"] for e in CATALOG} == {1, 2, 3, 4, 5, 6} and [sum(1 for e in CATALOG if e["batch"] == b) for b in range(1, 7)] == [25, 25, 50, 50, 50, 50]


def test_catalogue_has_no_duplicate_ids_urls_or_collisions_with_existing_sources():
    ids = [e["id"] for e in CATALOG]
    assert len(set(ids)) == 250 and not set(ids) & {s.id for s in BUILTIN}
    norm = [sv.normalize_feed_url(e["url"]) for e in CATALOG]
    assert len(set(norm)) == 250 and not set(norm) & {sv.normalize_feed_url(s.url) for s in BUILTIN}
    assert all(urlparse(e["url"]).scheme in ("http", "https") for e in CATALOG) and all(e["validation"]["status"] == "verified" and e["validation"]["entries"] >= 1 for e in CATALOG)
    assert all(e["category"] in CATEGORIES for e in CATALOG)


def test_official_status_in_the_catalogue_needs_the_feed_to_sit_on_the_publishers_domain():
    from app.news.sources import is_verified_official
    for s in SOURCES:
        if s.origin == "catalog" and s.type == "official":
            assert s.official_domains and is_verified_official(s), s.id
            assert not any(d in ("github.com", "medium.com", "feedburner.com", "blogspot.com") for d in s.official_domains), s.id
        if s.origin == "catalog" and s.type != "official":
            assert not s.official_domains
    assert not any(e["type"] == "official" and urlparse(e["url"]).hostname.endswith("github.com") for e in CATALOG)


def test_unknown_country_and_language_stay_unknown():
    assert any(e["country"] is None for e in CATALOG) and any(e["language"] is None for e in CATALOG)
    assert all(e["country"] is None or (len(e["country"]) == 2 and e["country"].isupper()) for e in CATALOG)


def test_source_url_normalisation_detects_equivalent_feeds():
    n = sv.normalize_feed_url
    assert n("https://www.Example.com/feed/?utm_source=x") == n("http://example.com/feed") == n("https://example.com/Feed/")
    assert n("https://example.com/feed?cat=1") != n("https://example.com/feed?cat=2") and n("https://example.com/news.xml") != n("https://example.com/vulns.xml")


# ---------------------------------------------------------------- validation: RSS, Atom, errors, relevance (mocked network)
def test_valid_rss_and_atom_are_verified(monkeypatch):
    monkeypatch.setattr(sv, "probe", fake_probe({"https://a.test/rss": {"content": rss(), "etag": "W/1"}, "https://a.test/atom": {"content": atom()}}))
    r = sv.assess("https://a.test/rss")
    assert r["status"] == "verified" and r["entries"] == 5 and r["language"] == "en" and r["title"] == "Sec Feed" and r["relevance"] >= 0.9 and r["etag"] == "W/1"
    a = sv.assess("https://a.test/atom")
    assert a["status"] == "verified" and a["entries"] == 3 and a["title"] == "Atom Sec"


@pytest.mark.parametrize("name,entry,status", [
    ("403", {"status": "unsupported", "http": 403, "note": "HTTP 403", "content": None}, "unsupported"),
    ("404", {"status": "invalid", "http": 404, "note": "HTTP 404", "content": None}, "invalid"),
    ("429", {"status": "temporarily_unavailable", "http": 429, "note": "HTTP 429", "content": None}, "temporarily_unavailable"),
    ("timeout", {"status": "temporarily_unavailable", "http": None, "note": "ReadTimeout", "content": None}, "temporarily_unavailable"),
    ("html", {"content": b"<!doctype html><html><body>Hello</body></html>"}, "invalid"),
    ("empty", {"content": b'<?xml version="1.0"?><rss version="2.0"><channel><title>x</title></channel></rss>'}, "invalid"),
    ("challenge", {"content": b"<html><title>Just a moment...</title>captcha</html>"}, "unsupported"),
    ("offtopic", {"content": rss(title="Weekend recipes and gardening tips").replace(b"Ransomware and malware advisory", b"Lovely roses").replace(b"security", b"garden").replace(b"CVE-2026-", b"rose-")}, "invalid"),
    ("stale", {"content": rss(hours=24 * 900)}, "invalid"),
])
def test_validation_never_trusts_http_200(monkeypatch, name, entry, status):
    monkeypatch.setattr(sv, "probe", fake_probe({"https://b.test/f": entry}))
    assert sv.assess("https://b.test/f")["status"] == status


def test_feed_without_dates_is_valid_but_reported_undated(monkeypatch):
    monkeypatch.setattr(sv, "probe", fake_probe({"https://c.test/f": {"content": rss(dated=False)}}))
    r = sv.assess("https://c.test/f")
    assert r["status"] == "verified" and r["newest"] is None


def test_ssrf_blocks_private_loopback_linklocal_and_metadata_destinations():
    from app.news.safefetch import validate_url
    pub = lambda *a, **k: [(0, 0, 0, "", ("93.184.216.34", 0))]  # noqa: E731
    for ip in ("127.0.0.1", "10.0.0.5", "192.168.1.1", "172.16.0.9", "169.254.169.254", "::1", "fe80::1", "0.0.0.0", "::ffff:127.0.0.1"):
        with pytest.raises(FetchError):
            validate_url("https://x.test/feed", frozenset({"x.test"}), lambda *a, ip=ip, **k: [(0, 0, 0, "", (ip, 0))])
    for url in ("file:///etc/passwd", "ftp://x.test/feed", "gopher://x.test", "javascript:alert(1)"):
        with pytest.raises(FetchError):
            validate_url(url, frozenset({"x.test"}), pub)
    validate_url("https://x.test/feed", frozenset({"x.test"}), pub)


def test_probe_blocks_internal_hosts_and_validates_every_redirect_hop(monkeypatch):
    monkeypatch.setattr("app.news.source_validation.validate_url", lambda url, hosts, *a, **k: (_ for _ in ()).throw(FetchError("blocked non-public address")) if "internal" in url else None)
    assert sv.probe("https://internal.local/feed")["note"].startswith("blocked")


def test_peer_address_check_blocks_dns_rebinding():
    from app.news.safefetch import peer_ok

    class R:
        def __init__(self, ip): self.extensions = {"network_stream": type("S", (), {"get_extra_info": lambda s, k, ip=ip: (ip, 443)})()}
    assert peer_ok(R("93.184.216.34")) and not peer_ok(R("127.0.0.1")) and not peer_ok(R("169.254.169.254")) and not peer_ok(R("10.1.2.3"))


# ---------------------------------------------------------------- administration API
def test_add_manual_source_validates_first_and_enables_only_verified(api, monkeypatch):
    monkeypatch.setattr(sv, "probe", fake_probe({"https://ok.test/feed.xml": {"content": rss()}, "https://bad.test/feed.xml": {"status": "invalid", "http": 404, "note": "HTTP 404", "content": None}}))
    r = api.post("/api/v1/news/source-admin", json={"name": "My Feed", "url": "https://ok.test/feed.xml", "category": "news", "country": "AR"})
    assert r.status_code == 201 and r.json()["enabled"] and r.json()["validation"]["status"] == "verified" and r.json()["id"] in BY_ID
    bad = api.post("/api/v1/news/source-admin", json={"name": "Dead Feed", "url": "https://bad.test/feed.xml", "category": "news"}).json()
    assert bad["enabled"] is False and bad["validation"]["status"] == "invalid"
    ok = api.get("/api/v1/news/source-admin", params={"q": "my feed"}).json()["items"][0]
    assert ok["origin"] == "manual" and ok["country"] == "AR" and ok["validation_status"] == "verified" and ok["operational"] is False       # not synced yet: not operational
    assert api.post("/api/v1/news/source-admin", json={"name": "Dup", "url": "https://www.ok.test/feed.xml/?utm_source=z", "category": "news"}).status_code == 409
    for body in ({"name": "x", "url": "javascript:alert(1)", "category": "news"}, {"name": "x", "url": "ftp://a.test/f", "category": "news"}, {"name": "x", "url": "https://a.test/f", "category": "nope"},
                 {"name": "", "url": "https://a.test/f", "category": "news"}, {"name": "x", "url": "https://a.test/f", "category": "news", "country": "ZZZ"}):
        assert api.post("/api/v1/news/source-admin", json=body).status_code == 422, body
    assert api.post(f"/api/v1/news/source-admin/{bad['id']}/enabled", json={"enabled": True}).status_code == 409        # an invalid source cannot be switched on
    with db.connect() as c:
        assert c.execute("SELECT enabled FROM news_source WHERE id=?", (bad["id"],)).fetchone()[0] == 0


def test_edit_delete_and_protection_of_builtin_sources(api, monkeypatch):
    monkeypatch.setattr(sv, "probe", fake_probe({"https://m.test/f": {"content": rss()}}))
    sid = api.post("/api/v1/news/source-admin", json={"name": "Mine", "url": "https://m.test/f", "category": "news"}).json()["id"]
    assert api.patch(f"/api/v1/news/source-admin/{sid}", json={"name": "Mine Renamed", "category": "cert", "country": "FR"}).status_code == 200
    got = api.get("/api/v1/news/source-admin", params={"q": "renamed"}).json()["items"][0]
    assert got["name"] == "Mine Renamed" and got["type"] == "official" and got["country"] == "FR"
    assert api.patch("/api/v1/news/source-admin/krebs", json={"url": "https://evil.test/feed"}).status_code == 403                    # built-in identity is fixed
    assert api.patch("/api/v1/news/source-admin/krebs", json={"country": "US", "publisher": "Brian Krebs"}).status_code == 200
    assert api.delete("/api/v1/news/source-admin/krebs").status_code == 403
    assert api.delete(f"/api/v1/news/source-admin/{sid}").json()["deleted"] and sid not in BY_ID
    assert api.post("/api/v1/news/source-admin/nope/validate").status_code == 404
    remote = TestClient(app, client=("203.0.113.9", 1))
    assert remote.post("/api/v1/news/source-admin", json={"name": "x", "url": "https://a.test/f", "category": "news"}).status_code == 403
    assert remote.get("/api/v1/news/source-admin").status_code == 200


def test_listing_filters_search_sort_and_pagination(api):
    p = api.get("/api/v1/news/source-admin", params={"page_size": 25}).json()
    assert p["total"] == 315 and p["pages"] == 13 and len(p["items"]) == 25 and p["indicators"]["total"] == 315
    seen = [i["id"] for pg in range(1, 14) for i in api.get("/api/v1/news/source-admin", params={"page_size": 25, "page": pg}).json()["items"]]
    assert len(seen) == 315 == len(set(seen))                                                                    # pagination neither repeats nor drops
    assert api.get("/api/v1/news/source-admin", params={"category": "cert"}).json()["total"] == sum(1 for s in SOURCES if s.category == "cert")
    assert api.get("/api/v1/news/source-admin", params={"origin": "catalog"}).json()["total"] == 250
    assert api.get("/api/v1/news/source-admin", params={"batch": 1}).json()["total"] == 25
    assert api.get("/api/v1/news/source-admin", params={"country": "FR"}).json()["total"] == sum(1 for s in SOURCES if s.country == "FR")
    q = api.get("/api/v1/news/source-admin", params={"q": "krebs"}).json()
    assert q["total"] >= 1 and q["items"][0]["name"].lower().startswith("krebs")
    assert [i["name"].lower() for i in api.get("/api/v1/news/source-admin", params={"page_size": 100}).json()["items"]] == sorted(i["name"].lower() for i in api.get("/api/v1/news/source-admin", params={"page_size": 100}).json()["items"])
    assert api.get("/api/v1/news/source-admin", params={"status": "disabled"}).json()["total"] >= 250
    assert api.get("/api/v1/news/source-admin", params={"page_size": 500}).status_code == 422 and api.get("/api/v1/news/source-admin", params={"sort": "x"}).status_code == 422
    assert api.get("/api/v1/news/source-admin", params={"category": "nope"}).status_code == 422


def test_disabled_sources_are_never_failed_and_failed_validation_is_never_operational(api):
    with db.connect() as c:
        c.execute("UPDATE news_source SET status='error', error='HTTP 500', enabled=0 WHERE id='krebs'")
        c.execute("UPDATE news_source SET status='ok', validation_status='invalid', enabled=1 WHERE id='bleepingcomputer'")
    ind = api.get("/api/v1/news/source-admin").json()["indicators"]
    rows = {i["id"]: i for i in api.get("/api/v1/news/source-admin", params={"page_size": 100, "q": ""}).json()["items"]}
    krebs = api.get("/api/v1/news/source-admin", params={"q": "krebs"}).json()["items"][0]
    bleep = api.get("/api/v1/news/source-admin", params={"q": "bleepingcomputer"}).json()["items"][0]
    assert krebs["state"] == "disabled" and bleep["operational"] is False and bleep["state"] == "failed"
    assert ind["failed"] >= 1 and ind["enabled"] == sum(1 for s in api.get("/api/v1/news/sources").json()["sources"] if s["enabled"])


def test_bulk_actions_are_limited_and_report_skipped(api, monkeypatch):
    ids = [s.id for s in BUILTIN[:5]]
    r = api.post("/api/v1/news/source-admin/bulk", json={"ids": ids, "action": "disable"}).json()
    assert len(r["done"]) == 5 and not r["skipped"]
    assert api.post("/api/v1/news/source-admin/bulk", json={"ids": ids + ["ghost"], "action": "enable"}).json()["skipped"][0]["id"] == "ghost"
    assert api.post("/api/v1/news/source-admin/bulk", json={"ids": [s.id for s in SOURCES[:60]], "action": "enable"}).status_code == 422
    assert api.post("/api/v1/news/source-admin/bulk", json={"ids": [s.id for s in SOURCES[:20]], "action": "validate"}).status_code == 422
    assert api.post("/api/v1/news/source-admin/bulk", json={"ids": ids, "action": "delete"}).status_code == 422


def test_coverage_report_separates_quiet_from_failed(api):
    old = (NOW - timedelta(days=40)).isoformat(timespec="seconds")
    with db.connect() as c:
        c.execute("UPDATE news_source SET status='ok',last_success=?,last_attempt=?,enabled=1 WHERE id IN ('krebs','talos')", (NOW.isoformat(timespec="seconds"),) * 2)
        c.execute("UPDATE news_source SET status='error',error='HTTP 500',enabled=1 WHERE id='eset'")
        c.execute("INSERT INTO news_item(id,source_id,guid,url,url_canon,title,summary,published,collected_at,content_hash,sort_ts) VALUES('x1','krebs','g','https://k.test/1','https://k.test/1','Old','',?,?,'h',?)", (old, old, old))
    cov = api.get("/api/v1/news/source-admin/coverage").json()
    assert "eset" in {s["id"] for s in cov["failed"]} and "krebs" not in {s["id"] for s in cov["failed"]}
    assert "krebs" in {s["id"] for s in cov["no_recent_activity"]} and cov["by_category"] and cov["by_country"] and cov["by_language"] is not None
    assert "not a failure" in cov["note"]


# ---------------------------------------------------------------- scalable synchronisation
def mock_fetch(monkeypatch, table, log=None):
    def fetch(src, etag=None, lm=None):
        if log is not None:
            log.append(src.id)
        r = table.get(src.id)
        if isinstance(r, Exception):
            raise r
        if r is None:
            raise FetchError("HTTP 404", 404)
        if etag and etag == r.get("etag"):
            return FetchResult(304, None, etag, lm, src.url, 0)
        return FetchResult(200, r["content"], r.get("etag"), r.get("lm"), src.url, 0)
    monkeypatch.setattr(collector, "fetch_feed", fetch)


def enable(*ids):
    with db.connect() as c:
        for i in ids:
            c.execute("UPDATE news_source SET enabled=1 WHERE id=?", (i,))


def test_sync_isolates_failures_applies_backoff_with_jitter_and_respects_retry_after(env, monkeypatch):
    enable("krebs", "talos", "eset")
    only = ["krebs", "talos", "eset"]
    mock_fetch(monkeypatch, {"krebs": {"content": rss(base="https://k.test/")}, "talos": FetchError("HTTP 429", 429, retry_after=7200), "eset": FetchError("HTTP 403", 403)})
    s = collector.run_news_sync(force=True, only_ids=only)
    assert s["ok"] == 1 and s["failed"] == 2
    with db.connect() as c:
        rows = {r["id"]: dict(r) for r in c.execute("SELECT id,status,backoff_until,consecutive_failures,error FROM news_source WHERE id IN ('krebs','talos','eset')")}
    assert rows["krebs"]["status"] == "ok" and rows["talos"]["status"] == "error" and rows["eset"]["error"] == "HTTP 403"
    assert datetime.fromisoformat(rows["talos"]["backoff_until"]) - NOW > timedelta(minutes=110)                 # Retry-After honoured
    spread = {collector.backoff_until(1, now=NOW, jitter=0.15) for _ in range(30)}
    assert len(spread) > 1 and all(timedelta(minutes=25) < datetime.fromisoformat(x) - NOW < timedelta(minutes=35) for x in spread)
    assert collector.backoff_until(1, now=NOW) == collector.backoff_until(1, now=NOW)                            # default stays deterministic
    again = collector.run_news_sync(only_due=True, only_ids=only)
    assert again["skipped"]["backoff"] == 2                                                                      # failed sources wait for their backoff


def test_conditional_get_makes_unchanged_feeds_free(env, monkeypatch):
    enable("krebs")
    mock_fetch(monkeypatch, {"krebs": {"content": rss(base="https://k.test/"), "etag": "E1"}})
    assert collector.run_news_sync(force=False, only_ids=["krebs"])["new"] == 5
    s = collector.run_news_sync(force=False, only_ids=["krebs"])
    assert s["ok"] == 1 and s["new"] == 0 and s["outcomes"][0]["http"] == 304


def test_first_sync_stores_only_the_newest_entries_not_the_whole_history(env, monkeypatch):
    enable("krebs")
    mock_fetch(monkeypatch, {"krebs": {"content": rss(n=120, base="https://k.test/")}})
    s = collector.run_news_sync(force=True, only_ids=["krebs"], initial_entries=30)
    assert s["new"] == 30
    with db.connect() as c:
        assert c.execute("SELECT COUNT(*) FROM news_item WHERE source_id='krebs'").fetchone()[0] == 30
    assert collector.run_news_sync(force=True, only_ids=["krebs"])["new"] == 90                                  # once it has articles, normal rules apply


def test_per_cycle_cap_defers_remaining_feeds_to_the_next_cycle(env, monkeypatch):
    enable("krebs", "talos", "eset")
    mock_fetch(monkeypatch, {i: {"content": rss(n=10, base=f"https://{i}.test/")} for i in ("krebs", "talos", "eset")})
    s = collector.run_news_sync(force=True, only_ids=["krebs", "talos", "eset"], max_items=10)
    assert s["deferred"] == 2 and s["ok"] == 1                                                                # the cap is soft: one feed fills it, the rest wait
    nxt = collector.run_news_sync(force=True, only_ids=["krebs", "talos", "eset"], max_items=1000)
    assert nxt["new"] > 0


def test_only_one_cycle_runs_and_concurrency_is_bounded(env, monkeypatch):
    ids = [s.id for s in BUILTIN[:12]]
    enable(*ids)
    live, peak, lock = [0], [0], threading.Lock()

    def slow(src, etag=None, lm=None):
        with lock:
            live[0] += 1
            peak[0] = max(peak[0], live[0])
        time.sleep(0.15)
        with lock:
            live[0] -= 1
        return FetchResult(200, rss(base=f"https://{src.id}.test/"), None, None, src.url, 0)
    monkeypatch.setattr(collector, "fetch_feed", slow)
    object.__setattr__(settings, "news_workers", 3)
    results = []
    ts = [threading.Thread(target=lambda: results.append(collector.run_news_sync(force=True, only_ids=ids))) for _ in range(3)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    object.__setattr__(settings, "news_workers", 8)
    assert sum(1 for r in results if r is not None) >= 1 and results.count(None) >= 1                           # overlapping cycles are refused, not queued
    assert peak[0] <= 3


def test_slow_download_hits_the_wall_clock_deadline(monkeypatch):
    import httpx
    from app.news import safefetch

    class R:
        status_code, headers, extensions = 200, {}, {}
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def iter_bytes(self):
            for _ in range(50):
                time.sleep(0.05)
                yield b"x"

    class C:
        def __init__(self, *a, **k): pass
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def stream(self, *a, **k): return R()
    monkeypatch.setattr(httpx, "Client", C)
    monkeypatch.setattr(safefetch, "validate_url", lambda *a, **k: None)
    object.__setattr__(settings, "news_source_deadline", 0.2)
    try:
        with pytest.raises(FetchError, match="timeout"):
            safefetch._once(BUILTIN[0], None, None)
    finally:
        object.__setattr__(settings, "news_source_deadline", 45.0)


# ---------------------------------------------------------------- article-level behaviour with many sources
def test_article_deduplication_across_sources_and_clustering_still_work(env, monkeypatch):
    enable("krebs", "talos")
    same = rss(n=3, title="LockBit hits hospital CVE-2026-9001", base="https://shared.test/a", cve=4000)
    mock_fetch(monkeypatch, {"krebs": {"content": same}, "talos": {"content": same}})
    s = collector.run_news_sync(force=True, only_ids=["krebs", "talos"])
    assert s["new"] == 3 and s["duplicate"] >= 3                                                                 # same URL = same article, not two
    with db.connect() as c:
        assert c.execute("SELECT COUNT(*) FROM news_item").fetchone()[0] == 3
    # distinct URLs for the same story: two articles, one event
    enable("eset", "sans-isc")
    mock_fetch(monkeypatch, {"eset": {"content": rss(n=1, title="Qilin ransomware attacks hospital CVE-2026-9100", base="https://e.test/", cve=7000)}, "sans-isc": {"content": rss(n=1, title="Qilin ransomware attack on hospital CVE-2026-9100", base="https://s.test/", cve=7000)}})
    collector.run_news_sync(force=True, only_ids=["eset", "sans-isc"])
    intel.reset_cache()
    with db.connect() as c:
        corpus = intel.get_corpus(c)
    ev = [cl for cl in corpus.clusters if "CVE-2026-9100" in cl["cves"]]
    assert len(ev) == 1 and len(ev[0]["members"]) == 2


def test_cve_and_html_sanitisation_in_stored_articles(env, monkeypatch):
    enable("krebs")
    dirty = (b'<?xml version="1.0"?><rss version="2.0"><channel><title>t</title><item><title>&lt;script&gt;alert(1)&lt;/script&gt;Exploit for CVE-2026-4242</title>'
             b'<link>https://k.test/dirty</link><description>&lt;img src=x onerror=alert(1)&gt; patch now</description></item>'
             b'<item><title>Bad link item</title><link>javascript:alert(1)</link></item></channel></rss>')
    mock_fetch(monkeypatch, {"krebs": {"content": dirty}})
    collector.run_news_sync(force=True, only_ids=["krebs"])
    with db.connect() as c:
        rows = c.execute("SELECT title,summary,url FROM news_item WHERE source_id='krebs'").fetchall()
        cves = [r[0] for r in c.execute("SELECT cve_id FROM news_cve")]
    assert len(rows) == 1 and "<script" not in rows[0]["title"] and "<img" not in rows[0]["summary"] and rows[0]["url"] == "https://k.test/dirty" and "CVE-2026-4242" in cves


# ---------------------------------------------------------------- onboarding in batches
def make_batch(monkeypatch, fail=()):
    table = {}
    for e in CATALOG:
        table[e["url"]] = {"content": rss(n=4, base=f"https://{e['id']}.test/")} if e["id"] not in fail else {"status": "invalid", "http": 404, "note": "HTTP 404", "content": None}
    monkeypatch.setattr(sv, "probe", fake_probe(table))
    fetch_table = {e["id"]: ({"content": rss(n=4, base=f"https://{e['id']}.test/")} if e["id"] not in fail else FetchError("HTTP 500", 500)) for e in CATALOG}
    mock_fetch(monkeypatch, fetch_table)


def test_batch_one_validates_enables_syncs_and_records_the_result(api, monkeypatch):
    make_batch(monkeypatch)
    r = ob.run_batch(1)
    assert r["status"] == "completed" and r["sources"] == 25 and r["enabled"] == 25 and r["ok"] == 25 and r["failed"] == 0 and r["new_items"] == 100 and r["lock_errors"] == 0
    assert r["articles_after"] - r["articles_before"] == 100
    with db.connect() as c:
        assert c.execute("SELECT COUNT(*) FROM news_source WHERE origin='catalog' AND batch=1 AND enabled=1").fetchone()[0] == 25
        assert c.execute("SELECT COUNT(*) FROM news_source WHERE origin='catalog' AND batch=2 AND enabled=1").fetchone()[0] == 0     # other batches untouched
        assert c.execute("SELECT status FROM source_onboarding WHERE batch=1").fetchone()[0] == "completed"
    ov = api.get("/api/v1/news/source-admin/onboarding").json()
    assert ov["batches"][0]["enabled"] == 25 and ov["batches"][0]["last_run"]["status"] == "completed" and ov["plan"] == {"1": 25, "2": 25, "3": 50, "4": 50, "5": 50, "6": 50}


def test_generalised_failures_halt_the_next_batches(api, monkeypatch):
    fail = set(sorted(e["id"] for e in CATALOG if e["batch"] == 1)[:12])                   # 12 of 25 (48%) fail their first sync
    make_batch(monkeypatch, fail=fail)
    r = ob.run_batch(1)
    assert r["status"] == "halted" and r["enabled"] == 25 and r["ok"] == 13 and r["failed"] == 12 and "next batches are blocked" in r["note"]
    with pytest.raises(sa.AdminError) as e:
        ob.run_batch(2)                                                                    # the next batch is refused until the failing one is reviewed
    assert e.value.status == 409 and "Batch 1" in e.value.msg
    with db.connect() as c:
        assert c.execute("SELECT COUNT(*) FROM news_source WHERE origin='catalog' AND batch=2 AND enabled=1").fetchone()[0] == 0
        assert c.execute("SELECT status,failed FROM source_onboarding WHERE batch=1").fetchone()[:] == ("halted", 12)
    assert ob.run_batch(2, force=True)["batch"] == 2                                       # explicit override only


def test_invalid_batch_numbers_and_unverified_sources_are_never_enabled(api, monkeypatch):
    assert api.post("/api/v1/news/source-admin/onboarding/9").status_code == 422
    bad = next(e["id"] for e in CATALOG if e["batch"] == 1)
    make_batch(monkeypatch, fail={bad})
    with db.connect() as c:
        c.execute("UPDATE news_source SET validated_at=? WHERE id=?", ((NOW - timedelta(days=30)).isoformat(timespec="seconds"), bad))      # stale validation: it is checked again
    r = ob.run_batch(1)
    with db.connect() as c:
        assert tuple(c.execute("SELECT enabled,validation_status FROM news_source WHERE id=?", (bad,)).fetchone()) == (0, "invalid")
    assert r["enabled"] == 24 and r["status"] == "completed"


def test_interrupted_cycle_resumes_with_the_sources_it_did_not_reach(env, monkeypatch):
    ids = ["krebs", "talos", "eset", "sans-isc"]
    enable(*ids)
    with db.connect() as c:
        c.execute("UPDATE news_source SET last_attempt=?,status='ok' WHERE id IN ('krebs','talos')", (NOW.isoformat(timespec="seconds"),))
        c.execute("UPDATE news_source SET last_attempt=NULL WHERE id IN ('eset','sans-isc')")
    order: list[str] = []
    mock_fetch(monkeypatch, {i: {"content": rss(base=f"https://{i}.test/")} for i in ids}, order)
    object.__setattr__(settings, "news_workers", 1)
    s = collector.run_news_sync(only_due=True, only_ids=ids)
    object.__setattr__(settings, "news_workers", 8)
    assert sorted(order) == ["eset", "sans-isc"] and s["skipped"]["not_due"] == 2                                       # only what was never attempted is picked up


# ---------------------------------------------------------------- SQLite safety and integrations
def test_concurrent_source_admin_and_sync_writes_do_not_lock(api, monkeypatch):
    enable("krebs", "talos")
    mock_fetch(monkeypatch, {i: {"content": rss(n=40, base=f"https://{i}.test/")} for i in ("krebs", "talos")})
    errors = []

    def sync():
        try:
            collector.run_news_sync(force=True, only_ids=["krebs", "talos"])
        except Exception as e:
            errors.append(repr(e))
    th = threading.Thread(target=sync)
    th.start()
    for i in range(15):
        r = api.post("/api/v1/news/source-admin/bulk", json={"ids": ["eset", "sans-isc"], "action": "disable" if i % 2 else "enable"})
        if r.status_code != 200:
            errors.append(r.text)
        api.get("/api/v1/news/source-admin")
    th.join(30)
    assert not errors, errors[:3]


def test_get_endpoints_do_not_write_once_registry_rows_exist(env):
    import sqlite3
    obs = sqlite3.connect(settings.db_path)
    v0 = obs.execute("PRAGMA data_version").fetchone()[0]
    api = TestClient(app, client=("127.0.0.1", 12))
    for url in ("/api/v1/news/sources", "/api/v1/news/source-admin", "/api/v1/news/source-admin/coverage", "/api/v1/news/source-admin/onboarding"):
        assert api.get(url).status_code == 200
    assert obs.execute("PRAGMA data_version").fetchone()[0] == v0
    obs.close()


def test_existing_sources_and_articles_survive_the_expansion(env):
    with db.connect() as c:
        c.execute("INSERT INTO news_item(id,source_id,guid,url,url_canon,title,summary,published,collected_at,content_hash,sort_ts) VALUES('keep1','krebs','g','https://k.test/keep','https://k.test/keep','Keep me','',?,?,'h',?)",
                  (NOW.isoformat(timespec="seconds"),) * 3)
        c.execute("UPDATE news_source SET enabled=0 WHERE id='eset'")
    db.init_db()
    with db.connect() as c:
        repo.sync_source_rows(c)
        assert c.execute("SELECT title FROM news_item WHERE id='keep1'").fetchone()[0] == "Keep me"
        assert c.execute("SELECT enabled FROM news_source WHERE id='eset'").fetchone()[0] == 0            # user choice kept across restarts
        assert c.execute("SELECT COUNT(*) FROM news_source WHERE origin='builtin'").fetchone()[0] == 65
        assert c.execute("PRAGMA integrity_check").fetchone()[0] == "ok"


def test_dashboards_and_briefing_warn_when_sources_were_added_in_the_period(env):
    from app import briefing
    now = NOW.isoformat(timespec="seconds")
    with db.connect() as c:
        for i in range(12):
            c.execute("INSERT INTO news_item(id,source_id,guid,url,url_canon,title,summary,published,collected_at,content_hash,sort_ts) VALUES(?,?,?,?,?,?,?,?,?,'h',?)",
                      (f"{i:02d}" + "z" * 22, "krebs", f"g{i}", f"https://k.test/{i}", f"https://k.test/{i}", f"Ransomware story {i}", "", now, now, now))
        c.execute("UPDATE news_source SET enabled=1,status='ok',last_success=?,enabled_at=? WHERE id='krebs'", (now, now))
    api = TestClient(app, client=("127.0.0.1", 13))
    d = api.post("/api/v1/intelligence-dashboards", json={"name": "Cov", "keywords": [{"display_name": "R", "terms": [{"term": "ransomware"}]}]}).json()
    st = api.get(f"/api/v1/intelligence-dashboards/{d['id']}/statistics", params={"period": "7d"}).json()
    assert st["coverage"]["sources_enabled_in_period"] >= 1 and any("were enabled during this period" in w for w in st["coverage"]["warnings"])
    assert "Unique Events" in " ".join(st["coverage"]["warnings"]) and st["scale"]["legend"].startswith("Colors represent relative news coverage")
    b = briefing.generate(24, force=True, enrich_epss=False)
    assert any("were enabled during this period" in w for w in b["coverage"]["warnings"])
    assert b["schema_version"] == 1 and len(b["sections"]) == 6                                      # the briefing structure is unchanged


def test_priority_score_and_authority_do_not_depend_on_how_many_sources_exist(env):
    from app.news import intel as I
    assert I.PRIORITY.relevant_threshold == 40.0
    off = [s for s in SOURCES if s.type == "official"]
    assert len(off) > 15 and all(s.official_domains for s in off)                                    # advisories/CERTs keep their separate authority class
    assert {s.type for s in SOURCES if s.origin == "catalog"} >= {"news", "official", "threat_intel", "vuln_research", "malware", "cloud", "appsec", "privacy", "ics"}


def test_storage_estimate_inputs_exist(env):
    with db.connect() as c:
        n = c.execute("SELECT COUNT(*) FROM news_item").fetchone()[0]
        assert n >= 0 and c.execute("SELECT COUNT(*) FROM source_onboarding").fetchone()[0] == 0
