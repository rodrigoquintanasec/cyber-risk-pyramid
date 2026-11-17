import sqlite3
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.db import SCHEMA  # noqa: E402
from app.news import collector, repo  # noqa: E402
from app.news.classify import canonical_url, classify, clean_text, detect_technologies, extract_cves, safe_url  # noqa: E402
from app.news.safefetch import FetchError, validate_url  # noqa: E402
from app.news.sources import BY_ID, SOURCES  # noqa: E402

NOW = datetime(2026, 11, 16, 12, tzinfo=timezone.utc)
SRC = BY_ID["bleepingcomputer"]
SRC2 = BY_ID["krebs"]


@pytest.fixture()
def con():
    c = sqlite3.connect(":memory:")
    c.row_factory = sqlite3.Row
    c.executescript(SCHEMA)
    repo.sync_source_rows(c)
    return c


def item(i, title=None, summary="", guid=None, url=None, hours_ago=1, **kw):
    pub = (NOW - timedelta(hours=hours_ago)).isoformat(timespec="seconds")
    return {"guid": guid or f"g{i}", "url": url or f"https://example.com/a{i}", "title": title or f"Title {i}",
            "summary": summary, "published": pub, "feed_updated": None, "tags": [], **kw}


# ---- CVE extraction
def test_extract_cves():
    assert extract_cves("Fix for CVE-2026-12345 and cve-2025-0001? no: CVE-2025-0001, CVE-2026-12345") == ["CVE-2026-12345", "CVE-2025-0001"]
    assert extract_cves("CVE-26-1234 CVE-2026-12 XCVE-2026-12345 CVE-2999-12345", max_year=2027) == []
    assert extract_cves("") == []


# ---- classification
def test_classification_multi_and_fallback():
    c = classify("LockBit ransomware exploits a zero-day in a VPN appliance")
    assert {"Ransomware", "Vulnerabilities", "Network Security"} <= set(c)
    assert classify("Quarterly earnings of a vendor") == ["General Cybersecurity"]
    assert "Data Breaches" in classify("Retailer confirms data breach affecting customers")


# ---- technology association
def test_tech_detection_explicit_only():
    assert detect_technologies("Critical FortiOS SSL-VPN flaw exploited") == {"fortinet": "name"}
    assert detect_technologies("VMware ESXi hit by ransomware") == {"vmware": "name"}
    assert set(detect_technologies("Docker and Kubernetes misconfigurations")) == {"docker", "kubernetes"}
    assert detect_technologies("Patch Tuesday fixes Windows Server and Microsoft Exchange bugs") == {"windows-server": "name"}


def test_generic_terms_do_not_associate():
    assert detect_technologies("Microsoft Edge update fixes a sandbox bug") == {}
    assert detect_technologies("Microsoft patches a Windows 11 bug") == {"windows-11": "name"}      # explicit product name only; the vendor alone never matches
    assert detect_technologies("Fortune 500 firms and the Linux Foundation announce a fund") == {}
    assert detect_technologies("Workstation security tips; fusion centers") == {}


def test_passing_summary_mention_is_not_enough():
    assert detect_technologies("Gateway flaws. Also affects Fortinet devices.", title="Gateway flaws exploited") == {}
    assert detect_technologies("Gateway flaws. Fortinet and FortiGate patched.", title="Gateway flaws exploited") == {"fortinet": "name"}
    assert detect_technologies("Gateway flaws", title="FortiGate flaws exploited") == {"fortinet": "name"}


def test_tech_via_correlated_cve():
    r = detect_technologies("Attackers exploit CVE-2026-1111", {"CVE-2026-1111": {"vmware"}}, ["CVE-2026-1111"])
    assert r == {"vmware": "cve"}
    assert detect_technologies("Attackers exploit CVE-2026-2222", {"CVE-2026-1111": {"vmware"}}, ["CVE-2026-2222"]) == {}


# ---- sanitisation / URLs
def test_sanitisation_and_urls():
    assert clean_text("<p>Hello <script>alert(1)</script><b>world</b> &amp; co</p>") == "Hello alert(1)world & co"
    assert "<" not in clean_text("<img src=x onerror=alert(1)>text")
    assert safe_url("javascript:alert(1)") is None and safe_url("https://a.com/x") == "https://a.com/x"
    assert canonical_url("HTTPS://Example.com/a/?utm_source=x&id=2#frag") == "https://example.com/a?id=2"


# ---- SSRF
def fake_resolver(ip):
    return lambda host, port, type=None: [(2, 1, 6, "", (ip, port))]


def test_ssrf_blocks():
    hosts = frozenset({"www.bleepingcomputer.com"})
    validate_url("https://www.bleepingcomputer.com/feed/", hosts, fake_resolver("104.18.1.1"))
    for bad, ip in (("file:///etc/passwd", "1.1.1.1"), ("ftp://www.bleepingcomputer.com/x", "1.1.1.1"),
                    ("https://evil.example/feed", "1.1.1.1"), ("https://www.bleepingcomputer.com/feed/", "127.0.0.1"),
                    ("https://www.bleepingcomputer.com/feed/", "10.0.0.5"), ("https://www.bleepingcomputer.com/feed/", "169.254.169.254"),
                    ("https://www.bleepingcomputer.com/feed/", "::1")):
        with pytest.raises(FetchError):
            validate_url(bad, hosts, fake_resolver(ip))


# ---- dedup
def test_dedup_repeated_sync(con):
    assert repo.upsert_item(con, SRC, item(1), {}, NOW) == "new"
    assert repo.upsert_item(con, SRC, item(1), {}, NOW) == "duplicate"
    # same canonical URL via different guid / tracking params
    assert repo.upsert_item(con, SRC, item(9, guid="other", url="https://example.com/a1?utm_source=z"), {}, NOW) == "duplicate"
    # same URL published by a different source
    assert repo.upsert_item(con, SRC2, item(1, guid="x"), {}, NOW) == "duplicate"
    assert con.execute("SELECT COUNT(*) FROM news_item").fetchone()[0] == 1


def test_similar_titles_are_not_duplicates(con):
    assert repo.upsert_item(con, SRC, item(1, title="Same title"), {}, NOW) == "new"
    assert repo.upsert_item(con, SRC, item(2, title="Same title"), {}, NOW) == "new"


def test_update_detected_when_content_changes(con):
    repo.upsert_item(con, SRC, item(1, title="Old"), {}, NOW)
    assert repo.upsert_item(con, SRC, item(1, title="New title"), {}, NOW) == "updated"
    assert con.execute("SELECT title,updated_at FROM news_item").fetchone()["title"] == "New title"


def test_parse_feed_rss_and_invalid():
    rss = b"""<?xml version='1.0'?><rss version='2.0'><channel><title>t</title><item><title>A &amp; B</title>
    <link>https://example.com/p?utm_x=1</link><guid>g1</guid><pubDate>Mon, 16 Nov 2026 10:00:00 GMT</pubDate>
    <description>&lt;p&gt;Body CVE-2026-0001&lt;/p&gt;</description></item>
    <item><title>bad</title><link>javascript:alert(1)</link></item></channel></rss>"""
    items = collector.parse_feed(rss)
    assert len(items) == 1 and items[0]["summary"] == "Body CVE-2026-0001" and items[0]["published"].startswith("2026-11-16T10:00")
    with pytest.raises(ValueError):
        collector.parse_feed(b"<html><body>Forbidden</body></html>")


# ---- filters & pagination
@pytest.fixture()
def populated(con):
    cve_techs = {"CVE-2026-1111": {"vmware"}}
    repo.upsert_item(con, SRC, item(1, "FortiOS zero-day exploited", "Details CVE-2026-5555", hours_ago=2), cve_techs, NOW)
    repo.upsert_item(con, SRC, item(2, "LockBit ransomware hits hospital", "", hours_ago=30), cve_techs, NOW)
    repo.upsert_item(con, SRC2, item(3, "Escape bug in a hypervisor CVE-2026-1111", "", hours_ago=24 * 10), cve_techs, NOW)
    repo.upsert_item(con, BY_ID["talos"], item(4, "Quarterly report 100%_done", "", hours_ago=24 * 60), cve_techs, NOW)
    return con


def search(con, **kw):
    # period filters are relative to the real clock, so tests use explicit dates for deterministic ranges
    return repo.search_news(con, **kw)


def test_filters(populated):
    c = populated
    assert search(c)["total"] == 4
    assert [i["title"] for i in search(c, q="forti")["items"]] == ["FortiOS zero-day exploited"]
    assert search(c, source="krebs")["total"] == 1
    assert search(c, source_type="threat_intel")["total"] == 1
    assert search(c, category="Ransomware")["total"] == 1
    assert search(c, tech="fortinet")["total"] == 1
    assert search(c, tech="vmware")["total"] == 1  # linked only through the correlated CVE
    assert search(c, cve="cve-2026-5555")["total"] == 1
    assert search(c, tech="fortinet", category="Vulnerabilities", source="bleepingcomputer")["total"] == 1
    assert search(c, tech="fortinet", source="krebs")["total"] == 0
    assert search(c, date_from="2026-11-16")["total"] == 1
    assert search(c, date_to="2026-11-10")["total"] == 2
    assert search(c, q="%x")["total"] == 0 and search(c, q="100%_")["total"] == 1  # wildcards are escaped
    assert search(c, q="'; DROP TABLE news_item;--")["total"] == 0 and search(c)["total"] == 4


def test_period_filter_relative_to_now(con):
    now = datetime.now(timezone.utc)
    for i, h in enumerate((1, 48, 24 * 20, 24 * 90)):
        it = item(i, hours_ago=0)
        it["published"] = (now - timedelta(hours=h)).isoformat(timespec="seconds")
        repo.upsert_item(con, SRC, it, {}, now)
    assert repo.search_news(con, period="24h")["total"] == 1
    assert repo.search_news(con, period="7d")["total"] == 2
    assert repo.search_news(con, period="30d")["total"] == 3
    assert repo.search_news(con, period="all")["total"] == 4


def test_pagination_and_order(con):
    for i in range(25):
        repo.upsert_item(con, SRC, item(i, hours_ago=i + 1), {}, NOW)
    p1 = repo.search_news(con, page=1, page_size=10)
    p3 = repo.search_news(con, page=3, page_size=10)
    assert p1["total"] == 25 and p1["pages"] == 3 and len(p1["items"]) == 10 and len(p3["items"]) == 5
    assert p1["items"][0]["title"] == "Title 0"  # newest first
    pubs = [i["published"] for i in p1["items"]]
    assert pubs == sorted(pubs, reverse=True)
    assert repo.search_news(con, page_size=10_000)["page_size"] == repo.MAX_PAGE_SIZE


def test_stats_and_sources(populated):
    st = repo.stats(populated)
    assert st["total_news"] == 4 and st["cve_references"] == 2 and st["correlated_news"] == 2
    assert st["sources_configured"] == len(SOURCES) and st["sources_active"] == 0 and st["sources_pending"] == sum(1 for x in SOURCES if x.enabled) and st["sources_disabled"] == sum(1 for x in SOURCES if not x.enabled)
