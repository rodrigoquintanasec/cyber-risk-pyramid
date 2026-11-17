"""SQLite lock regressions: short write transactions, write-free start-up, maintenance jobs that never starve the API."""
import sqlite3
import sys
import threading
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app import catalog, categories, db, intel_corr, intel_dash as idash, nvd_products, vulns  # noqa: E402
from app.config import settings  # noqa: E402
from app.main import app  # noqa: E402


@pytest.fixture()
def tdb(tmp_path):
    object.__setattr__(settings, "db_path", str(tmp_path / "l.sqlite"))
    db.init_db()
    yield tmp_path / "l.sqlite"
    catalog.set_registry(catalog.seed_technologies())
    object.__setattr__(settings, "db_path", str(tmp_path / "unused.sqlite"))


def fast_fail(monkeypatch, seconds=1.0):
    """Make every connection give up after `seconds`, so a held lock shows up as an error instead of a long wait."""
    from contextlib import contextmanager
    real = db.connect

    @contextmanager
    def short(timeout=30):
        with real(timeout=min(timeout, seconds)) as c:
            yield c
    monkeypatch.setattr(db, "connect", short)
    return real


def hold_write_lock(path, seconds):
    """A second connection that owns the write lock for `seconds` (what a long import / rebuild used to do)."""
    ready = threading.Event()

    def run():
        c = sqlite3.connect(path, timeout=30, isolation_level=None)
        c.execute("BEGIN IMMEDIATE")
        ready.set()
        time.sleep(seconds)
        c.execute("ROLLBACK")
        c.close()
    t = threading.Thread(target=run, daemon=True)
    t.start()
    assert ready.wait(5)
    return t


def counts(path):
    c = sqlite3.connect(path)
    out = {t: c.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0] for t in ("technology", "technology_category", "technology_product", "intelligence_dashboard")}
    c.close()
    return out


# ---------------------------------------------------------------- start-up
def test_normal_restart_performs_no_write_and_therefore_cannot_hit_a_lock(tdb, monkeypatch):
    before = counts(tdb)
    assert before["technology"] == 153 and before["technology_category"] == 15
    fast_fail(monkeypatch, 0.5)
    t = hold_write_lock(str(tdb), 3)                                 # another process / thread owns the write lock during the whole start-up
    t0 = time.time()
    db.init_db(retries=0)                                           # before the fix: categories.link / catalog sync wrote and failed with "database is locked"
    assert time.time() - t0 < 2.5
    t.join()
    assert counts(tdb) == before


def test_first_start_on_an_old_database_waits_for_a_temporary_lock_instead_of_crashing(tmp_path, monkeypatch):
    object.__setattr__(settings, "db_path", str(tmp_path / "old.sqlite"))
    db.init_db()
    with db.connect() as c:                                          # simulate a database created before the migration revision existed
        c.execute("DELETE FROM app_meta")
    real_sleep = time.sleep
    monkeypatch.setattr(db.time, "sleep", lambda s: real_sleep(0.2))
    t = hold_write_lock(str(tmp_path / "old.sqlite"), 1.5)
    real_connect = fast_fail(monkeypatch, 0.3)
    db.init_db(retries=12)                                           # fails fast on each try, retries, succeeds once the other writer is done
    t.join()
    monkeypatch.setattr(db, "connect", real_connect)
    with db.connect() as c:
        assert c.execute("SELECT value FROM app_meta WHERE key='schema_rev'").fetchone()[0] == str(db.SCHEMA_REV)
        assert c.execute("SELECT COUNT(*) FROM technology").fetchone()[0] == 153
    object.__setattr__(settings, "db_path", str(tmp_path / "unused.sqlite"))


def test_migrations_run_once_and_keep_categories_and_associations(tdb):
    with db.connect() as c:
        links_before = c.execute("SELECT id,category,category_id FROM technology ORDER BY id").fetchall()
        c.execute("DELETE FROM app_meta")                            # force the (idempotent) migration path again
    db.init_db()
    db.init_db()
    with db.connect() as c:
        assert [tuple(r) for r in c.execute("SELECT id,category,category_id FROM technology ORDER BY id")] == [tuple(r) for r in links_before]
        assert c.execute("SELECT COUNT(*) FROM technology_category").fetchone()[0] == 15
        assert c.execute("SELECT COUNT(*) FROM technology WHERE category_id IS NULL").fetchone()[0] == 0
        assert c.execute("SELECT COUNT(*) FROM technology_product").fetchone()[0] == 186
        assert c.execute("PRAGMA integrity_check").fetchone()[0] == "ok"


def test_link_helpers_do_not_write_when_nothing_changed(tdb):
    obs = sqlite3.connect(tdb)
    v0 = obs.execute("PRAGMA data_version").fetchone()[0]
    with db.connect() as c:
        assert categories.link(c) == 0 and nvd_products.link_existing(c) == 0
        from app import catalog_db
        catalog_db.sync(c)
    assert obs.execute("PRAGMA data_version").fetchone()[0] == v0     # no commit by any other connection
    obs.close()


# ---------------------------------------------------------------- long maintenance jobs vs the API
def seed_local_cves(n):
    with db.connect() as c:
        rows, cpes = [], []
        for i in range(n):
            cid = f"CVE-2024-{i:06d}"
            rows.append((cid, f"2024-0{1 + i % 9}-10T00:00:00", f"2024-0{1 + i % 9}-10T00:00:00", 5.0 + (i % 5), "3.1", f"d{i}", "", "2026-01-01T00:00:00"))
            cpes.append((cid, "a", "vendor%d" % (i % 400), "product%d" % (i % 900), "*"))
        c.executemany("INSERT INTO nvd_cve(cve_id,published,last_modified,cvss,cvss_version,description,cpes,fetched_at) VALUES(?,?,?,?,?,?,?,?)", rows)
        c.executemany("INSERT INTO cve_cpe(cve_id,part,vendor,product,version) VALUES(?,?,?,?,?)", cpes)
        c.execute("INSERT INTO cve_cpe(cve_id,part,vendor,product,version) VALUES('CVE-2024-000001','a','apache','log4j','*')")


def test_rebuild_and_derived_refresh_never_block_dashboard_and_category_writes(tdb, monkeypatch):
    seed_local_cves(60000)
    errors, lat = [], []
    stop = threading.Event()

    def maintenance():
        try:
            intel_corr.rebuild(derived=True)
            intel_corr.rebuild(derived=True)
            with db.connect() as c:
                nvd_products.refresh(c)
        except Exception as e:  # pragma: no cover - the assertion below reports it
            errors.append(("maintenance", repr(e)))
        finally:
            stop.set()
    fast_fail(monkeypatch, 5.0)                                      # an API write that waits more than 5 s fails the test
    th = threading.Thread(target=maintenance)
    th.start()
    api = TestClient(app, client=("127.0.0.1", 3))
    n = 0
    while not stop.is_set() or n < 4:
        t0 = time.time()
        try:
            d = api.post("/api/v1/intelligence-dashboards", json={"name": f"Dash {n}", "keywords": [{"display_name": "K", "terms": [{"term": "ransomware"}]}]})
            assert d.status_code == 201, d.text
            assert api.post("/api/v1/categories", json={"name": f"Cat {n}"}).status_code == 200
            assert api.put(f"/api/v1/categories/{categories.slug(f'Cat {n}')}", json={"description": "x"}).status_code == 200
            assert api.delete(f"/api/v1/intelligence-dashboards/{d.json()['id']}").status_code == 200
        except Exception as e:
            errors.append(("api", repr(e)))
            break
        lat.append(time.time() - t0)
        n += 1
        if n > 200:
            break
    th.join(120)
    assert not errors, errors
    assert max(lat) < 4.0 and n >= 4
    with db.connect() as c:                                          # derived data is complete and equals the live view
        assert c.execute("SELECT COUNT(*) FROM cve_index").fetchone()[0] == 60000
        assert c.execute("SELECT COUNT(*) FROM nvd_cve").fetchone()[0] == 60000
        assert c.execute("SELECT COUNT(*) FROM cve_product_stats").fetchone()[0] >= 400


def test_derived_refresh_is_equivalent_to_the_full_rebuild_and_drops_stale_rows(tdb):
    seed_local_cves(500)
    with db.connect() as c:
        c.execute("INSERT INTO cve_index(id,published,cvss,epss,in_kev,kev_date,ransomware,has_nvd) VALUES('CVE-1999-0001','1999-01-01',1.0,NULL,0,NULL,0,1)")
        c.execute("INSERT INTO cve_product_stats(vendor,product,cves) VALUES('ghost','ghost',9)")
    vulns.refresh_derived(chunk=100)
    with db.connect() as c:
        live = {r["id"]: tuple(r) for r in c.execute("SELECT id,published,cvss,epss,in_kev,kev_date,ransomware,has_nvd FROM (" + vulns.BASE_SQL + ")")}
        idx = {r["id"]: tuple(r) for r in c.execute("SELECT id,published,cvss,epss,in_kev,kev_date,ransomware,has_nvd FROM cve_index")}
        assert idx == live and "CVE-1999-0001" not in idx
        stats = {(r[0], r[1]): r[2] for r in c.execute("SELECT vendor,product,cves FROM cve_product_stats")}
        want = {(r[0], r[1]): r[2] for r in c.execute("SELECT vendor,product,COUNT(DISTINCT cve_id) FROM cve_cpe GROUP BY vendor,product")}
        assert stats == want


def test_rebuild_is_idempotent_and_writes_nothing_when_nothing_changed(tdb):
    seed_local_cves(300)
    intel_corr.rebuild(derived=True)
    obs = sqlite3.connect(tdb)
    v0 = obs.execute("PRAGMA data_version").fetchone()[0]
    out = intel_corr.rebuild()                                       # what the periodic sync does
    assert out["mode"] == "local" and "index_rows" not in out        # the 400k-row index is not rewritten every cycle
    assert obs.execute("PRAGMA data_version").fetchone()[0] == v0
    obs.close()


def test_news_sync_style_writes_and_dashboard_deletes_interleave_without_errors(tdb, monkeypatch):
    fast_fail(monkeypatch, 5.0)
    errors = []
    api = TestClient(app, client=("127.0.0.1", 4))
    ds = [api.post("/api/v1/intelligence-dashboards", json={"name": f"D{i}", "keywords": [{"display_name": "K", "terms": [{"term": "akira"}]}]}).json()["id"] for i in range(12)]

    def news_writer():
        try:
            for i in range(300):
                with db.connect() as c:                                  # the collector writes in short bursts
                    c.execute("INSERT OR REPLACE INTO source_status(source,last_attempt,last_success,ok) VALUES(?,?,?,1)", (f"s{i % 20}", db.now_iso(), db.now_iso()))
        except Exception as e:
            errors.append(repr(e))
    ts = [threading.Thread(target=news_writer) for _ in range(3)]
    [t.start() for t in ts]
    for d in ds:
        r = api.delete(f"/api/v1/intelligence-dashboards/{d}")
        if r.status_code != 200:
            errors.append(r.text)
    [t.join() for t in ts]
    assert not errors, errors[:3]
    assert counts(tdb)["intelligence_dashboard"] == 0


def test_backend_restart_keeps_all_data(tdb):
    api = TestClient(app, client=("127.0.0.1", 5))
    d = api.post("/api/v1/intelligence-dashboards", json={"name": "Keep me", "keywords": [{"display_name": "K", "terms": [{"term": "qilin"}]}]}).json()
    api.post("/api/v1/categories", json={"name": "Mine"})
    before = counts(tdb)
    for _ in range(2):                                               # restart = init_db again (what the app does at start-up)
        db.init_db()
    assert counts(tdb) == before and api.get(f"/api/v1/intelligence-dashboards/{d['id']}").json()["name"] == "Keep me"
    assert "Mine" in [c["name"] for c in api.get("/api/v1/categories").json()["items"]]
    with db.connect() as c:
        assert c.execute("PRAGMA integrity_check").fetchone()[0] == "ok" and c.execute("PRAGMA journal_mode").fetchone()[0] == "wal"


def test_read_endpoints_work_while_another_connection_holds_the_write_lock(tdb, monkeypatch):
    """Settings page regression: /news/sources and /intel-db/status used to UPSERT on every GET and returned HTTP 500 behind a long writer."""
    api = TestClient(app, client=("127.0.0.1", 6))
    assert api.get("/api/v1/news/sources").status_code == 200          # first call may legitimately create the 65 rows
    assert api.get("/api/v1/intel-db/status").status_code == 200       # creates the dataset rows once
    fast_fail(monkeypatch, 0.5)
    t = hold_write_lock(str(tdb), 4)
    for url in ("/api/v1/news/sources", "/api/v1/news/stats", "/api/v1/intel-db/status", "/api/v1/products/status", "/api/v1/categories", "/api/v1/intelligence-dashboards", "/api/v1/catalog/facets"):
        r = api.get(url)
        assert r.status_code == 200, (url, r.text[:200])
    t.join()
