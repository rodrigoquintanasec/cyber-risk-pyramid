import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app import catalog, catalog_db, db, service, sync, techsync  # noqa: E402
from app.config import settings  # noqa: E402
from app.connectors import nvd as nvd_c  # noqa: E402
from app.connectors.http import RateLimited, SourceError  # noqa: E402
from app.main import app  # noqa: E402

NOW = datetime.now(timezone.utc)
ISO = lambda d: d.isoformat(timespec="seconds")  # noqa: E731
LOG4J_Q = "cpe:2.3:a:apache:log4j"


def cve(i, published, cpes="a:apache:log4j", versions=None):
    return {"cve_id": f"CVE-{published.year}-{i:04d}", "published": published.isoformat(timespec="milliseconds").replace("+00:00", ""), "last_modified": None, "cvss": 8.0, "cvss_version": "3.1",
            "description": f"d{i}", "cpes": cpes, "versions": json.dumps(versions) if versions else None}


class FakeNVD:
    """Stands in for nvd_c.fetch_page / fetch_by_cpe. `data` = list of CVE dicts (the 'whole NVD' for the query)."""
    def __init__(self, data, fail=None):
        self.data, self.calls, self.fail = data, [], fail or {}

    def fetch_page(self, q, start_index=0, per_page=2000, pub_start=None, pub_end=None):
        self.calls.append((q, start_index, per_page, pub_start, pub_end))
        n = len(self.calls)
        if n in self.fail:
            raise self.fail[n]
        rows = self.data
        if pub_start and pub_end:
            rows = [r for r in rows if pub_start <= datetime.fromisoformat(r["published"]).replace(tzinfo=timezone.utc) <= pub_end]
        return rows[start_index:start_index + per_page], len(rows)

    def fetch_by_cpe(self, q, days, pages):
        self.calls.append(("recent", q))
        start = NOW - timedelta(days=days)
        rows = [r for r in self.data if datetime.fromisoformat(r["published"]).replace(tzinfo=timezone.utc) >= start]
        return rows, len(rows), False


@pytest.fixture()
def env(tmp_path, monkeypatch):
    object.__setattr__(settings, "db_path", str(tmp_path / "t.sqlite"))
    db.init_db()
    with db.connect() as c:                                                   # isolate the scenario: nothing but the technologies a test pins is monitored
        c.execute("UPDATE technology SET dashboard=0")
        catalog_db.load(c)
    monkeypatch.setattr(techsync, "start_background", lambda tid=None: True)

    def install(data, fail=None, page=2000):
        f = FakeNVD(data, fail)
        monkeypatch.setattr(nvd_c, "fetch_page", f.fetch_page)
        monkeypatch.setattr(nvd_c, "fetch_by_cpe", f.fetch_by_cpe)
        monkeypatch.setattr(nvd_c, "PAGE", page)
        return f
    yield install
    catalog.set_registry(catalog.seed_technologies())
    object.__setattr__(settings, "db_path", str(tmp_path / "unused.sqlite"))


def status(tid="apache-log4j"):
    with db.connect() as c:
        return techsync.tech_status(c, tid, catalog_db.monitored_ids(c))


def pin(tid="apache-log4j"):
    with db.connect() as c:
        catalog_db.set_dashboard(c, tid, True)


# ---------------------------------------------------------------- the original problem
def test_old_cves_are_found_by_historical_backfill_but_never_scored(env):
    f = env([cve(44228, datetime(2021, 12, 10, tzinfo=timezone.utc), versions=[{"v": "apache", "p": "log4j", "ver": None, "fi": "2.0.1", "fe": None, "ti": None, "te": "2.3.1", "complex": False}]),
             cve(45046, datetime(2021, 12, 14, tzinfo=timezone.utc)), cve(1, NOW - timedelta(days=10))])
    with db.connect() as c:                                                   # the old kev row alone already correlates (Apache / Log4j2) as history, not as a recent signal
        c.execute("INSERT INTO kev_entry(cve_id,vendor,product,name,date_added,ransomware) VALUES('CVE-2021-44228','Apache','Log4j2','x','2021-12-10',1)")
    assert status()["status"] == "not_started"
    pin()
    assert status()["status"] == "pending"                                    # monitored, nothing run yet: Pending (not "0 vulnerabilities")
    r = techsync.drain(10)
    assert r["ran"] and status()["status"] == "completed"
    with db.connect() as c:
        hist = {r["cve_id"]: r["applicability"] for r in c.execute("SELECT * FROM tech_cve_hist WHERE tech_id='apache-log4j'")}
        recent = [r[0] for r in c.execute("SELECT cve_id FROM tech_cve WHERE tech_id='apache-log4j'")]
        t = service.build_technology(c, "apache-log4j", detail=True)
    assert hist == {"CVE-2021-44228": "versioned", "CVE-2021-45046": "product"} and recent == [f"CVE-{NOW.year}-0001"]
    assert t["historical"]["count"] == 2 and t["historical"]["scored"] is False and t["historical"]["kev"] == 1 and t["cves_complete"] is True
    assert "historical" not in json.dumps(t["drivers"])                       # old CVEs are never score drivers
    assert t["score"] is not None                                             # the recent CVE yields a score as before


def test_kev_old_entry_correlates_as_history_without_any_nvd_call(env):
    with db.connect() as c:
        c.execute("INSERT INTO kev_entry(cve_id,vendor,product,name,date_added,ransomware) VALUES('CVE-2021-44228','Apache','Log4j2','x','2021-12-10',1)")
    sync.recompute_correlations()
    with db.connect() as c:
        assert [tuple(r) for r in c.execute("SELECT tech_id,cve_id,match_source FROM tech_cve_hist")] == [("apache-log4j", "CVE-2021-44228", "kev-product")]
        assert c.execute("SELECT COUNT(*) FROM tech_cve WHERE tech_id='apache-log4j'").fetchone()[0] == 0
        t = service.build_technology(c, "apache-log4j")
    assert t["score"] is None and "historical" in t["insufficient_reason"] and t["cves_complete"] is False       # zero recent CVEs is not shown as "no vulnerabilities"


# ---------------------------------------------------------------- state machine: pagination, windows, horizon
def test_small_product_is_fully_paginated_and_a_new_technology_reaches_completed_unattended(env):
    data = [cve(i, datetime(2015 + i % 5, 3, 1, tzinfo=timezone.utc)) for i in range(1, 6)]
    f = env(data, page=2)
    pin()
    assert status()["status"] == "pending"
    techsync.drain(20)
    s = status()
    assert s["status"] == "completed" and s["queries_completed"] == s["queries_required"] == 1 and s["cves_retrieved"] == 5 and s["last_success"]
    starts = [c[1] for c in f.calls if c[0] == LOG4J_Q and c[2] == 2]
    assert starts == [0, 2, 4]                                                # complete pagination
    with db.connect() as c:
        assert c.execute("SELECT COUNT(*) FROM nvd_cve").fetchone()[0] == 5 and c.execute("SELECT COUNT(*) FROM tech_cve_hist").fetchone()[0] == 5
    n = len(f.calls)
    techsync.drain(20)
    assert len(f.calls) == n                                                  # completed jobs are never repeated


def test_large_product_goes_newest_first_in_valid_windows_and_is_marked_history_limited(env, monkeypatch):
    old = (settings.nvd_backfill_all_cap, settings.nvd_backfill_years)
    object.__setattr__(settings, "nvd_backfill_all_cap", 3)
    object.__setattr__(settings, "nvd_backfill_years", 1)
    monkeypatch.setattr(techsync, "WINDOW_DAYS", 119)
    data = [cve(i, NOW - timedelta(days=60 * i)) for i in range(1, 12)]       # 11 CVEs spread over ~22 months
    f = env(data)
    pin()
    techsync.drain(60)
    wins = [(c[3], c[4]) for c in f.calls if len(c) > 3 and c[3]]
    assert wins and all((e - s).days <= 119 for s, e in wins) and wins[0][1] > wins[-1][1]          # <=119-day windows, newest first
    s = status()
    assert s["status"] == "partial" and s["history_limited"] and "limited" in s["note"]               # not claimed as complete
    with db.connect() as c:
        got = {r[0] for r in c.execute("SELECT cve_id FROM nvd_cve")}
    assert 0 < len(got) < 11                                                                          # only up to the horizon, not the whole of NVD
    object.__setattr__(settings, "nvd_backfill_all_cap", old[0])
    object.__setattr__(settings, "nvd_backfill_years", old[1])


def test_budget_stops_midway_and_the_next_run_resumes_without_refetching(env):
    data = [cve(i, datetime(2016, 1, i, tzinfo=timezone.utc)) for i in range(1, 8)]
    f = env(data, page=2)
    pin()
    techsync.drain(2)                                                         # probe + first page only
    assert status()["status"] == "partial" and status()["cves_retrieved"] == 2
    techsync.drain(20)
    assert status()["status"] == "completed"
    starts = [c[1] for c in f.calls if c[0] == LOG4J_Q and c[2] == 2]
    assert starts == [0, 2, 4, 6] and len(starts) == len(set(starts))        # each page fetched exactly once


# ---------------------------------------------------------------- failures: retries, rate limit, interruption, duplicates
def test_transient_error_then_retry_resumes_from_the_saved_cursor(env):
    data = [cve(i, datetime(2016, 1, i, tzinfo=timezone.utc)) for i in range(1, 6)]
    f = env(data, fail={3: SourceError("boom")}, page=2)
    pin()
    techsync.drain(20)
    s = status()
    assert s["status"] == "partial" and "boom" in s["last_error"] and s["next_eligible"] and s["cves_retrieved"] == 2       # progress kept, backoff set
    n = len(f.calls)
    techsync.drain(20)
    assert len(f.calls) == n                                                  # inside the backoff nothing is retried
    with db.connect() as c:
        c.execute("UPDATE tech_sync_job SET next_eligible=NULL")
    techsync.drain(20)
    assert status()["status"] == "completed" and status()["last_error"] is None
    assert [c[1] for c in f.calls if c[0] == LOG4J_Q and c[2] == 2] == [0, 2, 2, 4]       # page 0 once (kept), the failed page retried once


def test_first_attempt_failing_without_progress_is_failed(env):
    env([], fail={1: SourceError("down")})
    pin()
    techsync.drain(5)
    s = status()
    assert s["status"] == "failed" and "down" in s["last_error"]


def test_rate_limit_stops_everything_sets_backoff_and_manual_requests_do_not_bypass_it(env):
    f = env([cve(1, datetime(2016, 1, 1, tzinfo=timezone.utc))], fail={1: RateLimited("HTTP 429", 120)})
    pin(); pin("jenkins")
    r = techsync.drain(20)
    assert r["stopped"] == "rate_limited" and len(f.calls) == 1               # the second technology was NOT attempted
    s = status("apache-log4j") if status("apache-log4j")["status"] == "rate_limited" else status("jenkins")
    assert s["status"] == "rate_limited" and s["next_eligible"] and datetime.fromisoformat(s["next_eligible"]) > NOW and s["error_kind"] == "rate_limit"
    tid = "apache-log4j" if status("apache-log4j")["status"] == "rate_limited" else "jenkins"
    with db.connect() as c:
        assert techsync.request(c, tid)["accepted"] is True                   # accepted (queued) ...
    n = len(f.calls)
    techsync.drain(20, manual=True)
    assert all(c[0] != catalog.BY_ID[tid].nvd_queries[0] for c in f.calls[n:])   # ... but the throttled query is not called during backoff


def test_interrupted_jobs_are_resumable_and_running_jobs_are_never_duplicated(env):
    data = [cve(i, datetime(2016, 1, i, tzinfo=timezone.utc)) for i in range(1, 6)]
    f = env(data, page=2)
    pin()
    techsync.drain(2)
    with db.connect() as c:                                                   # simulate a crash: status stuck in_progress, heartbeat fresh -> another runner owns it
        c.execute("UPDATE tech_sync_job SET status='in_progress', heartbeat=?", (ISO(NOW),))
        assert techsync.request(c, "apache-log4j")["reason"] == "already_running"
    n = len(f.calls)
    techsync.drain(20)
    assert len(f.calls) == n and status()["status"] == "in_progress"
    with db.connect() as c:                                                   # heartbeat goes stale -> interrupted -> resumable
        c.execute("UPDATE tech_sync_job SET heartbeat=?", (ISO(NOW - timedelta(minutes=30)),))
    assert status()["status"] == "partial"
    techsync.drain(20)
    assert status()["status"] == "completed"
    with db.connect() as c:
        assert c.execute("SELECT COUNT(*) FROM nvd_cve").fetchone()[0] == 5   # re-runs never duplicate rows


def test_single_runner_lock_prevents_parallel_backfills(env):
    env([])
    pin()
    assert techsync._runner.acquire(blocking=False)
    try:
        assert techsync.drain(5) == {"ran": False, "reason": "busy"}
    finally:
        techsync._runner.release()


# ---------------------------------------------------------------- correct and incorrect CPE correlation
def test_only_verified_product_ids_are_correlated(env):
    old = datetime(2018, 1, 1, tzinfo=timezone.utc)
    env([cve(1, old), cve(2, old, cpes="a:apache:log4cxx"), cve(3, old, cpes="a:apache:http_server,a:apache:log4j"), cve(4, old, cpes="a:microsoft:paint")])
    pin()
    techsync.drain(10)
    with db.connect() as c:
        mine = sorted(r[0] for r in c.execute("SELECT cve_id FROM tech_cve_hist WHERE tech_id='apache-log4j'"))
        http = sorted(r[0] for r in c.execute("SELECT cve_id FROM tech_cve_hist WHERE tech_id='apache-http-server'"))
    assert mine == ["CVE-2018-0001", "CVE-2018-0003"] and http == ["CVE-2018-0003"]          # log4cxx / vendor-only / other vendors never attributed
    # a family does not hand every CVE to every member
    sync.recompute_correlations()
    with db.connect() as c:
        assert c.execute("SELECT COUNT(*) FROM tech_cve_hist WHERE tech_id='apache-tomcat'").fetchone()[0] == 0


def test_complex_nvd_configurations_are_flagged_for_review(env):
    cx = [{"v": "apache", "p": "log4j", "ver": None, "fi": None, "fe": None, "ti": None, "te": "2.15.0", "complex": True}]
    env([cve(1, datetime(2018, 1, 1, tzinfo=timezone.utc), versions=cx)])
    pin()
    techsync.drain(10)
    with db.connect() as c:
        assert c.execute("SELECT applicability FROM tech_cve_hist").fetchone()[0] == "review"


# ---------------------------------------------------------------- scores, coverage states, companies
def test_technologies_without_cpe_have_no_sync_and_no_score(env):
    with db.connect() as c:
        st = techsync.tech_status(c, "aws")
        assert st["applicable"] is False and st["status"] == "not_started" and "CPE" in st["note"]
        t = service.build_technology(c, "aws")
        assert t["score"] is None and t["cves_complete"] is True and t["coverage_state"] == "catalog_only"
        assert techsync.request(c, "aws")["reason"] == "no_cpe"


def test_existing_scored_technology_is_unchanged_by_history(env):
    with db.connect() as c:
        c.execute("INSERT INTO nvd_cve(cve_id,published,cvss,cvss_version,description,cpes,fetched_at) VALUES('CVE-2026-9','"+ISO(NOW - timedelta(days=5))+"',9.0,'3.1','d','o:linux:linux_kernel','x')")
        c.execute("INSERT INTO epss(cve_id,score,percentile,score_date,fetched_at) VALUES('CVE-2026-9',0.5,0.9,'2026-01-01','x')")
        c.execute("INSERT INTO query_log(key,last_success,total_results,truncated) VALUES('cpe:2.3:o:linux:linux_kernel',?,1,0)", (ISO(NOW),))
    sync.recompute_correlations()
    with db.connect() as c:
        before = service.build_technology(c, "linux")["score"]
        c.execute("INSERT INTO nvd_cve(cve_id,published,cvss,cvss_version,description,cpes,fetched_at) VALUES('CVE-2010-1','2010-01-01T00:00:00',10.0,'2.0','old','o:linux:linux_kernel','x')")
    sync.recompute_correlations()
    with db.connect() as c:
        after = service.build_technology(c, "linux")
        assert c.execute("SELECT COUNT(*) FROM tech_cve_hist WHERE tech_id='linux' AND cve_id='CVE-2010-1'").fetchone()[0] == 1
    assert before is not None and after["score"] == before and after["historical"]["count"] == 1


def test_company_exposure_uses_historical_cves_and_stays_isolated(env):
    rng = [{"v": "apache", "p": "log4j", "ver": None, "fi": "2.0.1", "fe": None, "ti": None, "te": "2.15.1", "complex": False}]
    env([cve(44228, datetime(2021, 12, 10, tzinfo=timezone.utc), versions=rng)])
    client = TestClient(app, client=("127.0.0.1", 1))
    a = client.post("/api/v1/companies", json={"name": "A", "industry": "x"}).json()["id"]
    b = client.post("/api/v1/companies", json={"name": "B", "industry": "x"}).json()["id"]
    client.post(f"/api/v1/companies/{a}/assets", json={"tech_id": "apache-log4j", "version": "2.14.1"})
    client.post(f"/api/v1/companies/{b}/assets", json={"tech_id": "apache-log4j", "version": "2.17.1"})
    techsync.drain(10)                                                        # the company inventory made log4j monitored: no manual pinning needed
    st = lambda cid: client.get(f"/api/v1/companies/{cid}/vulnerabilities").json()["items"][0]["effective_status"]  # noqa: E731
    assert st(a) == "potentially_applicable" and st(b) == "not_applicable"
    assert client.get(f"/api/v1/companies/{a}/vulnerabilities").json()["total"] == 1


# ---------------------------------------------------------------- API
def test_sync_api_is_protected_non_blocking_and_deduplicated(env):
    f = env([cve(1, datetime(2016, 1, 1, tzinfo=timezone.utc))])
    local, remote = TestClient(app, client=("127.0.0.1", 1)), TestClient(app)
    assert remote.post("/api/v1/catalog/apache-log4j/sync").status_code == 403
    assert local.post("/api/v1/catalog/nope/sync").status_code == 404
    r = local.post("/api/v1/catalog/apache-log4j/sync")
    assert r.status_code == 202 and r.json()["accepted"] is True and r.json()["sync"]["status"] == "pending" and not f.calls     # returns immediately, nothing ran inline
    assert local.post("/api/v1/catalog/aws/sync").json()["reason"] == "no_cpe"
    techsync.drain(10, manual=True)
    d = local.get("/api/v1/catalog/apache-log4j").json()
    assert d["sync_status"]["status"] == "completed" and d["historical"]["count"] == 1 and d["sync_jobs"][0]["fetched"] == 1
    assert local.post("/api/v1/catalog/apache-log4j/sync").json()["reason"] == "completed"
    row = local.get("/api/v1/catalog?q=log4j").json()["items"][0]
    assert row["sync"]["status"] == "completed" and row["cves_complete"] is True and row["historical_cve_count"] == 1
    v = local.get("/api/v1/vulns?tech=apache-log4j").json()
    assert v["total"] == 1 and v["tech_coverage"]["coverage_state"] in ("monitored", "partial")
    assert local.get("/api/v1/catalog/apache-log4j/sync").json()["status"] == "completed"
