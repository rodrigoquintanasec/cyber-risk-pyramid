import gzip
import hashlib
import io
import json
import sys
import tarfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app import catalog, db, exposure, intel_corr, intel_import as ii, intel_io, service, techsync, vulns  # noqa: E402
from app.config import settings  # noqa: E402
from app.intel_io import FeedError  # noqa: E402
from app.main import app  # noqa: E402

NOW = datetime.now(timezone.utc)
Y = NOW.year
TS = lambda d: d.strftime("%Y-%m-%dT%H:%M:%S.000")  # noqa: E731
FEEDS = ii.NVD_FEEDS


# ---------------------------------------------------------------- record builders
def match(vendor, product, ver="*", vsi=None, vse=None, vei=None, vee=None, vulnerable=True, part="a"):
    m = {"vulnerable": vulnerable, "criteria": f"cpe:2.3:{part}:{vendor}:{product}:{ver}:*:*:*:*:*:*:*", "matchCriteriaId": f"{abs(hash((vendor, product, ver, vsi, vee))) % 10**8:08d}-AAAA"}
    for k, v in (("versionStartIncluding", vsi), ("versionStartExcluding", vse), ("versionEndIncluding", vei), ("versionEndExcluding", vee)):
        if v:
            m[k] = v
    return m


def conf(*matches, operator=None):
    return {"nodes": [{"operator": "OR", "negate": False, "cpeMatch": list(matches)}], **({"operator": operator} if operator else {})}


def cve(n, year, pub=None, mod=None, status="Analyzed", cvss=7.5, cwe="CWE-79", confs=None, desc=None, refs=1):
    cid = f"CVE-{year}-{n:04d}"
    pub = pub or datetime(year, 3, 1, tzinfo=timezone.utc)
    mod = mod or pub
    rec = {"id": cid, "sourceIdentifier": "nvd@nist.gov", "published": TS(pub), "lastModified": TS(mod), "vulnStatus": status, "descriptions": [{"lang": "en", "value": desc or f"Description of {cid}"}],
           "metrics": {"cvssMetricV31": [{"type": "Primary", "cvssData": {"version": "3.1", "baseScore": cvss, "vectorString": "CVSS:3.1/AV:N", "baseSeverity": "HIGH"}}]} if cvss is not None else {},
           "weaknesses": [{"source": "nvd@nist.gov", "type": "Primary", "description": [{"lang": "en", "value": cwe}]}] if cwe else [],
           "references": [{"url": f"https://example.test/{cid}/{i}", "source": "x", "tags": ["Patch"]} for i in range(refs)]}
    if confs is not None:
        rec["configurations"] = confs
    return {"cve": rec}


def feed(items, key="vulnerabilities"):
    return json.dumps({"resultsPerPage": len(items), "startIndex": 0, "totalResults": len(items), "format": "NVD_CVE", "version": "2.0", "timestamp": "2026-01-01T00:00:00", key: items}).encode()


class Net:
    """In-memory stand-in for the official hosts. Records every request; can inject failures."""
    def __init__(self):
        self.gz, self.meta, self.text, self.fetched, self.fail, self.sha_override = {}, {}, {}, [], {}, {}

    def add_cve_unit(self, unit, items):
        raw = feed(items)
        z = gzip.compress(raw)
        url = f"{FEEDS}/cve/2.0/{unit}.json.gz"
        self.gz[url] = z
        sha = self.sha_override.get(unit) or hashlib.sha256(raw).hexdigest().upper()
        self.text[url.replace(".json.gz", ".meta")] = f"lastModifiedDate:2026-01-01T00:00:00-05:00\r\nsize:{len(raw)}\r\nzipSize:{len(z)}\r\ngzSize:{len(z)}\r\nsha256:{sha}\r\n"

    def add_tar(self, ds_path, name, key, items, members=None, sha_of="members"):
        buf = io.BytesIO()
        cat = b""
        with tarfile.open(fileobj=buf, mode="w") as tf:
            for mname, mitems in (members or [(f"{name}-chunks/{name}-chunk-00001.json", items)]):
                data = feed(mitems, key)
                cat += data
                ti = tarfile.TarInfo(mname)
                ti.size = len(data)
                tf.addfile(ti, io.BytesIO(data))
        tar = buf.getvalue()
        z = gzip.compress(tar)
        url = f"{FEEDS}/{ds_path}/{name}.tar.gz"
        self.gz[url] = z
        h = {"gz": hashlib.sha256(z), "tar": hashlib.sha256(tar), "members": hashlib.sha256(cat)}[sha_of]     # the real NVD feeds hash the concatenated member contents
        self.text[url.replace(".tar.gz", ".meta")] = f"lastModifiedDate:2026-01-01T00:00:00-05:00\r\nsize:{len(cat)}\r\nzipSize:{len(z)}\r\ngzSize:{len(z)}\r\nsha256:{h.hexdigest().upper()}\r\n"

    def fetch_text(self, url, max_bytes=2_000_000):
        self.fetched.append(("text", url))
        if url in self.fail:
            raise self.fail[url]
        if url not in self.text:
            raise FeedError(f"HTTP 404 for {url}", fatal=True)
        return self.text[url]

    def fetch_to(self, url, dest, max_bytes, expected_size=None, resume=True, progress=None):
        self.fetched.append(("file", url))
        intel_io.check_url(url)
        if url in self.fail:
            raise self.fail[url]
        if url not in self.gz:
            raise FeedError(f"HTTP 404 for {url}", fatal=True)
        data = self.gz[url]
        if len(data) > max_bytes:
            raise FeedError("download exceeds the configured size limit", fatal=True)
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(data)
        if expected_size and len(data) != expected_size:
            raise FeedError("size mismatch")
        return len(data)

    def files(self):
        return [u for k, u in self.fetched if k == "file"]


@pytest.fixture()
def env(tmp_path, monkeypatch):
    object.__setattr__(settings, "db_path", str(tmp_path / "i.sqlite"))
    object.__setattr__(settings, "intel_tmp_dir", str(tmp_path / "tmp"))
    old, old_free = settings.intel_batch, settings.intel_min_free_gb
    object.__setattr__(settings, "intel_min_free_gb", 0.0)                       # the disk-space guard has its own test; the others must not depend on the machine running them
    object.__setattr__(settings, "intel_batch", 3)
    object.__setattr__(settings, "intel_throttle_ms", 0)
    ii._stop.clear()
    monkeypatch.setattr(ii, "FIRST_YEAR", Y - 1)
    net = Net()
    monkeypatch.setattr(intel_io, "fetch_text", net.fetch_text)
    monkeypatch.setattr(intel_io, "fetch_to", net.fetch_to)
    monkeypatch.setattr(techsync, "invalidate_caches", lambda: None)
    db.init_db()
    yield net
    catalog.set_registry(catalog.seed_technologies())
    object.__setattr__(settings, "intel_batch", old)
    object.__setattr__(settings, "intel_min_free_gb", old_free)
    object.__setattr__(settings, "db_path", str(tmp_path / "unused.sqlite"))


def run(mode="full", datasets=None):
    r = ii.start(mode, datasets, wait=True)
    assert r["started"], r
    return r


def q1(sql, *a):
    with db.connect() as c:
        return c.execute(sql, a).fetchone()[0]


def cves_for_years(net, per_year=4):
    net.add_cve_unit(f"nvdcve-2.0-{Y - 1}", [cve(i, Y - 1) for i in range(1, per_year + 1)])
    net.add_cve_unit(f"nvdcve-2.0-{Y}", [cve(i, Y) for i in range(1, per_year + 1)])
    net.add_cve_unit("nvdcve-2.0-modified", [])


LOG4J = [conf(match("apache", "log4j", vsi="2.0.1", vee="2.3.1"), match("apache", "log4j", vsi="2.4.0", vee="2.12.2"), match("apache", "log4j", vsi="2.13.0", vee="2.15.0"),
              match("apache", "log4j", ver="2.0", vsi=None))]


# ---------------------------------------------------------------- parsing & safety primitives
def test_stream_parser_survives_chunk_boundaries_unicode_and_detects_truncation():
    items = [{"id": i, "t": "ñandú ✓ " * 20, "n": {"a": [1, 2, {"b": "]"}]}} for i in range(200)]
    raw = json.dumps({"head": "x", "vulnerabilities": items, "tail": 1}).encode()
    for chunk in (7, 64, 1 << 20):
        pos = [0]

        def read(n, pos=pos):
            b = raw[pos[0]:pos[0] + n]
            pos[0] += n
            return b
        assert list(intel_io.iter_array(read, "vulnerabilities", chunk)) == items
    cut = raw[:len(raw) // 2]
    pos = [0]

    def read2(n):
        b = cut[pos[0]:pos[0] + n]
        pos[0] += n
        return b
    with pytest.raises(ValueError):
        list(intel_io.iter_array(read2, "vulnerabilities", 100))


def test_only_official_https_hosts_are_reachable_and_redirects_are_checked():
    for bad in ("http://nvd.nist.gov/x", "https://evil.example/x", "https://nvd.nist.gov.evil.example/x", "https://user:pw@nvd.nist.gov/x", "file:///etc/passwd"):
        with pytest.raises(FeedError):
            intel_io.check_url(bad)
    intel_io.check_url("https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-recent.meta")
    intel_io.check_url("https://epss.cyentia.com/epss_scores-current.csv.gz")


def test_decompression_bomb_and_unexpected_archive_members_are_rejected(tmp_path):
    z = tmp_path / "bomb.json.gz"
    z.write_bytes(gzip.compress(b"0" * 3_000_000))
    object.__setattr__(settings, "intel_max_uncompressed_mb", 1)
    try:
        with pytest.raises(FeedError):
            intel_io.gz_sha256(z)
    finally:
        object.__setattr__(settings, "intel_max_uncompressed_mb", 8000)
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        ti = tarfile.TarInfo("../../evil.json")
        ti.size = 2
        tf.addfile(ti, io.BytesIO(b"{}"))
    t = tmp_path / "x.tar.gz"
    t.write_bytes(gzip.compress(buf.getvalue()))
    with pytest.raises(FeedError):
        list(intel_io.iter_tar_json(t, "products"))


def test_meta_parsing_and_download_size_limits(tmp_path, monkeypatch):
    m = intel_io.parse_meta("lastModifiedDate:2026-01-01T00:00:00-05:00\r\nsize:100\r\ngzSize:50\r\nsha256:abcdef\r\n")
    assert m["size"] == 100 and m["gzSize"] == 50 and m["sha256"] == "ABCDEF"
    monkeypatch.setattr(intel_io.shutil, "disk_usage", lambda p: type("D", (), {"free": 10})())
    with pytest.raises(FeedError, match="free disk"):
        intel_io.fetch_to("https://nvd.nist.gov/feeds/json/cve/2.0/x.json.gz", tmp_path / "f", 10**9, expected_size=10**6)


# ---------------------------------------------------------------- stage 1: CVE import
def test_normalisation_keeps_the_configuration_tree_and_logic(env):
    complex_conf = [{"operator": "AND", "nodes": [{"operator": "OR", "negate": False, "cpeMatch": [match("acme", "app", vee="2.0")]},
                                                  {"operator": "OR", "negate": False, "cpeMatch": [match("acme", "os", vulnerable=False, part="o")]}]}]
    rec = ii.normalize_cve(cve(1, Y, confs=complex_conf, cwe="CWE-787")["cve"])
    assert json.loads(rec["config_json"]) == complex_conf                      # original tree, not flattened
    assert rec["complex"] == 1 and [m["product"] for m in rec["matches"]] == ["app"]      # only the VULNERABLE match is a product row
    assert rec["cvss"] == 7.5 and rec["cvss_version"] == "3.1" and rec["vector"].startswith("CVSS:3.1") and rec["cwes"] == [("CWE-787", "nvd@nist.gov")]
    simple = ii.normalize_cve(cve(2, Y, confs=[conf(match("acme", "app", vee="2.0"))])["cve"])
    assert simple["complex"] == 0 and simple["matches"][0]["vee"] == "2.0"
    with pytest.raises(ValueError):
        ii.normalize_cve({"id": "NOT-A-CVE"})


def test_full_import_loads_all_tables_and_reports_complete_only_when_every_unit_is_done(env):
    net = env
    net.add_cve_unit(f"nvdcve-2.0-{Y}", [cve(1, Y, confs=[conf(match("acme", "app", vee="2.0"))]), cve(2, Y, cwe=None), cve(3, Y, cvss=None)])
    net.add_cve_unit("nvdcve-2.0-modified", [])
    # the previous year's file is missing -> the dataset must NOT be reported complete
    r = run("full", ["cve"])
    with db.connect() as c:
        info = ii.dataset_info(c, "cve")
        assert info["status"] == "partial" and info["units_done"] == 1 and info["units_total"] == 2
        assert c.execute("SELECT status FROM intel_import_run WHERE id=?", (r["run_id"],)).fetchone()[0] == "partial"
    assert q1("SELECT COUNT(*) FROM nvd_cve") == 3 and q1("SELECT COUNT(*) FROM cve_cwe") == 2 and q1("SELECT COUNT(*) FROM cve_ref") == 3 and q1("SELECT COUNT(*) FROM cve_cpe") == 1
    assert q1("SELECT COUNT(*) FROM nvd_cve WHERE cvss IS NOT NULL") == 2
    net.add_cve_unit(f"nvdcve-2.0-{Y - 1}", [cve(1, Y - 1)])
    run("resume")
    with db.connect() as c:
        assert ii.dataset_info(c, "cve")["status"] == "complete"
    assert q1("SELECT COUNT(*) FROM nvd_cve") == 4
    assert net.files().count(f"{FEEDS}/cve/2.0/nvdcve-2.0-{Y}.json.gz") == 1          # the finished unit was not downloaded again


def test_no_download_is_started_by_the_normal_startup_path(env):
    assert q1("SELECT COUNT(*) FROM intel_import_run") == 0 and env.fetched == []
    assert ii.scheduled_tick() is None                                                  # an uninitialised database is never auto-imported
    with db.connect() as c:
        assert all(ii.dataset_info(c, d)["status"] == "not_initialized" for d in ii.DATASETS)


def test_hash_mismatch_rejects_the_file_without_touching_existing_data(env):
    net = env
    cves_for_years(net)
    run("full", ["cve"])
    before = q1("SELECT COUNT(*) FROM nvd_cve")
    net.add_cve_unit("nvdcve-2.0-modified", [cve(1, Y, mod=NOW, desc="TAMPERED")])
    net.sha_override["nvdcve-2.0-modified"] = "0" * 64
    net.add_cve_unit("nvdcve-2.0-modified", [cve(1, Y, mod=NOW, desc="TAMPERED")])
    r = run("incremental", ["cve"])
    assert q1("SELECT COUNT(*) FROM nvd_cve") == before and "TAMPERED" not in str(q1("SELECT description FROM nvd_cve WHERE cve_id=?", f"CVE-{Y}-0001"))
    with db.connect() as c:
        assert "sha256" in (ii.dataset_info(c, "cve")["last_error"] or "") and c.execute("SELECT status FROM intel_import_run WHERE id=?", (r["run_id"],)).fetchone()[0] == "partial"


def test_failed_download_keeps_everything_previously_imported(env):
    net = env
    cves_for_years(net)
    run("full", ["cve"])
    before = q1("SELECT COUNT(*) FROM nvd_cve")
    net.fail[f"{FEEDS}/cve/2.0/nvdcve-2.0-modified.json.gz"] = FeedError("HTTP 503", 1)
    net.add_cve_unit("nvdcve-2.0-modified", [cve(9, Y)])
    run("incremental", ["cve"])
    assert q1("SELECT COUNT(*) FROM nvd_cve") == before
    with db.connect() as c:
        assert ii.dataset_info(c, "cve")["status"] == "complete" and "503" in ii.dataset_info(c, "cve")["last_error"]      # data intact; the error is reported


def test_interrupted_import_resumes_from_its_checkpoint_without_duplicates(env, monkeypatch):
    net = env
    net.add_cve_unit(f"nvdcve-2.0-{Y}", [cve(i, Y) for i in range(1, 11)])
    net.add_cve_unit(f"nvdcve-2.0-{Y - 1}", [cve(1, Y - 1)])
    net.add_cve_unit("nvdcve-2.0-modified", [])
    real, calls = ii.apply_cve, [0]

    def flaky(con, item, ctx):
        calls[0] += 1
        if calls[0] == 8:
            raise RuntimeError("power cut")
        return real(con, item, ctx)
    monkeypatch.setattr(ii, "apply_cve", flaky)
    r = run("full", ["cve"])
    with db.connect() as c:
        st = c.execute("SELECT status,message FROM intel_import_run WHERE id=?", (r["run_id"],)).fetchone()
        cp = json.loads(ii._ds_row(c, "cve")["checkpoint"])
    assert st[0] == "partial" and "power cut" in st[1] and cp["unit"] == f"nvdcve-2.0-{Y}" and cp["items_done"] == 6 and cp["verified"]
    done_before = q1("SELECT COUNT(*) FROM nvd_cve")
    assert done_before == 6                                                       # whole batches only: the failed batch was rolled back
    monkeypatch.setattr(ii, "apply_cve", real)
    run("resume")
    assert q1("SELECT COUNT(*) FROM nvd_cve") == 11 and q1("SELECT COUNT(DISTINCT cve_id) FROM nvd_cve") == 11
    assert net.files().count(f"{FEEDS}/cve/2.0/nvdcve-2.0-{Y}.json.gz") == 1      # the verified temp file was reused (no second download)
    with db.connect() as c:
        assert ii.dataset_info(c, "cve")["status"] == "complete" and ii._ds_row(c, "cve")["checkpoint"] is None


def test_stop_request_ends_the_run_as_interrupted_and_it_can_be_resumed(env, monkeypatch):
    net = env
    cves_for_years(net, 10)
    real = ii.apply_cve

    def stopper(con, item, ctx):
        ii.request_stop()
        return real(con, item, ctx)
    monkeypatch.setattr(ii, "apply_cve", stopper)
    r = run("full", ["cve"])
    assert q1("SELECT status FROM intel_import_run WHERE id=?", r["run_id"]) == "interrupted"
    monkeypatch.setattr(ii, "apply_cve", real)
    run("resume")
    assert q1("SELECT COUNT(*) FROM nvd_cve") == 20


def test_incremental_updates_dedup_and_removal_of_rejected_cves(env):
    net = env
    cves_for_years(net)
    run("full", ["cve"])
    base = q1("SELECT COUNT(*) FROM nvd_cve")
    later = NOW
    net.add_cve_unit("nvdcve-2.0-modified", [cve(1, Y, mod=later, desc="Updated text", cvss=9.9, confs=[conf(match("acme", "app", vee="3.0"))]), cve(2, Y), cve(99, Y), cve(3, Y, status="Rejected")])
    r = run("incremental", ["cve"])
    with db.connect() as c:
        run_row = c.execute("SELECT new_items,updated_items FROM intel_import_run WHERE id=?", (r["run_id"],)).fetchone()
        assert tuple(run_row) == (1, 2)                                        # 1 new (99), 1 updated (1) + 1 removed (3); CVE-2 unchanged
        assert c.execute("SELECT description,cvss FROM nvd_cve WHERE cve_id=?", (f"CVE-{Y}-0001",)).fetchone()[:] == ("Updated text", 9.9)
        assert c.execute("SELECT COUNT(*) FROM cve_cpe WHERE cve_id=?", (f"CVE-{Y}-0001",)).fetchone()[0] == 1
        assert c.execute("SELECT 1 FROM nvd_cve WHERE cve_id=?", (f"CVE-{Y}-0003",)).fetchone() is None
    assert q1("SELECT COUNT(*) FROM nvd_cve") == base                           # +1 new -1 rejected
    n = len(net.files())
    run("incremental", ["cve"])                                                 # same .meta hash: nothing is downloaded again
    assert len(net.files()) == n
    net.add_cve_unit("nvdcve-2.0-recent", [cve(1, Y, mod=later)])               # same lastModified as stored: unchanged
    run("incremental", ["cve"])
    assert q1("SELECT COUNT(*) FROM nvd_cve WHERE cve_id=?", f"CVE-{Y}-0001") == 1 and q1("SELECT COUNT(*) FROM cve_ref WHERE cve_id=?", f"CVE-{Y}-0001") == 1


def test_invalid_records_are_skipped_and_reported_not_fatal(env):
    net = env
    bad = {"cve": {"id": "garbage"}}
    net.add_cve_unit(f"nvdcve-2.0-{Y}", [cve(1, Y), bad, cve(2, Y)])
    net.add_cve_unit(f"nvdcve-2.0-{Y - 1}", [])
    net.add_cve_unit("nvdcve-2.0-modified", [])
    r = run("full", ["cve"])
    assert q1("SELECT COUNT(*) FROM nvd_cve") == 2 and q1("SELECT errors FROM intel_import_run WHERE id=?", r["run_id"]) == 1
    assert q1("SELECT COUNT(*) FROM intel_import_error WHERE run_id=?", r["run_id"]) == 1


def test_only_one_import_runs_at_a_time(env):
    assert ii._lock.acquire(blocking=False)
    try:
        assert ii.start("full", ["kev"]) == {"started": False, "reason": "already_running"}
    finally:
        ii._lock.release()


# ---------------------------------------------------------------- CPE dictionary & match criteria
def test_cpe_dictionary_and_match_criteria_import_with_bounds_and_dedup(env):
    net = env
    cpes = [{"cpe": {"deprecated": False, "cpeName": "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*", "cpeNameId": "AAA-1", "lastModified": "2020-01-01T00:00:00.000", "created": "2019-01-01T00:00:00.000",
                     "titles": [{"title": "Apache Log4j 2.14.1", "lang": "en"}], "refs": [{"ref": "https://logging.apache.org"}]}},
            {"cpe": {"deprecated": True, "cpeName": "cpe:2.3:a:apache:log4j:1.0:*:*:*:*:*:*:*", "cpeNameId": "AAA-2", "lastModified": "2020-01-01T00:00:00.000"}}, {"cpe": {"cpeName": "x"}}]
    net.add_tar("cpe/2.0", "nvdcpe-2.0", "products", cpes)
    ms = [{"matchString": {"matchCriteriaId": "M-1", "criteria": "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*", "versionStartIncluding": "2.0.1", "versionEndExcluding": "2.3.1", "status": "Active",
                           "lastModified": "2020-01-01T00:00:00.000", "matches": [{"cpeName": "a", "cpeNameId": "AAA-1"}, {"cpeName": "b", "cpeNameId": "AAA-2"}]}},
          {"matchString": {"matchCriteriaId": "M-2", "criteria": "cpe:2.3:a:apache:log4j:2.0:*:*:*:*:*:*:*", "status": "Active", "lastModified": "2020-01-01T00:00:00.000"}}]
    net.add_tar("cpematch/2.0", "nvdcpematch-2.0", "matchStrings", ms, sha_of="gz")        # the archive hash is also accepted
    run("full", ["cpe", "cpematch"])
    with db.connect() as c:
        d = c.execute("SELECT vendor,product,version,deprecated,title FROM cpe_dictionary WHERE cpe_name_id='AAA-1'").fetchone()
        assert tuple(d) == ("apache", "log4j", "2.14.1", 0, "Apache Log4j 2.14.1") and c.execute("SELECT deprecated FROM cpe_dictionary WHERE cpe_name_id='AAA-2'").fetchone()[0] == 1
        m = c.execute("SELECT vsi,vee,match_count,status FROM cpe_match_criteria WHERE mc_id='M-1'").fetchone()
        assert tuple(m) == ("2.0.1", "2.3.1", 2, "Active") and c.execute("SELECT version FROM cpe_match_criteria WHERE mc_id='M-2'").fetchone()[0] == "2.0"
        assert ii.dataset_info(c, "cpe")["status"] == "complete" and ii.dataset_info(c, "cpematch")["status"] == "complete"
        assert c.execute("SELECT COUNT(*) FROM intel_import_error").fetchone()[0] == 1                     # the record without cpeNameId
    # re-importing the same archive creates nothing new (idempotent / dedup)
    with db.connect() as c:
        c.execute("DELETE FROM intel_unit")
    run("full", ["cpe", "cpematch"])
    assert q1("SELECT COUNT(*) FROM cpe_dictionary") == 2 and q1("SELECT COUNT(*) FROM cpe_match_criteria") == 2
    # a tampered archive (hash matches neither the archive nor the tar stream) is refused
    net.text[f"{FEEDS}/cpe/2.0/nvdcpe-2.0.meta"] = net.text[f"{FEEDS}/cpe/2.0/nvdcpe-2.0.meta"].replace("sha256:", "sha256:00")
    with db.connect() as c:
        c.execute("DELETE FROM intel_unit WHERE dataset='cpe'")
    run("full", ["cpe"])
    with db.connect() as c:
        assert "sha256" in ii.dataset_info(c, "cpe")["last_error"]


def test_cpe_search_offers_candidates_without_confirming_anything(env):
    with db.connect() as c:
        c.executemany("INSERT INTO cpe_dictionary(cpe_name_id,cpe_name,part,vendor,product,version,title) VALUES(?,?,?,?,?,?,?)",
                      [("1", "cpe:2.3:a:acme:widget:1:*:*:*:*:*:*:*", "a", "acme", "widget", "1", "Acme Widget"), ("2", "cpe:2.3:a:acme:widget:2:*:*:*:*:*:*:*", "a", "acme", "widget", "2", "Acme Widget"),
                       ("3", "cpe:2.3:a:other:widget_pro:1:*:*:*:*:*:*:*", "a", "other", "widget_pro", "1", "Widget Pro"), ("4", "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*", "a", "apache", "log4j", "2.14.1", "Log4j")])
        r = intel_corr.search_cpe(c, "widget")
        assert {(x["vendor"], x["product"]) for x in r["items"]} == {("acme", "widget"), ("other", "widget_pro")} and "never confirmed automatically" in r["note"]
        assert next(x for x in intel_corr.search_cpe(c, "log4j")["items"])["already_in_catalog"] == "apache-log4j"
        assert intel_corr.search_cpe(c, "x")["items"] == [] and intel_corr.cpe_exists(c, "acme", "widget") is True and intel_corr.cpe_exists(c, "acme", "nope") is False


# ---------------------------------------------------------------- stage 2: KEV & EPSS
def kev_payload(*rows):
    return json.dumps({"title": "k", "vulnerabilities": [{"cveID": c, "vendorProject": v, "product": p, "vulnerabilityName": n, "dateAdded": d, "shortDescription": f"short {c}", "requiredAction": "Apply updates.",
                                                           "dueDate": "2022-01-01", "knownRansomwareCampaignUse": r, "notes": "n", "cwes": ["CWE-20"]} for c, v, p, n, d, r in rows]})


def test_kev_import_keeps_full_catalogue_with_actions_and_never_duplicates(env, monkeypatch):
    net = env
    net.text[ii.kev_c.URL] = kev_payload(("CVE-2021-44228", "Apache", "Log4j2", "Log4Shell", "2021-12-10", "Known"), ("CVE-2020-0001", "Acme", "App", "x", "2022-01-01", "Unknown"))
    run("enrichment", ["kev"])
    with db.connect() as c:
        k = c.execute("SELECT vendor,product,date_added,ransomware,description,required_action,due_date,notes,cwes FROM kev_entry WHERE cve_id='CVE-2021-44228'").fetchone()
    assert tuple(k) == ("Apache", "Log4j2", "2021-12-10", 1, "short CVE-2021-44228", "Apply updates.", "2022-01-01", "n", "CWE-20")
    run("enrichment", ["kev"])
    assert q1("SELECT COUNT(*) FROM kev_entry") == 2
    net.text[ii.kev_c.URL] = "{not json"
    run("enrichment", ["kev"])                                                     # an invalid payload leaves the catalogue untouched
    assert q1("SELECT COUNT(*) FROM kev_entry") == 2
    with db.connect() as c:
        assert ii.dataset_info(c, "kev")["last_error"] and ii.dataset_info(c, "kev")["status"] == "complete"


def epss_gz(rows, date="2026-11-17", model="v2026.06.15", header="cve,epss,percentile"):
    return gzip.compress((f"#model_version:{model},score_date:{date}T12:00:00Z\n{header}\n" + "\n".join(rows) + "\n").encode())


def test_epss_bulk_import_keeps_date_model_and_survives_bad_rows(env):
    net = env
    net.gz[ii.EPSS_URL] = epss_gz(["CVE-2021-44228,0.99999,1.0", "CVE-2020-0001,0.5,0.7", "BAD,1,1", "CVE-2020-0002,2.0,0.1"])
    r = run("enrichment", ["epss"])
    with db.connect() as c:
        e = c.execute("SELECT score,percentile,score_date,model_version FROM epss WHERE cve_id='CVE-2021-44228'").fetchone()
        assert tuple(e) == (0.99999, 1.0, "2026-11-17", "v2026.06.15") and c.execute("SELECT COUNT(*) FROM epss").fetchone()[0] == 2
        assert c.execute("SELECT errors FROM intel_import_run WHERE id=?", (r["run_id"],)).fetchone()[0] == 1
        assert ii.dataset_info(c, "epss")["dataset_date"] == "2026-11-17"
    net.gz[ii.EPSS_URL] = epss_gz(["CVE-2021-44228,0.5,0.5"], date="2026-11-18")
    run("enrichment", ["epss"])
    assert q1("SELECT score_date FROM epss WHERE cve_id='CVE-2021-44228'") == "2026-11-18" and q1("SELECT COUNT(*) FROM epss") == 2        # last snapshot per CVE; others untouched
    net.gz[ii.EPSS_URL] = epss_gz(["x"], header="a,b,c")
    run("enrichment", ["epss"])
    assert q1("SELECT score FROM epss WHERE cve_id='CVE-2021-44228'") == 0.5                                                           # a bad file never replaces good data
    with db.connect() as c:
        assert "header" in ii.dataset_info(c, "epss")["last_error"]


def test_epss_history_retention_is_configurable_and_off_by_default(env):
    net = env
    net.gz[ii.EPSS_URL] = epss_gz(["CVE-2020-0001,0.1,0.2"], date="2026-11-10")
    run("enrichment", ["epss"])
    assert q1("SELECT COUNT(*) FROM epss_history") == 0
    object.__setattr__(settings, "epss_history_days", 30)
    try:
        for d in ("2026-11-11", "2026-11-12"):
            net.gz[ii.EPSS_URL] = epss_gz(["CVE-2020-0001,0.3,0.4"], date=d)
            run("enrichment", ["epss"])
        assert q1("SELECT COUNT(*) FROM epss_history WHERE cve_id='CVE-2020-0001'") == 2
    finally:
        object.__setattr__(settings, "epss_history_days", 0)


def test_dataset_status_machine_includes_stale_and_failed(env):
    net = env
    with db.connect() as c:
        assert ii.dataset_info(c, "epss")["status"] == "not_initialized"
    net.fail[ii.EPSS_URL] = FeedError("HTTP 404", fatal=True)
    run("enrichment", ["epss"])
    with db.connect() as c:
        assert ii.dataset_info(c, "epss")["status"] == "failed"
    del net.fail[ii.EPSS_URL]
    net.gz[ii.EPSS_URL] = epss_gz(["CVE-2020-0001,0.1,0.2"])
    run("enrichment", ["epss"])
    with db.connect() as c:
        assert ii.dataset_info(c, "epss")["status"] == "complete"
        c.execute("UPDATE intel_dataset SET last_success=? WHERE key='epss'", ((NOW - timedelta(days=5)).isoformat(),))
        assert ii.dataset_info(c, "epss")["status"] == "stale"


# ---------------------------------------------------------------- stage 3: correlation
def import_log4j(net, extra=()):
    ii.FIRST_YEAR = 2021                                                           # restored by the fixture's monkeypatch
    for y in range(2022, Y - 1):
        net.add_cve_unit(f"nvdcve-2.0-{y}", [])
    net.add_cve_unit(f"nvdcve-2.0-{Y}", [cve(1, Y, pub=NOW - timedelta(days=10), confs=[conf(match("linux", "linux_kernel", vee="6.9"))], cvss=8.0), *extra])
    net.add_cve_unit(f"nvdcve-2.0-{Y - 1}", [cve(1, Y - 1)])
    net.add_cve_unit("nvdcve-2.0-modified", [])
    net.text[ii.kev_c.URL] = kev_payload(("CVE-2021-44228", "Apache", "Log4j2", "Log4Shell", "2021-12-10", "Known"))
    net.gz[ii.EPSS_URL] = epss_gz(["CVE-2021-44228,0.99999,1.0", f"CVE-{Y}-0001,0.4,0.9"])
    log4shell = cve(44228, 2021, pub=datetime(2021, 12, 10, tzinfo=timezone.utc), cvss=10.0, cwe="CWE-502", confs=LOG4J)
    net.add_cve_unit(f"nvdcve-2.0-2021", [log4shell])
    return log4shell


def test_log4j_cve_2021_44228_is_served_locally_with_no_external_nvd_call(env, monkeypatch):
    net = env
    import_log4j(net)
    for name in ("fetch_page", "fetch_by_cpe", "fetch_cve", "_call"):                          # any live NVD API use would blow up
        monkeypatch.setattr(techsync.nvd_c, name, lambda *a, **k: (_ for _ in ()).throw(AssertionError("external NVD call")))
    run("full", ["cve", "kev", "epss"])
    with db.connect() as c:
        hist = c.execute("SELECT applicability,match_source FROM tech_cve_hist WHERE tech_id='apache-log4j' AND cve_id='CVE-2021-44228'").fetchone()
        assert tuple(hist) == ("versioned", "nvd-cpe")
        t = service.build_technology(c, "apache-log4j", detail=True)
        assert t["sync"]["status"] in ("completed", "partial") and t["historical"]["count"] >= 1 and t["historical"]["kev"] == 1 and t["score"] is None       # history is shown, not scored
        assert t["historical"]["scored"] is False and t["cves_known"] >= 1
        d = vulns.detail(c, "CVE-2021-44228")
    assert d["epss"] == 0.99999 and d["epss_date"] == "2026-11-17" and d["in_kev"] and d["kev"]["required_action"] == "Apply updates." and d["cwes"][0]["id"] == "CWE-502"
    assert d["references"] and any(a["vendor"] == "apache" and a["product"] == "log4j" and a["from_incl"] == "2.0.1" for a in d["affected"]) and d["nvd"]["has_configuration"]
    assert {h["id"] for h in d["historical_techs"]} == {"apache-log4j"}


def test_technology_added_after_the_import_needs_no_external_request(env, monkeypatch):
    net = env
    import_log4j(net, extra=[cve(7, Y, pub=NOW - timedelta(days=5), confs=[conf(match("acme", "widget", vee="2.0"))]), cve(8, 2015, confs=[conf(match("acme", "widget", vee="1.0"))]),
                              cve(9, 2016, confs=[conf(match("acme", "widgetx"))])])
    run("full", ["cve"])
    with db.connect() as c:
        assert c.execute("SELECT COUNT(*) FROM tech_cve_hist WHERE cve_id LIKE 'CVE-2015%'").fetchone()[0] == 0
    for name in ("fetch_page", "fetch_by_cpe", "fetch_cve", "_call"):
        monkeypatch.setattr(techsync.nvd_c, name, lambda *a, **k: (_ for _ in ()).throw(AssertionError("external NVD call")))
    client = TestClient(app, client=("127.0.0.1", 1))
    r = client.post("/api/v1/catalog", json={"id": "acme-widget", "name": "Acme Widget", "category": "Enterprise Applications", "kind": "product", "cpe_part": "a", "cpe_vendor": "acme", "cpe_product": "widget"})
    assert r.status_code == 201
    d = client.get("/api/v1/catalog/acme-widget").json()
    assert d["recent_cve_count"] == 1 and d["historical_cve_count"] == 1 and "found in the local NVD data" in d["correlation"]["source"]
    ids = {x["cve_id"] for x in d["historical"]["items"]} | {x["id"] for x in d["cves"]}
    assert ids == {f"CVE-{Y}-0007", "CVE-2015-0008"}                                                  # exact product only: 'widgetx' and vendor-only never match
    assert client.get("/api/v1/catalog/cpe-search?q=widget").status_code == 200


def test_version_specific_cves_are_not_assigned_to_every_version(env):
    net = env
    import_log4j(net)
    run("full", ["cve"])
    client = TestClient(app, client=("127.0.0.1", 1))
    ids = {}
    for name, ver in (("old", "2.14.1"), ("fixed", "2.17.1"), ("unknown", None)):
        cid = client.post("/api/v1/companies", json={"name": name, "industry": "x"}).json()["id"]
        client.post(f"/api/v1/companies/{cid}/assets", json={"tech_id": "apache-log4j", "version": ver})
        ids[name] = cid
    st = lambda n: {x["id"]: x["effective_status"] for x in client.get(f"/api/v1/companies/{ids[n]}/vulnerabilities").json()["items"]}["CVE-2021-44228"]  # noqa: E731
    assert st("old") == "potentially_applicable" and st("fixed") == "not_applicable" and st("unknown") == "insufficient_data"


FORTI_AND = [{"operator": "AND", "nodes": [{"operator": "OR", "negate": False, "cpeMatch": [match("fortinet", "fortios", vee="7.2.0")]},
                                           {"operator": "OR", "negate": False, "cpeMatch": [match("fortinet", "fortigate_100e", part="h", vulnerable=False)]}]}]


def test_complex_configurations_never_produce_false_confirmations():
    prod = exposure.Product("fortinet", None, None)
    a = lambda v: exposure.assess_from_config({"version": v}, prod, FORTI_AND)["status"]  # noqa: E731
    assert a("7.0.5") == exposure.REVIEW and a("7.4.1") == exposure.NOT_APPLICABLE                          # inside range but conditional -> review; outside -> not applicable
    assert exposure.assess_from_config({}, prod, FORTI_AND)["status"] == exposure.INSUFFICIENT
    neg = [{"nodes": [{"operator": "OR", "negate": True, "cpeMatch": [match("fortinet", "fortios", vee="7.2.0")]}]}]
    assert exposure.assess_from_config({"version": "7.0.5"}, prod, neg)["status"] == exposure.REVIEW
    simple = [conf(match("fortinet", "fortios", vee="7.2.0"))]
    assert exposure.assess_from_config({"version": "7.0.5"}, prod, simple)["status"] == exposure.POTENTIAL
    assert exposure.assess_from_config({"version": "7.0.5-beta"}, prod, simple)["status"] == exposure.REVIEW
    two = [conf(match("fortinet", "fortios", vee="7.2.0"), match("fortinet", "fortiweb", vee="9.0"))]
    assert exposure.assess_from_config({"version": "7.0.5"}, prod, two)["status"] == exposure.REVIEW      # a family cannot borrow another member's range
    assert exposure.assess_from_config({"version": "7.0.5"}, exposure.Product(None, "fortinet", "fortios"), two)["status"] == exposure.POTENTIAL
    other = [conf(match("acme", "app", vee="9"))]
    assert exposure.assess_from_config({"version": "1.0"}, prod, other)["status"] == exposure.REVIEW


def test_manual_assessments_survive_imports_and_rebuilds(env):
    net = env
    import_log4j(net)
    run("full", ["cve"])
    client = TestClient(app, client=("127.0.0.1", 1))
    cid = client.post("/api/v1/companies", json={"name": "A", "industry": "x"}).json()["id"]
    client.post(f"/api/v1/companies/{cid}/assets", json={"tech_id": "apache-log4j", "version": "2.14.1"})
    ct = client.get(f"/api/v1/companies/{cid}/inventory").json()["technologies"][0]["id"]
    r = client.put(f"/api/v1/companies/{cid}/vulnerabilities/CVE-2021-44228/assessment", json={"company_tech_id": ct, "status": "confirmed_applicable", "evidence": "Verified on host LOG-01 by the audit team"})
    assert r.status_code == 200
    net.add_cve_unit("nvdcve-2.0-modified", [cve(44228, 2021, pub=datetime(2021, 12, 10, tzinfo=timezone.utc), mod=NOW, cvss=10.0, confs=LOG4J)])
    run("incremental", ["cve"])
    intel_corr.rebuild()
    f = client.get(f"/api/v1/companies/{cid}/vulnerabilities/CVE-2021-44228").json()
    assert f["effective_status"] == "confirmed_applicable" and f["history"][0]["new_status"] == "confirmed_applicable" and f["products"][0]["automatic_status"] == "potentially_applicable"


# ---------------------------------------------------------------- scoring, explorer, integration
def test_threat_signal_score_is_unchanged_by_history_and_caches_are_invalidated(env, monkeypatch):
    calls = []
    monkeypatch.setattr(techsync, "invalidate_caches", lambda: calls.append(1))
    net = env
    import_log4j(net, extra=[cve(5, Y, pub=NOW - timedelta(days=4), confs=[conf(match("linux", "linux_kernel", vee="6.1"))], cvss=9.0)])
    with db.connect() as c:
        c.execute("INSERT INTO query_log(key,last_success,total_results,truncated) VALUES('cpe:2.3:o:linux:linux_kernel',?,1,0)", (NOW.isoformat(),))
    run("full", ["cve", "epss"])
    assert calls                                                                  # pyramids/caches are refreshed after new intelligence arrives
    with db.connect() as c:
        s1 = service.build_technology(c, "linux")["score"]
        assert s1 is not None
        before = s1
        c.execute("INSERT INTO tech_cve_hist(tech_id,cve_id,product,match_source,applicability) VALUES('linux','CVE-2010-9','linux linux_kernel','nvd-cpe','product')")
        c.execute("INSERT INTO nvd_cve(cve_id,published,cvss,cvss_version,description,cpes,fetched_at) VALUES('CVE-2010-9','2010-01-01T00:00:00',10.0,'2.0','old','o:linux:linux_kernel','x')")
        assert service.build_technology(c, "linux")["score"] == before              # 1,000 old CVEs would not change it either: volume is never summed


def test_explorer_fast_index_matches_the_live_view_and_uses_local_products(env):
    net = env
    import_log4j(net)
    run("full", ["cve", "kev", "epss"])
    with db.connect() as c:
        assert vulns.index_ready(c) and c.execute("SELECT COUNT(*) FROM cve_product_stats").fetchone()[0] > 0
        fast = vulns.search(c, vendor="apache", product="log4j")
        kev = vulns.search(c, kev=True)
        high = vulns.search(c, cvss_min=9, epss_min=0.9)
        c.execute("DELETE FROM cve_index")                                           # same answers from the slow live view
        slow = vulns.search(c, vendor="apache", product="log4j")
    assert [i["id"] for i in fast["items"]] == [i["id"] for i in slow["items"]] == ["CVE-2021-44228"] and fast["total"] == slow["total"] == 1
    assert kev["items"][0]["id"] == "CVE-2021-44228" and kev["items"][0]["epss_date"] == "2026-11-17" and high["total"] == 1
    client = TestClient(app, client=("127.0.0.1", 1))
    assert client.get("/api/v1/vulns/facets").json()["vendors"] and client.get("/api/v1/vulns?tech=apache-log4j").json()["total"] == 1
    assert client.get("/api/v1/graph/search?q=log4j").status_code == 200 and client.get("/api/v1/vulns/CVE-2021-44228").json()["cwes"]


def test_graph_resolves_products_from_the_sql_index(env):
    net = env
    import_log4j(net)
    run("full", ["cve"])
    client = TestClient(app, client=("127.0.0.1", 1))
    r = client.get("/api/v1/graph/neighbors?node=product:apache:log4j").json()
    assert any(n["id"] == "cve:CVE-2021-44228" for n in r["nodes"]) and client.get("/api/v1/graph/neighbors?node=cve:CVE-2021-44228").status_code == 200


# ---------------------------------------------------------------- API & administration
def test_admin_api_status_estimate_confirmation_and_guards(env, monkeypatch):
    local, remote = TestClient(app, client=("127.0.0.1", 1)), TestClient(app)
    s = local.get("/api/v1/intel-db/status").json()
    assert s["overall"] == "not_initialized" and s["counts"]["cves"] == 0 and s["database_bytes"] > 0 and set(s["datasets"]) == set(ii.DATASETS) and s["active_run"] is None
    assert remote.post("/api/v1/intel-db/initialize", json={"confirm": True}).status_code == 403
    assert remote.get("/api/v1/intel-db/estimate").status_code == 403
    assert local.post("/api/v1/intel-db/initialize", json={"confirm": False}).status_code == 422                 # no accidental mass download
    assert local.post("/api/v1/intel-db/initialize", json={"confirm": True, "datasets": ["evil"]}).status_code == 422
    assert local.post("/api/v1/intel-db/sync").status_code == 409                                                  # needs Initialize first
    monkeypatch.setattr(ii, "estimate", lambda: {"datasets": [], "download_bytes": 1, "enough_space": True, "warning": "w"})
    assert local.get("/api/v1/intel-db/estimate").json()["warning"] == "w"
    assert local.post("/api/v1/intel-db/stop").json()["requested"] is True
    monkeypatch.setattr(ii, "start", lambda mode, ds=None, wait=False: {"started": True, "run_id": 1, "datasets": ds or [], "mode": mode})
    assert local.post("/api/v1/intel-db/initialize", json={"confirm": True, "datasets": ["kev"]}).status_code == 202
    assert local.post("/api/v1/intel-db/epss").status_code == 202 and local.post("/api/v1/intel-db/kev").status_code == 202 and local.post("/api/v1/intel-db/resume").status_code == 202


def test_status_reports_real_counts_and_partial_is_never_complete(env):
    net = env
    import_log4j(net)
    run("full", ["cve", "kev", "epss"])
    local = TestClient(app, client=("127.0.0.1", 1))
    s = local.get("/api/v1/intel-db/status").json()
    c = s["counts"]
    assert c["cves"] >= 3 and c["cves_with_cvss"] >= 3 and c["cves_with_cwe"] >= 3 and c["cves_in_kev"] == 1 and c["cves_with_epss"] == 2 and c["epss_score_date"] == "2026-11-17"
    assert s["overall"] == "partial" and s["datasets"]["cve"]["status"] == "complete" and s["datasets"]["cpe"]["status"] == "not_initialized"      # datasets never imported: the database is NOT complete
    assert s["last_successful_sync"] and s["recent_runs"][0]["status"] in ("completed", "partial")
    assert local.get(f"/api/v1/intel-db/runs/{s['recent_runs'][0]['id']}/errors").status_code == 200


def test_migration_from_the_previous_schema_is_additive_and_idempotent(tmp_path):
    import sqlite3
    p = tmp_path / "old.sqlite"
    con = sqlite3.connect(p)
    con.executescript("CREATE TABLE nvd_cve(cve_id TEXT PRIMARY KEY, published TEXT, last_modified TEXT, cvss REAL, cvss_version TEXT, description TEXT, cpes TEXT NOT NULL DEFAULT '', fetched_at TEXT NOT NULL);"
                      "INSERT INTO nvd_cve VALUES('CVE-2020-0001','2020-01-01','2020-01-02',7.5,'3.1','old row','a:x:y','t');"
                      "CREATE TABLE kev_entry(cve_id TEXT PRIMARY KEY, vendor TEXT, product TEXT, name TEXT, date_added TEXT, ransomware INTEGER DEFAULT 0);"
                      "INSERT INTO kev_entry VALUES('CVE-2020-0001','V','P','n','2020-01-05',1);"
                      "CREATE TABLE epss(cve_id TEXT PRIMARY KEY, score REAL, percentile REAL, score_date TEXT, fetched_at TEXT NOT NULL);")
    con.commit()
    con.close()
    object.__setattr__(settings, "db_path", str(p))
    try:
        db.init_db()
        db.init_db()
        with db.connect() as c:
            cols = {r[1] for r in c.execute("PRAGMA table_info(nvd_cve)")}
            assert {"config_json", "complex_config", "vuln_status", "origin"} <= cols and {"required_action", "due_date"} <= {r[1] for r in c.execute("PRAGMA table_info(kev_entry)")}
            assert c.execute("SELECT description FROM nvd_cve").fetchone()[0] == "old row" and c.execute("SELECT ransomware FROM kev_entry").fetchone()[0] == 1       # data preserved
            assert c.execute("SELECT COUNT(*) FROM technology").fetchone()[0] >= 100
    finally:
        object.__setattr__(settings, "db_path", str(tmp_path / "unused.sqlite"))


def test_legacy_rows_are_upgraded_by_the_first_import_of_the_same_cve(env):
    net = env
    with db.connect() as c:
        c.execute("INSERT INTO nvd_cve(cve_id,published,last_modified,cvss,cvss_version,description,cpes,fetched_at) VALUES(?,?,?,?,?,?,?,?)",
                  (f"CVE-{Y}-0001", TS(datetime(Y, 3, 1, tzinfo=timezone.utc)), TS(datetime(Y, 3, 1, tzinfo=timezone.utc)), 5.0, "3.1", "legacy", "", "t"))
    net.add_cve_unit(f"nvdcve-2.0-{Y}", [cve(1, Y, confs=[conf(match("acme", "app", vee="2.0"))])])
    net.add_cve_unit(f"nvdcve-2.0-{Y - 1}", [])
    net.add_cve_unit("nvdcve-2.0-modified", [])
    run("full", ["cve"])
    with db.connect() as c:
        r = c.execute("SELECT description,config_json,origin FROM nvd_cve WHERE cve_id=?", (f"CVE-{Y}-0001",)).fetchone()
    assert r[0] == f"Description of CVE-{Y}-0001" and r[1] and r[2]                                              # same last_modified, but the legacy row had no configuration: upgraded
    assert q1("SELECT COUNT(*) FROM nvd_cve") == 1


def test_initialize_refuses_when_the_disk_is_too_small(env, monkeypatch):
    from app import intel_api
    monkeypatch.setattr(intel_api, "disk", lambda: {"disk_free_bytes": int(1e9), "database_bytes": 0})
    object.__setattr__(settings, "intel_min_free_gb", 6.0)
    c = TestClient(app, client=("127.0.0.1", 1))
    r = c.post("/api/v1/intel-db/initialize", json={"confirm": True, "datasets": ["kev"]})
    assert r.status_code == 409 and "free on the disk" in r.json()["detail"]
    assert q1("SELECT COUNT(*) FROM intel_import_run") == 0                        # nothing was started
