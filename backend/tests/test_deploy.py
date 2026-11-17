"""Docker / self-hosting behaviour: access policy behind the bundled proxy, automatic KEV/EPSS bootstrap, and static checks of the distribution files."""
import json
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parent.parent
REPO = ROOT.parent
sys.path.insert(0, str(ROOT))

from app import db, intel_import as ii, security  # noqa: E402
from app.config import settings  # noqa: E402
from app.main import app  # noqa: E402


class Req:
    def __init__(self, host):
        self.client = type("C", (), {"host": host})() if host else None


@pytest.fixture()
def trust(monkeypatch):
    def set_(v):
        monkeypatch.setattr(settings, "trust_proxy", v, raising=False) if False else object.__setattr__(settings, "trust_proxy", v)
    old = settings.trust_proxy
    yield set_
    object.__setattr__(settings, "trust_proxy", old)


# ---------------------------------------------------------------- access policy behind the proxy
def test_loopback_is_always_local_and_public_addresses_never_are(trust):
    for t in (False, True):
        trust(t)
        assert security.is_local(Req("127.0.0.1")) and security.is_local(Req("::1")) and security.is_local(Req("localhost"))
        for bad in ("8.8.8.8", "93.184.216.34", "2001:4860:4860::8888", "not-an-ip", "", None):
            assert not security.is_local(Req(bad)), bad


def test_private_peers_count_as_local_only_when_the_proxy_is_trusted(trust):
    for ip in ("172.18.0.3", "10.0.0.5", "192.168.1.20", "fd00::5", "::ffff:172.18.0.3"):
        trust(False)
        assert not security.is_local(Req(ip)), ip                          # a bare uvicorn on a LAN keeps the old localhost-only rule
        trust(True)
        assert security.is_local(Req(ip)), ip
    trust(True)
    assert not security.is_local(Req("0.0.0.0")) and not security.is_local(Req("224.0.0.1"))


def test_admin_endpoints_work_through_the_proxy_network_but_not_from_the_internet(tmp_path, trust):
    object.__setattr__(settings, "db_path", str(tmp_path / "d.sqlite"))
    db.init_db()
    body = {"name": "Proxy test"}
    behind = TestClient(app, client=("172.18.0.3", 5555))
    trust(False)
    assert behind.post("/api/v1/categories", json=body).status_code == 403
    trust(True)
    assert behind.post("/api/v1/categories", json=body).status_code == 200
    internet = TestClient(app, client=("203.0.113.9", 5555))
    assert internet.post("/api/v1/categories", json={"name": "Nope"}).status_code == 403
    assert internet.get("/api/v1/categories").status_code == 200           # reads stay open, as before
    object.__setattr__(settings, "db_path", str(tmp_path / "unused.sqlite"))


def test_sync_token_still_overrides_the_network_rule(trust):
    trust(True)
    object.__setattr__(settings, "sync_token", "s3cret")
    try:
        with pytest.raises(Exception):
            security.authorize_sync(Req("172.18.0.3"), None)
        security.authorize_sync(Req("203.0.113.9"), "s3cret")
    finally:
        object.__setattr__(settings, "sync_token", None)


# ---------------------------------------------------------------- automatic KEV / EPSS, never the historical NVD import
@pytest.fixture()
def tdb(tmp_path):
    object.__setattr__(settings, "db_path", str(tmp_path / "b.sqlite"))
    db.init_db()
    yield
    object.__setattr__(settings, "db_path", str(tmp_path / "unused.sqlite"))


def test_empty_installation_fetches_only_kev_and_epss(tdb, monkeypatch):
    calls = []
    monkeypatch.setattr(ii, "start", lambda mode, datasets=None, wait=False: calls.append((mode, list(datasets or []))) or {"started": True})
    ii.bootstrap_enrichment()
    assert calls == [("enrichment", ["kev", "epss"])]
    assert not {"cve", "cpe", "cpematch"} & set(calls[0][1])                # the historical NVD import is never started automatically


def test_bootstrap_skips_fresh_data_retries_stale_data_and_can_be_disabled(tdb, monkeypatch):
    calls = []
    monkeypatch.setattr(ii, "start", lambda mode, datasets=None, wait=False: calls.append(list(datasets)) or {"started": True})
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    old = "2020-01-01T00:00:00+00:00"
    with db.connect() as c:
        for k, ts in (("kev", now), ("epss", old)):
            c.execute("INSERT OR REPLACE INTO intel_dataset(key,kind,status,last_success,updated_at) VALUES(?,?,?,?,?)", (k, k, "complete", ts, ts))
    ii.bootstrap_enrichment()
    assert calls == [["epss"]]                                              # KEV is fresh, EPSS is stale
    with db.connect() as c:
        c.execute("UPDATE intel_dataset SET last_success=? WHERE key='epss'", (now,))
    assert ii.bootstrap_enrichment() is None and calls == [["epss"]]
    object.__setattr__(settings, "auto_enrich", False)
    try:
        with db.connect() as c:
            c.execute("UPDATE intel_dataset SET last_success=? WHERE key='kev'", (old,))
        assert ii.bootstrap_enrichment() is None and len(calls) == 1
    finally:
        object.__setattr__(settings, "auto_enrich", True)


def test_bootstrap_leaves_an_initialised_nvd_database_to_the_regular_scheduler(tdb, monkeypatch):
    calls = []
    monkeypatch.setattr(ii, "start", lambda *a, **k: calls.append(a) or {"started": True})
    with db.connect() as c:
        c.execute("INSERT INTO intel_unit(dataset,unit,sha256,items,completed_at) VALUES('cve','nvdcve-2.0-2026','x',1,'2026-01-01T00:00:00+00:00')")
    assert ii.bootstrap_enrichment() is None and calls == []


def test_restart_does_not_duplicate_or_remigrate(tmp_path):
    object.__setattr__(settings, "db_path", str(tmp_path / "r.sqlite"))
    db.init_db()
    with db.connect() as c:
        before = [c.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0] for t in ("technology", "technology_category", "news_source", "app_meta")]
    for _ in range(3):
        db.init_db()
    with db.connect() as c:
        assert before == [c.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0] for t in ("technology", "technology_category", "news_source", "app_meta")]
        assert c.execute("SELECT COUNT(*) FROM intel_import_run").fetchone()[0] == 0      # a start-up never begins an import
    object.__setattr__(settings, "db_path", str(tmp_path / "unused.sqlite"))


def test_database_location_comes_from_the_environment(tmp_path):
    code = "import sys;sys.path.insert(0,r'%s');from app.config import settings;print(settings.db_path);print(settings.intel_tmp_dir)" % ROOT
    out = subprocess.run([sys.executable, "-I", "-c", code], capture_output=True, text=True, env={"DB_PATH": "/data/cache.sqlite", "INTEL_TMP_DIR": "/data/import_tmp", "SystemRoot": "C:\\Windows"}).stdout.split()
    assert out == ["/data/cache.sqlite", "/data/import_tmp"]


# ---------------------------------------------------------------- distribution files
def read(p: str) -> str:
    return (REPO / p).read_text(encoding="utf-8")


def test_compose_publishes_only_the_web_port_on_loopback_and_persists_data():
    import yaml
    c = yaml.safe_load(read("compose.yaml"))
    be, fe = c["services"]["backend"], c["services"]["frontend"]
    assert "ports" not in be and "8000" in [str(x) for x in be["expose"]]       # the API is never published
    assert fe["ports"] == ["127.0.0.1:${PYRAMID_PORT:-8080}:8080"]
    assert any(v.startswith("pyramid_data:/data") for v in be["volumes"]) and "pyramid_data" in c["volumes"]
    assert be["environment"]["DB_PATH"] == "/data/cache.sqlite" and be["environment"]["PYRAMID_TRUST_PROXY"] == "1"
    assert "healthcheck" in be and "healthcheck" in fe and be["restart"] == fe["restart"] == "unless-stopped"
    assert fe["depends_on"]["backend"]["condition"] == "service_healthy" and be["init"] is True
    assert set(c["services"]) == {"backend", "frontend"}                          # no extra containers (no database or cache service)


def test_backend_image_is_non_root_single_process_and_has_no_database():
    d = read("backend/Dockerfile")
    assert "USER pyramid" in d and "--workers\", \"1\"" in d and "HEALTHCHECK" in d and d.index("CMD [") > d.index("USER pyramid")
    assert "COPY data/mitre_attack.json" in d and not re.search(r"COPY\s+(\.|data)\s", d)
    ign = read("backend/.dockerignore")
    assert ".venv" in ign and "*.sqlite" in ign and "data/*" in ign and "!data/mitre_attack.json" in ign and ".env" in ign
    req = read("backend/requirements-docker.txt")
    assert "pytest" not in req and all("==" in l for l in req.splitlines() if l and not l.startswith("#"))


def test_nginx_proxies_the_api_falls_back_to_the_spa_and_guards_writes():
    n = read("docker/nginx.conf")
    assert "proxy_pass http://backend:8000" in n and "try_files $uri $uri/ /index.html" in n and "deny_write" in n and "location = /healthz" in n
    assert "X-Content-Type-Options" in n and "X-Frame-Options" in n and "Content-Security-Policy" in n and "frame-ancestors 'none'" in n
    assert "localhost:8000" not in n and "127.0.0.1:8000" not in n


def test_frontend_never_hardcodes_the_backend_address():
    hits = [str(p) for p in (REPO / "src").rglob("*.ts*") if re.search(r"localhost:\d+|127\.0\.0\.1:\d+", p.read_text(encoding="utf-8"))]
    assert hits == []                                                             # all calls are relative (/api/...)


def test_repository_hygiene_files_exclude_data_and_secrets():
    g = read(".gitignore")
    for pat in (".env", "node_modules/", ".venv/", "*.sqlite", "*.sqlite-wal", "*.sqlite-shm", "backend/data/backups/", "*.log", "*.pem"):
        assert pat in g, pat
    assert "!.env.example" in g and "backend/data/*" in g and "!backend/data/mitre_attack.json" in g
    e = read(".env.example")
    assert not re.search(r"(KEY|TOKEN|SECRET|PASSWORD)=\S", e), "the example file must not carry credentials"
    assert "SYNC_TOKEN" not in e
    di = read(".dockerignore")
    assert "node_modules" in di and "backend" in di and ".env" in di


def test_no_windows_absolute_paths_in_runtime_code_or_distribution_files():
    bad = []
    files = [p for p in (ROOT / "app").rglob("*.py")] + [REPO / f for f in ("compose.yaml", "frontend.Dockerfile", "docker/nginx.conf")] + [ROOT / "Dockerfile"]
    for p in files:
        if re.search(r"[A-Za-z]:\\\\|[A-Za-z]:/(Users|Pyramid|Program)", p.read_text(encoding="utf-8")):
            bad.append(str(p))
    assert bad == []


# ---------------------------------------------------------------- publication readiness
def test_ci_workflow_is_valid_and_covers_the_release_checks():
    import yaml
    w = yaml.safe_load(read(".github/workflows/ci.yml"))
    on = w.get("on", w.get(True))
    assert "push" in on and "pull_request" in on
    jobs = w["jobs"]
    assert {"hygiene", "backend", "frontend", "docker"} <= set(jobs)
    for j in ("backend", "frontend"):
        assert set(jobs[j]["strategy"]["matrix"]["os"]) == {"ubuntu-latest", "windows-latest"}
    text = read(".github/workflows/ci.yml")
    assert "3.13" in text and "node-version: \"22\"" in text and "docker compose config" in text and "check_repo_hygiene.py" in text and "gitleaks" in text.lower()
    assert "docker push" not in text and "docker/login-action" not in text and "secrets." not in text      # no registry publishing, no credentials
    assert "intel-db/initialize" not in text                                                                  # CI never starts an NVD import


def run_hygiene(path: Path) -> tuple[int, str]:
    r = subprocess.run([sys.executable, "-I", str(REPO / "scripts" / "check_repo_hygiene.py"), "--dir", str(path)], capture_output=True, text=True)
    return r.returncode, r.stdout


def test_hygiene_check_passes_a_clean_tree_and_never_prints_secret_values(tmp_path):
    (tmp_path / "a.py").write_text("print('ok')\n")
    assert run_hygiene(tmp_path)[0] == 0
    fake_key = "AKIA" + "ABCDEFGHIJKLMNOP"                                       # assembled at runtime so this file itself carries no key-like literal
    (tmp_path / "config.py").write_text(f"KEY = '{fake_key}'\n")
    code, out = run_hygiene(tmp_path)
    assert code == 1 and "config.py:1" in out and fake_key not in out


@pytest.mark.parametrize("name", ["backend/data/cache.sqlite", "x/db.sqlite-wal", ".env", "backend/.env", "backups/b.sqlite", "server.pem", "run.log", "backend/data/import_tmp/x.gz", "backend/data/other.json"])
def test_hygiene_check_rejects_data_and_credential_files(tmp_path, name):
    p = tmp_path / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text("x")
    code, out = run_hygiene(tmp_path)
    assert code == 1 and "PROBLEM" in out


def test_hygiene_check_allows_the_documented_exceptions(tmp_path):
    for name in (".env.example", "backend/data/mitre_attack.json", "backend/.env.example"):
        p = tmp_path / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text('{"x": 1}\nNVD_API_KEY=\n')
    assert run_hygiene(tmp_path)[0] == 0


def test_the_files_needed_by_a_clean_clone_are_not_git_ignored():
    needed = ["backend/data/mitre_attack.json", "backend/app/news/sources_catalog.json", "backend/tests/data/cpe_verification_2026-11-17.json", "compose.yaml", "backend/Dockerfile",
              "frontend.Dockerfile", "docker/nginx.conf", ".env.example", "backend/requirements-docker.txt", "package-lock.json"]
    for rel in needed:
        assert (REPO / rel).is_file(), rel
    gi = (REPO / ".gitignore").read_text() + (REPO / "backend" / ".gitignore").read_text()
    assert "data/*" in (REPO / "backend" / ".gitignore").read_text() and "!data/mitre_attack.json" in (REPO / "backend" / ".gitignore").read_text()
    assert "backend/data/*" in gi and "!backend/data/mitre_attack.json" in gi


def test_documentation_is_complete_honest_and_has_no_invented_urls():
    readme = read("README.md")
    for section in ("## Features", "## Technology stack", "## Requirements", "## Quick start", "## First run", "## Data sources", "## Security", "## License", "## Known limitations"):
        assert section in readme, section
    assert "<repository-url>" in readme and "http://localhost:8080" in readme and "docker compose up -d" in readme
    assert not re.search(r"github\.com/(?!actions|gitleaks)[\w.-]+/[\w.-]+", readme)                          # no invented repository URL
    lic = (REPO / "LICENSE").read_text(encoding="utf-8")                                                      # official Apache-2.0 text, unmodified
    assert "Apache-2.0" in readme and "Apache License 2.0" in readme and "(LICENSE)" in readme
    assert lic.lstrip().startswith("Apache License") and "Version 2.0, January 2004" in lic and "END OF TERMS AND CONDITIONS" in lic and len(lic.encode()) == 11358
    assert "authentication" in readme.lower() and "not been tested" in readme.lower().replace("*", "")                        # honest scope: Linux host and ARM64 untested
    for f in ("SECURITY.md", "CONTRIBUTING.md", "docs/OPERATIONS.md", "docs/INSTALL.md", "docs/RELEASE_NOTES_v0.1.0-beta.md", "docs/screenshots/README.md", ".gitattributes"):
        assert (REPO / f).is_file(), f
    assert not list((REPO / "docs" / "screenshots").glob("*.png"))                                           # no fictional screenshots


def test_version_is_prepared_but_not_released():
    assert json.loads(read("package.json"))["version"] == "0.1.0-beta" and 'version="0.1.0-beta"' in read("backend/app/main.py")
    assert "Not tagged and not released yet" in read("docs/RELEASE_NOTES_v0.1.0-beta.md")
