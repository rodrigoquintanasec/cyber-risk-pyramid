"""Runtime settings (env vars / backend/.env) and the scoring configuration."""
from __future__ import annotations

import os
from dataclasses import dataclass, fields
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent


def _load_dotenv() -> None:
    env = BASE_DIR / ".env"
    if not env.exists():
        return
    for line in env.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))


_load_dotenv()


def _int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, default))
    except ValueError:
        return default


@dataclass(frozen=True)
class Settings:
    db_path: str = os.getenv("DB_PATH", str(BASE_DIR / "data" / "cache.sqlite"))
    nvd_api_key: str | None = os.getenv("NVD_API_KEY") or None  # never sent to the frontend
    nvd_window_days: int = min(_int("NVD_WINDOW_DAYS", 120), 120)  # NVD max range is 120 days
    nvd_max_pages: int = _int("NVD_MAX_PAGES", 2)  # 2000 CVEs per page
    nvd_lookup_budget: int = _int("NVD_LOOKUP_BUDGET", 25)  # per-CVE lookups per sync
    nvd_backfill_calls: int = _int("NVD_BACKFILL_CALLS", 6)  # NVD API calls per scheduled cycle spent on historical backfill
    nvd_backfill_all_cap: int = _int("NVD_BACKFILL_ALL_CAP", 4000)  # products with at most this many CVEs are fetched completely
    nvd_backfill_years: int = _int("NVD_BACKFILL_YEARS", 5)  # larger products are fetched newest-first back to this horizon
    nvd_query_budget: int = _int("NVD_QUERY_BUDGET", 16)  # CPE queries per sync (monitored technologies only, stalest first)
    # --- local intelligence database (bulk import) limits, all configurable
    intel_batch: int = _int("INTEL_BATCH", 500)                       # records per SQLite transaction
    intel_throttle_ms: int = _int("INTEL_THROTTLE_MS", 5)             # pause between batches so the app stays responsive
    intel_tmp_dir: str = os.getenv("INTEL_TMP_DIR", str(BASE_DIR / "data" / "import_tmp"))
    intel_max_download_mb: int = _int("INTEL_MAX_DOWNLOAD_MB", 1500)  # per file (CPE Match is ~890 MB compressed)
    intel_max_uncompressed_mb: int = _int("INTEL_MAX_UNCOMPRESSED_MB", 8000)
    intel_min_free_gb: float = float(os.getenv("INTEL_MIN_FREE_GB", "6"))
    epss_history_days: int = _int("EPSS_HISTORY_DAYS", 0)             # 0 = keep only the latest EPSS snapshot
    kev_lookback_days: int = _int("KEV_LOOKBACK_DAYS", 365)
    kev_ttl_hours: int = _int("KEV_TTL_HOURS", 12)
    nvd_ttl_hours: int = _int("NVD_TTL_HOURS", 6)
    epss_ttl_hours: int = _int("EPSS_TTL_HOURS", 24)
    sync_interval_minutes: int = _int("SYNC_INTERVAL_MINUTES", 360)
    news_interval_minutes: int = _int("NEWS_INTERVAL_MINUTES", 30)
    news_workers: int = max(1, min(_int("NEWS_WORKERS", 8), 16))                  # feeds fetched at once (never all of them together)
    news_source_deadline: float = float(os.getenv("NEWS_SOURCE_DEADLINE", "45"))  # hard wall-clock limit for ONE feed download (slow-drip servers)
    news_initial_entries: int = _int("NEWS_INITIAL_ENTRIES", 50)                  # newest entries stored from a source that has no article yet
    news_max_items_per_run: int = _int("NEWS_MAX_ITEMS_PER_RUN", 25000)           # soft cap per sync cycle; remaining feeds wait for the next cycle
    attack_interval_hours: int = _int("ATTACK_SYNC_INTERVAL_HOURS", 168)  # 0 = manual only
    attack_url: str = os.getenv("ATTACK_STIX_URL", "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json")
    graph_max_nodes: int = min(_int("GRAPH_MAX_NODES", 150), 400)
    graph_max_edges: int = min(_int("GRAPH_MAX_EDGES", 400), 1500)
    sync_on_startup: bool = os.getenv("SYNC_ON_STARTUP", "1") != "0"
    sync_token: str | None = os.getenv("SYNC_TOKEN") or None  # optional guard for POST /api/sync
    # Docker: the backend sits behind the bundled nginx on a private network and is never published. With PYRAMID_TRUST_PROXY=1 a request from a PRIVATE address
    # (i.e. from that proxy) counts as local; the real boundary is the host port binding (127.0.0.1). Leave it off for a bare `uvicorn` run.
    trust_proxy: bool = os.getenv("PYRAMID_TRUST_PROXY", "0") == "1"
    auto_enrich: bool = os.getenv("PYRAMID_AUTO_ENRICH", "1") != "0"      # fetch the small CISA KEV / FIRST EPSS files automatically when missing or stale
    http_timeout: float = float(os.getenv("HTTP_TIMEOUT", "30"))
    http_retries: int = _int("HTTP_RETRIES", 3)
    cors_origins: str = os.getenv("CORS_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173")


@dataclass(frozen=True)
class ScoringConfig:
    """Deterministic "current threat state" formula (all values overridable via env SCORE_<NAME>).

    Per CVE (relevance 0..1):
      relevance = w_cvss*cvss/10*decay_pub + w_epss*min(1,epss/epss_cap)
                + [KEV]*(w_kev*decay_kev + w_ransom*[ransomware use]*decay_kev + w_recent*recent)
      decay_pub = max(cvss_floor, 0.5^(days since NVD publication / cvss_half_life_days))
      decay_kev = max(kev_floor,  0.5^(days since KEV dateAdded   / kev_half_life_days))   # old exploitation fades, never vanishes
      recent    = 0.5^(days since KEV dateAdded / recent_half_life_days)                     # no floor: only fresh confirmations
    Technology score (volume never adds up; only the most relevant CVEs matter):
      score = 100 * ( peak + corroboration * (1 - peak) * mean(next `corroboration_n` relevances, zero-padded) )
    Adding more CVEs can never lower the score, and cannot raise it beyond the corroboration bonus.
    """

    w_cvss: float = 0.30
    w_epss: float = 0.25
    w_kev: float = 0.25
    w_recent: float = 0.12
    w_ransom: float = 0.08
    cvss_missing: float = 0.4  # assumed CVSS/10 when no score is published yet (flagged in data quality)
    epss_cap: float = 0.5
    cvss_half_life_days: float = 90.0
    cvss_floor: float = 0.25
    kev_half_life_days: float = 180.0
    kev_floor: float = 0.35
    recent_days: int = 30  # KEV additions within this many days are labelled "recent exploitation"
    recent_half_life_days: float = 21.0
    corroboration: float = 0.25
    corroboration_n: int = 3
    min_coverage: float = 0.5  # below this NVD coverage (and no KEV evidence) the state is grey

    @classmethod
    def from_env(cls) -> "ScoringConfig":
        kw = {}
        for f in fields(cls):
            raw = os.getenv(f"SCORE_{f.name.upper()}")
            if raw is not None:
                try:
                    kw[f.name] = type(f.default)(raw)
                except ValueError:
                    pass
        return cls(**kw)


settings = Settings()
scoring_config = ScoringConfig.from_env()
