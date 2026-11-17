# Contributing

Thanks for your interest. This is an early beta (`v0.1.0-beta`); small, focused changes are easiest to review.

## Ground rules

- **Never commit data or secrets**: SQLite files (including `-wal`/`-shm`), backups, `.env`, API keys, company data. `.gitignore` excludes them; `python scripts/check_repo_hygiene.py` verifies it and CI runs it.
- Keep the app local-first: no external database, no cloud service, no AI/LLM service.
- Do not weaken the SQLite rules: short write transactions, no transaction open during network I/O, heavy scans read before writing (see `backend/app/db.py`).
- Fetching feeds goes through the SSRF-hardened fetcher in `backend/app/news/safefetch.py`; do not add other outbound fetchers without the same protections.
- Do not change scoring algorithms (Threat Signal Score, News Priority Score) without discussing it first.

## Development setup (without Docker)

```bash
# API: from backend/, create a virtual environment and install the pinned runtime dependencies
python -m venv .venv
.venv/bin/pip install -r requirements-docker.txt pytest        # Windows: .venv\Scripts\pip
.venv/bin/python -m uvicorn app.main:app --port 8000

# UI: from the repository root
npm ci
npm run dev                                                    # http://localhost:5173 (proxies /api to port 8000)
```

The development database is created in `backend/data/` (git-ignored). Use a temporary `DB_PATH` for experiments.

## Before opening a pull request

```bash
cd backend && python -m pytest tests -q        # uses temporary databases and mocked network
cd .. && npm run build && npm run test:briefing
python scripts/check_repo_hygiene.py
docker compose config --quiet
```

Add a test for every behaviour you change. Tests must not call the network or start an NVD import.

## Adding or changing news sources

Use **Settings → Intelligence Sources** for local use. To propose catalogue sources, validate them with `backend/tools/validate_sources.py` (real fetch and parse, relevance check, duplicate detection) and include the output; do not add feeds that need authentication, bypass anti-bot controls, or were not verified.

## Reporting issues

Security problems: see [SECURITY.md](SECURITY.md) (do not open a public issue). Everything else: include your OS, Docker version, `docker compose ps` and the relevant `docker compose logs backend` lines (without secrets).
