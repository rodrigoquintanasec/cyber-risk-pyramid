# Cyber Risk Pyramid

**Self-hosted cyber threat intelligence workspace.** Monitor technologies on an interactive 3D pyramid dashboard, follow hundreds of security news sources, explore a local vulnerability database (NVD, CISA KEV, FIRST EPSS) and generate a printable daily briefing. Everything lives in one SQLite database on your machine: no external database, no cloud account, no AI service.

> **Status: `v0.1.0-beta`, single-user, local-only.** There is **no user authentication yet.** Do not expose the application to a network or the Internet. See [SECURITY.md](SECURITY.md).

<!-- Screenshots: add real captures to docs/screenshots/ (see docs/screenshots/README.md). None are included yet. -->

## Features

All of the following is implemented in this repository:

- **Technology Risk Dashboard (3D).** One pyramid per monitored technology, coloured by its Threat Signal Score (CISA KEV, NVD CVSS, FIRST EPSS signals). A catalogue of 153 technologies with user-managed categories; technologies can be added from the NVD product dictionary.
- **Vulnerability Explorer.** Search and filter CVEs with CVSS, EPSS, KEV flags, affected products, references and related news.
- **Intelligence Feed.** 315 configured RSS/Atom sources (65 original + 250 catalogue sources verified before inclusion), deduplicated articles, event clustering, a News Priority Score (reading priority, not risk), and an admin screen to add, edit, validate and enable sources.
- **Custom News Intelligence Dashboards.** Keyword pyramids coloured by *relative media attention*, with a related-news side panel that links to the original articles.
- **Technology Watchlists.**
- **Company Threat Intelligence.** Technology inventories per company with version-aware applicability of vulnerabilities (potential vs analyst-confirmed).
- **Threat Actors & Campaigns** (MITRE ATT&CK) and a **Relationship Graph** of verified relationships.
- **Intelligence Analytics.** Coverage and trend views over the collected news.
- **Morning Cyber Briefing.** 24 h / 48 h / 7 d briefings built with deterministic templates and a print-ready layout that keeps source links.
- **Local Vulnerability Intelligence Database.** Optional, resumable import of the official NVD CVE, CPE Dictionary and CPE Match feeds; incremental updates afterwards.

Colours on the news dashboards show **news coverage, not risk**, and a mention in the news is never treated as confirmed exposure.

## Technology stack

React 18, TypeScript, Vite, Tailwind CSS, Three.js (React Three Fiber) · FastAPI, Python 3.13 · SQLite (WAL) · Nginx · Docker Compose.

## Requirements

- Docker Engine + Docker Compose v2 (Linux) or Docker Desktop (Windows/macOS), `linux/amd64`.
- Outbound HTTPS (news feeds, CISA, FIRST, NVD).
- Approximate resources, **measured on one Windows machine with Docker Desktop** (they will vary):

| | Measured |
|---|---|
| Images | backend 250 MB, web 76 MB |
| Memory, light install (idle, after the first sync) | backend ≈ 250 MiB, web ≈ 8 MiB |
| Database, light install after the first sync cycle | ≈ 90 MB (≈ 1,400-2,200 articles, KEV, EPSS) |
| Database growth from news | ≈ 1 KB per stored article (≈ 800 articles/day with the enabled sources) |
| Database with the NVD history imported | ≈ 3.4 GB with CVE + CPE Dictionary + EPSS + KEV (CPE Match not included in that measurement); the app shows its own estimate and free space before you confirm the import |

The historical NVD import is large and slow and only starts when you ask for it.

## Quick start

```bash
git clone <repository-url>
cd cyber-risk-pyramid
docker compose up -d
```

Open **http://localhost:8080**.

`docker compose up -d` builds the two images on the first run (a few minutes). After pulling new code use `docker compose up -d --build`. On Windows run Compose from PowerShell or CMD (see [docs/INSTALL.md](docs/INSTALL.md)).

| Task | Command |
|---|---|
| Logs | `docker compose logs -f backend` |
| Status | `docker compose ps` |
| Stop (keeps data) | `docker compose down` |

> `docker compose down -v` also deletes the `pyramid_data` volume, i.e. your whole database.

## First run

1. The API creates its SQLite database in the Docker volume `pyramid_data` and applies the schema once. No sample or fictional data is created; restarts never repeat migrations or duplicate data.
2. The default catalogue (153 technologies, 15 categories) and the news sources are registered. 57 sources are enabled by default; the 250 catalogue sources are disabled until you enable them in **Settings → Intelligence Sources**.
3. News are collected automatically shortly after start and then about every 30 minutes (deduplicated, with retries and backoff).
4. **CISA KEV** and **FIRST EPSS** (small daily files) are fetched automatically and refreshed periodically.
5. The **historical NVD database is optional**: open **Settings → Local Intelligence Database** and press **Initialize Database**. Progress is saved and the import can be resumed. Until then vulnerability coverage is reported as partial, and the news features work normally. For the technologies on the dashboard the app also queries the NVD API in small, rate-limited batches.

## Data sources

| Data | Origin |
|---|---|
| Vulnerabilities (CVE, CVSS, CPE) | [NVD](https://nvd.nist.gov/) feeds and API. *This product uses NVD data but is not endorsed or certified by the NVD.* |
| Known exploited vulnerabilities | [CISA KEV catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) |
| Exploit prediction | [FIRST EPSS](https://www.first.org/epss/) (data provided by FIRST) |
| Threat actors, campaigns, techniques | [MITRE ATT&CK®](https://attack.mitre.org/) (bundled snapshot, MITRE terms of use apply) |
| News | RSS/Atom feeds published by the sources listed in [docs/sources_catalog.csv](docs/sources_catalog.csv) and in the app; only titles, short excerpts and links are stored |

External services can change, rate-limit or become unavailable; the app keeps existing data and retries later. Feed publishers keep the rights to their content.

## Backups, updates, troubleshooting

See [docs/OPERATIONS.md](docs/OPERATIONS.md) (consistent backup with `VACUUM INTO`, restore, update, common problems) and [docs/INSTALL.md](docs/INSTALL.md) (Windows and Linux).

## Configuration

Everything is optional; see [.env.example](.env.example): `PYRAMID_PORT`, `NVD_API_KEY`, `NEWS_INTERVAL_MINUTES`, `NEWS_WORKERS`, `PYRAMID_AUTO_ENRICH`.

## Security

Local use only. The web port is bound to `127.0.0.1`; the API is not published; write operations are refused unless the page is opened via `localhost`. This is **not authentication**. Do not put the app on a public address without adding authentication in front of it. Details and reporting: [SECURITY.md](SECURITY.md).

## Development

```bash
# API (from backend/, in a virtual environment with backend/requirements-docker.txt + pytest installed)
python -m uvicorn app.main:app --port 8000
# UI (repository root)
npm ci && npm run dev        # http://localhost:5173, proxies /api to port 8000
```

Tests: `cd backend && python -m pytest tests -q`, `npm run build`, `npm run test:briefing`. Contributions: [CONTRIBUTING.md](CONTRIBUTING.md). Continuous integration runs on GitHub Actions (`.github/workflows/ci.yml`).

## Known limitations

- No authentication or multi-user support; localhost only.
- Tested on Windows with Docker Desktop (`linux/amd64`); the backend test suite also passes in a Linux container. A native Linux Docker Engine install and ARM64 have **not** been tested.
- Some feeds block automated clients or change URLs; such sources are shown as failed and retried with backoff, never bypassed.
- The NVD import needs a lot of time, bandwidth and disk, and the full CPE Match import has not been verified end to end in this release.
- The UI loads the Inter font from Google Fonts (falls back to system fonts if blocked).
- One API process only (SQLite single writer).
- The development toolchain has one npm advisory without an upstream fix (`picomatch`, build-time only; production dependencies report none).

## License

Cyber Risk Pyramid is distributed under the **Apache License 2.0** (SPDX: `Apache-2.0`). See the [LICENSE](LICENSE) file for the full text. Third-party data and software keep their own terms (see "Data sources" above).
