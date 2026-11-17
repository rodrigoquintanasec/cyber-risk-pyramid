# Cyber Risk Pyramid v0.1.0-beta (draft release notes)

First public beta of a self-hosted, local-first cyber threat intelligence workspace. **Not tagged and not released yet**: these notes are prepared for the maintainer.

## Highlights

- Interactive 3D Technology Risk Dashboard (Threat Signal Score per technology).
- Intelligence Feed over 315 configured RSS/Atom sources (65 original + 250 verified catalogue sources), with event clustering and a News Priority Score.
- Custom News Intelligence Dashboards: keyword pyramids coloured by relative media attention, with a related-news panel.
- Local Vulnerability Intelligence Database (NVD CVE, CPE Dictionary, CPE Match, CISA KEV, FIRST EPSS) stored in SQLite; the NVD history is an explicit, resumable import.
- Vulnerability Explorer, Technology Catalog and Watchlists, Company Threat Intelligence, Threat Actors & Campaigns, Relationship Graph, Intelligence Analytics.
- Morning Cyber Briefing (24 h / 48 h / 7 d) with a print-ready, link-preserving PDF layout.
- Docker Compose installation: one command, one local port, one data volume.

## Install

```bash
git clone <repository-url>
cd cyber-risk-pyramid
docker compose up -d        # builds the images on first run; then open http://localhost:8080
```

Details for Windows and Linux: [docs/INSTALL.md](INSTALL.md). Backups, updates and troubleshooting: [docs/OPERATIONS.md](OPERATIONS.md).

## Security warnings

- **No authentication.** Single-user, local only. The port is bound to `127.0.0.1`; do not expose it to a network or the Internet.
- Backups and the database contain whatever you enter (e.g. company inventories) and are not encrypted.
- See [SECURITY.md](../SECURITY.md).

## Known limitations

- Verified on Windows with Docker Desktop (`linux/amd64`). Native Linux Docker Engine and ARM64 are untested.
- The historical NVD import is large and slow and only runs when requested.
- Some feeds block automated clients or move; failing sources are reported and retried with backoff, never bypassed.
- One API process only (SQLite single writer).
- The UI loads the Inter font from Google Fonts (falls back to system fonts).
- One build-time advisory without an upstream fix (`picomatch` ReDoS, development tooling only; production dependencies report none).
- Distributed under the Apache License 2.0 (see `LICENSE`).
