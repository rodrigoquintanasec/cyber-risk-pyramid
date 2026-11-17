# Installation guide

Cyber Risk Pyramid runs as two containers (web UI + API) and keeps all data in one Docker volume. It is meant for **one user on one machine**: the UI is published on `127.0.0.1` only.

## Windows (Docker Desktop)

1. Install and start [Docker Desktop](https://www.docker.com/products/docker-desktop/) (Linux containers / WSL 2 backend).
2. Open **PowerShell** (or CMD) and run:

```powershell
git clone <repository-url>
cd cyber-risk-pyramid
docker compose up -d
```

3. Open http://localhost:8080.

Notes
- Run Compose from **PowerShell/CMD**, not from Git Bash: Git Bash path translation can make `docker compose build` stop with "additional privileges requested".
- The first start builds the images (a few minutes). `docker compose up -d` builds automatically when the images do not exist; use `docker compose up -d --build` after pulling new code.
- If port 8080 is busy, create `.env` from `.env.example` and set `PYRAMID_PORT`.

## Linux (Docker Engine + Compose v2)

```bash
git clone <repository-url>
cd cyber-risk-pyramid
docker compose up -d
```

Open http://localhost:8080. Your user must be allowed to run Docker (membership of the `docker` group, or use `sudo`). The containers run as unprivileged users; the data volume is created and owned by Docker, so no manual permissions are needed.

> The maintainers have run the installation on Windows with Docker Desktop (`linux/amd64` images). The backend test suite has also been run inside a Linux container. A native Linux Docker Engine installation has **not** been tested yet; ARM64 (e.g. Raspberry Pi, Apple Silicon without emulation) is **not** verified.

## Check that it works

```bash
docker compose ps                       # backend and frontend should be "healthy"
docker compose logs -f backend          # follow the API log
curl http://localhost:8080/api/health   # {"ok":true}
```

## Stop, update, back up

- Stop (keeps data): `docker compose down`. **Never add `-v`** unless you want to delete the database.
- Update: back up first, then `git pull`, `docker compose build --pull`, `docker compose up -d`.
- Backups, restore and troubleshooting: [OPERATIONS.md](OPERATIONS.md).
