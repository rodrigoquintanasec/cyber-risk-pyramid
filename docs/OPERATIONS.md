# Operations: storage, backup, updates, troubleshooting

## Where the data is

| What | Where |
|---|---|
| SQLite database `cache.sqlite` (+ `-wal`, `-shm`) | Docker volume `pyramid_data`, `/data` in the `backend` container |
| NVD/CPE import checkpoints and downloads in progress | `/data/import_tmp` (same volume) |
| Application code and the bundled ATT&CK catalogue | The image (replaced on update, holds no user data) |

`docker compose restart`, `docker compose down` followed by `docker compose up -d`, and image rebuilds keep the volume. **`docker compose down -v` deletes it.**

Find the volume: `docker volume ls` (named `<project>_pyramid_data`, normally `cyber-risk-pyramid_pyramid_data`).

## Consistent backup

Do not copy `cache.sqlite` while the app is writing: the WAL file may hold recent commits. Use SQLite's own snapshot (works while the app runs and does not block it):

```bash
docker compose exec backend python -c "import sqlite3,datetime; d='/data/backup-'+datetime.datetime.now().strftime('%Y%m%d-%H%M')+'.sqlite'; sqlite3.connect('/data/cache.sqlite').execute('VACUUM INTO ?',(d,)); print(d)"
docker compose cp backend:/data/backup-YYYYMMDD-HHMM.sqlite ./
docker compose exec backend rm /data/backup-YYYYMMDD-HHMM.sqlite
```

Replace the timestamp with the printed file name. The backup needs free space about the size of the database. Verify it: `sqlite3 backup.sqlite "PRAGMA integrity_check"` (expects `ok`).

## Restore

```bash
docker compose down                       # no -v
docker compose run --rm --no-deps -v "$(pwd):/restore:ro" backend python -c "import shutil;[__import__('os').remove(p) for p in ('/data/cache.sqlite-wal','/data/cache.sqlite-shm') if __import__('os').path.exists(p)];shutil.copy('/restore/backup-YYYYMMDD-HHMM.sqlite','/data/cache.sqlite')"
docker compose up -d
```

(The `-wal`/`-shm` files belong to the replaced database and must go with it; here the whole stack is stopped.)

## Update

1. Back up (above).
2. `git pull`, then `docker compose build --pull` and `docker compose up -d`.
3. Watch `docker compose logs -f backend`: a new schema revision is applied once, then the app starts. Volumes are untouched.

## Troubleshooting

| Symptom | Check |
|---|---|
| `docker compose build` says "additional privileges requested ... --allow=fs.read=..." | Seen on Windows when Compose is run from Git Bash. Run the command from PowerShell or CMD instead. |
| Page does not open | `docker compose ps` (both services `healthy`?); `docker compose logs backend`; is port 8080 free? Set `PYRAMID_PORT` in `.env`. |
| Settings actions return 403 | Open the app as `http://localhost:8080` (not by LAN IP or another host name). |
| No news yet | The first cycle starts shortly after boot; check **Settings → Intelligence Sources → Source Coverage**. Offline: data is kept and retried. |
| `database is locked` in logs | Report it with the surrounding lines. Never run a second API container against the same volume, and do not open the database with another writer while the app runs. |
| Vulnerability data shows partial coverage | Expected until you run **Settings → Local Intelligence Database → Initialize Database**. |
| NVD import interrupted | Press **Resume Import**; completed files are not downloaded again. |
| Disk full | Free space, then **Resume Import**. Temporary downloads are in `/data/import_tmp`. |
| Start from scratch | `docker compose down -v` (**deletes all data**). |

## Limitations

Single user, localhost only; one API process (SQLite has one writer); `linux/amd64` verified.
