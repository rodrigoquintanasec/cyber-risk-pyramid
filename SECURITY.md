# Security

## Supported use

Cyber Risk Pyramid currently targets **one person on one machine**. It has **no user accounts, authentication or authorisation**. Docker is not an access-control mechanism.

- The web port is published as `127.0.0.1:8080` only. **Do not change it to `0.0.0.0`**, put it behind a public reverse proxy, or forward it to the internet without adding authentication in front of it.
- The API container publishes no port at all; it is reachable only from the bundled web container.
- Administrative and state-changing API calls (`POST/PUT/PATCH/DELETE`) are refused by the web container unless the page was opened through `localhost`, `127.0.0.1` or `[::1]`. This blocks DNS-rebinding and accidental LAN use of write operations. It is **not** authentication: a client that can reach the port can forge a `Host` header.
- Inside Docker the API treats requests coming from the private Docker network (RFC 1918 / unique-local ranges) as local (`PYRAMID_TRUST_PROXY=1`, set by `compose.yaml` only). Outside Docker the original rule applies: loopback only.

## Data protection

- The database holds your company inventories and assessments. Keep backups private; they are **not** encrypted by the application.
- `.env`, SQLite files (including `-wal`/`-shm`), backups and logs are excluded from Git and from the Docker build context. Check `git status` before committing, and review history for secrets before publishing a fork.
- Optional secrets (e.g. `NVD_API_KEY`) are read from the environment and are never sent to the browser.

## Network behaviour

The backend fetches only configured news feeds and the official NVD, CISA and FIRST endpoints. Feed fetching blocks non-public addresses (loopback, private, link-local, metadata), validates every redirect, checks the address actually connected to, and applies size and time limits. Feed content is treated as untrusted: HTML is stripped and only `http(s)` links are kept.

## Reporting a vulnerability

Please do not open a public issue for security problems. Contact the maintainer privately (add the preferred contact address here before publishing). Include the version/commit, what you observed and how to reproduce it.
