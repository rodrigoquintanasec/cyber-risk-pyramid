"""Safe I/O for the bulk importer: official-host-only streaming downloads, bounded decompression, incremental JSON/tar parsing.

Nothing downloaded is ever executed or extracted to disk: archives are streamed member by member with strict name/size checks,
and every limit (download size, decompressed size, member count, free disk) is enforced while streaming.
"""
from __future__ import annotations

import codecs
import gzip
import hashlib
import json
import re
import shutil
import tarfile
import time
from pathlib import Path
from urllib.parse import urlparse

import httpx

from .config import settings

# SSRF protection: ONLY these official hosts over HTTPS. URLs are never taken from users; this also guards redirects.
ALLOWED_HOSTS = frozenset({"nvd.nist.gov", "services.nvd.nist.gov", "www.cisa.gov", "epss.cyentia.com", "epss.empiricalsecurity.com", "www.first.org", "epss.org"})
UA = "cyber-risk-pyramid/0.3 (local vulnerability intelligence importer)"
MAX_REDIRECTS = 3
RETRIES = 5
TAR_NAME = re.compile(r"^nvdcpe(?:match)?-2\.0-chunks/[A-Za-z0-9._-]+\.json$")
MAX_TAR_MEMBERS = 5000


class FeedError(Exception):
    """A download/validation problem. `retry_after` (seconds) is set for throttling responses."""
    def __init__(self, msg: str, retry_after: float = 0.0, fatal: bool = False):
        super().__init__(msg)
        self.retry_after, self.fatal = retry_after, fatal


def check_url(url: str) -> str:
    p = urlparse(url)
    if p.scheme != "https" or (p.hostname or "").lower() not in ALLOWED_HOSTS or p.username or p.password:
        raise FeedError(f"URL not allowed (official HTTPS hosts only): {p.hostname}", fatal=True)
    return url


def _client() -> httpx.Client:
    return httpx.Client(timeout=httpx.Timeout(settings.http_timeout * 2, read=120.0), follow_redirects=False, verify=True, headers={"User-Agent": UA, "Accept-Encoding": "identity"})


def _open(client: httpx.Client, method: str, url: str, headers: dict | None = None):
    """Request following at most MAX_REDIRECTS redirects, re-validating the host at every hop."""
    for _ in range(MAX_REDIRECTS + 1):
        check_url(url)
        req = client.build_request(method, url, headers=headers)
        r = client.send(req, stream=True)
        if r.status_code in (301, 302, 303, 307, 308) and r.headers.get("location"):
            url = str(httpx.URL(url).join(r.headers["location"]))
            r.close()
            continue
        return r
    raise FeedError("too many redirects", fatal=True)


def _retry_after(r: httpx.Response) -> float:
    try:
        return min(900.0, float(r.headers.get("Retry-After", 0) or 0))
    except ValueError:
        return 0.0


def fetch_text(url: str, max_bytes: int = 2_000_000) -> str:
    """Small text resources (.meta files, KEV/EPSS headers). Bounded; retries with backoff."""
    last: Exception | None = None
    for attempt in range(RETRIES):
        try:
            with _client() as c:
                r = _open(c, "GET", url)
                try:
                    if r.status_code in (403, 429, 502, 503, 504):
                        raise FeedError(f"HTTP {r.status_code}", _retry_after(r))
                    if r.status_code != 200:
                        raise FeedError(f"HTTP {r.status_code} for {urlparse(url).path}", fatal=r.status_code in (404, 410))
                    data = b""
                    for ch in r.iter_bytes(65536):
                        data += ch
                        if len(data) > max_bytes:
                            raise FeedError("response too large", fatal=True)
                    return data.decode("utf-8", "replace")
                finally:
                    r.close()
        except FeedError as e:
            last = e
            if e.fatal:
                raise
            time.sleep(min(60.0, e.retry_after or 2.0 * 2 ** attempt))
        except httpx.HTTPError as e:
            last = e
            time.sleep(min(60.0, 2.0 * 2 ** attempt))
    raise FeedError(f"{urlparse(url).path}: {last}")


def fetch_to(url: str, dest: Path, max_bytes: int, expected_size: int | None = None, resume: bool = True, progress=None) -> int:
    """Stream a download into `dest` (resuming a partial file with a Range request when the server allows). Returns the final size.
    Validates the size cap while streaming, the expected size (from .meta) at the end, and refuses to start without free disk space."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    need = (expected_size or 0) * 2 + int(settings.intel_min_free_gb * 1e9 * 0.1)
    if shutil.disk_usage(dest.parent).free < need:
        raise FeedError("Not enough free disk space for this download", fatal=True)
    last: Exception | None = None
    for attempt in range(RETRIES):
        have = dest.stat().st_size if resume and dest.exists() else 0
        try:
            with _client() as c:
                r = _open(c, "GET", url, {"Range": f"bytes={have}-"} if have else None)
                try:
                    if r.status_code in (403, 429, 502, 503, 504):
                        raise FeedError(f"HTTP {r.status_code}", _retry_after(r))
                    if r.status_code == 416 and expected_size and have == expected_size:
                        return have
                    if r.status_code not in (200, 206):
                        raise FeedError(f"HTTP {r.status_code} for {urlparse(url).path}", fatal=r.status_code in (404, 410))
                    mode = "ab" if (r.status_code == 206 and have) else "wb"
                    if mode == "wb":
                        have = 0
                    total = have + int(r.headers.get("content-length") or 0)
                    if total > max_bytes or (expected_size and expected_size > max_bytes):
                        raise FeedError(f"download of {total or expected_size} bytes exceeds the configured limit ({max_bytes})", fatal=True)
                    with open(dest, mode) as f:
                        for ch in r.iter_bytes(1 << 20):
                            have += len(ch)
                            if have > max_bytes:
                                raise FeedError("download exceeds the configured size limit", fatal=True)
                            f.write(ch)
                            if progress:
                                progress(have, total or expected_size)
                finally:
                    r.close()
            if expected_size and have != expected_size:
                raise FeedError(f"size mismatch: got {have} bytes, .meta says {expected_size}")
            return have
        except FeedError as e:
            last = e
            if e.fatal:
                raise
            time.sleep(min(120.0, e.retry_after or 3.0 * 2 ** attempt))
        except httpx.HTTPError as e:   # network cut: keep the partial file and retry (Range resume)
            last = e
            time.sleep(min(120.0, 3.0 * 2 ** attempt))
    raise FeedError(f"{urlparse(url).path}: {last}")


def parse_meta(text: str) -> dict:
    """NVD .meta: 'lastModifiedDate:..', 'size:..', 'zipSize:..', 'gzSize:..', 'sha256:..' (sha of the UNCOMPRESSED file)."""
    out = {}
    for line in text.splitlines():
        k, _, v = line.partition(":")
        if k.strip():
            out[k.strip()] = v.strip()
    for k in ("size", "zipSize", "gzSize"):
        if k in out:
            try:
                out[k] = int(out[k])
            except ValueError:
                out.pop(k)
    if "sha256" in out:
        out["sha256"] = out["sha256"].upper()
    return out


# ----------------------------------------------------------------------------- decompression & integrity
class Bounded:
    """File-like wrapper that raises when more than `limit` bytes are read (decompression-bomb protection) and optionally hashes the stream."""
    def __init__(self, f, limit: int, hasher=None):
        self.f, self.limit, self.n, self.h = f, limit, 0, hasher

    def read(self, size: int = -1) -> bytes:
        b = self.f.read(size)
        self.n += len(b)
        if self.n > self.limit:
            raise FeedError("decompressed data exceeds the configured limit", fatal=True)
        if self.h is not None:
            self.h.update(b)
        return b


def uncompressed_limit() -> int:
    return settings.intel_max_uncompressed_mb * 1_000_000


def gz_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with gzip.open(path, "rb") as g:
        b = Bounded(g, uncompressed_limit(), h)
        while b.read(1 << 20):
            pass
    return h.hexdigest().upper()


def file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for ch in iter(lambda: f.read(1 << 20), b""):
            h.update(ch)
    return h.hexdigest().upper()


def verify_gz(path: Path, meta: dict) -> str:
    """Integrity: size from .meta and the sha256 of the uncompressed stream (CVE feeds). Raises FeedError on mismatch."""
    if meta.get("gzSize") and path.stat().st_size != meta["gzSize"]:
        raise FeedError(f"gz size mismatch ({path.stat().st_size} != {meta['gzSize']})")
    try:
        got = gz_sha256(path)
    except (OSError, EOFError, gzip.BadGzipFile) as e:
        raise FeedError(f"corrupt gzip file: {e}")
    if meta.get("sha256") and got != meta["sha256"]:
        raise FeedError("sha256 mismatch against the official .meta")
    return got


# ----------------------------------------------------------------------------- incremental parsing
_SKIP = re.compile(r"[ \n\r\t,]*")


def iter_array(read, key: str, chunk: int = 1 << 20):
    """Yield the elements of the top-level array `key` of a huge JSON document without loading it into memory.
    `read(n)` returns bytes. Raises ValueError on truncated/invalid JSON."""
    dec = codecs.getincrementaldecoder("utf-8")(errors="strict")
    jd = json.JSONDecoder()
    marker = f'"{key}"'
    buf, pos = "", 0
    # 1) find the array
    while True:
        i = buf.find(marker)
        if i >= 0:
            j = buf.find("[", i + len(marker))
            if j >= 0:
                pos = j + 1
                break
        more = read(chunk)
        if not more:
            raise ValueError(f"array '{key}' not found")
        buf = buf[-(len(marker) + 64):] + dec.decode(more)
    # 2) items
    while True:
        pos = _SKIP.match(buf, pos).end()
        if pos >= len(buf):
            more = read(chunk)
            if not more:
                raise ValueError("truncated JSON")
            buf = buf[pos:] + dec.decode(more); pos = 0
            continue
        if buf[pos] == "]":
            return
        try:
            obj, end = jd.raw_decode(buf, pos)
        except json.JSONDecodeError:
            more = read(chunk)
            if not more:
                raise ValueError("truncated JSON")
            buf = buf[pos:] + dec.decode(more); pos = 0
            continue
        yield obj
        pos = end


def iter_gz_json(path: Path, key: str):
    with gzip.open(path, "rb") as g:
        yield from iter_array(Bounded(g, uncompressed_limit()).read, key)


def iter_tar_json(path: Path, key: str):
    """Stream the JSON chunk files of an NVD tar.gz, one element at a time. Only expected member names are read; nothing is written to disk."""
    members = 0
    with gzip.open(path, "rb") as g:
        bounded = Bounded(g, uncompressed_limit())
        with tarfile.open(fileobj=bounded, mode="r|") as tf:
            for m in tf:
                if not m.isfile():
                    continue
                members += 1
                if members > MAX_TAR_MEMBERS or not TAR_NAME.match(m.name):
                    raise FeedError(f"unexpected archive member: {m.name[:80]}", fatal=True)
                f = tf.extractfile(m)
                if f is not None:
                    yield from iter_array(f.read, key)


def tar_members_sha256(path: Path) -> tuple[str, int]:
    """sha256 + total size of the tar members' contents concatenated in archive order. This is what NVD publishes in the CPE / CPE Match .meta files
    (verified against the real feed: `size` = sum of member sizes, `sha256` = hash of their concatenation). Nothing is extracted to disk."""
    h, total, members = hashlib.sha256(), 0, 0
    try:
        with gzip.open(path, "rb") as g:
            with tarfile.open(fileobj=Bounded(g, uncompressed_limit()), mode="r|") as tf:
                for m in tf:
                    if not m.isfile():
                        continue
                    members += 1
                    if members > MAX_TAR_MEMBERS or not TAR_NAME.match(m.name):
                        raise FeedError(f"unexpected archive member: {m.name[:80]}", fatal=True)
                    f = tf.extractfile(m)
                    while f is not None:
                        ch = f.read(1 << 20)
                        if not ch:
                            break
                        h.update(ch)
                        total += len(ch)
    except (OSError, EOFError, gzip.BadGzipFile, tarfile.TarError) as e:
        raise FeedError(f"corrupt archive: {e}")
    return h.hexdigest().upper(), total


def gz_text_lines(path: Path):
    with gzip.open(path, "rb") as g:
        b = Bounded(g, uncompressed_limit())
        buf = b""
        while True:
            ch = b.read(1 << 20)
            if not ch:
                break
            buf += ch
            *lines, buf = buf.split(b"\n")
            for ln in lines:
                yield ln.decode("utf-8", "replace").rstrip("\r")
        if buf:
            yield buf.decode("utf-8", "replace").rstrip("\r")
