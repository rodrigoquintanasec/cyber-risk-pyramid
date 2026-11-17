"""Controlled validation of candidate feeds (never part of the app's request path). Usage: python tools/validate_sources.py [candidates.txt] [out.json]

Real fetch + real parse for every candidate, at most 8 in flight, one request at a time per host, a jittered pause between requests, no retries
beyond one for temporary failures. Duplicates are detected by normalised URL, by final (redirected) URL and by overlapping recent article URLs
against the other candidates AND the stored articles of the sources already configured."""
from __future__ import annotations

import json
import os
import random
import sqlite3
import sys
import threading
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib.parse import urlparse

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from app.news import source_validation as sv  # noqa: E402
from app.news.sources import SOURCES  # noqa: E402

args = [a for a in sys.argv[1:] if not a.startswith("--")]
out = Path(next((a.split("=", 1)[1] for a in sys.argv[1:] if a.startswith("--out=")), Path(__file__).with_name("validation_results.json")))
reuse_path = next((a.split("=", 1)[1] for a in sys.argv[1:] if a.startswith("--reuse=")), None)
files = [Path(a) for a in args] or [Path(__file__).with_name("source_candidates.txt")]
cands, seen_c = [], set()
for src in files:
    for line in src.read_text(encoding="utf-8").splitlines():
        if line.strip() and not line.startswith("#"):
            cat, cc, name, url = [x.strip() for x in line.split("|", 3)]
            if sv.normalize_feed_url(url) not in seen_c:      # the same URL listed twice is fetched once
                seen_c.add(sv.normalize_feed_url(url))
                cands.append({"category": cat, "country": cc or None, "name": name, "url": url})
# decisions already taken in an earlier run are reused (no repeated requests to the same provider); verified and temporary results are fetched again
reuse = {}
if reuse_path and Path(reuse_path).exists():
    reuse = {r["url"]: r for r in json.loads(Path(reuse_path).read_text(encoding="utf-8")) if r["status"] in ("invalid", "unsupported")}

host_locks: dict[str, threading.Lock] = defaultdict(threading.Lock)
done = [0]


def run(c: dict) -> dict:
    if c["url"] in reuse:
        done[0] += 1
        return {**c, **{k: v for k, v in reuse[c["url"]].items() if k not in c}, "reused": True}
    host = urlparse(c["url"]).hostname or ""
    with host_locks[host]:
        r = sv.assess(c["url"], require_relevance=True)
        if r["status"] == "temporarily_unavailable":
            time.sleep(3 + random.random() * 2)
            r = sv.assess(c["url"], require_relevance=True)
        time.sleep(0.3 + random.random() * 0.4)
    done[0] += 1
    if done[0] % 40 == 0:
        print(f"  {done[0]}/{len(cands)}", flush=True)
    return {**c, **r}


t0 = time.time()
with ThreadPoolExecutor(max_workers=8) as ex:
    results = list(ex.map(run, cands))

# ---- duplicates: existing sources first, then earlier candidates win
existing_urls = {sv.normalize_feed_url(s.url): s.id for s in SOURCES}
existing_sigs: dict[str, str] = {}
db_path = os.environ.get("DB_PATH") or str(Path(__file__).resolve().parent.parent / "data" / "cache.sqlite")
try:
    con = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=5)
    for sid, canon in con.execute("SELECT source_id,url_canon FROM news_item WHERE sort_ts>=date('now','-30 day')"):
        existing_sigs[canon] = sid
    con.close()
except sqlite3.Error as e:
    print("note: could not read stored articles for content-duplicate check:", e)
seen_urls, seen_sigs = dict(existing_urls), {}
for r in results:
    if r["status"] != "verified":
        continue
    keys = {sv.normalize_feed_url(r["url"]), sv.normalize_feed_url(r["final_url"])}
    hit = next((seen_urls[k] for k in keys if k in seen_urls), None)
    why = None
    if hit:
        why = f"same feed URL as {hit}"
    else:
        sig = set(r["signature"])
        for other_url, osig in seen_sigs.items():
            if sig and osig and len(sig & osig) >= max(2, 0.5 * min(len(sig), len(osig))):
                why = f"same articles as {other_url}"
                break
        if not why and sig:
            owners = defaultdict(int)
            for u in sig:
                if u in existing_sigs:
                    owners[existing_sigs[u]] += 1
            if owners:
                o, n = max(owners.items(), key=lambda kv: kv[1])
                if n >= max(2, 0.5 * len(sig)):
                    why = f"same articles as existing source {o}"
    if why:
        r["status"], r["note"] = "duplicate", why
        continue
    for k in keys:
        seen_urls[k] = r["name"]
    seen_sigs[r["url"]] = set(r["signature"])
for r in results:
    r.pop("signature", None)
out.write_text(json.dumps(results, indent=1), encoding="utf-8")
cnt = defaultdict(int)
for r in results:
    cnt[r["status"]] += 1
print(f"{len(results)} candidates in {time.time() - t0:.0f}s ->", dict(cnt))
