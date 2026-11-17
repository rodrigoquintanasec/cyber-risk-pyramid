"""Turn validation results into the shipped catalogue. Usage: python tools/build_catalog.py [results.json] [--max=250]

Only `verified` sources are written to app/news/sources_catalog.json; they are registered DISABLED and enabled batch by batch (source_onboarding).
Also writes data/sources_catalog_new.csv (the verified catalogue) and data/sources_candidates_report.csv (every candidate, status and reason)."""
from __future__ import annotations

import csv
import json
import re
import sys
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from app.news import source_validation as sv  # noqa: E402
from app.news.sources import BY_ID, CATEGORIES, SOURCE_TYPES  # noqa: E402

args = [a for a in sys.argv[1:] if not a.startswith("--")]
res_path = Path(args[0]) if args else Path(__file__).with_name("validation_results_all.json")
limit = int(next((a.split("=")[1] for a in sys.argv[1:] if a.startswith("--max=")), 250))
results = json.loads(res_path.read_text(encoding="utf-8"))
CAT = {"NEWS": "news", "TI": "threat_intel", "VULN": "vuln_research", "VEND": "vendor_advisory", "CERT": "cert", "CLOUD": "cloud", "APPSEC": "appsec", "MAL": "malware", "PRIV": "privacy", "ICS": "ics"}
TYPE = {"news": "news", "threat_intel": "threat_intel", "vuln_research": "vuln_research", "vendor_advisory": "official", "cert": "official", "cloud": "cloud", "appsec": "appsec",
        "malware": "malware", "privacy": "privacy", "ics": "ics"}
THIRD_PARTY = {"github.com", "githubusercontent.com", "googlegroups.com", "medium.com", "feedburner.com", "feedproxy.google.com", "blogspot.com", "wordpress.com", "substack.com",
               "hatenadiary.jp", "hnrss.org", "reddit.com", "lore.kernel.org", "atom.io", "bsky.app"}
ADVISORY_WORDS = re.compile(r"advisor|bulletin|security release|announce|\bcve\b|errata|glsa|vulnerab|psirt|security notices|security updates|alertas|avisos|alerts|reports", re.I)


def slug(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", name.lower().replace("&", " and ")).strip("-")[:40]


def registrable(host: str) -> str:
    return sv.registrable(host)


taken = set(BY_ID)
verified = [r for r in results if r["status"] == "verified"]
verified.sort(key=lambda r: (-(r.get("relevance") or 0), r.get("newest") or ""), reverse=False)
verified.sort(key=lambda r: ((r.get("relevance") or 0) >= 0.5, r.get("newest") or ""), reverse=True)        # relevant and recently active first: they form batch 1
entries, reserve = [], []
for r in verified:
    cat = CAT[r["category"]]
    host = (urlparse(r["url"]).hostname or "").lower()
    third = registrable(host) in THIRD_PARTY or host in THIRD_PARTY
    if cat == "vendor_advisory" and not ADVISORY_WORDS.search(r["name"]):
        cat = "news"                                                       # a vendor BLOG is not an advisory feed
    typ = TYPE[cat]
    if typ == "official" and third:
        typ = "vuln_research" if cat == "vendor_advisory" else "news"       # a github.com / lists host cannot vouch for provenance
    sid = slug(r["name"])
    base, n = sid, 2
    while sid in taken:
        sid, n = f"{base}-{n}", n + 1
    if len(entries) >= limit:
        reserve.append(r["name"])
        continue
    taken.add(sid)
    final_host = (urlparse(r["final_url"]).hostname or host).lower()
    site = None if third else f"https://{host}/"
    hosts = [h for h in dict.fromkeys(r["hosts"]) if h != host][:3]
    entries.append({"id": sid, "name": r["name"], "type": typ, "category": cat, "url": r["url"], "site": site, "country": r.get("country"), "language": r.get("language"),
                    "extra_hosts": hosts, "official_domains": [registrable(host)] if typ == "official" else [], "publisher": None,
                    "validation": {"status": "verified", "validated_at": r["validated_at"], "entries": r["entries"], "newest": r["newest"], "relevance": r.get("relevance"), "note": r.get("note"), "final_url": r["final_url"]}})
plan, k = [(1, 25), (2, 25), (3, 50), (4, 50), (5, 50), (6, 50)], 0
for b, size in plan:
    for e in entries[k:k + size]:
        e["batch"] = b
    k += size
for e in entries[k:]:
    e["batch"] = 6
(ROOT / "app" / "news" / "sources_catalog.json").write_text(json.dumps(entries, indent=1, ensure_ascii=False), encoding="utf-8")
(ROOT / "data").mkdir(exist_ok=True)
with open(ROOT / "data" / "sources_catalog_new.csv", "w", newline="", encoding="utf-8-sig") as f:
    w = csv.writer(f)
    w.writerow(["id", "name", "category", "type", "country", "language", "feed_url", "site_url", "batch", "validation_status", "validated_at", "entries_seen", "newest_entry", "security_relevance", "redirect_hosts"])
    for e in entries:
        v = e["validation"]
        w.writerow([e["id"], e["name"], e["category"], e["type"], e["country"] or "", e["language"] or "", e["url"], e["site"] or "", e["batch"], v["status"], v["validated_at"], v["entries"], v["newest"] or "", v["relevance"], ";".join(e["extra_hosts"])])
with open(ROOT / "data" / "sources_candidates_report.csv", "w", newline="", encoding="utf-8-sig") as f:
    w = csv.writer(f)
    w.writerow(["name", "category", "country", "feed_url", "status", "http", "reason", "entries", "newest_entry"])
    for r in results:
        w.writerow([r["name"], r["category"], r.get("country") or "", r["url"], r["status"], r.get("http") or "", r.get("note") or "", r.get("entries") or "", r.get("newest") or ""])
print(f"catalogue: {len(entries)} sources (reserve not registered: {len(reserve)}); by type:", {t: sum(1 for e in entries if e['type'] == t) for t in SOURCE_TYPES if any(e['type'] == t for e in entries)})
