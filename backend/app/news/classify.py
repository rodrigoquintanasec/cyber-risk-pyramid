"""Deterministic keyword classification, CVE extraction and technology correlation (no AI)."""
from __future__ import annotations

import html
import re
from datetime import datetime, timezone
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

import bleach

from ..catalog import CATALOG

CVE_RE = re.compile(r"\bCVE-(\d{4})-(\d{4,7})\b", re.I)

# Configurable: add a category by adding a key. Patterns are case-insensitive regexes over title + summary + feed tags.
CATEGORY_RULES: dict[str, tuple[str, ...]] = {
    "Vulnerabilities": (r"\bvulnerabilit", r"\bzero[- ]?days?\b", r"\b0[- ]day\b", r"\bpatch(?:es|ed)?\b", r"\bexploit",
                        r"remote code execution", r"\brce\b", r"privilege escalation", r"\bcve-\d{4}-\d{4,}", r"security (?:flaw|bug|hole)", r"\bsecurity update"),
    "Ransomware": (r"ransomware", r"\bransom\b", r"\blockbit\b", r"\bblackcat\b", r"\bakira\b", r"\bqilin\b", r"\bplay ransomware\b", r"double[- ]extortion"),
    "Malware": (r"\bmalware\b", r"\btrojan", r"\bbackdoor", r"\bbotnet", r"\binfostealer", r"\bstealer\b", r"\brootkit", r"\bspyware",
                r"\bloader\b", r"\bworm\b", r"\bkeylogger", r"\brat\b", r"\bwiper\b"),
    "Data Breaches": (r"data breach", r"\bbreach(?:ed|es)?\b", r"data leak", r"\bleaked\b", r"stolen data", r"exposed (?:data|database|records)",
                      r"compromised (?:accounts|credentials)", r"\bexfiltrat"),
    "Threat Intelligence": (r"threat actor", r"\bapt ?\d*\b", r"\bnation[- ]state", r"state[- ]sponsored", r"\bespionage\b", r"\bcampaign\b",
                            r"\bttps?\b", r"\bindicators? of compromise\b", r"\biocs?\b", r"\battribution\b", r"threat intelligence", r"\bintrusion set"),
    "Cloud Security": (r"\bcloud\b", r"\baws\b", r"\bazure\b", r"\bgcp\b", r"google cloud", r"\bs3 bucket", r"\bsaas\b", r"\bkubernetes\b",
                       r"\bcontainers?\b", r"\bserverless\b", r"\biam\b", r"\bentra\b"),
    "Network Security": (r"\bfirewalls?\b", r"\bvpn\b", r"\brouters?\b", r"\bddos\b", r"\bdns\b", r"network security", r"\bssl[- ]vpn\b",
                         r"\bwi-?fi\b", r"\bedge devices?\b", r"\bfortigate\b", r"\bnetwork devices?\b"),
    "Application Security": (r"web application", r"\bxss\b", r"sql injection", r"\bowasp\b", r"\bapi security\b", r"supply[- ]chain",
                             r"\bnpm\b", r"\bpypi\b", r"open[- ]source (?:package|librar)", r"\bsast\b", r"\bdevsecops\b", r"\bbrowser extension"),
}
FALLBACK_CATEGORY = "General Cybersecurity"
CATEGORIES = [*CATEGORY_RULES, FALLBACK_CATEGORY]
_COMPILED = {c: [re.compile(p, re.I) for p in ps] for c, ps in CATEGORY_RULES.items()}

# Technology patterns come from the catalog (explicit product names only).
_TECH: dict[str, list] = {}


def refresh_patterns() -> None:
    """(Re)compile the news patterns of the enabled catalogue technologies (called when the catalogue changes)."""
    from ..catalog import CATALOG as _C
    _TECH.clear()
    _TECH.update({t.id: [re.compile(p, re.I) for p in t.news_patterns] for t in _C if t.news_patterns})


refresh_patterns()

_TRACKING = {"fbclid", "gclid", "mc_cid", "mc_eid", "ref", "ref_src", "source", "feature", "ocid"}


def extract_cves(text: str, max_year: int | None = None) -> list[str]:
    max_year = max_year or datetime.now(timezone.utc).year + 1
    seen: dict[str, None] = {}
    for y, n in CVE_RE.findall(text or ""):
        if 1999 <= int(y) <= max_year:
            seen[f"CVE-{y}-{n}"] = None
    return list(seen)


def classify(text: str) -> list[str]:
    cats = [c for c, pats in _COMPILED.items() if any(p.search(text) for p in pats)]
    return cats or [FALLBACK_CATEGORY]


def detect_technologies(text: str, cve_techs: dict[str, set[str]] | None = None, cves: list[str] | None = None,
                        title: str | None = None) -> dict[str, str]:
    """{tech_id: basis}. basis 'name' = explicit product name; 'cve' = a mentioned CVE is already correlated with that
    technology by structured NVD/KEV data. Vendor-only or generic words never match. When `title` is given, a name
    must appear in the title, or at least twice in the rest of the text (a single passing mention is not enough)."""
    out: dict[str, str] = {}
    for tid, pats in _TECH.items():
        if title is None:
            hit = any(p.search(text) for p in pats)
        else:
            hit = any(p.search(title) for p in pats) or sum(len(p.findall(text)) for p in pats) >= 2
        if hit:
            out[tid] = "name"
    for cve in cves or []:
        for tid in (cve_techs or {}).get(cve, ()):
            out.setdefault(tid, "cve")
    return out


def clean_text(raw: str | None, limit: int = 400) -> str:
    """Strip every HTML tag (sanitisation), decode entities, collapse whitespace, truncate."""
    if not raw:
        return ""
    txt = bleach.clean(raw, tags=[], attributes={}, strip=True, strip_comments=True)
    txt = re.sub(r"\s+", " ", html.unescape(txt)).strip()
    return txt if len(txt) <= limit else txt[: limit - 1].rstrip() + "…"


def safe_url(url: str | None) -> str | None:
    p = urlparse((url or "").strip())
    return url.strip() if p.scheme in ("http", "https") and p.netloc else None


def canonical_url(url: str) -> str:
    p = urlparse(url.strip())
    q = [(k, v) for k, v in parse_qsl(p.query, keep_blank_values=True) if not k.lower().startswith("utm_") and k.lower() not in _TRACKING]
    path = p.path.rstrip("/") or "/"
    return urlunparse((p.scheme.lower(), p.netloc.lower(), path, "", urlencode(q), ""))
