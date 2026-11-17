"""CISA Known Exploited Vulnerabilities catalog."""
from __future__ import annotations

import re

from .http import SourceError, get_json

URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")


def parse(payload: dict) -> list[dict]:
    vulns = payload.get("vulnerabilities")
    if not isinstance(vulns, list):
        raise SourceError("KEV payload missing 'vulnerabilities'")
    out = []
    for v in vulns:
        if not isinstance(v, dict):
            continue
        cve = str(v.get("cveID", "")).strip().upper()
        if not CVE_RE.match(cve):
            continue
        out.append({
            "cve_id": cve,
            "vendor": str(v.get("vendorProject", "")).strip(),
            "product": str(v.get("product", "")).strip(),
            "name": str(v.get("vulnerabilityName", "")).strip(),
            "date_added": str(v.get("dateAdded", "")).strip() or None,
            "ransomware": 1 if str(v.get("knownRansomwareCampaignUse", "")).lower() == "known" else 0,
            "description": str(v.get("shortDescription", "")).strip()[:2000] or None,
            "required_action": str(v.get("requiredAction", "")).strip()[:1000] or None,
            "due_date": str(v.get("dueDate", "")).strip() or None,
            "notes": str(v.get("notes", "")).strip()[:1000] or None,
            "cwes": ",".join(str(c) for c in (v.get("cwes") or []) if c)[:200] or None,
        })
    if not out:
        raise SourceError("KEV payload contained no valid entries")
    return out


def fetch() -> list[dict]:
    return parse(get_json(URL))
