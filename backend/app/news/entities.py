"""Configurable entity dictionaries (vendors, products, malware, ransomware) and MITRE ATT&CK ids.

Everything is explicit-name matching. Threat actors are NOT extracted: a story is never attributed to a group
without an explicit statement. Add/override entries with a JSON file (env ENTITIES_FILE):
{"vendors": {"Name": "regex"}, "products": {"Name": ["Vendor", "regex"]}, "malware": {"Name": "regex"}, "ransomware": {"Name": "regex"}}
"""
from __future__ import annotations

import json
import os
import re
from functools import lru_cache
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent.parent

VENDORS = {
    "Microsoft": r"\bmicrosoft\b", "Google": r"\bgoogle\b|\bchrome\b|\bandroid\b", "Apple": r"\bapple\b|\bmacos\b|\biphone\b|\bios 1\d\b|\bipados\b",
    "Cisco": r"\bcisco\b", "Fortinet": r"\bfortinet\b|\bforti(?:os|gate|manager|web|analyzer|proxy|sandbox|client|ems|siem)\b",
    "Palo Alto Networks": r"palo alto", "VMware": r"\bvmware\b|\bbroadcom\b|\besxi\b|\bvcenter\b",
    "Ivanti": r"\bivanti\b", "Citrix": r"\bcitrix\b|\bnetscaler\b", "Oracle": r"\boracle\b", "SAP": r"\bsap\b",
    "Atlassian": r"\batlassian\b|\bconfluence\b|\bjira\b", "Adobe": r"\badobe\b", "F5": r"\bf5\b|\bbig-ip\b",
    "SonicWall": r"\bsonicwall\b", "Juniper": r"\bjuniper\b", "Check Point": r"check point", "Zyxel": r"\bzyxel\b",
    "GitLab": r"\bgitlab\b", "GitHub": r"\bgithub\b", "Amazon Web Services": r"\baws\b|amazon web services",
    "Red Hat": r"\bred hat\b", "Canonical": r"\bcanonical\b|\bubuntu\b", "Docker": r"\bdocker\b",
    "Kubernetes": r"\bkubernetes\b|\bk8s\b", "Linux": r"\blinux(?! foundation)\b", "Samsung": r"\bsamsung\b",
    "Qualcomm": r"\bqualcomm\b", "Progress": r"\bprogress software\b|\bmoveit\b", "SolarWinds": r"\bsolarwinds\b",
    "Veeam": r"\bveeam\b", "Trend Micro": r"trend micro", "CrowdStrike": r"\bcrowdstrike\b", "Okta": r"\bokta\b",
    "Cloudflare": r"\bcloudflare\b", "Zscaler": r"\bzscaler\b", "WordPress": r"\bwordpress\b", "Apache": r"\bapache\b",
    "OpenSSL": r"\bopenssl\b", "Mozilla": r"\bmozilla\b|\bfirefox\b", "Intel": r"\bintel\b", "AMD": r"\bamd\b",
    "NVIDIA": r"\bnvidia\b", "Dell": r"\bdell\b", "HPE": r"\bhpe\b|hewlett packard", "Zoom": r"\bzoom\b",
    "Salesforce": r"\bsalesforce\b", "Snowflake": r"\bsnowflake\b", "Microsoft Azure": r"\bazure\b",
    "Google Cloud": r"google cloud|\bgcp\b", "Veritas": r"\bveritas\b", "Synology": r"\bsynology\b", "QNAP": r"\bqnap\b",
    "TP-Link": r"tp-?link", "D-Link": r"d-?link", "Ubiquiti": r"\bubiquiti\b", "WatchGuard": r"\bwatchguard\b",
}
PRODUCTS = {  # product -> (vendor, regex)
    "Exchange Server": ("Microsoft", r"\bexchange server\b"), "SharePoint": ("Microsoft", r"\bsharepoint\b"),
    "Windows Server": ("Microsoft", r"\bwindows server\b|\bwsus\b"), "Windows": ("Microsoft", r"\bwindows (?:1[01]|update|defender|smb|rdp)\b"),
    "Outlook": ("Microsoft", r"\boutlook\b"), "Microsoft Teams": ("Microsoft", r"\bmicrosoft teams\b"),
    "Entra ID": ("Microsoft", r"\bentra\b|azure ad\b"), "Chrome": ("Google", r"\bchrome\b"), "Android": ("Google", r"\bandroid\b"),
    "FortiOS": ("Fortinet", r"\bfortios\b"), "FortiGate": ("Fortinet", r"\bfortigate\b"), "FortiWeb": ("Fortinet", r"\bfortiweb\b"),
    "FortiManager": ("Fortinet", r"\bfortimanager\b"), "FortiSIEM": ("Fortinet", r"\bfortisiem\b"),
    "ESXi": ("VMware", r"\besxi\b"), "vCenter": ("VMware", r"\bvcenter\b"), "vSphere": ("VMware", r"\bvsphere\b"),
    "NetScaler": ("Citrix", r"\bnetscaler\b"), "Ivanti Connect Secure": ("Ivanti", r"connect secure|pulse secure"),
    "PAN-OS": ("Palo Alto Networks", r"\bpan-os\b|globalprotect"), "Confluence": ("Atlassian", r"\bconfluence\b"),
    "MOVEit": ("Progress", r"\bmoveit\b"), "BIG-IP": ("F5", r"\bbig-ip\b"), "Cisco IOS XE": ("Cisco", r"\bios xe\b"),
    "OpenSSH": ("OpenSSH", r"\bopenssh\b"), "Jenkins": ("Jenkins", r"\bjenkins\b"), "Kubernetes": ("Kubernetes", r"\bkubernetes\b|\bk8s\b|\bkubectl\b"),
    "Docker": ("Docker", r"\bdocker\b|\bdockerfile\b"), "Linux kernel": ("Linux", r"\blinux kernel\b|\bglibc\b"),
}
MALWARE = {
    "Emotet": r"\bemotet\b", "QakBot": r"\bqakbot\b|\bqbot\b", "Lumma Stealer": r"\blumma\b", "RedLine": r"\bredline\b",
    "AsyncRAT": r"\basyncrat\b", "Cobalt Strike": r"cobalt strike", "Mirai": r"\bmirai\b", "IcedID": r"\bicedid\b",
    "TrickBot": r"\btrickbot\b", "DarkGate": r"\bdarkgate\b", "Agent Tesla": r"agent tesla", "Remcos": r"\bremcos\b",
    "njRAT": r"\bnjrat\b", "XWorm": r"\bxworm\b", "FormBook": r"\bformbook\b", "SocGholish": r"\bsocgholish\b",
    "PlugX": r"\bplugx\b", "ShadowPad": r"\bshadowpad\b", "Sliver": r"\bsliver (?:c2|implant|framework)\b", "Brute Ratel": r"brute ratel",
    "Havoc": r"\bhavoc (?:c2|framework)\b", "Latrodectus": r"\blatrodectus\b", "Pikabot": r"\bpikabot\b", "Raspberry Robin": r"raspberry robin",
    "Rhadamanthys": r"\brhadamanthys\b", "Vidar": r"\bvidar\b", "StealC": r"\bstealc\b", "Atomic Stealer": r"atomic stealer|\bamos stealer\b",
    "Gootloader": r"\bgootloader\b", "BumbleBee": r"\bbumblebee\b", "Mimikatz": r"\bmimikatz\b", "Metasploit": r"\bmetasploit\b",
    "Mythic": r"\bmythic c2\b", "AgentTesla": r"\bagenttesla\b", "Stuxnet": r"\bstuxnet\b", "Pegasus": r"\bpegasus spyware\b|\bnso group\b",
}
RANSOMWARE = {
    "LockBit": r"\blockbit\b", "BlackCat/ALPHV": r"\bblackcat\b|\balphv\b", "Akira": r"\bakira\b", "Qilin": r"\bqilin\b",
    "Black Basta": r"black basta", "Cl0p": r"\bcl0p\b|\bclop\b", "Rhysida": r"\brhysida\b", "BianLian": r"\bbianlian\b",
    "Hunters International": r"hunters international", "RansomHub": r"\bransomhub\b", "DragonForce": r"\bdragonforce\b",
    "Conti": r"\bconti\b", "REvil": r"\brevil\b|\bsodinokibi\b", "Babuk": r"\bbabuk\b", "Ryuk": r"\bryuk\b", "Trigona": r"\btrigona\b",
    "8Base": r"\b8base\b", "Cicada3301": r"cicada3301", "Hellcat": r"\bhellcat\b", "Everest": r"\beverest ransomware\b",
    # ambiguous common words: only with explicit ransomware context
    "Play": r"\bplay ransomware\b|\bplay (?:gang|group)\b", "Medusa": r"\bmedusa (?:ransomware|gang|group)\b",
    "Royal": r"\broyal ransomware\b", "Cactus": r"\bcactus ransomware\b", "Interlock": r"\binterlock ransomware\b",
    "INC Ransom": r"\binc ransom\b", "Lynx": r"\blynx ransomware\b", "Fog": r"\bfog ransomware\b", "Sarcoma": r"\bsarcoma (?:ransomware|group)\b",
}
# Explicit incident / advisory identifiers (used by clustering as strong evidence of the same event).
INCIDENT_ID_RE = re.compile(
    r"\b(GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}|ZDI-\d{2}-\d{3,5}|VMSA-\d{4}-\d{4}|FG-IR-\d{2}-\d{3,4}|"
    r"AA\d{2}-\d{3}[A-Z]|ICSA-\d{2}-\d{3}-\d{2}|ADV\d{6}|KB\d{6,7}|PSIRT-\d{4}-\d+|SA-\d{4}-\d+)\b", re.I)
MITRE_RE = re.compile(r"\bT(1\d{3}|0\d{3})(?:\.(\d{3}))?\b")


@lru_cache(maxsize=1)
def _dicts():
    v, p, m, r = dict(VENDORS), dict(PRODUCTS), dict(MALWARE), dict(RANSOMWARE)
    f = os.getenv("ENTITIES_FILE")
    if f and Path(f).is_file():
        try:
            extra = json.loads(Path(f).read_text(encoding="utf-8"))
            v.update(extra.get("vendors", {})); m.update(extra.get("malware", {})); r.update(extra.get("ransomware", {}))
            p.update({k: tuple(x) for k, x in extra.get("products", {}).items()})
        except (OSError, ValueError):
            pass
    c = lambda d: {k: re.compile(x, re.I) for k, x in d.items()}  # noqa: E731
    return c(v), {k: (ven, re.compile(x, re.I)) for k, (ven, x) in p.items()}, c(m), c(r)


@lru_cache(maxsize=1)
def _bundled_catalog() -> dict:
    try:
        return json.loads((BASE / "data" / "mitre_attack.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {"source": None, "version": None, "techniques": {}}


def mitre_catalog() -> dict:
    """ATT&CK Enterprise techniques: the imported STIX data when available (single source of truth), else the bundled file."""
    try:
        from .. import attack
        c = attack.catalog_from_db()
        if c:
            return c
    except Exception:
        pass
    return _bundled_catalog()


def mitre_url(tid: str) -> str:
    return "https://attack.mitre.org/techniques/" + tid.replace(".", "/") + "/"


def extract_mitre(title: str, summary: str) -> list[dict]:
    """Only explicit, catalogue-valid technique ids are mapped; the origin (field) is recorded."""
    cat = mitre_catalog()["techniques"]
    out: dict[str, dict] = {}
    for field, text in (("title", title), ("summary", summary)):
        for m in MITRE_RE.finditer(text or ""):
            tid = m.group(0).upper()
            if tid in cat and tid not in out:
                out[tid] = {"id": tid, "name": cat[tid]["n"], "tactics": cat[tid]["t"], "origin": f"explicit id in {field}", "url": mitre_url(tid)}
    return list(out.values())


def extract(title: str, summary: str) -> dict:
    v, p, m, r = _dicts()
    text = f"{title} {summary}"
    ttl = title or ""
    # a vendor/product counts when named in the title, or at least twice overall (single passing mentions ignored)
    def hit(rx):
        return rx.search(ttl) is not None or len(rx.findall(text)) >= 2
    vendors = [k for k, rx in v.items() if hit(rx)]
    products = [k for k, (_, rx) in p.items() if hit(rx)]
    for k in products:
        ven = p[k][0]
        if ven not in vendors and ven in v:
            vendors.append(ven)
    return {
        "vendors": sorted(vendors), "products": sorted(products),
        "malware": sorted(k for k, rx in m.items() if rx.search(text)),
        "ransomware": sorted(k for k, rx in r.items() if rx.search(text)),
        "mitre": extract_mitre(title, summary),
        "incident_ids": sorted({x.upper() for x in INCIDENT_ID_RE.findall(text)}),
    }


def catalog_lists() -> dict:
    v, p, m, r = _dicts()
    return {"vendors": sorted(v), "products": sorted(p), "malware": sorted(m), "ransomware": sorted(r)}
