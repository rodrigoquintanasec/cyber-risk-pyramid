"""Configured feed sources. Only these URLs (and redirects to their allowed hosts) are ever fetched;
users cannot supply URLs. `hosts` is the per-source allow-list (feed host + known official redirect targets)."""
from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlparse

SOURCE_TYPES = {
    "news": "Cybersecurity News",
    "threat_intel": "Threat Intelligence",
    "malware": "Malware Research",
    "cloud": "Cloud Security",
    "vuln_research": "Vulnerability Research",
    "dfir": "DFIR",
    "official": "Official Security Advisories",
    "appsec": "Application Security & DevSecOps",
    "privacy": "Privacy, Breaches & Policy",
    "ics": "OT, ICS & IoT Security",
}
# Editorial taxonomy shown in the source manager (independent of `type`, which drives authority/verification rules).
CATEGORIES = {
    "news": "Cybersecurity News & Media", "threat_intel": "Threat Intelligence Research", "vuln_research": "Vulnerability Research & Exploit Intelligence",
    "vendor_advisory": "Vendor Security Advisories", "cert": "National CERTs & CSIRTs", "cloud": "Cloud & Infrastructure Security", "appsec": "Application Security & DevSecOps",
    "malware": "Malware & Ransomware Research", "privacy": "Privacy, Data Breaches & Cyber Policy", "ics": "OT, ICS & IoT Security",
}
DEFAULT_CATEGORY = {"news": "news", "threat_intel": "threat_intel", "malware": "malware", "cloud": "cloud", "vuln_research": "vuln_research", "dfir": "threat_intel",
                    "official": "vendor_advisory", "appsec": "appsec", "privacy": "privacy", "ics": "ics"}


@dataclass(frozen=True)
class FeedSource:
    id: str
    name: str
    type: str
    url: str
    extra_hosts: tuple[str, ...] = ()
    enabled: bool = True                      # default state; the user can toggle it afterwards (stored in SQLite)
    note: str | None = None                   # documented reason when a source is configured but inactive
    official_domains: tuple[str, ...] = ()    # only for type "official": domains that verify provenance
    publisher: str | None = None              # organisation behind the feed (unknown allowed)
    site: str | None = None                   # official site URL (unknown allowed)
    category: str | None = None               # key of CATEGORIES
    country: str | None = None                # ISO-3166 alpha-2 when it can be verified, else None
    origin: str = "builtin"                   # builtin | catalog | manual
    batch: int | None = None                  # onboarding batch of catalogue sources

    @property
    def hosts(self) -> frozenset[str]:
        return frozenset({urlparse(self.url).hostname or "", *self.extra_hosts})


def _s(id, name, type, url, *extra, off=(), enabled=True, note=None):
    return FeedSource(id, name, type, url, tuple(extra), enabled, note, tuple(off))


def host_in(host: str | None, domains: tuple[str, ...]) -> bool:
    h = (host or "").lower().rstrip(".")
    return any(h == d or h.endswith("." + d) for d in domains)


def is_verified_official(src: "FeedSource", item_url: str | None = None) -> bool:
    """An Official Security Advisory counts as official only if the feed host (and the item link) sit on the vendor/agency domain."""
    if src.type != "official" or not src.official_domains:
        return False
    if not host_in(urlparse(src.url).hostname, src.official_domains):
        return False
    return item_url is None or host_in(urlparse(item_url).hostname, src.official_domains)


# URLs validated on 2026-11-16. Redirect targets observed: feedburner (Hacker News), api.theregister.com, scworld.com.
SOURCES: tuple[FeedSource, ...] = (
    _s("bleepingcomputer", "BleepingComputer", "news", "https://www.bleepingcomputer.com/feed/"),
    _s("thehackernews", "The Hacker News", "news", "https://thehackernews.com/feeds/posts/default?alt=rss", "feeds.feedburner.com"),
    _s("securityweek", "SecurityWeek", "news", "https://www.securityweek.com/feed/"),
    _s("krebs", "Krebs on Security", "news", "https://krebsonsecurity.com/feed/"),
    _s("helpnetsecurity", "Help Net Security", "news", "https://www.helpnetsecurity.com/feed/"),
    _s("theregister", "The Register Security", "news", "https://www.theregister.com/security/headlines.atom", "api.theregister.com"),
    _s("darkreading", "Dark Reading", "news", "https://www.darkreading.com/rss.xml"),
    _s("scmedia", "SC Media", "news", "https://www.scmagazine.com/rss", "www.scworld.com", enabled=False,
       note="HTTP 403 (anti-bot block) after redirect to scworld.com; not circumvented."),
    _s("infosecurity", "Infosecurity Magazine", "news", "https://www.infosecurity-magazine.com/rss/news/"),
    _s("csoonline", "CSO Online", "news", "https://www.csoonline.com/feed/"),
    _s("sans-isc", "SANS Internet Storm Center", "threat_intel", "https://isc.sans.edu/rssfeed.xml"),
    _s("talos", "Cisco Talos", "threat_intel", "https://blog.talosintelligence.com/rss/"),
    _s("unit42", "Palo Alto Unit 42", "threat_intel", "https://unit42.paloaltonetworks.com/feed/"),
    _s("crowdstrike", "CrowdStrike", "threat_intel", "https://www.crowdstrike.com/en-us/blog/feed"),
    _s("microsoft-security", "Microsoft Security Blog", "threat_intel", "https://www.microsoft.com/en-us/security/blog/feed/"),
    _s("project-zero", "Google Project Zero", "threat_intel", "https://projectzero.google/feed.xml"),
    _s("dfir-report", "The DFIR Report", "threat_intel", "https://thedfirreport.com/feed/"),
    _s("checkpoint", "Check Point Research", "threat_intel", "https://research.checkpoint.com/feed/"),
    _s("securelist", "Securelist (Kaspersky)", "malware", "https://securelist.com/feed/"),
    _s("eset", "ESET WeLiveSecurity", "malware", "https://www.welivesecurity.com/en/rss/feed/"),
    _s("malwarebytes", "Malwarebytes Labs", "malware", "https://www.malwarebytes.com/blog/feed/index.xml"),
    _s("aws-security", "AWS Security Blog", "cloud", "https://aws.amazon.com/blogs/security/feed/"),
    _s("cloudflare", "Cloudflare Security", "cloud", "https://blog.cloudflare.com/tag/security/rss/"),
    # Original /blog/feed/ now returns 404; official feed is /rss.xml (the /blog/rss/ URL redirects to it).
    _s("rapid7", "Rapid7 Blog", "vuln_research", "https://www.rapid7.com/rss.xml"),
    _s("tenable", "Tenable Blog", "vuln_research", "https://www.tenable.com/blog/feed"),
    _s("zdi", "Zero Day Initiative", "vuln_research", "https://www.zerodayinitiative.com/rss/published/"),
    # ---- Expansion (validated 2026-11-17). Types follow each publisher's specialisation.
    # Cybersecurity News
    _s("therecord", "The Record", "news", "https://therecord.media/feed"),
    _s("cyberscoop", "CyberScoop", "news", "https://cyberscoop.com/feed/"),
    _s("wired-security", "WIRED Security", "news", "https://www.wired.com/feed/category/security/latest/rss"),
    _s("ars-security", "Ars Technica Security", "news", "https://arstechnica.com/security/feed/"),
    _s("securityaffairs", "Security Affairs", "news", "https://securityaffairs.com/feed"),
    _s("schneier", "Schneier on Security", "news", "https://www.schneier.com/feed/atom/"),
    _s("troyhunt", "Troy Hunt", "news", "https://www.troyhunt.com/rss/"),
    _s("grahamcluley", "Graham Cluley", "news", "https://grahamcluley.com/feed/"),
    _s("techcrunch-security", "TechCrunch Security", "news", "https://techcrunch.com/category/security/feed/"),
    _s("cyberwire", "The CyberWire", "news", "https://thecyberwire.com/feeds/rss.xml"),  # served Brotli-compressed
    # Threat Intelligence & Research
    _s("recordedfuture", "Recorded Future", "threat_intel", "https://www.recordedfuture.com/feed"),
    _s("secureworks", "Secureworks CTU", "threat_intel", "https://www.secureworks.com/rss?feed=blog", "www.sophos.com", enabled=False,
       note="Obsolete: secureworks.com now redirects (301) to sophos.com/en-us, which publishes no RSS/Atom feed."),
    _s("teamcymru", "Team Cymru", "threat_intel", "https://team-cymru.com/feed/", "www.team-cymru.com", enabled=False,
       note="Obsolete: redirects to www.team-cymru.com/feed, which returns HTTP 404; no feed advertised on the site."),
    _s("intel471", "Intel 471", "threat_intel", "https://intel471.com/blog/feed", "www.intel471.com"),
    _s("anomali", "Anomali", "threat_intel", "https://www.anomali.com/blog/rss.xml", enabled=False,
       note="HTTP 404; no replacement feed advertised on the official site."),
    _s("qualys", "Qualys Security Blog", "vuln_research", "https://blog.qualys.com/feed"),
    # replaces /en/publications.rss (404); the new URL is advertised by the site itself (<link rel="alternate">)
    _s("synacktiv", "Synacktiv Research", "vuln_research", "https://www.synacktiv.com/en/feed/lastblog.xml"),
    _s("sophos", "Sophos News", "malware", "https://news.sophos.com/en-us/feed/", "www.sophos.com", enabled=False,
       note="Obsolete: news.sophos.com moved to sophos.com/en-us/blog and the feed URL returns HTTP 404; no replacement advertised."),
    _s("malware-traffic-analysis", "Malware Traffic Analysis", "dfir", "https://www.malware-traffic-analysis.net/blog-entries.rss"),
    _s("anyrun", "ANY.RUN Research", "malware", "https://any.run/cybersecurity-blog/feed/"),
    _s("binarydefense", "Binary Defense", "threat_intel", "https://www.binarydefense.com/feed/", "binarydefense.com", enabled=False,
       note="HTTP 410 Gone (redirects to binarydefense.com/feed/); no replacement advertised."),
    _s("elastic-security-labs", "Elastic Security Labs", "threat_intel", "https://www.elastic.co/security-labs/rss/feed.xml"),
    _s("sentinelone-labs", "SentinelLabs", "malware", "https://www.sentinelone.com/labs/feed/"),
    _s("gcloud-threatintel", "Google Cloud Threat Intelligence", "threat_intel", "https://cloudblog.withgoogle.com/topics/threat-intelligence/rss/"),
    # Official Security Advisories (official only when feed host and item links are on the vendor/agency domain)
    _s("cisa-alerts", "CISA Alerts", "official", "https://www.cisa.gov/cybersecurity-advisories/alerts.xml", off=("cisa.gov",), enabled=False,
       note="HTTP 403 (anti-bot block); not circumvented."),
    _s("cisa-ics", "CISA ICS Advisories", "official", "https://www.cisa.gov/cybersecurity-advisories/ics-advisories.xml", off=("cisa.gov",), enabled=False,
       note="HTTP 403 (anti-bot block); not circumvented."),
    _s("certcc", "CERT/CC Vulnerability Notes", "official", "https://www.kb.cert.org/vuls/atomfeed/", off=("cert.org",)),
    _s("msrc", "Microsoft Security Update Guide", "official", "https://api.msrc.microsoft.com/update-guide/rss", off=("microsoft.com",)),
    _s("cisco-psirt", "Cisco Security Advisories", "official", "https://sec.cloudapps.cisco.com/security/center/psirtrss20/CiscoSecurityAdvisory.xml", off=("cisco.com",)),
    _s("paloalto-advisories", "Palo Alto Security Advisories", "official", "https://security.paloaltonetworks.com/rss.xml", off=("paloaltonetworks.com",)),
    _s("fortinet-psirt", "Fortinet PSIRT Advisories", "official", "https://filestore.fortinet.com/fortiguard/rss/ir.xml", off=("fortinet.com",)),
    _s("ubuntu-usn", "Ubuntu Security Notices", "official", "https://ubuntu.com/security/notices/rss.xml", off=("ubuntu.com",)),
    _s("chrome-releases", "Google Chrome Releases", "official", "https://chromereleases.googleblog.com/feeds/posts/default", "feeds.feedburner.com", off=("chromereleases.googleblog.com",)),
    _s("aws-bulletins", "AWS Security Bulletins", "official", "https://aws.amazon.com/security/security-bulletins/rss/feed/", off=("aws.amazon.com",)),
    _s("splunk-advisories", "Splunk Security Advisories", "official", "https://advisory.splunk.com/feed.xml", off=("splunk.com",)),
    _s("sonicwall-psirt", "SonicWall Security Advisories", "official", "https://psirtapi.global.sonicwall.com/api/v1/feed/rss.xml", off=("sonicwall.com",)),
    _s("ncsc-uk", "UK NCSC", "official", "https://www.ncsc.gov.uk/api/1/services/v1/all-rss-feed.xml", off=("ncsc.gov.uk",)),
    _s("cert-eu", "CERT-EU Security Advisories", "official", "https://cert.europa.eu/publications/security-advisories-rss", off=("europa.eu",)),
    _s("siemens-productcert", "Siemens ProductCERT", "official", "https://cert-portal.siemens.com/productcert/rss/advisories.atom", off=("siemens.com",)),
)
BUILTIN = SOURCES
SOURCES = list(BUILTIN)                       # live registry: builtin + verified catalogue + manual sources (mutated in place, never rebound)
BY_ID = {s.id: s for s in SOURCES}

CATALOG_VALIDATION: dict[str, dict] = {}      # validation facts of catalogue entries (used when their rows are first created)
CATALOG_FILE = __import__("pathlib").Path(__file__).with_name("sources_catalog.json")


def register(src: FeedSource) -> None:
    if src.id in BY_ID:
        SOURCES[:] = [s for s in SOURCES if s.id != src.id]
    SOURCES.append(src)
    BY_ID[src.id] = src


def unregister(source_id: str) -> None:
    SOURCES[:] = [s for s in SOURCES if s.id != source_id]
    BY_ID.pop(source_id, None)


def from_row(r: dict, origin: str, enabled: bool = False) -> FeedSource:
    """FeedSource from a catalogue entry / database row (extra hosts and official domains are stored as lists)."""
    return FeedSource(r["id"], r["name"], r["type"], r["url"], tuple(r.get("extra_hosts") or ()), enabled, r.get("note"), tuple(r.get("official_domains") or ()),
                      r.get("publisher"), r.get("site"), r.get("category") or DEFAULT_CATEGORY.get(r["type"]), r.get("country"), origin, r.get("batch"))


def load_catalog() -> int:
    """Verified catalogue sources (tools/build_catalog.py output). They are registered DISABLED: onboarding enables them batch by batch."""
    import json
    if not CATALOG_FILE.exists():
        return 0
    n = 0
    for r in json.loads(CATALOG_FILE.read_text(encoding="utf-8")):
        if r["id"] not in BY_ID:
            register(from_row(r, "catalog"))
            CATALOG_VALIDATION[r["id"]] = r.get("validation") or {}
            n += 1
    return n


load_catalog()




# Candidates that were evaluated and NOT configured (kept here so the decision is traceable).
REJECTED = {
    "mandiant": "https://www.mandiant.com/resources/blog/rss.xml - obsolete: redirects to cloud.google.com/security/mandiant (HTML, no feed). "
                "Its content is published in the 'Google Cloud Threat Intelligence' feed, which is configured (gcloud-threatintel).",
}
