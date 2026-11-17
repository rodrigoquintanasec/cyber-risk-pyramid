"""Technology catalog: structured identifiers used for correlation.

Correlation is evidence-based only: a CVE is attributed to a technology when an NVD
`vulnerable` CPE match (vendor:product) or a CISA KEV product name matches an entry here.
Vendor-only matches are never enough (e.g. not every Microsoft/Fortinet CVE).
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Technology:
    id: str
    name: str
    aliases: tuple[str, ...]
    # (vendor, product-regex) matched with fullmatch against NVD CPE 2.3 vendor/product
    cpe_matchers: tuple[tuple[str, str], ...]
    # CPE prefixes used to query NVD (virtualMatchString)
    nvd_queries: tuple[str, ...]
    # (vendorProject-regex, product-regex) matched (case-insensitive, fullmatch) against CISA KEV
    kev_matchers: tuple[tuple[str, str], ...]
    # KEV vendors whose entries are ambiguous: confirmed only through NVD CPE data
    ambiguous_kev_vendors: tuple[str, ...] = field(default=())
    # Explicit, non-generic regexes used to link news to this technology (never bare vendor words like 'Microsoft')
    news_patterns: tuple[str, ...] = field(default=())
    # --- dynamic catalogue metadata (defaults keep the six original definitions valid unchanged)
    vendor: str = ""
    product: str = ""
    category: str = "Other"
    kind: str = "product"            # product | family | platform | cloud
    description: str = ""
    custom: bool = False
    enabled: bool = True
    monitor: str = "auto"            # auto | on | off
    dashboard: bool = False
    correlation_source: str = "seed"


LEGACY: tuple[Technology, ...] = (
    Technology(
        id="windows-server", name="Windows Server",
        aliases=("Windows Server 2012", "Windows Server 2016", "Windows Server 2019", "Windows Server 2022", "Windows Server 2025"),
        cpe_matchers=(("microsoft", r"windows_server.*"),),
        nvd_queries=tuple(f"cpe:2.3:o:microsoft:windows_server_{y}" for y in (2012, 2016, 2019, 2022, 2025)),
        kev_matchers=(("microsoft", r"windows server.*"),),
        ambiguous_kev_vendors=("microsoft",),
        news_patterns=(r'\bwindows server\b', r'\bwsus\b',),
    ),
    Technology(
        id="linux", name="Linux",
        aliases=("Linux Kernel",),
        cpe_matchers=(("linux", r"linux_kernel"),),
        nvd_queries=("cpe:2.3:o:linux:linux_kernel",),
        kev_matchers=(("linux", r"kernel"),),
        news_patterns=(r'\blinux(?! foundation)\b', r'\bglibc\b',),
    ),
    Technology(
        id="docker", name="Docker",
        aliases=("Docker Engine", "Docker Desktop", "Moby"),
        cpe_matchers=(("docker", r"docker.*"), ("mobyproject", r"moby")),
        nvd_queries=("cpe:2.3:a:docker:docker", "cpe:2.3:a:docker:docker_desktop", "cpe:2.3:a:mobyproject:moby"),
        kev_matchers=(("docker", r".*"), ("mobyproject", r".*")),
        ambiguous_kev_vendors=("docker",),
        news_patterns=(r'\bdocker\b', r'\bdockerfile\b',),
    ),
    Technology(
        id="kubernetes", name="Kubernetes",
        aliases=("K8s", "ingress-nginx"),
        cpe_matchers=(("kubernetes", r"kubernetes|ingress-nginx|ingress_nginx|kubelet|kube-apiserver"),),
        nvd_queries=("cpe:2.3:a:kubernetes:kubernetes", "cpe:2.3:a:kubernetes:ingress-nginx"),
        kev_matchers=(("kubernetes", r".*"),),
        ambiguous_kev_vendors=("kubernetes",),
        news_patterns=(r'\bkubernetes\b', r'\bk8s\b', r'\bkubectl\b', r'\bkubelet\b', r'\bingress-nginx\b',),
    ),
    Technology(
        id="vmware", name="VMware",
        aliases=("ESXi", "vCenter Server", "Workstation", "Fusion", "Cloud Foundation"),
        cpe_matchers=(("vmware", r"esxi|vcenter_server|workstation|fusion|cloud_foundation|vsphere.*"),),
        nvd_queries=(
            "cpe:2.3:o:vmware:esxi", "cpe:2.3:a:vmware:vcenter_server", "cpe:2.3:a:vmware:workstation",
            "cpe:2.3:a:vmware:fusion", "cpe:2.3:a:vmware:cloud_foundation",
        ),
        kev_matchers=(("vmware", r"esxi|vcenter server|workstation|fusion|cloud foundation|vsphere.*"),),
        ambiguous_kev_vendors=("vmware",),
            news_patterns=(r'\bvmware\b', r'\besxi\b', r'\bvcenter\b', r'\bvsphere\b',),
    ),
    Technology(
        id="fortinet", name="Fortinet",
        aliases=("FortiOS", "FortiProxy", "FortiManager", "FortiAnalyzer", "FortiWeb"),
        cpe_matchers=(("fortinet", r"fortios|fortiproxy|fortimanager|fortianalyzer|fortiweb|fortisandbox"),),
        nvd_queries=(
            "cpe:2.3:o:fortinet:fortios", "cpe:2.3:a:fortinet:fortiproxy", "cpe:2.3:a:fortinet:fortimanager",
            "cpe:2.3:a:fortinet:fortianalyzer", "cpe:2.3:a:fortinet:fortiweb", "cpe:2.3:a:fortinet:fortisandbox",
        ),
        kev_matchers=(("fortinet", r"fortios.*|fortiproxy.*|fortimanager.*|fortianalyzer.*|fortiweb.*|fortisandbox.*"),),
        ambiguous_kev_vendors=("fortinet",),
            news_patterns=(r'\bfortinet\b', r'\bforti(?:os|gate|manager|analyzer|web|proxy|sandbox|client|siem|ems|nac|switch|ap|soar|edr)\b',),
    ),
)


# ----------------------------------------------------------------------------- registry
# CATALOG = enabled technologies (used for correlation/sync/pickers); BY_ID = every known technology (so references to a disabled one still
# resolve). Both are mutated IN PLACE by `set_registry`, so modules that imported them keep seeing the current catalogue. SQLite is the
# source of truth; this module only holds the in-memory view (and the six legacy definitions + seed used to populate an empty database).
CATALOG: list[Technology] = []
BY_ID: dict[str, Technology] = {}
VERSION = [0]


def set_registry(techs) -> None:
    techs = list(techs)
    CATALOG[:] = [t for t in techs if t.enabled]
    BY_ID.clear()
    BY_ID.update({t.id: t for t in techs})
    VERSION[0] += 1


def _cpe_rows(tokens: str):
    out: dict[tuple[str, str], list[str]] = {}
    queries = []
    for tok in tokens.split():
        part, vendor, product = tok.split(":", 2)[0], tok.split(":")[1], tok.split(":", 2)[2]
        out.setdefault((part, vendor), []).append(product)
        queries.append(f"cpe:2.3:{part}:{vendor}:{product}")
    return out, tuple(queries)


def build_matchers(tokens: str) -> tuple[tuple[tuple[str, str], ...], tuple[str, ...]]:
    """'a:vendor:product ...' -> (cpe_matchers[(vendor, exact-alternatives regex)], nvd_queries). Exact identifiers only; nothing is guessed."""
    import re
    groups, queries = _cpe_rows(tokens)
    by_vendor: dict[str, list[str]] = {}
    for (part, vendor), prods in groups.items():
        by_vendor.setdefault(vendor, []).extend(prods)
    return tuple((v, "|".join(re.escape(p) for p in dict.fromkeys(ps))) for v, ps in by_vendor.items()), queries


def from_seed(row) -> Technology:
    from .catalog_seed import NEW  # noqa: F401  (import for type clarity)
    tid, name, vendor, product, category, kind, desc, aliases, cpes, kev, news = row
    matchers, queries = build_matchers(cpes)
    return Technology(id=tid, name=name, aliases=tuple(aliases), cpe_matchers=matchers, nvd_queries=queries, kev_matchers=tuple(kev), news_patterns=tuple(news),
                      vendor=vendor, product=product, category=category, kind=kind, description=desc, correlation_source="NVD CPE dictionary" if cpes else "none (no CPE)")


def legacy_with_meta() -> list[Technology]:
    from dataclasses import replace
    from .catalog_seed import LEGACY_META
    out = []
    for t in LEGACY:
        v, p, cat, kind, desc = LEGACY_META[t.id]
        out.append(replace(t, vendor=v, product=p, category=cat, kind=kind, description=desc, dashboard=True, correlation_source="NVD CPE + CISA KEV (original catalogue)"))
    return out


def seed_technologies() -> list[Technology]:
    from .catalog_seed import NEW
    return legacy_with_meta() + [from_seed(r) for r in NEW]


def match_kind(t: Technology) -> str:
    """How reliably a CVE can be tied to this technology: exact product id / family of products / cloud service / no verified identifier."""
    if t.kind == "cloud" or (not t.nvd_queries and t.kind == "platform"):
        return "cloud"
    if not t.cpe_matchers and not t.kev_matchers:
        return "unverified"
    plain = all(re_plain(p) for _, p in t.cpe_matchers) if t.cpe_matchers else False
    return "exact" if t.kind == "product" and len(t.nvd_queries) <= 1 and plain else "family" if t.cpe_matchers else "kev-only"


def re_plain(rx: str) -> bool:
    return "|" not in rx and not any(c in rx for c in ".*+?[]()")


set_registry(seed_technologies())   # usable without a database (tests, tooling); replaced by the persisted catalogue at start-up
