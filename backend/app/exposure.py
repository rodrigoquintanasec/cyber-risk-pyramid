"""Applicability of a CVE to a company's registered assets (deterministic, evidence based, no scanning).

Statuses
  confirmed_applicable   only ever set by an analyst with recorded evidence - never automatic
  potentially_applicable product matches AND the asset's version(s) fall inside a documented affected range
  not_applicable         product matches but every documented affected range is interpretable and excludes the asset's version(s)
  needs_review           ranges not cached locally, not interpretable, conditional (AND/negated) configurations, or product family ambiguity
  insufficient_data      the asset has no version information (or no assets)
A vendor match alone is never enough; a product match is required before a CVE is related to an asset at all.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass

from .catalog import BY_ID
from .correlation import match_cpe

CONFIRMED, POTENTIAL, NOT_APPLICABLE, REVIEW, INSUFFICIENT = "confirmed_applicable", "potentially_applicable", "not_applicable", "needs_review", "insufficient_data"
STATUSES = (CONFIRMED, POTENTIAL, NOT_APPLICABLE, REVIEW, INSUFFICIENT)
LABELS = {CONFIRMED: "Confirmed Applicable", POTENTIAL: "Potentially Applicable", NOT_APPLICABLE: "Not Applicable", REVIEW: "Needs Review", INSUFFICIENT: "Insufficient Data"}
_RANK = {CONFIRMED: 5, POTENTIAL: 4, REVIEW: 3, INSUFFICIENT: 2, NOT_APPLICABLE: 1}
VER_RE = re.compile(r"^v?\d+(\.\d+){0,5}$")


def worst(statuses) -> str | None:
    """Most actionable status of a set (confirmed > potential > review > insufficient > not applicable)."""
    return max(statuses, key=lambda s: _RANK[s], default=None)


def norm(s: str | None) -> str:
    return re.sub(r"\s+", "_", (s or "").strip().lower())


def parse_version(s) -> tuple[int, ...] | None:
    """Purely numeric dotted versions only. Anything else (build tags, letters) is NOT interpreted."""
    if s is None:
        return None
    t = str(s).strip().lower()
    return tuple(int(x) for x in t.lstrip("v").split(".")) if VER_RE.match(t) else None


def _cmp(a: tuple[int, ...], b: tuple[int, ...]) -> int:
    n = max(len(a), len(b))
    a, b = a + (0,) * (n - len(a)), b + (0,) * (n - len(b))
    return (a > b) - (a < b)


Interval = tuple  # (lo, lo_inclusive, hi, hi_inclusive) - None bound = unbounded


def overlaps(x: Interval, y: Interval) -> bool:
    lo = x if y[0] is None else y if x[0] is None else (x if _cmp(x[0], y[0]) > 0 or (_cmp(x[0], y[0]) == 0 and not x[1]) else y)
    hi = x if y[2] is None else y if x[2] is None else (x if _cmp(x[2], y[2]) < 0 or (_cmp(x[2], y[2]) == 0 and not x[3]) else y)
    if lo[0] is None or hi[2] is None:
        return True
    c = _cmp(lo[0], hi[2])
    return c < 0 or (c == 0 and lo[1] and hi[3])


def asset_interval(a: dict) -> Interval | None:
    """Exact version -> point; range -> [min, max] (a missing side is unbounded). None when nothing usable is known/interpretable."""
    if a.get("version"):
        v = parse_version(a["version"])
        return (v, True, v, True) if v else None
    if a.get("version_min") or a.get("version_max"):
        lo = parse_version(a.get("version_min")) if a.get("version_min") else None
        hi = parse_version(a.get("version_max")) if a.get("version_max") else None
        if (a.get("version_min") and lo is None) or (a.get("version_max") and hi is None):
            return None
        return (lo, True, hi, True)
    return None


def has_version_info(a: dict) -> bool:
    return bool(a.get("version") or a.get("version_min") or a.get("version_max"))


def entry_interval(e: dict) -> Interval | None | bool:
    """Affected range of one NVD cpeMatch. True = all versions, None = not interpretable."""
    if e.get("complex"):
        return None
    exact = e.get("ver")
    if exact is not None:
        v = parse_version(exact)
        return (v, True, v, True) if v else None
    bounds = [e.get("fi"), e.get("fe"), e.get("ti"), e.get("te")]
    if not any(bounds):
        return True
    parsed = [parse_version(b) if b else None for b in bounds]
    if any(b and p is None for b, p in zip(bounds, parsed)):
        return None
    fi, fe, ti, te = parsed
    lo = fi or fe
    hi = ti or te
    return (lo, bool(fi) or lo is None, hi, bool(ti) or hi is None)


# ----------------------------------------------------------------------------- product identity
@dataclass(frozen=True)
class Product:
    tech_id: str | None
    vendor: str | None
    product: str | None

    def matches(self, vendor: str, product: str) -> bool:
        vendor, product = norm(vendor), norm(product)
        if self.vendor and self.product:
            return vendor == self.vendor and product == self.product
        if self.tech_id and self.tech_id in BY_ID:
            t = match_cpe(vendor, product)
            return bool(t and t.id == self.tech_id)
        return False


def load_entries(nvd_versions: str | None, detail_versions: str | None) -> list[dict] | None:
    """Normalised affected-range entries {v,p,ver,fi,fe,ti,te,complex}; None when no range data is cached for the CVE."""
    if nvd_versions:
        try:
            return json.loads(nvd_versions)
        except ValueError:
            pass
    if detail_versions:
        try:
            out = []
            for d in json.loads(detail_versions):
                v, _, p = (d.get("product") or "").partition(" / ")
                out.append({"v": norm(v), "p": norm(p), "ver": d.get("version"), "fi": d.get("from_incl"), "fe": d.get("from_excl"), "ti": d.get("to_incl"), "te": d.get("to_excl"), "complex": False})
            return out
        except ValueError:
            return None
    return None


def assess_asset(asset: dict, product: Product, entries: list[dict] | None) -> dict:
    """Automatic applicability of ONE related CVE to ONE asset. Never returns confirmed_applicable."""
    if not has_version_info(asset):
        return {"status": INSUFFICIENT, "reason": "The asset has no version recorded, so applicability cannot be assessed."}
    if entries is None:
        return {"status": REVIEW, "reason": "Affected version ranges for this CVE are not cached locally (run a lookup in Vulnerability Explorer or wait for the next NVD sync)."}
    rel = [e for e in entries if product.matches(e.get("v", ""), e.get("p", ""))]
    if not rel:
        return {"status": REVIEW, "reason": "The CVE's documented configurations do not list this product with version data (it may be related through the CISA KEV catalogue only)."}
    if product.tech_id and not (product.vendor and product.product) and len({(e["v"], e["p"]) for e in rel}) > 1:
        return {"status": REVIEW, "reason": "The technology spans several products; register the exact vendor/product on the asset to evaluate versions."}
    ai = asset_interval(asset)
    if ai is None:
        return {"status": REVIEW, "reason": "The asset's version is not a plain numeric version, so it cannot be compared safely."}
    verdicts = []
    for e in rel:
        iv = entry_interval(e)
        verdicts.append(None if iv is None else True if iv is True else overlaps(ai, iv))
    if any(v is True for v in verdicts):
        return {"status": POTENTIAL, "reason": "The asset's version falls inside a documented affected range for this product. This is not confirmation that the asset is vulnerable."}
    if any(v is None for v in verdicts):
        return {"status": REVIEW, "reason": "Some affected-version conditions are complex or not interpretable with certainty."}
    return {"status": NOT_APPLICABLE, "reason": "Every documented affected range for this product excludes the asset's version."}


# ----------------------------------------------------------------------------- NVD configuration trees (AND / OR / negate / platform conditions)
_CPE_SPLIT = re.compile(r"(?<!\\):")
NVD_BOUNDS = {"vsi": "versionStartIncluding", "vse": "versionStartExcluding", "vei": "versionEndIncluding", "vee": "versionEndExcluding"}


def _match_entry(m: dict) -> tuple[str, str, dict] | None:
    p = _CPE_SPLIT.split(m.get("criteria", ""))
    if len(p) < 6 or p[0] != "cpe" or p[1] != "2.3":
        return None
    ver = p[5] if p[5] not in ("*", "-", "") else None
    return p[3].lower(), p[4].lower(), {"ver": ver, "fi": m.get("versionStartIncluding"), "fe": m.get("versionStartExcluding"), "ti": m.get("versionEndIncluding"), "te": m.get("versionEndExcluding"), "complex": False}


def parse_config(config_json: str | None) -> list | None:
    if not config_json:
        return None
    try:
        v = json.loads(config_json)
    except ValueError:
        return None
    return v if isinstance(v, list) and v else None


def assess_from_config(asset: dict, product: Product, configs: list) -> dict:
    """Applicability of a CVE to ONE asset evaluated on the ORIGINAL NVD configuration tree (never a flat product list).
    Configurations are OR-ed. A configuration is *simple* when it is a single OR node of vulnerable matches; anything with AND, negation or
    non-vulnerable (platform / 'running on') conditions can only yield Needs Review when the asset's version is inside the vulnerable range."""
    if not has_version_info(asset):
        return {"status": INSUFFICIENT, "reason": "The asset has no version recorded, so applicability cannot be assessed."}
    ai = asset_interval(asset)
    if ai is None:
        return {"status": REVIEW, "reason": "The asset's version is not a plain numeric version, so it cannot be compared safely."}
    simple_hit, conditional, unknown, targeted, seen = False, [], False, False, set()
    for conf in configs:
        nodes = conf.get("nodes") or []
        hits: list[bool | None] = []
        for node in nodes:
            for m in node.get("cpeMatch") or []:
                e = _match_entry(m)
                if not e or m.get("vulnerable") is not True or not product.matches(e[0], e[1]):
                    continue
                seen.add((e[0], e[1]))
                iv = entry_interval(e[2])
                hits.append(None if iv is None else True if iv is True else overlaps(ai, iv))
                if node.get("negate"):
                    hits[-1] = None
        if not hits:
            continue
        targeted = True
        is_simple = conf.get("operator") in (None, "OR") and len(nodes) == 1 and nodes[0].get("operator", "OR") == "OR" and not nodes[0].get("negate") \
            and all(m.get("vulnerable") is True for m in nodes[0].get("cpeMatch") or [])
        if any(h is True for h in hits):
            if is_simple:
                simple_hit = True
            else:
                kinds = sorted({("AND with other conditions" if (conf.get("operator") == "AND" or len(nodes) > 1) else "negated/conditional node") for _ in [0]})
                conditional.append(kinds[0])
        elif any(h is None for h in hits):
            unknown = True
    if product.tech_id and not (product.vendor and product.product) and len(seen) > 1:
        return {"status": REVIEW, "reason": "The technology spans several products; register the exact vendor/product on the asset to evaluate versions."}
    if simple_hit:
        return {"status": POTENTIAL, "reason": "The asset's version falls inside a documented affected range of a simple NVD configuration. This is not confirmation that the asset is vulnerable."}
    if conditional:
        return {"status": REVIEW, "reason": f"The version is inside an affected range, but the NVD configuration is conditional ({conditional[0]}): platform/other-product conditions must be checked by a person."}
    if unknown:
        return {"status": REVIEW, "reason": "Some affected-version conditions are not interpretable with certainty."}
    if targeted:
        return {"status": NOT_APPLICABLE, "reason": "Every vulnerable configuration for this product excludes the asset's version."}
    return {"status": REVIEW, "reason": "The CVE's configurations do not list this product with version data (it may be related through the CISA KEV catalogue only)."}
