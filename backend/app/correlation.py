"""Correlate CVEs with catalog technologies using structured product data only."""
from __future__ import annotations

import re
from typing import Iterable

from .catalog import CATALOG, VERSION, Technology


def parse_cpe(criteria: str) -> tuple[str, str, str] | None:
    """'cpe:2.3:o:microsoft:windows_server_2022:-:...' -> ('o','microsoft','windows_server_2022')."""
    if not isinstance(criteria, str):
        return None
    parts = re.split(r"(?<!\\):", criteria)
    if len(parts) < 5 or parts[0] != "cpe" or parts[1] != "2.3":
        return None
    part, vendor, product = parts[2].lower(), parts[3].lower(), parts[4].lower()
    if not vendor or vendor in ("*", "-") or not product or product in ("*", "-"):
        return None
    return part, vendor, product


_idx: dict = {"version": -1, "by_vendor": {}}


def _by_vendor() -> dict[str, list[tuple[Technology, re.Pattern]]]:
    """vendor -> [(technology, compiled product regex)] for ENABLED technologies; rebuilt when the catalogue changes."""
    if _idx["version"] != VERSION[0]:
        d: dict[str, list] = {}
        for t in CATALOG:
            for v, p in t.cpe_matchers:
                d.setdefault(v, []).append((t, re.compile(p)))
        _idx.update(version=VERSION[0], by_vendor=d)
    return _idx["by_vendor"]


def match_cpes(vendor: str, product: str) -> list[Technology]:
    """Every technology whose declared CPE identifiers cover this vendor/product exactly (never by vendor alone)."""
    return [t for t, rx in _by_vendor().get(vendor, ()) if rx.fullmatch(product)]


def match_cpe(vendor: str, product: str) -> Technology | None:
    m = match_cpes(vendor, product)
    return m[0] if m else None


def correlate_cpes(cpes: Iterable[str]) -> dict[str, set[str]]:
    """cpes: 'part:vendor:product' strings of *vulnerable* matches -> {tech_id: {product,...}}."""
    out: dict[str, set[str]] = {}
    for c in cpes:
        bits = c.split(":")
        if len(bits) != 3:
            continue
        for t in match_cpes(bits[1], bits[2]):
            out.setdefault(t.id, set()).add(f"{bits[1]} {bits[2]}")
    return out


def correlate_kev(vendor: str, product: str) -> Technology | None:
    v, p = (vendor or "").strip().lower(), (product or "").strip().lower()
    for t in CATALOG:
        for vm, pm in t.kev_matchers:
            if re.fullmatch(vm, v) and re.fullmatch(pm, p):
                return t
    return None


def kev_is_ambiguous_candidate(vendor: str) -> bool:
    """Vendor of a catalog tech but product not explicitly recognised: needs NVD CPE confirmation."""
    v = (vendor or "").strip().lower()
    return any(v in t.ambiguous_kev_vendors for t in CATALOG)
