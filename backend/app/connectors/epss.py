"""FIRST EPSS API (https://api.first.org/data/v1/epss)."""
from __future__ import annotations

from .http import get_json

URL = "https://api.first.org/data/v1/epss"
CHUNK = 80  # keeps the query string well under URL limits


def parse(payload: dict) -> list[dict]:
    out = []
    for r in payload.get("data") or []:
        try:
            out.append({
                "cve_id": str(r["cve"]).upper(),
                "score": float(r["epss"]),
                "percentile": float(r["percentile"]),
                "date": str(r.get("date", "")),
            })
        except (KeyError, TypeError, ValueError):
            continue
    return [r for r in out if 0.0 <= r["score"] <= 1.0]


def fetch(cve_ids: list[str]) -> list[dict]:
    out: list[dict] = []
    for i in range(0, len(cve_ids), CHUNK):
        chunk = cve_ids[i : i + CHUNK]
        out += parse(get_json(URL, params={"cve": ",".join(chunk), "limit": len(chunk)}))
    return out
