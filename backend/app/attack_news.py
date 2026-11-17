"""Links news to ATT&CK groups and campaigns — only on explicit, verifiable evidence. Never changes any score.

confirmed : the article text contains the entity's ATT&CK id (G0016 / C0024) or its attack.mitre.org page URL
            (the id must exist in the imported catalogue).
candidate : the article TITLE contains a distinctive name/alias of exactly one entity. This is only a name mention:
            it is NOT an attribution and is shown separately as unverified.
Ambiguous names (shared by several entities, very short, or common words) are never linked at all.
"""
from __future__ import annotations

import re

from . import db
from .news import intel

ID_RE = re.compile(r"\b([GC]\d{4})\b")
URL_RE = re.compile(r"attack\.mitre\.org/(?:groups|campaigns)/([GC]\d{4})", re.I)
CODE_NAME = re.compile(r"^(APT|FIN|UNC|TA|DEV-|Storm-)\d+$", re.I)
COMMON_WORDS = {"silence", "inception", "patchwork", "strider", "carbon", "sandstorm", "wizard", "dragon", "tick", "gold", "cobalt", "leafminer"}
MIN_LEN = {"intrusion-set": 5, "campaign": 10}

_cache: dict = {"key": None, "idx": None, "result": None}


def _index(con):
    ids: dict[str, str] = {}
    owners: dict[str, set[str]] = {}
    meta: dict[str, dict] = {}
    for r in con.execute("SELECT attack_id,name,aliases,type FROM stix_object WHERE type IN ('intrusion-set','campaign') AND revoked=0 AND deprecated=0"):
        ids[r["attack_id"]] = r["type"]
        meta[r["attack_id"]] = {"name": r["name"], "type": r["type"]}
        names = {r["name"], *(__import__("json").loads(r["aliases"] or "[]"))}
        for n in names:
            key = n.strip().lower()
            owners.setdefault(key, set()).add(r["attack_id"])
    names = []
    for key, own in owners.items():
        if len(own) != 1:
            continue  # ambiguous alias
        aid = next(iter(own))
        typ = meta[aid]["type"]
        if key in COMMON_WORDS or (len(key) < MIN_LEN[typ] and not CODE_NAME.match(key)):
            continue
        names.append((re.compile(r"(?<![\w\-])" + re.escape(key) + r"(?![\w\-])", re.I), aid))
    return ids, names


def _scan(corpus, con) -> dict[str, dict[str, list]]:
    ck = (id(corpus), con.execute("SELECT last_success FROM stix_sync WHERE key='enterprise-attack'").fetchone())
    ck = (ck[0], tuple(ck[1]) if ck[1] else None)
    if _cache["key"] == ck:
        return _cache["result"]
    ids, names = _index(con)
    out: dict[str, dict[str, list]] = {}
    for it in corpus.items:
        text = f"{it['title']} {it['summary']}"
        found = {m for m in ID_RE.findall(text) if m in ids} | {m.upper() for m in URL_RE.findall(text) if m.upper() in ids}
        for a in found:
            out.setdefault(a, {"confirmed": [], "candidates": []})["confirmed"].append(it)
        for rx, aid in names:
            if aid not in found and rx.search(it["title"]):
                out.setdefault(aid, {"confirmed": [], "candidates": []})["candidates"].append(it)
    _cache.update(key=ck, result=out)
    return out


def news_for(attack_id: str, limit: int = 10) -> dict:
    with db.connect() as con:
        corpus = intel.get_corpus(con)
        hits = _scan(corpus, con).get(attack_id, {"confirmed": [], "candidates": []})
    shape = lambda items: [intel.article(m, corpus) for m in sorted(items, key=lambda x: x["ts"], reverse=True)[:limit]]  # noqa: E731
    return {"confirmed": shape(hits["confirmed"]), "confirmed_total": len(hits["confirmed"]),
            "candidates": shape(hits["candidates"]), "candidates_total": len(hits["candidates"]),
            "rule": "Confirmed = the article cites the ATT&CK id or its attack.mitre.org page. Candidate = a distinctive name appears in the headline; this is not attribution and is not verified."}


def reverse(con, corpus) -> dict[str, dict[str, list[str]]]:
    """news id -> {"confirmed": [attack ids], "candidates": [attack ids]} (same rules as news_for)."""
    out: dict[str, dict[str, list[str]]] = {}
    for aid, d in _scan(corpus, con).items():
        for kind in ("confirmed", "candidates"):
            for it in d[kind]:
                out.setdefault(it["id"], {"confirmed": [], "candidates": []})[kind].append(aid)
    return out


_tech_cache: dict = {"id": None, "map": None}


def technique_mentions(corpus) -> dict[str, list]:
    """ATT&CK technique id -> corpus items that write that id explicitly (validated against the catalogue)."""
    if _tech_cache["id"] == id(corpus):
        return _tech_cache["map"]
    m: dict[str, list] = {}
    for it in corpus.items:
        for t in it["entities"]["mitre"]:
            m.setdefault(t["id"], []).append(it)
    _tech_cache.update(id=id(corpus), map=m)
    return m
