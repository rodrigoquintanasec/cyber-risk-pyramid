"""Company exposure assessment: related CVEs per product, automatic applicability per asset, manual assessments with history.

Terminology (never interchangeable): Threat Signal (global, per technology) / Potential Exposure (product+version match) /
Confirmed Exposure (analyst-validated with evidence) / Intelligence Attention (news and advisories).
Global vulnerability tables are only read, never written.
"""
from __future__ import annotations

import re
import threading
from datetime import datetime, timezone

from . import company, db, exposure
from .company import CompanyError
from .exposure import CONFIRMED, LABELS, STATUSES, Product
from .vulns import BASE_SQL

MAX_CVES_PER_PRODUCT = 3000
URL_RE = re.compile(r"^https?://[^\s]{4,480}$")
_memo: dict = {}
_lock = threading.Lock()


def _esc(s: str) -> str:
    return s.replace("!", "!!").replace("%", "!%").replace("_", "!_")


def _assess(asset: dict, prod: Product, rng) -> dict:
    if rng is not None and rng[0] == "config":
        return exposure.assess_from_config(asset, prod, rng[1])
    return exposure.assess_asset(asset, prod, rng[1] if rng else None)


def product_of(ct: dict) -> Product:
    return Product(ct["tech_id"], ct["vendor"], ct["product"])


def related_rows(con, ct: dict) -> tuple[list[dict], bool]:
    """CVEs related to one product by structured identifiers only (catalog correlation or exact CPE vendor/product). Vendor-only never matches."""
    if ct["tech_id"]:
        where, args = "id IN (SELECT cve_id FROM tech_cve WHERE tech_id=? UNION SELECT cve_id FROM tech_cve_hist WHERE tech_id=?)", [ct["tech_id"], ct["tech_id"]]
    else:
        v, p = ct["vendor"], ct["product"]
        where = "((',' || cpes || ',') LIKE ? ESCAPE '!' OR (REPLACE(kv,' ','_')=? AND REPLACE(kp,' ','_')=?))"
        args = [f"%,_:{_esc(v)}:{_esc(p)},%", v, p]
    rows = [dict(r) for r in con.execute(f"SELECT id,published,cvss,cvss_version,epss,epss_pct,in_kev,kev_date,ransomware,description FROM ({BASE_SQL}) WHERE {where} LIMIT ?", [*args, MAX_CVES_PER_PRODUCT + 1])]
    return rows[:MAX_CVES_PER_PRODUCT], len(rows) > MAX_CVES_PER_PRODUCT


def _ranges(con, ids: list[str]) -> dict[str, tuple[str, object] | None]:
    """cve -> ('config', parsed NVD configuration tree) when the local database stored it, else ('legacy', flat range entries), else None (unknown)."""
    out: dict[str, tuple[str, object] | None] = {}
    for i in range(0, len(ids), 400):
        ch = ids[i:i + 400]
        ph = ",".join("?" * len(ch))
        nv = {r[0]: (r[1], r[2]) for r in con.execute(f"SELECT cve_id,versions,config_json FROM nvd_cve WHERE cve_id IN ({ph})", ch)}
        dv = {r[0]: r[1] for r in con.execute(f"SELECT cve_id,versions FROM cve_detail WHERE cve_id IN ({ph})", ch)}
        for c in ch:
            versions, cfg = nv.get(c, (None, None))
            parsed = exposure.parse_config(cfg)
            if parsed is not None:
                out[c] = ("config", parsed)
            else:
                ent = exposure.load_entries(versions, dv.get(c))
                out[c] = ("legacy", ent) if ent is not None else None
    return out


def _sig(con, cid: str) -> tuple:
    q = lambda s, *a: tuple(con.execute(s, a).fetchone())  # noqa: E731
    return (company._ver[0], q("SELECT COUNT(*),COALESCE(MAX(updated_at),'') FROM company_asset WHERE company_id=?", cid), q("SELECT COUNT(*) FROM company_technology WHERE company_id=?", cid),
            q("SELECT COUNT(*),COALESCE(MAX(updated_at),'') FROM company_vulnerability_assessment WHERE company_id=?", cid),
            q("SELECT COUNT(*),COALESCE(MAX(fetched_at),'') FROM nvd_cve"), q("SELECT COUNT(*) FROM kev_entry"), q("SELECT COUNT(*) FROM tech_cve"), q("SELECT COUNT(*) FROM tech_cve_hist"),
            q("SELECT COUNT(*),COALESCE(MAX(fetched_at),'') FROM cve_detail"), q("SELECT COUNT(*),COALESCE(MAX(fetched_at),'') FROM epss"))


def company_exposure(con, cid: str) -> dict:
    """{'products': {ctid: ct+assets}, 'cves': {cve: {...record, 'per_tech': {ctid: {...}}, 'effective': status}}, 'truncated': bool}. Memoised per data signature."""
    company.get(con, cid)
    sig = _sig(con, cid)
    with _lock:
        hit = _memo.get(cid)
        if hit and hit[0] == sig:
            return hit[1]
    inv = company.inventory(con, cid)
    products = {t["id"]: t for t in inv["technologies"]}
    manual = {(r["cve_id"], r["company_tech_id"]): dict(r) for r in con.execute("SELECT * FROM company_vulnerability_assessment WHERE company_id=?", (cid,))}
    cves: dict[str, dict] = {}
    truncated = False
    for ctid, ct in products.items():
        rows, tr = related_rows(con, ct)
        truncated |= tr
        rng = _ranges(con, [r["id"] for r in rows])
        prod = product_of(ct)
        act = [a for a in ct["assets"] if a["status"] == "active"]
        for r in rows:
            rec = cves.setdefault(r["id"], {**r, "in_kev": bool(r["in_kev"]), "per_tech": {}})
            res = [{"asset_id": a["id"], "asset_ref": a["asset_ref"], "version": a["version"] or (f"{a['version_min'] or '*'}–{a['version_max'] or '*'}" if a["version_min"] or a["version_max"] else None),
                    **_assess(a, prod, rng.get(r["id"]))} for a in act]
            auto = exposure.worst(x["status"] for x in res) if res else None
            man = manual.get((r["id"], ctid))
            rec["per_tech"][ctid] = {"company_tech_id": ctid, "label": ct["label"], "auto": auto, "assets": res, "manual": man, "effective": man["status"] if man else auto,
                                     "ranges_cached": rng.get(r["id"]) is not None}
    for rec in cves.values():
        eff = [t["effective"] for t in rec["per_tech"].values() if t["effective"]]
        rec["effective"] = exposure.worst(eff)
        rec["assets_flagged"] = sum(1 for t in rec["per_tech"].values() for a in t["assets"] if a["status"] in (exposure.POTENTIAL, exposure.REVIEW))
    out = {"products": products, "cves": cves, "truncated": truncated}
    with _lock:
        if len(_memo) > 100:
            _memo.clear()
        _memo[cid] = (sig, out)
    return out


def counts(expo: dict) -> dict:
    c = {s: 0 for s in STATUSES}
    for rec in expo["cves"].values():
        if rec["effective"]:
            c[rec["effective"]] += 1
    return {"related": len(expo["cves"]), "kev": sum(1 for r in expo["cves"].values() if r["in_kev"]), "statuses": c, "unassessed": sum(1 for r in expo["cves"].values() if not r["effective"])}


# ----------------------------------------------------------------------------- manual assessments
def assess(con, cid: str, cve_id: str, d: dict, who: str = "local analyst") -> dict:
    company.get(con, cid, writable=True)
    cve_id = (cve_id or "").upper()
    status = d.get("status")
    if status not in STATUSES:
        raise CompanyError(422, f"status must be one of {', '.join(STATUSES)}")
    ctid = d.get("company_tech_id")
    ct = con.execute("SELECT id FROM company_technology WHERE id=? AND company_id=?", (ctid if isinstance(ctid, int) else -1, cid)).fetchone()
    if not ct:
        raise CompanyError(404, "Product not found for this company")
    expo = company_exposure(con, cid)
    if cve_id not in expo["cves"] or ct["id"] not in expo["cves"][cve_id]["per_tech"]:
        raise CompanyError(422, "This CVE is not related to that product of the company")
    evidence = company._txt(d.get("evidence"), "Evidence", 1000)
    ref = (d.get("reference_url") or "").strip() or None
    if ref and not URL_RE.match(ref):
        raise CompanyError(422, "reference_url must be an http(s) URL")
    if status == CONFIRMED and not ((evidence and len(evidence) >= 10) or ref):
        raise CompanyError(422, "Confirmed Applicable requires recorded evidence (a note of at least 10 characters or a reference URL)")
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    company.touch()
    old = con.execute("SELECT * FROM company_vulnerability_assessment WHERE company_id=? AND cve_id=? AND company_tech_id=?", (cid, cve_id, ct["id"])).fetchone()
    if old and (old["status"], old["evidence"], old["reference_url"]) == (status, evidence, ref):
        return {"changed": False, "assessment": dict(old)}
    if old:
        con.execute("UPDATE company_vulnerability_assessment SET status=?,evidence=?,reference_url=?,assessed_by=?,assessed_at=?,updated_at=? WHERE id=?", (status, evidence, ref, who, now, now, old["id"]))
        aid = old["id"]
    else:
        aid = con.execute("INSERT INTO company_vulnerability_assessment(company_id,cve_id,company_tech_id,status,evidence,reference_url,assessed_by,assessed_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)",
                          (cid, cve_id, ct["id"], status, evidence, ref, who, now, now)).lastrowid
    con.execute("INSERT INTO company_assessment_history(assessment_id,company_id,cve_id,company_tech_id,old_status,new_status,evidence,reference_url,assessed_by,changed_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
                (aid, cid, cve_id, ct["id"], old["status"] if old else None, status, evidence, ref, who, now))
    company.log_event(con, cid, "assessment_changed", cve_id, f"{LABELS.get(old['status']) if old else 'new'} → {LABELS[status]}")
    return {"changed": True, "assessment": dict(con.execute("SELECT * FROM company_vulnerability_assessment WHERE id=?", (aid,)).fetchone())}


def history(con, cid: str, cve_id: str) -> list[dict]:
    company.get(con, cid)
    return [dict(r) for r in con.execute("SELECT * FROM company_assessment_history WHERE company_id=? AND cve_id=? ORDER BY id DESC LIMIT 200", (cid, cve_id.upper()))]


def cve_fiche(con, cid: str, cve_id: str) -> dict:
    from . import vulns
    cve_id = cve_id.upper()
    expo = company_exposure(con, cid)
    rec = expo["cves"].get(cve_id)
    if not rec:
        raise CompanyError(404, "CVE is not related to any product of this company")
    g = vulns.detail(con, cve_id) or {}
    ranges = (g.get("detail") or {}).get("versions") or []
    return {
        "cve": cve_id, "description": g.get("description") or rec.get("description"), "cvss": rec["cvss"], "cvss_version": rec.get("cvss_version"), "epss": rec["epss"], "epss_percentile": rec.get("epss_pct"),
        "kev": g.get("kev"), "published": rec["published"], "effective_status": rec["effective"], "effective_label": LABELS.get(rec["effective"]),
        "products": [{"company_tech_id": t["company_tech_id"], "label": t["label"], "automatic_status": t["auto"], "effective_status": t["effective"], "ranges_cached": t["ranges_cached"],
                      "assets": t["assets"], "assessment": t["manual"], "history": history(con, cid, cve_id) if False else None} for t in rec["per_tech"].values()],
        "documented_versions": ranges, "references": ((g.get("detail") or {}).get("references") or [])[:15], "global_links": g.get("links"),
        "history": history(con, cid, cve_id), "last_assessed": max((t["manual"]["assessed_at"] for t in rec["per_tech"].values() if t["manual"]), default=None),
        "notes": ["Automatic statuses never reach Confirmed Applicable; only an analyst's recorded evidence can.",
                  "Assessments belong to this company and never change the global vulnerability records."]}
