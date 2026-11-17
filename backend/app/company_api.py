"""Company Threat Intelligence REST API (/api/v1/companies).

SECURITY MODEL (first version = local administrative tool). EVERY route, reads included, uses the existing policy: allowed from the
local machine, or from elsewhere only with the SYNC_TOKEN header when SYNC_TOKEN is configured. company_id scoping prevents accidental
cross-company access but is NOT multi-tenant isolation or authentication. Do not expose this module with real client data to the Internet
without per-organisation authentication and authorisation. `owner_id` columns prepare a future multi-user model.
"""
from __future__ import annotations

import re
from datetime import date

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request
from pydantic import BaseModel, Field

from . import company, company_expo, company_intel as ci, db
from .company import CompanyError
from .exposure import STATUSES
from .security import authorize_sync

CVE_ID = re.compile(r"CVE-\d{4}-\d{4,7}")


def guard(request: Request, x_sync_token: str | None = Header(default=None)) -> None:
    authorize_sync(request, x_sync_token)


router = APIRouter(prefix="/api/v1/companies", tags=["companies"], dependencies=[Depends(guard)])
PERIOD = "^(24h|7d|30d|90d|custom)$"
FIXED = "^(24h|7d|30d|90d)$"


def run(fn, *a, write=False, snap: str | None = None, **k):
    try:
        with db.connect() as con:
            out = fn(con, *a, **k)
            if write and snap:
                try:
                    ci.take_snapshot(con, a[0], snap, ci.SNAP_MIN_MINUTES)
                except Exception:
                    pass
            return out
    except CompanyError as e:
        raise HTTPException(e.status, e.msg)
    except ValueError as e:      # analytics window validation
        raise HTTPException(422, str(e))


class CompanyIn(BaseModel):
    name: str | None = Field(None, max_length=200)
    trade_name: str | None = Field(None, max_length=200)
    industry: str | None = Field(None, max_length=200)
    country: str | None = Field(None, max_length=200)
    description: str | None = Field(None, max_length=2000)
    status: str | None = Field(None, pattern="^(active|archived)$")


class AssetIn(BaseModel):
    tech_id: str | None = Field(None, max_length=60)
    vendor: str | None = Field(None, max_length=80)
    product: str | None = Field(None, max_length=80)
    label: str | None = Field(None, max_length=100)
    asset_ref: str | None = Field(None, max_length=100)
    version: str | None = Field(None, max_length=60)
    version_min: str | None = Field(None, max_length=60)
    version_max: str | None = Field(None, max_length=60)
    environment: str | None = None
    criticality: str | None = None
    internet_exposed: str | None = None
    status: str | None = None
    last_verified: str | None = Field(None, max_length=20)
    notes: str | None = Field(None, max_length=1000)


class AssessmentIn(BaseModel):
    company_tech_id: int
    status: str
    evidence: str | None = Field(None, max_length=1200)
    reference_url: str | None = Field(None, max_length=500)


class ReportIn(BaseModel):
    period: str = Field("30d", pattern=FIXED)


def _d(m: BaseModel) -> dict:
    return m.model_dump(exclude_unset=True)


def _cve(v: str) -> str:
    if not CVE_ID.fullmatch(v.upper()):
        raise HTTPException(422, "Invalid CVE id")
    return v.upper()


# ---- companies
@router.get("")
def list_companies(q: str | None = Query(None, max_length=80), status: str = Query("active", pattern="^(active|archived|all)$"), industry: str | None = Query(None, max_length=80),
                   page: int = Query(1, ge=1, le=100), page_size: int = Query(25, ge=1, le=50)):
    return run(company.list_companies, q=q, status=status, industry=industry, page=page, page_size=page_size)


@router.post("", status_code=201)
def create_company(body: CompanyIn):
    return run(company.create, _d(body))


@router.get("/compare")
def compare(ids: str = Query(..., max_length=200)):
    return run(ci.compare, [i for i in ids.split(",") if i])


@router.get("/{cid}")
def get_company(cid: str):
    return run(company.profile, cid)


@router.put("/{cid}")
def update_company(cid: str, body: CompanyIn):
    return run(company.update, cid, _d(body))


@router.post("/{cid}/archive")
def archive(cid: str):
    return run(company.update, cid, {"status": "archived"})


@router.post("/{cid}/restore")
def restore(cid: str):
    return run(company.update, cid, {"status": "active"})


# ---- inventory
def _inventory(con, cid):
    from . import catalog_api
    inv = company.inventory(con, cid)
    meta = {r["id"]: r for r in catalog_api.rows(con)} if any(t["tech_id"] for t in inv["technologies"]) else {}
    for t in inv["technologies"]:
        m = meta.get(t["tech_id"])
        t["catalog_info"] = {k: m[k] for k in ("vendor", "product", "category", "kind", "coverage_state", "coverage_label", "monitored", "score_possible", "cve_count", "kev_count")} if m else None
    return {**inv, "coverage": company.coverage([a for t in inv["technologies"] for a in t["assets"]]),
            "options": {"environments": list(company.ENVS), "criticalities": list(company.CRITS), "internet_exposed": list(company.EXPOSED)}}


@router.get("/{cid}/inventory")
def inventory(cid: str):
    return run(_inventory, cid)


@router.post("/{cid}/assets", status_code=201)
def add_asset(cid: str, body: AssetIn):
    return run(company.add_asset, cid, _d(body), write=True, snap="inventory_change")


@router.put("/{cid}/assets/{aid}")
def update_asset(cid: str, aid: int, body: AssetIn):
    return run(company.update_asset, cid, aid, _d(body), write=True, snap="inventory_change")


# ---- dashboard / technologies / vulnerabilities / news
@router.get("/{cid}/dashboard")
def dashboard(cid: str, period: str = Query("30d", pattern=FIXED)):
    return run(ci.dashboard, cid, period)


@router.get("/{cid}/technologies/{ctid}")
def technology(cid: str, ctid: int):
    return run(ci.tech_detail, cid, ctid)


@router.get("/{cid}/vulnerabilities")
def vulnerabilities(cid: str, status: str | None = Query(None, pattern="^(" + "|".join(STATUSES) + "|unassessed)$"), technology: int | None = Query(None, ge=1), kev: bool | None = None,
                    q: str | None = Query(None, max_length=60), sort: str = Query("priority", pattern="^(priority|cvss|epss|published|status)$"),
                    page: int = Query(1, ge=1, le=200), page_size: int = Query(25, ge=1, le=50)):
    return run(ci.vulnerabilities, cid, status=status, ctid=technology, kev=kev, q=q, sort=sort, page=page, page_size=page_size)


@router.get("/{cid}/vulnerabilities/{cve}")
def vulnerability(cid: str, cve: str):
    return run(company_expo.cve_fiche, cid, _cve(cve))


@router.put("/{cid}/vulnerabilities/{cve}/assessment")
def assess(cid: str, cve: str, body: AssessmentIn):
    return run(company_expo.assess, cid, _cve(cve), _d(body), write=True, snap="assessment_change")


@router.get("/{cid}/news")
def news(cid: str, official: bool | None = None, page: int = Query(1, ge=1, le=100), page_size: int = Query(20, ge=1, le=50)):
    return run(ci.news, cid, official=official, page=page, page_size=page_size)


# ---- analytics / changes
@router.get("/{cid}/analytics")
def analytics_(cid: str, period: str = Query("30d", pattern=PERIOD), date_from: date | None = None, date_to: date | None = None, mode: str = Query("all", pattern="^(all|comparable)$")):
    return run(ci.company_analytics, cid, period, date_from.isoformat() if date_from else None, date_to.isoformat() if date_to else None, mode)


@router.get("/{cid}/changes")
def changes(cid: str, period: str = Query("7d", pattern=PERIOD), date_from: date | None = None, date_to: date | None = None, page: int = Query(1, ge=1, le=100), page_size: int = Query(30, ge=1, le=50)):
    return run(ci.changes, cid, period, date_from.isoformat() if date_from else None, date_to.isoformat() if date_to else None, page, page_size)


# ---- reports
@router.post("/{cid}/reports", status_code=201)
def create_report(cid: str, body: ReportIn):
    return run(ci.save_report, cid, body.period)


@router.get("/{cid}/reports")
def reports(cid: str, limit: int = Query(30, ge=1, le=100)):
    return {"items": run(ci.list_reports, cid, limit)}


@router.get("/{cid}/reports/{rid}")
def report(cid: str, rid: str):
    return run(ci.get_report, cid, rid)


@router.get("/{cid}/reports/{rid}/text")
def report_text(cid: str, rid: str):
    return {"text": ci.report_text(run(ci.get_report, cid, rid))}
