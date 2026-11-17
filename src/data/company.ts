import type { Technology } from './types'

async function req<T>(method: string, url: string, body?: unknown): Promise<T> {
  const r = await fetch(url, { method, headers: body ? { 'Content-Type': 'application/json' } : undefined, body: body ? JSON.stringify(body) : undefined })
  if (!r.ok) {
    let msg = `HTTP ${r.status}`
    try { const j = await r.json(); if (typeof j.detail === 'string') msg = j.detail; else if (Array.isArray(j.detail)) msg = j.detail.map((d: { msg: string }) => d.msg).join('; ') } catch { /* ignore */ }
    throw new Error(msg)
  }
  return r.json() as Promise<T>
}
const q = (o: Record<string, string | number | boolean | undefined | null>) => {
  const p = new URLSearchParams()
  Object.entries(o).forEach(([k, v]) => { if (v !== undefined && v !== null && v !== '') p.set(k, String(v)) })
  return p.toString()
}

export type Applicability = 'confirmed_applicable' | 'potentially_applicable' | 'not_applicable' | 'needs_review' | 'insufficient_data'
export const STATUS_LABEL: Record<string, string> = { confirmed_applicable: 'Confirmed Applicable', potentially_applicable: 'Potentially Applicable', not_applicable: 'Not Applicable', needs_review: 'Needs Review', insufficient_data: 'Insufficient Data', unassessed: 'Unassessed' }

export interface Company { id: string; name: string; trade_name: string | null; industry: string; country: string | null; description: string | null; status: 'active' | 'archived'; created_at: string; updated_at: string; technologies: number; assets: number; retired_assets: number; last_verified: string | null }
export interface CompanyPage { items: Company[]; total: number; page: number; pages: number; industries: string[] }
export interface Asset { id: number; company_tech_id: number; asset_ref: string | null; version: string | null; version_min: string | null; version_max: string | null; environment: string; criticality: string; internet_exposed: 'yes' | 'no' | 'unknown'; status: 'active' | 'retired'; last_verified: string | null; notes: string | null }
export interface Product { id: number; tech_id: string | null; vendor: string | null; product: string | null; label: string; catalog: boolean; active_assets: number; assets: Asset[]; catalog_info?: { vendor: string; product: string; category: string; kind: string; coverage_state: 'monitored' | 'partial' | 'catalog_only'; coverage_label: string; monitored: boolean; score_possible: boolean; cve_count: number; kev_count: number } | null }
export interface Coverage { active_assets: number; with_version_pct: number | null; exposure_known_pct: number | null; verified_pct: number | null; verified_90d_pct: number | null; median_verification_age_days: number | null; oldest_verification_days: number | null; inventory_coverage: number | null }
export interface Inventory { technologies: Product[]; assets: number; active_assets: number; coverage: Coverage; options: { environments: string[]; criticalities: string[]; internet_exposed: string[] } }
export interface CKpi { key: string; label: string; value: number | null; unit?: string; scope: 'signal' | 'potential' | 'confirmed' | 'attention' | 'coverage'; hint?: string }
export interface CTech extends Technology { company_tech_id: number; catalog: boolean; assets: number; retired_assets: number; versions: string[]; assets_without_version: number; related_cves: number; related_kev: number; exposure: { potential: number; confirmed: number; needs_review: number; insufficient: number }; news_events: number | null; official_advisories: number | null; data_availability: 'full' | 'monitored' | 'partial' | 'catalog_only' | 'unavailable' }
export interface Dashboard { company: Company; period: string; kpis: CKpi[]; technologies: CTech[]; exposure: { related: number; kev: number; statuses: Record<string, number>; unassessed: number }; inventory: Coverage; truncated: boolean; notes: string[]; concepts: Record<string, string> }
export interface TechDetail { company_tech_id: number; technology: CTech; catalog: boolean; vendor: string | null; product: string | null; assets: Asset[]; cves: { id: string; cvss: number | null; epss: number | null; kev: boolean; published: string | null; effective_status: Applicability | null; automatic_status: Applicability | null; assets_flagged: number }[]; cve_total: number; advisories: { id: string; title: string; url: string; last_published: string; sources: number; priority: number }[]; news: { id: string; title: string; url: string; last_published: string; sources: number; priority: number }[]; graph_node: string | null; explorer: { tech?: string; vendor?: string | null; product?: string | null }; news_available: boolean; note: string | null }
export interface VulnRow { id: string; description: string | null; cvss: number | null; epss: number | null; kev: boolean; published: string | null; effective_status: Applicability | null; products: { company_tech_id: number; label: string; status: Applicability | null; assessed: boolean }[]; assets_flagged: number }
export interface VulnPage { items: VulnRow[]; total: number; page: number; pages: number; counts: { related: number; kev: number; statuses: Record<string, number>; unassessed: number }; note: string }
export interface AssetStatus { asset_id: number; asset_ref: string | null; version: string | null; status: Applicability; reason: string }
export interface Assessment { status: Applicability; evidence: string | null; reference_url: string | null; assessed_at: string; assessed_by: string | null }
export interface Fiche { cve: string; description: string | null; cvss: number | null; epss: number | null; kev: { date_added: string } | null; published: string | null; effective_status: Applicability | null; products: { company_tech_id: number; label: string; automatic_status: Applicability | null; effective_status: Applicability | null; ranges_cached: boolean; assets: AssetStatus[]; assessment: Assessment | null }[]; documented_versions: { product: string; version: string | null; from_incl: string | null; to_excl: string | null; to_incl: string | null; from_excl: string | null }[]; references: { url: string }[]; history: { id: number; old_status: string | null; new_status: string; evidence: string | null; reference_url: string | null; changed_at: string; company_tech_id: number }[]; last_assessed: string | null; notes: string[] }
export type { Cmp } from './analytics'
import type { Cmp } from './analytics'
export interface CAnalytics {
  status: 'ok' | 'insufficient_comparable'; message: string | null; filters: { since: string; until: string; bucket_hours: number; comparable: { count: number; excluded: number; excluded_reasons: Record<string, number>; criteria: string[] } | null }
  timeline: { bucket_starts: string[]; events: number[]; articles: number[]; official_advisory_articles: number[]; compare: Cmp }
  discovery: { bucket_starts: string[]; new_cves: number[]; kev_related_new: number[]; compare: Cmp; note: string }
  kev_watch: { bucket_starts: string[]; series: number[]; total_related: number; compare: Cmp; added: { cve: string; kev_added: string; cvss: number | null; epss: number | null; status: Applicability | null; products: string[] }[]; note: string }
  attention: { tech_id: string; name: string; events: number; compare: Cmp }[]
  exposure_status: { current: Record<string, number>; unassessed: number; related: number; history: ({ taken_at: string } & Record<string, number | string>)[]; history_note: string | null }
  inventory_quality: { coverage: Coverage; by_technology: { label: string; assets: number; with_version: number }[]; verification_age: Record<string, number>; inventory_changes: { kind: string; n: number }[] }
  epss: { available: boolean; movers: { cve: string; from: number; to: number; delta: number }[]; note: string }
  snapshots: { count: number; first: string | null }; notes: string[]
}
export interface Change { kind: string; title: string; cve?: string | null; source?: string; url?: string; published_at: string | null; known_at: string; historical: boolean; note: string | null }
export interface Changes { items: Change[]; total: number; page: number; pages: number; counts: Record<string, number>; notes: string[]; snapshots: number }
export interface Report { id: string; company: { id: string; name: string; industry: string }; period: string; period_label: string; since: string; until: string; generated_at: string; last_sync: string | null; sections: Record<string, any> } // eslint-disable-line @typescript-eslint/no-explicit-any
export interface Compare { companies: { id: string; name: string; status: string; technologies: number; assets: number; related_cves: number; kev: number; potential: number; confirmed: number; events_30d: number; advisories_30d: number; inventory_coverage: number | null; with_version_pct: number | null; median_verification_age_days: number | null; oldest_verification_days: number | null; normalised: { cves_per_technology: number | null; potential_per_100_assets: number | null; kev_share_pct: number | null } }[]; notes: string[] }

const B = '/api/v1/companies'
export const cList = (f: { q?: string; status?: string; industry?: string; page?: number }) => req<CompanyPage>('GET', `${B}?${q({ ...f, page_size: 24 })}`)
export const cGet = (id: string) => req<Company>('GET', `${B}/${id}`)
export const cCreate = (b: Partial<Company>) => req<Company>('POST', B, b)
export const cUpdate = (id: string, b: Partial<Company>) => req<Company>('PUT', `${B}/${id}`, b)
export const cArchive = (id: string, archive: boolean) => req<Company>('POST', `${B}/${id}/${archive ? 'archive' : 'restore'}`)
export const cInventory = (id: string) => req<Inventory>('GET', `${B}/${id}/inventory`)
export const cAddAsset = (id: string, b: Record<string, unknown>) => req<Asset>('POST', `${B}/${id}/assets`, b)
export const cUpdateAsset = (id: string, aid: number, b: Record<string, unknown>) => req<Asset>('PUT', `${B}/${id}/assets/${aid}`, b)
export const cDashboard = (id: string, period: string) => req<Dashboard>('GET', `${B}/${id}/dashboard?period=${period}`)
export const cTech = (id: string, ctid: number) => req<TechDetail>('GET', `${B}/${id}/technologies/${ctid}`)
export const cVulns = (id: string, f: Record<string, string | number | boolean | undefined>) => req<VulnPage>('GET', `${B}/${id}/vulnerabilities?${q({ ...f, page_size: 20 })}`)
export const cFiche = (id: string, cve: string) => req<Fiche>('GET', `${B}/${id}/vulnerabilities/${cve}`)
export const cAssess = (id: string, cve: string, b: { company_tech_id: number; status: string; evidence?: string; reference_url?: string }) => req<{ changed: boolean }>('PUT', `${B}/${id}/vulnerabilities/${cve}/assessment`, b)
export const cNews = (id: string, official: boolean | undefined, page: number) => req<{ items: { id: string; title: string; url: string; summary: string | null; published: string | null; collected_at: string; source: { name: string; type_label: string } }[]; total: number; pages: number; note: string }>('GET', `${B}/${id}/news?${q({ official, page, page_size: 15 })}`)
export const cAnalytics = (id: string, f: { period: string; date_from?: string; date_to?: string; mode: string }) => req<CAnalytics>('GET', `${B}/${id}/analytics?${q(f)}`)
export const cChanges = (id: string, f: { period: string; date_from?: string; date_to?: string; page: number }) => req<Changes>('GET', `${B}/${id}/changes?${q({ ...f, page_size: 20 })}`)
export const cReports = (id: string) => req<{ items: { id: string; period: string; generated_at: string; summary: string }[] }>('GET', `${B}/${id}/reports`)
export const cReport = (id: string, rid: string) => req<Report>('GET', `${B}/${id}/reports/${rid}`)
export const cReportText = (id: string, rid: string) => req<{ text: string }>('GET', `${B}/${id}/reports/${rid}/text`)
export const cMakeReport = (id: string, period: string) => req<Report>('POST', `${B}/${id}/reports`, { period })
export const cCompare = (ids: string[]) => req<Compare>('GET', `${B}/compare?ids=${ids.join(',')}`)
