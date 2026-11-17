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

export type CoverageState = 'monitored' | 'partial' | 'catalog_only'
export interface CatalogItem {
  id: string; name: string; vendor: string; product: string; category: string; kind: 'product' | 'family' | 'platform' | 'cloud'; description: string; aliases: string[]
  enabled: boolean; custom: boolean; monitor: 'auto' | 'on' | 'off'; monitored: boolean; dashboard: boolean
  coverage_state: CoverageState; coverage_label: string; limitations: string[]; has_cpe: boolean; score_possible: boolean
  correlation: { kind: 'exact' | 'family' | 'cloud' | 'kev-only' | 'unverified'; source: string }
  cve_count: number; recent_cve_count: number; historical_cve_count: number; kev_count: number; news_count: number; nvd_queries: string; last_sync: string | null
  sync: SyncBrief; cves_complete: boolean
}
export type SyncState = 'not_started' | 'pending' | 'in_progress' | 'partial' | 'completed' | 'failed' | 'rate_limited'
export interface SyncBrief { status: SyncState; label: string; applicable: boolean; queries_completed: number; queries_required: number; complete?: boolean }
export interface SyncFull extends SyncBrief { cves_retrieved: number; last_success: string | null; last_attempt: string | null; last_error: string | null; error_kind: string | null; next_eligible: string | null; history_limited: boolean; note: string | null }
export interface SyncJob { query: string; status: string; phase: string; fetched: number; total: number | null; calls: number }
export interface CatalogPage { items: CatalogItem[]; total: number; page: number; pages: number; note: string }
export interface CatalogFacets { total: number; enabled: number; categories: { id?: string; name: string; active?: boolean; count: number }[]; vendors: { name: string; count: number }[]; kinds: { name: string; count: number }[]; coverage: Record<CoverageState, number>; pinned: number; max_pinned: number; custom: number }
export interface CatalogDetail extends CatalogItem {
  monitoring_reasons: string[]; identifiers: { cpe_matchers: string[][]; nvd_queries: string[]; kev_matchers: string[][] }; news_patterns: string[]
  score: number | null; level: { key: string; label: string; color: string }; insufficient_reason: string | null
  cves: { id: string; cvss: number | null; epss: number | null; kev: boolean; published: string | null }[]
  news: { id: string; title: string; url: string; published: string | null; collected_at: string; source: string }[]
  sync_status: SyncFull; sync_jobs: SyncJob[]
  historical: { count: number; kev: number; note: string; items: { cve_id: string; product: string; applicability: string; published: string | null; cvss: number | null; kev_date: string | null; match_source: string }[] }
}
export interface CatalogFilters { q?: string; category?: string; vendor?: string; kind?: string; coverage?: string; status?: string; monitored?: boolean; pinned?: boolean; sort?: string; page?: number; page_size?: number }

export const COVERAGE_TONE: Record<string, string> = { monitored: 'border-emerald-400/30 bg-emerald-400/10 text-emerald-300', partial: 'border-amber-400/30 bg-amber-400/10 text-amber-300', catalog_only: 'border-line text-mute' }
export const KIND_LABEL: Record<string, string> = { product: 'Versioned product', family: 'Product family', platform: 'Platform', cloud: 'Cloud service' }

export const fetchCatalog = (f: CatalogFilters) => req<CatalogPage>('GET', `/api/v1/catalog?${q({ ...f })}`)
export const fetchCatalogFacets = () => req<CatalogFacets>('GET', '/api/v1/catalog/facets')
export const fetchCatalogItem = (id: string) => req<CatalogDetail>('GET', `/api/v1/catalog/${id}`)
export const createTech = (b: Record<string, unknown>) => req<{ id: string }>('POST', '/api/v1/catalog', b)
export const updateTech = (id: string, b: Record<string, unknown>) => req<{ id: string }>('PUT', `/api/v1/catalog/${id}`, b)
export const setTechEnabled = (id: string, enabled: boolean) => req<{ id: string }>('POST', `/api/v1/catalog/${id}/${enabled ? 'enable' : 'disable'}`)
export const setTechMonitor = (id: string, monitor: string) => req<{ id: string }>('PUT', `/api/v1/catalog/${id}/monitoring`, { monitor })
export const setTechPinned = (id: string, pinned: boolean) => req<{ id: string }>('PUT', `/api/v1/catalog/${id}/dashboard`, { pinned })

export const syncTech = (id: string) => req<{ accepted: boolean; reason?: string; message?: string; sync: SyncFull }>('POST', `/api/v1/catalog/${id}/sync`)
export const fetchTechSync = (id: string) => req<SyncFull>('GET', `/api/v1/catalog/${id}/sync`)
export const SYNC_TONE: Record<string, string> = { completed: 'text-emerald-300', in_progress: 'text-accent', pending: 'text-sky-300', partial: 'text-amber-300', failed: 'text-red-300', rate_limited: 'text-orange-300', not_started: 'text-mute' }
/** Count shown to people: an incomplete backfill never reads as "0 vulnerabilities". */
export const cveLabel = (t: { cve_count: number; cves_complete: boolean }) => (t.cves_complete ? String(t.cve_count) : t.cve_count > 0 ? `${t.cve_count}+` : 'pending')
