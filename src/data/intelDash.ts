async function req<T>(method: string, url: string, body?: unknown): Promise<T> {
  const r = await fetch(url, { method, headers: body ? { 'Content-Type': 'application/json' } : undefined, body: body ? JSON.stringify(body) : undefined })
  if (!r.ok) {
    let msg = `HTTP ${r.status}`
    try { const j = await r.json(); if (typeof j.detail === 'string') msg = j.detail; else if (Array.isArray(j.detail)) msg = j.detail.map((d: { msg: string }) => d.msg).join('; ') } catch { /* ignore */ }
    throw new Error(msg)
  }
  return r.json() as Promise<T>
}
const qs = (o: Record<string, string | number | undefined | null>) => {
  const p = new URLSearchParams()
  Object.entries(o).forEach(([k, v]) => { if (v !== undefined && v !== null && v !== '') p.set(k, String(v)) })
  return p.toString()
}

export type MatchType = 'word' | 'phrase' | 'exact'
export interface Term { id?: number; term: string; match_type: MatchType; is_exclusion?: boolean }
export interface Keyword { id: number; display_name: string; enabled: boolean; display_order: number; terms: Term[]; excluded_terms: Term[] }
export interface Dashboard { id: number; name: string; description: string; default_period: string; display_order: number; created_at: string; updated_at: string; keywords: Keyword[]; keyword_count: number; enabled_keywords: number }
export interface DashList {
  items: Dashboard[]; periods: { id: string; label: string }[]
  limits: { dashboards: number; keywords: number; search_terms: number; excluded_terms: number }; match_types: { id: MatchType; label: string }[]
}
export interface Level { key: 'none' | 'low' | 'moderate' | 'high' | 'very_high' | 'insufficient'; label: string; color: string }
export interface KwStat {
  id: number; display_name: string; enabled: boolean; display_order: number; terms: Term[]; excluded_terms: Term[]
  article_count: number | null; unique_events: number | null; source_count: number | null; latest_publication: string | null; level: Level | null
}
export interface Coverage { status: 'sufficient' | 'partial' | 'insufficient'; label: string; warnings: string[]; articles_in_period: number; history_covered_pct: number; last_sync: string | null; undated_excluded: number; duplicates_collapsed: number; note: string }
export interface Stats {
  dashboard: { id: number; name: string; description: string; default_period: string; updated_at: string; keyword_count: number; enabled_keywords: number }
  window: { period: string; label: string; start: string; end: string; timezone: string; effective: string; custom: boolean }
  keywords: KwStat[]
  totals: { keywords_monitored: number; matching_articles: number; unique_events: number; contributing_sources: number; articles_in_period: number }
  coverage: Coverage; events_note: string | null
  scale: { method: string; levels: Level[]; legend: string }
}
export interface DashArticle {
  id: string; title: string; source: string; source_id: string; published: string | null; excerpt: string | null; cves: string[]; url: string | null; priority: number | null
  event: { id: string; title: string; articles: number; publishers: number } | null
}
export interface ArticlePage {
  keyword: { id: number; display_name: string }; window: Stats['window']; items: DashArticle[]; total: number; page: number; page_size: number; pages: number
  summary: { article_count: number | null; unique_events: number | null; source_count: number | null; latest_publication: string | null }
  sources: { id: string; name: string }[]; coverage: { status: string; label: string; warnings: string[] }
}
export interface Range { period: string; start?: string; end?: string }

const B = '/api/v1/intelligence-dashboards'
const rq = (r: Range) => ({ period: r.period, start: r.period === 'custom' ? r.start : undefined, end: r.period === 'custom' ? r.end : undefined })

export const listDashboards = () => req<DashList>('GET', B)
export const getDashboard = (id: number) => req<Dashboard>('GET', `${B}/${id}`)
export const createDashboard = (b: { name: string; description?: string; default_period?: string; keywords?: Partial<Keyword>[] }) => req<Dashboard>('POST', B, b)
export const updateDashboard = (id: number, b: { name?: string; description?: string; default_period?: string }) => req<Dashboard>('PATCH', `${B}/${id}`, b)
export const deleteDashboard = (id: number) => req<{ deleted: boolean }>('DELETE', `${B}/${id}`)
export const duplicateDashboard = (id: number) => req<Dashboard>('POST', `${B}/${id}/duplicate`)
export const orderDashboards = (ids: number[]) => req<{ items: Dashboard[] }>('PUT', `${B}/order`, { ids })
export const addKeyword = (id: number, b: { display_name: string; enabled?: boolean; terms: Term[]; excluded_terms?: Term[] }) => req<Dashboard>('POST', `${B}/${id}/keywords`, b)
export const updateKeyword = (id: number, kid: number, b: { display_name?: string; enabled?: boolean; terms?: Term[]; excluded_terms?: Term[] }) => req<Dashboard>('PATCH', `${B}/${id}/keywords/${kid}`, b)
export const deleteKeyword = (id: number, kid: number) => req<Dashboard>('DELETE', `${B}/${id}/keywords/${kid}`)
export const orderKeywords = (id: number, ids: number[]) => req<Dashboard>('PUT', `${B}/${id}/keywords/order`, { ids })
export const fetchStats = (id: number, r: Range) => req<Stats>('GET', `${B}/${id}/statistics?${qs(rq(r))}`)
export const fetchKeywordArticles = (id: number, kid: number, r: Range, o: { sort: string; source?: string; event?: string; page: number; page_size: number }) =>
  req<ArticlePage>('GET', `${B}/${id}/keywords/${kid}/articles?${qs({ ...rq(r), ...o })}`)

export const LEVEL_FALLBACK: Level[] = [
  { key: 'low', label: 'Low Attention', color: '#22C55E' }, { key: 'moderate', label: 'Moderate Attention', color: '#EAB308' }, { key: 'high', label: 'High Attention', color: '#F97316' },
  { key: 'very_high', label: 'Very High Attention', color: '#EF4444' }, { key: 'none', label: 'No Matches', color: '#6B7280' }, { key: 'insufficient', label: 'Insufficient Feed Coverage', color: '#475569' },
]
