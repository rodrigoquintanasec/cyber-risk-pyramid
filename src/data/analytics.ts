export interface AFilters { period: string; date_from?: string; date_to?: string; category?: string; source?: string; vendor?: string; tech?: string; mode: 'all' | 'comparable' }
export const DEFAULT_FILTERS: AFilters = { period: '7d', mode: 'all' }

export interface Cmp { current: number | null; previous: number | null; delta: number | null; pct: number | null; status: 'ok' | 'insufficient' | 'coverage_changed' | 'no_data'; reason: string | null }
export interface Kpi extends Cmp { key: string; label: string; unit: string; scope: 'news' | 'vulnerability' | 'quality' }
export interface Coverage { status: 'complete' | 'partial' | 'degraded' | 'insufficient'; configured: number; enabled: number; operational: number; healthy: number; failed: number; quiet: number; disabled: number; undated_articles: number; failed_sources: string[] }
export interface Echo { period: string; since: string; until: string; previous_since: string; bucket_hours: number; mode: string; timezone: string; generated_at: string; comparable: null | { count: number; excluded: number; excluded_reasons: Record<string, number>; sufficient: boolean; criteria: string[] } }
export interface Assessment { history_ok: boolean; previous_articles: number; coverage_changed: boolean; late_sources: number; contributing: number }
interface Base { filters: Echo; status: 'ok' | 'insufficient_comparable'; message: string | null; notes?: string[] }

export interface Overview extends Base { coverage: Coverage; kpis: Kpi[]; assessment: Assessment | null }
export interface SeriesSet { events: number[]; new_events: number[]; articles: number[] }
export interface Trends extends Base { bucket_starts: string[]; categories: { category: string; events: number; new_events: number; articles: number; compare: Cmp }[]; series: Record<string, SeriesSet>; total: Cmp }
export interface EventRow { id: string; title: string; category: string; first_published: string | null; last_published: string | null; articles_in_period: number; article_count: number; source_count: number; cves: string[]; priority: number; official: boolean; advisory_only: boolean; articles: { title: string; url: string; source: string; published: string | null }[] }
export interface EventPage { items: EventRow[]; total: number; page: number; pages: number; message: string | null }
export interface VulnPoint { cve: string; cvss: number | null; epss: number | null; epss_percentile: number | null; kev: boolean; kev_added: string | null; articles: number; events: number; mentioned: boolean; monitored: string[]; published: string | null }
export interface Vulns extends Base { points: VulnPoint[]; totals: { cves: number; plottable: number; missing_cvss: number; missing_epss: number; kev: number; mentioned: number; monitored: number; truncated: boolean; shown: number } }
export interface EntityRow { id: string; name: string; events: number; articles: number; cves: number; kev_cves: number; sources: number; compare: Cmp }
export interface Entities extends Base { items: EntityRow[]; total: number; page: number; pages: number; label: string }
export interface EntityDetail extends Base { name: string; id: string; bucket_starts: string[]; series: { events: number[]; articles: number[] }; events: number; articles: number; cves: { cve: string; articles: number; kev: boolean; cvss: number | null; epss: number | null }[]; watchlists: { id: number; name: string }[]; graph_node: string | null; news: { title: string; url: string; source: string; published: string | null }[] }
export interface Story extends EventRow { growth: number | null; recent_articles: number; earlier_articles: number; new_sources: number; independent_sources: number; history_sufficient: boolean; technologies: string[]; vendors: string[]; series: { sources_cumulative: number[]; articles: number[]; start: string } }
export interface Emerging extends Base { items: Story[]; total: number; page: number; pages: number; half_window_hours: number }
export interface AttackTech { id: string; name: string; tactics: string[]; url: string; articles: number; events: number }
export interface Attack extends Base { articles_total: number; articles_with_attack: number; coverage_pct: number | null; sufficient: boolean; insufficient_message: string | null; techniques: AttackTech[]; technique_count: number; tactics: { tactic: string; mentions: number }[]; trend: { bucket_starts: string[]; series: { id: string; name: string; mentions: number[] }[] } | null; catalog: { source: string; version: string; size: number } }
export interface Rel { id: string; name: string }
export interface AttackDetail { id: string; name: string; tactics: string[]; url: string; news_mentions: { articles: number; items: { title: string; url: string; source: string; published: string | null }[] }; documented: { actors: Rel[]; actor_total: number; campaigns: Rel[]; campaign_total: number; software_total: number; note: string }; graph_node: string | null }
export interface QSource { id: string; name: string; type: string; health: string; enabled: boolean; articles_period: number; stored: number; undated: number; first_collected: string | null; last_success: string | null; error: string | null }
export interface Quality extends Base {
  coverage: Coverage
  metrics: { configured: number; enabled: number; healthy: number; failed: number; quiet: number; disabled: number; undated_articles: number; unique_events: number; multi_source_events: number; official_share_pct: number | null; cve_extraction_pct: number | null; attack_mapping_pct: number | null }
  duplicates: { available: boolean; note: string; resighted_since_logging: number; logging_since: string | null; syncs_logged: number }
  charts: { articles_by_source: { id: string; name: string; value: number }[]; events_by_category: { name: string; value: number }[]; articles_by_source_type: { name: string; value: number }[]; daily: { bucket_starts: string[]; articles: number[]; sources: number[] }; metadata_quality: { name: string; value: number | null }[] }
  sources: QSource[]; sync_history: { id: number; finished_at: string; ok: number; failed: number; new_items: number; resighted: number }[]
}
export interface Meta { generated_at: string; timezone: string; max_range_days: number; categories: string[]; sources: { id: string; name: string; type: string; enabled: boolean; health: string }[]; vendors: string[]; technologies: { id: string; name: string }[]; data_range: { oldest_dated: string | null; newest_dated: string | null; undated_articles: number; articles: number; events: number }; coverage: Coverage; snapshots: { count: number; first: string | null; last: string | null } }
export interface Snapshot { id: number; taken_at: string; config_hash: string; articles: number; events: number; multi_source_events: number; sources_enabled: number; sources_operational: number; sources_failed: number; sources_quiet: number; undated_articles: number; config_changed: boolean; delta: Record<string, number> | null; note: string | null }
export interface History { snapshots: Snapshot[]; note: string; dates: Record<string, string> }

type Q = Record<string, string | number | boolean | undefined | null>
const qs = (f: AFilters, x: Q = {}) => {
  const p = new URLSearchParams()
  const all: Q = { period: f.period, mode: f.mode, category: f.category, source: f.source, vendor: f.vendor, tech: f.tech, ...(f.period === 'custom' ? { date_from: f.date_from, date_to: f.date_to } : {}), ...x }
  Object.entries(all).forEach(([k, v]) => { if (v !== undefined && v !== null && v !== '' && v !== false) p.set(k, String(v)) })
  return p.toString()
}
async function get<T>(path: string, f: AFilters, x: Q = {}): Promise<T> {
  const r = await fetch(`/api/v1/analytics/${path}?${qs(f, x)}`)
  if (!r.ok) {
    let msg = `HTTP ${r.status}`
    try { const j = await r.json(); if (typeof j.detail === 'string') msg = j.detail } catch { /* ignore */ }
    throw new Error(msg)
  }
  return r.json() as Promise<T>
}
export const aMeta = () => fetch('/api/v1/analytics/meta').then((r) => { if (!r.ok) throw new Error(`HTTP ${r.status}`); return r.json() as Promise<Meta> })
export const aHistory = () => fetch('/api/v1/analytics/history?limit=30').then((r) => { if (!r.ok) throw new Error(`HTTP ${r.status}`); return r.json() as Promise<History> })
export const aOverview = (f: AFilters) => get<Overview>('overview', f)
export const aTrends = (f: AFilters) => get<Trends>('trends', f)
export const aEvents = (f: AFilters, x: Q) => get<EventPage>('events', f, x)
export const aVulns = (f: AFilters, x: Q) => get<Vulns>('vulnerabilities', f, x)
export const aEntities = (f: AFilters, kind: 'vendor' | 'technology', x: Q) => get<Entities>(kind === 'vendor' ? 'vendors' : 'technologies', f, x)
export const aEntity = (f: AFilters, kind: string, id: string) => get<EntityDetail>('entity', f, { kind, id })
export const aEmerging = (f: AFilters, x: Q) => get<Emerging>('emerging', f, x)
export const aAttack = (f: AFilters) => get<Attack>('attack', f)
export const aTechnique = (f: AFilters, id: string) => get<AttackDetail>(`attack/technique/${id}`, f)
export const aQuality = (f: AFilters) => get<Quality>('quality', f)
