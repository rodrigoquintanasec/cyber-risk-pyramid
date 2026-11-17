export interface Level { key: string; label: string; color: string }

export interface Explanation {
  formula: string
  components: Record<string, { value: number; points: number }>
  notes: string[]
  window_days: number
  recent_days: number
}

export type Evidence = 'recent_exploitation' | 'known_exploited' | 'none'

export interface Driver {
  id: string
  relevance: number
  evidence: Evidence
  cvss: number | null
  epss: number | null
  kev: boolean
  product: string | null
  reasons: string[]
  link: string
}

export interface Quality { level: 'good' | 'partial' | 'limited'; reasons: string[] }

export interface Technology {
  id: string
  name: string
  score: number | null // null = insufficient information
  level: Level
  cve_count: number
  kev_count: number
  recent_exploited_count: number
  insufficient_reason: string | null
  updated_at: string | null
  coverage: { nvd_queries_ok: number; nvd_queries_total: number; truncated_queries: number }
  quality: Quality
  drivers: Driver[]
  explanation: Explanation
  vendor?: string; product?: string; category?: string; kind?: string; monitored?: boolean
  coverage_state?: 'monitored' | 'partial' | 'catalog_only' | 'unavailable'; coverage_label?: string; limitations?: string[]; last_sync?: string | null
  correlation?: { kind: string; source: string }
  sync?: { status: string; label: string; applicable: boolean; queries_completed: number; queries_required: number; complete?: boolean }
  cves_complete?: boolean; cves_known?: number
  historical?: { count: number; kev: number; note: string }
}

export interface CveItem {
  id: string
  product: string | null
  match_source: string
  published: string | null
  cvss: number | null
  cvss_version: string | null
  epss: number | null
  epss_percentile: number | null
  kev: boolean
  kev_date_added: string | null
  kev_ransomware: boolean
  evidence: Evidence
  relevance: number
  description: string | null
  links: { nvd: string; kev: string | null; epss: string | null }
}

export interface TechnologyDetail extends Technology {
  cves: CveItem[]
}

export type DataState = 'loading' | 'live' | 'stale' | 'error'

export interface SourceStatus { ok: boolean | null; last_success: string | null; error: string | null }
export interface Status {
  state: DataState
  syncing: boolean
  phase: string | null
  last_success: string | null
  sources: Record<'kev' | 'nvd' | 'epss', SourceStatus>
}

export interface Overview {
  technologies: Technology[]
  totals: { unique_cves: number; kev_cves: number; security_news: number | null }
  status: Status
  updated_at: string | null
}

export interface NewsItem {
  id: string
  title: string
  summary: string | null
  url: string
  source: { id: string; name: string; type: string; type_label: string }
  published: string | null
  collected_at: string
  categories: string[]
  technologies: { id: string; basis: 'name' | 'cve' }[]
  cves: string[]
}
export interface NewsPage { items: NewsItem[]; total: number; page: number; page_size: number; pages: number }
export interface NewsSource {
  id: string; name: string; type: string; type_label: string; status: 'ok' | 'error' | 'pending'
  enabled: boolean; health: 'healthy' | 'quiet' | 'failed' | 'disabled' | 'pending'
  operational: boolean; last_success: string | null; last_attempt: string | null; error: string | null; items_stored: number; items_24h: number
  note: string | null; language: string | null; last_http: number | null; final_url: string | null; redirects: number
  newest_item: string | null; undated: number; backoff_until: string | null; official_verified: boolean; url: string; consecutive_failures: number
}
export interface NewsStats {
  total_news: number; last_24h: number; cve_references: number; correlated_news: number
  sources_configured: number; sources_enabled: number; sources_disabled: number; sources_active: number; sources_failed: number; sources_quiet: number; sources_pending: number
  categories: Record<string, number>; last_success: string | null
  state: DataState; syncing: boolean; interval_minutes: number
  technologies: { id: string; name: string }[]
  failed_sources: { id: string; name: string; error: string | null }[]
}
export interface NewsFilters {
  q?: string; source?: string; source_type?: string; category?: string; tech?: string; period?: string; watchlist?: string | number
  page?: number; page_size?: number
}

// ---- Intelligence modules
export interface Mitre { id: string; name: string; tactics: string[]; origin?: string; url: string }
export interface Article extends Omit<NewsItem, 'technologies'> {
  updated_at: string | null; technologies: { id: string; basis: string }[]
  vendors: string[]; products: string[]; malware: string[]; ransomware: string[]; mitre: Mitre[]
  event_id: string | null; priority: number | null
}
export interface Page<T> { items: T[]; total: number; page: number; page_size: number; pages: number }
export interface PriorityComponent { key: string; label: string; weight: number; value: number; points: number; detail: string }
export interface Priority { score: number; label?: string; note?: string; components?: PriorityComponent[] }
export interface CveSignal {
  cve: string; cvss: number | null; epss: number | null; kev: { date_added: string; ransomware: boolean } | null; products: string[]
}
export interface Coverage {
  articles: number; publishers: number; note: string
  first_source: { name: string; at: string; url: string }; last_source: { name: string; at: string; url: string }
  by_publisher: { source_id: string; name: string; type_label: string; article_count: number; first: string; last: string; articles: { title: string; url: string; published: string | null }[] }[]
  by_source_type: Record<string, number>; daily: { date: string; articles: number }[]
}
export interface TimelineEntry {
  article_id: string; title: string; url: string; source: string; published: string | null; collected_at: string
  known_update: string | null; date_basis: 'published' | 'collected'; at: string; new_information: string[]; is_first: boolean
}
export interface Cluster {
  id: string; title: string; category: string; categories: string[]; first_published: string; last_published: string
  article_count: number; source_count: number; sources: string[]; cves: string[]
  technologies: { id: string; name: string; basis: string }[]; vendors: string[]; products: string[]; malware: string[]; ransomware: string[]
  mitre: Mitre[]; official: boolean; priority: Priority
  articles?: Article[]; coverage?: Coverage; timeline?: { entries: TimelineEntry[]; note: string }; cve_signals?: CveSignal[]
}
export interface TrendTopic { topic: string; articles: number; events: number; previous_events: number | null; change_pct: number | null; trend: 'up' | 'down' | 'flat' | null }
export interface Trending {
  period: string; total_articles: number; total_events: number; history_sufficient: boolean; note: string | null
  topics: TrendTopic[]; families: { name: string; kind: string; articles: number; events: number }[]
}
export interface ObsRow { id: string; name: string; events: number; articles: number; cves: string[]; cve_count: number; series: number[]; latest: { title: string; url: string; source: string; published: string | null }[] }
export interface Observatory { period: string; vendors: ObsRow[]; technologies: ObsRow[]; note: string }
export interface Facets {
  vendors: { name: string; articles: number }[]; products: { name: string; articles: number }[]
  malware: { name: string; articles: number }[]; ransomware: { name: string; articles: number }[]
  categories: { name: string; articles: number }[]; mitre: { id: string; name: string; articles: number }[]
  technologies: { id: string; name: string }[]
}
export interface MitreTech { id: string; name: string; tactics: string[]; url: string; articles?: number }
export interface MitreList { source: string; version: string | null; catalog_size: number; scope: string; techniques: MitreTech[] }
export interface BriefingSection { id: string; title: string; [k: string]: unknown }
export interface Briefing {
  schema_version: number; id: string; title: string; generated_at: string; reused?: boolean; disclaimer: string
  period: { hours: number; label: string; since: string; until: string }
  coverage: { status: 'complete' | 'partial' | 'stale' | 'insufficient'; articles: number; events: number; sources_configured: number; sources_operational: number; sources_failed: number; sources_contributing: number; last_sync: string | null; hours_since_sync: number | null; warnings: string[] }
  sections: BriefingSection[]; references: string[]
  format?: number
  cover?: { title: string; subtitle: string; period_label: string; since: string; until: string; generated_at: string; scope: string; unique_events: number; contributing_sources: number; cves_identified: number; cves_in_kev: number; coverage_status: string; note: string }
  bibliography?: { id: string; kind: string; outlet: string; title: string; published?: string | null; url: string; supports: string[] }[]
}
export interface BriefingListItem { id: string; generated_at: string; period_hours: number; coverage_status: string; events: number }

// ---- Vulnerability Explorer & Watchlists
export interface VulnRow {
  id: string; published: string | null; cvss: number | null; cvss_version: string | null; severity: string
  epss: number | null; epss_percentile: number | null; epss_date?: string | null; in_kev: boolean; kev_date_added: string | null; kev_ransomware: boolean
  description: string | null; products: string[]; news_count: number; has_nvd_record: boolean
}
export interface VulnPage extends Page<VulnRow> { scope: string; tech_coverage?: { id: string; name: string; coverage_label: string; recent_cves: number; historical_cves: number; note: string | null; limitations: string[] } }
export interface VulnDetail extends VulnRow {
  epss_date?: string | null
  nvd?: { status: string | null; source: string | null; vector: string | null; severity: string | null; last_modified: string | null; complex_configuration: boolean; has_configuration: boolean; from_local_database: boolean }
  cwes?: { id: string; source: string }[]
  references?: { url: string; source: string | null; tags: string[] }[]
  affected?: { vendor: string; product: string; version: string | null; from_incl: string | null; from_excl: string | null; to_incl: string | null; to_excl: string | null }[]
  historical_techs?: { id: string; name: string; applicability: string }[]
  kev: { date_added: string; ransomware: boolean; vendor: string | null; product: string | null; description?: string | null; required_action?: string | null; due_date?: string | null; notes?: string | null } | null
  detail: { status: string | null; cwes: string[]; references: { url: string; source: string; tags: string[] }[]; fetched_at: string
    versions: { product: string; version: string | null; from_incl: string | null; from_excl: string | null; to_incl: string | null; to_excl: string | null }[] } | null
  techs: { id: string; name: string; product: string | null; match_source: string }[]
  news: { id: string; title: string; url: string; source: string; published: string }[]
  links: { nvd: string; kev: string | null; epss: string }
  cache: { nvd_record: boolean; in_kev: boolean; epss: boolean; full_detail: boolean }
}
export interface VulnCoverage {
  explorer_total: number; nvd_cached: number; kev_catalog: number; epss_cached: number; news_cves: number; on_demand_or_enriched: number; detail_cached: number
  nvd_published_range: { from: string | null; to: string | null }; note: string
  sources: Record<string, { ok: boolean; last_success: string | null; error: string | null }>
}
export interface VulnFacets { vendors: { name: string; cves: number }[]; products: { name: string; cves: number }[]; technologies: { id: string; name: string }[] }
export interface Watchlist { id: number; name: string; technologies: string[]; created_at: string; updated_at: string }
export interface WatchlistSummary extends Watchlist {
  technology_details: { id: string; name: string; score: number | null; level: Level | null; cve_count: number; kev_count: number; recent_exploited_count: number; insufficient_reason: string | null; quality: string | null; news_count: number; coverage_state?: string | null; coverage_label?: string | null; cves_complete?: boolean; sync_status?: string | null }[]
  totals: { technologies: number; unique_cves: number; kev_cves: number; news: number; scored: number; without_score: number }
  highest: { id: string; name: string; score: number } | null; note: string
}

// ---- MITRE ATT&CK intelligence
export type AttackKind = 'actor' | 'campaign' | 'technique' | 'malware' | 'tool'
export interface AttackRel { id: string; type: string; status: string; source: string; evidence_id: string; modified: string | null; description: string | null; evidence: { source_name: string; url: string | null; description: string | null }[] }
export interface AttackBrief { id: string; stix_id: string; type: AttackKind; name: string; aliases: string[]; url: string; modified: string | null; tactics?: string[]; is_subtechnique?: boolean; first_seen?: string | null; last_seen?: string | null; relationship?: AttackRel }
export interface AttackEntity extends AttackBrief {
  description: string; created: string | null; platforms?: string[]
  counts?: { techniques?: number; software?: number; campaigns?: number }
  actors?: AttackBrief[]; techniques?: AttackBrief[]; software?: AttackBrief[]; campaigns?: AttackBrief[]
  subtechniques?: AttackBrief[]; parent?: AttackBrief | null
  references?: { source_name: string; external_id: string | null; url: string | null; description: string | null }[]
  revoked?: boolean; deprecated?: boolean; source?: { dataset: string; stix_id: string; imported_at: string }
  news?: { confirmed: Article[]; confirmed_total: number; candidates: Article[]; candidates_total: number; rule: string }
}
export interface AttackStatus {
  source: string; dataset: string; syncing: boolean; imported: boolean; last_attempt: string | null; last_success: string | null
  status: string; error: string | null; collection_version: string | null; spec_version: string | null; interval_hours: number
  counts: { actors: number; campaigns: number; techniques: number; malware: number; tools: number; relationships: number; revoked_or_deprecated_objects: number }
}

// ---- Relationship graph
export type GraphNodeType = 'threat_actor' | 'campaign' | 'technique' | 'malware' | 'tool' | 'cve' | 'technology' | 'product' | 'vendor' | 'news'
export interface GraphNode {
  id: string; type: GraphNodeType; label: string; source: string; external_id?: string; stix_id?: string; url?: string; published?: string
  ref: { kind: string; id: string; vendor?: string }; revoked?: boolean; in_kev?: boolean
}
export interface GraphEdge { id: string; source: string; target: string; type: string; evidence: string; status: 'verified' | 'candidate'; dataset: string; modified: string | null; stix_id?: string }
export interface GraphResult {
  center: string; nodes: GraphNode[]; edges: GraphEdge[]; depth: number
  page: { total_neighbors: number; offset: number; limit: number; returned: number; has_more: boolean }
  truncated: boolean; omitted_nodes: number; limits: { max_nodes: number; max_edges: number }; types_available: Record<string, number>
}
export interface GraphNodeDetail extends GraphNode {
  description: string; aliases: string[]; references: { source_name: string; url?: string | null; description?: string | null }[]
  details: Record<string, unknown>; modified?: string; available_relations: { relation: string; counts: Record<string, number> }[]
}
export interface GraphEdgeDetail {
  edge: GraphEdge; source: GraphNode | null; target: GraphNode | null; description: string
  references: { source_name?: string; url?: string | null; description?: string | null }[]; evidence_id: string; interpretation: string
}
export interface GraphMeta {
  dataset: { name: string; version: string | null; imported: boolean; last_success: string | null; counts: AttackStatus['counts'] }
  node_types: GraphNodeType[]; relation_types: string[]; limits: { max_nodes: number; max_edges: number }; relation_notes: Record<string, string>
}
