import type { Overview, TechnologyDetail } from './types'

async function getJson<T>(url: string): Promise<T> {
  const r = await fetch(url)
  if (!r.ok) throw new Error(`${url}: HTTP ${r.status}`)
  return r.json() as Promise<T>
}

export const fetchOverview = () => getJson<Overview>('/api/technologies')
export const fetchTechnology = (id: string) => getJson<TechnologyDetail>(`/api/technologies/${id}`)
export const triggerSync = () => fetch('/api/sync', { method: 'POST' }).then((r) => r.ok)

import type { NewsFilters, NewsPage, NewsSource, NewsStats } from './types'

export function fetchNews(f: NewsFilters): Promise<NewsPage> {
  const p = new URLSearchParams()
  Object.entries(f).forEach(([k, v]) => { if (v !== undefined && v !== '' && v !== 'all') p.set(k, String(v)) })
  return getJson<NewsPage>(`/api/v1/news?${p}`)
}
export const fetchNewsStats = () => getJson<NewsStats>('/api/v1/news/stats')
export const fetchNewsSources = () =>
  getJson<{ sources: NewsSource[]; types: { id: string; label: string }[] }>('/api/v1/news/sources')
export const triggerNewsSync = () => fetch('/api/v1/news/sync', { method: 'POST' }).then((r) => r.ok)

import type { Article, Briefing, BriefingListItem, Cluster, Facets, MitreList, Observatory, Page, Trending } from './types'

const qs = (o: Record<string, string | number | boolean | undefined | null>) => {
  const p = new URLSearchParams()
  Object.entries(o).forEach(([k, v]) => { if (v !== undefined && v !== null && v !== '' && v !== 'all') p.set(k, String(v)) })
  return p.toString()
}
export const fetchClusters = (f: Record<string, string | number | undefined>) => getJson<Page<Cluster>>(`/api/v1/clusters?${qs(f)}`)
export const fetchCluster = (id: string) => getJson<Cluster>(`/api/v1/clusters/${id}`)
export const fetchTrending = (period: string) => getJson<Trending>(`/api/v1/trending?period=${period}`)
export const fetchObservatory = (period: string) => getJson<Observatory>(`/api/v1/observatory?period=${period}&limit=10`)
export const fetchFacets = () => getJson<Facets>('/api/v1/intel/facets')
export const searchIntel = (f: Record<string, string | number | undefined>) => getJson<Page<Article>>(`/api/v1/intel/search?${qs(f)}`)
export const fetchMitre = (q?: string) => getJson<MitreList>(`/api/v1/mitre/techniques?${qs({ q, mentioned: q ? false : true, limit: 60 })}`)
export const fetchBriefings = () => getJson<{ items: BriefingListItem[] }>('/api/v1/briefings')
export const fetchBriefing = (id: string) => getJson<Briefing>(`/api/v1/briefings/${id}`)
export const fetchBriefingMarkdown = (id: string) => getJson<{ text: string }>(`/api/v1/briefings/${id}/markdown`)
export async function generateBriefing(hours: number, force = false): Promise<Briefing> {
  const r = await fetch('/api/v1/briefings', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ hours, force }) })
  if (!r.ok) throw new Error(`HTTP ${r.status}`)
  return r.json()
}

import type { VulnCoverage, VulnDetail, VulnFacets, VulnPage, Watchlist, WatchlistSummary } from './types'

export const fetchVulns = (f: Record<string, string | number | boolean | undefined>) => getJson<VulnPage>(`/api/v1/vulns?${qs(f)}`)
export const fetchVulnCoverage = () => getJson<VulnCoverage>('/api/v1/vulns/coverage')
export const fetchVulnFacets = (vendor?: string) => getJson<VulnFacets>(`/api/v1/vulns/facets?${qs({ vendor })}`)
export const fetchVuln = (id: string) => getJson<VulnDetail>(`/api/v1/vulns/${id}`)
async function send<T>(method: string, url: string, body?: unknown): Promise<T> {
  const r = await fetch(url, { method, headers: body ? { 'Content-Type': 'application/json' } : undefined, body: body ? JSON.stringify(body) : undefined })
  if (!r.ok) {
    let msg = `HTTP ${r.status}`
    try { const j = await r.json(); if (typeof j.detail === 'string') msg = j.detail } catch { /* ignore */ }
    throw new Error(msg)
  }
  return (r.status === 204 ? undefined : await r.json()) as T
}
export const lookupVuln = (id: string) => send<VulnDetail>('POST', `/api/v1/vulns/${id}/lookup`)
export const fetchWatchlists = () => getJson<{ items: Watchlist[]; available_technologies: { id: string; name: string; category?: string }[] }>('/api/v1/watchlists')
export const fetchWatchlist = (id: number) => getJson<WatchlistSummary>(`/api/v1/watchlists/${id}`)
export const createWatchlist = (name: string, technologies: string[]) => send<Watchlist>('POST', '/api/v1/watchlists', { name, technologies })
export const renameWatchlist = (id: number, name: string) => send<Watchlist>('PUT', `/api/v1/watchlists/${id}`, { name })
export const deleteWatchlist = (id: number) => send<void>('DELETE', `/api/v1/watchlists/${id}`)
export const addWatchTech = (id: number, tech_id: string) => send<Watchlist>('POST', `/api/v1/watchlists/${id}/technologies`, { tech_id })
export const removeWatchTech = (id: number, tech_id: string) => send<Watchlist>('DELETE', `/api/v1/watchlists/${id}/technologies/${tech_id}`)

import type { AttackEntity, AttackKind, AttackStatus } from './types'

export const fetchAttackStatus = () => getJson<AttackStatus>('/api/v1/attack/status')
export const syncAttack = (force = false) => send<{ started: boolean }>('POST', `/api/v1/attack/sync?force=${force}`)
export const fetchActors = (f: Record<string, string | number | undefined>) => getJson<Page<AttackEntity>>(`/api/v1/actors?${qs(f)}`)
export const fetchActor = (id: string) => getJson<AttackEntity>(`/api/v1/actors/${id}`)
export const fetchCampaigns = (f: Record<string, string | number | undefined>) => getJson<Page<AttackEntity>>(`/api/v1/campaigns?${qs(f)}`)
export const fetchCampaign = (id: string) => getJson<AttackEntity>(`/api/v1/campaigns/${id}`)
export const fetchTechniqueEntity = (id: string) => getJson<AttackEntity>(`/api/v1/attack/techniques/${id}`)
export const fetchSoftware = (id: string) => getJson<AttackEntity>(`/api/v1/attack/software/${id}`)
export const lookupAttack = (q: string, kind: 'technique' | 'software' | 'actor' | 'campaign') => getJson<{ items: AttackEntity[] }>(`/api/v1/attack/lookup?${qs({ q, kind })}`)
export const fetchAttackEntity = (kind: AttackKind, id: string) =>
  kind === 'actor' ? fetchActor(id) : kind === 'campaign' ? fetchCampaign(id) : kind === 'technique' ? fetchTechniqueEntity(id) : fetchSoftware(id)

import type { GraphEdgeDetail, GraphMeta, GraphNode, GraphNodeDetail, GraphResult } from './types'

export const fetchGraphMeta = () => getJson<GraphMeta>('/api/v1/graph/meta')
export const searchGraph = (q: string, type?: string) => getJson<{ items: GraphNode[] }>(`/api/v1/graph/search?${qs({ q, type })}`)
export const fetchNeighbors = (f: Record<string, string | number | boolean | undefined>) => getJson<GraphResult>(`/api/v1/graph/neighbors?${qs(f)}`)
export const fetchGraphNode = (id: string) => getJson<GraphNodeDetail>(`/api/v1/graph/node?${qs({ id })}`)
export const fetchGraphEdge = (id: string) => getJson<GraphEdgeDetail>(`/api/v1/graph/edge?${qs({ id })}`)

export const patchNewsSource = (id: string, enabled: boolean) => send<NewsSource>('PATCH', `/api/v1/news/sources/${id}`, { enabled })
