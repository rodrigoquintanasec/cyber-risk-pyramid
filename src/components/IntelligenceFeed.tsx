import { useCallback, useEffect, useRef, useState } from 'react'
import {
  Newspaper, Radio, Clock, Hash, Search, ExternalLink, Bug, Loader2, AlertTriangle, XCircle, ChevronDown, Inbox, Cpu, RefreshCw, CheckCircle2,
} from 'lucide-react'
import MetricCard from './MetricCard'
import { fetchNews, fetchWatchlists, fetchNewsSources, fetchNewsStats, triggerNewsSync } from '../data/api'
import type { DataState, NewsItem, NewsPage, NewsSource, NewsStats } from '../data/types'

const CATEGORIES = ['Vulnerabilities', 'Ransomware', 'Malware', 'Data Breaches', 'Threat Intelligence', 'Cloud Security', 'Network Security', 'Application Security', 'General Cybersecurity']
const PERIODS = [['24h', 'Last 24 Hours'], ['7d', 'Last 7 Days'], ['30d', 'Last 30 Days'], ['all', 'All Time']]
const PAGE = 20

const BADGE: Record<DataState | 'partial', { label: string; cls: string; Icon: typeof Radio }> = {
  loading: { label: 'Loading', cls: 'border-accent/30 bg-accent/10 text-accent', Icon: Loader2 },
  live: { label: 'Live Data', cls: 'border-emerald-400/30 bg-emerald-400/10 text-emerald-300', Icon: Radio },
  stale: { label: 'Stale Data', cls: 'border-amber-400/30 bg-amber-400/10 text-amber-300', Icon: AlertTriangle },
  error: { label: 'Error', cls: 'border-red-400/30 bg-red-400/10 text-red-300', Icon: XCircle },
  partial: { label: 'Partial', cls: 'border-amber-400/30 bg-amber-400/10 text-amber-300', Icon: AlertTriangle },
}

const HEALTH_DOT: Record<string, string> = { healthy: 'bg-emerald-400', quiet: 'bg-sky-400/70', failed: 'bg-red-400', disabled: 'bg-slate-600', pending: 'bg-slate-500' }
const fmt = (iso: string | null) => (iso ? new Date(iso).toLocaleString('en-US', { dateStyle: 'medium', timeStyle: 'short' }) : '-')
const sel = 'rounded-lg border border-line bg-surface px-3 py-2 text-sm text-ink outline-none transition-colors hover:border-accent/40 focus:border-accent/60'

export function ago(iso: string | null): string {
  if (!iso) return 'date unavailable'
  const m = Math.max(0, Math.round((Date.now() - new Date(iso).getTime()) / 60000))
  if (m < 60) return `${m}m ago`
  if (m < 1440) return `${Math.round(m / 60)}h ago`
  return `${Math.round(m / 1440)}d ago`
}

function NewsCard({ n, techName }: { n: NewsItem; techName: (id: string) => string }) {
  const vuln = n.categories.includes('Vulnerabilities') || n.cves.length > 0
  return (
    <article className={`rounded-xl border bg-surface p-5 transition-colors hover:border-accent/40 ${vuln ? 'border-l-2 border-line border-l-orange-400/70' : 'border-line'}`}>
      <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-mute">
        <span className="font-medium text-ink">{n.source.name}</span>
        <span className="rounded border border-line px-1.5 py-0.5 text-[10px]">{n.source.type_label}</span>
        <span title={fmt(n.published)} className="flex items-center gap-1"><Clock size={11} /> {ago(n.published ?? n.collected_at)}{n.published ? '' : ' (collected)'}</span>
      </div>
      <h3 className="mt-2 text-[15px] font-semibold leading-snug text-ink">{n.title}</h3>
      {n.summary && <p className="mt-1.5 line-clamp-3 text-[13px] leading-relaxed text-mute">{n.summary}</p>}
      <div className="mt-3 flex flex-wrap gap-1.5">
        {n.categories.map((c) => (
          <span key={c} className={`rounded-full border px-2 py-0.5 text-[11px] ${c === 'Vulnerabilities' ? 'border-orange-400/40 bg-orange-400/10 text-orange-300' : 'border-line text-mute'}`}>{c}</span>
        ))}
        {n.technologies.map((t) => (
          <span key={t.id} title={t.basis === 'cve' ? 'Linked through a correlated CVE' : 'Product named in the article'} className="flex items-center gap-1 rounded-full border border-accent/30 bg-accent/10 px-2 py-0.5 text-[11px] text-accent">
            <Cpu size={10} /> {techName(t.id)}
          </span>
        ))}
        {n.cves.slice(0, 6).map((c) => (
          <a key={c} href={`https://nvd.nist.gov/vuln/detail/${c}`} target="_blank" rel="noopener noreferrer" className="flex items-center gap-1 rounded-full border border-red-400/30 bg-red-400/10 px-2 py-0.5 text-[11px] text-red-300 hover:underline">
            <Bug size={10} /> {c}
          </a>
        ))}
        {n.cves.length > 6 && <span className="text-[11px] text-mute">+{n.cves.length - 6} CVEs</span>}
      </div>
      <a href={n.url} target="_blank" rel="noopener noreferrer nofollow" className="mt-4 inline-flex items-center gap-1.5 rounded-lg border border-accent/30 bg-accent/10 px-3 py-1.5 text-xs font-medium text-accent transition-colors hover:bg-accent/20">
        Read Original Article <ExternalLink size={12} />
      </a>
    </article>
  )
}

export default function IntelligenceFeed({ initialTech, initialWatchlist = '', onStats }: { initialTech: string; initialWatchlist?: string; onStats?: (s: NewsStats | null) => void }) {
  const [stats, setStats] = useState<NewsStats | null>(null)
  const [sources, setSources] = useState<NewsSource[]>([])
  const [types, setTypes] = useState<{ id: string; label: string }[]>([])
  const [showSources, setShowSources] = useState(false)
  const [filters, setFilters] = useState({ q: '', source: '', source_type: '', category: '', tech: initialTech, period: 'all', watchlist: initialWatchlist })
  const [debouncedQ, setDebouncedQ] = useState('')
  const [page, setPage] = useState<NewsPage | null>(null)
  const [items, setItems] = useState<NewsItem[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const reqId = useRef(0)
  const [watchlists, setWatchlists] = useState<{ id: number; name: string }[]>([])
  useEffect(() => { fetchWatchlists().then((r) => setWatchlists(r.items)).catch(() => undefined) }, [])

  useEffect(() => { const t = setTimeout(() => setDebouncedQ(filters.q), 300); return () => clearTimeout(t) }, [filters.q])

  const loadMeta = useCallback(() => {
    fetchNewsStats().then((s) => { setStats(s); onStats?.(s) }).catch(() => setStats(null))
    fetchNewsSources().then((r) => { setSources(r.sources); setTypes(r.types) }).catch(() => undefined)
  }, [onStats])

  const syncing = stats?.syncing
  useEffect(() => {
    loadMeta()
    const id = setInterval(loadMeta, syncing ? 5_000 : 60_000)
    return () => clearInterval(id)
  }, [loadMeta, syncing])

  const load = useCallback((pg: number, append: boolean) => {
    const id = ++reqId.current
    setLoading(true)
    fetchNews({ ...filters, q: debouncedQ, page: pg, page_size: PAGE })
      .then((p) => { if (id !== reqId.current) return; setPage(p); setItems((cur) => (append ? [...cur, ...p.items] : p.items)); setError(null) })
      .catch((e) => { if (id === reqId.current) setError(String(e.message ?? e)) })
      .finally(() => { if (id === reqId.current) setLoading(false) })
  }, [filters.source, filters.source_type, filters.category, filters.tech, filters.period, filters.watchlist, debouncedQ]) // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => { load(1, false) }, [load])
  useEffect(() => { if (stats && !syncing) load(1, false) }, [syncing]) // eslint-disable-line react-hooks/exhaustive-deps

  const set = (k: keyof typeof filters) => (e: { target: { value: string } }) => setFilters((f) => ({ ...f, [k]: e.target.value }))
  const techName = (id: string) => stats?.technologies.find((t) => t.id === id)?.name ?? id
  const state: DataState | 'partial' = !stats ? (error ? 'error' : 'loading') : stats.state === 'stale' && stats.sources_failed > 0 && stats.last_success && stats.sources_active > 0 && Date.now() - new Date(stats.last_success).getTime() < 2 * stats.interval_minutes * 60000 ? 'partial' : stats.state
  const { label, cls, Icon } = BADGE[state]
  const filtersActive = !!(debouncedQ || filters.source || filters.source_type || filters.category || filters.tech || filters.watchlist || filters.period !== 'all')

  return (
    <div className="space-y-5 p-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-3">
          <div className={`flex items-center gap-2 rounded-full border px-3 py-1.5 text-xs font-medium ${cls}`} title={stats?.failed_sources.map((f) => `${f.name}: ${f.error}`).join('\n')}>
            <Icon size={13} className={state === 'loading' || stats?.syncing ? 'animate-spin' : ''} /> {label}
            {state === 'partial' && stats && ` · ${stats.sources_active}/${stats.sources_configured} sources`}
          </div>
          <span className="text-xs text-mute">Collector: {stats?.syncing ? 'syncing…' : 'idle'} · every {stats?.interval_minutes ?? 30} min · last sync {fmt(stats?.last_success ?? null)}</span>
        </div>
        <button onClick={() => triggerNewsSync().then(() => setTimeout(loadMeta, 800))} disabled={!!stats?.syncing}
          className="flex items-center gap-2 rounded-lg border border-line px-3 py-1.5 text-xs text-mute transition-colors hover:border-accent/40 hover:text-ink disabled:opacity-40">
          <RefreshCw size={13} className={stats?.syncing ? 'animate-spin' : ''} /> Refresh
        </button>
      </div>

      <div className="grid grid-cols-2 gap-4 xl:grid-cols-4">
        <MetricCard label="Total News" value={stats?.total_news ?? '-'} icon={Newspaper} hint={stats ? `${stats.correlated_news} linked to technologies` : undefined} />
        <MetricCard label="Healthy Sources" value={stats ? `${stats.sources_active}/${stats.sources_enabled}` : '-'} icon={Radio} tone="#34D399" hint={stats ? `${stats.sources_configured} configured · ${stats.sources_failed} failed` : undefined} />
        <MetricCard label="CVE References" value={stats?.cve_references ?? '-'} icon={Hash} tone="#F97316" hint="Unique CVEs in articles" />
        <MetricCard label="Last 24 Hours" value={stats?.last_24h ?? '-'} icon={Clock} />
      </div>

      {stats && (
        <div className="flex flex-wrap items-center gap-x-5 gap-y-1 rounded-xl border border-line bg-surface px-5 py-2.5 text-xs text-mute" title="Quiet = healthy feed with no article in the last 24 h (not a failure). Disabled feeds are excluded from health and coverage.">
          <span>Total Sources <b className="text-ink">{stats.sources_configured}</b></span><span>Enabled <b className="text-ink">{stats.sources_enabled}</b></span>
          <span>Healthy <b className="text-emerald-300">{stats.sources_active}</b></span><span>Failed <b className={stats.sources_failed ? 'text-red-300' : 'text-ink'}>{stats.sources_failed}</b></span>
          <span>Quiet (24 h) <b className="text-ink">{stats.sources_quiet}</b></span><span>Disabled <b className="text-ink">{stats.sources_disabled}</b></span>
          <span className="ml-auto">Manage feeds in Settings</span>
        </div>
      )}

      <div className="rounded-xl border border-line bg-surface">
        <button onClick={() => setShowSources(!showSources)} className="flex w-full items-center justify-between px-5 py-3 text-sm text-ink">
          <span className="flex items-center gap-2"><CheckCircle2 size={15} className="text-accent" /> Source status — {stats?.sources_configured ?? 0} configured · {stats?.sources_enabled ?? 0} enabled · {stats?.sources_active ?? 0} healthy · {stats?.sources_failed ?? 0} failed</span>
          <ChevronDown size={15} className={`text-mute transition-transform ${showSources ? 'rotate-180' : ''}`} />
        </button>
        {showSources && (
          <div className="space-y-3 border-t border-line px-5 py-3 text-xs">
            {types.map((t) => (
              <div key={t.id}>
                <div className="mb-1 text-[11px] uppercase tracking-wider text-mute">{t.label}</div>
                <div className="grid gap-x-6 gap-y-1 sm:grid-cols-2 xl:grid-cols-3">
                  {sources.filter((s) => s.type === t.id).map((s) => (
                    <div key={s.id} className="flex items-center justify-between gap-2" title={s.error ?? s.note ?? `Last success ${fmt(s.last_success)}`}>
                      <span className="flex items-center gap-2 text-ink"><span className={`h-1.5 w-1.5 shrink-0 rounded-full ${HEALTH_DOT[s.health]}`} />{s.name}{s.official_verified && <span title="Official advisory: feed and links verified on the vendor/agency domain" className="text-[9px] text-accent">OFFICIAL</span>}</span>
                      <span className="truncate text-mute">{s.health === 'failed' ? `failed · ${s.error}` : s.health === 'disabled' ? 'disabled' : `${s.items_stored} stored · ${s.items_24h} /24h`}</span>
                    </div>
                  ))}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      <div className="flex flex-wrap gap-3">
        <div className="relative min-w-[240px] flex-1">
          <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-mute" />
          <input value={filters.q} onChange={set('q')} maxLength={100} placeholder="Search titles…" className={`${sel} w-full pl-9`} />
        </div>
        <select value={filters.source} onChange={set('source')} className={sel} aria-label="Source"><option value="">All sources</option>{types.map((t) => <optgroup key={t.id} label={t.label}>{sources.filter((s) => s.type === t.id).map((s) => <option key={s.id} value={s.id}>{s.name} ({s.items_stored})</option>)}</optgroup>)}</select>
        <select value={filters.source_type} onChange={set('source_type')} className={sel} aria-label="Source type"><option value="">All source types</option>{types.map((t) => <option key={t.id} value={t.id}>{t.label}</option>)}</select>
        <select value={filters.category} onChange={set('category')} className={sel} aria-label="Category"><option value="">All categories</option>{CATEGORIES.map((c) => <option key={c}>{c}</option>)}</select>
        <select value={filters.tech} onChange={set('tech')} className={sel} aria-label="Technology"><option value="">All technologies</option>{(stats?.technologies ?? []).map((t) => <option key={t.id} value={t.id}>{t.name}</option>)}</select>
        <select value={filters.watchlist} onChange={set('watchlist')} className={sel} aria-label="Watchlist"><option value="">All watchlists</option>{watchlists.map((w) => <option key={w.id} value={w.id}>{w.name}</option>)}</select>
        <select value={filters.period} onChange={set('period')} className={sel} aria-label="Period">{PERIODS.map(([v, l]) => <option key={v} value={v}>{l}</option>)}</select>
      </div>

      {page && <div className="text-xs text-mute">{page.total} article{page.total === 1 ? '' : 's'}{filtersActive ? ' match the filters' : ''} · newest first</div>}

      {error && (
        <div className="flex items-center gap-3 rounded-xl border border-red-400/30 bg-red-400/10 p-4 text-sm text-red-300"><XCircle size={16} /> Could not load news from the backend ({error}).
          <button onClick={() => load(1, false)} className="ml-auto rounded border border-red-400/40 px-2 py-1 text-xs">Retry</button></div>
      )}
      {stats?.state === 'stale' && !error && (
        <div className="flex items-center gap-2 rounded-xl border border-amber-400/30 bg-amber-400/10 px-4 py-2.5 text-xs text-amber-300">
          <AlertTriangle size={14} /> Showing the last stored articles.{' '}
          {stats.failed_sources.length > 0 ? `${stats.failed_sources.length} source(s) inactive: ${stats.failed_sources.map((f) => `${f.name} (${f.error})`).join(', ')}.` : 'The last successful sync is older than expected.'}
        </div>
      )}

      <div className="space-y-3">
        {items.map((n) => <NewsCard key={n.id} n={n} techName={techName} />)}
        {loading && <div className="flex items-center justify-center gap-2 py-8 text-sm text-mute"><Loader2 size={16} className="animate-spin" /> Loading articles…</div>}
        {!loading && !error && items.length === 0 && (
          <div className="flex flex-col items-center rounded-xl border border-dashed border-line py-14 text-center text-sm text-mute">
            <Inbox size={28} className="mb-3 text-line" />
            {filtersActive ? 'No articles match the selected filters.' : stats?.syncing || stats?.state === 'loading' ? 'The first synchronisation is in progress. Articles will appear shortly.' : stats && stats.sources_active === 0 ? 'No sources are operational right now, so no articles have been collected.' : 'No articles have been collected yet.'}
            {filtersActive && <button onClick={() => setFilters({ q: '', source: '', source_type: '', category: '', tech: '', period: 'all', watchlist: '' })} className="mt-3 rounded-lg border border-line px-3 py-1.5 text-xs text-ink hover:border-accent/40">Clear filters</button>}
          </div>
        )}
      </div>
      {page && page.page < page.pages && !loading && (
        <div className="flex justify-center"><button onClick={() => load(page.page + 1, true)} className="rounded-lg border border-line px-5 py-2 text-sm text-ink transition-colors hover:border-accent/40">Load more ({page.total - items.length} remaining)</button></div>
      )}
      <p className="pb-2 text-center text-[11px] text-mute">Headlines and short excerpts belong to their original publishers. Articles are linked, not copied.</p>
    </div>
  )
}
