import { useEffect, useState } from 'react'
import { ExternalLink, Loader2, X } from 'lucide-react'
import { fetchKeywordArticles, type ArticlePage, type KwStat, type Range } from '../../data/intelDash'
import { safeUrl } from '../intel/briefingDoc'
import { Chip, Note, fmt } from '../intel/ui'

const SORTS: [string, string][] = [['newest', 'Newest'], ['oldest', 'Oldest'], ['priority', 'News Priority Score'], ['source', 'Source']]
const PAGE = 15

function Stat({ label, value }: { label: string; value: string | number }) {
  return <div className="rounded-lg border border-line bg-bg/40 px-3 py-2"><div className="text-[10px] uppercase tracking-wider text-mute">{label}</div><div className="mt-0.5 truncate text-sm font-semibold tabular-nums text-ink">{value}</div></div>
}

/** Related Security News for the selected pyramid: only that keyword's articles, original links, sorted/paged. Reads local data only. */
export default function NewsPanel({ dashId, kw, range, coverage, onClose }: { dashId: number; kw: KwStat; range: Range; coverage: { status: string; label: string; warnings: string[] }; onClose: () => void }) {
  const [sort, setSort] = useState('newest')
  const [source, setSource] = useState('')
  const [event, setEvent] = useState<{ id: string; title: string } | null>(null)
  const [page, setPage] = useState(1)
  const [data, setData] = useState<ArticlePage | null>(null)
  const [busy, setBusy] = useState(true)
  const [err, setErr] = useState<string | null>(null)
  const rangeKey = `${range.period}|${range.start ?? ''}|${range.end ?? ''}`

  // the selected pyramid persists across period changes; paging and the event filter restart when the query changes
  useEffect(() => { setPage(1) }, [sort, source, event, kw.id, rangeKey, dashId])
  useEffect(() => { setEvent(null); setSource('') }, [kw.id, dashId])
  useEffect(() => {
    let alive = true
    setBusy(true)
    fetchKeywordArticles(dashId, kw.id, range, { sort, source: source || undefined, event: event?.id, page, page_size: PAGE })
      .then((d) => { if (alive) { setData(d); setErr(null) } })
      .catch((e) => { if (alive) setErr(String(e.message)) })
      .finally(() => { if (alive) setBusy(false) })
    return () => { alive = false }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [dashId, kw.id, rangeKey, sort, source, event, page, kw.article_count])
  const warn = coverage.status !== 'sufficient'
  return (
    <aside className="slide-in flex w-[28rem] shrink-0 flex-col border-l border-line bg-sidebar" aria-label="Related Security News">
      <div className="flex items-start justify-between gap-3 border-b border-line px-5 py-4">
        <div className="min-w-0"><div className="text-[11px] font-semibold uppercase tracking-wider text-accent">Related Security News</div><h2 className="truncate text-lg font-semibold text-ink">{kw.display_name}</h2>
          {kw.level && <div className="mt-1 flex items-center gap-1.5 text-[11px] text-mute"><span className="h-2 w-2 rounded-full" style={{ background: kw.level.color }} />{kw.level.label}</div>}</div>
        <button onClick={onClose} aria-label="Close panel" className="rounded-lg border border-line p-1.5 text-mute hover:text-ink"><X size={14} /></button>
      </div>
      <div className="grid grid-cols-2 gap-2 px-5 pt-4">
        <Stat label="Articles" value={kw.article_count ?? 0} /><Stat label="Unique events" value={kw.unique_events ?? 0} />
        <Stat label="Contributing sources" value={kw.source_count ?? 0} /><Stat label="Latest publication" value={kw.latest_publication ? fmt(kw.latest_publication) : 'N/A'} />
      </div>
      {warn && <div className="px-5 pt-3"><Note tone="warn"><b>{coverage.label}.</b> {coverage.warnings[0] ?? 'Feed coverage is incomplete for this period.'}</Note></div>}
      <div className="flex flex-wrap items-center gap-2 px-5 pt-3 text-xs">
        <label className="flex items-center gap-1.5 text-mute">Sort<select value={sort} onChange={(e) => setSort(e.target.value)} className="rounded-lg border border-line bg-surface px-2 py-1 text-xs text-ink">{SORTS.map(([v, l]) => <option key={v} value={v}>{l}</option>)}</select></label>
        <label className="flex items-center gap-1.5 text-mute">Source<select value={source} onChange={(e) => setSource(e.target.value)} className="max-w-[11rem] rounded-lg border border-line bg-surface px-2 py-1 text-xs text-ink"><option value="">All sources</option>{(data?.sources ?? []).map((s) => <option key={s.id} value={s.id}>{s.name}</option>)}</select></label>
        {event && <button onClick={() => setEvent(null)} className="flex items-center gap-1 rounded-full border border-accent/40 bg-accent/10 px-2 py-0.5 text-accent" title="Show all articles again">One event: {event.title.slice(0, 28)}… <X size={10} /></button>}
      </div>
      <div className="min-h-0 flex-1 overflow-y-auto px-5 py-3">
        {busy && !data && <div className="flex items-center justify-center gap-2 py-10 text-sm text-mute"><Loader2 size={16} className="animate-spin" /> Loading…</div>}
        {err && <Note tone="warn">Could not load the articles ({err}).</Note>}
        {data && data.items.length === 0 && !busy && <div className="rounded-lg border border-dashed border-line px-4 py-8 text-center text-sm text-mute">No articles matched this keyword during the selected period.</div>}
        <ul className={`space-y-3 ${busy && data ? 'opacity-60' : ''}`}>
          {data?.items.map((a) => {
            const u = safeUrl(a.url)
            return (
              <li key={a.id} className="rounded-lg border border-line bg-bg/40 p-3">
                <h3 className="text-[13px] font-semibold leading-snug text-ink">{u ? <a href={u} target="_blank" rel="noopener noreferrer nofollow" className="hover:text-accent">{a.title}</a> : a.title}</h3>
                <div className="mt-1 flex flex-wrap items-center gap-x-2 text-[11px] text-mute"><span className="text-ink/80">{a.source}</span><span>·</span><span>{a.published ? fmt(a.published) : 'Date unknown'}</span>{a.priority != null && <Chip title="News Priority Score of the event: reading priority, not risk">Priority {Math.round(a.priority)}</Chip>}</div>
                {a.excerpt && <p className="mt-1.5 text-xs text-mute">{a.excerpt}</p>}
                {a.cves.length > 0 && <div className="mt-1.5 flex flex-wrap gap-1">{a.cves.slice(0, 6).map((c) => <Chip key={c} tone="red">{c}</Chip>)}</div>}
                <div className="mt-2 flex flex-wrap items-center justify-between gap-2">
                  {u ? <a href={u} target="_blank" rel="noopener noreferrer nofollow" className="inline-flex items-center gap-1 text-xs font-medium text-accent hover:underline">Read Original Article <ExternalLink size={11} /></a> : <span className="text-[11px] text-mute">No original link available</span>}
                  {a.event && a.event.articles > 1 && <button onClick={() => setEvent({ id: a.event!.id, title: a.event!.title })} className="text-[11px] text-mute hover:text-accent" title={a.event.title}>Event · {a.event.articles} articles / {a.event.publishers} publishers</button>}
                </div>
              </li>
            )
          })}
        </ul>
      </div>
      {data && data.total > 0 && (
        <div className="flex items-center justify-between border-t border-line px-5 py-2 text-xs text-mute">
          <span>{data.total} article{data.total === 1 ? '' : 's'}</span>
          <span className="flex items-center gap-2"><button disabled={page <= 1 || busy} onClick={() => setPage((p) => p - 1)} className="rounded border border-line px-2 py-1 disabled:opacity-40">Prev</button>{page} / {data.pages}<button disabled={page >= data.pages || busy} onClick={() => setPage((p) => p + 1)} className="rounded border border-line px-2 py-1 disabled:opacity-40">Next</button></span>
        </div>
      )}
      <div className="border-t border-line px-5 py-2 text-[10px] text-mute">Coverage metrics from stored news, not confirmed incidents. {data?.window.effective}</div>
    </aside>
  )
}
