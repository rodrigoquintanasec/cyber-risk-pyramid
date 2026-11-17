import { useEffect, useState } from 'react'
import { ChevronDown, Clock, Cpu, Bug, Layers, Newspaper, Radio } from 'lucide-react'
import { fetchCluster, fetchClusters } from '../../data/api'
import type { Cluster, Facets } from '../../data/types'
import { ago } from '../IntelligenceFeed'
import { Bar, Chip, ExtLink, Note, Pager, PriorityBadge, Status, card, fmt, sel, useAsync } from './ui'

const CATS = ['Vulnerabilities', 'Ransomware', 'Malware', 'Data Breaches', 'Threat Intelligence', 'Cloud Security', 'Network Security', 'Application Security', 'General Cybersecurity']

function Detail({ id }: { id: string }) {
  const { data: c, loading, error, reload } = useAsync(() => fetchCluster(id), [id])
  const [tab, setTab] = useState<'articles' | 'coverage' | 'timeline' | 'priority'>('articles')
  if (loading || error || !c) return <div className="px-5 pb-4"><Status loading={loading} error={error} onRetry={reload} /></div>
  const cov = c.coverage!
  const maxDay = Math.max(1, ...cov.daily.map((d) => d.articles))
  return (
    <div className="border-t border-line px-5 pb-5 pt-3">
      <div className="mb-3 flex gap-1 text-xs">
        {([['articles', `Articles (${c.articles!.length})`], ['coverage', 'Source coverage'], ['timeline', 'Timeline'], ['priority', 'Priority breakdown']] as const).map(([k, l]) => (
          <button key={k} onClick={() => setTab(k)} className={`rounded-md px-3 py-1.5 ${tab === k ? 'bg-accent/15 text-accent' : 'text-mute hover:text-ink'}`}>{l}</button>
        ))}
      </div>
      {tab === 'articles' && (
        <ul className="space-y-2">
          {c.articles!.map((a) => (
            <li key={a.id} className="rounded-lg border border-line bg-bg/40 p-3 text-sm">
              <div className="flex flex-wrap items-center gap-2 text-[11px] text-mute"><span className="font-medium text-ink">{a.source.name}</span><span>{fmt(a.published ?? a.collected_at)}</span></div>
              <div className="mt-1 text-ink">{a.title}</div>
              <div className="mt-1.5"><ExtLink href={a.url}>Original article</ExtLink></div>
            </li>
          ))}
        </ul>
      )}
      {tab === 'coverage' && (
        <div className="space-y-4 text-sm">
          <div className="grid grid-cols-3 gap-3">
            <div className="rounded-lg border border-line p-3"><div className="text-[11px] text-mute">Publications</div><div className="text-xl font-semibold text-ink">{cov.articles}</div></div>
            <div className="rounded-lg border border-line p-3"><div className="text-[11px] text-mute">Identifiable publishers</div><div className="text-xl font-semibold text-ink">{cov.publishers}</div></div>
            <div className="rounded-lg border border-line p-3"><div className="text-[11px] text-mute">First / last detected</div><div className="text-xs text-ink">{cov.first_source.name}<br />{cov.last_source.name}</div></div>
          </div>
          <Note>{cov.note}</Note>
          <table className="w-full text-left text-xs">
            <thead className="text-mute"><tr><th className="py-1.5">Publisher</th><th>Type</th><th>Articles</th><th>First</th><th>Last</th><th /></tr></thead>
            <tbody>
              {cov.by_publisher.map((p) => (
                <tr key={p.source_id} className="border-t border-line text-ink">
                  <td className="py-1.5 font-medium">{p.name}</td><td className="text-mute">{p.type_label}</td><td>{p.article_count}</td><td className="text-mute">{fmt(p.first)}</td><td className="text-mute">{fmt(p.last)}</td>
                  <td>{p.articles.slice(0, 1).map((a) => <ExtLink key={a.url} href={a.url}>Open</ExtLink>)}</td>
                </tr>
              ))}
            </tbody>
          </table>
          <div>
            <div className="mb-1 text-[11px] uppercase tracking-wider text-mute">Publications per day</div>
            {cov.daily.map((d) => (
              <div key={d.date} className="flex items-center gap-3 py-0.5 text-xs"><span className="w-20 text-mute">{d.date}</span><div className="flex-1"><Bar value={d.articles} max={maxDay} /></div><span className="w-6 text-right text-ink">{d.articles}</span></div>
            ))}
          </div>
        </div>
      )}
      {tab === 'timeline' && (
        <div>
          <ol className="relative ml-2 border-l border-line">
            {c.timeline!.entries.map((e) => (
              <li key={e.article_id} className="mb-4 ml-4">
                <span className={`absolute -left-[5px] mt-1.5 h-2.5 w-2.5 rounded-full ${e.is_first ? 'bg-accent' : 'bg-line'}`} />
                <div className="flex flex-wrap items-center gap-2 text-[11px] text-mute">
                  <span className="text-ink">{fmt(e.at)}</span><Chip>{e.date_basis === 'published' ? 'published' : 'collected (no pub. date)'}</Chip>
                  <span>collected {fmt(e.collected_at)}</span>{e.known_update && <Chip tone="orange">updated {fmt(e.known_update)}</Chip>}
                </div>
                <div className="mt-0.5 text-sm text-ink">{e.title} <span className="text-mute">— {e.source}</span></div>
                {e.new_information.map((n) => <div key={n} className="text-xs text-accent">{n}</div>)}
                <ExtLink href={e.url}>Open</ExtLink>
              </li>
            ))}
          </ol>
          <Note>{c.timeline!.note}</Note>
        </div>
      )}
      {tab === 'priority' && (
        <div className="space-y-2 text-sm">
          {c.priority.components!.map((p) => (
            <div key={p.key}>
              <div className="flex justify-between text-xs"><span className="text-ink">{p.label} <span className="text-mute">(weight {(p.weight * 100).toFixed(0)}%)</span></span><span className="tabular-nums text-ink">+{p.points} pts</span></div>
              <Bar value={p.value} max={1} /><div className="mt-0.5 text-[11px] text-mute">{p.detail}</div>
            </div>
          ))}
          <Note>{c.priority.note} Deterministic formula; independent of the pyramid Threat Signal Score.</Note>
          {c.cve_signals && c.cve_signals.length > 0 && (
            <div className="pt-2 text-xs text-mute">Signals used: {c.cve_signals.map((s) => `${s.cve} (${[s.kev ? 'KEV' : '', s.epss != null ? `EPSS ${s.epss.toFixed(2)}` : '', s.cvss != null ? `CVSS ${s.cvss}` : ''].filter(Boolean).join(', ') || 'no local data'})`).join(' · ')}</div>
          )}
        </div>
      )}
    </div>
  )
}

function ClusterCard({ c, open, onToggle }: { c: Cluster; open: boolean; onToggle: () => void }) {
  return (
    <article className={`${card} transition-colors hover:border-accent/40`}>
      <button onClick={onToggle} className="flex w-full items-start gap-4 p-5 text-left" aria-expanded={open}>
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2 text-xs text-mute">
            <Chip tone="accent">{c.category}</Chip><PriorityBadge score={c.priority.score} />
            <span className="flex items-center gap-1"><Clock size={11} /> first {ago(c.first_published)} · last {ago(c.last_published)}</span>
          </div>
          <h3 className="mt-2 text-[15px] font-semibold leading-snug text-ink">{c.title}</h3>
          <div className="mt-2 flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-mute">
            <span className="flex items-center gap-1"><Newspaper size={12} /> {c.article_count} article{c.article_count === 1 ? '' : 's'}</span>
            <span className="flex items-center gap-1"><Radio size={12} /> {c.source_count} publisher{c.source_count === 1 ? '' : 's'}</span>
            <span title={fmt(c.first_published)}>First: {fmt(c.first_published)}</span><span>Last: {fmt(c.last_published)}</span>
          </div>
          <div className="mt-2 flex flex-wrap gap-1.5">
            {c.technologies.map((t) => <Chip key={t.id} tone="accent"><Cpu size={10} className="mr-1 inline" />{t.name}</Chip>)}
            {c.cves.slice(0, 5).map((v) => <Chip key={v} tone="red"><Bug size={10} className="mr-1 inline" />{v}</Chip>)}
            {c.cves.length > 5 && <span className="text-[11px] text-mute">+{c.cves.length - 5} CVEs</span>}
          </div>
        </div>
        <ChevronDown size={16} className={`mt-1 shrink-0 text-mute transition-transform ${open ? 'rotate-180' : ''}`} />
      </button>
      {open && <Detail id={c.id} />}
    </article>
  )
}

export default function ClustersTab({ facets, initialTech }: { facets: Facets | null; initialTech: string }) {
  const [f, setF] = useState({ period: '7d', category: '', tech: initialTech, min_sources: '1', sort: 'priority', q: '' })
  const [q, setQ] = useState('')
  const [page, setPage] = useState(1)
  const [openId, setOpenId] = useState<string | null>(null)
  useEffect(() => { const t = setTimeout(() => { setQ(f.q); setPage(1) }, 300); return () => clearTimeout(t) }, [f.q])
  const { data, loading, error, reload } = useAsync(() => fetchClusters({ ...f, q, page, page_size: 15 }), [f.period, f.category, f.tech, f.min_sources, f.sort, q, page])
  const set = (k: keyof typeof f) => (e: { target: { value: string } }) => { setF((s) => ({ ...s, [k]: e.target.value })); setPage(1) }
  return (
    <div className="space-y-4 p-6">
      <div className="flex items-start gap-3 text-xs text-mute"><Layers size={15} className="mt-0.5 text-accent" /> Related articles are grouped into one event only on verifiable evidence (shared CVE or advisory id, or near-identical titles within a time window). Same vendor or ransomware name alone never merges stories.</div>
      <div className="flex flex-wrap gap-3">
        <input value={f.q} onChange={set('q')} maxLength={100} placeholder="Search event titles…" className={`${sel} min-w-[220px] flex-1`} />
        <select value={f.period} onChange={set('period')} className={sel} aria-label="Period">{[['24h', 'Last 24h'], ['48h', 'Last 48h'], ['7d', 'Last 7 days'], ['30d', 'Last 30 days'], ['all', 'All']].map(([v, l]) => <option key={v} value={v}>{l}</option>)}</select>
        <select value={f.category} onChange={set('category')} className={sel} aria-label="Category"><option value="">All categories</option>{CATS.map((c) => <option key={c}>{c}</option>)}</select>
        <select value={f.tech} onChange={set('tech')} className={sel} aria-label="Technology"><option value="">All technologies</option>{(facets?.technologies ?? []).map((t) => <option key={t.id} value={t.id}>{t.name}</option>)}</select>
        <select value={f.min_sources} onChange={set('min_sources')} className={sel} aria-label="Minimum publishers"><option value="1">Any publishers</option><option value="2">2+ publishers</option><option value="3">3+ publishers</option></select>
        <select value={f.sort} onChange={set('sort')} className={sel} aria-label="Sort"><option value="priority">Sort: News Priority</option><option value="recent">Sort: Most recent</option><option value="size">Sort: Most articles</option></select>
      </div>
      {data && <div className="text-xs text-mute">{data.total} event{data.total === 1 ? '' : 's'} · each event may contain several original articles</div>}
      <Status loading={loading && !data} error={error} onRetry={reload} empty={!!data && data.items.length === 0} emptyText="No events match these filters." />
      <div className="space-y-3">{data?.items.map((c) => <ClusterCard key={c.id} c={c} open={openId === c.id} onToggle={() => setOpenId(openId === c.id ? null : c.id)} />)}</div>
      {data && <Pager page={data.page} pages={data.pages} onPage={(p) => { setPage(p); setOpenId(null) }} />}
    </div>
  )
}
