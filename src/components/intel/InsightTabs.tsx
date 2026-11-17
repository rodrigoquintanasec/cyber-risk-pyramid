import { useState } from 'react'
import { ArrowDown, ArrowRight, ArrowUp, Minus, Search } from 'lucide-react'
import { fetchMitre, fetchObservatory, fetchTrending } from '../../data/api'
import type { ObsRow } from '../../data/types'
import { Bar, Chip, ExtLink, Note, Segmented, Spark, Status, card, sel, useAsync } from './ui'

const P3: [string, string][] = [['24h', 'Last 24 hours'], ['7d', 'Last 7 days'], ['30d', 'Last 30 days']]

export function TrendingTab() {
  const [p, setP] = useState('24h')
  const { data, loading, error, reload } = useAsync(() => fetchTrending(p), [p])
  const max = Math.max(1, ...(data?.topics.map((t) => t.events) ?? [1]))
  return (
    <div className="space-y-4 p-6">
      <div className="flex flex-wrap items-center justify-between gap-3"><Segmented options={P3} value={p} onChange={setP} />
        {data && <span className="text-xs text-mute">{data.total_events} unique events from {data.total_articles} articles</span>}</div>
      <Status loading={loading && !data} error={error} onRetry={reload} />
      {data && (
        <>
          {data.note && <Note tone="warn">{data.note}</Note>}
          <div className={`${card} divide-y divide-line`}>
            {data.topics.map((t) => (
              <div key={t.topic} className="grid grid-cols-[170px_1fr_auto] items-center gap-4 px-5 py-3 text-sm">
                <span className="text-ink">{t.topic}</span>
                <div><Bar value={t.events} max={max} /><div className="mt-1 text-[11px] text-mute">{t.events} unique event{t.events === 1 ? '' : 's'} · {t.articles} article{t.articles === 1 ? '' : 's'}{t.articles > t.events ? ' (same stories repeated by several outlets)' : ''}</div></div>
                <div className="w-36 text-right text-xs">
                  {t.change_pct === null ? <span className="text-mute" title="Not enough previous-period data">no trend data</span> : (
                    <span className={`inline-flex items-center gap-1 ${t.trend === 'up' ? 'text-orange-300' : t.trend === 'down' ? 'text-emerald-300' : 'text-mute'}`}>
                      {t.trend === 'up' ? <ArrowUp size={13} /> : t.trend === 'down' ? <ArrowDown size={13} /> : <Minus size={13} />}{t.change_pct > 0 ? '+' : ''}{t.change_pct}% <span className="text-mute">vs previous ({t.previous_events})</span>
                    </span>
                  )}
                </div>
              </div>
            ))}
          </div>
          {data.families.length > 0 && (
            <div className={`${card} p-5`}>
              <div className="mb-2 text-xs uppercase tracking-wider text-mute">Named malware & ransomware families</div>
              <div className="flex flex-wrap gap-2">{data.families.map((f) => <Chip key={f.name + f.kind} tone={f.kind === 'ransomware' ? 'orange' : 'violet'}>{f.name} · {f.events} event{f.events === 1 ? '' : 's'}</Chip>)}</div>
              <p className="mt-2 text-[11px] text-mute">Families are counted when named explicitly in the text; this is not attribution.</p>
            </div>
          )}
        </>
      )}
    </div>
  )
}

function ObsList({ title, rows, onOpen }: { title: string; rows: ObsRow[]; onOpen: (r: ObsRow) => void }) {
  const max = Math.max(1, ...rows.map((r) => r.events))
  return (
    <div className={`${card} p-5`}>
      <div className="mb-3 text-xs uppercase tracking-wider text-mute">{title}</div>
      {rows.length === 0 && <div className="py-6 text-center text-sm text-mute">No mentions in this period.</div>}
      <div className="space-y-4">
        {rows.map((r) => (
          <div key={r.id}>
            <div className="flex items-center justify-between gap-3">
              <button onClick={() => onOpen(r)} className="flex items-center gap-1 text-sm font-medium text-ink hover:text-accent">{r.name}<ArrowRight size={12} /></button>
              <Spark values={r.series} />
            </div>
            <Bar value={r.events} max={max} />
            <div className="mt-1 flex flex-wrap gap-x-4 text-[11px] text-mute"><span>{r.events} unique events</span><span>{r.articles} articles</span><span>{r.cve_count} CVE{r.cve_count === 1 ? '' : 's'}</span></div>
            {r.cves.length > 0 && <div className="mt-1 flex flex-wrap gap-1">{r.cves.slice(0, 4).map((c) => <Chip key={c} tone="red">{c}</Chip>)}</div>}
            {r.latest[0] && <div className="mt-1 text-[11px] text-mute">Latest: <ExtLink href={r.latest[0].url}>{r.latest[0].title.slice(0, 80)}</ExtLink></div>}
          </div>
        ))}
      </div>
    </div>
  )
}

export function ObservatoryTab({ onOpen }: { onOpen: (kind: 'vendor' | 'tech', id: string) => void }) {
  const [p, setP] = useState('7d')
  const { data, loading, error, reload } = useAsync(() => fetchObservatory(p), [p])
  return (
    <div className="space-y-4 p-6">
      <Segmented options={P3} value={p} onChange={setP} />
      <Note>Charts show how often vendors and technologies appear in the news (unique events). Media attention is not a measure of risk; for risk see the pyramid scores and verified CVE signals.</Note>
      <Status loading={loading && !data} error={error} onRetry={reload} />
      {data && (
        <div className="grid gap-4 xl:grid-cols-2">
          <ObsList title="Most mentioned vendors" rows={data.vendors} onOpen={(r) => onOpen('vendor', r.id)} />
          <ObsList title="Most mentioned monitored technologies" rows={data.technologies} onOpen={(r) => onOpen('tech', r.id)} />
        </div>
      )}
    </div>
  )
}

export function MitreTab({ onFilter }: { onFilter: (id: string) => void }) {
  const [q, setQ] = useState('')
  const [dq, setDq] = useState('')
  const { data, loading, error, reload } = useAsync(() => fetchMitre(dq || undefined), [dq])
  return (
    <div className="space-y-4 p-6">
      <Note>An ATT&amp;CK technique is attached to an article only when its identifier (e.g. T1059.001) is written in the title or excerpt and exists in the official catalogue. Nothing is inferred from generic words; articles without evidence show “Unmapped”.</Note>
      <form onSubmit={(e) => { e.preventDefault(); setDq(q.trim()) }} className="flex gap-2">
        <div className="relative flex-1"><Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-mute" /><input value={q} onChange={(e) => setQ(e.target.value)} maxLength={60} placeholder="Search the catalogue by id or name (e.g. T1059, phishing)…" className={`${sel} w-full pl-9`} /></div>
        <button className="rounded-lg border border-accent/30 bg-accent/10 px-4 text-sm text-accent">Search</button>
        {dq && <button type="button" onClick={() => { setQ(''); setDq('') }} className="rounded-lg border border-line px-3 text-sm text-mute">Mentioned only</button>}
      </form>
      <Status loading={loading && !data} error={error} onRetry={reload} empty={!!data && data.techniques.length === 0} emptyText={dq ? 'No technique matches.' : 'No stored article cites an ATT&CK technique id yet — all stories are currently Unmapped.'} />
      {data && data.techniques.length > 0 && (
        <div className={`${card} divide-y divide-line`}>
          <div className="px-5 py-2 text-[11px] text-mute">{data.scope} · {data.catalog_size} techniques in the bundled MITRE ATT&amp;CK Enterprise catalogue</div>
          {data.techniques.map((t) => (
            <div key={t.id} className="flex flex-wrap items-center gap-3 px-5 py-3 text-sm">
              <Chip tone="violet">{t.id}</Chip><span className="text-ink">{t.name}</span>
              <span className="text-xs text-mute">{t.tactics.join(', ')}</span>
              <span className="ml-auto flex items-center gap-4 text-xs">
                {t.articles !== undefined && <span className="text-mute">{t.articles} article{t.articles === 1 ? '' : 's'}</span>}
                <button onClick={() => onFilter(t.id)} className="text-accent hover:underline">Filter news</button>
                <ExtLink href={t.url}>MITRE docs</ExtLink>
              </span>
            </div>
          ))}
        </div>
      )}
      <p className="text-[11px] text-mute">The origin of each association is recorded per article (hover the technique in the Explorer). Catalogue: MITRE ATT&amp;CK® Enterprise, bundled with the app.</p>
    </div>
  )
}
