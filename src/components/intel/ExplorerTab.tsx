import { useEffect, useState } from 'react'
import { Bug, Clock, Cpu, Search, X } from 'lucide-react'
import { searchIntel } from '../../data/api'
import type { Article, Facets } from '../../data/types'
import { ago } from '../IntelligenceFeed'
import { Chip, ExtLink, Note, Pager, PriorityBadge, Status, fmt, sel, useAsync } from './ui'

export interface ExplorerFilters { q: string; cve: string; vendor: string; product: string; tech: string; malware: string; ransomware: string; mitre: string; category: string; source: string; date_from: string; date_to: string }
export const EMPTY_FILTERS: ExplorerFilters = { q: '', cve: '', vendor: '', product: '', tech: '', malware: '', ransomware: '', mitre: '', category: '', source: '', date_from: '', date_to: '' }

function Row({ a, facets }: { a: Article; facets: Facets | null }) {
  const tn = (id: string) => facets?.technologies.find((t) => t.id === id)?.name ?? id
  return (
    <article className="rounded-xl border border-line bg-surface p-5 transition-colors hover:border-accent/40">
      <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-mute">
        <span className="font-medium text-ink">{a.source.name}</span><Chip>{a.source.type_label}</Chip>
        <span title={fmt(a.published)} className="flex items-center gap-1"><Clock size={11} /> {ago(a.published ?? a.collected_at)}</span><PriorityBadge score={a.priority} />
      </div>
      <h3 className="mt-2 text-[15px] font-semibold leading-snug text-ink">{a.title}</h3>
      <div className="mt-3 flex flex-wrap gap-1.5">
        {a.categories.map((c) => <Chip key={c}>{c}</Chip>)}
        {a.vendors.map((v) => <Chip key={v} tone="accent" title="Vendor named in the article">{v}</Chip>)}
        {a.products.map((p) => <Chip key={p} tone="accent" title="Product named in the article">{p}</Chip>)}
        {a.technologies.map((t) => <Chip key={t.id} tone="accent"><Cpu size={10} className="mr-1 inline" />{tn(t.id)}</Chip>)}
        {a.malware.map((m) => <Chip key={m} tone="violet" title="Malware family named in the text — not an attribution">{m}</Chip>)}
        {a.ransomware.map((m) => <Chip key={m} tone="orange" title="Ransomware family named in the text — not an attribution">{m}</Chip>)}
        {a.cves.slice(0, 5).map((c) => <Chip key={c} tone="red"><Bug size={10} className="mr-1 inline" />{c}</Chip>)}
        {a.mitre.length === 0 ? <Chip title="No explicit ATT&CK technique id in the article">MITRE: Unmapped</Chip> : a.mitre.map((m) => <a key={m.id} href={m.url} target="_blank" rel="noopener noreferrer"><Chip tone="violet" title={`${m.name} — ${m.origin}`}>{m.id} {m.name}</Chip></a>)}
      </div>
      <div className="mt-3"><ExtLink href={a.url}>Read original article</ExtLink></div>
    </article>
  )
}

export default function ExplorerTab({ facets, preset }: { facets: Facets | null; preset: Partial<ExplorerFilters> }) {
  const [f, setF] = useState<ExplorerFilters>({ ...EMPTY_FILTERS, ...preset })
  const [q, setQ] = useState(f.q)
  const [page, setPage] = useState(1)
  useEffect(() => { const t = setTimeout(() => { setQ(f.q); setPage(1) }, 300); return () => clearTimeout(t) }, [f.q])
  const { data, loading, error, reload } = useAsync(() => searchIntel({ ...f, q, page, page_size: 20 }), [q, f.cve, f.vendor, f.product, f.tech, f.malware, f.ransomware, f.mitre, f.category, f.source, f.date_from, f.date_to, page])
  const set = (k: keyof ExplorerFilters) => (e: { target: { value: string } }) => { setF((s) => ({ ...s, [k]: e.target.value })); setPage(1) }
  const active = Object.entries(f).filter(([, v]) => v)
  const opts = (xs: { name: string; articles: number }[] | undefined) => (xs ?? []).map((x) => <option key={x.name} value={x.name}>{x.name} ({x.articles})</option>)
  return (
    <div className="space-y-4 p-6">
      <Note>Combine any filters. Malware and ransomware names are matched only when written explicitly in the text; stories are never attributed to a threat group automatically.</Note>
      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <div className="relative sm:col-span-2"><Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-mute" /><input value={f.q} onChange={set('q')} maxLength={100} placeholder="Keyword in title or excerpt…" className={`${sel} w-full pl-9`} /></div>
        <input value={f.cve} onChange={set('cve')} maxLength={20} placeholder="CVE-2026-12345" aria-label="CVE" className={sel} />
        <select value={f.category} onChange={set('category')} className={sel} aria-label="Category"><option value="">All categories</option>{(facets?.categories ?? []).map((c) => <option key={c.name} value={c.name}>{c.name} ({c.articles})</option>)}</select>
        <select value={f.vendor} onChange={set('vendor')} className={sel} aria-label="Vendor"><option value="">Any vendor</option>{opts(facets?.vendors)}</select>
        <select value={f.product} onChange={set('product')} className={sel} aria-label="Product"><option value="">Any product</option>{opts(facets?.products)}</select>
        <select value={f.tech} onChange={set('tech')} className={sel} aria-label="Technology"><option value="">Any monitored technology</option>{(facets?.technologies ?? []).map((t) => <option key={t.id} value={t.id}>{t.name}</option>)}</select>
        <select value={f.malware} onChange={set('malware')} className={sel} aria-label="Malware"><option value="">Any malware family</option>{opts(facets?.malware)}</select>
        <select value={f.ransomware} onChange={set('ransomware')} className={sel} aria-label="Ransomware"><option value="">Any ransomware family</option>{opts(facets?.ransomware)}</select>
        <select value={f.mitre} onChange={set('mitre')} className={sel} aria-label="MITRE technique"><option value="">Any ATT&amp;CK technique</option>{(facets?.mitre ?? []).map((m) => <option key={m.id} value={m.id}>{m.id} {m.name} ({m.articles})</option>)}</select>
        <input type="date" value={f.date_from} onChange={set('date_from')} aria-label="From date" className={sel} />
        <input type="date" value={f.date_to} onChange={set('date_to')} aria-label="To date" className={sel} />
      </div>
      {active.length > 0 && (
        <div className="flex flex-wrap items-center gap-2">
          {active.map(([k, v]) => <button key={k} onClick={() => setF((s) => ({ ...s, [k]: '' }))} className="flex items-center gap-1 rounded-full border border-accent/30 bg-accent/10 px-2.5 py-1 text-[11px] text-accent">{k}: {v}<X size={11} /></button>)}
          <button onClick={() => setF(EMPTY_FILTERS)} className="text-[11px] text-mute underline">Clear all</button>
        </div>
      )}
      {data && <div className="text-xs text-mute">{data.total} matching article{data.total === 1 ? '' : 's'}</div>}
      <Status loading={loading && !data} error={error} onRetry={reload} empty={!!data && data.items.length === 0} emptyText="No articles match this combination of filters." />
      <div className="space-y-3">{data?.items.map((a) => <Row key={a.id} a={a} facets={facets} />)}</div>
      {data && <Pager page={data.page} pages={data.pages} onPage={setPage} />}
    </div>
  )
}
