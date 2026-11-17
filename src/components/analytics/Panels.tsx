import { useEffect, useMemo, useState } from 'react'
import { AlertTriangle, ExternalLink, Network, Newspaper, Search } from 'lucide-react'
import { aEmerging, aEntities, aEntity, aEvents, aTrends, aVulns, type AFilters, type Meta, type VulnPoint } from '../../data/analytics'
import { Chip, ExtLink, Note, Segmented, Status, card, fmt, sel, useAsync } from '../intel/ui'
import { Legend, LineChart, Scatter, Spark, colorOf } from './charts'
import { CmpBadge, EventList, periodText, type Nav } from './shared'

const key = (f: AFilters) => JSON.stringify(f)
const Head = ({ title, sub }: { title: string; sub?: string }) => <div className="mb-3"><h3 className="text-sm font-semibold text-ink">{title}</h3>{sub && <p className="mt-0.5 text-xs text-mute">{sub}</p>}</div>
function Insufficient({ msg }: { msg: string | null }) {
  return <div className="rounded-xl border border-amber-400/30 bg-amber-400/10 p-6 text-center text-sm text-amber-300"><AlertTriangle size={18} className="mx-auto mb-2" />{msg ?? 'Insufficient comparable coverage'}<div className="mt-1 text-xs text-amber-300/80">Switch to “All Available Sources” to see the data with coverage warnings.</div></div>
}

// ----------------------------------------------------------------------------- A. Threat trends
export function TrendsPanel({ f, nav }: { f: AFilters; nav: Nav }) {
  const { data, loading, error, reload } = useAsync(() => aTrends(f), [key(f)])
  const [metric, setMetric] = useState<'events' | 'new_events' | 'articles'>('events')
  const [hidden, setHidden] = useState<string[]>([])
  const [pick, setPick] = useState<number | null>(null)
  const [cat, setCat] = useState<string | null>(null)
  useEffect(() => { setPick(null) }, [key(f)])
  const e = data?.filters
  const cats = data?.categories ?? []
  const shown = cats.filter((c) => !hidden.includes(c.category)).slice(0, 8)
  const lines = [{ name: 'All categories', color: '#E5EDF7', values: data?.series.__total?.[metric] ?? [], dashed: true }, ...shown.map((c) => ({ name: c.category, color: colorOf(cats.indexOf(c)), values: data?.series[c.category]?.[metric] ?? [] }))]
  const evq = useAsync(() => (pick !== null && data ? aEvents(f, { at: data.bucket_starts[pick], span_hours: data.filters.bucket_hours, category: cat ?? f.category, page_size: 10 }) : Promise.resolve(null)), [key(f), pick, cat, !!data])
  return (
    <div className="space-y-4">
      <Status loading={loading && !data} error={error} onRetry={reload} />
      {data?.status === 'insufficient_comparable' && <Insufficient msg={data.message} />}
      {data?.status === 'ok' && e && (
        <>
          <div className={`${card} p-5`}>
            <div className="mb-3 flex flex-wrap items-center justify-between gap-3">
              <Head title="Distinct events by category" sub={periodText(e)} />
              <Segmented options={[['events', 'Active events'], ['new_events', 'New events'], ['articles', 'Articles']]} value={metric} onChange={(v) => setMetric(v as typeof metric)} />
            </div>
            <LineChart labels={data.bucket_starts} hourly={e.bucket_hours === 1} series={lines} onPoint={setPick} selected={pick} unit="" />
            <div className="mt-2 flex flex-wrap items-center gap-2">
              {cats.slice(0, 12).map((c) => { const off = hidden.includes(c.category); return (
                <button key={c.category} onClick={() => setHidden((h) => (off ? h.filter((x) => x !== c.category) : [...h, c.category]))} className={`flex items-center gap-1.5 rounded-full border px-2 py-0.5 text-[11px] ${off ? 'border-line text-mute/60' : 'border-line text-ink'}`}>
                  <span className="h-2 w-2 rounded-full" style={{ background: off ? '#475569' : colorOf(cats.indexOf(c)) }} />{c.category}</button>) })}
            </div>
            <div className="mt-2"><Legend items={[{ name: 'All categories (dashed)', color: '#E5EDF7', dashed: true }]} /></div>
            <p className="mt-2 text-[11px] text-mute">{metric === 'events' ? 'Events with at least one article in the bucket.' : metric === 'new_events' ? 'Events whose first known publication falls in the bucket (a new story, not a new article).' : 'Publications, including several per event.'} Click a point to list the events. More coverage is not evidence of more attacks.</p>
          </div>
          <div className={`${card} overflow-x-auto`}>
            <table className="w-full min-w-[640px] text-sm">
              <thead className="border-b border-line text-left text-xs uppercase tracking-wider text-mute"><tr><th className="px-4 py-3">Category</th><th className="px-4 py-3 text-right">Events</th><th className="px-4 py-3 text-right">New events</th><th className="px-4 py-3 text-right">Articles</th><th className="px-4 py-3">vs previous period</th></tr></thead>
              <tbody>
                {cats.map((c) => (
                  <tr key={c.category} onClick={() => { setCat(cat === c.category ? null : c.category) }} className={`cursor-pointer border-b border-line/60 last:border-0 hover:bg-bg/40 ${cat === c.category ? 'bg-accent/5' : ''}`}>
                    <td className="px-4 py-2.5"><span className="mr-2 inline-block h-2 w-2 rounded-full" style={{ background: colorOf(cats.indexOf(c)) }} />{c.category}</td>
                    <td className="px-4 py-2.5 text-right tabular-nums text-ink">{c.events}</td><td className="px-4 py-2.5 text-right tabular-nums text-mute">{c.new_events}</td><td className="px-4 py-2.5 text-right tabular-nums text-mute">{c.articles}</td>
                    <td className="px-4 py-2.5"><CmpBadge c={c.compare} /></td>
                  </tr>
                ))}
              </tbody>
            </table>
            {cat && <div className="border-t border-line px-4 py-2 text-xs text-mute">Drill-down restricted to <b className="text-ink">{cat}</b> (click the row again to clear).</div>}
          </div>
          {pick !== null && (
            <div className={`${card} p-5`}>
              <Head title={`Events in bucket starting ${fmt(data.bucket_starts[pick])}`} sub={cat ? `Category: ${cat}` : 'All categories'} />
              <Status loading={evq.loading} error={evq.error} empty={!!evq.data && evq.data.items.length === 0} emptyText="No events in this bucket." />
              {evq.data && <><div className="mb-1 text-xs text-mute">{evq.data.total} event(s)</div><EventList items={evq.data.items} onCve={nav.vuln} /></>}
            </div>
          )}
          {data.notes && <Note>{data.notes.join(' ')}</Note>}
        </>
      )}
    </div>
  )
}

// ----------------------------------------------------------------------------- B. Vulnerability intelligence
export function VulnPanel({ f, nav }: { f: AFilters; nav: Nav }) {
  const [cvssMin, setCvssMin] = useState('')
  const [epssMin, setEpssMin] = useState('')
  const [kevOnly, setKevOnly] = useState(false)
  const [q, setQ] = useState('')
  const [sqrt, setSqrt] = useState(true)
  const [pick, setPick] = useState<string | null>(null)
  const [page, setPage] = useState(1)
  const num = (v: string) => (v !== '' && !Number.isNaN(Number(v)) ? Number(v) : undefined)
  const { data, loading, error, reload } = useAsync(() => aVulns(f, { cvss_min: num(cvssMin), epss_min: num(epssMin), kev_only: kevOnly, q: q.trim() || undefined }), [key(f), cvssMin, epssMin, kevOnly, q])
  useEffect(() => setPage(1), [key(f), cvssMin, epssMin, kevOnly, q])
  const pts = data?.points ?? []
  const plot = useMemo(() => pts.filter((p) => p.cvss !== null && p.epss !== null).map((p) => ({ cve: p.cve, cvss: p.cvss!, epss: p.epss!, kev: p.kev, mentioned: p.mentioned, monitored: p.monitored.length > 0 })), [pts])
  const sel1 = pts.find((p) => p.cve === pick) ?? null
  const rows = pts.slice((page - 1) * 12, page * 12)
  const na = (v: number | null, d = 1) => (v === null ? 'N/A' : v.toFixed(d))
  const t = data?.totals
  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-end gap-3">
        <label className="text-xs text-mute">Min CVSS<input value={cvssMin} onChange={(e) => setCvssMin(e.target.value)} inputMode="decimal" placeholder="0-10" className={`${sel} mt-1 block w-24`} /></label>
        <label className="text-xs text-mute">Min EPSS<input value={epssMin} onChange={(e) => setEpssMin(e.target.value)} inputMode="decimal" placeholder="0-1" className={`${sel} mt-1 block w-24`} /></label>
        <label className="text-xs text-mute">CVE<input value={q} onChange={(e) => setQ(e.target.value)} maxLength={20} placeholder="CVE-2026-…" className={`${sel} mt-1 block w-44`} /></label>
        <label className="flex items-center gap-2 pb-2 text-xs text-ink"><input type="checkbox" checked={kevOnly} onChange={(e) => setKevOnly(e.target.checked)} /> CISA KEV only</label>
        <div className="ml-auto pb-0.5"><Segmented options={[['sqrt', 'EPSS: sqrt scale'], ['lin', 'EPSS: linear']]} value={sqrt ? 'sqrt' : 'lin'} onChange={(v) => setSqrt(v === 'sqrt')} /></div>
      </div>
      <Status loading={loading && !data} error={error} onRetry={reload} />
      {data?.status === 'insufficient_comparable' && <Insufficient msg={data.message} />}
      {data?.status === 'ok' && t && (
        <>
          <div className="grid grid-cols-2 gap-3 md:grid-cols-6">
            {([['CVEs listed', t.cves], ['Plotted (CVSS + EPSS)', t.plottable], ['Missing CVSS (N/A)', t.missing_cvss], ['Missing EPSS (N/A)', t.missing_epss], ['In CISA KEV', t.kev], ['Mentioned in news', t.mentioned]] as [string, number][]).map(([l, v]) => (
              <div key={l} className={`${card} px-4 py-3`}><div className="text-[11px] uppercase tracking-wider text-mute">{l}</div><div className="text-2xl font-semibold tabular-nums text-ink">{v}</div></div>))}
          </div>
          <div className="grid gap-4 xl:grid-cols-[1fr_320px]">
            <div className={`${card} p-5`}>
              <Head title="CVSS vs EPSS" sub="Each point is one CVE. CVEs without CVSS or EPSS are not plotted (never drawn as zero); see the table for N/A values." />
              <Scatter points={plot} sqrt={sqrt} selected={pick} onSelect={setPick} />
              <div className="mt-2 flex flex-wrap gap-x-5 gap-y-1 text-[11px] text-mute">
                <span className="flex items-center gap-1.5"><span className="h-2.5 w-2.5 rounded-full border border-red-300 bg-red-500" />In CISA KEV</span>
                <span className="flex items-center gap-1.5"><span className="h-2.5 w-2.5 rounded-full bg-accent" />Mentioned in news</span>
                <span className="flex items-center gap-1.5"><span className="h-2.5 w-2.5 rounded-full border border-violet-400" />Monitored technology</span>
                <span className="flex items-center gap-1.5"><span className="h-2.5 w-2.5 rounded-full border border-mute" />Other</span>
              </div>
              {t.truncated && <div className="mt-2 text-[11px] text-amber-300">Showing the {t.shown} most relevant of {t.cves} CVEs (KEV first, then most mentioned). Narrow the filters to see the rest.</div>}
            </div>
            <div className={`${card} p-5`}>
              <Head title={sel1 ? sel1.cve : 'Select a CVE'} sub={sel1 ? undefined : 'Click a point or a table row.'} />
              {sel1 && (
                <div className="space-y-2 text-sm">
                  <div className="flex flex-wrap gap-1.5">{sel1.kev ? <Chip tone="red" title="Listed in CISA's Known Exploited Vulnerabilities catalogue">CISA KEV{sel1.kev_added ? ` · added ${sel1.kev_added}` : ''}</Chip> : <Chip>Not in CISA KEV</Chip>}{sel1.mentioned && <Chip tone="accent">{sel1.articles} article(s) · {sel1.events} event(s)</Chip>}{sel1.monitored.map((m) => <Chip key={m} tone="violet">{m}</Chip>)}</div>
                  <dl className="grid grid-cols-2 gap-2 text-xs"><dt className="text-mute">CVSS</dt><dd className="text-ink">{na(sel1.cvss)}</dd><dt className="text-mute">EPSS probability</dt><dd className="text-ink">{sel1.epss === null ? 'N/A' : `${(sel1.epss * 100).toFixed(2)}%`}</dd><dt className="text-mute">EPSS percentile</dt><dd className="text-ink">{sel1.epss_percentile === null ? 'N/A' : `${(sel1.epss_percentile * 100).toFixed(0)}`}</dd></dl>
                  <div className="flex flex-wrap gap-2 pt-1">
                    <button onClick={() => nav.vuln(sel1.cve)} className="flex items-center gap-1.5 rounded-lg border border-accent/40 bg-accent/10 px-3 py-1.5 text-xs text-accent"><Search size={12} /> Vulnerability Explorer</button>
                    <button onClick={() => nav.feed({ cve: sel1.cve })} className="flex items-center gap-1.5 rounded-lg border border-line px-3 py-1.5 text-xs text-ink hover:border-accent/40"><Newspaper size={12} /> News</button>
                    <button onClick={() => nav.graph(`cve:${sel1.cve}`)} className="flex items-center gap-1.5 rounded-lg border border-line px-3 py-1.5 text-xs text-ink hover:border-accent/40"><Network size={12} /> Graph</button>
                  </div>
                </div>
              )}
              <div className="mt-4 space-y-2 border-t border-line pt-3 text-[11px] leading-relaxed text-mute">
                <p><b className="text-ink">EPSS</b> is an estimated probability of exploitation activity within its prediction horizon (about 30 days).</p>
                <p><b className="text-ink">KEV</b> means CISA lists the CVE as exploited in the wild. The two are different signals and no combined risk score is computed here.</p>
                <p>A CVE in a recent article is not evidence of recent exploitation.</p>
              </div>
            </div>
          </div>
          <div className={`${card} overflow-x-auto`}>
            <table className="w-full min-w-[720px] text-sm">
              <thead className="border-b border-line text-left text-xs uppercase tracking-wider text-mute"><tr><th className="px-4 py-3">CVE</th><th className="px-4 py-3">CVSS</th><th className="px-4 py-3">EPSS</th><th className="px-4 py-3">KEV</th><th className="px-4 py-3">News</th><th className="px-4 py-3">Monitored</th></tr></thead>
              <tbody>
                {rows.map((p: VulnPoint) => (
                  <tr key={p.cve} onClick={() => setPick(p.cve)} className={`cursor-pointer border-b border-line/60 last:border-0 hover:bg-bg/40 ${pick === p.cve ? 'bg-accent/5' : ''}`}>
                    <td className="px-4 py-2 font-medium text-ink">{p.cve}</td><td className="px-4 py-2 tabular-nums text-mute">{na(p.cvss)}</td><td className="px-4 py-2 tabular-nums text-mute">{p.epss === null ? 'N/A' : `${(p.epss * 100).toFixed(2)}%`}</td>
                    <td className="px-4 py-2">{p.kev ? <Chip tone="red">KEV</Chip> : <span className="text-xs text-mute">no</span>}</td><td className="px-4 py-2 text-xs text-mute">{p.articles ? `${p.articles} article(s)` : '-'}</td><td className="px-4 py-2 text-xs text-mute">{p.monitored.join(', ') || '-'}</td>
                  </tr>))}
              </tbody>
            </table>
            <div className="flex items-center justify-between border-t border-line px-4 py-2 text-xs text-mute"><span>{pts.length} CVE(s)</span>
              <span className="flex items-center gap-2"><button disabled={page <= 1} onClick={() => setPage(page - 1)} className="rounded border border-line px-2 py-1 disabled:opacity-40">Prev</button>{page} / {Math.max(1, Math.ceil(pts.length / 12))}<button disabled={page * 12 >= pts.length} onClick={() => setPage(page + 1)} className="rounded border border-line px-2 py-1 disabled:opacity-40">Next</button></span></div>
          </div>
        </>
      )}
    </div>
  )
}

// ----------------------------------------------------------------------------- C. Vendors & technologies
export function EntitiesPanel({ f, meta, nav }: { f: AFilters; meta: Meta | null; nav: Nav }) {
  const [kind, setKind] = useState<'vendor' | 'technology'>('vendor')
  const [sort, setSort] = useState('events')
  const [page, setPage] = useState(1)
  const [pick, setPick] = useState<{ kind: 'vendor' | 'technology'; id: string } | null>(null)
  const list = useAsync(() => aEntities(f, kind, { sort, page, page_size: 12 }), [key(f), kind, sort, page])
  useEffect(() => setPage(1), [key(f), kind, sort])
  const det = useAsync(() => (pick ? aEntity(f, pick.kind, pick.id) : Promise.resolve(null)), [key(f), pick?.kind, pick?.id])
  const quick = useMemo(() => {
    const out: { kind: 'vendor' | 'technology'; id: string; label: string }[] = []
    for (const w of ['Microsoft', 'Linux', 'Fortinet', 'VMware', 'Docker', 'Kubernetes']) {
      const v = meta?.vendors.find((x) => x.toLowerCase() === w.toLowerCase())
      const t = meta?.technologies.find((x) => x.name.toLowerCase().includes(w.toLowerCase()))
      if (v) out.push({ kind: 'vendor', id: v, label: w }); else if (t) out.push({ kind: 'technology', id: t.id, label: t.name })
    }
    return out
  }, [meta])
  const d = list.data
  const dd = det.data
  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-3">
        <Segmented options={[['vendor', 'Vendors'], ['technology', 'Technologies']]} value={kind} onChange={(v) => { setKind(v as typeof kind); setPick(null) }} />
        <select value={sort} onChange={(e) => setSort(e.target.value)} className={sel} aria-label="Sort"><option value="events">Sort: distinct events</option><option value="articles">Sort: articles</option><option value="cves">Sort: CVEs mentioned</option><option value="kev">Sort: KEV CVEs</option><option value="sources">Sort: independent sources</option></select>
        <div className="flex flex-wrap gap-1.5">{quick.map((q) => <button key={q.label} onClick={() => { setKind(q.kind); setPick({ kind: q.kind, id: q.id }) }}><Chip tone={pick?.id === q.id ? 'accent' : 'mute'}>{q.label}</Chip></button>)}</div>
      </div>
      <Status loading={list.loading && !d} error={list.error} onRetry={list.reload} />
      {d?.status === 'insufficient_comparable' && <Insufficient msg={d.message} />}
      {d?.status === 'ok' && (
        <div className="grid gap-4 xl:grid-cols-[1fr_420px]">
          <div className={`${card} overflow-x-auto`}>
            <div className="border-b border-line px-4 py-3"><span className="text-sm font-semibold text-ink">Media Attention</span> <span className="text-xs text-mute">· ranked by distinct events, not article volume. Not a risk level.</span></div>
            <table className="w-full min-w-[620px] text-sm">
              <thead className="border-b border-line text-left text-xs uppercase tracking-wider text-mute"><tr><th className="px-4 py-2.5">{kind === 'vendor' ? 'Vendor' : 'Technology'}</th><th className="px-4 py-2.5 text-right">Events</th><th className="px-4 py-2.5 text-right">Articles</th><th className="px-4 py-2.5 text-right">CVEs</th><th className="px-4 py-2.5 text-right">KEV</th><th className="px-4 py-2.5 text-right">Sources</th><th className="px-4 py-2.5">vs prev.</th></tr></thead>
              <tbody>
                {d.items.map((r) => (
                  <tr key={r.id} onClick={() => setPick({ kind, id: r.id })} className={`cursor-pointer border-b border-line/60 last:border-0 hover:bg-bg/40 ${pick?.id === r.id ? 'bg-accent/5' : ''}`}>
                    <td className="px-4 py-2 font-medium text-ink">{r.name}</td><td className="px-4 py-2 text-right tabular-nums text-ink">{r.events}</td><td className="px-4 py-2 text-right tabular-nums text-mute">{r.articles}</td>
                    <td className="px-4 py-2 text-right tabular-nums text-mute">{r.cves}</td><td className="px-4 py-2 text-right tabular-nums text-mute">{r.kev_cves}</td><td className="px-4 py-2 text-right tabular-nums text-mute">{r.sources}</td><td className="px-4 py-2"><CmpBadge c={r.compare} /></td>
                  </tr>))}
              </tbody>
            </table>
            <div className="flex items-center justify-between border-t border-line px-4 py-2 text-xs text-mute"><span>{d.total} {kind === 'vendor' ? 'vendors' : 'technologies'}</span>
              <span className="flex items-center gap-2"><button disabled={page <= 1} onClick={() => setPage(page - 1)} className="rounded border border-line px-2 py-1 disabled:opacity-40">Prev</button>{page} / {d.pages}<button disabled={page >= d.pages} onClick={() => setPage(page + 1)} className="rounded border border-line px-2 py-1 disabled:opacity-40">Next</button></span></div>
          </div>
          <div className={`${card} p-5`}>
            {!pick && <div className="py-10 text-center text-sm text-mute">Select a vendor or technology to see its timeline, news, vulnerabilities, watchlists and graph.</div>}
            {pick && <Status loading={det.loading && !dd} error={det.error} onRetry={det.reload} />}
            {pick && dd?.status === 'ok' && (
              <div className="space-y-4">
                <Head title={dd.name} sub={`${dd.events} distinct event(s) · ${dd.articles} article(s) in the period`} />
                <LineChart labels={dd.bucket_starts} hourly={dd.filters.bucket_hours === 1} height={170} series={[{ name: 'Events', color: '#22D3EE', values: dd.series.events }, { name: 'Articles', color: '#F97316', values: dd.series.articles, dashed: true }]} />
                <div className="flex flex-wrap gap-2">
                  {pick.kind === 'technology' ? <button onClick={() => nav.techNews(pick.id)} className="flex items-center gap-1.5 rounded-lg border border-accent/40 bg-accent/10 px-3 py-1.5 text-xs text-accent"><Newspaper size={12} /> News</button>
                    : <button onClick={() => nav.feed({ vendor: pick.id })} className="flex items-center gap-1.5 rounded-lg border border-accent/40 bg-accent/10 px-3 py-1.5 text-xs text-accent"><Newspaper size={12} /> News</button>}
                  <button onClick={() => (pick.kind === 'vendor' ? nav.vulnVendor(pick.id) : nav.vuln(''))} className="flex items-center gap-1.5 rounded-lg border border-line px-3 py-1.5 text-xs text-ink hover:border-accent/40"><Search size={12} /> Vulnerabilities</button>
                  {dd.graph_node ? <button onClick={() => nav.graph(dd.graph_node!)} className="flex items-center gap-1.5 rounded-lg border border-line px-3 py-1.5 text-xs text-ink hover:border-accent/40"><Network size={12} /> Relationship Graph</button> : <span className="px-1 py-1.5 text-[11px] text-mute">No verifiable graph relationships</span>}
                </div>
                {dd.watchlists.length > 0 && <div><div className="mb-1 text-[11px] uppercase tracking-wider text-mute">In Technology Watchlists</div><div className="flex flex-wrap gap-1.5">{dd.watchlists.map((w) => <button key={w.id} onClick={nav.watchlists}><Chip tone="violet">{w.name}</Chip></button>)}</div></div>}
                {dd.cves.length > 0 && <div><div className="mb-1 text-[11px] uppercase tracking-wider text-mute">CVEs mentioned</div><div className="flex flex-wrap gap-1.5">{dd.cves.slice(0, 12).map((c) => <button key={c.cve} onClick={() => nav.vuln(c.cve)} title={`${c.articles} article(s)`}><Chip tone={c.kev ? 'red' : 'orange'}>{c.cve}{c.kev ? ' · KEV' : ''}</Chip></button>)}</div></div>}
                <div><div className="mb-1 text-[11px] uppercase tracking-wider text-mute">Latest news</div><ul className="space-y-1.5 text-xs">{dd.news.slice(0, 6).map((n) => <li key={n.url}><ExtLink href={n.url}>{n.title}</ExtLink><span className="ml-1 text-mute">· {n.source}</span></li>)}</ul></div>
              </div>
            )}
          </div>
        </div>
      )}
      {d?.notes && <Note>{d.notes.join(' ')}</Note>}
    </div>
  )
}

// ----------------------------------------------------------------------------- D. Emerging stories
export function EmergingPanel({ f, nav }: { f: AFilters; nav: Nav }) {
  const [sort, setSort] = useState('growth')
  const [page, setPage] = useState(1)
  const [open, setOpen] = useState<string | null>(null)
  const { data, loading, error, reload } = useAsync(() => aEmerging(f, { sort, page, page_size: 12 }), [key(f), sort, page])
  useEffect(() => setPage(1), [key(f), sort])
  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-3"><Segmented options={[['growth', 'Coverage growth'], ['sources', 'Independent sources'], ['recency', 'Recency'], ['priority', 'News Priority Score']]} value={sort} onChange={setSort} /></div>
      <Status loading={loading && !data} error={error} onRetry={reload} empty={data?.status === 'ok' && data.items.length === 0} emptyText="No events in this period." />
      {data?.status === 'insufficient_comparable' && <Insufficient msg={data.message} />}
      {data?.status === 'ok' && (
        <>
          <ul className="space-y-3">
            {data.items.map((s) => (
              <li key={s.id} className={`${card} p-4`}>
                <div className="flex flex-wrap items-start gap-2">
                  <div className="min-w-0 flex-1">
                    <div className="text-sm font-medium text-ink">{s.title}</div>
                    <div className="mt-1 flex flex-wrap gap-1.5"><Chip tone="accent">{s.category}</Chip>{s.official && <Chip tone="violet">official</Chip>}<Chip title="News Priority Score — reading priority, not risk">Priority {s.priority.toFixed(0)}</Chip>
                      {s.history_sufficient && s.growth !== null ? <Chip tone={s.growth > 0 ? 'orange' : 'mute'} title={`${s.recent_articles} article(s) in the latest ${data.half_window_hours} h vs ${s.earlier_articles} in the half before`}>coverage {s.growth > 0 ? '+' : ''}{s.growth}</Chip> : <Chip title="Needs at least two dated articles and a full earlier half-window of history">insufficient history</Chip>}
                      {s.new_sources > 0 && <Chip tone="orange" title="Outlets that began covering the story in the latest half-window">+{s.new_sources} new outlet(s)</Chip>}</div>
                  </div>
                  <div className="flex items-center gap-3 text-xs text-mute">
                    <div title="Cumulative independent outlets covering the story, by day since first publication"><Spark values={s.series.sources_cumulative} /></div>
                    <div className="text-right tabular-nums"><div className="text-ink">{s.independent_sources} source(s)</div><div>{s.article_count} article(s)</div></div>
                  </div>
                </div>
                <div className="mt-2 text-xs text-mute">First known publication {fmt(s.first_published)} · last {fmt(s.last_published)}</div>
                {(s.cves.length > 0 || s.technologies.length > 0) && <div className="mt-2 flex flex-wrap gap-1.5">{s.cves.map((c) => <button key={c} onClick={() => nav.vuln(c)}><Chip tone="orange">{c}</Chip></button>)}{s.technologies.map((t) => <Chip key={t} tone="violet">{t}</Chip>)}</div>}
                <button onClick={() => setOpen(open === s.id ? null : s.id)} className="mt-2 flex items-center gap-1 text-xs text-accent"><ExternalLink size={11} />{open === s.id ? 'Hide articles' : 'Original articles'}</button>
                {open === s.id && <ul className="mt-2 space-y-1 text-xs">{s.articles.map((a) => <li key={a.url}><ExtLink href={a.url}>{a.title}</ExtLink><span className="ml-1 text-mute">· {a.source}</span></li>)}<li><button onClick={() => nav.feed({ q: s.title.split(' ').slice(0, 5).join(' ') })} className="text-accent hover:underline">Open in Intelligence Feed</button></li></ul>}
              </li>))}
          </ul>
          <div className="flex items-center justify-between text-xs text-mute"><span>{data.total} event(s)</span><span className="flex items-center gap-2"><button disabled={page <= 1} onClick={() => setPage(page - 1)} className="rounded border border-line px-2 py-1 disabled:opacity-40">Prev</button>{page} / {data.pages}<button disabled={page >= data.pages} onClick={() => setPage(page + 1)} className="rounded border border-line px-2 py-1 disabled:opacity-40">Next</button></span></div>
          {data.notes && <Note>{data.notes.join(' ')}</Note>}
        </>
      )}
    </div>
  )
}
