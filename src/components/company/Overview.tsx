import { useEffect, useState } from 'react'
import { AlertTriangle, Network, Newspaper, Search } from 'lucide-react'
import { cChanges, cDashboard, cTech, type Change, type CTech } from '../../data/company'
import Scene from '../Scene'
import { Chip, ExtLink, Note, Segmented, Status, card, fmt, useAsync } from '../intel/ui'
import { btn2, ScopeTag, StatusBadge, ver, type CNav } from './common'

export function ChangesPanel({ id, period, custom }: { id: string; period: string; custom?: { date_from?: string; date_to?: string } }) {
  const [page, setPage] = useState(1)
  const { data, loading, error, reload } = useAsync(() => cChanges(id, { period, page, ...custom }), [id, period, page, custom?.date_from, custom?.date_to])
  useEffect(() => setPage(1), [id, period])
  const KIND: Record<string, string> = { new_cve: 'New CVE associated', kev_added: 'KEV listing', official_advisory: 'Official advisory', news: 'News', inventory: 'Inventory', assessment_change: 'Assessment' }
  return (
    <div className={`${card} p-5`}>
      <h3 className="text-sm font-semibold text-ink">What Changed?</h3>
      <p className="mb-3 text-xs text-mute">Verifiable changes. <b className="text-ink">Published</b> = when the fact became public; <b className="text-ink">known</b> = when Cyber Risk Pyramid recorded it.</p>
      <Status loading={loading && !data} error={error} onRetry={reload} empty={!!data && data.items.length === 0} emptyText="No changes recorded in this period." />
      {data && data.items.length > 0 && (
        <>
          <div className="mb-2 flex flex-wrap gap-1.5">{Object.entries(data.counts).map(([k, v]) => <Chip key={k}>{KIND[k] ?? k}: {v}</Chip>)}</div>
          <ul className="divide-y divide-line/60">
            {data.items.map((c: Change, i) => (
              <li key={i} className="py-2.5 text-sm">
                <div className="flex flex-wrap items-center gap-2"><Chip tone={c.kind === 'kev_added' ? 'red' : c.kind === 'official_advisory' ? 'violet' : 'accent'}>{KIND[c.kind] ?? c.kind}</Chip>
                  {c.url ? <ExtLink href={c.url}>{c.title}</ExtLink> : <span className="text-ink">{c.title}</span>}
                  {c.historical && <Chip tone="orange" title={c.note ?? ''}>historical, discovered late</Chip>}</div>
                <div className="mt-0.5 text-[11px] text-mute">Published {c.published_at ? fmt(c.published_at) : 'n/a'} · known {fmt(c.known_at)}{c.source ? ` · ${c.source}` : ''}{c.note && !c.historical ? ` · ${c.note}` : ''}</div>
              </li>
            ))}
          </ul>
          <div className="mt-2 flex items-center justify-between text-xs text-mute"><span>{data.total} item(s)</span>
            <span className="flex items-center gap-2"><button disabled={page <= 1} onClick={() => setPage(page - 1)} className="rounded border border-line px-2 py-1 disabled:opacity-40">Prev</button>{page} / {data.pages}<button disabled={page >= data.pages} onClick={() => setPage(page + 1)} className="rounded border border-line px-2 py-1 disabled:opacity-40">Next</button></span></div>
        </>
      )}
      {data && <p className="mt-2 text-[11px] text-mute">{data.notes.join(' ')}</p>}
    </div>
  )
}

function TechPanel({ id, tech, nav, onCve, onClose }: { id: string; tech: CTech; nav: CNav; onCve: (cve: string) => void; onClose: () => void }) {
  const { data, loading, error } = useAsync(() => cTech(id, tech.company_tech_id), [id, tech.company_tech_id])
  const d = data
  const sc = tech.score
  return (
    <aside className="slide-in w-[380px] shrink-0 overflow-y-auto border-l border-line bg-sidebar p-5">
      <div className="flex items-start justify-between gap-2"><div><div className="text-base font-semibold text-ink">{tech.name}</div><div className="text-xs text-mute">{tech.assets} active asset(s){tech.versions.length ? ` · versions ${tech.versions.join(', ')}` : ''}</div></div><button onClick={onClose} className="text-xs text-mute hover:text-ink">Close</button></div>
      <div className="mt-3 rounded-lg border border-line p-3"><ScopeTag scope="signal" />
        <div className="mt-1 flex items-center gap-2"><span className="text-xl font-semibold tabular-nums" style={{ color: tech.level.color }}>{sc === null ? 'N/A' : Math.round(sc)}</span><span className="text-xs text-ink">{sc === null ? (tech.data_availability === 'monitored' || tech.data_availability === 'partial' ? 'Insufficient Data' : 'Score Unavailable') : tech.level.label}</span></div>
        {tech.coverage_label && <div className="mt-1 text-[11px] text-mute">{tech.coverage_label}{tech.limitations && tech.limitations[1] ? ` — ${tech.limitations[1]}` : ''}</div>}
        <p className="mt-1 text-[11px] text-mute">Global score for the technology — not this company's risk, and independent of its asset count.</p></div>
      <div className="mt-3 grid grid-cols-2 gap-2 text-xs">
        <div className="rounded-lg border border-line p-2"><ScopeTag scope="potential" /><div className="text-ink">{tech.exposure.potential} potential · {tech.exposure.needs_review} review</div><div className="text-mute">{tech.exposure.insufficient} insufficient data</div></div>
        <div className="rounded-lg border border-line p-2"><ScopeTag scope="confirmed" /><div className="text-ink">{tech.exposure.confirmed} confirmed</div><div className="text-mute">{tech.related_cves} related · {tech.related_kev} KEV</div></div>
      </div>
      {tech.cves_complete === false && <div className="mt-2 flex items-start gap-1.5 text-[11px] text-amber-300"><AlertTriangle size={12} className="mt-0.5 shrink-0" />Vulnerability data for this technology is still being collected{tech.sync ? ` (backfill ${tech.sync.label.toLowerCase()})` : ''}: counts are lower bounds, not the absence of vulnerabilities.</div>}
      {tech.assets_without_version > 0 && <div className="mt-2 flex items-start gap-1.5 text-[11px] text-amber-300"><AlertTriangle size={12} className="mt-0.5 shrink-0" />{tech.assets_without_version} asset(s) have no version: applicability cannot be assessed.</div>}
      <Status loading={loading && !d} error={error} />
      {d && (
        <div className="mt-4 space-y-4">
          <div className="flex flex-wrap gap-2">
            <button onClick={() => nav.explorer(d.explorer.tech ? { tech: d.explorer.tech } : { vendor: d.explorer.vendor ?? undefined, product: d.explorer.product ?? undefined })} className={btn2}><Search size={11} className="mr-1 inline" />Vulnerability Explorer</button>
            {d.graph_node && <button onClick={() => nav.graph(d.graph_node!)} className={btn2}><Network size={11} className="mr-1 inline" />Graph</button>}
          </div>
          <div><div className="mb-1 text-[11px] uppercase tracking-wider text-mute">Assets</div><ul className="space-y-1 text-xs">{d.assets.map((a) => <li key={a.id} className="flex justify-between gap-2 text-ink"><span>{a.asset_ref ?? `#${a.id}`}{a.status === 'retired' ? ' (retired)' : ''}</span><span className="text-mute">{ver(a)} · {a.environment} · internet: {a.internet_exposed}</span></li>)}</ul></div>
          <div><div className="mb-1 text-[11px] uppercase tracking-wider text-mute">Related CVEs ({d.cve_total})</div>
            <ul className="space-y-1">{d.cves.slice(0, 12).map((c) => <li key={c.id} className="flex items-center gap-2 text-xs"><button onClick={() => onCve(c.id)} className="text-accent hover:underline">{c.id}</button>{c.kev && <Chip tone="red">KEV</Chip>}<span className="ml-auto"><StatusBadge s={c.effective_status} auto /></span></li>)}</ul></div>
          {d.note && <Note>{d.note}</Note>}
          {d.advisories.length > 0 && <div><div className="mb-1 text-[11px] uppercase tracking-wider text-mute">Official advisories (30 d)</div><ul className="space-y-1 text-xs">{d.advisories.map((n) => <li key={n.id}><ExtLink href={n.url}>{n.title}</ExtLink></li>)}</ul></div>}
          {d.news.length > 0 && <div><div className="mb-1 flex items-center gap-1 text-[11px] uppercase tracking-wider text-mute"><Newspaper size={11} />Related news events (30 d)</div><ul className="space-y-1 text-xs">{d.news.map((n) => <li key={n.id}><ExtLink href={n.url}>{n.title}</ExtLink> <span className="text-mute">· {n.sources} source(s)</span></li>)}</ul></div>}
        </div>
      )}
    </aside>
  )
}

export default function Overview({ id, nav, goInventory, goVuln }: { id: string; nav: CNav; goInventory: () => void; goVuln: (cve: string) => void }) {
  const [period, setPeriod] = useState('30d')
  const [sel, setSel] = useState<string | null>(null)
  const { data, loading, error, reload } = useAsync(() => cDashboard(id, period), [id, period])
  const techs = data?.technologies ?? []
  const picked = techs.find((t) => t.id === sel) ?? null
  return (
    <div className="space-y-4 p-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <p className="max-w-3xl text-xs text-mute">Technology threat monitoring and potential exposure assessment. Pyramids show the <b className="text-ink">global Threat Signal Score</b> of each technology the company uses; they are not the company's risk, and red does not mean compromised.</p>
        <Segmented options={[['24h', '24 h'], ['7d', '7 days'], ['30d', '30 days'], ['90d', '90 days']]} value={period} onChange={setPeriod} />
      </div>
      <Status loading={loading && !data} error={error} onRetry={reload} />
      {data && (
        <>
          <div className="grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-5">
            {data.kpis.map((k) => (
              <div key={k.key} className={`${card} px-4 py-3`}><div className="flex items-center justify-between gap-2"><div className="text-[11px] uppercase tracking-wider text-mute">{k.label}</div><ScopeTag scope={k.scope} /></div>
                <div className="mt-0.5 text-2xl font-semibold tabular-nums text-ink">{k.value === null ? 'N/A' : k.value}{k.value !== null && k.unit ? k.unit : ''}</div>{k.hint && <div className="text-[11px] text-mute">{k.hint}</div>}</div>))}
          </div>
          {techs.length === 0 ? (
            <div className="rounded-xl border border-dashed border-line py-16 text-center"><div className="text-sm text-ink">No technologies registered yet</div><p className="mx-auto mt-1 max-w-md text-xs text-mute">Add the products this company uses in the inventory to see their pyramids, related CVEs, news and advisories.</p><button onClick={goInventory} className={`${btn2} mt-4`}>Go to Technology Inventory</button></div>
          ) : (
            <div className="flex min-h-[460px] overflow-hidden rounded-xl border border-line bg-bg">
              <div className="relative min-w-0 flex-1">
                <Scene technologies={techs} selectedId={sel} onSelect={setSel} />
                <div className="pointer-events-none absolute left-4 top-3 text-[11px] text-mute">{techs.length} technolog{techs.length === 1 ? 'y' : 'ies'} · one pyramid per product, not per asset · drag to rotate, click a pyramid</div>
              </div>
              {picked && <TechPanel key={picked.id} id={id} tech={picked} nav={nav} onCve={goVuln} onClose={() => setSel(null)} />}
            </div>
          )}
          {techs.length > 0 && (
            <div className={`${card} overflow-x-auto`}>
              <table className="w-full min-w-[820px] text-sm"><thead className="border-b border-line text-left text-xs uppercase tracking-wider text-mute"><tr><th className="px-4 py-2.5">Technology</th><th className="px-4 py-2.5 text-right">Assets</th><th className="px-4 py-2.5">Threat Signal</th><th className="px-4 py-2.5 text-right">CVEs</th><th className="px-4 py-2.5 text-right">KEV</th><th className="px-4 py-2.5 text-right">News ev.</th><th className="px-4 py-2.5 text-right">Advisories</th><th className="px-4 py-2.5">Data</th></tr></thead>
                <tbody>{techs.map((t) => (
                  <tr key={t.id} onClick={() => setSel(t.id)} className={`cursor-pointer border-b border-line/60 last:border-0 hover:bg-bg/40 ${sel === t.id ? 'bg-accent/5' : ''}`}>
                    <td className="px-4 py-2 font-medium text-ink">{t.name}</td><td className="px-4 py-2 text-right tabular-nums">{t.assets}</td>
                    <td className="px-4 py-2 text-xs" style={{ color: t.level.color }}>{t.score === null ? (t.data_availability === 'monitored' || t.data_availability === 'partial' ? 'Insufficient Data' : 'Score Unavailable') : `${Math.round(t.score)} · ${t.level.label}`}</td>
                    <td className="px-4 py-2 text-right tabular-nums text-mute">{t.related_cves}</td><td className="px-4 py-2 text-right tabular-nums text-mute">{t.related_kev}</td>
                    <td className="px-4 py-2 text-right tabular-nums text-mute">{t.news_events ?? 'n/a'}</td><td className="px-4 py-2 text-right tabular-nums text-mute">{t.official_advisories ?? 'n/a'}</td>
                    <td className="px-4 py-2 text-xs text-mute">{t.data_availability === 'full' ? 'Score available' : t.data_availability === 'monitored' ? 'Monitored · Insufficient Data' : t.data_availability === 'partial' ? 'Partial Coverage' : t.data_availability === 'catalog_only' ? 'Catalog Only' : 'Score Unavailable'}</td></tr>))}</tbody></table>
            </div>
          )}
          <ChangesPanel id={id} period={period === '24h' ? '24h' : period} />
          {data.truncated && <Note tone="warn">Some products have more related CVEs than the per-product cap; counts are lower bounds.</Note>}
          <Note>{data.notes.join(' ')}</Note>
        </>
      )}
    </div>
  )
}
