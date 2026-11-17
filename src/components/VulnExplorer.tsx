import { useEffect, useState } from 'react'
import { ArrowLeft, Bug, Cpu, Database, Download, Loader2, Network, Newspaper, Search } from 'lucide-react'
import { fetchVuln, fetchVulnCoverage, fetchVulnFacets, fetchVulns, fetchWatchlists, lookupVuln } from '../data/api'
import type { VulnDetail, VulnRow } from '../data/types'
import { Chip, ExtLink, Note, Pager, Status, card, fmt, sel, useAsync } from './intel/ui'

export interface VulnPreset { q?: string; tech?: string; watchlist?: string; vendor?: string; product?: string; open?: string }
const SEV: Record<string, string> = {
  critical: 'border-red-400/40 bg-red-400/10 text-red-300', high: 'border-orange-400/40 bg-orange-400/10 text-orange-300',
  medium: 'border-amber-400/40 bg-amber-400/10 text-amber-300', low: 'border-emerald-400/40 bg-emerald-400/10 text-emerald-300',
  unrated: 'border-line text-mute', none: 'border-line text-mute',
}
const day = (s: string | null) => (s ? s.slice(0, 10) : '-')

function Sev({ r }: { r: Pick<VulnRow, 'cvss' | 'severity'> }) {
  return <span className={`rounded-full border px-2 py-0.5 text-[11px] font-medium tabular-nums ${SEV[r.severity]}`}>{r.cvss !== null ? `${r.cvss.toFixed(1)} ${r.severity}` : 'CVSS n/a'}</span>
}
function Signals({ r }: { r: Pick<VulnRow, 'epss' | 'in_kev' | 'kev_ransomware'> }) {
  return (
    <>
      {r.in_kev && <Chip tone="red" title="Listed in CISA Known Exploited Vulnerabilities">{r.kev_ransomware ? 'KEV · ransomware use' : 'CISA KEV'}</Chip>}
      <Chip title="FIRST EPSS: probability of exploitation in the next 30 days">{r.epss !== null ? `EPSS ${(r.epss * 100).toFixed(1)}%` : 'EPSS n/a'}</Chip>
    </>
  )
}

function Detail({ id, onBack, onNews, onTech, onGraph }: { id: string; onBack: () => void; onNews: (cve: string) => void; onTech: (t: string) => void; onGraph: (nodeId: string) => void }) {
  const [d, setD] = useState<VulnDetail | null>(null)
  const [err, setErr] = useState<string | null>(null)
  const [missing, setMissing] = useState(false)
  const [busy, setBusy] = useState(false)
  useEffect(() => {
    let alive = true
    setD(null); setErr(null); setMissing(false)
    fetchVuln(id).then((x) => alive && setD(x)).catch((e) => alive && (String(e.message).includes('404') ? setMissing(true) : setErr(String(e.message))))
    return () => { alive = false }
  }, [id])
  const look = () => { setBusy(true); setErr(null); lookupVuln(id).then((x) => { setD(x); setMissing(false) }).catch((e) => setErr(String(e.message))).finally(() => setBusy(false)) }
  return (
    <div className="space-y-5 p-6">
      <button onClick={onBack} className="flex items-center gap-1.5 text-xs text-mute hover:text-ink"><ArrowLeft size={14} /> Back to results</button>
      <div className="flex flex-wrap items-center gap-3"><h2 className="text-xl font-semibold text-ink">{id}</h2>
        {d && <button onClick={() => onGraph(`cve:${id}`)} className="flex items-center gap-1.5 rounded-lg border border-line px-3 py-1.5 text-xs text-ink hover:border-accent/40"><Network size={13} /> Explore Relationships</button>}</div>
      {err && <Note tone="warn">{err}</Note>}
      {!d && !missing && !err && <div className="flex items-center gap-2 text-sm text-mute"><Loader2 size={15} className="animate-spin" /> Loading…</div>}
      {missing && (
        <div className={`${card} space-y-3 p-5 text-sm`}>
          <p className="text-ink">This CVE is not in the local catalogue.</p>
          <p className="text-mute">The local catalogue is not the full NVD database. You can query NVD for this one identifier (limited to a few lookups per hour).</p>
          <button onClick={look} disabled={busy} className="flex items-center gap-2 rounded-lg border border-accent/40 bg-accent/15 px-4 py-2 text-accent disabled:opacity-50">{busy ? <Loader2 size={14} className="animate-spin" /> : <Download size={14} />} Look up in NVD</button>
        </div>
      )}
      {d && (
        <div className="grid gap-5 xl:grid-cols-[1fr_320px]">
          <div className="space-y-5">
            <div className={`${card} space-y-3 p-5`}>
              <div className="flex flex-wrap items-center gap-2"><Sev r={d} /><Signals r={d} />{d.detail?.status && <Chip>{d.detail.status}</Chip>}{d.techs.map((t) => <button key={t.id} onClick={() => onTech(t.id)}><Chip tone="accent"><Cpu size={10} className="mr-1 inline" />{t.name}</Chip></button>)}</div>
              <p className="text-sm leading-relaxed text-ink">{d.description ?? 'No description available in the local catalogue.'}</p>
              <div className="text-xs text-mute">Published {day(d.published)}{d.kev ? ` · added to KEV ${d.kev.date_added}` : ''}{d.epss_percentile !== null ? ` · EPSS percentile ${(d.epss_percentile * 100).toFixed(0)}` : ''}{d.epss_date ? ` · EPSS score date ${d.epss_date}` : ''}{d.nvd?.last_modified ? ` · NVD modified ${day(d.nvd.last_modified)}` : ''}</div>
              {d.kev && <div className="text-xs text-mute">KEV entry: {d.kev.vendor} {d.kev.product}{d.kev.ransomware ? ' — known ransomware campaign use' : ''}{d.kev.required_action ? ` · Required action: ${d.kev.required_action}` : ''}{d.kev.due_date ? ` (due ${d.kev.due_date})` : ''}. KEV means known exploitation, not necessarily recent.</div>}
              {d.nvd?.complex_configuration && <div className="text-xs text-amber-300">This CVE has a conditional NVD configuration (AND / platform conditions): applicability to a version needs review.</div>}
            </div>

            <div className={`${card} p-5`}>
              <div className="mb-2 text-xs uppercase tracking-wider text-mute">Weakness (CWE) & affected versions</div>
              {(d.cwes?.length || d.affected?.length) ? (
                <div className="space-y-3 text-sm">
                  <div className="flex flex-wrap gap-1.5">{d.cwes?.length ? d.cwes.map((c) => (/^CWE-\d+$/.test(c.id) ? <a key={c.id} href={`https://cwe.mitre.org/data/definitions/${c.id.slice(4)}.html`} target="_blank" rel="noopener noreferrer"><Chip tone="violet">{c.id}</Chip></a> : <Chip key={c.id}>{c.id}</Chip>)) : <span className="text-mute">No CWE recorded.</span>}</div>
                  {d.affected?.length ? (
                    <table className="w-full text-left text-xs"><thead className="text-mute"><tr><th className="py-1">Product (vulnerable CPE)</th><th>Affected</th></tr></thead><tbody>
                      {d.affected.slice(0, 40).map((v, i) => <tr key={i} className="border-t border-line text-ink"><td className="py-1">{v.vendor} / {v.product}</td><td className="text-mute">{[v.version && `= ${v.version}`, v.from_incl && `≥ ${v.from_incl}`, v.from_excl && `> ${v.from_excl}`, v.to_incl && `≤ ${v.to_incl}`, v.to_excl && `< ${v.to_excl}`].filter(Boolean).join(', ') || 'all versions'}</td></tr>)}
                    </tbody></table>
                  ) : <span className="text-xs text-mute">No vulnerable-product data in the NVD record (a CVE without version data does not mean it does not affect a product).</span>}
                </div>
              ) : d.detail ? (
                <div className="space-y-3 text-sm">
                  <div className="flex flex-wrap gap-1.5">{d.detail.cwes.length ? d.detail.cwes.map((c) => (/^CWE-\d+$/.test(c) ? <a key={c} href={`https://cwe.mitre.org/data/definitions/${c.slice(4)}.html`} target="_blank" rel="noopener noreferrer"><Chip tone="violet">{c}</Chip></a> : <Chip key={c}>{c}</Chip>)) : <span className="text-mute">No CWE recorded.</span>}</div>
                  {d.detail.versions.length ? (
                    <table className="w-full text-left text-xs"><thead className="text-mute"><tr><th className="py-1">Product</th><th>Affected</th></tr></thead><tbody>
                      {d.detail.versions.map((v, i) => <tr key={i} className="border-t border-line text-ink"><td className="py-1">{v.product}</td><td className="text-mute">{[v.version && `= ${v.version}`, v.from_incl && `≥ ${v.from_incl}`, v.from_excl && `> ${v.from_excl}`, v.to_incl && `≤ ${v.to_incl}`, v.to_excl && `< ${v.to_excl}`].filter(Boolean).join(', ') || 'all versions'}</td></tr>)}
                    </tbody></table>
                  ) : <span className="text-xs text-mute">No affected-version data published.</span>}
                </div>
              ) : (
                <div className="space-y-2 text-sm text-mute">
                  <p>CWE, affected versions and references are fetched from NVD on request (not stored for every CVE).</p>
                  <button onClick={look} disabled={busy} className="flex items-center gap-2 rounded-lg border border-accent/40 bg-accent/15 px-3 py-1.5 text-xs text-accent disabled:opacity-50">{busy ? <Loader2 size={13} className="animate-spin" /> : <Download size={13} />} Fetch full details from NVD</button>
                </div>
              )}
              {d.products.length > 0 && <div className="mt-3 text-xs text-mute">Products (CPE / KEV): {d.products.join(' · ')}</div>}
            </div>

            <div className={`${card} p-5`}>
              <div className="mb-2 text-xs uppercase tracking-wider text-mute">References</div>
              <div className="flex flex-wrap gap-x-5 gap-y-1 text-sm"><ExtLink href={d.links.nvd}>NVD record</ExtLink>{d.links.kev && <ExtLink href={d.links.kev}>CISA KEV catalogue</ExtLink>}<ExtLink href={d.links.epss}>FIRST EPSS</ExtLink></div>
              {d.references && d.references.length > 0 ? (
                <ul className="mt-3 space-y-1 text-xs">{d.references.slice(0, 15).map((r) => <li key={r.url} className="flex items-center gap-2"><ExtLink href={r.url}>{r.url.length > 80 ? r.url.slice(0, 80) + '…' : r.url}</ExtLink>{r.tags.slice(0, 2).map((t) => <Chip key={t}>{t}</Chip>)}</li>)}</ul>
              ) : d.detail && d.detail.references.length > 0 && (
                <ul className="mt-3 space-y-1 text-xs">{d.detail.references.slice(0, 12).map((r) => <li key={r.url} className="flex items-center gap-2"><ExtLink href={r.url}>{r.url.length > 80 ? r.url.slice(0, 80) + '…' : r.url}</ExtLink>{r.tags.slice(0, 2).map((t) => <Chip key={t}>{t}</Chip>)}</li>)}</ul>
              )}
            </div>
          </div>

          <div className="space-y-5">
            <div className={`${card} p-5`}>
              <div className="mb-2 flex items-center justify-between text-xs uppercase tracking-wider text-mute"><span className="flex items-center gap-1.5"><Newspaper size={13} /> Related news ({d.news.length})</span></div>
              {d.news.length === 0 && <p className="text-xs text-mute">No stored article cites this CVE.</p>}
              <ul className="space-y-2.5">{d.news.map((n) => <li key={n.id} className="text-[13px]"><a href={n.url} target="_blank" rel="noopener noreferrer nofollow" className="text-ink hover:text-accent">{n.title}</a><div className="text-[11px] text-mute">{n.source} · {fmt(n.published)}</div></li>)}</ul>
              {d.news.length > 0 && <button onClick={() => onNews(id)} className="mt-3 w-full rounded-lg border border-line py-1.5 text-xs text-ink hover:border-accent/40">Open in Threat Explorer</button>}
            </div>
            <div className={`${card} space-y-1 p-5 text-xs text-mute`}>
              <div className="mb-1 uppercase tracking-wider">Local cache</div>
              {([['NVD record', d.cache.nvd_record], ['CISA KEV', d.cache.in_kev], ['EPSS score', d.cache.epss], ['Full details', d.cache.full_detail]] as [string, boolean][]).map(([l, v]) => <div key={l} className="flex justify-between"><span>{l}</span><span className={v ? 'text-emerald-300' : ''}>{v ? 'cached' : 'not cached'}</span></div>)}
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

export default function VulnExplorer({ preset, onNews, onTech, onGraph }: { preset: VulnPreset; onNews: (cve: string) => void; onTech: (t: string) => void; onGraph: (nodeId: string) => void }) {
  const [f, setF] = useState({ q: preset.q ?? '', vendor: preset.vendor ?? '', product: preset.product ?? '', tech: preset.tech ?? '', watchlist: preset.watchlist ?? '', cvss_min: '', epss_min: '', kev: '', has_news: '', sort: 'published', order: 'desc' })
  const [q, setQ] = useState(f.q)
  const [page, setPage] = useState(1)
  const [open, setOpen] = useState<string | null>(preset.open ?? null)
  useEffect(() => { const t = setTimeout(() => { setQ(f.q); setPage(1) }, 350); return () => clearTimeout(t) }, [f.q])
  const cov = useAsync(fetchVulnCoverage, [])
  const wl = useAsync(fetchWatchlists, [])
  const fac = useAsync(() => fetchVulnFacets(f.vendor || undefined), [f.vendor])
  const params = { ...f, q, page, page_size: 25, kev: f.kev === '' ? undefined : f.kev === '1', has_news: f.has_news === '1' ? true : undefined, cvss_min: f.cvss_min || undefined, epss_min: f.epss_min || undefined }
  const { data, loading, error, reload } = useAsync(() => fetchVulns(params), [q, f.vendor, f.product, f.tech, f.watchlist, f.cvss_min, f.epss_min, f.kev, f.has_news, f.sort, f.order, page])
  const set = (k: keyof typeof f) => (e: { target: { value: string } }) => { setF((s) => ({ ...s, [k]: e.target.value, ...(k === 'vendor' ? { product: '' } : {}) })); setPage(1) }
  const c = cov.data

  if (open) return <Detail id={open} onBack={() => setOpen(null)} onNews={onNews} onTech={onTech} onGraph={onGraph} />
  const looksCve = /^CVE-\d{4}-\d{4,7}$/i.test(f.q.trim())
  return (
    <div className="space-y-4 p-6">
      {c && (
        <div className={`${card} p-4`}>
          <div className="flex flex-wrap items-center gap-x-6 gap-y-2 text-xs text-mute">
            <span className="flex items-center gap-1.5 text-ink"><Database size={14} className="text-accent" /> Local catalogue: <b>{c.explorer_total}</b> CVEs</span>
            <span>{c.nvd_cached} cached from NVD</span><span>{c.kev_catalog} in CISA KEV</span><span>{c.epss_cached} with EPSS</span><span>{c.news_cves} cited in news</span>
            <span>NVD range: {day(c.nvd_published_range.from)} → {day(c.nvd_published_range.to)}</span>
          </div>
          <p className="mt-2 text-[11px] text-mute">{c.note}</p>
        </div>
      )}
      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <div className="relative sm:col-span-2"><Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-mute" /><input value={f.q} onChange={set('q')} maxLength={100} placeholder="CVE-2026-12345 or keyword in description…" className={`${sel} w-full pl-9`} /></div>
        <select value={f.vendor} onChange={set('vendor')} className={sel} aria-label="Vendor"><option value="">Any vendor</option>{(fac.data?.vendors ?? []).map((v) => <option key={v.name} value={v.name}>{v.name} ({v.cves})</option>)}</select>
        <select value={f.product} onChange={set('product')} disabled={!f.vendor} className={`${sel} disabled:opacity-40`} aria-label="Product"><option value="">{f.vendor ? 'Any product' : 'Select a vendor first'}</option>{(fac.data?.products ?? []).map((v) => <option key={v.name} value={v.name}>{v.name} ({v.cves})</option>)}</select>
        <select value={f.tech} onChange={set('tech')} className={sel} aria-label="Technology"><option value="">Any monitored technology</option>{(fac.data?.technologies ?? []).map((t) => <option key={t.id} value={t.id}>{t.name}</option>)}</select>
        <select value={f.watchlist} onChange={set('watchlist')} className={sel} aria-label="Watchlist"><option value="">Any watchlist</option>{(wl.data?.items ?? []).map((w) => <option key={w.id} value={w.id}>{w.name}</option>)}</select>
        <select value={f.cvss_min} onChange={set('cvss_min')} className={sel} aria-label="Minimum CVSS"><option value="">Any CVSS</option><option value="9">Critical (≥ 9.0)</option><option value="7">High+ (≥ 7.0)</option><option value="4">Medium+ (≥ 4.0)</option></select>
        <select value={f.epss_min} onChange={set('epss_min')} className={sel} aria-label="Minimum EPSS"><option value="">Any EPSS</option><option value="0.5">EPSS ≥ 50%</option><option value="0.1">EPSS ≥ 10%</option><option value="0.01">EPSS ≥ 1%</option></select>
        <select value={f.kev} onChange={set('kev')} className={sel} aria-label="CISA KEV"><option value="">KEV: any</option><option value="1">In CISA KEV</option><option value="0">Not in KEV</option></select>
        <select value={f.has_news} onChange={set('has_news')} className={sel} aria-label="News"><option value="">News: any</option><option value="1">Cited in news</option></select>
        <select value={`${f.sort}:${f.order}`} onChange={(e) => { const [s, o] = e.target.value.split(':'); setF((x) => ({ ...x, sort: s, order: o })); setPage(1) }} className={sel} aria-label="Sort">
          <option value="published:desc">Newest first</option><option value="published:asc">Oldest first</option><option value="cvss:desc">Severity (CVSS) high → low</option>
          <option value="epss:desc">Exploit probability (EPSS)</option><option value="kev_date:desc">Recently added to KEV</option></select>
      </div>
      {data?.tech_coverage && <Note tone={data.tech_coverage.note ? 'warn' : 'info'}>{data.tech_coverage.name}: {data.tech_coverage.coverage_label} · {data.tech_coverage.recent_cves} recent + {data.tech_coverage.historical_cves} historical CVE(s). {data.tech_coverage.note ?? ''}</Note>}
      {data && <div className="text-xs text-mute">{data.total} CVE{data.total === 1 ? '' : 's'} in the local catalogue match</div>}
      <Status loading={loading && !data} error={error} onRetry={reload} empty={!!data && data.items.length === 0} emptyText="No CVE in the local catalogue matches these filters." />
      {data && data.items.length === 0 && looksCve && (
        <div className={`${card} flex flex-wrap items-center gap-3 p-4 text-sm`}><span className="text-mute">{f.q.toUpperCase()} is not cached locally.</span>
          <button onClick={() => setOpen(f.q.trim().toUpperCase())} className="rounded-lg border border-accent/40 bg-accent/15 px-3 py-1.5 text-xs text-accent">Open card / look up in NVD</button></div>
      )}
      <div className="space-y-2.5">
        {data?.items.map((r) => (
          <button key={r.id} onClick={() => setOpen(r.id)} className={`${card} block w-full p-4 text-left transition-colors hover:border-accent/40`}>
            <div className="flex flex-wrap items-center gap-2"><Bug size={14} className="text-accent" /><span className="text-sm font-semibold text-ink">{r.id}</span><Sev r={r} /><Signals r={r} />
              <span className="ml-auto text-[11px] text-mute">{day(r.published)}{r.news_count ? ` · ${r.news_count} news` : ''}</span></div>
            <p className="mt-1.5 line-clamp-2 text-[13px] text-mute">{r.description ?? 'No description in the local catalogue.'}</p>
            {r.products.length > 0 && <div className="mt-1.5 text-[11px] text-mute">{r.products.join(' · ')}</div>}
          </button>
        ))}
      </div>
      {data && <Pager page={data.page} pages={data.pages} onPage={setPage} />}
    </div>
  )
}
