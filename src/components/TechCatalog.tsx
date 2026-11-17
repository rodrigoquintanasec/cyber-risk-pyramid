import { useEffect, useState } from 'react'
import { Plus } from 'lucide-react'
import { cpeSearch, type CpeCandidate } from '../data/intelDb'
import { COVERAGE_TONE, KIND_LABEL, SYNC_TONE, createTech, cveLabel, fetchTechSync, syncTech, fetchCatalog, fetchCatalogFacets, fetchCatalogItem, setTechEnabled, setTechMonitor, setTechPinned, updateTech, type CatalogItem } from '../data/catalog'
import { btn, btn2, Field, inp, Modal } from './company/common'
import NvdProductExplorer from './NvdProductExplorer'
import ManageCategories from './ManageCategories'
import { Chip, ExtLink, Note, Status, card, fmt, sel, useAsync } from './intel/ui'

export function CoverageBadge({ t }: { t: Pick<CatalogItem, 'coverage_state' | 'coverage_label'> }) {
  return <span className={`whitespace-nowrap rounded-full border px-2 py-0.5 text-[11px] ${COVERAGE_TONE[t.coverage_state]}`}>{t.coverage_label}</span>
}

function TechForm({ initial, categories, onClose, onSaved }: { initial?: CatalogItem; categories: string[]; onClose: () => void; onSaved: (id: string) => void }) {
  const [f, setF] = useState({ id: initial?.id ?? '', name: initial?.name ?? '', vendor: initial?.vendor ?? '', product: initial?.product ?? '', category: initial?.category ?? categories[0] ?? '', kind: initial?.kind ?? 'product',
    description: initial?.description ?? '', aliases: (initial?.aliases ?? []).join(', '), cpe_part: 'a', cpe_vendor: '', cpe_product: '', news_terms: '' })
  const [err, setErr] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const [cq, setCq] = useState('')
  const [cands, setCands] = useState<CpeCandidate[] | null>(null)
  useEffect(() => { if (cq.trim().length < 2) { setCands(null); return }
    const t = setTimeout(() => cpeSearch(cq.trim()).then((r) => setCands(r.items)).catch(() => setCands([])), 300)
    return () => clearTimeout(t) }, [cq])
  const set = (k: string) => (e: { target: { value: string } }) => setF((s) => ({ ...s, [k]: e.target.value }))
  const save = () => {
    setBusy(true); setErr(null)
    const split = (s: string) => s.split(',').map((x) => x.trim()).filter(Boolean)
    const body: Record<string, unknown> = { name: f.name, vendor: f.vendor, product: f.product, category: f.category, kind: f.kind, description: f.description, aliases: split(f.aliases) }
    if (f.cpe_vendor || f.cpe_product || !initial) Object.assign(body, { cpe_part: f.cpe_part, cpe_vendor: f.cpe_vendor, cpe_product: f.cpe_product })
    if (f.news_terms) body.news_terms = split(f.news_terms)
    ;(initial ? updateTech(initial.id, body) : createTech({ ...body, id: f.id })).then((r) => onSaved(r.id)).catch((e) => setErr(String(e.message))).finally(() => setBusy(false))
  }
  return (
    <Modal title={initial ? `Edit — ${initial.name}` : 'New custom technology'} onClose={onClose}>
      <div className="grid grid-cols-2 gap-3">
        {!initial && <Field label="ID *" hint="Stable, lowercase, dashes. Cannot change later."><input value={f.id} onChange={set('id')} className={inp} maxLength={49} /></Field>}
        <Field label="Name *"><input value={f.name} onChange={set('name')} className={inp} maxLength={100} /></Field>
        <Field label="Vendor"><input value={f.vendor} onChange={set('vendor')} className={inp} maxLength={80} /></Field>
        <Field label="Product"><input value={f.product} onChange={set('product')} className={inp} maxLength={80} /></Field>
        <Field label="Category"><select value={f.category} onChange={set('category')} className={inp}>{categories.map((c) => <option key={c}>{c}</option>)}</select></Field>
        <Field label="Type"><select value={f.kind} onChange={set('kind')} className={inp}>{Object.entries(KIND_LABEL).map(([k, v]) => <option key={k} value={k}>{v}</option>)}</select></Field>
        <div className="col-span-2"><Field label="Description"><input value={f.description} onChange={set('description')} className={inp} maxLength={300} /></Field></div>
        <div className="col-span-2"><Field label="Aliases (comma separated)"><input value={f.aliases} onChange={set('aliases')} className={inp} /></Field></div>
        <div className="col-span-2 rounded-lg border border-line p-3">
          <div className="mb-2 text-xs font-semibold text-ink">Official CPE identifier (optional)</div>
          <input value={cq} onChange={(e) => setCq(e.target.value)} placeholder="Search the local CPE data by product or vendor name…" className={`${inp} mb-2`} maxLength={60} />
          {cands && (cands.length === 0 ? <div className="mb-2 text-[11px] text-mute">No candidate found in the local data. Without a verified CPE the technology stays Catalog Only / Score Unavailable.</div> :
            <ul className="mb-2 max-h-40 divide-y divide-line/60 overflow-y-auto rounded-lg border border-line text-xs">{cands.map((c) => (
              <li key={`${c.vendor}:${c.product}`}><button type="button" disabled={!!c.already_in_catalog} onClick={() => setF((s) => ({ ...s, cpe_vendor: c.vendor, cpe_product: c.product, cpe_part: c.part ?? 'a' }))} className="flex w-full items-center gap-2 px-3 py-1.5 text-left hover:bg-bg/40 disabled:opacity-50">
                <span className="min-w-0 flex-1"><span className="text-ink">{c.vendor} / {c.product}</span>{c.title && <span className="block truncate text-[11px] text-mute">{c.title}</span>}</span><span className="text-mute">{c.cves} CVE{c.already_in_catalog ? ` · in catalog: ${c.already_in_catalog}` : ''}</span></button></li>))}</ul>)}
          {cands && cands.length > 0 && <div className="mb-2 text-[11px] text-amber-300">Suggestions only: pick the exact product yourself. Nothing is confirmed automatically.</div>}
          <div className="grid grid-cols-3 gap-2"><Field label="Part"><select value={f.cpe_part} onChange={set('cpe_part')} className={inp}><option value="a">a (application)</option><option value="o">o (OS)</option><option value="h">h (hardware)</option></select></Field>
            <Field label="Vendor id"><input value={f.cpe_vendor} onChange={set('cpe_vendor')} className={inp} placeholder="fortinet" /></Field><Field label="Product id"><input value={f.cpe_product} onChange={set('cpe_product')} className={inp} placeholder="fortios" /></Field></div>
          <p className="mt-2 text-[11px] text-mute">Enter an identifier only if it exists in the NVD CPE dictionary: it is used as an exact match and is not verified automatically. Without one, no CVE is linked through NVD and no Threat Signal Score is computed.</p>
        </div>
        <div className="col-span-2"><Field label="News terms (comma separated, optional)" hint="Explicit product names only (min 4 characters). Nothing is inferred from the name."><input value={f.news_terms} onChange={set('news_terms')} className={inp} /></Field></div>
      </div>
      {err && <div className="mt-3"><Note tone="warn">{err}</Note></div>}
      <div className="mt-4 flex justify-end gap-2"><button onClick={onClose} className={btn2}>Cancel</button><button disabled={busy || !f.name.trim() || (!initial && !f.id.trim())} onClick={save} className={btn}>Save</button></div>
    </Modal>
  )
}

function Drawer({ id, onClose, onChanged, categories, onEdit }: { id: string; onClose: () => void; onChanged: () => void; categories: string[]; onEdit: (t: CatalogItem) => void }) {
  const { data: d, loading, error, reload } = useAsync(() => fetchCatalogItem(id), [id])
  const [err, setErr] = useState<string | null>(null)
  void categories
  const act = (p: Promise<unknown>) => p.then(() => { setErr(null); reload(); onChanged() }).catch((e) => setErr(String(e.message)))
  const [msg, setMsg] = useState<string | null>(null)
  const running = d?.sync_status.status === 'in_progress' || d?.sync_status.status === 'pending' || msg === 'queued'
  useEffect(() => {   // persistent progress: poll while a job may be running; the server keeps the state, so reopening the panel shows the same
    if (!running) return
    const t = setInterval(() => { fetchTechSync(id).then((s) => { if (s.status !== 'in_progress' && s.status !== 'pending') { setMsg(null); onChanged() } reload() }).catch(() => undefined) }, 5000)
    return () => clearInterval(t)
  }, [running, id]) // eslint-disable-line react-hooks/exhaustive-deps
  const runSync = () => syncTech(id).then((r) => { setErr(null); setMsg(r.accepted ? 'queued' : r.message ?? null); reload(); onChanged() }).catch((e) => setErr(String(e.message)))
  return (
    <aside className="slide-in w-full shrink-0 overflow-y-auto rounded-xl border border-line bg-sidebar p-5 xl:w-[440px]">
      <div className="flex items-start justify-between"><div className="text-base font-semibold text-ink">{d?.name ?? id}</div><button onClick={onClose} className="text-xs text-mute hover:text-ink">Close</button></div>
      <Status loading={loading && !d} error={error} onRetry={reload} />
      {d && (
        <div className="mt-3 space-y-4 text-sm">
          <div className="flex flex-wrap gap-1.5"><CoverageBadge t={d} /><Chip>{d.category}</Chip><Chip>{KIND_LABEL[d.kind]}</Chip>{d.custom && <Chip tone="violet">custom</Chip>}{!d.enabled && <Chip tone="orange">disabled</Chip>}</div>
          <p className="text-xs text-mute">{d.description || 'No description.'}</p>
          <dl className="grid grid-cols-2 gap-x-3 gap-y-1.5 text-xs">
            <dt className="text-mute">Vendor / product</dt><dd className="text-ink">{d.vendor || '-'} / {d.product || '-'}</dd>
            <dt className="text-mute">Monitoring</dt><dd className="text-ink">{d.monitored ? `Monitored (${d.monitoring_reasons.join(', ')})` : 'Not monitored (catalogue only)'} · setting: {d.monitor}</dd>
            <dt className="text-mute">Last data sync</dt><dd className="text-ink">{d.last_sync ? fmt(d.last_sync) : 'never'}</dd>
            <dt className="text-mute">NVD queries synced</dt><dd className="text-ink">{d.nvd_queries}</dd>
            <dt className="text-mute">CVE coverage</dt><dd className="text-ink">{cveLabel(d)} related{d.cves_complete ? '' : ' (incomplete)'} · {d.kev_count} in CISA KEV</dd>
            <dt className="text-mute">Threat Signal</dt><dd className="text-ink">{d.score === null ? (d.score_possible ? 'Insufficient Data' : 'Score Unavailable (no CPE)') : `${Math.round(d.score)} · ${d.level.label}`}</dd>
            <dt className="text-mute">Correlation</dt><dd className="text-ink">{d.correlation.kind} · {d.correlation.source}</dd>
          </dl>
          <div className="rounded-lg border border-line p-3">
            <div className="mb-2 flex items-center justify-between"><div className="text-xs font-semibold text-ink">Vulnerability data sync</div><span className={`text-xs font-medium ${SYNC_TONE[d.sync_status.status]}`}>{d.sync_status.label}</span></div>
            {!d.sync_status.applicable ? <p className="text-[11px] text-mute">{d.sync_status.note}</p> : (
              <dl className="grid grid-cols-2 gap-x-3 gap-y-1 text-[11px]">
                <dt className="text-mute">Queries completed / required</dt><dd className="text-ink">{d.sync_status.queries_completed} / {d.sync_status.queries_required}</dd>
                <dt className="text-mute">CVEs retrieved / correlated</dt><dd className="text-ink">{d.sync_status.cves_retrieved} / {d.cve_count} ({d.recent_cve_count} recent · {d.historical_cve_count} historical)</dd>
                <dt className="text-mute">Last successful sync</dt><dd className="text-ink">{d.sync_status.last_success ? fmt(d.sync_status.last_success) : 'never'}</dd>
                <dt className="text-mute">Last attempt</dt><dd className="text-ink">{d.sync_status.last_attempt ? fmt(d.sync_status.last_attempt) : 'never'}</dd>
                <dt className="text-mute">Next eligible sync</dt><dd className="text-ink">{d.sync_status.next_eligible ? fmt(d.sync_status.next_eligible) : 'now'}</dd>
                <dt className="text-mute">Historical backfill</dt><dd className="text-ink">{d.sync_status.status === 'completed' ? 'Completed' : d.sync_status.label}{d.sync_status.history_limited ? ' (limited horizon)' : ''}</dd>
              </dl>)}
            {d.sync_status.last_error && <div className="mt-2 rounded border border-red-400/30 bg-red-400/10 p-2 text-[11px] text-red-300">Last error{d.sync_status.error_kind === 'rate_limit' ? ' (rate limited, backing off)' : ''}: {d.sync_status.last_error}</div>}
            {d.sync_status.note && <p className="mt-2 text-[11px] text-mute">{d.sync_status.note}</p>}
            {!d.cves_complete && d.sync_status.applicable && <p className="mt-2 text-[11px] text-amber-300">Collection incomplete: a count of 0 here does not mean the technology has no vulnerabilities.</p>}
            {d.sync_status.applicable && d.sync_jobs.length > 0 && <ul className="mt-2 space-y-0.5 font-mono text-[10px] text-mute">{d.sync_jobs.map((j) => <li key={j.query}>{j.query.replace('cpe:2.3:', '')} · {j.status} · {j.fetched}{j.total !== null ? `/${j.total}` : ''} CVEs</li>)}</ul>}
            <div className="mt-3 flex items-center gap-2"><button disabled={!d.sync_status.applicable || d.sync_status.status === 'completed' || running} onClick={runSync} className={btn}>{running ? 'Sync running…' : 'Sync Vulnerability Data'}</button>
              <span className="text-[10px] text-mute">Runs in the background within NVD rate limits; progress is saved and resumes after interruptions.</span></div>
            {msg && msg !== 'queued' && <div className="mt-2 text-[11px] text-mute">{msg}</div>}
          </div>
          {d.aliases.length > 0 && <div className="flex flex-wrap gap-1.5">{d.aliases.map((a) => <Chip key={a}>{a}</Chip>)}</div>}
          <div><div className="mb-1 text-[11px] uppercase tracking-wider text-mute">Identifiers</div>
            {d.identifiers.nvd_queries.length ? <ul className="space-y-0.5 font-mono text-[11px] text-mute">{d.identifiers.nvd_queries.map((x) => <li key={x}>{x}</li>)}</ul> : <div className="text-xs text-mute">No CPE identifiers.</div>}
            {d.identifiers.kev_matchers.length > 0 && <div className="mt-1 text-[11px] text-mute">CISA KEV names: {d.identifiers.kev_matchers.map((m) => `${m[0]} / ${m[1]}`).join('; ')}</div>}</div>
          <div><div className="mb-1 text-[11px] uppercase tracking-wider text-mute">Data limitations</div><ul className="list-disc space-y-1 pl-4 text-[11px] text-mute">{d.limitations.map((l) => <li key={l}>{l}</li>)}{d.insufficient_reason && <li>{d.insufficient_reason}</li>}</ul></div>
          {d.historical.count > 0 && <div><div className="mb-1 text-[11px] uppercase tracking-wider text-mute">Historical CVEs ({d.historical.count}{d.historical.kev ? ` · ${d.historical.kev} in KEV` : ''})</div><p className="mb-1 text-[11px] text-mute">{d.historical.note}</p>
            <ul className="space-y-1 text-xs">{d.historical.items.slice(0, 12).map((c) => <li key={c.cve_id} className="flex items-center gap-2"><span className="text-ink">{c.cve_id}</span>{c.kev_date && <Chip tone="red">KEV</Chip>}<Chip title={c.applicability === 'versioned' ? 'NVD lists explicit versions/ranges' : c.applicability === 'review' ? 'Conditional NVD configuration: needs review' : 'Product listed, no version data'}>{c.applicability}</Chip><span className="ml-auto text-mute">{c.published ? c.published.slice(0, 4) : ''} · CVSS {c.cvss ?? 'N/A'}</span></li>)}</ul></div>}
          {d.cves.length > 0 && <div><div className="mb-1 text-[11px] uppercase tracking-wider text-mute">Recent CVEs (scored window)</div><ul className="space-y-1 text-xs">{d.cves.slice(0, 10).map((c) => <li key={c.id} className="flex items-center gap-2"><span className="text-ink">{c.id}</span>{c.kev && <Chip tone="red">KEV</Chip>}<span className="ml-auto text-mute">CVSS {c.cvss ?? 'N/A'}</span></li>)}</ul></div>}
          {d.news.length > 0 && <div><div className="mb-1 text-[11px] uppercase tracking-wider text-mute">Related news</div><ul className="space-y-1 text-xs">{d.news.slice(0, 6).map((n) => <li key={n.id}><ExtLink href={n.url}>{n.title}</ExtLink> <span className="text-mute">· {n.source}</span></li>)}</ul></div>}
          <div className="rounded-lg border border-line p-3">
            <div className="mb-2 text-xs font-semibold text-ink">Administration</div>
            <div className="flex flex-wrap items-center gap-2 text-xs"><span className="text-mute">Monitoring</span>
              <select value={d.monitor} onChange={(e) => act(setTechMonitor(d.id, e.target.value))} className={`${sel} !py-1 text-xs`} aria-label="Monitoring mode"><option value="auto">auto (when used)</option><option value="on">always on</option><option value="off">off</option></select>
              <button onClick={() => act(setTechPinned(d.id, !d.dashboard))} className={btn2}>{d.dashboard ? 'Hide from dashboard' : 'Show on dashboard'}</button>
              {d.custom && <><button onClick={() => onEdit(d)} className={btn2}>Edit</button><button onClick={() => act(setTechEnabled(d.id, !d.enabled))} className={btn2}>{d.enabled ? 'Disable' : 'Enable'}</button></>}</div>
            {err && <div className="mt-2"><Note tone="warn">{err}</Note></div>}
          </div>
        </div>
      )}
    </aside>
  )
}

export default function TechCatalog() {
  const [f, setF] = useState({ q: '', category: '', vendor: '', kind: '', coverage: '', status: 'enabled', page: 1 })
  const [open, setOpen] = useState<string | null>(null)
  const [form, setForm] = useState<{ edit?: CatalogItem } | null>(null)
  const [nvd, setNvd] = useState(false)
  const [manage, setManage] = useState(false)
  const [toast, setToast] = useState<string | null>(null)
  const facets = useAsync(fetchCatalogFacets, [])
  const list = useAsync(() => fetchCatalog({ ...f, page_size: 20 }), [JSON.stringify(f)])
  const set = (k: string, v: string) => setF((s) => ({ ...s, [k]: v, page: 1 }))
  const fx = facets.data
  const d = list.data
  const refresh = () => { list.reload(); facets.reload() }
  return (
    <div className="space-y-4 p-6">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div><h2 className="text-base font-semibold text-ink">Technology Catalog</h2><p className="max-w-3xl text-xs text-mute">All known technologies. Only <b className="text-ink">monitored</b> ones (dashboard, watchlists, company inventories) receive NVD data; the rest are catalogue entries. The absence of CVEs is never evidence of the absence of vulnerabilities.</p></div>
        <div className="flex gap-2"><button onClick={() => setNvd(true)} className={btn}><Plus size={12} className="mr-1 inline" />Add Technology from NVD</button><button onClick={() => setManage(true)} className={btn2}>Manage Categories</button><button onClick={() => setForm({})} className={btn2}>New custom technology</button></div>
      </div>
      {fx && <div className="grid grid-cols-2 gap-3 md:grid-cols-5">{([['In catalogue', fx.enabled], ['Monitored', fx.coverage.monitored], ['Partial coverage', fx.coverage.partial], ['Catalog only', fx.coverage.catalog_only], ['Custom', fx.custom]] as [string, number][]).map(([l, v]) => <div key={l} className={`${card} px-4 py-3`}><div className="text-[11px] uppercase tracking-wider text-mute">{l}</div><div className="text-2xl font-semibold tabular-nums text-ink">{v}</div></div>)}</div>}
      <div className="flex flex-wrap gap-3">
        <input value={f.q} onChange={(e) => set('q', e.target.value)} placeholder="Search name, alias, vendor…" maxLength={80} className={`${sel} min-w-[240px]`} />
        <select value={f.category} onChange={(e) => set('category', e.target.value)} className={sel} aria-label="Category"><option value="">All categories</option>{(fx?.categories ?? []).map((c) => <option key={c.name} value={c.name}>{c.name} ({c.count})</option>)}</select>
        <select value={f.vendor} onChange={(e) => set('vendor', e.target.value)} className={`${sel} max-w-[200px]`} aria-label="Vendor"><option value="">All vendors</option>{(fx?.vendors ?? []).map((c) => <option key={c.name} value={c.name}>{c.name} ({c.count})</option>)}</select>
        <select value={f.coverage} onChange={(e) => set('coverage', e.target.value)} className={sel} aria-label="Coverage"><option value="">All coverage states</option><option value="monitored">Monitored</option><option value="partial">Partial Coverage</option><option value="catalog_only">Catalog Only</option></select>
        <select value={f.kind} onChange={(e) => set('kind', e.target.value)} className={sel} aria-label="Type"><option value="">All types</option>{Object.entries(KIND_LABEL).map(([k, v]) => <option key={k} value={k}>{v}</option>)}</select>
        <select value={f.status} onChange={(e) => set('status', e.target.value)} className={sel} aria-label="Status"><option value="enabled">Enabled</option><option value="disabled">Disabled</option><option value="all">All</option></select>
      </div>
      <Status loading={list.loading && !d} error={list.error} onRetry={list.reload} empty={!!d && d.items.length === 0} emptyText="No technology matches these filters." />
      <div className="flex flex-col gap-4 xl:flex-row">
        {d && d.items.length > 0 && (
          <div className={`${card} min-w-0 flex-1 overflow-x-auto`}>
            <table className="w-full min-w-[820px] text-sm"><thead className="border-b border-line text-left text-xs uppercase tracking-wider text-mute"><tr><th className="px-4 py-2.5">Technology</th><th className="px-4 py-2.5">Category</th><th className="px-4 py-2.5">Type</th><th className="px-4 py-2.5">Coverage</th><th className="px-4 py-2.5">Sync</th><th className="px-4 py-2.5 text-right">CVEs</th><th className="px-4 py-2.5 text-right">KEV</th><th className="px-4 py-2.5 text-right">News</th></tr></thead>
              <tbody>{d.items.map((t) => (
                <tr key={t.id} onClick={() => setOpen(t.id)} className={`cursor-pointer border-b border-line/60 last:border-0 hover:bg-bg/40 ${open === t.id ? 'bg-accent/5' : ''} ${t.enabled ? '' : 'opacity-60'}`}>
                  <td className="px-4 py-2"><div className="font-medium text-ink">{t.name}{t.custom && <span className="ml-1.5 text-[10px] text-violet-300">custom</span>}{t.dashboard && <span className="ml-1.5 text-[10px] text-accent">dashboard</span>}</div><div className="text-[11px] text-mute">{t.vendor}</div></td>
                  <td className="px-4 py-2 text-xs text-mute">{t.category}</td><td className="px-4 py-2 text-xs text-mute">{KIND_LABEL[t.kind]}</td><td className="px-4 py-2"><CoverageBadge t={t} /></td><td className={`px-4 py-2 text-xs ${SYNC_TONE[t.sync.status]}`}>{t.sync.applicable ? `${t.sync.label} (${t.sync.queries_completed}/${t.sync.queries_required})` : <span className="text-mute">n/a (no CPE)</span>}</td>
                  <td className="px-4 py-2 text-right tabular-nums text-mute" title={t.cves_complete ? '' : 'Vulnerability data is incomplete: this is not the absence of vulnerabilities'}>{cveLabel(t)}</td><td className="px-4 py-2 text-right tabular-nums text-mute">{t.kev_count}</td><td className="px-4 py-2 text-right tabular-nums text-mute">{t.news_count}</td></tr>))}</tbody></table>
            <div className="flex items-center justify-between border-t border-line px-4 py-2 text-xs text-mute"><span>{d.total} technolog{d.total === 1 ? 'y' : 'ies'}</span>
              <span className="flex items-center gap-2"><button disabled={f.page <= 1} onClick={() => setF((s) => ({ ...s, page: s.page - 1 }))} className="rounded border border-line px-2 py-1 disabled:opacity-40">Prev</button>{f.page} / {d.pages}<button disabled={f.page >= d.pages} onClick={() => setF((s) => ({ ...s, page: s.page + 1 }))} className="rounded border border-line px-2 py-1 disabled:opacity-40">Next</button></span></div>
          </div>
        )}
        {open && <Drawer key={open} id={open} onClose={() => setOpen(null)} onChanged={refresh} categories={(fx?.categories ?? []).filter((c) => c.active !== false).map((c) => c.name)} onEdit={(t) => setForm({ edit: t })} />}
      </div>
      {toast && <Note>{toast}</Note>}
      {nvd && <NvdProductExplorer onClose={() => setNvd(false)} onDone={(r) => { setNvd(false); refresh(); setOpen(r.id); setToast(r.created ? 'Technology added to the catalogue and correlated with the local vulnerability database.' : 'This product is already in the Technology Catalog: opened the existing technology.') }} />}
      {manage && <ManageCategories onClose={() => setManage(false)} onChanged={refresh} />}
      {form && <TechForm initial={form.edit} categories={(fx?.categories ?? []).filter((c) => c.active !== false || c.name === form.edit?.category).map((c) => c.name)} onClose={() => setForm(null)} onSaved={(id) => { setForm(null); refresh(); setOpen(id) }} />}
    </div>
  )
}

export function DashboardPicker({ onClose, onChanged }: { onClose: () => void; onChanged: () => void }) {
  const [f, setF] = useState({ q: '', category: '', page: 1 })
  const [err, setErr] = useState<string | null>(null)
  const facets = useAsync(fetchCatalogFacets, [])
  const list = useAsync(() => fetchCatalog({ ...f, page_size: 10 }), [JSON.stringify(f)])
  const toggle = (t: CatalogItem) => setTechPinned(t.id, !t.dashboard).then(() => { setErr(null); list.reload(); facets.reload(); onChanged() }).catch((e) => setErr(String(e.message)))
  const d = list.data
  return (
    <Modal title="Technologies shown on the global dashboard" onClose={onClose}>
      <p className="mb-3 text-xs text-mute">Pick which pyramids to render ({facets.data?.pinned ?? '…'} of at most {facets.data?.max_pinned ?? 24}). Showing a technology also starts monitoring it. Search the whole catalogue below.</p>
      <div className="mb-3 flex gap-2"><input value={f.q} onChange={(e) => setF((s) => ({ ...s, q: e.target.value, page: 1 }))} placeholder="Search…" maxLength={80} className={`${sel} flex-1`} />
        <select value={f.category} onChange={(e) => setF((s) => ({ ...s, category: e.target.value, page: 1 }))} className={sel} aria-label="Category"><option value="">All categories</option>{(facets.data?.categories ?? []).map((c) => <option key={c.name}>{c.name}</option>)}</select></div>
      {err && <div className="mb-2"><Note tone="warn">{err}</Note></div>}
      <Status loading={list.loading && !d} error={list.error} empty={!!d && d.items.length === 0} emptyText="No match." />
      <ul className="divide-y divide-line/60">{(d?.items ?? []).map((t) => (
        <li key={t.id} className="flex items-center gap-3 py-2"><input type="checkbox" checked={t.dashboard} onChange={() => toggle(t)} aria-label={`Show ${t.name}`} /><div className="min-w-0 flex-1"><div className="truncate text-sm text-ink">{t.name}</div><div className="text-[11px] text-mute">{t.category} · {t.vendor}</div></div><CoverageBadge t={t} /></li>))}</ul>
      {d && <div className="mt-2 flex items-center justify-between text-xs text-mute"><span>{d.total} technologies</span><span className="flex items-center gap-2"><button disabled={f.page <= 1} onClick={() => setF((s) => ({ ...s, page: s.page - 1 }))} className="rounded border border-line px-2 py-1 disabled:opacity-40">Prev</button>{f.page} / {d.pages}<button disabled={f.page >= d.pages} onClick={() => setF((s) => ({ ...s, page: s.page + 1 }))} className="rounded border border-line px-2 py-1 disabled:opacity-40">Next</button></span></div>}
    </Modal>
  )
}
