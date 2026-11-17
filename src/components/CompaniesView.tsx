import { useState } from 'react'
import { ArrowLeft, Building2, GitCompare, Plus } from 'lucide-react'
import { cArchive, cCompare, cCreate, cGet, cList, cUpdate, type Company } from '../data/company'
import { HBars } from './analytics/charts'
import CompanyAnalytics from './company/Analytics'
import { btn, btn2, Field, inp, Modal, type CNav } from './company/common'
import Inventory from './company/Inventory'
import Overview from './company/Overview'
import Reports from './company/Reports'
import { FeedTab, VulnsTab } from './company/Vulns'
import { Chip, Note, Status, Tabs, card, fmt, sel, useAsync } from './intel/ui'
import { BarChart3, FileText, Layers, ListChecks, Newspaper, ShieldAlert } from 'lucide-react'

type Tab = 'overview' | 'inventory' | 'vulns' | 'feed' | 'analytics' | 'reports'
const TABS: { id: Tab; label: string; icon: typeof Layers }[] = [
  { id: 'overview', label: 'Overview', icon: Layers }, { id: 'inventory', label: 'Technology Inventory', icon: ListChecks }, { id: 'vulns', label: 'Vulnerabilities', icon: ShieldAlert },
  { id: 'feed', label: 'Intelligence Feed', icon: Newspaper }, { id: 'analytics', label: 'Analytics', icon: BarChart3 }, { id: 'reports', label: 'Reports', icon: FileText },
]

function CompanyForm({ initial, onSaved, onClose }: { initial?: Company; onSaved: (c: Company) => void; onClose: () => void }) {
  const [f, setF] = useState({ name: initial?.name ?? '', trade_name: initial?.trade_name ?? '', industry: initial?.industry ?? '', country: initial?.country ?? '', description: initial?.description ?? '' })
  const [err, setErr] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const set = (k: string) => (e: { target: { value: string } }) => setF((s) => ({ ...s, [k]: e.target.value }))
  const save = () => {
    setBusy(true); setErr(null)
    const body = { ...f, trade_name: f.trade_name || null, country: f.country || null, description: f.description || null }
    ;(initial ? cUpdate(initial.id, body) : cCreate(body)).then(onSaved).catch((e) => setErr(String(e.message))).finally(() => setBusy(false))
  }
  return (
    <Modal title={initial ? 'Edit company' : 'New company'} onClose={onClose}>
      <div className="grid grid-cols-2 gap-3">
        <div className="col-span-2"><Field label="Name *"><input value={f.name} onChange={set('name')} className={inp} maxLength={120} autoFocus /></Field></div>
        <Field label="Trade name"><input value={f.trade_name} onChange={set('trade_name')} className={inp} maxLength={120} /></Field>
        <Field label="Industry *"><input value={f.industry} onChange={set('industry')} className={inp} maxLength={80} /></Field>
        <Field label="Country"><input value={f.country} onChange={set('country')} className={inp} maxLength={80} /></Field>
        <div className="col-span-2"><Field label="Description"><textarea value={f.description} onChange={set('description')} className={inp} rows={3} maxLength={1000} /></Field></div>
      </div>
      {err && <div className="mt-3"><Note tone="warn">{err}</Note></div>}
      <div className="mt-4 flex justify-end gap-2"><button onClick={onClose} className={btn2}>Cancel</button><button disabled={busy || !f.name.trim() || !f.industry.trim()} onClick={save} className={btn}>Save</button></div>
    </Modal>
  )
}

function CompareView({ ids, onBack }: { ids: string[]; onBack: () => void }) {
  const { data, loading, error, reload } = useAsync(() => cCompare(ids), [ids.join(',')])
  const rows: [string, (c: NonNullable<typeof data>['companies'][number]) => number | null, string?][] = [
    ['Monitored technologies', (c) => c.technologies], ['Registered assets', (c) => c.assets], ['Related CVEs (unique)', (c) => c.related_cves], ['CVEs in KEV', (c) => c.kev], ['Potentially applicable CVEs', (c) => c.potential],
    ['Confirmed applicable CVEs', (c) => c.confirmed], ['Related news events (30 d)', (c) => c.events_30d], ['Official advisories (30 d)', (c) => c.advisories_30d], ['Inventory coverage', (c) => c.inventory_coverage, '%'],
    ['Assets with version known', (c) => c.with_version_pct, '%'], ['Median verification age', (c) => c.median_verification_age_days, ' d'], ['Oldest verification', (c) => c.oldest_verification_days, ' d'],
    ['CVEs per technology', (c) => c.normalised.cves_per_technology], ['Potential per 100 assets', (c) => c.normalised.potential_per_100_assets], ['KEV share of related CVEs', (c) => c.normalised.kev_share_pct, '%'],
  ]
  return (
    <div className="space-y-4 p-6">
      <button onClick={onBack} className="flex items-center gap-1.5 text-xs text-accent"><ArrowLeft size={13} /> Companies</button>
      <h2 className="text-base font-semibold text-ink">Company Comparison</h2>
      <Status loading={loading && !data} error={error} onRetry={reload} />
      {data && (
        <>
          <Note tone="warn">{data.notes.join(' ')}</Note>
          <div className={`${card} overflow-x-auto`}>
            <table className="w-full min-w-[640px] text-sm"><thead className="border-b border-line text-left text-xs uppercase tracking-wider text-mute"><tr><th className="px-4 py-3">Metric</th>{data.companies.map((c) => <th key={c.id} className="px-4 py-3 text-ink">{c.name}{c.status === 'archived' ? ' (archived)' : ''}</th>)}</tr></thead>
              <tbody>{rows.map(([l, get, u]) => <tr key={l} className="border-b border-line/60 last:border-0"><td className="px-4 py-2 text-mute">{l}</td>{data.companies.map((c) => { const v = get(c); return <td key={c.id} className="px-4 py-2 tabular-nums text-ink">{v === null ? 'N/A' : `${v}${u ?? ''}`}</td> })}</tr>)}</tbody></table>
          </div>
          <div className="grid gap-4 md:grid-cols-2">
            {rows.slice(0, 9).filter((_, i) => [1, 2, 3, 4, 8].includes(i)).map(([l, get, u]) => (
              <div key={l} className={`${card} p-4`}><div className="mb-2 text-xs font-semibold text-ink">{l}</div><HBars unit={u} items={data.companies.map((c) => ({ label: c.name, value: get(c) }))} /></div>))}
          </div>
        </>
      )}
    </div>
  )
}

export default function CompaniesView({ nav, initialCompany }: { nav: CNav; initialCompany?: string | null }) {
  const [openId, setOpenId] = useState<string | null>(initialCompany ?? null)
  const [tab, setTab] = useState<Tab>('overview')
  const [form, setForm] = useState<{ edit?: Company } | null>(null)
  const [q, setQ] = useState('')
  const [status, setStatus] = useState('active')
  const [industry, setIndustry] = useState('')
  const [page, setPage] = useState(1)
  const [picked, setPicked] = useState<string[]>([])
  const [comparing, setComparing] = useState(false)
  const [cve, setCve] = useState<string | null>(null)
  const list = useAsync(() => cList({ q: q.trim() || undefined, status, industry: industry || undefined, page }), [q, status, industry, page])
  const co = useAsync(() => (openId ? cGet(openId) : Promise.resolve(null)), [openId])
  const openCompany = (id: string) => { setOpenId(id); setTab('overview'); setCve(null) }
  const company = co.data

  if (comparing && picked.length >= 2) return <CompareView ids={picked} onBack={() => setComparing(false)} />

  if (openId) {
    return (
      <div>
        <div className="border-b border-line px-6 py-4">
          <button onClick={() => { setOpenId(null); list.reload() }} className="mb-2 flex items-center gap-1.5 text-xs text-accent"><ArrowLeft size={13} /> Companies</button>
          <Status loading={co.loading && !company} error={co.error} onRetry={co.reload} />
          {company && (
            <div className="flex flex-wrap items-start gap-3">
              <div className="min-w-0 flex-1"><h2 className="text-base font-semibold text-ink">Company Threat Intelligence — {company.name}</h2><p className="text-xs text-mute">Technology threat monitoring and potential exposure assessment</p>
                <div className="mt-1.5 flex flex-wrap gap-1.5"><Chip>{company.industry}</Chip>{company.country && <Chip>{company.country}</Chip>}{company.status === 'archived' && <Chip tone="orange">archived</Chip>}<Chip title="Registered active assets / monitored technologies">{company.assets} assets · {company.technologies} technologies</Chip></div></div>
              <div className="flex gap-2"><button onClick={() => setForm({ edit: company })} className={btn2}>Edit</button><button onClick={() => cArchive(company.id, company.status === 'active').then(co.reload)} className={btn2}>{company.status === 'active' ? 'Archive' : 'Restore'}</button></div>
            </div>)}
        </div>
        {company && (
          <>
            <Tabs tabs={TABS} value={tab} onChange={setTab} />
            {tab === 'overview' && <Overview id={company.id} nav={nav} goInventory={() => setTab('inventory')} goVuln={(c) => { setCve(c); setTab('vulns') }} key={`${company.id}${company.assets}`} />}
            {tab === 'inventory' && <Inventory company={company} onChanged={co.reload} />}
            {tab === 'vulns' && <VulnsTab company={company} nav={nav} initialCve={cve} />}
            {tab === 'feed' && <FeedTab company={company} />}
            {tab === 'analytics' && <CompanyAnalytics id={company.id} />}
            {tab === 'reports' && <Reports company={company} />}
          </>
        )}
        {form && <CompanyForm initial={form.edit} onClose={() => setForm(null)} onSaved={() => { setForm(null); co.reload() }} />}
      </div>
    )
  }

  const d = list.data
  return (
    <div className="space-y-4 p-6">
      <div className="flex flex-wrap items-center gap-3">
        <input value={q} onChange={(e) => { setQ(e.target.value); setPage(1) }} placeholder="Search companies…" maxLength={80} className={`${sel} min-w-[220px]`} />
        <select value={status} onChange={(e) => { setStatus(e.target.value); setPage(1) }} className={sel} aria-label="Status"><option value="active">Active</option><option value="archived">Archived</option><option value="all">All</option></select>
        <select value={industry} onChange={(e) => { setIndustry(e.target.value); setPage(1) }} className={sel} aria-label="Industry"><option value="">All industries</option>{(d?.industries ?? []).map((i) => <option key={i}>{i}</option>)}</select>
        <div className="ml-auto flex gap-2"><button disabled={picked.length < 2} onClick={() => setComparing(true)} className={btn2} title="Select 2 to 5 companies"><GitCompare size={12} className="mr-1 inline" />Compare ({picked.length})</button><button onClick={() => setForm({})} className={btn}><Plus size={12} className="mr-1 inline" />New company</button></div>
      </div>
      <Status loading={list.loading && !d} error={list.error} onRetry={list.reload} />
      {d && d.total === 0 && (
        <div className="rounded-xl border border-dashed border-line py-20 text-center"><Building2 size={28} className="mx-auto mb-3 text-mute" /><div className="text-sm text-ink">{q || industry || status !== 'active' ? 'No companies match these filters' : 'No companies yet'}</div>
          <p className="mx-auto mt-1 max-w-md text-xs text-mute">Create an organisation profile, register the technologies it uses and get a personalised threat monitoring dashboard.</p>{!q && !industry && status === 'active' && <button onClick={() => setForm({})} className={`${btn} mt-4`}>Create the first company</button>}</div>
      )}
      {d && d.items.length > 0 && (
        <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
          {d.items.map((c) => (
            <div key={c.id} className={`${card} p-4 transition-colors hover:border-accent/40`}>
              <div className="flex items-start gap-2"><label className="mt-1 flex items-center" title="Select for comparison (2-5)"><input type="checkbox" checked={picked.includes(c.id)} disabled={!picked.includes(c.id) && picked.length >= 5} onChange={(e) => setPicked((p) => (e.target.checked ? [...p, c.id] : p.filter((x) => x !== c.id)))} /></label>
                <button onClick={() => openCompany(c.id)} className="min-w-0 flex-1 text-left"><div className="truncate text-sm font-semibold text-ink">{c.name}</div><div className="text-xs text-mute">{c.trade_name ? `${c.trade_name} · ` : ''}{c.industry}{c.country ? ` · ${c.country}` : ''}</div></button>
                {c.status === 'archived' && <Chip tone="orange">archived</Chip>}</div>
              <div className="mt-3 flex gap-4 text-xs text-mute"><span><b className="text-ink">{c.technologies}</b> technologies</span><span><b className="text-ink">{c.assets}</b> assets</span><span>verified {c.last_verified ? fmt(c.last_verified) : 'never'}</span></div>
            </div>))}
        </div>
      )}
      {d && d.pages > 1 && <div className="flex items-center justify-end gap-2 text-xs text-mute"><button disabled={page <= 1} onClick={() => setPage(page - 1)} className="rounded border border-line px-2 py-1 disabled:opacity-40">Prev</button>{page} / {d.pages}<button disabled={page >= d.pages} onClick={() => setPage(page + 1)} className="rounded border border-line px-2 py-1 disabled:opacity-40">Next</button></div>}
      <p className="text-[11px] text-mute">Local administrative tool: company data is protected only by the local-access / SYNC_TOKEN policy. Do not expose real client data on the Internet without authentication and per-organisation authorisation.</p>
      {form && <CompanyForm initial={form.edit} onClose={() => setForm(null)} onSaved={(c) => { setForm(null); list.reload(); openCompany(c.id) }} />}
    </div>
  )
}
