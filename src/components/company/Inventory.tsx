import { useState } from 'react'
import { fetchCatalog } from '../../data/catalog'
import { CoverageBadge } from '../TechCatalog'
import { cAddAsset, cInventory, cUpdateAsset, type Asset, type Company, type Inventory as Inv } from '../../data/company'
import { Chip, Note, Status, card, fmt, useAsync } from '../intel/ui'
import { btn, btn2, Field, inp, Modal, ver } from './common'
import NvdProductExplorer from '../NvdProductExplorer'
import { techVersions } from '../../data/products'

const EMPTY = { source: 'catalog', tech_id: '', vendor: '', product: '', label: '', asset_ref: '', mode: 'exact', version: '', version_min: '', version_max: '', environment: 'production', criticality: 'medium', internet_exposed: 'unknown', status: 'active', last_verified: '', notes: '' }

function AssetForm({ company, inv, edit, onDone, onClose }: { company: Company; inv: Inv; edit?: { asset: Asset; label: string }; onDone: () => void; onClose: () => void }) {
  const [tq, setTq] = useState('')
  const found = useAsync(() => (tq.trim().length >= 2 ? fetchCatalog({ q: tq.trim(), page_size: 8 }) : Promise.resolve(null)), [tq])
  const a = edit?.asset
  const [f, setF] = useState(a ? { ...EMPTY, asset_ref: a.asset_ref ?? '', mode: a.version_min || a.version_max ? 'range' : 'exact', version: a.version ?? '', version_min: a.version_min ?? '', version_max: a.version_max ?? '', environment: a.environment, criticality: a.criticality, internet_exposed: a.internet_exposed, status: a.status, last_verified: a.last_verified ?? '', notes: a.notes ?? '' } : EMPTY)
  const [err, setErr] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const [nvd, setNvd] = useState(false)
  const techId = a ? '' : f.source === 'catalog' ? f.tech_id : ''
  const vsug = useAsync(() => (techId ? techVersions(techId, f.version) : Promise.resolve(null)), [techId, f.version])
  const set = (k: string) => (e: { target: { value: string } }) => setF((s) => ({ ...s, [k]: e.target.value }))
  const submit = () => {
    setBusy(true); setErr(null)
    const body: Record<string, unknown> = { asset_ref: f.asset_ref || null, version: f.mode === 'exact' ? f.version || null : null, version_min: f.mode === 'range' ? f.version_min || null : null, version_max: f.mode === 'range' ? f.version_max || null : null,
      environment: f.environment, criticality: f.criticality, internet_exposed: f.internet_exposed, status: f.status, last_verified: f.last_verified || null, notes: f.notes || null }
    if (!a) Object.assign(body, f.source === 'catalog' ? { tech_id: f.tech_id } : { vendor: f.vendor, product: f.product, label: f.label || undefined })
    ;(a ? cUpdateAsset(company.id, a.id, body) : cAddAsset(company.id, body)).then(() => { onDone(); onClose() }).catch((e) => setErr(String(e.message))).finally(() => setBusy(false))
  }
  return (
    <Modal title={a ? `Edit asset — ${edit!.label}` : 'Add asset'} onClose={onClose}>
      <div className="grid grid-cols-2 gap-3">
        {!a && <div className="col-span-2 flex gap-2 text-xs">{[['catalog', 'Catalogue technology'], ['custom', 'Other product (vendor + product)']].map(([v, l]) => <button key={v} onClick={() => setF((s) => ({ ...s, source: v }))} className={`rounded-lg border px-3 py-1.5 ${f.source === v ? 'border-accent/50 bg-accent/10 text-accent' : 'border-line text-mute'}`}>{l}</button>)}</div>}
        {!a && f.source === 'catalog' && <div className="col-span-2"><Field label="Search the catalogue (name, alias, vendor)" hint={f.tech_id ? `Selected: ${f.tech_id}` : 'Type at least 2 characters.'}><input value={tq} onChange={(e) => setTq(e.target.value)} className={inp} placeholder="e.g. fortinet, jenkins, postgres" maxLength={60} /></Field>
          <div className="mt-1 text-[11px] text-mute">Not in the catalogue? <button type="button" onClick={() => setNvd(true)} className="text-accent hover:underline">Add a product from NVD</button> (you choose its category).</div>
          {found.data && <ul className="mt-2 max-h-52 divide-y divide-line/60 overflow-y-auto rounded-lg border border-line">{found.data.items.length === 0 && <li className="p-3 text-xs text-mute">No technology found. Use "Other product" to register an exact vendor/product.</li>}{found.data.items.map((t) => <li key={t.id}><button type="button" onClick={() => setF((s) => ({ ...s, tech_id: t.id }))} className={`flex w-full items-center gap-2 px-3 py-2 text-left text-xs ${f.tech_id === t.id ? 'bg-accent/10' : 'hover:bg-bg/40'}`}><span className="min-w-0 flex-1"><span className="text-ink">{t.name}</span><span className="block text-[11px] text-mute">{t.vendor} · {t.category}</span></span><CoverageBadge t={t} /></button></li>)}</ul>}</div>}
        {!a && f.source === 'custom' && <>
          <Field label="Vendor (CPE id)" hint="e.g. fortinet"><input value={f.vendor} onChange={set('vendor')} className={inp} maxLength={80} /></Field>
          <Field label="Product (CPE id)" hint="e.g. fortios"><input value={f.product} onChange={set('product')} className={inp} maxLength={80} /></Field>
          <div className="col-span-2 text-[11px] text-mute">Exact identifiers only: no fuzzy matching. Products outside the catalogue show "Threat Score Unavailable" and get no news linkage.</div></>}
        <Field label="Asset identifier"><input value={f.asset_ref} onChange={set('asset_ref')} className={inp} maxLength={80} placeholder="hostname / tag (optional)" /></Field>
        <Field label="Last verified"><input type="date" value={f.last_verified} max={new Date().toISOString().slice(0, 10)} onChange={set('last_verified')} className={inp} /></Field>
        <div className="col-span-2 flex gap-2 text-xs"><span className="py-1.5 text-mute">Version:</span>{[['exact', 'Exact'], ['range', 'Range']].map(([v, l]) => <button key={v} onClick={() => setF((s) => ({ ...s, mode: v }))} className={`rounded-lg border px-3 py-1 ${f.mode === v ? 'border-accent/50 bg-accent/10 text-accent' : 'border-line text-mute'}`}>{l}</button>)}</div>
        {f.mode === 'exact' ? <div className="col-span-2"><Field label="Exact version" hint="Leave empty if unknown: applicability will read 'Insufficient Data'."><input value={f.version} onChange={set('version')} className={inp} maxLength={40} placeholder="7.0.5" list="asset-versions" /><datalist id="asset-versions">{(vsug.data?.items ?? []).slice(0, 40).map((v) => <option key={v.version} value={v.version} />)}</datalist></Field></div>
          : <><Field label="From (inclusive)"><input value={f.version_min} onChange={set('version_min')} className={inp} maxLength={40} /></Field><Field label="To (inclusive)"><input value={f.version_max} onChange={set('version_max')} className={inp} maxLength={40} /></Field></>}
        <Field label="Environment"><select value={f.environment} onChange={set('environment')} className={inp}>{inv.options.environments.map((x) => <option key={x}>{x}</option>)}</select></Field>
        <Field label="Criticality"><select value={f.criticality} onChange={set('criticality')} className={inp}>{inv.options.criticalities.map((x) => <option key={x}>{x}</option>)}</select></Field>
        <Field label="Exposed to the Internet" hint="Never assumed; 'unknown' is a valid answer."><select value={f.internet_exposed} onChange={set('internet_exposed')} className={inp}>{inv.options.internet_exposed.map((x) => <option key={x}>{x}</option>)}</select></Field>
        <Field label="Status"><select value={f.status} onChange={set('status')} className={inp}><option>active</option><option>retired</option></select></Field>
        <div className="col-span-2"><Field label="Notes"><textarea value={f.notes} onChange={set('notes')} className={inp} rows={2} maxLength={500} /></Field></div>
      </div>
      {err && <div className="mt-3"><Note tone="warn">{err}</Note></div>}
      <div className="mt-4 flex justify-end gap-2"><button onClick={onClose} className={btn2}>Cancel</button><button disabled={busy} onClick={submit} className={btn}>{a ? 'Save' : 'Add asset'}</button></div>
      {nvd && <NvdProductExplorer onClose={() => setNvd(false)} onDone={(r) => { setNvd(false); setTq(''); setF((s) => ({ ...s, source: 'catalog', tech_id: r.id })) }} />}
    </Modal>
  )
}

export default function Inventory({ company, onChanged }: { company: Company; onChanged: () => void }) {
  const { data, loading, error, reload } = useAsync(() => cInventory(company.id), [company.id])
  const [form, setForm] = useState<{ edit?: { asset: Asset; label: string } } | null>(null)
  const archived = company.status === 'archived'
  const cov = data?.coverage
  const done = () => { reload(); onChanged() }
  return (
    <div className="space-y-4 p-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <p className="max-w-2xl text-xs text-mute">Manually maintained inventory. A <b className="text-ink">product</b> is a technology the company uses; an <b className="text-ink">asset</b> is one instance of it with its own version. Many assets can share a product.</p>
        <button disabled={archived} onClick={() => setForm({})} className={btn}>+ Add asset</button>
      </div>
      {archived && <Note tone="warn">This company is archived: restore it to change the inventory. History remains readable.</Note>}
      <Status loading={loading && !data} error={error} onRetry={reload} />
      {data && cov && (
        <>
          <div className="grid grid-cols-2 gap-3 md:grid-cols-5">
            {([['Active assets', cov.active_assets], ['Version known', cov.with_version_pct === null ? 'N/A' : `${cov.with_version_pct}%`], ['Internet exposure known', cov.exposure_known_pct === null ? 'N/A' : `${cov.exposure_known_pct}%`], ['Verified ≤ 90 days', cov.verified_90d_pct === null ? 'N/A' : `${cov.verified_90d_pct}%`], ['Inventory coverage', cov.inventory_coverage === null ? 'N/A' : `${cov.inventory_coverage}%`]] as [string, string | number][]).map(([l, v]) => (
              <div key={l} className={`${card} px-4 py-3`}><div className="text-[11px] uppercase tracking-wider text-mute">{l}</div><div className="text-xl font-semibold tabular-nums text-ink">{v}</div></div>))}
          </div>
          {data.technologies.length === 0 && <div className="rounded-xl border border-dashed border-line py-14 text-center text-sm text-mute">No products or assets registered yet.</div>}
          {data.technologies.map((t) => (
            <div key={t.id} className={`${card} overflow-x-auto`}>
              <div className="flex items-center gap-2 border-b border-line px-4 py-3"><span className="text-sm font-semibold text-ink">{t.label}</span>{t.catalog ? <><Chip tone="accent">catalogue</Chip>{t.catalog_info && <><Chip>{t.catalog_info.category}</Chip><CoverageBadge t={t.catalog_info} /></>}</> : <Chip title="Exact CPE vendor/product; no global score">{t.vendor} / {t.product}</Chip>}{(!t.catalog || (t.catalog_info && !t.catalog_info.score_possible)) && <Chip tone="orange">Threat Score Unavailable</Chip>}<span className="ml-auto text-xs text-mute">{t.active_assets} active asset(s)</span></div>
              <table className="w-full min-w-[760px] text-sm"><thead className="text-left text-xs uppercase tracking-wider text-mute"><tr><th className="px-4 py-2">Asset</th><th className="px-4 py-2">Version</th><th className="px-4 py-2">Env.</th><th className="px-4 py-2">Criticality</th><th className="px-4 py-2">Internet</th><th className="px-4 py-2">Status</th><th className="px-4 py-2">Verified</th><th /></tr></thead>
                <tbody>{t.assets.map((a) => (
                  <tr key={a.id} className={`border-t border-line/60 ${a.status === 'retired' ? 'opacity-60' : ''}`}><td className="px-4 py-2 text-ink">{a.asset_ref ?? `#${a.id}`}</td><td className="px-4 py-2">{ver(a) === 'unknown' ? <span className="text-amber-300">unknown</span> : ver(a)}</td><td className="px-4 py-2 text-mute">{a.environment}</td><td className="px-4 py-2 text-mute">{a.criticality}</td><td className="px-4 py-2 text-mute">{a.internet_exposed}</td><td className="px-4 py-2 text-mute">{a.status}</td><td className="px-4 py-2 text-xs text-mute">{a.last_verified ? fmt(a.last_verified) : 'never'}</td>
                    <td className="px-4 py-2 text-right"><button disabled={archived} onClick={() => setForm({ edit: { asset: a, label: t.label } })} className="text-xs text-accent hover:underline disabled:opacity-40">Edit</button></td></tr>))}</tbody></table>
            </div>))}
        </>
      )}
      {form && data && <AssetForm company={company} inv={data} edit={form.edit} onDone={done} onClose={() => setForm(null)} />}
    </div>
  )
}
