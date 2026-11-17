import { useEffect, useState } from 'react'
import { addProduct, fetchCategories, productDetail, productSearch, productStatus, productVersions, type NvdProduct, type ProductDetail } from '../data/products'
import { btn, btn2, Field, inp, Modal } from './company/common'
import { Chip, Note, Status, card, fmt, sel, useAsync } from './intel/ui'

const PART: Record<string, string> = { '': 'All types', a: 'Applications', o: 'Operating systems', h: 'Hardware' }

function CoverageNote({ s }: { s: { label: string; limitations: string[] } }) {
  if (!s.limitations.length) return <div className="text-[11px] text-emerald-300">{s.label}</div>
  return <Note tone="warn"><b>{s.label}.</b> {s.limitations.join(' ')}</Note>
}

function Detail({ p, categories, onDone, onClose }: { p: NvdProduct; categories: { id: string; name: string }[]; onDone: (r: { id: string; created: boolean }) => void; onClose: () => void }) {
  const ident = { part: p.part, vendor: p.vendor, product: p.product }
  const d = useAsync(() => productDetail(ident), [p.part, p.vendor, p.product])
  const [vq, setVq] = useState('')
  const vers = useAsync(() => productVersions({ ...ident, q: vq }), [p.part, p.vendor, p.product, vq])
  const [category, setCategory] = useState('')
  const [name, setName] = useState('')
  const [family, setFamily] = useState<string[]>([])
  const [err, setErr] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const x: ProductDetail | null = d.data
  const ex = x?.already_in_catalog ?? p.already_in_catalog
  const submit = () => {
    setBusy(true); setErr(null)
    addProduct({ ...ident, category, name: name.trim() || undefined, family: family.map((f) => ({ part: p.part, vendor: p.vendor, product: f })) })
      .then((r) => onDone({ id: r.technology.id, created: r.created })).catch((e) => setErr(String(e.message))).finally(() => setBusy(false))
  }
  return (
    <div className={`${card} space-y-3 p-4`}>
      <div className="flex items-start justify-between gap-2">
        <div className="min-w-0"><div className="truncate text-sm font-semibold text-ink">{p.name}</div><div className="text-[11px] text-mute">{p.vendor} / {p.product} · {p.type}</div></div>
        <button onClick={onClose} className="text-xs text-mute hover:text-ink" aria-label="Close product">×</button>
      </div>
      <Status loading={d.loading && !x} error={d.error} onRetry={d.reload} />
      {x && <>
        <div className="flex flex-wrap gap-1.5">{x.deprecated ? <Chip tone="red">Deprecated</Chip> : <Chip tone="accent">Current</Chip>}<Chip>{x.version_count} versions</Chip><Chip>{x.cpe_identifier_count} CPE records</Chip>{x.variant_count > 0 && <Chip>{x.variant_count} variants</Chip>}
          <Chip tone={x.cve_count_reliable ? 'mute' : 'orange'}>{x.cve_count === null ? 'CVE count unavailable' : `${x.cve_count} CVE`}</Chip>{x.kev_count ? <Chip tone="red">{x.kev_count} KEV</Chip> : null}</div>
        <CoverageNote s={x.coverage} />
        {x.deprecated_by.length > 0 && <Note tone="warn">Deprecated by NVD in favour of: {x.deprecated_by.join(', ')}</Note>}
        <div><div className="mb-1 text-[11px] uppercase tracking-wider text-mute">CPE identifiers (examples)</div><ul className="space-y-0.5 text-[11px] text-ink">{x.cpe_identifiers.slice(0, 4).map((c) => <li key={c} className="break-all font-mono">{c}</li>)}</ul></div>
        <div>
          <div className="mb-1 flex items-center justify-between"><span className="text-[11px] uppercase tracking-wider text-mute">Available versions</span><input value={vq} onChange={(e) => setVq(e.target.value)} placeholder="filter…" maxLength={20} className="w-24 rounded border border-line bg-bg px-2 py-0.5 text-[11px] text-ink" /></div>
          <div className="flex max-h-24 flex-wrap gap-1 overflow-y-auto">{(vers.data?.items ?? []).slice(0, 80).map((v) => <span key={v.version} className="rounded border border-line px-1.5 py-0.5 text-[11px] text-mute">{v.version}</span>)}{vers.data && vers.data.total > 80 && <span className="text-[11px] text-mute">+{vers.data.total - 80} more</span>}</div>
          <div className="mt-1 text-[10px] text-mute">Versions identify the product. Whether a CVE applies to a version is decided from the CVE's own NVD configuration.</div>
        </div>
        {x.variants.length > 0 && <div><div className="mb-1 text-[11px] uppercase tracking-wider text-mute">Variants (never merged automatically)</div><ul className="space-y-0.5 text-[11px] text-mute">{x.variants.slice(0, 6).map((v, i) => <li key={i}>{[v.edition && `edition ${v.edition}`, v.sw_edition && `sw ${v.sw_edition}`, v.target_sw && `target ${v.target_sw}`, v.target_hw && `hw ${v.target_hw}`, v.other].filter(Boolean).join(' · ')} <span className="text-mute/60">({v.records})</span></li>)}</ul></div>}
        {x.references.length > 0 && <div className="text-[11px] text-mute">Official references: {x.references.slice(0, 3).map((r) => <a key={r.url} href={r.url} target="_blank" rel="noopener noreferrer" className="mr-2 text-accent hover:underline">{r.url.replace(/^https?:\/\//, '').slice(0, 40)}</a>)}</div>}
        <div className="text-[10px] text-mute">NVD CPE data: {fmt(x.coverage.dataset_dates.cpe ?? null)}</div>
      </>}
      <div className="border-t border-line pt-3">
        {ex ? (
          <div className="space-y-2"><Note><b>Already in Technology Catalog:</b> {ex.name} ({ex.category}). Use the existing technology instead of creating another one.</Note>
            <button onClick={() => onDone({ id: ex.id, created: false })} className={btn}>Use existing technology</button></div>
        ) : (
          <div className="space-y-2">
            <Field label="Category (required — you decide, nothing is assigned automatically)"><select value={category} onChange={(e) => setCategory(e.target.value)} className={inp}><option value="">Select a category…</option>{categories.map((c) => <option key={c.id} value={c.id}>{c.name}</option>)}</select></Field>
            <Field label="Display name (optional)"><input value={name} onChange={(e) => setName(e.target.value)} maxLength={100} placeholder={p.name} className={inp} /></Field>
            {x && x.related_products.length > 0 && <div className="text-xs text-mute"><div className="mb-1">Same product family? Tick only products that are really part of it (explicit, never automatic):</div>
              {x.related_products.map((r) => <label key={r.product} className="mr-3 inline-flex items-center gap-1"><input type="checkbox" checked={family.includes(r.product)} onChange={() => setFamily((f) => f.includes(r.product) ? f.filter((y) => y !== r.product) : [...f, r.product])} />{r.display_name ?? r.product}</label>)}</div>}
            {err && <Note tone="warn">{err}</Note>}
            <button disabled={!category || busy} onClick={submit} className={btn}>{busy ? 'Adding…' : 'Add to Technology Catalog'}</button>
          </div>
        )}
      </div>
    </div>
  )
}

/** Search the official NVD products (local CPE dictionary) and add one to the catalogue, or reuse the one already there. */
export default function NvdProductExplorer({ onClose, onDone }: { onClose: () => void; onDone: (r: { id: string; created: boolean }) => void }) {
  const [f, setF] = useState({ q: '', vendor: '', part: '', deprecated: 'hide', page: 1 })
  const [dq, setDq] = useState('')
  const [sel1, setSel1] = useState<NvdProduct | null>(null)
  useEffect(() => { const t = setTimeout(() => setDq(f.q), 250); return () => clearTimeout(t) }, [f.q])
  const st = useAsync(productStatus, [])
  const cats = useAsync(fetchCategories, [])
  const list = useAsync(() => productSearch({ q: dq, vendor: f.vendor, part: f.part, deprecated: f.deprecated, page: f.page, page_size: 12 }), [dq, f.vendor, f.part, f.deprecated, f.page])
  const d = list.data
  return (
    <Modal title="Add Technology from NVD" onClose={onClose} size="xl">
      <div className="-mx-1 max-h-[78vh] space-y-3 overflow-y-auto px-1" style={{ minWidth: 'min(860px, 80vw)' }}>
        <p className="text-xs text-mute">Search the official NVD product dictionary stored locally. A product becomes a monitored technology only when you add it and choose its category.</p>
        {st.data && st.data.state !== 'complete' && <CoverageNote s={st.data} />}
        <div className="flex flex-wrap gap-2">
          <input value={f.q} onChange={(e) => setF((s) => ({ ...s, q: e.target.value, page: 1 }))} placeholder="Product or vendor (e.g. log4j, fortinet fortios)…" maxLength={80} autoFocus className={`${sel} min-w-[240px] flex-1`} aria-label="Search products" />
          <input value={f.vendor} onChange={(e) => setF((s) => ({ ...s, vendor: e.target.value.toLowerCase(), page: 1 }))} placeholder="Vendor id (optional)" maxLength={60} className={`${sel} w-40`} aria-label="Vendor" />
          <select value={f.part} onChange={(e) => setF((s) => ({ ...s, part: e.target.value, page: 1 }))} className={sel} aria-label="CPE type">{Object.entries(PART).map(([k, v]) => <option key={k} value={k}>{v}</option>)}</select>
          <select value={f.deprecated} onChange={(e) => setF((s) => ({ ...s, deprecated: e.target.value, page: 1 }))} className={sel} aria-label="Deprecated"><option value="hide">Current only</option><option value="show">Include deprecated</option><option value="only">Deprecated only</option></select>
        </div>
        <div className="grid gap-3 md:grid-cols-2">
          <div className="min-w-0">
            <Status loading={list.loading && !d} error={list.error} onRetry={list.reload} empty={!!d && d.items.length === 0} emptyText={st.data && !st.data.dictionary_ready ? 'The NVD CPE dictionary is not imported yet (Settings → Local Intelligence Database).' : 'No official product matches.'} />
            {d && d.items.length > 0 && <>
              <ul className={`${card} divide-y divide-line/60`}>{d.items.map((p) => (
                <li key={`${p.part}:${p.vendor}:${p.product}`}><button onClick={() => setSel1(p)} className={`flex w-full items-center gap-2 px-3 py-2 text-left hover:bg-bg/40 ${sel1 && sel1.vendor === p.vendor && sel1.product === p.product && sel1.part === p.part ? 'bg-accent/5' : ''}`}>
                  <span className="min-w-0 flex-1"><span className="block truncate text-sm text-ink">{p.name}</span><span className="block truncate text-[11px] text-mute">{p.vendor} / {p.product} · {p.type} · {p.version_count} versions</span></span>
                  {p.deprecated && <Chip tone="red">deprecated</Chip>}{p.already_in_catalog && <Chip tone="accent">in catalog</Chip>}
                  <span className="text-[11px] tabular-nums text-mute">{p.cve_count === null ? '—' : `${p.cve_count} CVE`}</span></button></li>))}</ul>
              <div className="mt-2 flex items-center justify-between text-xs text-mute"><span>{d.total} products</span><span className="flex items-center gap-2"><button disabled={f.page <= 1} onClick={() => setF((s) => ({ ...s, page: s.page - 1 }))} className="rounded border border-line px-2 py-1 disabled:opacity-40">Prev</button>{f.page} / {d.pages}<button disabled={f.page >= d.pages} onClick={() => setF((s) => ({ ...s, page: s.page + 1 }))} className="rounded border border-line px-2 py-1 disabled:opacity-40">Next</button></span></div>
            </>}
          </div>
          <div className="min-w-0">{sel1 ? <Detail key={`${sel1.part}:${sel1.vendor}:${sel1.product}`} p={sel1} categories={(cats.data?.items ?? []).filter((c) => c.active)} onDone={onDone} onClose={() => setSel1(null)} /> : <div className="rounded-lg border border-dashed border-line p-6 text-center text-xs text-mute">Select a product to see its versions, variants, identifiers and coverage.</div>}</div>
        </div>
        <div className="flex justify-end"><button onClick={onClose} className={btn2}>Close</button></div>
      </div>
    </Modal>
  )
}
