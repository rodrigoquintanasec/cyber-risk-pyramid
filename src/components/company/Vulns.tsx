import { useEffect, useState } from 'react'
import { cAssess, cFiche, cNews, cVulns, cInventory, STATUS_LABEL, type Company, type Fiche } from '../../data/company'
import { Chip, ExtLink, Note, Segmented, Status, card, fmt, sel, useAsync } from '../intel/ui'
import { btn, Field, inp, StatusBadge, ver, type CNav } from './common'

function FichePanel({ company, cve, onClose, onSaved, nav }: { company: Company; cve: string; onClose: () => void; onSaved: () => void; nav: CNav }) {
  const { data, loading, error, reload } = useAsync(() => cFiche(company.id, cve), [company.id, cve])
  const [ctid, setCtid] = useState<number | null>(null)
  const [status, setStatus] = useState('needs_review')
  const [evidence, setEvidence] = useState('')
  const [ref, setRef] = useState('')
  const [err, setErr] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const f: Fiche | null = data
  useEffect(() => { if (f && ctid === null) setCtid(f.products[0]?.company_tech_id ?? null) }, [f, ctid])
  const save = () => {
    if (ctid === null) return
    setBusy(true); setErr(null)
    cAssess(company.id, cve, { company_tech_id: ctid, status, evidence: evidence || undefined, reference_url: ref || undefined })
      .then(() => { setEvidence(''); setRef(''); reload(); onSaved() }).catch((e) => setErr(String(e.message))).finally(() => setBusy(false))
  }
  const archived = company.status === 'archived'
  return (
    <aside className="slide-in w-full shrink-0 overflow-y-auto rounded-xl border border-line bg-sidebar p-5 xl:w-[460px]">
      <div className="flex items-start justify-between"><div className="text-base font-semibold text-ink">{cve}</div><button onClick={onClose} className="text-xs text-mute hover:text-ink">Close</button></div>
      <Status loading={loading && !f} error={error} onRetry={reload} />
      {f && (
        <div className="mt-3 space-y-4 text-sm">
          <div className="flex flex-wrap gap-1.5"><StatusBadge s={f.effective_status} />{f.kev ? <Chip tone="red" title="Listed in CISA KEV: exploited somewhere, not necessarily here">CISA KEV · {f.kev.date_added}</Chip> : <Chip>Not in KEV</Chip>}</div>
          <p className="text-xs text-mute">{f.description ?? 'No description cached.'}</p>
          <dl className="grid grid-cols-3 gap-2 text-xs"><div><dt className="text-mute">CVSS</dt><dd className="text-ink">{f.cvss ?? 'N/A'}</dd></div><div><dt className="text-mute">EPSS</dt><dd className="text-ink">{f.epss === null ? 'N/A' : `${(f.epss * 100).toFixed(2)}%`}</dd></div><div><dt className="text-mute">Published</dt><dd className="text-ink">{f.published ? fmt(f.published) : 'N/A'}</dd></div></dl>
          {f.products.map((p) => (
            <div key={p.company_tech_id} className="rounded-lg border border-line p-3">
              <div className="flex items-center gap-2"><span className="font-medium text-ink">{p.label}</span><span className="ml-auto"><StatusBadge s={p.effective_status} /></span></div>
              <div className="mt-1 text-[11px] text-mute">Automatic: <StatusBadge s={p.automatic_status} auto />{!p.ranges_cached && ' · affected-version ranges not cached'}</div>
              <ul className="mt-2 space-y-1 text-xs">{p.assets.map((a) => <li key={a.asset_id}><div className="flex items-center gap-2 text-ink">{a.asset_ref ?? `#${a.asset_id}`}<span className="text-mute">v {a.version ?? 'unknown'}</span><span className="ml-auto"><StatusBadge s={a.status} auto /></span></div><div className="text-[11px] text-mute">{a.reason}</div></li>)}</ul>
              {p.assessment && <div className="mt-2 rounded border border-line/70 p-2 text-[11px] text-mute"><div>Analyst: <b className="text-ink">{STATUS_LABEL[p.assessment.status]}</b> · {fmt(p.assessment.assessed_at)}</div>{p.assessment.evidence && <div>Evidence: {p.assessment.evidence}</div>}{p.assessment.reference_url && <ExtLink href={p.assessment.reference_url}>Reference</ExtLink>}</div>}
            </div>))}
          {f.documented_versions.length > 0 && <div><div className="mb-1 text-[11px] uppercase tracking-wider text-mute">Documented affected versions</div><ul className="space-y-0.5 text-[11px] text-mute">{f.documented_versions.slice(0, 10).map((v, i) => <li key={i}>{v.product}: {v.version ?? ([v.from_incl && `≥ ${v.from_incl}`, v.from_excl && `> ${v.from_excl}`, v.to_incl && `≤ ${v.to_incl}`, v.to_excl && `< ${v.to_excl}`].filter(Boolean).join(' ') || 'all versions')}</li>)}</ul></div>}
          <div className="rounded-lg border border-accent/20 p-3">
            <div className="mb-2 text-xs font-semibold text-ink">Record an assessment</div>
            {archived ? <Note tone="warn">Archived company: restore it to record assessments.</Note> : (
              <div className="space-y-2">
                <Field label="Product"><select value={ctid ?? ''} onChange={(e) => setCtid(Number(e.target.value))} className={inp}>{f.products.map((p) => <option key={p.company_tech_id} value={p.company_tech_id}>{p.label}</option>)}</select></Field>
                <Field label="Applicability"><select value={status} onChange={(e) => setStatus(e.target.value)} className={inp}>{['confirmed_applicable', 'potentially_applicable', 'needs_review', 'not_applicable', 'insufficient_data'].map((s) => <option key={s} value={s}>{STATUS_LABEL[s]}</option>)}</select></Field>
                <Field label="Evidence note" hint={status === 'confirmed_applicable' ? 'Required (≥ 10 characters) or a reference URL.' : undefined}><textarea value={evidence} onChange={(e) => setEvidence(e.target.value)} rows={2} maxLength={1000} className={inp} /></Field>
                <Field label="Reference URL"><input value={ref} onChange={(e) => setRef(e.target.value)} className={inp} placeholder="https://…" maxLength={400} /></Field>
                {err && <Note tone="warn">{err}</Note>}
                <button disabled={busy || ctid === null} onClick={save} className={btn}>Save assessment</button>
                <p className="text-[10px] text-mute">Saved with the current date. Previous evidence is never deleted. Global vulnerability records are not modified.</p>
              </div>)}
          </div>
          {f.history.length > 0 && <div><div className="mb-1 text-[11px] uppercase tracking-wider text-mute">Assessment history</div><ul className="space-y-1.5 text-[11px] text-mute">{f.history.map((h) => <li key={h.id} className="rounded border border-line/60 p-2"><div>{fmt(h.changed_at)} · {h.old_status ? `${STATUS_LABEL[h.old_status]} → ` : ''}<b className="text-ink">{STATUS_LABEL[h.new_status]}</b></div>{h.evidence && <div>{h.evidence}</div>}{h.reference_url && <ExtLink href={h.reference_url}>Reference</ExtLink>}</li>)}</ul></div>}
          <div className="flex flex-wrap gap-3 text-xs"><button className="text-accent hover:underline" onClick={() => nav.explorer({ open: cve })}>Vulnerability Explorer</button><button className="text-accent hover:underline" onClick={() => nav.graph(`cve:${cve}`)}>Relationship Graph</button>{f.references.slice(0, 3).map((r) => <ExtLink key={r.url} href={r.url}>Reference</ExtLink>)}</div>
        </div>
      )}
    </aside>
  )
}

export function VulnsTab({ company, nav, initialCve }: { company: Company; nav: CNav; initialCve?: string | null }) {
  const [status, setStatus] = useState('')
  const [ctid, setCtid] = useState('')
  const [kev, setKev] = useState('')
  const [q, setQ] = useState('')
  const [page, setPage] = useState(1)
  const [open, setOpen] = useState<string | null>(initialCve ?? null)
  const inv = useAsync(() => cInventory(company.id), [company.id])
  const { data, loading, error, reload } = useAsync(() => cVulns(company.id, { status: status || undefined, technology: ctid ? Number(ctid) : undefined, kev: kev === '' ? undefined : kev === 'yes', q: q.trim() || undefined, page }), [company.id, status, ctid, kev, q, page])
  useEffect(() => setPage(1), [status, ctid, kev, q])
  useEffect(() => { if (initialCve) setOpen(initialCve) }, [initialCve])
  return (
    <div className="space-y-4 p-6">
      <p className="max-w-3xl text-xs text-mute">CVEs related to the company's products by structured identifiers (never by vendor name alone), listed once per CVE. <b className="text-ink">Potentially Applicable</b> means product and version may match; only an analyst can mark <b className="text-ink">Confirmed Applicable</b> with evidence.</p>
      {data && <div className="grid grid-cols-2 gap-3 md:grid-cols-6">{([['Related CVEs', data.counts.related], ['In KEV', data.counts.kev], ['Potentially applicable', data.counts.statuses.potentially_applicable], ['Confirmed', data.counts.statuses.confirmed_applicable], ['Needs review', data.counts.statuses.needs_review], ['Insufficient data', data.counts.statuses.insufficient_data]] as [string, number][]).map(([l, v]) => <div key={l} className={`${card} px-4 py-3`}><div className="text-[11px] uppercase tracking-wider text-mute">{l}</div><div className="text-xl font-semibold tabular-nums text-ink">{v}</div></div>)}</div>}
      <div className="flex flex-wrap gap-3">
        <input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Search CVE or text…" maxLength={60} className={`${sel} min-w-[200px]`} />
        <select value={status} onChange={(e) => setStatus(e.target.value)} className={sel} aria-label="Applicability"><option value="">All applicability states</option>{Object.entries(STATUS_LABEL).map(([k, v]) => <option key={k} value={k}>{v}</option>)}</select>
        <select value={ctid} onChange={(e) => setCtid(e.target.value)} className={sel} aria-label="Product"><option value="">All products</option>{(inv.data?.technologies ?? []).map((t) => <option key={t.id} value={t.id}>{t.label}</option>)}</select>
        <Segmented options={[['', 'All'], ['yes', 'KEV only'], ['no', 'Not KEV']]} value={kev} onChange={setKev} />
      </div>
      <Status loading={loading && !data} error={error} onRetry={reload} empty={!!data && data.items.length === 0} emptyText="No related CVEs for these filters. Missing data is not evidence of safety." />
      <div className="flex flex-col gap-4 xl:flex-row">
        {data && data.items.length > 0 && (
          <div className={`${card} min-w-0 flex-1 overflow-x-auto`}>
            <table className="w-full min-w-[720px] text-sm"><thead className="border-b border-line text-left text-xs uppercase tracking-wider text-mute"><tr><th className="px-4 py-2.5">CVE</th><th className="px-4 py-2.5">CVSS</th><th className="px-4 py-2.5">EPSS</th><th className="px-4 py-2.5">KEV</th><th className="px-4 py-2.5">Products</th><th className="px-4 py-2.5">Applicability</th></tr></thead>
              <tbody>{data.items.map((v) => (
                <tr key={v.id} onClick={() => setOpen(v.id)} className={`cursor-pointer border-b border-line/60 last:border-0 hover:bg-bg/40 ${open === v.id ? 'bg-accent/5' : ''}`}>
                  <td className="px-4 py-2 font-medium text-ink">{v.id}</td><td className="px-4 py-2 tabular-nums text-mute">{v.cvss ?? 'N/A'}</td><td className="px-4 py-2 tabular-nums text-mute">{v.epss === null ? 'N/A' : `${(v.epss * 100).toFixed(1)}%`}</td>
                  <td className="px-4 py-2">{v.kev ? <Chip tone="red">KEV</Chip> : <span className="text-xs text-mute">no</span>}</td><td className="px-4 py-2 text-xs text-mute">{v.products.map((p) => p.label).join(', ')}</td><td className="px-4 py-2"><StatusBadge s={v.effective_status} /></td></tr>))}</tbody></table>
            <div className="flex items-center justify-between border-t border-line px-4 py-2 text-xs text-mute"><span>{data.total} CVE(s)</span><span className="flex items-center gap-2"><button disabled={page <= 1} onClick={() => setPage(page - 1)} className="rounded border border-line px-2 py-1 disabled:opacity-40">Prev</button>{page} / {data.pages}<button disabled={page >= data.pages} onClick={() => setPage(page + 1)} className="rounded border border-line px-2 py-1 disabled:opacity-40">Next</button></span></div>
          </div>
        )}
        {open && <FichePanel key={open} company={company} cve={open} nav={nav} onClose={() => setOpen(null)} onSaved={reload} />}
      </div>
      {data && <Note>{data.note}</Note>}
    </div>
  )
}

export function FeedTab({ company }: { company: Company }) {
  const [official, setOfficial] = useState('all')
  const [page, setPage] = useState(1)
  const { data, loading, error, reload } = useAsync(() => cNews(company.id, official === 'all' ? undefined : official === 'official', page), [company.id, official, page])
  useEffect(() => setPage(1), [official])
  return (
    <div className="space-y-4 p-6">
      <div className="flex flex-wrap items-center gap-3"><Segmented options={[['all', 'All news'], ['official', 'Official advisories']]} value={official} onChange={setOfficial} /><span className="text-xs text-mute">Intelligence Attention about the company's catalogue technologies, not incidents affecting the company.</span></div>
      <Status loading={loading && !data} error={error} onRetry={reload} empty={!!data && data.items.length === 0} emptyText="No articles linked to this company's technologies yet." />
      {data && data.items.length > 0 && <ul className="space-y-2">{data.items.map((n) => (
        <li key={n.id} className={`${card} p-4`}><ExtLink href={n.url}>{n.title}</ExtLink><div className="mt-1 text-[11px] text-mute">{n.source.name} · {n.source.type_label} · {n.published ? fmt(n.published) : 'no publication date'}</div>{n.summary && <p className="mt-1 text-xs text-mute">{n.summary}</p>}</li>))}</ul>}
      {data && <div className="flex items-center justify-between text-xs text-mute"><span>{data.total} article(s) · {data.note}</span><span className="flex items-center gap-2"><button disabled={page <= 1} onClick={() => setPage(page - 1)} className="rounded border border-line px-2 py-1 disabled:opacity-40">Prev</button>{page} / {data.pages}<button disabled={page >= data.pages} onClick={() => setPage(page + 1)} className="rounded border border-line px-2 py-1 disabled:opacity-40">Next</button></span></div>}
    </div>
  )
}
void ver; void btn
