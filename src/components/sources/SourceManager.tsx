import { useState } from 'react'
import { Loader2, ShieldCheck } from 'lucide-react'
import { VAL_LABEL, VAL_TONE, STATE_LABEL, STATE_TONE, adminList, addSource, bulkSources, deleteSource, editSource, setSourceEnabled, validateSource, type AdminFilters, type AdminSource, type AdminPage } from '../../data/sourceAdmin'
import { ago } from '../IntelligenceFeed'
import { btn, btn2, Field, inp, Modal } from '../company/common'
import { Chip, Note, Status, card, fmt, sel, useAsync } from '../intel/ui'

const Badge = ({ cls, children, title }: { cls: string; children: string; title?: string }) => <span title={title} className={`whitespace-nowrap rounded-full border px-2 py-0.5 text-[11px] ${cls}`}>{children}</span>
const SORT_OPTS: [string, string][] = [['name', 'Name'], ['category', 'Category'], ['country', 'Country'], ['status', 'State'], ['articles', 'Articles'], ['last_sync', 'Last sync'], ['newest', 'Newest article']]

function SourceForm({ page, edit, onClose, onSaved }: { page: AdminPage; edit?: AdminSource; onClose: () => void; onSaved: (msg: string) => void }) {
  const manual = !edit || edit.origin === 'manual'
  const [f, setF] = useState({ name: edit?.name ?? '', url: edit?.url ?? '', category: edit?.category ?? 'news', publisher: edit?.publisher ?? '', site: edit?.site ?? '', country: edit?.country ?? '', language: edit?.language && edit.language !== 'unknown' ? edit.language : '' })
  const [err, setErr] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const set = (k: string) => (e: { target: { value: string } }) => setF((s) => ({ ...s, [k]: e.target.value }))
  const submit = () => {
    setBusy(true); setErr(null)
    const body = { name: f.name, category: f.category, publisher: f.publisher, site: f.site, country: f.country.toUpperCase(), language: f.language.toLowerCase(), ...(manual ? { url: f.url } : {}) }
    const p = edit ? editSource(edit.id, manual ? body : { category: f.category, publisher: f.publisher, site: f.site, country: f.country.toUpperCase(), language: f.language.toLowerCase() }).then(() => 'Source updated.')
      : addSource(body).then((r) => (r.enabled ? `Added and enabled: ${r.validation.entries} entries found.` : `Added but NOT enabled: validation says "${VAL_LABEL[r.validation.status] ?? r.validation.status}"${r.validation.note ? ` (${r.validation.note})` : ''}.`))
    p.then((m) => onSaved(m)).catch((e) => setErr(String(e.message))).finally(() => setBusy(false))
  }
  return (
    <Modal title={edit ? `Edit source — ${edit.name}` : 'Add source'} onClose={onClose}>
      <div className="grid grid-cols-2 gap-3">
        <div className="col-span-2"><Field label="Name"><input value={f.name} onChange={set('name')} maxLength={100} disabled={!manual} className={inp} /></Field></div>
        {manual && <div className="col-span-2"><Field label="Feed URL (RSS or Atom)" hint="It is fetched and parsed before the source is enabled; only verified feeds start enabled."><input value={f.url} onChange={set('url')} maxLength={500} placeholder="https://example.org/feed.xml" className={inp} /></Field></div>}
        <Field label="Category"><select value={f.category} onChange={set('category')} className={inp}>{page.categories.map((c) => <option key={c.id} value={c.id}>{c.label}</option>)}</select></Field>
        <Field label="Publisher (optional)"><input value={f.publisher} onChange={set('publisher')} maxLength={100} className={inp} /></Field>
        <Field label="Site URL (optional)"><input value={f.site} onChange={set('site')} maxLength={300} placeholder="https://…" className={inp} /></Field>
        <div className="grid grid-cols-2 gap-3"><Field label="Country (ISO, optional)"><input value={f.country} onChange={set('country')} maxLength={2} placeholder="e.g. FR" className={inp} /></Field><Field label="Language (optional)"><input value={f.language} onChange={set('language')} maxLength={3} placeholder="e.g. es" className={inp} /></Field></div>
      </div>
      <div className="mt-2 text-[11px] text-mute">Unknown values are fine: nothing is guessed. {!manual && 'Built-in and catalogue sources keep their name, URL and type.'}</div>
      {err && <div className="mt-3"><Note tone="warn">{err}</Note></div>}
      <div className="mt-4 flex justify-end gap-2"><button onClick={onClose} className={btn2}>Cancel</button><button disabled={busy || !f.name.trim() || (manual && !f.url.trim())} onClick={submit} className={btn}>{busy ? 'Working…' : edit ? 'Save' : 'Validate and add'}</button></div>
    </Modal>
  )
}

function Detail({ s, onClose }: { s: AdminSource; onClose: () => void }) {
  const rows: [string, React.ReactNode][] = [
    ['Feed URL', <a key="u" href={s.url} target="_blank" rel="noopener noreferrer nofollow" className="break-all text-accent hover:underline">{s.url}</a>], ['Publisher', s.publisher ?? 'unknown'], ['Site', s.site ?? 'unknown'],
    ['Category', s.category_label ?? 'unclassified'], ['Country', s.country ?? 'unknown'], ['Language', s.language ?? 'unknown'], ['Origin', `${s.origin}${s.batch ? ` · batch ${s.batch}` : ''}`],
    ['Validation', `${VAL_LABEL[s.validation_status ?? 'unvalidated']}${s.validated_at ? ` · ${fmt(s.validated_at)}` : ''}${s.validation_note ? ` — ${s.validation_note}` : ''}`],
    ['Last attempt', s.last_attempt ? fmt(s.last_attempt) : 'never'], ['Last successful sync', s.last_success ? fmt(s.last_success) : 'never'], ['Last error', s.error ?? 'none'],
    ['Articles', `${s.items_stored} stored · ${s.articles_7d} in 7 d · ${s.articles_30d} in 30 d · last fetch returned ${s.last_items ?? 0}`], ['Newest publication', s.latest_publication ? fmt(s.latest_publication) : 'unknown'],
  ]
  return (
    <Modal title={s.name} onClose={onClose}>
      <dl className="grid grid-cols-[9rem_1fr] gap-x-3 gap-y-1.5 text-xs">{rows.map(([k, v]) => <><dt key={k} className="text-mute">{k}</dt><dd key={`${k}v`} className="text-ink">{v}</dd></>)}</dl>
    </Modal>
  )
}

export default function SourceManager() {
  const [f, setF] = useState<AdminFilters>({ sort: 'name', order: 'asc', page: 1, page_size: 25 })
  const { data, loading, error, reload } = useAsync(() => adminList(f), [JSON.stringify(f)])
  const [picked, setPicked] = useState<Set<string>>(new Set())
  const [msg, setMsg] = useState<string | null>(null)
  const [err, setErr] = useState<string | null>(null)
  const [busy, setBusy] = useState<string | null>(null)
  const [form, setForm] = useState<null | 'new' | AdminSource>(null)
  const [detail, setDetail] = useState<AdminSource | null>(null)
  const set = (k: keyof AdminFilters, v: string) => { setF((s) => ({ ...s, [k]: v || undefined, page: 1 })); setPicked(new Set()) }
  const ind = data?.indicators
  const run = (id: string, p: Promise<unknown>, ok?: string) => { setBusy(id); setErr(null); p.then(() => { if (ok) setMsg(ok); reload() }).catch((e) => setErr(String(e.message))).finally(() => setBusy(null)) }
  const toggle = (id: string) => setPicked((s) => { const n = new Set(s); if (n.has(id)) n.delete(id); else n.add(id); return n })
  const bulk = async (action: 'enable' | 'disable' | 'validate') => {
    const ids = [...picked]; setBusy('bulk'); setErr(null); setMsg(null)
    const done: string[] = []; const skipped: string[] = []
    try {
      for (let i = 0; i < ids.length; i += action === 'validate' ? 10 : 50) {
        const r = await bulkSources(ids.slice(i, i + (action === 'validate' ? 10 : 50)), action)
        done.push(...r.done.map((d) => d.id)); skipped.push(...r.skipped.map((d) => `${d.id}: ${d.reason}`))
      }
      setMsg(`${action}: ${done.length} done${skipped.length ? `, ${skipped.length} skipped (${skipped.slice(0, 3).join('; ')}${skipped.length > 3 ? '…' : ''})` : ''}.`); setPicked(new Set()); reload()
    } catch (e) { setErr(String((e as Error).message)) } finally { setBusy(null) }
  }
  const items = data?.items ?? []
  const allOn = items.length > 0 && items.every((s) => picked.has(s.id))
  const fc = data?.facets
  const opt = (m: Record<string, number> | undefined, label?: (k: string) => string) => Object.entries(m ?? {}).sort((a, b) => a[0].localeCompare(b[0])).map(([k, n]) => <option key={k} value={k}>{label ? label(k) : k} ({n})</option>)
  return (
    <div className="space-y-4">
      {ind && <div className="grid grid-cols-2 gap-3 md:grid-cols-6">{([['Total Sources', ind.total], ['Enabled Sources', ind.enabled], ['Verified Sources', ind.verified], ['Failed Sources', ind.failed], ['With Recent Articles', ind.with_recent_articles], ['Last Successful Sync', ind.last_successful_sync ? ago(ind.last_successful_sync) : 'never']] as [string, string | number][]).map(([l, v]) =>
        <div key={l} className={`${card} px-4 py-3`}><div className="text-[11px] uppercase tracking-wider text-mute">{l}</div><div className="mt-0.5 text-2xl font-semibold tabular-nums text-ink">{v}</div></div>)}</div>}
      <div className="flex flex-wrap items-center gap-2">
        <input value={f.q ?? ''} onChange={(e) => set('q', e.target.value)} placeholder="Search name, publisher or URL…" maxLength={80} className={`${sel} min-w-[220px]`} aria-label="Search sources" />
        <select value={f.category ?? ''} onChange={(e) => set('category', e.target.value)} className={sel} aria-label="Category"><option value="">All categories</option>{(data?.categories ?? []).map((c) => <option key={c.id} value={c.id}>{c.label} ({fc?.categories[c.id] ?? 0})</option>)}</select>
        <select value={f.country ?? ''} onChange={(e) => set('country', e.target.value)} className={sel} aria-label="Country"><option value="">All countries</option>{opt(fc?.countries)}</select>
        <select value={f.language ?? ''} onChange={(e) => set('language', e.target.value)} className={sel} aria-label="Language"><option value="">All languages</option>{opt(fc?.languages)}</select>
        <select value={f.status ?? ''} onChange={(e) => set('status', e.target.value)} className={sel} aria-label="State"><option value="">All states</option>
          <optgroup label="Sync state">{Object.entries(STATE_LABEL).map(([k, v]) => <option key={k} value={k}>{v} ({fc?.states[k] ?? 0})</option>)}</optgroup>
          <optgroup label="Validation">{Object.entries(VAL_LABEL).map(([k, v]) => <option key={k} value={k}>{v} ({fc?.validation[k] ?? 0})</option>)}</optgroup></select>
        <select value={f.sort} onChange={(e) => set('sort', e.target.value)} className={sel} aria-label="Sort by">{SORT_OPTS.map(([v, l]) => <option key={v} value={v}>Sort: {l}</option>)}</select>
        <button onClick={() => setF((s) => ({ ...s, order: s.order === 'asc' ? 'desc' : 'asc' }))} className={btn2} aria-label="Toggle order">{f.order === 'asc' ? '↑' : '↓'}</button>
        <button onClick={() => setForm('new')} className={`${btn} ml-auto`}>Add source</button>
      </div>
      {picked.size > 0 && <div className="flex flex-wrap items-center gap-2 rounded-lg border border-accent/30 bg-accent/5 px-3 py-2 text-xs text-ink">{picked.size} selected
        <button disabled={busy === 'bulk'} onClick={() => bulk('enable')} className={btn2}>Enable</button><button disabled={busy === 'bulk'} onClick={() => bulk('disable')} className={btn2}>Disable</button>
        <button disabled={busy === 'bulk'} onClick={() => bulk('validate')} className={btn2}>Validate</button><button onClick={() => setPicked(new Set())} className="text-mute hover:text-ink">Clear</button>{busy === 'bulk' && <Loader2 size={13} className="animate-spin" />}</div>}
      {msg && <Note>{msg}</Note>}
      {err && <Note tone="warn">{err}</Note>}
      <Status loading={loading && !data} error={error} onRetry={reload} empty={!!data && items.length === 0} emptyText="No source matches these filters." />
      {items.length > 0 && data && (
        <div className={`${card} overflow-x-auto`}>
          <table className="w-full min-w-[1000px] text-sm">
            <thead className="border-b border-line text-left text-xs uppercase tracking-wider text-mute"><tr>
              <th className="px-3 py-3"><input type="checkbox" checked={allOn} onChange={() => setPicked(allOn ? new Set() : new Set(items.map((s) => s.id)))} aria-label="Select all on this page" /></th>
              <th className="px-3 py-3">On</th><th className="px-3 py-3">Source</th><th className="px-3 py-3">Category</th><th className="px-3 py-3">Country · Lang</th><th className="px-3 py-3">State</th><th className="px-3 py-3">Validation</th><th className="px-3 py-3">Articles</th><th className="px-3 py-3">Last sync</th><th className="px-3 py-3" /></tr></thead>
            <tbody>{items.map((s) => (
              <tr key={s.id} className="border-b border-line/60 align-top last:border-0 hover:bg-bg/40">
                <td className="px-3 py-2.5"><input type="checkbox" checked={picked.has(s.id)} onChange={() => toggle(s.id)} aria-label={`Select ${s.name}`} /></td>
                <td className="px-3 py-2.5"><button role="switch" aria-checked={s.enabled} aria-label={`${s.enabled ? 'Disable' : 'Enable'} ${s.name}`} disabled={busy === s.id} onClick={() => run(s.id, setSourceEnabled(s.id, !s.enabled))}
                  className={`relative h-5 w-9 rounded-full border transition-colors ${s.enabled ? 'border-accent/50 bg-accent/30' : 'border-line bg-bg'}`}><span className={`absolute top-0.5 h-3.5 w-3.5 rounded-full bg-ink transition-all ${s.enabled ? 'left-[18px]' : 'left-0.5 opacity-60'}`} /></button></td>
                <td className="px-3 py-2.5"><button onClick={() => setDetail(s)} className="text-left font-medium text-ink hover:text-accent">{s.name}</button>
                  <div className="flex items-center gap-1.5 text-[11px] text-mute">{s.type_label}{s.official_verified && <span title="Feed host verified as the official domain"><ShieldCheck size={11} className="inline text-emerald-300" /></span>}{s.origin !== 'builtin' && <Chip>{s.origin}</Chip>}</div></td>
                <td className="px-3 py-2.5 text-xs text-mute">{s.category_label ?? '—'}</td>
                <td className="px-3 py-2.5 text-xs text-mute">{s.country ?? '—'} · {s.language && s.language !== 'unknown' ? s.language : '—'}</td>
                <td className="px-3 py-2.5"><Badge cls={STATE_TONE[s.state] ?? STATE_TONE.pending} title={s.error ?? undefined}>{STATE_LABEL[s.state] ?? s.state}</Badge></td>
                <td className="px-3 py-2.5"><Badge cls={VAL_TONE[s.validation_status ?? 'unvalidated']} title={s.validation_note ?? undefined}>{VAL_LABEL[s.validation_status ?? 'unvalidated']}</Badge></td>
                <td className="px-3 py-2.5 text-xs tabular-nums text-mute"><span className="text-ink">{s.items_stored}</span> · {s.articles_7d}/7d</td>
                <td className="px-3 py-2.5 text-xs text-mute" title={fmt(s.last_success)}>{s.last_success ? ago(s.last_success) : 'never'}</td>
                <td className="whitespace-nowrap px-3 py-2.5 text-right text-xs"><button disabled={busy === s.id} onClick={() => run(s.id, validateSource(s.id).then((r) => setMsg(`${s.name}: ${VAL_LABEL[r.status]}${r.note ? ` — ${r.note}` : ''} (${r.entries} entries)`)))} className="mr-2 text-accent hover:underline">{busy === s.id ? '…' : 'Validate'}</button>
                  <button onClick={() => setForm(s)} className="mr-2 text-mute hover:text-ink">Edit</button>{s.origin === 'manual' && <button onClick={() => run(s.id, deleteSource(s.id), 'Source deleted.')} className="text-red-300 hover:underline">Delete</button>}</td>
              </tr>))}</tbody>
          </table>
          <div className="flex items-center justify-between border-t border-line px-4 py-2 text-xs text-mute"><span>{data.total} source{data.total === 1 ? '' : 's'}</span>
            <span className="flex items-center gap-2"><button disabled={(f.page ?? 1) <= 1} onClick={() => setF((s) => ({ ...s, page: (s.page ?? 1) - 1 }))} className="rounded border border-line px-2 py-1 disabled:opacity-40">Prev</button>{f.page} / {data.pages}
              <button disabled={(f.page ?? 1) >= data.pages} onClick={() => setF((s) => ({ ...s, page: (s.page ?? 1) + 1 }))} className="rounded border border-line px-2 py-1 disabled:opacity-40">Next</button></span></div>
        </div>
      )}
      {form && data && <SourceForm page={data} edit={form === 'new' ? undefined : form} onClose={() => setForm(null)} onSaved={(m) => { setForm(null); setMsg(m); reload() }} />}
      {detail && <Detail s={detail} onClose={() => setDetail(null)} />}
    </div>
  )
}
