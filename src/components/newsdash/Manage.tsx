import { useState } from 'react'
import { ArrowDown, ArrowUp, Plus, X } from 'lucide-react'
import { addKeyword, createDashboard, deleteDashboard, deleteKeyword, duplicateDashboard, orderDashboards, orderKeywords, updateDashboard, updateKeyword, type DashList, type Dashboard, type Keyword, type MatchType, type Term } from '../../data/intelDash'
import { btn, btn2, Field, inp, Modal } from '../company/common'
import { Chip, Note, fmt } from '../intel/ui'

const PRESETS = (l: DashList) => l.periods.filter((p) => p.id !== 'custom')

/** New / edit dashboard. A new dashboard can be seeded with simple keywords (one per line or comma separated); each becomes a pyramid matching that whole word. */
export function DashboardForm({ list, edit, onClose, onSaved }: { list: DashList; edit?: Dashboard; onClose: () => void; onSaved: (d: Dashboard) => void }) {
  const [f, setF] = useState({ name: edit?.name ?? '', description: edit?.description ?? '', default_period: edit?.default_period ?? '7d', quick: '' })
  const [err, setErr] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const submit = () => {
    setBusy(true); setErr(null)
    const names = [...new Set(f.quick.split(/[\n,]/).map((x) => x.trim()).filter(Boolean))]
    const p = edit ? updateDashboard(edit.id, { name: f.name, description: f.description, default_period: f.default_period })
      : createDashboard({ name: f.name, description: f.description, default_period: f.default_period, keywords: names.map((n) => ({ display_name: n, enabled: true, terms: [{ term: n, match_type: (/\s/.test(n) ? 'phrase' : 'word') as MatchType }], excluded_terms: [] })) })
    p.then(onSaved).catch((e) => setErr(String(e.message))).finally(() => setBusy(false))
  }
  return (
    <Modal title={edit ? 'Edit Dashboard' : 'New Dashboard'} onClose={onClose}>
      <div className="space-y-3">
        <Field label="Name"><input value={f.name} onChange={(e) => setF((s) => ({ ...s, name: e.target.value }))} maxLength={80} autoFocus className={inp} placeholder="e.g. Ransomware Intelligence" /></Field>
        <Field label="Description (optional)"><input value={f.description} onChange={(e) => setF((s) => ({ ...s, description: e.target.value }))} maxLength={300} className={inp} /></Field>
        <Field label="Default period"><select value={f.default_period} onChange={(e) => setF((s) => ({ ...s, default_period: e.target.value }))} className={inp}>{PRESETS(list).map((p) => <option key={p.id} value={p.id}>{p.label}</option>)}</select></Field>
        {!edit && <Field label="Keywords (optional, one per line or comma separated)" hint="Each keyword becomes a pyramid that matches that whole word or phrase. You can add aliases and exclusions later in Manage Keywords."><textarea value={f.quick} onChange={(e) => setF((s) => ({ ...s, quick: e.target.value }))} rows={4} className={inp} placeholder={'Ransomware\nLockBit\nAkira\nQilin'} /></Field>}
        {err && <Note tone="warn">{err}</Note>}
        <div className="flex justify-end gap-2"><button onClick={onClose} className={btn2}>Cancel</button><button disabled={busy || !f.name.trim()} onClick={submit} className={btn}>{edit ? 'Save' : 'Create dashboard'}</button></div>
      </div>
    </Modal>
  )
}

/** Open, edit, duplicate, delete and reorder the saved dashboards. */
export function ManageDashboards({ list, activeId, onClose, onChanged, onOpen, onEdit }: { list: DashList; activeId: number | null; onClose: () => void; onChanged: (openId?: number) => void; onOpen: (id: number) => void; onEdit: (d: Dashboard) => void }) {
  const [err, setErr] = useState<string | null>(null)
  const [confirm, setConfirm] = useState<number | null>(null)
  const run = (p: Promise<unknown>, openId?: number) => p.then(() => { setErr(null); onChanged(openId) }).catch((e) => setErr(String(e.message)))
  const move = (i: number, d: -1 | 1) => { const ids = list.items.map((x) => x.id); [ids[i], ids[i + d]] = [ids[i + d], ids[i]]; run(orderDashboards(ids)) }
  return (
    <Modal title="Manage Dashboards" onClose={onClose} size="xl">
      <div className="space-y-3">
        {err && <Note tone="warn">{err}</Note>}
        {list.items.length === 0 && <div className="rounded-lg border border-dashed border-line px-4 py-8 text-center text-sm text-mute">No dashboards yet. Create one from “New Dashboard”.</div>}
        <ul className="divide-y divide-line/60 rounded-xl border border-line">
          {list.items.map((d, i) => (
            <li key={d.id} className="flex flex-wrap items-center gap-3 px-3 py-2.5">
              <div className="flex flex-col"><button disabled={i === 0} onClick={() => move(i, -1)} aria-label={`Move ${d.name} up`} className="text-mute hover:text-ink disabled:opacity-30"><ArrowUp size={12} /></button><button disabled={i === list.items.length - 1} onClick={() => move(i, 1)} aria-label={`Move ${d.name} down`} className="text-mute hover:text-ink disabled:opacity-30"><ArrowDown size={12} /></button></div>
              <div className="min-w-0 flex-1"><div className="truncate text-sm font-medium text-ink">{d.name}{d.id === activeId && <span className="ml-2 text-[10px] text-accent">open</span>}</div>
                <div className="truncate text-[11px] text-mute">{d.description || 'No description'} · {d.keyword_count} pyramid{d.keyword_count === 1 ? '' : 's'} · default {list.periods.find((p) => p.id === d.default_period)?.label ?? d.default_period} · modified {fmt(d.updated_at)}</div></div>
              <button onClick={() => { onOpen(d.id); onClose() }} className={btn2}>Open</button>
              <button onClick={() => onEdit(d)} className={btn2}>Edit</button>
              <button onClick={() => run(duplicateDashboard(d.id), undefined)} className={btn2}>Duplicate</button>
              {confirm === d.id ? <><button onClick={() => { setConfirm(null); run(deleteDashboard(d.id)) }} className="rounded-lg border border-red-400/40 bg-red-400/10 px-3 py-1.5 text-xs text-red-300">Confirm delete</button><button onClick={() => setConfirm(null)} className={btn2}>Cancel</button></>
                : <button onClick={() => setConfirm(d.id)} className="rounded-lg border border-red-400/30 px-3 py-1.5 text-xs text-red-300 hover:bg-red-400/10">Delete</button>}
            </li>
          ))}
        </ul>
        <div className="flex items-center justify-between text-[11px] text-mute"><span>{list.items.length} of {list.limits.dashboards} dashboards. Deleting removes only the configuration, never news.</span><button onClick={onClose} className={btn2}>Close</button></div>
      </div>
    </Modal>
  )
}

function TermRows({ title, hint, rows, onChange, max }: { title: string; hint: string; rows: Term[]; onChange: (r: Term[]) => void; max: number }) {
  return (
    <div>
      <div className="mb-1 flex items-baseline justify-between"><span className="text-xs font-medium text-ink">{title}</span><span className="text-[10px] text-mute">{hint}</span></div>
      <div className="space-y-1.5">
        {rows.map((t, i) => (
          <div key={i} className="flex gap-1.5">
            <input value={t.term} onChange={(e) => onChange(rows.map((x, j) => (j === i ? { ...x, term: e.target.value } : x)))} maxLength={80} aria-label={`${title} ${i + 1}`} className={`${inp} flex-1`} />
            <select value={t.match_type} onChange={(e) => onChange(rows.map((x, j) => (j === i ? { ...x, match_type: e.target.value as MatchType } : x)))} aria-label="Match type" className="rounded-lg border border-line bg-bg px-2 text-xs text-ink">
              <option value="word">Whole word</option><option value="phrase">Exact phrase</option><option value="exact">Exact text</option></select>
            <button onClick={() => onChange(rows.filter((_, j) => j !== i))} aria-label="Remove term" className="rounded-lg border border-line px-2 text-mute hover:text-ink"><X size={12} /></button>
          </div>
        ))}
        {rows.length < max && <button onClick={() => onChange([...rows, { term: '', match_type: 'word' }])} className="text-xs text-accent hover:underline"><Plus size={11} className="mr-0.5 inline" />Add</button>}
      </div>
    </div>
  )
}

function KeywordEditor({ k, onCancel, onSave, limits }: { k: Keyword | null; onCancel: () => void; onSave: (d: { display_name: string; enabled: boolean; terms: Term[]; excluded_terms: Term[] }) => Promise<unknown>; limits: DashList['limits'] }) {
  const [name, setName] = useState(k?.display_name ?? '')
  const [enabled, setEnabled] = useState(k?.enabled ?? true)
  const [terms, setTerms] = useState<Term[]>(k?.terms.map(({ term, match_type }) => ({ term, match_type })) ?? [{ term: '', match_type: 'word' }])
  const [ex, setEx] = useState<Term[]>(k?.excluded_terms.map(({ term, match_type }) => ({ term, match_type })) ?? [])
  const [err, setErr] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const save = () => {
    setBusy(true); setErr(null)
    const clean = (r: Term[]) => r.filter((t) => t.term.trim()).map((t) => ({ term: t.term.trim(), match_type: t.match_type }))
    onSave({ display_name: name.trim(), enabled, terms: clean(terms), excluded_terms: clean(ex) }).catch((e) => setErr(String(e.message))).finally(() => setBusy(false))
  }
  return (
    <div className="space-y-3 rounded-xl border border-accent/30 bg-bg/40 p-4">
      <div className="grid gap-3 md:grid-cols-[1fr_auto] md:items-end"><Field label="Display name (the pyramid label)"><input value={name} onChange={(e) => setName(e.target.value)} maxLength={60} className={inp} placeholder="e.g. Microsoft" /></Field>
        <label className="flex items-center gap-2 pb-2 text-xs text-ink"><input type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} /> Enabled</label></div>
      <div className="grid gap-4 md:grid-cols-2">
        <TermRows title="Search terms" hint="any of these (OR)" rows={terms} onChange={setTerms} max={limits.search_terms} />
        <TermRows title="Excluded terms" hint="an article with any of these is left out (NOT)" rows={ex} onChange={setEx} max={limits.excluded_terms} />
      </div>
      <p className="text-[11px] text-mute">Terms are matched case-insensitively in title, excerpt and CVE ids, never in the outlet name. “Whole word” does not match inside longer words; “Exact phrase” needs the words together; “Exact text” matches the characters anywhere. An article that matches several terms counts once. Terms are literal text, not patterns.</p>
      {err && <Note tone="warn">{err}</Note>}
      <div className="flex justify-end gap-2"><button onClick={onCancel} className={btn2}>Cancel</button><button disabled={busy || !name.trim()} onClick={save} className={btn}>{k ? 'Save keyword' : 'Add keyword'}</button></div>
    </div>
  )
}

/** Pyramids of one dashboard: add, edit terms/exclusions, enable/disable, reorder, delete. */
export function ManageKeywords({ dash, list, onClose, onChanged }: { dash: Dashboard; list: DashList; onClose: () => void; onChanged: () => void }) {
  const [d, setD] = useState<Dashboard>(dash)
  const [editing, setEditing] = useState<number | 'new' | null>(null)
  const [err, setErr] = useState<string | null>(null)
  const apply = (p: Promise<Dashboard>) => p.then((x) => { setD(x); setErr(null); onChanged(); return x })
  const move = (i: number, dir: -1 | 1) => { const ids = d.keywords.map((k) => k.id); [ids[i], ids[i + dir]] = [ids[i + dir], ids[i]]; apply(orderKeywords(d.id, ids)).catch((e) => setErr(String(e.message))) }
  return (
    <Modal title={`Manage Keywords — ${d.name}`} onClose={onClose} size="xl">
      <div className="space-y-3">
        <p className="text-xs text-mute">One pyramid per keyword (up to {list.limits.keywords}). Order here is the order on the dashboard. Changes are saved immediately.</p>
        {err && <Note tone="warn">{err}</Note>}
        <ul className="space-y-2">
          {d.keywords.map((k, i) => (
            <li key={k.id}>
              {editing === k.id ? <KeywordEditor k={k} limits={list.limits} onCancel={() => setEditing(null)} onSave={(b) => apply(updateKeyword(d.id, k.id, b)).then(() => setEditing(null))} /> : (
                <div className={`flex flex-wrap items-center gap-3 rounded-lg border border-line px-3 py-2 ${k.enabled ? '' : 'opacity-60'}`}>
                  <div className="flex flex-col"><button disabled={i === 0} onClick={() => move(i, -1)} aria-label={`Move ${k.display_name} up`} className="text-mute hover:text-ink disabled:opacity-30"><ArrowUp size={12} /></button><button disabled={i === d.keywords.length - 1} onClick={() => move(i, 1)} aria-label={`Move ${k.display_name} down`} className="text-mute hover:text-ink disabled:opacity-30"><ArrowDown size={12} /></button></div>
                  <div className="min-w-0 flex-1"><div className="text-sm font-medium text-ink">{k.display_name}{!k.enabled && <span className="ml-2 text-[10px] text-mute">disabled</span>}</div>
                    <div className="mt-0.5 flex flex-wrap gap-1">{k.terms.map((t) => <Chip key={t.term} title={t.match_type}>{t.term}</Chip>)}{k.excluded_terms.map((t) => <Chip key={`x${t.term}`} tone="red" title="excluded">NOT {t.term}</Chip>)}</div></div>
                  <label className="flex items-center gap-1.5 text-xs text-mute"><input type="checkbox" checked={k.enabled} onChange={(e) => apply(updateKeyword(d.id, k.id, { enabled: e.target.checked })).catch((x) => setErr(String(x.message)))} aria-label={`Enable ${k.display_name}`} />Enabled</label>
                  <button onClick={() => setEditing(k.id)} className={btn2}>Edit</button>
                  <button onClick={() => apply(deleteKeyword(d.id, k.id)).catch((x) => setErr(String(x.message)))} className="rounded-lg border border-red-400/30 px-3 py-1.5 text-xs text-red-300 hover:bg-red-400/10">Delete</button>
                </div>)}
            </li>
          ))}
        </ul>
        {d.keywords.length === 0 && editing !== 'new' && <div className="rounded-lg border border-dashed border-line px-4 py-6 text-center text-sm text-mute">No keywords yet: add the first pyramid.</div>}
        {editing === 'new' ? <KeywordEditor k={null} limits={list.limits} onCancel={() => setEditing(null)} onSave={(b) => apply(addKeyword(d.id, b)).then(() => setEditing(null))} />
          : <button disabled={d.keywords.length >= list.limits.keywords} onClick={() => setEditing('new')} className={btn}><Plus size={12} className="mr-1 inline" />Add keyword</button>}
        <div className="flex justify-end"><button onClick={onClose} className={btn2}>Done</button></div>
      </div>
    </Modal>
  )
}
