import { useState } from 'react'
import { ArrowDown, ArrowUp } from 'lucide-react'
import { assignCategory, categoryTechs, createCategory, deleteCategory, fetchCategories, orderCategories, updateCategory, type Category } from '../data/products'
import { btn, btn2, Field, inp, Modal } from './company/common'
import { Chip, Note, Status, card, useAsync } from './intel/ui'

function Row({ c, first, last, all, onMove, onChanged, setErr }: { c: Category; first: boolean; last: boolean; all: Category[]; onMove: (d: -1 | 1) => void; onChanged: () => void; setErr: (s: string | null) => void }) {
  const [edit, setEdit] = useState(false)
  const [f, setF] = useState({ name: c.name, description: c.description })
  const [show, setShow] = useState(false)
  const techs = useAsync(() => (show ? categoryTechs(c.id) : Promise.resolve(null)), [show, c.id, c.technologies])
  const run = (p: Promise<unknown>) => p.then(() => { setErr(null); onChanged() }).catch((e) => setErr(String(e.message)))
  return (
    <li className={`px-3 py-2 ${c.active ? '' : 'opacity-60'}`}>
      <div className="flex items-center gap-2">
        <div className="flex flex-col"><button disabled={first} onClick={() => onMove(-1)} aria-label={`Move ${c.name} up`} className="text-mute hover:text-ink disabled:opacity-30"><ArrowUp size={12} /></button><button disabled={last} onClick={() => onMove(1)} aria-label={`Move ${c.name} down`} className="text-mute hover:text-ink disabled:opacity-30"><ArrowDown size={12} /></button></div>
        <div className="min-w-0 flex-1">
          {edit ? <div className="grid gap-2 md:grid-cols-2"><Field label="Name"><input value={f.name} onChange={(e) => setF((s) => ({ ...s, name: e.target.value }))} maxLength={60} className={inp} /></Field><Field label="Description"><input value={f.description} onChange={(e) => setF((s) => ({ ...s, description: e.target.value }))} maxLength={300} className={inp} /></Field></div>
            : <><div className="truncate text-sm text-ink">{c.name}{!c.active && <span className="ml-2 text-[10px] text-mute">inactive</span>}</div>{c.description && <div className="truncate text-[11px] text-mute">{c.description}</div>}</>}
        </div>
        <button onClick={() => setShow((s) => !s)} className="text-[11px] text-accent hover:underline" title="Technologies in this category">{c.technologies} technolog{c.technologies === 1 ? 'y' : 'ies'}</button>
        {edit ? <><button onClick={() => run(updateCategory(c.id, f).then(() => setEdit(false)))} className={btn}>Save</button><button onClick={() => { setEdit(false); setF({ name: c.name, description: c.description }) }} className={btn2}>Cancel</button></>
          : <><button onClick={() => setEdit(true)} className={btn2}>Edit</button><button onClick={() => run(updateCategory(c.id, { active: !c.active }))} className={btn2}>{c.active ? 'Deactivate' : 'Activate'}</button>
            <button onClick={() => run(deleteCategory(c.id))} className="rounded-lg border border-red-400/30 px-3 py-1.5 text-xs text-red-300 hover:bg-red-400/10">Delete</button></>}
      </div>
      {show && <div className="mt-2 rounded-lg border border-line bg-bg/40 p-2">
        {techs.loading ? <div className="text-xs text-mute">Loading…</div> : (techs.data?.items.length ?? 0) === 0 ? <div className="text-xs text-mute">No technologies. This category can be deleted.</div> :
          <ul className="max-h-40 divide-y divide-line/50 overflow-y-auto">{techs.data!.items.map((t) => (
            <li key={t.id} className="flex items-center gap-2 py-1 text-xs"><span className="min-w-0 flex-1 truncate text-ink">{t.name} <span className="text-mute">· {t.vendor}</span></span>
              <select aria-label={`Move ${t.name}`} value="" onChange={(e) => e.target.value && run(assignCategory([t.id], e.target.value))} className="rounded border border-line bg-surface px-1 py-0.5 text-[11px] text-ink"><option value="">Move to…</option>{all.filter((x) => x.id !== c.id && x.active).map((x) => <option key={x.id} value={x.id}>{x.name}</option>)}</select></li>))}</ul>}
      </div>}
    </li>
  )
}

/** Categories belong to Cyber Risk Pyramid: created, ordered and reassigned here, never derived from NVD names. */
export default function ManageCategories({ onClose, onChanged }: { onClose: () => void; onChanged: () => void }) {
  const cats = useAsync(fetchCategories, [])
  const [nf, setNf] = useState({ name: '', description: '' })
  const [err, setErr] = useState<string | null>(null)
  const items = cats.data?.items ?? []
  const changed = () => { cats.reload(); onChanged() }
  const move = (i: number, d: -1 | 1) => { const ids = items.map((c) => c.id); [ids[i], ids[i + d]] = [ids[i + d], ids[i]]; orderCategories(ids).then(changed).catch((e) => setErr(String(e.message))) }
  return (
    <Modal title="Manage Categories" onClose={onClose} size="xl">
      <div className="space-y-3" style={{ minWidth: 'min(680px, 80vw)' }}>
        <p className="text-xs text-mute">Categories are yours: NVD updates never create, rename or move them. New categories appear in every filter and picker immediately. A category in use cannot be deleted: move its technologies first, or deactivate it.</p>
        <div className="grid gap-2 md:grid-cols-[1fr_1.5fr_auto] md:items-end">
          <Field label="New category"><input value={nf.name} onChange={(e) => setNf((s) => ({ ...s, name: e.target.value }))} maxLength={60} className={inp} placeholder="e.g. Data Platforms" /></Field>
          <Field label="Description (optional)"><input value={nf.description} onChange={(e) => setNf((s) => ({ ...s, description: e.target.value }))} maxLength={300} className={inp} /></Field>
          <button disabled={!nf.name.trim()} onClick={() => createCategory(nf).then(() => { setNf({ name: '', description: '' }); setErr(null); changed() }).catch((e) => setErr(String(e.message)))} className={btn}>Create</button>
        </div>
        {err && <Note tone="warn">{err}</Note>}
        <Status loading={cats.loading && !cats.data} error={cats.error} onRetry={cats.reload} />
        <ul className={`${card} max-h-[52vh] divide-y divide-line/60 overflow-y-auto`}>{items.map((c, i) => <Row key={c.id} c={c} first={i === 0} last={i === items.length - 1} all={items} onMove={(d) => move(i, d)} onChanged={changed} setErr={setErr} />)}</ul>
        <div className="flex items-center justify-between"><Chip>{items.filter((c) => c.active).length} active · {items.length} total</Chip><button onClick={onClose} className={btn2}>Close</button></div>
      </div>
    </Modal>
  )
}
