import { useEffect, useState, type ReactNode } from 'react'
import { ArrowLeft, Crosshair, Flag, Loader2, Network, RefreshCw, Search, ShieldCheck, Skull, X } from 'lucide-react'
import { fetchActors, fetchAttackEntity, fetchAttackStatus, fetchCampaigns, lookupAttack, syncAttack } from '../data/api'
import type { AttackBrief, AttackEntity, AttackKind, AttackRel, AttackStatus } from '../data/types'
import { ago } from './IntelligenceFeed'
import { Chip, ExtLink, Note, Pager, Status, card, fmt, sel, useAsync } from './intel/ui'

export interface AttackRef { kind: AttackKind; id: string }
type Nav = (kind: AttackKind, id: string) => void
const day = (s?: string | null) => (s ? s.slice(0, 10) : null)
const TONE: Record<string, 'accent' | 'red' | 'violet' | 'orange'> = { actor: 'accent', campaign: 'orange', technique: 'violet', malware: 'red', tool: 'violet' }
const LABEL: Record<string, string> = { actor: 'Group', campaign: 'Campaign', technique: 'Technique', malware: 'Malware', tool: 'Tool' }

function StatusBar() {
  const { data: s, reload } = useAsync(fetchAttackStatus, [])
  const [busy, setBusy] = useState(false)
  useEffect(() => { if (!s?.syncing && !busy) return; const t = setInterval(() => { reload(); if (s && !s.syncing) setBusy(false) }, 4000); return () => clearInterval(t) }, [s?.syncing, busy]) // eslint-disable-line react-hooks/exhaustive-deps
  if (!s) return null
  const c = s.counts
  return (
    <div className={`${card} flex flex-wrap items-center gap-x-5 gap-y-2 p-4 text-xs text-mute`}>
      <span className="flex items-center gap-1.5 text-ink"><ShieldCheck size={14} className="text-accent" /> MITRE ATT&amp;CK Enterprise {s.collection_version ? `v${s.collection_version}` : ''} · STIX {s.spec_version ?? '2.1'}</span>
      <span>{c.actors} groups</span><span>{c.campaigns} campaigns</span><span>{c.techniques} techniques</span><span>{c.malware} malware</span><span>{c.tools} tools</span><span>{c.relationships.toLocaleString()} relationships</span>
      <span className="ml-auto flex items-center gap-3">
        <span>{s.imported ? `Imported ${ago(s.last_success)}` : 'Not imported yet'}{s.status === 'error' ? ` · last update failed: ${s.error}` : ''}</span>
        <button onClick={() => { setBusy(true); syncAttack(false).then(() => setTimeout(reload, 800)).catch(() => setBusy(false)) }} disabled={s.syncing || busy}
          className="flex items-center gap-1.5 rounded border border-line px-2 py-1 text-ink hover:border-accent/40 disabled:opacity-40"><RefreshCw size={12} className={s.syncing || busy ? 'animate-spin' : ''} /> Check for updates</button>
      </span>
    </div>
  )
}

function Picker({ kind, label, value, onChange }: { kind: 'technique' | 'software' | 'actor'; label: string; value: AttackBrief | null; onChange: (v: AttackBrief | null) => void }) {
  const [q, setQ] = useState('')
  const [opts, setOpts] = useState<AttackBrief[]>([])
  useEffect(() => {
    if (q.trim().length < 2) { setOpts([]); return }
    let alive = true
    const t = setTimeout(() => lookupAttack(q, kind).then((r) => alive && setOpts(r.items)).catch(() => undefined), 250)
    return () => { alive = false; clearTimeout(t) }
  }, [q, kind])
  if (value) return <button onClick={() => onChange(null)} className="flex items-center gap-1.5 rounded-lg border border-accent/30 bg-accent/10 px-3 py-2 text-sm text-accent">{value.id} {value.name}<X size={13} /></button>
  return (
    <div className="relative">
      <input value={q} onChange={(e) => setQ(e.target.value)} maxLength={60} placeholder={label} aria-label={label} className={`${sel} w-56`} />
      {opts.length > 0 && (
        <ul className="absolute z-20 mt-1 max-h-60 w-72 overflow-auto rounded-lg border border-line bg-surface p-1 shadow-xl">
          {opts.map((o) => <li key={o.stix_id}><button onClick={() => { onChange(o); setQ(''); setOpts([]) }} className="block w-full rounded px-2 py-1.5 text-left text-xs text-ink hover:bg-accent/10"><span className="text-accent">{o.id}</span> {o.name}</button></li>)}
        </ul>
      )}
    </div>
  )
}

// ------------------------------------------------------------------ lists
function EntityCard({ e, onOpen, meta }: { e: AttackEntity; onOpen: () => void; meta: ReactNode }) {
  return (
    <button onClick={onOpen} className={`${card} flex flex-col gap-2 p-4 text-left transition-colors hover:border-accent/40`}>
      <div className="flex items-center gap-2"><Chip tone={TONE[e.type]}>{e.id}</Chip><span className="truncate text-sm font-semibold text-ink">{e.name}</span></div>
      {e.aliases.length > 0 && <div className="truncate text-[11px] text-mute" title={e.aliases.join(', ')}>aka {e.aliases.slice(0, 4).join(', ')}{e.aliases.length > 4 ? ` +${e.aliases.length - 4}` : ''}</div>}
      <p className="line-clamp-3 text-xs leading-relaxed text-mute">{e.description || 'No description published.'}</p>
      <div className="mt-auto flex flex-wrap gap-x-3 gap-y-1 pt-1 text-[11px] text-mute">{meta}</div>
    </button>
  )
}

function ActorsList({ nav }: { nav: Nav }) {
  const [q, setQ] = useState(''); const [dq, setDq] = useState('')
  const [tech, setTech] = useState<AttackBrief | null>(null); const [soft, setSoft] = useState<AttackBrief | null>(null)
  const [sort, setSort] = useState('name'); const [page, setPage] = useState(1)
  useEffect(() => { const t = setTimeout(() => { setDq(q); setPage(1) }, 300); return () => clearTimeout(t) }, [q])
  const { data, loading, error, reload } = useAsync(() => fetchActors({ q: dq, technique: tech?.id, software: soft?.id, sort, page }), [dq, tech?.id, soft?.id, sort, page])
  return (
    <div className="space-y-4 p-6">
      <StatusBar />
      <Note>Groups are as documented by MITRE ATT&amp;CK. Not every group is an APT, and no country of origin is inferred from names. Associations come only from published STIX relationships.</Note>
      <div className="flex flex-wrap items-center gap-3">
        <div className="relative min-w-[240px] flex-1"><Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-mute" /><input value={q} onChange={(e) => setQ(e.target.value)} maxLength={80} placeholder="Search by name, alias or ID (e.g. APT29, G0016)…" className={`${sel} w-full pl-9`} /></div>
        <Picker kind="technique" label="Filter by technique…" value={tech} onChange={(v) => { setTech(v); setPage(1) }} />
        <Picker kind="software" label="Filter by malware / tool…" value={soft} onChange={(v) => { setSoft(v); setPage(1) }} />
        <select value={sort} onChange={(e) => { setSort(e.target.value); setPage(1) }} className={sel} aria-label="Sort"><option value="name">Sort: name</option><option value="techniques">Sort: most techniques</option><option value="modified">Sort: recently updated</option></select>
      </div>
      {data && <div className="text-xs text-mute">{data.total} documented group{data.total === 1 ? '' : 's'}{tech || soft || dq ? ' match' : ' registered'}</div>}
      <Status loading={loading && !data} error={error} onRetry={reload} empty={!!data && data.items.length === 0} emptyText="No group matches these filters." />
      <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
        {data?.items.map((e) => <EntityCard key={e.stix_id} e={e} onOpen={() => nav('actor', e.id)} meta={<><span>{e.counts?.techniques} techniques</span><span>{e.counts?.software} malware/tools</span><span>{e.counts?.campaigns} campaigns</span></>} />)}
      </div>
      {data && <Pager page={data.page} pages={data.pages} onPage={setPage} />}
    </div>
  )
}

function CampaignsList({ nav }: { nav: Nav }) {
  const [q, setQ] = useState(''); const [dq, setDq] = useState('')
  const [grp, setGrp] = useState<AttackBrief | null>(null); const [tech, setTech] = useState<AttackBrief | null>(null)
  const [sort, setSort] = useState('name'); const [page, setPage] = useState(1)
  useEffect(() => { const t = setTimeout(() => { setDq(q); setPage(1) }, 300); return () => clearTimeout(t) }, [q])
  const { data, loading, error, reload } = useAsync(() => fetchCampaigns({ q: dq, group: grp?.id, technique: tech?.id, sort, page }), [dq, grp?.id, tech?.id, sort, page])
  return (
    <div className="space-y-4 p-6">
      <StatusBar />
      <Note>Campaigns are those documented by MITRE ATT&amp;CK. Actor links are STIX “attributed-to” relationships published by MITRE; none are inferred from news.</Note>
      <div className="flex flex-wrap items-center gap-3">
        <div className="relative min-w-[240px] flex-1"><Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-mute" /><input value={q} onChange={(e) => setQ(e.target.value)} maxLength={80} placeholder="Search campaigns by name or ID (e.g. SolarWinds, C0024)…" className={`${sel} w-full pl-9`} /></div>
        <Picker kind="actor" label="Filter by group…" value={grp} onChange={(v) => { setGrp(v); setPage(1) }} />
        <Picker kind="technique" label="Filter by technique…" value={tech} onChange={(v) => { setTech(v); setPage(1) }} />
        <select value={sort} onChange={(e) => { setSort(e.target.value); setPage(1) }} className={sel} aria-label="Sort"><option value="name">Sort: name</option><option value="first_seen">Sort: latest first seen</option><option value="modified">Sort: recently updated</option></select>
      </div>
      {data && <div className="text-xs text-mute">{data.total} documented campaign{data.total === 1 ? '' : 's'}</div>}
      <Status loading={loading && !data} error={error} onRetry={reload} empty={!!data && data.items.length === 0} emptyText="No campaign matches these filters." />
      <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
        {data?.items.map((e) => <EntityCard key={e.stix_id} e={e} onOpen={() => nav('campaign', e.id)} meta={<>
          <span>{period(e) ?? 'activity period not documented'}</span><span>{e.counts?.techniques} techniques</span>
          <span>{e.actors?.length ? `Group: ${e.actors.map((a) => a.name).join(', ')}` : 'no group documented'}</span></>} />)}
      </div>
      {data && <Pager page={data.page} pages={data.pages} onPage={setPage} />}
    </div>
  )
}

const period = (e: { first_seen?: string | null; last_seen?: string | null }) => (e.first_seen || e.last_seen ? `${day(e.first_seen) ?? '?'} → ${day(e.last_seen) ?? '?'}` : null)

// ------------------------------------------------------------------ details
function Rels({ title, items, nav, empty }: { title: string; items?: AttackBrief[]; nav: Nav; empty: string }) {
  const [all, setAll] = useState(false)
  const list = items ?? []
  const shown = all ? list : list.slice(0, 30)
  return (
    <section className={`${card} p-5`}>
      <div className="mb-3 flex items-center justify-between text-xs uppercase tracking-wider text-mute"><span>{title} ({list.length})</span>
        <span className="normal-case tracking-normal" title="Each link is a relationship published by MITRE in the STIX data">confirmed · STIX relationship</span></div>
      {list.length === 0 && <p className="text-sm text-mute">{empty}</p>}
      <ul className="divide-y divide-line/60">
        {shown.map((x) => (
          <li key={x.stix_id} className="flex flex-wrap items-center gap-x-3 gap-y-1 py-2 text-sm">
            <Chip tone={TONE[x.type]}>{x.id}</Chip>
            <button onClick={() => nav(x.type, x.id)} className="text-left text-ink hover:text-accent">{x.name}</button>
            {x.tactics && x.tactics.length > 0 && <span className="text-[11px] text-mute">{x.tactics.join(', ')}</span>}
            {period(x) && <span className="text-[11px] text-mute">{period(x)}</span>}
            {x.relationship && <RelBadge r={x.relationship} />}
          </li>
        ))}
      </ul>
      {list.length > 30 && <button onClick={() => setAll(!all)} className="mt-2 text-xs text-accent hover:underline">{all ? 'Show fewer' : `Show all ${list.length}`}</button>}
    </section>
  )
}

function RelBadge({ r }: { r: AttackRel }) {
  const ev = r.evidence.find((e) => e.url)
  return (
    <span className="ml-auto flex items-center gap-2 text-[11px] text-mute" title={`${r.source}\nEvidence id: ${r.evidence_id}\nUpdated: ${fmt(r.modified)}`}>
      <Chip>{r.type}</Chip>{r.modified && <span>{day(r.modified)}</span>}{ev && ev.url && <ExtLink href={ev.url}>evidence</ExtLink>}
    </span>
  )
}

function News({ n }: { n: NonNullable<AttackEntity['news']> }) {
  const [open, setOpen] = useState(false)
  return (
    <section className={`${card} p-5`}>
      <div className="mb-2 text-xs uppercase tracking-wider text-mute">Related news ({n.confirmed_total} confirmed)</div>
      {n.confirmed.length === 0 && <p className="text-sm text-mute">No stored article cites this entity by its ATT&amp;CK ID or MITRE page.</p>}
      <ul className="space-y-2">{n.confirmed.map((a) => <li key={a.id} className="text-[13px]"><ExtLink href={a.url}>{a.title}</ExtLink><div className="text-[11px] text-mute">{a.source.name} · {ago(a.published ?? a.collected_at)} · <Chip tone="accent">cites ATT&amp;CK ID</Chip></div></li>)}</ul>
      {n.candidates_total > 0 && (
        <div className="mt-4 border-t border-line pt-3">
          <button onClick={() => setOpen(!open)} className="text-xs text-amber-300 hover:underline">{open ? 'Hide' : 'Show'} {n.candidates_total} unverified name mention{n.candidates_total === 1 ? '' : 's'}</button>
          {open && (
            <div className="mt-2 space-y-2">
              <Note tone="warn">{n.rule}</Note>
              <ul className="space-y-2">{n.candidates.map((a) => <li key={a.id} className="text-[13px]"><ExtLink href={a.url}>{a.title}</ExtLink><div className="text-[11px] text-mute">{a.source.name} · {ago(a.published ?? a.collected_at)} · <Chip>unverified</Chip></div></li>)}</ul>
            </div>
          )}
        </div>
      )}
    </section>
  )
}

function Detail({ ref_, nav, onBack, onGraph }: { ref_: AttackRef; nav: Nav; onBack: () => void; onGraph: (nodeId: string) => void }) {
  const { data: e, loading, error, reload } = useAsync(() => fetchAttackEntity(ref_.kind, ref_.id), [ref_.kind, ref_.id])
  const Icon = ref_.kind === 'actor' ? Skull : ref_.kind === 'campaign' ? Flag : Crosshair
  return (
    <div className="space-y-5 p-6">
      <button onClick={onBack} className="flex items-center gap-1.5 text-xs text-mute hover:text-ink"><ArrowLeft size={14} /> Back</button>
      <Status loading={loading && !e} error={error} onRetry={reload} />
      {e && (
        <>
          <div className={`${card} space-y-3 p-5`}>
            <div className="flex flex-wrap items-center gap-3"><Icon size={20} className="text-accent" /><h2 className="text-xl font-semibold text-ink">{e.name}</h2><Chip tone={TONE[e.type]}>{e.id}</Chip><Chip>{LABEL[e.type]}</Chip>
              {e.type === 'actor' && <Chip title="MITRE documents intrusion sets that are not necessarily APTs">documented group</Chip>}
              {(e.revoked || e.deprecated) && <Chip tone="orange">{e.revoked ? 'revoked' : 'deprecated'}</Chip>}
              {e.is_subtechnique && <Chip>sub-technique</Chip>}</div>
            {e.aliases.length > 0 && <div className="flex flex-wrap items-center gap-1.5 text-xs text-mute">Aliases published by MITRE: {e.aliases.map((a) => <Chip key={a}>{a}</Chip>)}</div>}
            {e.tactics && e.tactics.length > 0 && <div className="flex flex-wrap items-center gap-1.5 text-xs text-mute">Tactics: {e.tactics.map((a) => <Chip key={a} tone="violet">{a}</Chip>)}{e.platforms && e.platforms.length > 0 && <span className="ml-2">Platforms: {e.platforms.join(', ')}</span>}</div>}
            {ref_.kind === 'campaign' && <div className="text-xs text-mute">Documented activity: <b className="text-ink">{period(e) ?? 'not documented'}</b></div>}
            <p className="whitespace-pre-line text-sm leading-relaxed text-ink">{e.description || 'No description published.'}</p>
            <div className="flex flex-wrap items-center gap-x-5 gap-y-1 text-xs text-mute">
              <span>Last updated by MITRE: <b className="text-ink">{day(e.modified) ?? '-'}</b></span><span>Created {day(e.created) ?? '-'}</span>
              {e.source && <span title={e.source.stix_id}>Imported {ago(e.source.imported_at)} · {e.source.dataset}</span>}<ExtLink href={e.url}>MITRE ATT&amp;CK page</ExtLink>
              <button onClick={() => onGraph(`attack:${e.id}`)} className="ml-auto flex items-center gap-1.5 rounded-lg border border-accent/30 bg-accent/10 px-3 py-1.5 text-accent hover:bg-accent/20"><Network size={13} /> Explore Relationships</button></div>
          </div>
          <div className="grid gap-5 xl:grid-cols-2">
            <div className="space-y-5">
              {ref_.kind === 'technique' && e.parent && <Rels title="Parent technique" items={[e.parent]} nav={nav} empty="" />}
              {ref_.kind === 'technique' && <Rels title="Sub-techniques" items={e.subtechniques} nav={nav} empty="No sub-techniques." />}
              {ref_.kind !== 'actor' && <Rels title="Groups" items={e.actors} nav={nav} empty={ref_.kind === 'campaign' ? 'MITRE documents no group attribution for this campaign.' : 'No group documented.'} />}
              {ref_.kind !== 'campaign' && <Rels title="Campaigns" items={e.campaigns} nav={nav} empty="No campaigns documented." />}
              {ref_.kind !== 'technique' && <Rels title="Techniques" items={e.techniques} nav={nav} empty="No techniques documented." />}
            </div>
            <div className="space-y-5">
              {(ref_.kind === 'actor' || ref_.kind === 'campaign' || ref_.kind === 'technique') && <Rels title="Malware & tools" items={e.software} nav={nav} empty="No malware or tools documented." />}
              {e.news && <News n={e.news} />}
              {e.references && (
                <section className={`${card} p-5`}>
                  <div className="mb-2 text-xs uppercase tracking-wider text-mute">References ({e.references.length})</div>
                  <ul className="space-y-1.5 text-xs">{e.references.map((r, i) => <li key={i} className="flex flex-wrap items-center gap-2"><span className="text-ink">{r.source_name}</span>{r.url ? <ExtLink href={r.url}>{r.url.length > 60 ? r.url.slice(0, 60) + '…' : r.url}</ExtLink> : <span className="text-mute">{r.description}</span>}</li>)}</ul>
                </section>
              )}
            </div>
          </div>
        </>
      )}
      {loading && e && <Loader2 size={14} className="animate-spin text-mute" />}
    </div>
  )
}

export default function AttackViews({ mode, stack, onNavigate, onBack, onGraph }: { mode: 'actors' | 'campaigns'; stack: AttackRef[]; onNavigate: Nav; onBack: () => void; onGraph: (nodeId: string) => void }) {
  const top = stack[stack.length - 1]
  if (top) return <Detail key={`${top.kind}:${top.id}`} ref_={top} nav={onNavigate} onBack={onBack} onGraph={onGraph} />
  return mode === 'actors' ? <ActorsList nav={onNavigate} /> : <CampaignsList nav={onNavigate} />
}
