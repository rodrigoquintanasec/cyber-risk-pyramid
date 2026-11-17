import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { Layers, Loader2, Newspaper, Radio, Tags } from 'lucide-react'
import MetricCard from './MetricCard'
import { PyramidBase, type PyramidSpec } from './Pyramid'
import { SceneBase } from './Scene'
import NewsPanel from './newsdash/NewsPanel'
import { DashboardForm, ManageDashboards, ManageKeywords } from './newsdash/Manage'
import { Chip, Note, Segmented, sel } from './intel/ui'
import { btn, btn2 } from './company/common'
import { LEVEL_FALLBACK, fetchStats, listDashboards, updateDashboard, type DashList, type Dashboard, type KwStat, type Level, type Range, type Stats } from '../data/intelDash'

const STORE = 'newsdash.active'
const remembered = () => { try { return Number(localStorage.getItem(STORE)) || null } catch { return null } }
const remember = (id: number | null) => { try { if (id) localStorage.setItem(STORE, String(id)) } catch { /* storage may be unavailable */ } }
const today = () => new Date().toISOString().slice(0, 10)

/** Media-attention legend: colours are relative news coverage, never risk. */
function NewsLegend({ levels, text, method }: { levels: Level[]; text: string; method: string }) {
  return (
    <div className="absolute left-4 top-4 max-w-[calc(100%-2rem)] rounded-xl border border-line bg-surface/90 px-4 py-2.5 backdrop-blur sm:max-w-[34rem]" title={method}>
      <div className="flex flex-wrap items-center gap-x-4 gap-y-1">
        <span className="text-[10px] font-semibold uppercase tracking-wider text-mute">Media attention</span>
        {levels.map((l) => <span key={l.key} className="flex items-center gap-1.5 text-[11px] text-ink"><span className="h-2.5 w-2.5 shrink-0 rounded-sm" style={{ background: l.color, boxShadow: `0 0 8px ${l.color}66` }} />{l.label}</span>)}
      </div>
      <div className="mt-1 text-[10px] leading-snug text-mute">{text}</div>
    </div>
  )
}

function tooltipFor(k: KwStat, stats: Stats) {
  const lv = k.level
  return (
    <>
      <div className="text-xs font-semibold text-ink">{k.display_name}</div>
      <div className="mt-0.5 flex items-center gap-1.5 text-[11px] text-mute"><span className="h-1.5 w-1.5 rounded-full" style={{ background: lv?.color }} />{lv?.label}</div>
      <div className="mt-1 space-y-0.5 text-[11px] text-mute">
        <div>Articles <span className="font-semibold text-ink">{k.article_count}</span> · Unique events <span className="font-semibold text-ink">{k.unique_events}</span></div>
        <div>Sources <span className="font-semibold text-ink">{k.source_count}</span> · {stats.window.label}</div>
      </div>
    </>
  )
}

export default function NewsPyramids() {
  const [list, setList] = useState<DashList | null>(null)
  const [listErr, setListErr] = useState<string | null>(null)
  const [sel1, setSel1] = useState<{ id: number | null; period: string; start: string; end: string }>({ id: null, period: '7d', start: '', end: '' })
  const [stats, setStats] = useState<Stats | null>(null)
  const [loading, setLoading] = useState(false)
  const [err, setErr] = useState<string | null>(null)
  const [kid, setKid] = useState<number | null>(null)
  const [modal, setModal] = useState<null | 'new' | 'manage' | 'keywords' | { edit: Dashboard }>(null)
  const [tick, setTick] = useState(0)
  const [saved, setSaved] = useState<string | null>(null)
  const reqId = useRef(0)

  const loadList = useCallback((openId?: number) => listDashboards().then((l) => {
    setList(l); setListErr(null)
    setSel1((s) => {
      const want = openId ?? s.id ?? remembered()
      const d = l.items.find((x) => x.id === want) ?? l.items[0] ?? null
      if (!d) return { id: null, period: '7d', start: '', end: '' }
      if (d.id === s.id && openId === undefined) return s
      return { id: d.id, period: d.default_period, start: '', end: '' }
    })
  }).catch((e) => setListErr(String(e.message))), [])
  useEffect(() => { loadList() }, [loadList])
  useEffect(() => { remember(sel1.id) }, [sel1.id])

  const dash = list?.items.find((d) => d.id === sel1.id) ?? null
  const customOk = sel1.period !== 'custom' || (/^\d{4}-\d{2}-\d{2}$/.test(sel1.start) && /^\d{4}-\d{2}-\d{2}$/.test(sel1.end) && sel1.start <= sel1.end)
  const range: Range = { period: sel1.period, start: sel1.start, end: sel1.end }

  // one request per (dashboard, period, range): switching dashboards sets id + default period together, so it never fires twice
  useEffect(() => {
    if (!sel1.id || !customOk) return
    const my = ++reqId.current
    setLoading(true)
    fetchStats(sel1.id, { period: sel1.period, start: sel1.start, end: sel1.end })
      .then((s) => { if (my === reqId.current) { setStats(s); setErr(null) } })
      .catch((e) => { if (my === reqId.current) setErr(String(e.message)) })
      .finally(() => { if (my === reqId.current) setLoading(false) })
  }, [sel1.id, sel1.period, sel1.start, sel1.end, customOk, tick])
  useEffect(() => { const t = setInterval(() => setTick((x) => x + 1), 120_000); return () => clearInterval(t) }, [])
  useEffect(() => { if (stats && kid !== null && !stats.keywords.some((k) => k.id === kid && k.enabled)) setKid(null) }, [stats, kid])
  useEffect(() => { setStats(null); setKid(null) }, [sel1.id])

  const pyramids = useMemo(() => (stats?.keywords ?? []).filter((k) => k.enabled).map((k) => ({ id: String(k.id), k })), [stats])
  const max = Math.max(1, ...pyramids.map((p) => p.k.article_count ?? 0))
  const selected = stats?.keywords.find((k) => k.id === kid && k.enabled) ?? null
  const specFor = (k: KwStat): PyramidSpec => ({ id: String(k.id), label: k.display_name, sublabel: `${k.article_count ?? 0} article${k.article_count === 1 ? '' : 's'}`, color: k.level?.color ?? '#6B7280', heightFactor: 0.85 + ((k.article_count ?? 0) / max) * 0.3, tooltip: tooltipFor(k, stats!) })

  const pick = (id: number) => { const d = list?.items.find((x) => x.id === id); if (d) setSel1({ id, period: d.default_period, start: '', end: '' }) }
  const setPeriod = (p: string) => setSel1((s) => ({ ...s, period: p, start: p === 'custom' && !s.start ? new Date(Date.now() - 7 * 864e5).toISOString().slice(0, 10) : s.start, end: p === 'custom' && !s.end ? today() : s.end }))
  const saveDefault = () => dash && updateDashboard(dash.id, { default_period: sel1.period }).then(() => { setSaved('Saved as the default period'); setTimeout(() => setSaved(null), 2500); loadList() }).catch((e) => setErr(String(e.message)))
  const refreshAfterEdit = (openId?: number) => { loadList(openId); setTick((x) => x + 1) }
  const levels = stats?.scale.levels ?? LEVEL_FALLBACK
  const cov = stats?.coverage

  if (listErr) return <div className="p-6"><Note tone="warn">Could not load the dashboards ({listErr}).</Note></div>
  if (!list) return <div className="flex items-center justify-center gap-2 p-16 text-sm text-mute"><Loader2 size={16} className="animate-spin" /> Loading…</div>

  return (
    <div className="flex min-h-0 flex-1">
      <main className="flex min-w-0 flex-1 flex-col gap-4 p-6">
        <div className="flex flex-wrap items-center gap-3">
          <select value={sel1.id ?? ''} onChange={(e) => pick(Number(e.target.value))} disabled={list.items.length === 0} aria-label="Saved dashboard" className={`${sel} min-w-[14rem]`}>
            {list.items.length === 0 && <option value="">No dashboards yet</option>}
            {list.items.map((d) => <option key={d.id} value={d.id}>{d.name} ({d.keyword_count})</option>)}</select>
          <button onClick={() => setModal('new')} className={btn}>New Dashboard</button>
          <button onClick={() => setModal('manage')} className={btn2}>Manage Dashboards</button>
          <button onClick={() => setModal('keywords')} disabled={!dash} className={btn2}>Manage Keywords</button>
          <span className="ml-auto" />
          <Segmented options={[['24h', '24h'], ['48h', '48h'], ['7d', '7d'], ['30d', '30d'], ['90d', '90d'], ['custom', 'Custom']]} value={sel1.period} onChange={setPeriod} />
        </div>
        {dash && (
          <div className="flex flex-wrap items-center gap-3 text-xs text-mute">
            {dash.description && <span className="text-ink/80">{dash.description}</span>}
            {sel1.period === 'custom' && <span className="flex items-center gap-1.5">From <input type="date" value={sel1.start} max={sel1.end || today()} onChange={(e) => setSel1((s) => ({ ...s, start: e.target.value }))} aria-label="Start date (UTC)" className={`${sel} py-1`} />
              to <input type="date" value={sel1.end} min={sel1.start} max={today()} onChange={(e) => setSel1((s) => ({ ...s, end: e.target.value }))} aria-label="End date (UTC)" className={`${sel} py-1`} /></span>}
            {stats && <span>Period used: <b className="text-ink">{stats.window.label}</b> · {stats.window.effective}</span>}
            {sel1.period !== dash.default_period && sel1.period !== 'custom' && <button onClick={saveDefault} className="rounded border border-line px-2 py-0.5 text-accent hover:border-accent/40">Save as default period</button>}
            {saved && <span className="text-emerald-300">{saved}</span>}
          </div>
        )}
        {err && <Note tone="warn">{err}</Note>}
        {sel1.period === 'custom' && !customOk && <Note tone="warn">Choose a valid start and end date (UTC, start not after end).</Note>}

        <div className="grid grid-cols-2 gap-4 xl:grid-cols-4">
          <MetricCard label="Keywords Monitored" value={stats?.totals.keywords_monitored ?? '–'} icon={Tags} />
          <MetricCard label="Matching Articles" value={stats?.totals.matching_articles ?? '–'} icon={Newspaper} tone="#F97316" hint="Unique articles across all pyramids" />
          <MetricCard label="Unique Events" value={stats?.totals.unique_events ?? '–'} icon={Layers} tone="#A78BFA" hint="Same story from many outlets = 1 event" />
          <MetricCard label="Contributing Sources" value={stats?.totals.contributing_sources ?? '–'} icon={Radio} tone="#34D399" />
        </div>
        {cov && cov.status !== 'sufficient' && <Note tone="warn"><b>{cov.label}.</b> {cov.warnings.join(' ')} {cov.status === 'insufficient' ? 'Zero here does not mean there was no news: the feed does not hold enough reliable data for this period.' : ''}</Note>}
        {cov && cov.status === 'sufficient' && cov.warnings.length > 0 && <Note>{cov.warnings.join(' ')}</Note>}
        {stats?.events_note && <div className="text-[11px] text-mute">{stats.events_note}</div>}

        <div className="relative min-h-[420px] flex-1 overflow-hidden rounded-xl border border-line bg-bg">
          {list.items.length === 0 ? (
            <div className="flex h-full flex-col items-center justify-center gap-3 p-8 text-center"><div className="text-sm text-ink">No custom dashboards yet</div><p className="max-w-md text-xs text-mute">Create a dashboard, add the keywords you want to follow (for example “Ransomware”, “LockBit”) and each one becomes a 3D pyramid coloured by how much news coverage it received.</p><button onClick={() => setModal('new')} className={btn}>Create your first dashboard</button></div>
          ) : dash && dash.keyword_count === 0 ? (
            <div className="flex h-full flex-col items-center justify-center gap-3 p-8 text-center"><div className="text-sm text-ink">“{dash.name}” has no keywords</div><button onClick={() => setModal('keywords')} className={btn}>Add keywords</button></div>
          ) : pyramids.length === 0 && stats ? (
            <div className="flex h-full items-center justify-center p-8 text-center text-sm text-mute">All keywords of this dashboard are disabled. Enable one in Manage Keywords.</div>
          ) : stats ? (
            <>
              <SceneBase items={pyramids} cols={pyramids.length <= 4 ? Math.max(1, pyramids.length) : 3} selectedId={kid === null ? null : String(kid)} onSelect={(id) => setKid(id === null ? null : Number(id))}
                renderItem={(p, position, selected1, dimmed) => <PyramidBase key={p.id} spec={specFor(p.k)} position={position} selected={selected1} dimmed={dimmed} onSelect={() => setKid(p.k.id)} />} />
              <NewsLegend levels={levels.filter((l) => l.key !== 'insufficient' || cov?.status === 'insufficient')} text={stats.scale.legend} method={stats.scale.method} />
              <div className="pointer-events-none absolute bottom-3 right-4 text-[11px] text-mute">Drag to rotate · Scroll to zoom · Click a pyramid</div>
              {loading && <div className="absolute bottom-3 left-4 flex items-center gap-1.5 rounded-lg border border-line bg-surface/90 px-2.5 py-1 text-[11px] text-mute"><Loader2 size={12} className="animate-spin" /> Updating…</div>}
            </>
          ) : <div className="flex h-full items-center justify-center gap-2 text-sm text-mute"><Loader2 size={16} className="animate-spin" /> Loading statistics…</div>}
        </div>
        {selected && stats && <div className="flex flex-wrap gap-1.5 text-[11px]"><Chip>Selected: {selected.display_name}</Chip></div>}
      </main>
      {selected && dash && cov && <NewsPanel key={dash.id} dashId={dash.id} kw={selected} range={range} coverage={cov} onClose={() => setKid(null)} />}
      {modal === 'new' && <DashboardForm list={list} onClose={() => setModal(null)} onSaved={(d) => { setModal(null); refreshAfterEdit(d.id) }} />}
      {modal === 'manage' && <ManageDashboards list={list} activeId={sel1.id} onClose={() => setModal(null)} onChanged={refreshAfterEdit} onOpen={pick} onEdit={(d) => setModal({ edit: d })} />}
      {modal === 'keywords' && dash && <ManageKeywords dash={dash} list={list} onClose={() => setModal(null)} onChanged={() => refreshAfterEdit()} />}
      {typeof modal === 'object' && modal && 'edit' in modal && <DashboardForm list={list} edit={modal.edit} onClose={() => setModal(null)} onSaved={() => { setModal(null); refreshAfterEdit() }} />}
    </div>
  )
}
