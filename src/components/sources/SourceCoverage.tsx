import { useState } from 'react'
import { adminCoverage, adminOnboarding, startBatch, STATE_LABEL, STATE_TONE, type CoverageRow } from '../../data/sourceAdmin'
import { ago } from '../IntelligenceFeed'
import { btn, btn2 } from '../company/common'
import { Note, Status, card, fmt, useAsync } from '../intel/ui'

function Bars({ title, data, top = 12 }: { title: string; data: Record<string, number>; top?: number }) {
  const rows = Object.entries(data).sort((a, b) => b[1] - a[1]).slice(0, top)
  const max = Math.max(1, ...rows.map((r) => r[1]))
  return (
    <div className={`${card} p-4`}><div className="mb-2 text-[11px] font-semibold uppercase tracking-wider text-mute">{title}</div>
      <ul className="space-y-1">{rows.map(([k, n]) => <li key={k} className="flex items-center gap-2 text-xs"><span className="w-28 shrink-0 truncate text-ink" title={k}>{k}</span><span className="h-2 flex-1 rounded bg-bg"><span className="block h-2 rounded bg-accent/60" style={{ width: `${(n / max) * 100}%` }} /></span><span className="w-8 text-right tabular-nums text-mute">{n}</span></li>)}</ul></div>
  )
}
const Row = ({ s }: { s: CoverageRow }) => <tr className="border-t border-line/60"><td className="py-1.5 pr-3 text-ink">{s.name}</td><td className="pr-3 text-mute">{s.category ?? '—'}</td><td className="pr-3 tabular-nums text-mute">{s.articles_30d}</td><td className="pr-3 text-mute">{s.latest_publication ? ago(s.latest_publication) : 'unknown'}</td><td className="text-red-300">{s.error ?? ''}</td></tr>

export function SourceCoverage() {
  const { data, loading, error, reload } = useAsync(adminCoverage, [])
  if (!data) return <Status loading={loading} error={error} onRetry={reload} />
  const ind = data.indicators
  return (
    <div className="space-y-4">
      <Note>{data.note}</Note>
      <div className="grid grid-cols-2 gap-3 md:grid-cols-5">{([['Sources', ind.total], ['Operational', data.operational], ['Failed', data.failed.length], ['No recent activity', data.no_recent_activity.length], ['Last sync', ind.last_successful_sync ? ago(ind.last_successful_sync) : 'never']] as [string, string | number][]).map(([l, v]) =>
        <div key={l} className={`${card} px-4 py-3`}><div className="text-[11px] uppercase tracking-wider text-mute">{l}</div><div className="text-2xl font-semibold tabular-nums text-ink">{v}</div></div>)}</div>
      <div className="grid gap-3 lg:grid-cols-3"><Bars title="Sources by category" data={data.by_category} /><Bars title="Sources by country" data={data.by_country} /><Bars title="Sources by language" data={data.by_language} /></div>
      {data.failed.length > 0 && <div className={`${card} p-4`}><div className="mb-2 text-sm font-semibold text-red-300">Failed sources ({data.failed.length})</div><table className="w-full text-left text-xs"><thead className="text-mute"><tr><th>Source</th><th>Category</th><th>30 d</th><th>Newest</th><th>Error</th></tr></thead><tbody>{data.failed.map((s) => <Row key={s.id} s={s} />)}</tbody></table></div>}
      {data.no_recent_activity.length > 0 && <div className={`${card} p-4`}><div className="mb-1 text-sm font-semibold text-ink">No recent activity ({data.no_recent_activity.length})</div><p className="mb-2 text-[11px] text-mute">Working feeds that published nothing in 7 days (and nothing newer than 14 days): possibly dormant, not failed.</p><table className="w-full text-left text-xs"><thead className="text-mute"><tr><th>Source</th><th>Category</th><th>30 d</th><th>Newest</th><th /></tr></thead><tbody>{data.no_recent_activity.slice(0, 40).map((s) => <Row key={s.id} s={s} />)}</tbody></table></div>}
      <div className={`${card} overflow-x-auto p-4`}><div className="mb-2 text-sm font-semibold text-ink">Publications per source (top 40, last 30 days)</div>
        <table className="w-full min-w-[640px] text-left text-xs"><thead className="text-mute"><tr><th>Source</th><th>State</th><th>7 d</th><th>30 d</th><th>Total</th><th>Last sync</th><th>Newest</th></tr></thead>
          <tbody>{data.sources.slice(0, 40).map((s) => <tr key={s.id} className="border-t border-line/60"><td className="py-1.5 text-ink">{s.name}</td><td><span className={`rounded-full border px-1.5 py-0.5 text-[10px] ${STATE_TONE[s.state] ?? ''}`}>{STATE_LABEL[s.state] ?? s.state}</span></td><td className="tabular-nums text-mute">{s.articles_7d}</td><td className="tabular-nums text-mute">{s.articles_30d}</td><td className="tabular-nums text-mute">{s.articles_total}</td><td className="text-mute" title={fmt(s.last_success)}>{s.last_success ? ago(s.last_success) : 'never'}</td><td className="text-mute">{s.latest_publication ? ago(s.latest_publication) : '—'}</td></tr>)}</tbody></table></div>
    </div>
  )
}

export function SourceOnboarding() {
  const { data, loading, error, reload } = useAsync(adminOnboarding, [])
  const [msg, setMsg] = useState<string | null>(null)
  const [err, setErr] = useState<string | null>(null)
  if (!data) return <Status loading={loading} error={error} onRetry={reload} />
  const go = (n: number) => { setErr(null); startBatch(n).then(() => { setMsg(`Batch ${n} started: validating, enabling the verified sources and running one controlled sync…`); setTimeout(reload, 4000) }).catch((e) => setErr(String(e.message))) }
  return (
    <div className="space-y-4">
      <Note>Catalogue sources are added in batches, never all at once. Each batch re-validates its feeds, enables only the verified ones, runs one controlled sync (newest entries per source, no history flood) and records errors, duplicates and SQLite lock waits. {data.rule}</Note>
      {msg && <Note>{msg}</Note>}{err && <Note tone="warn">{err}</Note>}
      {data.running && <Note>Batch {data.current.batch} is running ({data.current.phase}).<button onClick={reload} className="ml-2 underline">refresh</button></Note>}
      <div className={`${card} overflow-x-auto`}><table className="w-full min-w-[760px] text-left text-sm"><thead className="border-b border-line text-xs uppercase tracking-wider text-mute"><tr><th className="px-4 py-3">Batch</th><th className="px-4 py-3">Sources</th><th className="px-4 py-3">Enabled</th><th className="px-4 py-3">Last run</th><th className="px-4 py-3">Result</th><th className="px-4 py-3" /></tr></thead>
        <tbody>{data.batches.map((b) => (
          <tr key={b.batch} className="border-b border-line/60 last:border-0"><td className="px-4 py-2.5 font-medium text-ink">Batch {b.batch}</td><td className="px-4 py-2.5 tabular-nums text-mute">{b.sources}</td><td className="px-4 py-2.5 tabular-nums text-mute">{b.enabled}</td>
            <td className="px-4 py-2.5 text-xs text-mute">{b.last_run ? `${b.last_run.status}${b.last_run.finished_at ? ` · ${ago(b.last_run.finished_at)}` : ''}` : 'not run'}</td>
            <td className="px-4 py-2.5 text-xs text-mute">{b.last_run ? `${b.last_run.ok} ok · ${b.last_run.failed} failed · ${b.last_run.new_items} new · ${b.last_run.duplicate_items} re-seen · max write wait ${b.last_run.max_write_wait ?? 0}s${b.last_run.note ? ` — ${b.last_run.note}` : ''}` : '—'}</td>
            <td className="px-4 py-2.5 text-right"><button disabled={data.running || (b.enabled >= b.sources && b.sources > 0)} onClick={() => go(b.batch)} className={b.last_run ? btn2 : btn}>{b.last_run ? 'Run again' : 'Enable batch'}</button></td></tr>))}</tbody></table></div>
    </div>
  )
}
