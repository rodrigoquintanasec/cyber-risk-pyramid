import { useState } from 'react'
import { cAnalytics, STATUS_LABEL, type Cmp } from '../../data/company'
import { Columns, HBars, Legend, LineChart, colorOf } from '../analytics/charts'
import { CmpBadge } from '../analytics/shared'
import { Chip, Note, Segmented, Status, card, fmt, sel, useAsync } from '../intel/ui'
import { ChangesPanel } from './Overview'
import { ScopeTag, StatusBadge } from './common'

const Head = ({ title, sub, scope }: { title: string; sub?: string; scope?: string }) => <div className="mb-3"><div className="flex items-center gap-2"><h3 className="text-sm font-semibold text-ink">{title}</h3>{scope && <ScopeTag scope={scope} />}</div>{sub && <p className="mt-0.5 text-xs text-mute">{sub}</p>}</div>

export default function CompanyAnalytics({ id }: { id: string }) {
  const [period, setPeriod] = useState('30d')
  const [mode, setMode] = useState('all')
  const today = new Date().toISOString().slice(0, 10)
  const [from, setFrom] = useState(new Date(Date.now() - 13 * 864e5).toISOString().slice(0, 10))
  const [to, setTo] = useState(today)
  const custom = period === 'custom' ? { date_from: from, date_to: to } : undefined
  const { data, loading, error, reload } = useAsync(() => cAnalytics(id, { period, mode, ...custom }), [id, period, mode, from, to])
  const d = data
  const hourly = (d?.filters.bucket_hours ?? 24) === 1
  const cmp = (c: Cmp) => <CmpBadge c={c} />
  return (
    <div className="space-y-4 p-6">
      <div className="flex flex-wrap items-center gap-3">
        <Segmented options={[['24h', '24 h'], ['7d', '7 days'], ['30d', '30 days'], ['90d', '90 days'], ['custom', 'Custom']]} value={period} onChange={setPeriod} />
        {period === 'custom' && <div className="flex items-center gap-2 text-xs text-mute"><input type="date" value={from} max={to} onChange={(e) => setFrom(e.target.value)} className={sel} aria-label="From" />→<input type="date" value={to} min={from} max={today} onChange={(e) => setTo(e.target.value)} className={sel} aria-label="To" /><span>max 90 days</span></div>}
        <div className="ml-auto flex items-center gap-2 text-xs text-mute">Coverage mode<Segmented options={[['all', 'All Available Sources'], ['comparable', 'Comparable Sources']]} value={mode} onChange={setMode} /></div>
      </div>
      <Status loading={loading && !d} error={error} onRetry={reload} />
      {d?.status === 'insufficient_comparable' && <Note tone="warn"><b>{d.message}.</b> Only {d.filters.comparable?.count ?? 0} source(s) can be shown to cover both periods. Switch to All Available Sources to see the data with coverage warnings.</Note>}
      {d?.status === 'ok' && (
        <>
          <div className={`${card} p-5`}>
            <Head title="Threat Intelligence Timeline" scope="attention" sub="Distinct news events and official advisory publications about the company's catalogue technologies" />
            <div className="mb-1 flex items-center gap-3 text-xs text-mute">Events in period: <b className="text-ink">{d.timeline.compare.current}</b>{cmp(d.timeline.compare)}</div>
            <LineChart labels={d.timeline.bucket_starts} hourly={hourly} height={200} series={[{ name: 'Events', color: '#22D3EE', values: d.timeline.events }, { name: 'Articles', color: '#F97316', values: d.timeline.articles, dashed: true }, { name: 'Official advisory articles', color: '#A78BFA', values: d.timeline.official_advisory_articles }]} />
            <div className="mt-1"><Legend items={[{ name: 'Events', color: '#22D3EE' }, { name: 'Articles', color: '#F97316', dashed: true }, { name: 'Official advisories', color: '#A78BFA' }]} /></div>
          </div>
          <div className="grid gap-4 xl:grid-cols-2">
            <div className={`${card} p-5`}>
              <Head title="Vulnerability Discovery Trends" scope="signal" sub={d.discovery.note} />
              <div className="mb-1 flex items-center gap-3 text-xs text-mute">New related CVEs: <b className="text-ink">{d.discovery.compare.current}</b>{cmp(d.discovery.compare)}</div>
              <Columns labels={d.discovery.bucket_starts} values={d.discovery.new_cves} line={d.discovery.kev_related_new} hourly={hourly} unit="new CVEs" lineUnit="in KEV" />
            </div>
            <div className={`${card} p-5`}>
              <Head title="KEV Watch" scope="signal" sub={d.kev_watch.note} />
              <div className="mb-2 flex items-center gap-3 text-xs text-mute">Added to KEV in period: <b className="text-ink">{d.kev_watch.compare.current}</b>{cmp(d.kev_watch.compare)}<span>· {d.kev_watch.total_related} related in KEV overall</span></div>
              {d.kev_watch.added.length === 0 ? <div className="py-4 text-center text-xs text-mute">No related CVE was added to KEV in this period.</div> :
                <ul className="space-y-1.5 text-xs">{d.kev_watch.added.slice(0, 8).map((k) => <li key={k.cve} className="flex flex-wrap items-center gap-2"><Chip tone="red">{k.cve}</Chip><span className="text-mute">added {k.kev_added}</span><span className="text-mute">{k.products.join(', ')}</span><span className="ml-auto"><StatusBadge s={k.status} auto /></span></li>)}</ul>}
            </div>
          </div>
          <div className="grid gap-4 xl:grid-cols-2">
            <div className={`${card} p-5`}>
              <Head title="Technology Media Attention" scope="attention" sub="Distinct events per technology (not a risk level)" />
              <HBars items={d.attention.map((a) => ({ label: a.name, value: a.events, sub: <CmpBadge c={a.compare} /> }))} empty="No related news events in this period." />
            </div>
            <div className={`${card} p-5`}>
              <Head title="Exposure Assessment Status" scope="potential" sub={`${d.exposure_status.related} unique related CVEs · ${d.exposure_status.unassessed} not yet assessable`} />
              <ul className="space-y-1.5 text-xs">{Object.entries(d.exposure_status.current).map(([k, v]) => <li key={k} className="flex items-center gap-2"><StatusBadge s={k} /><span className="ml-auto tabular-nums text-ink">{v}</span></li>)}</ul>
              {d.exposure_status.history.length >= 2 && <div className="mt-3"><LineChart labels={d.exposure_status.history.map((h) => h.taken_at)} hourly height={140} series={['potentially_applicable', 'confirmed_applicable', 'needs_review'].map((k, i) => ({ name: STATUS_LABEL[k], color: colorOf(i), values: d.exposure_status.history.map((h) => Number(h[k] ?? 0)) }))} /></div>}
              {d.exposure_status.history_note && <div className="mt-2 text-[11px] text-mute">{d.exposure_status.history_note}</div>}
            </div>
          </div>
          <div className={`${card} p-5`}>
            <Head title="Inventory Data Quality" scope="coverage" sub="Completeness of the manual inventory" />
            <div className="grid gap-5 md:grid-cols-3">
              <div><div className="mb-1 text-[11px] uppercase tracking-wider text-mute">Version known (assets per product)</div><HBars color="#34D399" items={d.inventory_quality.by_technology.map((t) => ({ label: t.label, value: t.assets ? Math.round((100 * t.with_version) / t.assets) : 0, id: t.label }))} unit="%" /></div>
              <div><div className="mb-1 text-[11px] uppercase tracking-wider text-mute">Verification age</div><HBars color="#A78BFA" items={Object.entries(d.inventory_quality.verification_age).map(([k, v]) => ({ label: k, value: v }))} empty="No active assets." /></div>
              <div className="text-xs text-mute"><div className="mb-1 text-[11px] uppercase tracking-wider">Inventory changes in period</div>{d.inventory_quality.inventory_changes.length ? d.inventory_quality.inventory_changes.map((c) => <div key={c.kind} className="flex justify-between"><span>{c.kind.replace('_', ' ')}</span><span className="text-ink">{c.n}</span></div>) : 'None recorded.'}
                <div className="mt-3">Median verification age: <b className="text-ink">{d.inventory_quality.coverage.median_verification_age_days ?? 'N/A'}</b> days</div></div>
            </div>
          </div>
          <div className={`${card} p-5`}>
            <Head title="EPSS movement" scope="signal" sub={d.epss.note} />
            {d.epss.available && d.epss.movers.length > 0 ? <ul className="space-y-1 text-xs">{d.epss.movers.map((m) => <li key={m.cve} className="flex gap-3"><span className="text-ink">{m.cve}</span><span className="text-mute">{(m.from * 100).toFixed(1)}% → {(m.to * 100).toFixed(1)}%</span><span className={m.delta > 0 ? 'text-orange-300' : 'text-emerald-300'}>{m.delta > 0 ? '+' : ''}{(m.delta * 100).toFixed(1)} pts</span></li>)}</ul> : <div className="text-xs text-mute">{d.epss.available ? 'No EPSS movement ≥ 5 points between the latest snapshots.' : 'Not available yet.'}</div>}
            <div className="mt-2 text-[11px] text-mute">{d.snapshots.count} snapshot(s) recorded{d.snapshots.first ? ` since ${fmt(d.snapshots.first)}` : ''}. No earlier history exists or is fabricated.</div>
          </div>
          <ChangesPanel id={id} period={period} custom={custom} />
          <Note>{d.notes.join(' ')}</Note>
        </>
      )}
    </div>
  )
}
