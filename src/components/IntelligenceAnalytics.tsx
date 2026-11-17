import { useState } from 'react'
import { Activity, BarChart3, Bug, Building2, Flame, Gauge, Network, ShieldCheck } from 'lucide-react'
import { DEFAULT_FILTERS, aMeta, aOverview, type AFilters } from '../data/analytics'
import { Note, Segmented, Status, Tabs, card, fmt, sel, useAsync } from './intel/ui'
import { EmergingPanel, EntitiesPanel, TrendsPanel, VulnPanel } from './analytics/Panels'
import { AttackPanel, QualityPanel } from './analytics/Panels2'
import { CmpBadge, PERIOD_LABEL, periodText, type Nav } from './analytics/shared'

type Tab = 'trends' | 'vulns' | 'entities' | 'emerging' | 'attack' | 'quality'
const TABS: { id: Tab; label: string; icon: typeof Activity }[] = [
  { id: 'trends', label: 'Threat Trends', icon: BarChart3 },
  { id: 'vulns', label: 'Vulnerability Intelligence', icon: Bug },
  { id: 'entities', label: 'Vendors & Technologies', icon: Building2 },
  { id: 'emerging', label: 'Emerging Stories', icon: Flame },
  { id: 'attack', label: 'MITRE ATT&CK', icon: Network },
  { id: 'quality', label: 'Coverage & Quality', icon: Gauge },
]
const SCOPE: Record<string, string> = { news: 'text-accent', vulnerability: 'text-orange-300', quality: 'text-emerald-300' }
const COV: Record<string, string> = { complete: 'border-emerald-400/30 bg-emerald-400/10 text-emerald-300', partial: 'border-amber-400/30 bg-amber-400/10 text-amber-300', degraded: 'border-red-400/30 bg-red-400/10 text-red-300', insufficient: 'border-line text-mute' }

export default function IntelligenceAnalytics({ nav }: { nav: Nav }) {
  const [f, setF] = useState<AFilters>(DEFAULT_FILTERS)
  const [tab, setTab] = useState<Tab>('trends')
  const meta = useAsync(aMeta, [])
  const ov = useAsync(() => aOverview(f), [JSON.stringify(f)])
  const set = (p: Partial<AFilters>) => setF((x) => ({ ...x, ...p }))
  const m = meta.data
  const o = ov.data
  const today = new Date().toISOString().slice(0, 10)
  const cov = o?.coverage ?? m?.coverage
  return (
    <div className="space-y-4 p-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h2 className="text-base font-semibold text-ink">Intelligence Analytics</h2>
          <p className="text-xs text-mute">Threat intelligence trends &amp; coverage analysis · counts describe media coverage and distinct events, not real incidents</p>
        </div>
        <div className="flex flex-wrap items-center gap-2 text-xs text-mute">
          <span>Updated {fmt(m?.generated_at)} UTC</span>
          {cov && <span className={`flex items-center gap-1.5 rounded-full border px-2.5 py-1 ${COV[cov.status]}`} title={cov.failed_sources.join(', ') || 'No failing enabled source'}><ShieldCheck size={12} /> Coverage: {cov.status} · {cov.operational}/{cov.enabled} sources operational{cov.failed ? ` · ${cov.failed} failed` : ''}{cov.quiet ? ` · ${cov.quiet} quiet` : ''}</span>}
        </div>
      </div>

      <div className={`${card} space-y-3 p-4`}>
        <div className="flex flex-wrap items-center gap-3">
          <Segmented options={[['24h', '24 h'], ['7d', '7 days'], ['30d', '30 days'], ['90d', '90 days'], ['custom', 'Custom']]} value={f.period} onChange={(v) => set({ period: v, ...(v === 'custom' && !f.date_from ? { date_from: new Date(Date.now() - 6 * 864e5).toISOString().slice(0, 10), date_to: today } : {}) })} />
          {f.period === 'custom' && (
            <div className="flex items-center gap-2 text-xs text-mute">
              <input type="date" value={f.date_from ?? ''} max={f.date_to ?? today} onChange={(e) => set({ date_from: e.target.value })} className={sel} aria-label="From" />→
              <input type="date" value={f.date_to ?? ''} min={f.date_from} max={today} onChange={(e) => set({ date_to: e.target.value })} className={sel} aria-label="To" />
              <span>max {m?.max_range_days ?? 90} days</span>
            </div>
          )}
          <div className="ml-auto flex items-center gap-2"><span className="text-xs text-mute">Coverage mode</span>
            <Segmented options={[['all', 'All Available Sources'], ['comparable', 'Comparable Sources']]} value={f.mode} onChange={(v) => set({ mode: v as AFilters['mode'] })} /></div>
        </div>
        <div className="flex flex-wrap gap-3">
          <select value={f.category ?? ''} onChange={(e) => set({ category: e.target.value || undefined })} className={sel} aria-label="Category"><option value="">All categories</option>{(m?.categories ?? []).map((c) => <option key={c}>{c}</option>)}</select>
          <select value={f.source ?? ''} onChange={(e) => set({ source: e.target.value || undefined })} className={`${sel} max-w-[220px]`} aria-label="Source"><option value="">All sources</option>{(m?.sources ?? []).filter((s) => s.enabled).map((s) => <option key={s.id} value={s.id}>{s.name}</option>)}</select>
          <select value={f.vendor ?? ''} onChange={(e) => set({ vendor: e.target.value || undefined })} className={`${sel} max-w-[200px]`} aria-label="Vendor"><option value="">All vendors</option>{(m?.vendors ?? []).map((v) => <option key={v}>{v}</option>)}</select>
          <select value={f.tech ?? ''} onChange={(e) => set({ tech: e.target.value || undefined })} className={`${sel} max-w-[200px]`} aria-label="Technology"><option value="">All technologies</option>{(m?.technologies ?? []).map((t) => <option key={t.id} value={t.id}>{t.name}</option>)}</select>
          {(f.category || f.source || f.vendor || f.tech) && <button onClick={() => set({ category: undefined, source: undefined, vendor: undefined, tech: undefined })} className="text-xs text-accent hover:underline">Clear filters</button>}
        </div>
        {o && <div className="text-[11px] text-mute">{PERIOD_LABEL[f.period]} · {periodText(o.filters)}</div>}
      </div>

      {f.mode === 'comparable' && o?.filters.comparable && (
        o.status === 'insufficient_comparable'
          ? <Note tone="warn"><b>Insufficient comparable coverage.</b> Only {o.filters.comparable.count} source(s) can be shown to have been collected across both periods (minimum 3). Excluded: {Object.entries(o.filters.comparable.excluded_reasons).map(([k, v]) => `${v} ${k}`).join(', ') || 'none'}. Criteria: {o.filters.comparable.criteria.join('; ')}.</Note>
          : <Note>Comparable Sources: {o.filters.comparable.count} source(s) with demonstrable history in both periods ({o.filters.comparable.excluded} excluded). This reduces coverage bias but does not turn article counts into real incident rates.</Note>
      )}
      {f.mode === 'all' && o?.assessment?.coverage_changed && <Note tone="warn">Coverage changed between periods: {o.assessment.late_sources} of {o.assessment.contributing} contributing sources were first collected after the previous period began, so differences may reflect new sources rather than activity. Percentages are withheld; use Comparable Sources for a fairer comparison.</Note>}
      {f.mode === 'all' && o?.assessment && !o.assessment.history_ok && <Note tone="warn">The previous period has too little data ({o.assessment.previous_articles} dated articles) for a comparison.</Note>}

      <Status loading={ov.loading && !o} error={ov.error} onRetry={ov.reload} />
      {o && o.kpis.length > 0 && (
        <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
          {o.kpis.map((k) => (
            <div key={k.key} className={`${card} px-4 py-3`}>
              <div className="flex items-center justify-between gap-2"><div className="text-[11px] uppercase tracking-wider text-mute">{k.label}</div><span className={`text-[9px] uppercase tracking-wider ${SCOPE[k.scope]}`}>{k.scope === 'news' ? 'news' : k.scope === 'vulnerability' ? 'CVE' : 'quality'}</span></div>
              <div className="mt-0.5 text-2xl font-semibold tabular-nums text-ink">{k.current === null ? 'N/A' : k.key === 'data_coverage' ? `${k.current}%` : k.current.toLocaleString()}</div>
              {k.key === 'data_coverage' ? <div className="text-[11px] leading-snug text-mute" title={k.reason ?? ''}>{k.reason}</div> : <CmpBadge c={k} />}
            </div>
          ))}
        </div>
      )}
      {o?.notes && <div className="text-[11px] text-mute">{o.notes.join(' ')}</div>}

      <div className="-mx-6"><Tabs tabs={TABS} value={tab} onChange={setTab} /></div>
      <div>
        {tab === 'trends' && <TrendsPanel f={f} nav={nav} />}
        {tab === 'vulns' && <VulnPanel f={f} nav={nav} />}
        {tab === 'entities' && <EntitiesPanel f={f} meta={m} nav={nav} />}
        {tab === 'emerging' && <EmergingPanel f={f} nav={nav} />}
        {tab === 'attack' && <AttackPanel f={f} nav={nav} />}
        {tab === 'quality' && <QualityPanel f={f} />}
      </div>
    </div>
  )
}
