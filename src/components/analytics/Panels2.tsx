import { useState } from 'react'
import { AlertTriangle, ExternalLink, Network } from 'lucide-react'
import { aAttack, aHistory, aQuality, aTechnique, type AFilters } from '../../data/analytics'
import { Chip, ExtLink, Note, Status, card, fmt, useAsync } from '../intel/ui'
import { Columns, HBars, Legend, LineChart, colorOf } from './charts'
import { periodText, type Nav } from './shared'

const key = (f: AFilters) => JSON.stringify(f)
const Head = ({ title, sub }: { title: string; sub?: string }) => <div className="mb-3"><h3 className="text-sm font-semibold text-ink">{title}</h3>{sub && <p className="mt-0.5 text-xs text-mute">{sub}</p>}</div>
const HEALTH_TONE: Record<string, string> = { healthy: 'text-emerald-300', quiet: 'text-sky-300', failed: 'text-red-300', disabled: 'text-mute', pending: 'text-mute' }

// ----------------------------------------------------------------------------- E. MITRE ATT&CK
export function AttackPanel({ f, nav }: { f: AFilters; nav: Nav }) {
  const { data, loading, error, reload } = useAsync(() => aAttack(f), [key(f)])
  const [pick, setPick] = useState<string | null>(null)
  const det = useAsync(() => (pick ? aTechnique(f, pick) : Promise.resolve(null)), [key(f), pick])
  const d = data
  const t = det.data
  return (
    <div className="space-y-4">
      <Status loading={loading && !d} error={error} onRetry={reload} />
      {d?.status === 'insufficient_comparable' && <div className="rounded-xl border border-amber-400/30 bg-amber-400/10 p-6 text-center text-sm text-amber-300">{d.message}</div>}
      {d?.status === 'ok' && (
        <>
          {!d.sufficient && (
            <div className="flex items-start gap-3 rounded-xl border border-amber-400/30 bg-amber-400/10 p-4 text-sm text-amber-300"><AlertTriangle size={16} className="mt-0.5 shrink-0" />
              <div><div className="font-medium">{d.insufficient_message}</div><div className="mt-0.5 text-xs text-amber-300/80">Only {d.articles_with_attack} of {d.articles_total} articles in this period write an ATT&CK technique id{d.coverage_pct !== null ? ` (${d.coverage_pct}%)` : ''}. Trends are not drawn and no technique is inferred from keywords.</div></div></div>
          )}
          <div className="grid gap-4 xl:grid-cols-2">
            <div className={`${card} p-5`}>
              <Head title="News Mentions: techniques" sub={`Explicit ids in titles/excerpts · ${d.technique_count} technique(s) · ${periodText(d.filters)}`} />
              <HBars items={d.techniques.slice(0, 15).map((x) => ({ label: `${x.id} ${x.name}`, value: x.articles, id: x.id, sub: `${x.events} ev.` }))} onClick={setPick} empty="No technique ids were mentioned in this period." />
            </div>
            <div className={`${card} p-5`}>
              <Head title="Mentions by ATT&CK tactic" sub="A technique mapped to several tactics counts under each." />
              <HBars color="#A78BFA" items={d.tactics.map((x) => ({ label: x.tactic, value: x.mentions }))} empty="No tactic data." />
            </div>
          </div>
          {d.trend && (
            <div className={`${card} p-5`}>
              <Head title="Mentions over time (top techniques)" sub="Daily articles that explicitly cite the technique." />
              <LineChart labels={d.trend.bucket_starts} hourly={d.filters.bucket_hours === 1} series={d.trend.series.map((s, i) => ({ name: `${s.id} ${s.name}`, color: colorOf(i), values: s.mentions }))} />
              <div className="mt-2"><Legend items={d.trend.series.map((s, i) => ({ name: `${s.id} ${s.name}`, color: colorOf(i) }))} /></div>
            </div>
          )}
          {pick && (
            <div className={`${card} p-5`}>
              <Status loading={det.loading && !t} error={det.error} />
              {t && (
                <div className="space-y-4">
                  <div className="flex flex-wrap items-center gap-2"><h3 className="text-sm font-semibold text-ink">{t.id} · {t.name}</h3>{t.tactics.map((x) => <Chip key={x} tone="violet">{x}</Chip>)}<ExtLink href={t.url}>MITRE</ExtLink>
                    {t.graph_node && <button onClick={() => nav.graph(t.graph_node!)} className="ml-auto flex items-center gap-1.5 rounded-lg border border-line px-3 py-1.5 text-xs text-ink hover:border-accent/40"><Network size={12} /> Relationship Graph</button>}</div>
                  <div className="grid gap-4 md:grid-cols-2">
                    <div className="rounded-lg border border-line p-4"><div className="mb-2 text-xs font-semibold uppercase tracking-wider text-accent">News Mentions</div>
                      <div className="mb-2 text-xs text-mute">{t.news_mentions.articles} article(s) cite this id in the selected period.</div>
                      <ul className="space-y-1 text-xs">{t.news_mentions.items.map((n) => <li key={n.url}><ExtLink href={n.url}>{n.title}</ExtLink><span className="ml-1 text-mute">· {n.source}</span></li>)}</ul>
                      <button onClick={() => nav.feed({ mitre: t.id })} className="mt-2 flex items-center gap-1 text-xs text-accent"><ExternalLink size={11} /> Open in Intelligence Feed</button></div>
                    <div className="rounded-lg border border-line p-4"><div className="mb-2 text-xs font-semibold uppercase tracking-wider text-violet-300">Documented Relationships (MITRE)</div>
                      <div className="mb-2 text-xs text-mute">{t.documented.note}</div>
                      <div className="mb-1 text-[11px] text-mute">Threat Actors ({t.documented.actor_total})</div><div className="mb-2 flex flex-wrap gap-1.5">{t.documented.actors.map((a) => <button key={a.id} onClick={() => nav.attack('actor', a.id)}><Chip tone="violet">{a.name}</Chip></button>)}</div>
                      <div className="mb-1 text-[11px] text-mute">Threat Campaigns ({t.documented.campaign_total})</div><div className="flex flex-wrap gap-1.5">{t.documented.campaigns.map((a) => <button key={a.id} onClick={() => nav.attack('campaign', a.id)}><Chip tone="violet">{a.name}</Chip></button>)}</div>
                      <button onClick={() => nav.attack('technique', t.id)} className="mt-3 flex items-center gap-1 text-xs text-accent"><ExternalLink size={11} /> Technique detail with all relationships</button></div>
                  </div>
                </div>
              )}
            </div>
          )}
          {d.notes && <Note>{d.notes.join(' ')} Catalogue: {d.catalog.source} {d.catalog.version} ({d.catalog.size} techniques).</Note>}
        </>
      )}
    </div>
  )
}

// ----------------------------------------------------------------------------- F. Coverage & quality
export function QualityPanel({ f }: { f: AFilters }) {
  const { data, loading, error, reload } = useAsync(() => aQuality(f), [key(f)])
  const hist = useAsync(aHistory, [])
  const d = data
  const m = d?.metrics
  const pct = (v: number | null | undefined) => (v === null || v === undefined ? 'N/A' : `${v}%`)
  const cards: [string, string | number, string?][] = m ? [
    ['Configured Sources', m.configured], ['Enabled Sources', m.enabled], ['Healthy Sources', m.healthy], ['Failed Sources', m.failed, m.failed ? 'text-red-300' : ''], ['Quiet Sources', m.quiet, 'text-sky-300'], ['Disabled Sources', m.disabled],
    ['Articles Without Publication Date', m.undated_articles], ['Unique Events', m.unique_events], ['Multi-Source Events', m.multi_source_events], ['Official Advisory Share', pct(m.official_share_pct)],
    ['CVE Extraction Coverage', pct(m.cve_extraction_pct)], ['ATT&CK Mapping Coverage', pct(m.attack_mapping_pct)], ['Duplicate Articles Prevented', 'Not tracked'],
  ] : []
  return (
    <div className="space-y-4">
      <Status loading={loading && !d} error={error} onRetry={reload} />
      {d?.status === 'insufficient_comparable' && <div className="rounded-xl border border-amber-400/30 bg-amber-400/10 p-4 text-sm text-amber-300">{d.message} — source health below is current-state only.</div>}
      {d && m && (
        <>
          <div className="grid grid-cols-2 gap-3 md:grid-cols-4 xl:grid-cols-7">
            {cards.map(([l, v, cls]) => <div key={l} className={`${card} px-4 py-3`}><div className="text-[11px] uppercase tracking-wider text-mute">{l}</div><div className={`text-xl font-semibold tabular-nums text-ink ${cls ?? ''}`}>{v}</div></div>)}
          </div>
          <Note>{d.duplicates.note}{d.duplicates.syncs_logged ? ` Sync log: ${d.duplicates.syncs_logged} sync(s) since ${fmt(d.duplicates.logging_since)}; ${d.duplicates.resighted_since_logging} already-stored articles re-seen (not duplicates).` : ''}</Note>
          <div className="grid gap-4 xl:grid-cols-2">
            <div className={`${card} p-5`}><Head title="Articles by source" sub={`Dated articles in the period · top ${d.charts.articles_by_source.length}`} /><HBars items={d.charts.articles_by_source.map((x) => ({ label: x.name, value: x.value }))} /></div>
            <div className={`${card} p-5`}><Head title="Events by category" sub="Distinct events (primary category)" /><HBars color="#F97316" items={d.charts.events_by_category.map((x) => ({ label: x.name, value: x.value }))} /></div>
            <div className={`${card} p-5`}><Head title="Source type distribution" sub="Articles by type of publisher" /><HBars color="#A78BFA" items={d.charts.articles_by_source_type.map((x) => ({ label: x.name, value: x.value }))} /></div>
            <div className={`${card} p-5`}><Head title="Metadata quality" sub="Share of dated articles with each attribute (low ATT&CK coverage is expected: ids are rarely written out)" /><HBars color="#34D399" unit="%" items={d.charts.metadata_quality.map((x) => ({ label: x.name, value: x.value }))} /></div>
          </div>
          <div className={`${card} p-5`}>
            <Head title="Daily coverage" sub="Bars: dated articles published per bucket · line: distinct sources publishing" />
            <Columns labels={d.charts.daily.bucket_starts} values={d.charts.daily.articles} line={d.charts.daily.sources} hourly={d.filters.bucket_hours === 1} />
            <div className="mt-1"><Legend items={[{ name: 'Articles', color: '#22D3EE' }, { name: 'Distinct sources', color: '#F97316' }]} /></div>
          </div>
          <div className={`${card} overflow-x-auto`}>
            <div className="border-b border-line px-4 py-3 text-sm font-semibold text-ink">Sources <span className="text-xs font-normal text-mute">· quiet (healthy, nothing new) is not failed</span></div>
            <table className="w-full min-w-[760px] text-sm">
              <thead className="border-b border-line text-left text-xs uppercase tracking-wider text-mute"><tr><th className="px-4 py-2.5">Source</th><th className="px-4 py-2.5">Type</th><th className="px-4 py-2.5">State</th><th className="px-4 py-2.5 text-right">In period</th><th className="px-4 py-2.5 text-right">Stored</th><th className="px-4 py-2.5 text-right">Undated</th><th className="px-4 py-2.5">First collected</th></tr></thead>
              <tbody>
                {d.sources.slice(0, 80).map((s) => (
                  <tr key={s.id} className="border-b border-line/60 last:border-0"><td className="px-4 py-2 text-ink">{s.name}</td><td className="px-4 py-2 text-xs text-mute">{s.type}</td>
                    <td className={`px-4 py-2 text-xs ${HEALTH_TONE[s.health] ?? ''}`} title={s.error ?? ''}>{s.health}</td><td className="px-4 py-2 text-right tabular-nums text-ink">{s.articles_period}</td><td className="px-4 py-2 text-right tabular-nums text-mute">{s.stored}</td><td className="px-4 py-2 text-right tabular-nums text-mute">{s.undated}</td><td className="px-4 py-2 text-xs text-mute">{fmt(s.first_collected)}</td></tr>))}
              </tbody>
            </table>
          </div>
          <div className="grid gap-4 xl:grid-cols-2">
            <div className={`${card} p-5`}>
              <Head title="Sync history" sub="One row per feed refresh since logging began" />
              {d.sync_history.length === 0 ? <div className="text-xs text-mute">No sync recorded yet. Recording starts with the next refresh.</div> : (
                <table className="w-full text-xs"><thead className="text-left text-mute"><tr><th className="py-1">Finished</th><th className="text-right">OK</th><th className="text-right">Failed</th><th className="text-right">New</th><th className="text-right">Re-seen</th></tr></thead>
                  <tbody>{d.sync_history.map((s) => <tr key={s.id} className="border-t border-line/60"><td className="py-1 text-mute">{fmt(s.finished_at)}</td><td className="text-right tabular-nums">{s.ok}</td><td className="text-right tabular-nums">{s.failed}</td><td className="text-right tabular-nums">{s.new_items}</td><td className="text-right tabular-nums text-mute">{s.resighted}</td></tr>)}</tbody></table>)}
            </div>
            <div className={`${card} p-5`}>
              <Head title="Snapshots" sub="Append-only metrics recorded after each sync; nothing before the first snapshot exists" />
              {!hist.data || hist.data.snapshots.length === 0 ? <div className="text-xs text-mute">No snapshot recorded yet.</div> : (
                <table className="w-full text-xs"><thead className="text-left text-mute"><tr><th className="py-1">Taken (UTC)</th><th className="text-right">Articles</th><th className="text-right">Events</th><th className="text-right">Operational</th></tr></thead>
                  <tbody>{[...hist.data.snapshots].reverse().slice(0, 8).map((s) => <tr key={s.id} className="border-t border-line/60" title={s.note ?? ''}><td className="py-1 text-mute">{fmt(s.taken_at)}{s.config_changed && <span className="ml-1 text-amber-300">· reclassified</span>}</td><td className="text-right tabular-nums">{s.articles}{s.delta ? <span className="text-mute"> ({s.delta.articles >= 0 ? '+' : ''}{s.delta.articles})</span> : null}</td><td className="text-right tabular-nums">{s.events}</td><td className="text-right tabular-nums">{s.sources_operational}/{s.sources_enabled}</td></tr>)}</tbody></table>)}
              {hist.data && <div className="mt-2 text-[11px] text-mute">{hist.data.note}</div>}
            </div>
          </div>
          {d.notes && <Note>{d.notes.join(' ')}</Note>}
        </>
      )}
    </div>
  )
}
