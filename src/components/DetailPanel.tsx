import { useState } from 'react'
import { X, ShieldAlert, Bug, Flame, ExternalLink, Info, ChevronDown } from 'lucide-react'
import type { NewsItem, Technology, TechnologyDetail } from '../data/types'
import { ago } from './IntelligenceFeed'
import { getLevel } from '../lib/risk'

const LABELS: Record<string, string> = { peak: 'Most relevant CVE', corroboration: 'Corroboration (next 3 CVEs)' }
const QUALITY = { good: 'text-emerald-300', partial: 'text-amber-300', limited: 'text-red-300' } as const
const EVIDENCE = { recent_exploitation: 'Recent exploitation', known_exploited: 'Known exploited', none: '' } as const

interface Props { tech: Technology; detail: TechnologyDetail | null; loading: boolean; news: NewsItem[] | null; onViewAllNews: () => void; onClose: () => void }

export default function DetailPanel({ tech, detail, loading, news, onViewAllNews, onClose }: Props) {
  const level = getLevel(tech.score)
  const [open, setOpen] = useState(false)
  const cves = detail?.cves ?? []
  return (
    <aside className="slide-in flex w-96 shrink-0 flex-col overflow-y-auto border-l border-line bg-sidebar">
      <div className="flex items-start justify-between border-b border-line px-5 py-4">
        <div>
          <div className="text-[10px] font-semibold uppercase tracking-wider text-mute">Technology</div>
          <h2 className="mt-0.5 text-lg font-semibold text-ink">{tech.name}</h2>
        </div>
        <button onClick={onClose} aria-label="Close" className="rounded-lg border border-line p-1.5 text-mute transition-colors hover:border-accent/40 hover:text-ink">
          <X size={16} />
        </button>
      </div>

      <div className="space-y-4 p-5">
        <div className="rounded-xl border border-line bg-surface p-4">
          <div className="flex items-end justify-between">
            <div>
              <div className="text-xs text-mute">Threat Signal Score</div>
              <div className="text-4xl font-semibold tabular-nums" style={{ color: level.color }}>
                {tech.score === null ? 'N/A' : Math.round(tech.score)}
                {tech.score !== null && <span className="text-base text-mute">/100</span>}
              </div>
            </div>
            <span className="flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-xs font-medium" style={{ color: level.color, borderColor: `${level.color}55`, background: `${level.color}14` }}>
              <ShieldAlert size={13} /> {level.label}
            </span>
          </div>
          <div className="mt-3 h-1.5 overflow-hidden rounded-full bg-line">
            <div className="h-full rounded-full transition-all duration-500" style={{ width: `${tech.score ?? 0}%`, background: level.color }} />
          </div>
          {tech.insufficient_reason && <p className="mt-3 text-xs leading-snug text-mute">{tech.insufficient_reason}</p>}
          {tech.coverage_label && <p className="mt-2 text-xs text-mute">Coverage: <b className="text-ink">{tech.coverage_label}</b>{tech.sync && !tech.sync.complete && tech.sync.applicable ? ` · backfill ${tech.sync.label.toLowerCase()} (${tech.sync.queries_completed}/${tech.sync.queries_required})` : ''}</p>}
          {tech.historical && tech.historical.count > 0 && <p className="mt-1 text-xs text-mute">{tech.historical.count} historical CVE(s) are listed separately in the Technology Catalog; they are not part of the score.</p>}
        </div>

        <div className="grid grid-cols-2 gap-3">
          <div className="rounded-xl border border-line bg-surface p-3">
            <Bug size={15} className="text-accent" />
            <div className="mt-2 text-2xl font-semibold tabular-nums text-ink">{tech.cve_count}</div>
            <div className="text-xs text-mute">CVEs monitored</div>
          </div>
          <div className="rounded-xl border border-line bg-surface p-3">
            <Flame size={15} className="text-red-400" />
            <div className="mt-2 text-2xl font-semibold tabular-nums text-ink">{tech.kev_count}</div>
            <div className="text-xs text-mute">In CISA KEV</div>
          </div>
        </div>

        <div className="rounded-xl border border-line bg-surface">
          <button onClick={() => setOpen(!open)} className="flex w-full items-center justify-between px-4 py-3 text-left text-sm text-ink">
            <span className="flex items-center gap-2"><Info size={14} className="text-accent" /> How is this score calculated?</span>
            <ChevronDown size={14} className={`text-mute transition-transform ${open ? 'rotate-180' : ''}`} />
          </button>
          {open && (
            <div className="space-y-2 border-t border-line px-4 py-3 text-xs text-mute">
              <div className="text-ink">{tech.explanation.formula}</div>
              {Object.entries(tech.explanation.components).map(([k, c]) => (
                <div key={k} className="flex justify-between">
                  <span>{LABELS[k] ?? k}</span>
                  <span className="tabular-nums text-ink">+{c.points}</span>
                </div>
              ))}
              <div>The state comes from the most relevant CVEs, not from how many exist. Each CVE is weighted by CVSS (fades with age), EPSS, KEV listing (fades slowly, never to zero) and a bonus for exploitation confirmed in the last {tech.explanation.recent_days} days. Window: {tech.explanation.window_days} days of NVD publications + KEV additions.</div>
              {tech.explanation.notes.map((n) => <div key={n}>• {n}</div>)}
            </div>
          )}
        </div>

        {tech.drivers.length > 0 && (
          <div>
            <div className="mb-2 text-[10px] font-semibold uppercase tracking-wider text-mute">Top drivers of this status</div>
            <ul className="space-y-2">
              {tech.drivers.map((d) => (
                <li key={d.id} className="rounded-lg border bg-surface px-3 py-2.5" style={{ borderColor: `${level.color}44` }}>
                  <div className="flex items-center justify-between">
                    <a href={d.link} target="_blank" rel="noreferrer" className="flex items-center gap-1 text-[13px] font-semibold text-accent hover:underline">{d.id} <ExternalLink size={11} /></a>
                    <span className="text-[11px] tabular-nums text-mute">relevance <b className="text-ink">{d.relevance}</b></span>
                  </div>
                  {d.evidence !== 'none' && <div className="mt-1 text-[11px] font-medium" style={{ color: d.evidence === 'recent_exploitation' ? '#F87171' : '#FB923C' }}>{EVIDENCE[d.evidence]}</div>}
                  <ul className="mt-1 space-y-0.5 text-[11px] text-mute">{d.reasons.map((r) => <li key={r}>• {r}</li>)}</ul>
                </li>
              ))}
            </ul>
          </div>
        )}

        <div className="rounded-xl border border-line bg-surface px-4 py-3 text-xs text-mute">
          <div className="flex justify-between"><span>Data quality</span><b className={`capitalize ${QUALITY[tech.quality.level]}`}>{tech.quality.level}</b></div>
          <div className="mt-1 flex justify-between"><span>NVD coverage</span><span className="text-ink">{tech.coverage.nvd_queries_ok}/{tech.coverage.nvd_queries_total} queries</span></div>
          <div className="mt-1 flex justify-between"><span>Data as of</span><span className="text-ink">{tech.updated_at ? new Date(tech.updated_at).toLocaleString('en-US', { dateStyle: 'medium', timeStyle: 'short' }) : '-'}</span></div>
          {tech.quality.reasons.map((r) => <div key={r} className="mt-1">• {r}</div>)}
        </div>

        <div>
          <div className="mb-2 text-[10px] font-semibold uppercase tracking-wider text-mute">All related CVEs {cves.length > 0 && `(top ${cves.length})`}</div>
          {loading && !detail && <div className="text-xs text-mute">Loading…</div>}
          {detail && cves.length === 0 && <div className="text-xs text-mute">No confirmed CVEs correlated yet.</div>}
          <ul className="space-y-2">
            {cves.map((c) => (
              <li key={c.id} className="rounded-lg border border-line bg-surface px-3 py-2.5 transition-colors hover:border-accent/40">
                <div className="flex items-center justify-between gap-2">
                  <a href={c.links.nvd} target="_blank" rel="noreferrer" className="flex items-center gap-1 text-[13px] font-semibold text-accent hover:underline">
                    {c.id} <ExternalLink size={11} />
                  </a>
                  <div className="flex gap-1">
                    {c.kev && <span className="rounded border border-red-400/40 bg-red-400/10 px-1.5 py-0.5 text-[10px] font-semibold text-red-300">KEV</span>}
                    {c.kev_ransomware && <span className="rounded border border-orange-400/40 bg-orange-400/10 px-1.5 py-0.5 text-[10px] font-semibold text-orange-300">Ransomware</span>}
                  </div>
                </div>
                <div className="mt-1 text-[11px] text-mute">
                  {c.product ?? '—'} · {c.published ? c.published.slice(0, 10) : c.kev_date_added ? `KEV ${c.kev_date_added}` : '—'}
                </div>
                <div className="mt-1.5 flex gap-4 text-[11px] text-mute">
                  <span>CVSS <b className="text-ink">{c.cvss ?? 'n/a'}</b></span>
                  <span>EPSS <b className="text-ink">{c.epss === null ? 'n/a' : `${(c.epss * 100).toFixed(1)}%`}</b></span>
                </div>
                {c.description && <p className="mt-1.5 line-clamp-2 text-[12px] leading-snug text-mute">{c.description}</p>}
                <div className="mt-1.5 flex gap-3 text-[11px]">
                  <a href={c.links.nvd} target="_blank" rel="noreferrer" className="text-mute hover:text-accent">NVD</a>
                  {c.links.kev && <a href={c.links.kev} target="_blank" rel="noreferrer" className="text-mute hover:text-accent">CISA KEV</a>}
                  {c.links.epss && <a href={c.links.epss} target="_blank" rel="noreferrer" className="text-mute hover:text-accent">EPSS</a>}
                </div>
              </li>
            ))}
          </ul>
        </div>

        <div>
          <div className="mb-2 text-[10px] font-semibold uppercase tracking-wider text-mute">Related Security News</div>
          {news === null && <div className="text-xs text-mute">Loading…</div>}
          {news?.length === 0 && <div className="text-xs text-mute">No related articles collected yet.</div>}
          <ul className="space-y-2">
            {news?.map((n) => (
              <li key={n.id} className="rounded-lg border border-line bg-surface px-3 py-2.5 transition-colors hover:border-accent/40">
                <a href={n.url} target="_blank" rel="noopener noreferrer nofollow" className="text-[13px] font-medium leading-snug text-ink hover:text-accent">{n.title}</a>
                <div className="mt-1 flex items-center justify-between text-[11px] text-mute">
                  <span>{n.source.name} · {ago(n.published ?? n.collected_at)}</span>
                  <a href={n.url} target="_blank" rel="noopener noreferrer nofollow" aria-label="Open original article"><ExternalLink size={11} /></a>
                </div>
              </li>
            ))}
          </ul>
          <button onClick={onViewAllNews} className="mt-2 w-full rounded-lg border border-line py-2 text-sm text-ink transition-colors hover:border-accent/40">View All Related News</button>
        </div>

        <button onClick={onClose} className="w-full rounded-lg border border-accent/30 bg-accent/10 py-2 text-sm font-medium text-accent transition-colors hover:bg-accent/20">
          Back to overview
        </button>
      </div>
    </aside>
  )
}
