import { AlertTriangle, ArrowDown, ArrowUp, Minus } from 'lucide-react'
import type { Cmp, Echo } from '../../data/analytics'
import type { ExplorerFilters } from '../intel/ExplorerTab'
import { Chip, ExtLink, fmt } from '../intel/ui'
import type { EventRow } from '../../data/analytics'

export interface Nav {
  feed: (f: Partial<ExplorerFilters>) => void
  vuln: (cve: string) => void
  vulnVendor: (vendor: string) => void
  attack: (kind: 'actor' | 'campaign' | 'technique', id: string) => void
  graph: (nodeId: string) => void
  watchlists: () => void
  techNews: (techId: string) => void
}

export function CmpBadge({ c, unit = '' }: { c: Cmp; unit?: string }) {
  if (c.status === 'no_data') return <span className="text-[11px] text-amber-300" title={c.reason ?? ''}>Insufficient comparable coverage</span>
  if (c.status === 'insufficient') return <span className="flex items-center gap-1 text-[11px] text-mute" title={c.reason ?? ''}><Minus size={11} /> no baseline</span>
  const d = c.delta ?? 0
  const Icon = d > 0 ? ArrowUp : d < 0 ? ArrowDown : Minus
  if (c.status === 'coverage_changed')
    return <span className="flex items-center gap-1 text-[11px] text-amber-300" title={c.reason ?? ''}><AlertTriangle size={11} /> Δ {d > 0 ? '+' : ''}{d}{unit} · coverage changed</span>
  return (
    <span className="flex items-center gap-1 text-[11px] tabular-nums text-mute" title={`Previous equivalent period: ${c.previous}`}>
      <Icon size={11} /> {d > 0 ? '+' : ''}{d}{unit}{c.pct !== null ? ` (${c.pct > 0 ? '+' : ''}${c.pct}%)` : ' · % n/a'}
    </span>
  )
}

export function periodText(e: Echo) {
  return `${fmt(e.since)} – ${fmt(e.until)} (UTC) · previous period from ${fmt(e.previous_since)}`
}

export function EventList({ items, onCve }: { items: EventRow[]; onCve?: (c: string) => void }) {
  return (
    <ul className="divide-y divide-line/60">
      {items.map((e) => (
        <li key={e.id} className="py-3">
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-sm font-medium text-ink">{e.title}</span>
            <Chip tone="accent">{e.category}</Chip>
            {e.official && <Chip tone="violet" title="Official advisory or first-party publisher">official</Chip>}
            <Chip title="News Priority Score (reading priority, not risk)">Priority {e.priority.toFixed(0)}</Chip>
          </div>
          <div className="mt-1 text-xs text-mute">{e.articles_in_period} article(s) in period · {e.source_count} source(s) · last {fmt(e.last_published)}</div>
          {e.cves.length > 0 && <div className="mt-1.5 flex flex-wrap gap-1.5">{e.cves.map((c) => <button key={c} onClick={() => onCve?.(c)}><Chip tone="orange">{c}</Chip></button>)}</div>}
          <div className="mt-1.5 flex flex-wrap gap-x-4 gap-y-1 text-xs">{e.articles.slice(0, 3).map((a) => <ExtLink key={a.url} href={a.url}>{a.source}</ExtLink>)}</div>
        </li>
      ))}
    </ul>
  )
}

export const PERIOD_LABEL: Record<string, string> = { '24h': 'Last 24 hours', '7d': 'Last 7 days', '30d': 'Last 30 days', '90d': 'Last 90 days', custom: 'Custom period' }
