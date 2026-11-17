import { useEffect, useState, type ReactNode } from 'react'
import { AlertTriangle, ExternalLink, Info, Loader2, XCircle } from 'lucide-react'

export const sel = 'rounded-lg border border-line bg-surface px-3 py-2 text-sm text-ink outline-none transition-colors hover:border-accent/40 focus:border-accent/60'
export const card = 'rounded-xl border border-line bg-surface'
export const fmt = (iso: string | null | undefined) => (iso ? new Date(iso).toLocaleString('en-US', { dateStyle: 'medium', timeStyle: 'short' }) : '-')

export function useAsync<T>(fn: () => Promise<T>, deps: unknown[]) {
  const [data, setData] = useState<T | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)
  const [tick, setTick] = useState(0)
  useEffect(() => {
    let alive = true
    setLoading(true)
    fn().then((d) => { if (alive) { setData(d); setError(null) } })
      .catch((e) => { if (alive) setError(String(e.message ?? e)) })
      .finally(() => { if (alive) setLoading(false) })
    return () => { alive = false }
  }, [...deps, tick]) // eslint-disable-line react-hooks/exhaustive-deps
  return { data, error, loading, reload: () => setTick((t) => t + 1) }
}

export function Status({ loading, error, onRetry, empty, emptyText }: { loading: boolean; error: string | null; onRetry?: () => void; empty?: boolean; emptyText?: string }) {
  if (loading) return <div className="flex items-center justify-center gap-2 py-10 text-sm text-mute"><Loader2 size={16} className="animate-spin" /> Loading…</div>
  if (error) return (
    <div className="flex items-center gap-3 rounded-xl border border-red-400/30 bg-red-400/10 p-4 text-sm text-red-300"><XCircle size={16} /> Could not load data ({error}).
      {onRetry && <button onClick={onRetry} className="ml-auto rounded border border-red-400/40 px-2 py-1 text-xs">Retry</button>}</div>
  )
  if (empty) return <div className="rounded-xl border border-dashed border-line py-12 text-center text-sm text-mute">{emptyText ?? 'Nothing to show for these filters.'}</div>
  return null
}

export function Note({ children, tone = 'info' }: { children: ReactNode; tone?: 'info' | 'warn' }) {
  const warn = tone === 'warn'
  return (
    <div className={`flex items-start gap-2 rounded-lg border px-3 py-2 text-xs ${warn ? 'border-amber-400/30 bg-amber-400/10 text-amber-300' : 'border-line bg-bg/40 text-mute'}`}>
      {warn ? <AlertTriangle size={13} className="mt-0.5 shrink-0" /> : <Info size={13} className="mt-0.5 shrink-0" />}<span>{children}</span>
    </div>
  )
}

export function Tabs<T extends string>({ tabs, value, onChange }: { tabs: { id: T; label: string; icon: typeof Info }[]; value: T; onChange: (t: T) => void }) {
  return (
    <div className="flex flex-wrap gap-1 border-b border-line px-6" role="tablist">
      {tabs.map(({ id, label, icon: Icon }) => (
        <button key={id} role="tab" aria-selected={value === id} onClick={() => onChange(id)}
          className={`flex items-center gap-2 border-b-2 px-3.5 py-2.5 text-sm transition-colors ${value === id ? 'border-accent text-accent' : 'border-transparent text-mute hover:text-ink'}`}>
          <Icon size={14} /> {label}
        </button>
      ))}
    </div>
  )
}

export function Segmented({ options, value, onChange }: { options: [string, string][]; value: string; onChange: (v: string) => void }) {
  return (
    <div className="inline-flex rounded-lg border border-line bg-surface p-0.5">
      {options.map(([v, l]) => (
        <button key={v} onClick={() => onChange(v)} className={`rounded-md px-3 py-1.5 text-xs transition-colors ${value === v ? 'bg-accent/15 text-accent' : 'text-mute hover:text-ink'}`}>{l}</button>
      ))}
    </div>
  )
}

export function PriorityBadge({ score }: { score: number | null }) {
  if (score === null) return null
  const tone = score >= 60 ? 'border-red-400/40 bg-red-400/10 text-red-300' : score >= 40 ? 'border-orange-400/40 bg-orange-400/10 text-orange-300' : score >= 25 ? 'border-amber-400/30 bg-amber-400/10 text-amber-300' : 'border-line text-mute'
  return <span title="News Priority Score — reading priority, not a risk measurement" className={`rounded-full border px-2 py-0.5 text-[11px] font-medium tabular-nums ${tone}`}>Priority {score.toFixed(0)}</span>
}

export function Chip({ children, tone = 'mute', title }: { children: ReactNode; tone?: 'mute' | 'accent' | 'red' | 'violet' | 'orange'; title?: string }) {
  const t = { mute: 'border-line text-mute', accent: 'border-accent/30 bg-accent/10 text-accent', red: 'border-red-400/30 bg-red-400/10 text-red-300', violet: 'border-violet-400/30 bg-violet-400/10 text-violet-300', orange: 'border-orange-400/40 bg-orange-400/10 text-orange-300' }[tone]
  return <span title={title} className={`rounded-full border px-2 py-0.5 text-[11px] ${t}`}>{children}</span>
}

export function ExtLink({ href, children }: { href: string; children: ReactNode }) {
  return <a href={href} target="_blank" rel="noopener noreferrer nofollow" className="inline-flex items-center gap-1 text-accent hover:underline">{children}<ExternalLink size={11} /></a>
}

export function Pager({ page, pages, onPage }: { page: number; pages: number; onPage: (p: number) => void }) {
  if (pages <= 1) return null
  const b = 'rounded-lg border border-line px-3 py-1.5 text-xs text-ink transition-colors hover:border-accent/40 disabled:opacity-40'
  return (
    <div className="flex items-center justify-center gap-3 pt-2">
      <button className={b} disabled={page <= 1} onClick={() => onPage(page - 1)}>Previous</button>
      <span className="text-xs text-mute">Page {page} / {pages}</span>
      <button className={b} disabled={page >= pages} onClick={() => onPage(page + 1)}>Next</button>
    </div>
  )
}

export function Spark({ values, color = '#22D3EE', w = 90, h = 24 }: { values: number[]; color?: string; w?: number; h?: number }) {
  const max = Math.max(1, ...values)
  const step = values.length > 1 ? w / (values.length - 1) : w
  const pts = values.map((v, i) => `${(i * step).toFixed(1)},${(h - 2 - (v / max) * (h - 4)).toFixed(1)}`).join(' ')
  return <svg width={w} height={h} role="img" aria-label="trend over the period"><polyline points={pts} fill="none" stroke={color} strokeWidth="1.5" strokeLinejoin="round" /></svg>
}

export function Bar({ value, max, color = '#22D3EE' }: { value: number; max: number; color?: string }) {
  return <div className="h-2 w-full overflow-hidden rounded-full bg-bg"><div className="h-full rounded-full" style={{ width: `${max ? Math.max(3, (value / max) * 100) : 0}%`, background: color }} /></div>
}
