import type { ReactNode } from 'react'
import { STATUS_LABEL } from '../../data/company'

export interface CNav { explorer: (p: { tech?: string; vendor?: string; product?: string; open?: string }) => void; graph: (nodeId: string) => void }

const SCOPES: Record<string, { label: string; cls: string; tip: string }> = {
  signal: { label: 'Threat Signal', cls: 'text-orange-300', tip: 'External signals for a technology (global); not this company\'s risk' },
  potential: { label: 'Potential Exposure', cls: 'text-amber-300', tip: 'Product and version may match; not confirmation' },
  confirmed: { label: 'Confirmed Exposure', cls: 'text-violet-300', tip: 'Validated by an analyst with recorded evidence' },
  attention: { label: 'Intelligence Attention', cls: 'text-accent', tip: 'News and advisories about the technologies' },
  coverage: { label: 'Data Coverage', cls: 'text-emerald-300', tip: 'Completeness of the manually kept inventory' },
}
export function ScopeTag({ scope }: { scope: string }) {
  const s = SCOPES[scope]
  return s ? <span title={s.tip} className={`text-[9px] uppercase tracking-wider ${s.cls}`}>{s.label}</span> : null
}

const ST: Record<string, string> = {
  confirmed_applicable: 'border-violet-400/40 bg-violet-400/10 text-violet-300', potentially_applicable: 'border-amber-400/40 bg-amber-400/10 text-amber-300',
  needs_review: 'border-sky-400/40 bg-sky-400/10 text-sky-300', insufficient_data: 'border-line text-mute', not_applicable: 'border-emerald-400/30 bg-emerald-400/10 text-emerald-300', unassessed: 'border-line text-mute/70',
}
export function StatusBadge({ s, auto }: { s: string | null | undefined; auto?: boolean }) {
  const k = s ?? 'unassessed'
  return <span title={auto ? 'Automatic (product + version match); not an analyst confirmation' : undefined} className={`whitespace-nowrap rounded-full border px-2 py-0.5 text-[11px] ${ST[k]}`}>{STATUS_LABEL[k]}</span>
}

export function Field({ label, children, hint }: { label: string; children: ReactNode; hint?: string }) {
  return <label className="block text-xs text-mute">{label}<div className="mt-1">{children}</div>{hint && <div className="mt-0.5 text-[10px] text-mute/70">{hint}</div>}</label>
}
export const inp = 'w-full rounded-lg border border-line bg-bg px-3 py-2 text-sm text-ink outline-none focus:border-accent/60'
export const btn = 'rounded-lg border border-accent/40 bg-accent/15 px-3 py-1.5 text-xs font-medium text-accent hover:bg-accent/25 disabled:opacity-40'
export const btn2 = 'rounded-lg border border-line px-3 py-1.5 text-xs text-ink hover:border-accent/40 disabled:opacity-40'

export function Modal({ title, onClose, children, size = 'md' }: { title: string; onClose: () => void; children: ReactNode; size?: 'md' | 'xl' }) {
  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center overflow-y-auto bg-black/60 p-6" onMouseDown={(e) => e.target === e.currentTarget && onClose()}>
      <div role="dialog" aria-label={title} className={`mt-8 w-full rounded-xl border border-line bg-surface p-5 ${size === 'xl' ? 'max-w-5xl' : 'max-w-xl'}`}>
        <div className="mb-4 flex items-center justify-between"><h3 className="text-sm font-semibold text-ink">{title}</h3><button onClick={onClose} className="text-xs text-mute hover:text-ink">Close</button></div>
        {children}
      </div>
    </div>
  )
}

export const ver = (a: { version: string | null; version_min: string | null; version_max: string | null }) => a.version ?? (a.version_min || a.version_max ? `${a.version_min ?? '*'} – ${a.version_max ?? '*'}` : 'unknown')
