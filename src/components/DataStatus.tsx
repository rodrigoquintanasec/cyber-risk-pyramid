import { Loader2, Radio, AlertTriangle, XCircle, RefreshCw } from 'lucide-react'
import type { DataState, Status } from '../data/types'

const CFG: Record<DataState, { label: string; cls: string; Icon: typeof Radio }> = {
  loading: { label: 'Loading', cls: 'border-accent/30 bg-accent/10 text-accent', Icon: Loader2 },
  live: { label: 'Live Data', cls: 'border-emerald-400/30 bg-emerald-400/10 text-emerald-300', Icon: Radio },
  stale: { label: 'Stale Data', cls: 'border-amber-400/30 bg-amber-400/10 text-amber-300', Icon: AlertTriangle },
  error: { label: 'Error', cls: 'border-red-400/30 bg-red-400/10 text-red-300', Icon: XCircle },
}

interface Props { state: DataState; status: Status | null; onRefresh: () => void }

export default function DataStatus({ state, status, onRefresh }: Props) {
  const { label, cls, Icon } = CFG[state]
  const failing = status ? Object.entries(status.sources).filter(([, s]) => s.ok === false) : []
  const title = failing.length
    ? failing.map(([k, s]) => `${k.toUpperCase()}: ${s.error ?? 'failed'}`).join('\n') + '\nShowing last valid data.'
    : status?.syncing ? `Syncing${status.phase ? ` (${status.phase.toUpperCase()})` : ''}…` : 'All sources healthy'
  return (
    <div className="flex items-center gap-2">
      <div title={title} className={`flex items-center gap-2 rounded-full border px-3 py-1.5 text-xs font-medium ${cls}`}>
        <Icon size={13} className={state === 'loading' || status?.syncing ? 'animate-spin' : ''} /> {label}
      </div>
      <button
        onClick={onRefresh}
        disabled={!!status?.syncing}
        title="Refresh now (local sync)"
        className="rounded-lg border border-line p-1.5 text-mute transition-colors hover:border-accent/40 hover:text-ink disabled:opacity-40"
      >
        <RefreshCw size={13} className={status?.syncing ? 'animate-spin' : ''} />
      </button>
    </div>
  )
}
