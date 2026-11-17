import type { LucideIcon } from 'lucide-react'

interface Props {
  label: string
  value: number | string
  icon: LucideIcon
  tone?: string
  hint?: string
}

export default function MetricCard({ label, value, icon: Icon, tone = '#22D3EE', hint }: Props) {
  return (
    <div className="flex items-center justify-between rounded-xl border border-line bg-surface px-5 py-4 transition-colors hover:border-accent/40">
      <div>
        <div className="text-xs font-medium uppercase tracking-wider text-mute">{label}</div>
        <div className="mt-1.5 text-3xl font-semibold tabular-nums text-ink">{value}</div>
        {hint && <div className="mt-0.5 text-[11px] text-mute">{hint}</div>}
      </div>
      <div className="flex h-10 w-10 items-center justify-center rounded-lg" style={{ background: `${tone}1A`, color: tone }}>
        <Icon size={19} />
      </div>
    </div>
  )
}
