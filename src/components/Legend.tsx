import { LEVELS, RANGES, UNKNOWN_LEVEL } from '../lib/risk'

export default function Legend() {
  return (
    <div className="absolute bottom-4 left-4 rounded-xl border border-line bg-surface/90 px-4 py-3 backdrop-blur">
      <div className="mb-2 text-[10px] font-semibold uppercase tracking-wider text-mute">Severity</div>
      <div className="flex flex-col gap-1.5">
        {LEVELS.map((l, i) => (
          <div key={l.label} className="flex items-center gap-2 text-xs text-ink">
            <span className="h-2.5 w-2.5 rounded-sm" style={{ background: l.color, boxShadow: `0 0 8px ${l.color}66` }} />
            <span className="w-14">{l.label}</span>
            <span className="tabular-nums text-mute">{RANGES[i]}</span>
          </div>
        ))}
        <div className="flex items-center gap-2 text-xs text-ink">
          <span className="h-2.5 w-2.5 rounded-sm" style={{ background: UNKNOWN_LEVEL.color }} />
          <span className="w-14">No data</span>
          <span className="text-mute">Insufficient</span>
        </div>
      </div>
    </div>
  )
}
