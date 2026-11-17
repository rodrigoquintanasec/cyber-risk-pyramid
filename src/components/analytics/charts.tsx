import { useRef, useState, type ReactNode } from 'react'

export const PALETTE = ['#22D3EE', '#F97316', '#A78BFA', '#34D399', '#F472B6', '#FACC15', '#60A5FA', '#FB7185', '#2DD4BF', '#C084FC']
export const colorOf = (i: number) => PALETTE[i % PALETTE.length]
const GRID = '#243247'
const MUTE = '#94A3B8'

const short = (iso: string, hourly: boolean) => {
  const d = new Date(iso)
  return hourly ? `${String(d.getUTCHours()).padStart(2, '0')}:00` : d.toLocaleDateString('en-US', { month: 'short', day: 'numeric', timeZone: 'UTC' })
}
const niceMax = (m: number) => { if (m <= 4) return 4; const p = 10 ** Math.floor(Math.log10(m)); return Math.ceil(m / p) * p }

export interface Line { name: string; color: string; values: number[]; dashed?: boolean }

export function LineChart({ labels, series, hourly, height = 240, onPoint, selected, unit = '' }: { labels: string[]; series: Line[]; hourly: boolean; height?: number; onPoint?: (i: number) => void; selected?: number | null; unit?: string }) {
  const ref = useRef<SVGSVGElement>(null)
  const [hover, setHover] = useState<number | null>(null)
  const W = 760, H = height, L = 38, R = 12, T = 12, B = 26
  const n = labels.length
  const max = niceMax(Math.max(1, ...series.flatMap((s) => s.values)))
  const x = (i: number) => L + (n <= 1 ? (W - L - R) / 2 : (i * (W - L - R)) / (n - 1))
  const y = (v: number) => T + (1 - v / max) * (H - T - B)
  const idx = (e: React.MouseEvent) => {
    const r = ref.current!.getBoundingClientRect()
    const px = ((e.clientX - r.left) / r.width) * W
    return Math.max(0, Math.min(n - 1, Math.round(((px - L) / (W - L - R)) * (n - 1))))
  }
  const ticks = [0, 0.25, 0.5, 0.75, 1].map((f) => Math.round(max * f))
  const step = Math.max(1, Math.ceil(n / 8))
  const hi = hover ?? selected ?? null
  return (
    <div className="relative">
      <svg ref={ref} viewBox={`0 0 ${W} ${H}`} className="w-full select-none" role="img" aria-label="Time series chart"
        onMouseMove={(e) => setHover(idx(e))} onMouseLeave={() => setHover(null)} onClick={(e) => onPoint?.(idx(e))} style={{ cursor: onPoint ? 'pointer' : 'default' }}>
        {ticks.map((t) => <g key={t}><line x1={L} x2={W - R} y1={y(t)} y2={y(t)} stroke={GRID} strokeWidth={0.6} /><text x={L - 6} y={y(t) + 3} fontSize={10} fill={MUTE} textAnchor="end">{t}</text></g>)}
        {labels.map((l, i) => (i % step === 0 ? <text key={l} x={x(i)} y={H - 8} fontSize={10} fill={MUTE} textAnchor="middle">{short(l, hourly)}</text> : null))}
        {hi !== null && <line x1={x(hi)} x2={x(hi)} y1={T} y2={H - B} stroke={selected === hi ? '#22D3EE' : MUTE} strokeWidth={selected === hi ? 1.2 : 0.8} strokeDasharray="3 3" />}
        {series.map((s) => (
          <g key={s.name}>
            <polyline fill="none" stroke={s.color} strokeWidth={1.8} strokeDasharray={s.dashed ? '5 4' : undefined} points={s.values.map((v, i) => `${x(i)},${y(v)}`).join(' ')} />
            {hi !== null && s.values[hi] !== undefined && <circle cx={x(hi)} cy={y(s.values[hi])} r={3.5} fill={s.color} />}
          </g>
        ))}
      </svg>
      {hover !== null && (
        <div className="pointer-events-none absolute top-1 z-10 min-w-[140px] rounded-lg border border-line bg-bg/95 px-3 py-2 text-xs shadow-lg" style={{ left: `${Math.min(70, Math.max(2, (x(hover) / W) * 100))}%` }}>
          <div className="mb-1 text-mute">{hourly ? `${short(labels[hover], true)} UTC` : new Date(labels[hover]).toLocaleDateString('en-US', { dateStyle: 'medium', timeZone: 'UTC' })}</div>
          {series.map((s) => <div key={s.name} className="flex items-center gap-2"><span className="h-2 w-2 rounded-full" style={{ background: s.color }} /><span className="text-ink">{s.name}</span><span className="ml-auto tabular-nums text-ink">{s.values[hover]}{unit}</span></div>)}
        </div>
      )}
    </div>
  )
}

export function Legend({ items }: { items: { name: string; color: string; dashed?: boolean }[] }) {
  return <div className="flex flex-wrap gap-x-4 gap-y-1 text-[11px] text-mute">{items.map((i) => <span key={i.name} className="flex items-center gap-1.5"><span className="inline-block h-0.5 w-4" style={{ background: i.color, opacity: i.dashed ? 0.6 : 1 }} />{i.name}</span>)}</div>
}

export function HBars({ items, color = '#22D3EE', unit = '', onClick, empty = 'No data' }: { items: { label: string; value: number | null; sub?: ReactNode; id?: string }[]; color?: string; unit?: string; onClick?: (id: string) => void; empty?: string }) {
  const max = Math.max(1, ...items.map((i) => i.value ?? 0))
  if (!items.length) return <div className="py-6 text-center text-xs text-mute">{empty}</div>
  return (
    <ul className="space-y-1.5">
      {items.map((i) => (
        <li key={i.label}>
          <button disabled={!onClick || !i.id} onClick={() => i.id && onClick?.(i.id)} className="group flex w-full items-center gap-3 text-left text-xs enabled:hover:text-accent">
            <span className="w-40 shrink-0 truncate text-ink group-enabled:group-hover:text-accent" title={i.label}>{i.label}</span>
            <span className="relative h-3.5 flex-1 overflow-hidden rounded bg-bg"><span className="absolute inset-y-0 left-0 rounded" style={{ width: `${i.value === null ? 0 : (100 * i.value) / max}%`, background: color, opacity: 0.8 }} /></span>
            <span className="w-16 shrink-0 text-right tabular-nums text-ink">{i.value === null ? 'N/A' : `${i.value}${unit}`}</span>
            {i.sub && <span className="hidden shrink-0 text-mute md:block">{i.sub}</span>}
          </button>
        </li>
      ))}
    </ul>
  )
}

export function Spark({ values, color = '#22D3EE', w = 80, h = 22 }: { values: number[]; color?: string; w?: number; h?: number }) {
  if (values.length < 2) return <span className="text-[10px] text-mute">-</span>
  const max = Math.max(1, ...values)
  const pts = values.map((v, i) => `${(i * (w - 2)) / (values.length - 1) + 1},${h - 2 - (v / max) * (h - 4)}`).join(' ')
  return <svg width={w} height={h} role="img" aria-label="trend"><polyline points={pts} fill="none" stroke={color} strokeWidth={1.5} /></svg>
}

export function Columns({ labels, values, line, hourly, height = 170, color = '#22D3EE', unit = 'articles', lineUnit = 'sources' }: { labels: string[]; values: number[]; line?: number[]; hourly: boolean; height?: number; color?: string; unit?: string; lineUnit?: string }) {
  const [hover, setHover] = useState<number | null>(null)
  const W = 760, H = height, L = 36, B = 22, T = 8
  const max = niceMax(Math.max(1, ...values)), lmax = niceMax(Math.max(1, ...(line ?? [1])))
  const bw = (W - L - 8) / labels.length
  const step = Math.max(1, Math.ceil(labels.length / 8))
  return (
    <div className="relative">
      <svg viewBox={`0 0 ${W} ${H}`} className="w-full" role="img" aria-label="Daily coverage" onMouseLeave={() => setHover(null)}>
        {[0, 0.5, 1].map((f) => <g key={f}><line x1={L} x2={W - 8} y1={T + (1 - f) * (H - T - B)} y2={T + (1 - f) * (H - T - B)} stroke={GRID} strokeWidth={0.6} /><text x={L - 5} y={T + (1 - f) * (H - T - B) + 3} fontSize={10} fill={MUTE} textAnchor="end">{Math.round(max * f)}</text></g>)}
        {values.map((v, i) => <rect key={i} x={L + i * bw + 1} width={Math.max(1, bw - 2)} y={T + (1 - v / max) * (H - T - B)} height={(v / max) * (H - T - B)} fill={color} opacity={hover === i ? 1 : 0.7} onMouseEnter={() => setHover(i)} />)}
        {line && <polyline fill="none" stroke="#F97316" strokeWidth={1.6} points={line.map((v, i) => `${L + i * bw + bw / 2},${T + (1 - v / lmax) * (H - T - B)}`).join(' ')} />}
        {labels.map((l, i) => (i % step === 0 ? <text key={l} x={L + i * bw + bw / 2} y={H - 6} fontSize={10} fill={MUTE} textAnchor="middle">{short(l, hourly)}</text> : null))}
      </svg>
      {hover !== null && <div className="pointer-events-none absolute right-2 top-0 rounded-lg border border-line bg-bg/95 px-3 py-1.5 text-xs"><div className="text-mute">{short(labels[hover], hourly)}</div><div className="text-ink">{values[hover]} {unit}{line ? ` · ${line[hover]} ${lineUnit}` : ''}</div></div>}
    </div>
  )
}

export interface SPoint { cve: string; cvss: number; epss: number; kev: boolean; mentioned: boolean; monitored: boolean }
export function Scatter({ points, sqrt, selected, onSelect }: { points: SPoint[]; sqrt: boolean; selected: string | null; onSelect: (cve: string) => void }) {
  const [hover, setHover] = useState<SPoint | null>(null)
  const W = 760, H = 380, L = 48, R = 14, T = 12, B = 40
  const x = (v: number) => L + (v / 10) * (W - L - R)
  const yv = (v: number) => (sqrt ? Math.sqrt(v) : v)
  const y = (v: number) => T + (1 - yv(v)) * (H - T - B)
  const yt = [0, 0.01, 0.05, 0.1, 0.25, 0.5, 1].filter((t) => sqrt || [0, 0.25, 0.5, 1].includes(t))
  const style = (p: SPoint) => p.kev ? { fill: '#EF4444', stroke: '#FCA5A5', r: 4.5, o: 0.9 } : p.mentioned ? { fill: '#22D3EE', stroke: 'none', r: 3.6, o: 0.8 } : p.monitored ? { fill: 'none', stroke: '#A78BFA', r: 3, o: 0.8 } : { fill: 'none', stroke: MUTE, r: 2.6, o: 0.6 }
  const ordered = [...points].sort((a, b) => Number(a.kev) - Number(b.kev))
  return (
    <div className="relative">
      <svg viewBox={`0 0 ${W} ${H}`} className="w-full" role="img" aria-label="CVSS versus EPSS scatter plot">
        {yt.map((t) => <g key={t}><line x1={L} x2={W - R} y1={y(t)} y2={y(t)} stroke={GRID} strokeWidth={0.6} /><text x={L - 6} y={y(t) + 3} fontSize={10} fill={MUTE} textAnchor="end">{t}</text></g>)}
        {[0, 2, 4, 6, 8, 10].map((t) => <g key={t}><line y1={T} y2={H - B} x1={x(t)} x2={x(t)} stroke={GRID} strokeWidth={0.6} /><text x={x(t)} y={H - B + 14} fontSize={10} fill={MUTE} textAnchor="middle">{t}</text></g>)}
        <text x={(L + W - R) / 2} y={H - 6} fontSize={11} fill={MUTE} textAnchor="middle">CVSS base score (0-10)</text>
        <text transform={`translate(12 ${(T + H - B) / 2}) rotate(-90)`} fontSize={11} fill={MUTE} textAnchor="middle">EPSS probability{sqrt ? ' (sqrt scale)' : ''}</text>
        {ordered.map((p) => { const s = style(p); return <circle key={p.cve} cx={x(p.cvss)} cy={y(p.epss)} r={selected === p.cve ? s.r + 3 : s.r} fill={s.fill} stroke={selected === p.cve ? '#fff' : s.stroke} strokeWidth={selected === p.cve ? 2 : 1.2} opacity={s.o} style={{ cursor: 'pointer' }}
          onMouseEnter={() => setHover(p)} onMouseLeave={() => setHover(null)} onClick={() => onSelect(p.cve)} /> })}
      </svg>
      {hover && (
        <div className="pointer-events-none absolute z-10 rounded-lg border border-line bg-bg/95 px-3 py-2 text-xs shadow-lg" style={{ left: `${Math.min(75, (x(hover.cvss) / W) * 100)}%`, top: `${Math.max(0, (y(hover.epss) / H) * 100 - 14)}%` }}>
          <div className="font-medium text-ink">{hover.cve}</div>
          <div className="text-mute">CVSS {hover.cvss.toFixed(1)} · EPSS {(hover.epss * 100).toFixed(2)}%</div>
          <div className={hover.kev ? 'text-red-300' : 'text-mute'}>{hover.kev ? 'In CISA KEV' : 'Not in CISA KEV'}</div>
        </div>
      )}
    </div>
  )
}
