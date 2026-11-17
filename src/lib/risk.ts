export interface RiskLevel { label: string; color: string; min: number }

export const LEVELS: RiskLevel[] = [
  { label: 'Low', color: '#22C55E', min: 0 },
  { label: 'Medium', color: '#EAB308', min: 25 },
  { label: 'High', color: '#F97316', min: 50 },
  { label: 'Critical', color: '#EF4444', min: 75 },
]
export const UNKNOWN_LEVEL: RiskLevel = { label: 'Insufficient data', color: '#64748B', min: -1 }
export const RANGES = ['0–24', '25–49', '50–74', '75–100']

export const getLevel = (score: number | null): RiskLevel =>
  score === null ? UNKNOWN_LEVEL : ([...LEVELS].reverse().find((l) => score >= l.min) ?? LEVELS[0])
