async function req<T>(method: string, url: string, body?: unknown): Promise<T> {
  const r = await fetch(url, { method, headers: body ? { 'Content-Type': 'application/json' } : undefined, body: body ? JSON.stringify(body) : undefined })
  if (!r.ok) {
    let msg = `HTTP ${r.status}`
    try { const j = await r.json(); if (typeof j.detail === 'string') msg = j.detail; else if (Array.isArray(j.detail)) msg = j.detail.map((d: { msg: string }) => d.msg).join('; ') } catch { /* ignore */ }
    throw new Error(msg)
  }
  return r.json() as Promise<T>
}
const qs = (o: Record<string, string | number | boolean | undefined | null>) => {
  const p = new URLSearchParams()
  Object.entries(o).forEach(([k, v]) => { if (v !== undefined && v !== null && v !== '') p.set(k, String(v)) })
  return p.toString()
}

export type Validation = 'verified' | 'temporarily_unavailable' | 'unsupported' | 'invalid' | 'duplicate'
export interface AdminSource {
  id: string; name: string; type: string; type_label: string; url: string; enabled: boolean; status: string; health: string; state: string; operational: boolean
  last_attempt: string | null; last_success: string | null; error: string | null; consecutive_failures: number; items_stored: number; items_24h: number; articles_7d: number; articles_30d: number
  latest_publication: string | null; note: string | null; language: string | null; last_http: number | null; backoff_until: string | null; official_verified: boolean
  publisher: string | null; site: string | null; category: string | null; category_label: string | null; country: string | null; origin: 'builtin' | 'catalog' | 'manual'; batch: number | null
  validation_status: Validation | null; validation_note: string | null; validated_at: string | null; last_items: number | null
}
export interface Indicators { total: number; enabled: number; verified: number; failed: number; with_recent_articles: number; last_successful_sync: string | null; operational: number }
export interface AdminPage {
  items: AdminSource[]; total: number; page: number; page_size: number; pages: number; indicators: Indicators
  facets: { categories: Record<string, number>; countries: Record<string, number>; languages: Record<string, number>; states: Record<string, number>; validation: Record<string, number>; origins: Record<string, number> }
  categories: { id: string; label: string }[]; types: { id: string; label: string }[]
}
export interface AdminFilters { q?: string; category?: string; country?: string; language?: string; status?: string; origin?: string; sort?: string; order?: string; page?: number; page_size?: number }
export interface CoverageRow { id: string; name: string; category: string | null; country: string | null; language: string | null; state: string; enabled: boolean; articles_total: number; articles_30d: number; articles_7d: number; last_success: string | null; latest_publication: string | null; no_recent_activity: boolean; error: string | null; validation_status: string | null }
export interface Coverage { indicators: Indicators; by_category: Record<string, number>; by_country: Record<string, number>; by_language: Record<string, number>; operational: number; failed: CoverageRow[]; no_recent_activity: CoverageRow[]; sources: CoverageRow[]; note: string }
export interface BatchInfo { batch: number; sources: number; enabled: number; last_run: { status: string; finished_at: string | null; ok: number; failed: number; new_items: number; duplicate_items: number; max_write_wait: number | null; note: string | null } | null }
export interface Onboarding { batches: BatchInfo[]; history: { id: number; batch: number; started_at: string; finished_at: string | null; status: string; sources: number; enabled: number; ok: number; failed: number; new_items: number; duplicate_items: number; max_write_wait: number | null; note: string | null }[]; running: boolean; current: { batch: number | null; phase: string | null }; plan: Record<string, number>; rule: string }
export interface SourceForm { name?: string; url?: string; category?: string; publisher?: string; site?: string; country?: string; language?: string }

const B = '/api/v1/news/source-admin'
export const adminList = (f: AdminFilters) => req<AdminPage>('GET', `${B}?${qs({ ...f })}`)
export const adminCoverage = () => req<Coverage>('GET', `${B}/coverage`)
export const adminOnboarding = () => req<Onboarding>('GET', `${B}/onboarding`)
export const startBatch = (n: number, force = false) => req<{ started: boolean }>('POST', `${B}/onboarding/${n}?${qs({ force })}`)
export const addSource = (b: SourceForm) => req<{ id: string; enabled: boolean; validation: { status: string; note: string | null; entries: number } }>('POST', B, b)
export const editSource = (id: string, b: SourceForm) => req<{ id: string }>('PATCH', `${B}/${id}`, b)
export const deleteSource = (id: string) => req<{ deleted: boolean }>('DELETE', `${B}/${id}`)
export const validateSource = (id: string) => req<{ status: Validation; note: string | null; entries: number; newest: string | null; language: string | null }>('POST', `${B}/${id}/validate`)
export const setSourceEnabled = (id: string, enabled: boolean) => req<{ id: string }>('POST', `${B}/${id}/enabled`, { enabled })
export const bulkSources = (ids: string[], action: 'enable' | 'disable' | 'validate') => req<{ done: { id: string }[]; skipped: { id: string; reason: string }[] }>('POST', `${B}/bulk`, { ids, action })

export const VAL_LABEL: Record<string, string> = { verified: 'Verified', temporarily_unavailable: 'Temporarily unavailable', unsupported: 'Unsupported', invalid: 'Invalid', duplicate: 'Duplicate', unvalidated: 'Not validated' }
export const VAL_TONE: Record<string, string> = {
  verified: 'border-emerald-400/30 bg-emerald-400/10 text-emerald-300', temporarily_unavailable: 'border-amber-400/30 bg-amber-400/10 text-amber-300', unsupported: 'border-orange-400/30 bg-orange-400/10 text-orange-300',
  invalid: 'border-red-400/30 bg-red-400/10 text-red-300', duplicate: 'border-line text-mute', unvalidated: 'border-line text-mute',
}
export const STATE_LABEL: Record<string, string> = { healthy: 'Healthy', quiet: 'Quiet', failed: 'Failed', disabled: 'Disabled', pending: 'Pending first sync' }
export const STATE_TONE: Record<string, string> = {
  healthy: 'border-emerald-400/30 bg-emerald-400/10 text-emerald-300', quiet: 'border-sky-400/30 bg-sky-400/10 text-sky-300', failed: 'border-red-400/30 bg-red-400/10 text-red-300', disabled: 'border-line text-mute', pending: 'border-line text-mute',
}
