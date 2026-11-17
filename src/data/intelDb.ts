async function req<T>(method: string, url: string, body?: unknown): Promise<T> {
  const r = await fetch(url, { method, headers: body ? { 'Content-Type': 'application/json' } : undefined, body: body ? JSON.stringify(body) : undefined })
  if (!r.ok) {
    let msg = `HTTP ${r.status}`
    try { const j = await r.json(); if (typeof j.detail === 'string') msg = j.detail } catch { /* ignore */ }
    throw new Error(msg)
  }
  return r.json() as Promise<T>
}

export type DsStatus = 'not_initialized' | 'importing' | 'partial' | 'complete' | 'updating' | 'stale' | 'failed'
export interface Dataset { key: string; status: DsStatus; records: number; dataset_date: string | null; last_attempt: string | null; last_success: string | null; last_error: string | null; units_done: number; units_total: number; resumable: boolean }
export interface IntelStatus {
  overall: DsStatus; datasets: Record<string, Dataset>
  counts: { cves: number; cpe_records: number; cpe_match_criteria: number; nvd_products: number; nvd_vendors: number; cves_with_cvss: number; cves_with_cwe: number; cves_in_kev: number; cves_with_epss: number; affected_product_rows: number; epss_score_date: string | null; epss_model_version: string | null }
  last_successful_sync: string | null; database_bytes: number; disk_free_bytes: number | null; listing_index_rows: number
  active_run: { id: number; mode: string; datasets: string; started_at: string; heartbeat: string; processed: number; new_items: number; updated_items: number; errors: number; current: string | null; message: string | null } | null
  recent_runs: { id: number; mode: string; datasets: string; status: string; started_at: string; finished_at: string | null; processed: number; new_items: number; updated_items: number; errors: number; message: string | null }[]
  recent_errors: { run_id: number; dataset: string; item: string; message: string; at: string }[]
  limits: { batch: number; max_download_mb: number; max_uncompressed_mb: number; throttle_ms: number; epss_history_days: number }; note: string
}
export interface Estimate { datasets: { dataset: string; download_bytes: number; uncompressed_bytes: number }[]; download_bytes: number; uncompressed_bytes: number; estimated_db_bytes: number; temp_dir_peak_bytes: number; disk_free_bytes: number; disk_needed_bytes: number; enough_space: boolean; warning: string }
export interface CpeCandidate { vendor: string; product: string; part: string | null; dictionary_versions: number | null; title: string | null; cves: number; already_in_catalog: string | null }

const B = '/api/v1/intel-db'
export const fetchIntelStatus = () => req<IntelStatus>('GET', `${B}/status`)
export const fetchEstimate = () => req<Estimate>('GET', `${B}/estimate`)
export const initializeDb = (datasets: string[]) => req<{ started: boolean; run_id: number }>('POST', `${B}/initialize`, { datasets, confirm: true })
export const syncNow = () => req<{ started: boolean }>('POST', `${B}/sync`)
export const updateEpss = () => req<{ started: boolean }>('POST', `${B}/epss`)
export const updateKev = () => req<{ started: boolean }>('POST', `${B}/kev`)
export const resumeImport = () => req<{ started: boolean }>('POST', `${B}/resume`)
export const stopImport = () => req<{ requested: boolean }>('POST', `${B}/stop`)
export const cpeSearch = (q: string) => req<{ items: CpeCandidate[]; source: string | null; note?: string }>('GET', `/api/v1/catalog/cpe-search?q=${encodeURIComponent(q)}`)

export const DS_LABEL: Record<string, string> = { cve: 'NVD CVE', cpe: 'NVD CPE Dictionary', cpematch: 'NVD CPE Match Criteria', kev: 'CISA KEV', epss: 'FIRST EPSS' }
export const DS_TONE: Record<string, string> = {
  complete: 'border-emerald-400/30 bg-emerald-400/10 text-emerald-300', updating: 'border-accent/30 bg-accent/10 text-accent', importing: 'border-accent/30 bg-accent/10 text-accent',
  partial: 'border-amber-400/30 bg-amber-400/10 text-amber-300', stale: 'border-orange-400/30 bg-orange-400/10 text-orange-300', failed: 'border-red-400/30 bg-red-400/10 text-red-300', not_initialized: 'border-line text-mute',
}
export const bytes = (n: number | null | undefined) => (n === null || n === undefined ? 'unknown' : n >= 1e9 ? `${(n / 1e9).toFixed(1)} GB` : n >= 1e6 ? `${(n / 1e6).toFixed(1)} MB` : `${Math.round(n / 1e3)} KB`)
