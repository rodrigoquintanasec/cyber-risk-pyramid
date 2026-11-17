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

export interface Existing { id: string; name: string; category: string; enabled: number | boolean; custom: number | boolean }
export interface NvdProduct {
  part: 'a' | 'o' | 'h'; type: string; vendor: string; product: string; name: string; cpe_count: number; version_count: number; deprecated: boolean; deprecated_records: number
  last_modified: string | null; cve_count: number | null; cve_count_reliable: boolean; already_in_catalog: Existing | null
}
export interface ProductCoverage { state: 'not_initialized' | 'partial' | 'complete'; label: string; limitations: string[]; dictionary_ready: boolean }
export interface ProductStatus extends ProductCoverage { datasets: Record<string, string>; dataset_dates: Record<string, string | null>; cve_counts_reliable: boolean; products_indexed: number; vendors_indexed: number }
export interface ProductPage { items: NvdProduct[]; total: number; page: number; pages: number; coverage: ProductCoverage; note: string }
export interface ProductDetail {
  part: 'a' | 'o' | 'h'; type: string; vendor: string; product: string; name: string; cpe_count: number; deprecated: boolean; deprecated_records: number; last_modified: string | null
  cpe_identifiers: string[]; cpe_identifier_count: number; versions_preview: { version: string; records: number; active: number }[]; version_count: number
  variants: { edition: string; sw_edition: string; target_sw: string; target_hw: string; other: string; records: number }[]; variant_count: number
  references: { url: string; type: string | null }[]; deprecated_by: string[]; truncated: boolean
  cve_count: number | null; kev_count: number | null; cve_count_reliable: boolean; coverage: ProductStatus; already_in_catalog: Existing | null
  related_products: { product: string; display_name: string | null; cpe_count: number }[]; note: string
}
export interface AddResult { created: boolean; already_in_catalog: boolean; technology: { id: string; name: string; category: string }; correlated_cves?: { recent: number; historical: number }; coverage?: { label: string; limitations: string[] }; message: string }
export interface Category { id: string; name: string; description: string; sort_order: number; active: boolean; technologies: number; enabled_technologies: number }

const P = '/api/v1/products'
export const productStatus = () => req<ProductStatus>('GET', `${P}/status`)
export const productSearch = (f: { q?: string; vendor?: string; part?: string; deprecated?: string; sort?: string; page?: number; page_size?: number }) => req<ProductPage>('GET', `${P}/search?${qs(f)}`)
export const productVendors = (q: string) => req<{ items: { vendor: string; products: number }[] }>('GET', `${P}/vendors?${qs({ q })}`)
export const productDetail = (p: { part: string; vendor: string; product: string }) => req<ProductDetail>('GET', `${P}/detail?${qs(p)}`)
export const productVersions = (p: { part: string; vendor: string; product: string; q?: string; page?: number }) => req<{ items: { version: string; records: number; deprecated: boolean }[]; total: number }>('GET', `${P}/versions?${qs(p)}`)
export const techVersions = (tid: string, q = '') => req<{ items: { version: string; product: string }[]; source: string | null }>('GET', `${P}/tech/${encodeURIComponent(tid)}/versions?${qs({ q })}`)
export const addProduct = (b: { part: string; vendor: string; product: string; category: string; name?: string; family?: { part: string; vendor: string; product: string }[] }) => req<AddResult>('POST', `${P}/add`, b)

const C = '/api/v1/categories'
export const fetchCategories = () => req<{ items: Category[] }>('GET', C)
export const createCategory = (b: { name: string; description?: string }) => req<Category>('POST', C, b)
export const updateCategory = (id: string, b: Partial<Pick<Category, 'name' | 'description' | 'active'>>) => req<Category>('PUT', `${C}/${id}`, b)
export const orderCategories = (ids: string[]) => req<{ items: Category[] }>('PUT', `${C}/order`, { ids })
export const deleteCategory = (id: string) => req<{ deleted: boolean }>('DELETE', `${C}/${id}`)
export const categoryTechs = (id: string) => req<{ items: { id: string; name: string; vendor: string; enabled: number; dashboard: number }[] }>('GET', `${C}/${id}/technologies`)
export const assignCategory = (tech_ids: string[], category: string) => req<{ moved: number }>('POST', `${C}/assign`, { tech_ids, category })
