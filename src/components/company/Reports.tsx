import { useState } from 'react'
import { Copy, Printer } from 'lucide-react'
import { cMakeReport, cReport, cReportText, cReports, type Company, type Report } from '../../data/company'
import { Note, Segmented, Status, card, fmt, useAsync } from '../intel/ui'
import { btn, btn2 } from './common'

const esc = (s: unknown) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]!)
const cell = (v: unknown) => (v === null || v === undefined ? 'N/A' : Array.isArray(v) ? v.join(', ') || '-' : typeof v === 'object' ? JSON.stringify(v) : String(v))

/* eslint-disable @typescript-eslint/no-explicit-any */
function Table({ rows, cols }: { rows: any[]; cols: [string, string][] }) {
  if (!rows?.length) return <div className="text-xs text-mute">None in this period.</div>
  return <div className="overflow-x-auto"><table className="w-full text-xs"><thead className="text-left text-mute"><tr>{cols.map(([, l]) => <th key={l} className="py-1 pr-3">{l}</th>)}</tr></thead><tbody>{rows.map((r, i) => <tr key={i} className="border-t border-line/60">{cols.map(([k]) => <td key={k} className="py-1 pr-3 text-ink">{cell(r[k])}</td>)}</tr>)}</tbody></table></div>
}

function ReportView({ r }: { r: Report }) {
  const s = r.sections
  const sec = (title: string, body: any) => <section className="rounded-lg border border-line p-4"><h4 className="mb-2 text-sm font-semibold text-ink">{title}</h4>{body}</section>
  return (
    <div className="space-y-3">
      {sec('A. Executive Summary', <ul className="list-disc space-y-1 pl-5 text-xs text-ink">{s.A_executive_summary.lines.map((l: string) => <li key={l}>{l}</li>)}</ul>)}
      {sec('B. Monitored Technology Overview', <><Table rows={s.B_technologies.rows} cols={[['name', 'Technology'], ['assets', 'Assets'], ['versions', 'Versions'], ['assets_without_version', 'No version'], ['threat_signal', 'Threat Signal'], ['level', 'Level'], ['related_cves', 'CVEs'], ['kev', 'KEV'], ['news_events', 'News ev.']]} /><p className="mt-2 text-[11px] text-mute">{s.B_technologies.note}</p></>)}
      {sec('C. Vulnerability Intelligence', <><p className="mb-2 text-xs text-mute">{s.C_vulnerabilities.total_related} unique related CVE(s); {s.C_vulnerabilities.published_in_period} published in the period.</p><Table rows={s.C_vulnerabilities.top} cols={[['cve', 'CVE'], ['cvss', 'CVSS'], ['epss', 'EPSS'], ['kev', 'KEV'], ['status', 'Applicability'], ['products', 'Products']]} /></>)}
      {sec('D. CISA KEV Watch', <><p className="mb-2 text-xs text-mute">{s.D_kev.related_total} related CVE(s) are in KEV overall. A KEV listing is not evidence about this company.</p><Table rows={s.D_kev.added_in_period} cols={[['cve', 'CVE'], ['kev_added', 'KEV added'], ['cvss', 'CVSS'], ['status', 'Applicability'], ['products', 'Products']]} /></>)}
      {sec('E. Potential & Confirmed Exposure', <><p className="mb-2 text-xs text-mute">{Object.entries(s.E_exposure.counts).map(([k, v]) => `${k.replace(/_/g, ' ')}: ${v}`).join(' · ')}</p><div className="mb-1 text-[11px] uppercase text-mute">Confirmed (analyst evidence)</div><Table rows={s.E_exposure.confirmed} cols={[['cve', 'CVE'], ['products', 'Products'], ['evidence', 'Evidence']]} /><div className="mb-1 mt-3 text-[11px] uppercase text-mute">Potentially applicable</div><Table rows={s.E_exposure.potential} cols={[['cve', 'CVE'], ['cvss', 'CVSS'], ['kev', 'KEV'], ['products', 'Products']]} /><p className="mt-2 text-[11px] text-mute">{s.E_exposure.note}</p></>)}
      {sec('F. Related Security News', <Table rows={s.F_news.events} cols={[['title', 'Event'], ['sources', 'Sources'], ['priority', 'Priority'], ['last', 'Last']]} />)}
      {sec('G. Official Security Advisories', <Table rows={s.G_advisories.events} cols={[['title', 'Advisory event'], ['sources', 'Sources'], ['last', 'Last']]} />)}
      {sec('H. Intelligence Trends', <><p className="text-xs text-mute">{s.H_trends.status === 'ok' ? (s.H_trends.events ? `Events: ${s.H_trends.events.current}${s.H_trends.events.delta !== null ? ` (Δ ${s.H_trends.events.delta}${s.H_trends.events.pct !== null ? `, ${s.H_trends.events.pct}%` : ''})` : ''}. ${s.H_trends.events.reason ?? ''}` : '') : 'Insufficient comparable coverage.'}</p><Table rows={s.H_trends.attention} cols={[['name', 'Technology'], ['events', 'Events']]} /><p className="mt-2 text-[11px] text-mute">{s.H_trends.note}</p></>)}
      {sec('I. Inventory Coverage & Data Quality', <p className="text-xs text-ink">Active assets {s.I_inventory.coverage.active_assets} · version known {cell(s.I_inventory.coverage.with_version_pct)}% · internet exposure known {cell(s.I_inventory.coverage.exposure_known_pct)}% · verified ≤ 90 days {cell(s.I_inventory.coverage.verified_90d_pct)}% · inventory coverage {cell(s.I_inventory.coverage.inventory_coverage)}% · median verification age {cell(s.I_inventory.coverage.median_verification_age_days)} days</p>)}
      {sec('J. Sources & Limitations', <><div className="mb-2 text-xs text-mute">Sources: {s.J_sources.sources.join('; ')}. Last news sync: {r.last_sync ? fmt(r.last_sync) : 'unknown'}.</div><ul className="list-disc space-y-1 pl-5 text-xs text-mute">{s.J_sources.limitations.map((l: string) => <li key={l}>{l}</li>)}</ul></>)}
    </div>
  )
}

function printReport(r: Report) {
  const s = r.sections
  const rows = (arr: any[], cols: [string, string][]) => (arr?.length ? `<table><tr>${cols.map(([, l]) => `<th>${esc(l)}</th>`).join('')}</tr>${arr.map((x) => `<tr>${cols.map(([k]) => `<td>${esc(cell(x[k]))}</td>`).join('')}</tr>`).join('')}</table>` : '<p>None in this period.</p>')
  const html = `<!doctype html><html><head><meta charset="utf-8"><title>${esc(r.company.name)} — Company Threat Intelligence Report</title><style>body{font:13px/1.45 system-ui,sans-serif;color:#111;margin:28px}h1{font-size:20px}h2{font-size:15px;border-bottom:1px solid #ccc;padding-bottom:3px;margin-top:22px}table{border-collapse:collapse;width:100%;font-size:11px}th,td{border:1px solid #ccc;padding:3px 6px;text-align:left}small{color:#555}</style></head><body>
<h1>Company Threat Intelligence Report — ${esc(r.company.name)}</h1><small>${esc(r.period_label)} · ${esc(r.since)} to ${esc(r.until)} (UTC) · generated ${esc(r.generated_at)} · last news sync ${esc(r.last_sync ?? 'unknown')}</small>
<h2>A. Executive Summary</h2><ul>${s.A_executive_summary.lines.map((l: string) => `<li>${esc(l)}</li>`).join('')}</ul>
<h2>B. Monitored Technology Overview</h2>${rows(s.B_technologies.rows, [['name', 'Technology'], ['assets', 'Assets'], ['versions', 'Versions'], ['threat_signal', 'Threat Signal'], ['related_cves', 'CVEs'], ['kev', 'KEV']])}<small>${esc(s.B_technologies.note)}</small>
<h2>C. Vulnerability Intelligence</h2>${rows(s.C_vulnerabilities.top, [['cve', 'CVE'], ['cvss', 'CVSS'], ['epss', 'EPSS'], ['kev', 'KEV'], ['status', 'Applicability'], ['products', 'Products']])}
<h2>D. CISA KEV Watch</h2>${rows(s.D_kev.added_in_period, [['cve', 'CVE'], ['kev_added', 'KEV added'], ['status', 'Applicability']])}
<h2>E. Potential & Confirmed Exposure</h2><p>${esc(Object.entries(s.E_exposure.counts).map(([k, v]) => `${k}: ${v}`).join(' · '))}</p>${rows(s.E_exposure.confirmed, [['cve', 'CVE'], ['products', 'Products'], ['evidence', 'Evidence']])}<small>${esc(s.E_exposure.note)}</small>
<h2>F. Related Security News</h2>${rows(s.F_news.events, [['title', 'Event'], ['sources', 'Sources'], ['last', 'Last']])}
<h2>G. Official Security Advisories</h2>${rows(s.G_advisories.events, [['title', 'Advisory event'], ['sources', 'Sources'], ['last', 'Last']])}
<h2>H. Intelligence Trends</h2>${rows(s.H_trends.attention, [['name', 'Technology'], ['events', 'Events']])}<small>${esc(s.H_trends.note)}</small>
<h2>I. Inventory Coverage &amp; Data Quality</h2><p>${esc(JSON.stringify(s.I_inventory.coverage))}</p>
<h2>J. Sources &amp; Limitations</h2><p>${esc(s.J_sources.sources.join('; '))}</p><ul>${s.J_sources.limitations.map((l: string) => `<li>${esc(l)}</li>`).join('')}</ul></body></html>`
  const w = window.open('', '_blank')
  if (!w) return
  w.document.open(); w.document.write(html); w.document.close(); w.focus(); setTimeout(() => w.print(), 300)
}

export default function Reports({ company }: { company: Company }) {
  const list = useAsync(() => cReports(company.id), [company.id])
  const [period, setPeriod] = useState('30d')
  const [sel, setSel] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState<string | null>(null)
  const [copied, setCopied] = useState(false)
  const rep = useAsync(() => (sel ? cReport(company.id, sel) : Promise.resolve(null)), [company.id, sel])
  const gen = () => { setBusy(true); setErr(null); cMakeReport(company.id, period).then((r) => { list.reload(); setSel(r.id) }).catch((e) => setErr(String(e.message))).finally(() => setBusy(false)) }
  const copy = () => { if (sel) cReportText(company.id, sel).then((t) => navigator.clipboard.writeText(t.text)).then(() => { setCopied(true); setTimeout(() => setCopied(false), 1500) }).catch(() => setErr('Clipboard unavailable')) }
  return (
    <div className="space-y-4 p-6">
      <div className="flex flex-wrap items-center gap-3">
        <Segmented options={[['24h', 'Last 24 Hours'], ['7d', 'Last 7 Days'], ['30d', 'Last 30 Days'], ['90d', 'Last 90 Days']]} value={period} onChange={setPeriod} />
        <button onClick={gen} disabled={busy} className={btn}>{busy ? 'Generating…' : 'Generate report'}</button>
        <span className="text-xs text-mute">Deterministic template over existing data; no AI. Reports are stored and remain available.</span>
      </div>
      {err && <Note tone="warn">{err}</Note>}
      <div className="grid gap-4 xl:grid-cols-[260px_1fr]">
        <div className={`${card} p-3`}><div className="mb-2 text-[11px] uppercase tracking-wider text-mute">Previous reports</div>
          <Status loading={list.loading && !list.data} error={list.error} empty={!!list.data && list.data.items.length === 0} emptyText="No reports yet." />
          <ul className="space-y-1">{(list.data?.items ?? []).map((r) => <li key={r.id}><button onClick={() => setSel(r.id)} className={`w-full rounded-lg border px-3 py-2 text-left text-xs ${sel === r.id ? 'border-accent/40 bg-accent/10 text-accent' : 'border-line text-ink hover:border-accent/30'}`}>{fmt(r.generated_at)}<div className="text-mute">{r.period}</div></button></li>)}</ul></div>
        <div>
          {!sel && <div className="rounded-xl border border-dashed border-line py-16 text-center text-sm text-mute">Generate a report or select a previous one.</div>}
          {sel && <Status loading={rep.loading && !rep.data} error={rep.error} />}
          {rep.data && (
            <div className="space-y-3">
              <div className="flex flex-wrap items-center gap-2"><div><div className="text-sm font-semibold text-ink">Company Threat Intelligence Report — {rep.data.company.name}</div><div className="text-xs text-mute">{rep.data.period_label} · generated {fmt(rep.data.generated_at)} · last news sync {rep.data.last_sync ? fmt(rep.data.last_sync) : 'unknown'}</div></div>
                <div className="ml-auto flex gap-2"><button onClick={copy} className={btn2}><Copy size={12} className="mr-1 inline" />{copied ? 'Copied' : 'Copy summary'}</button><button onClick={() => printReport(rep.data!)} className={btn2}><Printer size={12} className="mr-1 inline" />Print / PDF</button></div></div>
              <ReportView r={rep.data} />
            </div>)}
        </div>
      </div>
    </div>
  )
}
