/* eslint-disable @typescript-eslint/no-explicit-any */
// Pure (no React, no DOM): builds the standalone light-theme document used by the preview and by Print / Save as PDF.
// Everything from feeds is untrusted: text is escaped, URLs are validated, nothing remote is loaded (CSP below), no script is embedded.
import type { Briefing } from '../../data/types'

export const esc = (v: unknown) => String(v ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c] as string)

/** Absolute http(s) URL without credentials / whitespace / markup characters; anything else (javascript:, data:, relative…) is dropped, never repaired. */
export function safeUrl(u: unknown): string | null {
  if (typeof u !== 'string') return null
  const s = u.trim()
  if (!s || s.length > 2000 || /[\x00-\x20\x7f<>"'`\\]/.test(s)) return null
  try {
    const p = new URL(s)
    if ((p.protocol !== 'https:' && p.protocol !== 'http:') || !p.hostname || p.username || p.password) return null
    return s
  } catch { return null }
}
const host = (u: string) => { try { return new URL(u).hostname.replace(/^www\./, '') } catch { return '' } }
const link = (url: unknown, text: unknown, cls = '') => {
  const u = safeUrl(url)
  return u ? `<a${cls ? ` class="${cls}"` : ''} href="${esc(u)}" target="_blank" rel="noopener noreferrer nofollow">${esc(text)}</a>` : esc(text)
}
const when = (iso?: string | null) => (iso ? new Date(iso).toLocaleString('en-US', { dateStyle: 'medium', timeStyle: 'short', timeZone: 'UTC' }) + ' UTC' : 'N/A')
const day = (iso?: string | null) => (iso && !isNaN(Date.parse(iso)) ? new Date(iso).toISOString().slice(0, 10) : '')
const nvd = (cve: string) => `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(cve)}`
const CVE_RE = /^CVE-\d{4}-\d{4,}$/

export interface Ref { name: string; title: string; url: string; published?: string | null; kind: string }
export interface BibEntry { id: string; kind: string; outlet: string; title: string; published?: string | null; url: string; supports: string[] }

/** Missing pieces of briefings stored before this layout existed are derived from what they do contain (nothing is invented). */
export function normalize(b: Briefing): any {
  const S = (id: string) => (b.sections.find((s) => s.id === id) as any) ?? {}
  const ex = S('executive_summary'), top = S('top_stories'), vw = S('vulnerability_watch'), tl = S('threat_landscape'), tw = S('technology_watchlist'), sq = S('sources_quality')
  const stories = (top.items ?? []).map((i: any) => ({ ...i, sources: (i.sources ?? []).map((s: any) => ({ kind: 'news', ...s })), cves: i.cves ?? [], technologies: i.technologies ?? [] }))
  const watch = (vw.items ?? []).map((w: any) => ({ ...w, products: w.products ?? [], references: (w.references ?? []).map((r: any) => ({ kind: r.kind ?? (r.label === 'NVD' ? 'nvd' : /KEV/.test(r.label ?? '') ? 'kev' : /EPSS/.test(r.label ?? '') ? 'epss' : 'other'), ...r })) }))
  const themes = (tl.themes ?? []).map((t: any) => ({ ...t, items: (t.items ?? []).map((i: any) => ({ ...i, sources: i.sources ?? (safeUrl(i.first_url) ? [{ name: host(i.first_url), title: i.title, url: i.first_url, kind: 'news' }] : []) })) }))
  const techs = (tw.items ?? []).map((t: any) => ({
    ...t, kev_cves: t.kev_cves ?? [], news: t.news ?? (t.top_events ?? []).filter((e: any) => safeUrl(e.url)).map((e: any) => ({ name: host(e.url), title: e.title, url: e.url, kind: 'news', event: e.title })),
    cves: t.cves ?? (t.verified_signals ?? []).map((v: any) => ({ cve: v.cve, in_kev: (t.kev_cves ?? []).includes(v.cve), url: nvd(v.cve) })),
    signals: t.signals ?? { media_attention: t.media_signal, threat_signal: t.pyramid_threat_signal ? `Pyramid Threat Signal ${t.pyramid_threat_signal.score ?? 'N/A'} (separate metric)` : 'Not available for this technology.', vulnerability_applicability: 'Not assessed here: a CVE mentioned in the news is not confirmed to apply to any version or company asset.' },
  }))
  const cveSet = new Set<string>([...stories.flatMap((s: any) => s.cves), ...watch.map((w: any) => w.cve)])
  const cover = b.cover ?? {
    title: 'CYBER RISK PYRAMID', subtitle: b.title, period_label: b.period.label, since: b.period.since, until: b.period.until, generated_at: b.generated_at,
    scope: `Open-source cybersecurity news and local NVD, CISA KEV and EPSS data for the ${String(b.period.label).toLowerCase()}.`,
    unique_events: b.coverage.events, contributing_sources: b.coverage.sources_contributing, cves_identified: cveSet.size, cves_in_kev: watch.filter((w: any) => w.in_kev).length,
    coverage_status: b.coverage.status, note: 'Open-source cybersecurity intelligence compiled from verified data sources.',
  }
  const blocks = ex.blocks ?? [{ id: 'summary', title: 'Summary', items: ex.bullets ?? [] }]
  const bib: BibEntry[] = b.bibliography ?? deriveBibliography(stories, watch, themes, techs)
  const methodology = sq.methodology ?? ['Events are grouped with fixed, deterministic rules; no AI is used.', 'News Priority Score ranks reading priority, not business risk.', 'A technology mention does not imply exposure.', 'CISA KEV indicates known exploitation, not necessarily recent.']
  return { cover, ex: { ...ex, blocks }, stories, watch, themes, techs, sq: { ...sq, failed_sources: sq.failed_sources ?? [], used_sources: sq.used_sources ?? [], coverage: sq.coverage ?? b.coverage, methodology }, bib }
}

function deriveBibliography(stories: any[], watch: any[], themes: any[], techs: any[]): BibEntry[] {
  const m = new Map<string, BibEntry>()
  const add = (kind: string, outlet: string, title: string, published: string | null | undefined, url: unknown, sup: string) => {
    const u = safeUrl(url); if (!u) return
    const e = m.get(u) ?? { id: '', kind, outlet, title: title || u, published, url: u, supports: [] }
    if (!e.supports.includes(sup)) e.supports.push(sup)
    m.set(u, e)
  }
  stories.forEach((s) => s.sources.forEach((x: any) => add(x.kind ?? 'news', x.name, x.title, x.published, x.url, `Story ${s.rank}`)))
  themes.forEach((t: any) => t.items.forEach((i: any) => i.sources.forEach((x: any) => add(x.kind ?? 'news', x.name, x.title, x.published, x.url, `Landscape: ${t.theme}`))))
  watch.forEach((w: any) => w.references.forEach((r: any) => { if (['nvd', 'kev', 'advisory'].includes(r.kind)) add(r.kind, r.kind === 'nvd' ? 'NVD' : r.kind === 'kev' ? 'CISA' : r.label, r.title ?? (r.kind === 'nvd' ? w.cve : 'Known Exploited Vulnerabilities Catalog'), r.published, r.url, w.cve) }))
  techs.forEach((t: any) => t.news.forEach((x: any) => add(x.kind ?? 'news', x.name, x.title, x.published, x.url, `Watchlist: ${t.name}`)))
  const order: Record<string, number> = { news: 0, advisory: 1, nvd: 2, kev: 3 }
  return [...m.values()].sort((a, b) => (order[a.kind] ?? 9) - (order[b.kind] ?? 9) || a.outlet.localeCompare(b.outlet) || a.title.localeCompare(b.title)).map((e, i) => ({ ...e, id: `R${i + 1}` }))
}

const KIND_LABEL: Record<string, string> = { news: 'News coverage', advisory: 'Official advisories', nvd: 'NVD records', kev: 'CISA KEV catalog' }
const STATUS_TXT: Record<string, string> = { complete: 'Complete', partial: 'Partial', stale: 'Stale', insufficient: 'Insufficient' }
const num = (v: unknown, dp = 2) => (typeof v === 'number' && isFinite(v) ? v.toFixed(dp) : 'N/A')

export const PRINT_CSS = `
@page{size:A4;margin:18mm 16mm 20mm}
@page{@bottom-left{content:"Cyber Risk Pyramid · Morning Cyber Briefing";font:8pt Arial,sans-serif;color:#64748b}@bottom-right{content:"Page " counter(page) " of " counter(pages);font:8pt Arial,sans-serif;color:#64748b}}
@page :first{@bottom-left{content:none}@bottom-right{content:none}}
*{box-sizing:border-box}
html{-webkit-print-color-adjust:exact;print-color-adjust:exact}
body{margin:0;background:#e9eef3;color:#1e293b;font:10.5pt/1.5 "Segoe UI",Calibri,Arial,Helvetica,sans-serif}
.sheet{max-width:794px;margin:24px auto;background:#fff;padding:56px 60px;box-shadow:0 2px 14px rgba(15,23,42,.15)}
h1,h2,h3,h4{font-family:"Segoe UI",Calibri,Arial,sans-serif;color:#0b1f3a;margin:0}
a{color:#0e7490;text-decoration:none;overflow-wrap:anywhere}a:hover{text-decoration:underline}
p{margin:.35em 0}ul{margin:.3em 0;padding-left:1.2em}li{margin:.15em 0}
.cover{min-height:240mm;display:flex;flex-direction:column;justify-content:space-between;break-after:page}.guide{border-top:1px solid #cbd5e1;padding-top:4mm;margin-top:8mm;font-size:9pt;color:#475569}.guide h4{margin:0 0 1.5mm}.guide ul{margin:0;padding-left:1.1em}
.brand{font:700 11pt Arial,sans-serif;letter-spacing:.32em;color:#0891b2;margin-top:6mm}
.cover h1{font-size:34pt;line-height:1.1;margin:10mm 0 3mm;letter-spacing:.01em}.rule{height:4px;width:64px;background:#0891b2;margin:5mm 0 7mm}
.cover .period{font-size:14pt;color:#0b1f3a}.cover .sub{color:#475569;margin-top:2mm}
.kpis{display:grid;grid-template-columns:repeat(3,1fr);gap:0;border:1px solid #cbd5e1;margin:10mm 0 6mm}
.kpi{padding:5mm 5mm;border-right:1px solid #cbd5e1;border-bottom:1px solid #cbd5e1}.kpi:nth-child(3n){border-right:0}.kpi:nth-last-child(-n+3){border-bottom:0}
.kpi b{display:block;font:700 20pt Arial,sans-serif;color:#0b1f3a}.kpi span{font:8.5pt Arial,sans-serif;text-transform:uppercase;letter-spacing:.08em;color:#64748b}
.note{border-left:3px solid #0891b2;background:#f0f9ff;padding:3mm 4mm;color:#0b1f3a}.caveat{color:#64748b;font-size:9pt;margin-top:3mm}
.toc{margin-top:6mm;columns:2;font-size:9.5pt;color:#334155}.toc-h{font:700 8pt Arial,sans-serif;text-transform:uppercase;letter-spacing:.08em;color:#0e7490;margin:0 0 1.5mm}.toc div{break-inside:avoid;margin:.1em 0}
h2.sec{font-size:13pt;text-transform:uppercase;letter-spacing:.06em;color:#0b1f3a;border-bottom:2px solid #0891b2;padding-bottom:2mm;margin:9mm 0 4mm;break-after:avoid}
h2.sec:first-of-type{margin-top:0}
h3{font-size:11.5pt;break-after:avoid}h4{font-size:9.5pt;text-transform:uppercase;letter-spacing:.06em;color:#0e7490;margin:4mm 0 1mm;break-after:avoid}
.meta{font-size:8.5pt;color:#64748b}.warn{color:#92400e}
.block{margin:0 0 3.5mm;break-inside:avoid}.block h4{margin-top:0}
.story{border:1px solid #d5dde6;border-left:4px solid #0b1f3a;padding:3.5mm 4.5mm;margin:0 0 4mm;break-inside:avoid;page-break-inside:avoid}
.story .top{display:flex;flex-wrap:wrap;gap:2mm 3mm;align-items:center;font:8.5pt Arial,sans-serif;color:#475569}
.num{display:inline-block;min-width:6mm;text-align:center;background:#0b1f3a;color:#fff;font-weight:700;border-radius:3px;padding:0 2mm}
.tag{border:1px solid #0891b2;color:#0e7490;border-radius:10px;padding:0 2.5mm}.score{border:1px solid #0b1f3a;color:#0b1f3a;border-radius:10px;padding:0 2.5mm;font-weight:700}
.story h3{margin:2mm 0 1.5mm;font-size:12.5pt;line-height:1.3}.why{font-size:9pt;color:#475569}
.chips{margin:2mm 0 0}.chip{display:inline-block;border:1px solid #cbd5e1;border-radius:3px;padding:0 2mm;margin:0 1.5mm 1mm 0;font:8.5pt Arial,sans-serif}.chip.kev{border-color:#b91c1c;background:#fef2f2}.chip.kev a{color:#b91c1c}
.src{margin-top:2mm;font-size:9pt;border-top:1px dashed #cbd5e1;padding-top:1.5mm}.src b{font:700 8pt Arial,sans-serif;text-transform:uppercase;letter-spacing:.06em;color:#64748b;margin-right:2mm}
table{width:100%;border-collapse:collapse;table-layout:fixed;font-size:9pt}th{background:#0b1f3a;color:#fff;text-align:left;font:700 8pt Arial,sans-serif;text-transform:uppercase;letter-spacing:.05em;padding:2mm 2mm}
td{border-bottom:1px solid #d5dde6;padding:2mm;vertical-align:top;overflow-wrap:anywhere;word-break:break-word}thead{display:table-header-group}tr{break-inside:avoid;page-break-inside:avoid}tbody tr:nth-child(even) td{background:#f8fafc}
.kevyes{color:#b91c1c;font-weight:700}.na{color:#94a3b8}
.theme{break-inside:avoid;margin:0 0 4mm}.theme h3{border-bottom:1px solid #d5dde6;padding-bottom:1mm;margin-bottom:1.5mm}.theme li{margin:.35em 0}.theme .meta{display:block}
.tech{border:1px solid #d5dde6;padding:3mm 4mm;margin:0 0 3.5mm;break-inside:avoid}.tech h3{margin-bottom:1.5mm}.tech dl{margin:0;display:grid;grid-template-columns:34mm 1fr;gap:1mm 3mm;font-size:9.5pt}.tech dt{font:700 8pt Arial,sans-serif;text-transform:uppercase;letter-spacing:.05em;color:#0e7490;padding-top:1px}.tech dd{margin:0}
.grid2{display:grid;grid-template-columns:repeat(4,1fr);border:1px solid #cbd5e1;margin:2mm 0 3mm}.grid2 div{padding:3mm;border-right:1px solid #cbd5e1}.grid2 div:last-child{border-right:0}.grid2 b{display:block;font:700 14pt Arial,sans-serif;color:#0b1f3a}.grid2 span{font:8pt Arial,sans-serif;color:#64748b;text-transform:uppercase}
.bibgroup{break-inside:auto}.bib td:first-child{color:#64748b}.bib td:nth-child(5){color:#64748b;font-size:8pt}.bib td:nth-child(4){white-space:nowrap}
.disc{margin-top:8mm;border-top:1px solid #cbd5e1;padding-top:3mm;font-size:8.5pt;color:#64748b}
.pagebreak{display:block;margin:10mm -60px;border-top:1px dashed #94a3b8;text-align:center;height:0}.pagebreak span{position:relative;top:-9px;background:#fff;color:#94a3b8;font:8pt Arial,sans-serif;padding:0 8px}
@media print{
  body{background:#fff}.sheet{max-width:none;margin:0;padding:0;box-shadow:none}
  .pagebreak{margin:0;border:0;height:0;break-after:page}.pagebreak span{display:none}
  a{color:#0e7490}tr,.story,.tech,.theme{break-inside:avoid}h2.sec,h3,h4{break-after:avoid}
  .cover{min-height:0;height:255mm}
}`

const CSP = `<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'">`

export function briefingDocument(b: Briefing): string {
  const n = normalize(b)
  const c = n.cover
  const o: string[] = []
  const secTitle = (s: string) => s.replace(/^[A-Z]\.\s*/, '')

  // ---- cover
  const kpi = (v: unknown, l: string) => `<div class="kpi"><b>${esc(v)}</b><span>${esc(l)}</span></div>`
  o.push(`<section class="cover"><div><div class="brand">${esc(c.title)}</div><h1>${esc(c.subtitle)}</h1><div class="rule"></div>
    <div class="period">${esc(c.period_label)}</div><div class="sub">${esc(when(c.since))} → ${esc(when(c.until))}</div><div class="sub">Generated ${esc(when(c.generated_at))}</div>
    <p style="margin-top:7mm">${esc(c.scope)}</p>
    <div class="kpis">${kpi(c.unique_events, 'Unique events')}${kpi(c.contributing_sources, 'Contributing sources')}${kpi(c.cves_identified, 'CVEs identified')}${kpi(c.cves_in_kev, 'CVEs in CISA KEV')}${kpi(STATUS_TXT[c.coverage_status] ?? c.coverage_status, 'Coverage status')}${kpi(c.period_label.replace('Last ', ''), 'Period analysed')}</div>
    <div class="note">${esc(c.note)}</div><div class="caveat">Events are media reports grouped by fixed rules; they are not all confirmed incidents. A technology or CVE mention is not confirmed exposure.</div></div>
    <div><div class="guide"><h4>How to read this report</h4><ul>${n.sq.methodology.map((m: string) => `<li>${esc(m)}</li>`).join('')}</ul></div>
    <div class="toc-h" style="margin-top:6mm">Contents</div><div class="toc"><div>1. Executive Summary</div><div>2. Top Security Stories</div><div>3. Critical Vulnerability Watch</div><div>4. Threat Landscape</div><div>5. Technology Watchlist</div><div>6. Sources &amp; Data Quality</div>${n.bib.length ? '<div>7. Sources &amp; References</div>' : ''}</div></div></section>`)

  // ---- executive summary
  o.push(`<h2 class="sec">${esc(secTitle(n.ex.title ?? 'Executive Summary'))}</h2>` + n.ex.blocks.map((k: any) => `<div class="block"><h4>${esc(k.title)}</h4>${k.text ? `<p>${esc(k.text)}</p>` : ''}${k.items?.length ? `<ul>${k.items.map((x: string) => `<li>${esc(x)}</li>`).join('')}</ul>` : ''}</div>`).join(''))

  // ---- top stories
  o.push(`<h2 class="sec">Top Security Stories</h2>`)
  if (!n.stories.length) o.push('<p class="meta">No events in the selected period.</p>')
  for (const s of n.stories) {
    const why = (s.priority?.why ?? []).map((w: string) => w.split(' — ')[0]).join('; ')
    o.push(`<article class="story"><div class="top"><span class="num">${esc(s.rank)}</span><span class="tag">${esc(s.category)}</span><span class="score" title="News Priority Score: reading priority, not risk">Priority ${esc(s.priority?.score ?? 'N/A')}</span><span>${esc(when(s.first_published))}</span><span>${esc(s.publishers)} publisher(s) · ${esc(s.articles)} article(s)</span></div>
      <h3>${esc(s.title)}</h3><p>${esc(s.description)}</p>${why ? `<p class="why"><b>Why it ranks:</b> ${esc(why)}</p>` : ''}
      ${s.cves.length || s.technologies.length ? `<div class="chips">${s.cves.map((v: string) => `<span class="chip">${CVE_RE.test(v) ? link(nvd(v), v) : esc(v)}</span>`).join('')}${s.technologies.map((t: string) => `<span class="chip">${esc(t)}</span>`).join('')}</div>` : ''}
      <div class="src"><b>Sources</b>${s.sources.length ? s.sources.map((x: any) => link(x.url, x.name)).join(' · ') : '<span class="meta">No original link available.</span>'}</div></article>`)
  }

  // ---- vulnerability watch
  o.push(`<h2 class="sec">Critical Vulnerability Watch</h2>`)
  if (!n.watch.length) o.push('<p class="meta">No CVEs cited in the period.</p>')
  else {
    o.push(`<table><colgroup><col style="width:23%"><col style="width:8%"><col style="width:8%"><col style="width:12%"><col style="width:23%"><col style="width:26%"></colgroup><thead><tr><th>CVE</th><th>CVSS</th><th>EPSS</th><th>CISA KEV</th><th>Product (per source)</th><th>References</th></tr></thead><tbody>`)
    for (const w of n.watch) {
      const refs = w.references.filter((r: any) => ['nvd', 'advisory', 'kev'].includes(r.kind))
      const prod = (w.products ?? []).slice(0, 3).join(', ')
      o.push(`<tr><td><b>${CVE_RE.test(w.cve) ? link(nvd(w.cve), w.cve) : esc(w.cve)}</b></td><td>${w.cvss != null ? esc(w.cvss) : '<span class="na">N/A</span>'}</td><td>${w.epss != null ? num(w.epss) : '<span class="na">N/A</span>'}</td>
        <td>${w.in_kev ? `<span class="kevyes">Yes</span>${w.kev?.ransomware ? '<div class="meta">ransomware use</div>' : ''}` : 'No'}</td>
        <td>${prod ? esc(prod) + `<div class="meta">reported via ${esc(w.products_origin ?? 'source data')}; not validated for any asset</div>` : '<span class="na">N/A</span>'}</td>
        <td>${refs.map((r: any) => `${link(r.url, r.kind === 'nvd' ? 'NVD' : r.kind === 'kev' ? 'CISA KEV' : r.label)}<span class="meta"> ${r.kind === 'advisory' ? '(advisory)' : r.kind === 'nvd' ? '(record)' : '(catalog)'}</span>`).join('<br>') || '<span class="na">N/A</span>'}</td></tr>`)
    }
    o.push('</tbody></table><p class="meta">N/A = not available locally. Only CVEs cited in the period\'s news. "Product" repeats what NVD/CISA list for the CVE; it is not a finding that any product or asset is affected.</p>')
  }

  // ---- threat landscape
  o.push(`<h2 class="sec">Threat Landscape</h2>`)
  const themes = n.themes.filter((t: any) => t.events > 0)
  if (!themes.length) o.push('<p class="meta">No events in the selected period.</p>')
  for (const t of themes) {
    o.push(`<div class="theme"><h3>${esc(t.theme)} <span class="meta">${esc(t.events)} event(s)</span></h3>${t.named_families?.length ? `<p class="meta">Named: ${t.named_families.map((f: any) => esc(f.name)).join(', ')}</p>` : ''}<ul>${t.items.map((i: any) =>
      `<li>${i.sources.length ? link(i.sources[0].url, i.title) : esc(i.title)}<span class="meta">Priority ${esc(i.priority)}${i.also_in_top ? ` · also Top story ${esc(i.also_in_top)}` : ''}${i.sources.length ? ' · ' + i.sources.map((x: any) => link(x.url, x.name)).join(' · ') : ''}</span></li>`).join('')}</ul>${t.more > 0 ? `<p class="meta">+${esc(t.more)} more event(s) not listed.</p>` : ''}</div>`)
  }

  // ---- technology watchlist
  o.push(`<h2 class="sec">Technology Watchlist</h2>`)
  if (!n.techs.length) o.push('<p class="meta">No watched technology appears in the period.</p>')
  for (const t of n.techs) {
    o.push(`<div class="tech"><h3>${esc(t.name)}</h3><dl>
      <dt>Media attention</dt><dd>${esc(t.signals.media_attention)} ${esc(t.events)} event(s), ${esc(t.articles)} article(s).</dd>
      <dt>Threat signal</dt><dd>${esc(t.signals.threat_signal)}</dd>
      <dt>Vulnerability applicability</dt><dd>${esc(t.signals.vulnerability_applicability)}</dd>
      <dt>CVEs mentioned</dt><dd>${t.cves.length ? t.cves.map((v: any) => `${link(v.url, v.cve)}${v.in_kev ? ' <span class="kevyes">(KEV)</span>' : ''}`).join(', ') : 'None cited.'}</dd>
      <dt>Related news</dt><dd>${t.news.length ? t.news.map((x: any) => `${link(x.url, x.title)} <span class="meta">— ${esc(x.name)}</span>`).join('<br>') : 'No linked article.'}</dd>
      ${t.coverage ? `<dt>Coverage</dt><dd>${esc(t.coverage)}</dd>` : ''}</dl></div>`)
  }

  // ---- sources & data quality
  const q = n.sq.coverage
  o.push(`<h2 class="sec">Sources &amp; Data Quality</h2><div class="grid2"><div><b>${esc(q.sources_configured ?? 'N/A')}</b><span>Configured</span></div><div><b>${esc(q.sources_enabled ?? 'N/A')}</b><span>Enabled</span></div><div><b>${esc(q.sources_contributing)}</b><span>Contributed</span></div><div><b>${esc(n.sq.failed_sources.length)}</b><span>Failed</span></div></div>
    <ul><li>Coverage status: <b>${esc(STATUS_TXT[q.status] ?? q.status)}</b> — ${esc(q.articles)} article(s) and ${esc(q.events)} event(s) in the period.</li><li>Last news synchronisation: ${esc(when(q.last_sync))}.</li>
    ${q.sources_disabled != null ? `<li>${esc(q.sources_disabled)} feed(s) disabled by choice (not counted as failures); ${esc(q.sources_quiet ?? 0)} healthy feed(s) published nothing in the period.</li>` : ''}
    <li>Failed feeds: ${n.sq.failed_sources.length ? n.sq.failed_sources.map((f: any) => esc(f.name)).join(', ') : 'none'}.</li>${(q.warnings ?? []).map((w: string) => `<li class="warn">${esc(w)}</li>`).join('')}</ul>
    <h4>Methodology</h4><ul>${n.sq.methodology.map((m: string) => `<li>${esc(m)}</li>`).join('')}</ul>`)

  // ---- sources & references
  if (n.bib.length) {
    o.push(`<div class="pagebreak"><span>page break</span></div><h2 class="sec">Sources &amp; References</h2><p class="meta">${n.bib.length} distinct reference(s), listed once each. "Supports" shows which part of this briefing relies on it.</p>`)
    for (const kind of ['news', 'advisory', 'nvd', 'kev']) {
      const items = n.bib.filter((e: BibEntry) => e.kind === kind)
      if (!items.length) continue
      o.push(`<div class="bibgroup"><h4>${esc(KIND_LABEL[kind])} (${items.length})</h4><table class="bib"><colgroup><col style="width:7%"><col style="width:16%"><col style="width:44%"><col style="width:13%"><col style="width:20%"></colgroup><thead><tr><th>#</th><th>Outlet</th><th>Title</th><th>Date</th><th>Supports</th></tr></thead><tbody>${items.map((e: BibEntry) =>
        `<tr><td>${esc(e.id)}</td><td>${esc(e.outlet)}</td><td>${link(e.url, e.title)}<div class="meta">${esc(host(e.url))}</div></td><td>${esc(day(e.published) || 'N/A')}</td><td>${esc(e.supports.join(', '))}</td></tr>`).join('')}</tbody></table></div>`)
    }
  }
  o.push(`<p class="disc">${esc(b.disclaimer)}</p>`)
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">${CSP}<base target="_blank"><title>${esc(b.title)} — ${esc(c.period_label)} — ${esc(day(b.generated_at))}</title><style>${PRINT_CSS}</style></head><body><div class="sheet">${o.join('')}</div></body></html>`
}
