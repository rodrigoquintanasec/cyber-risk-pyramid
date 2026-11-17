// Tests for the Morning Briefing document builder (preview + Print / Save as PDF). Run: npm run test:briefing
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { pathToFileURL } from 'node:url'
import { transformWithOxc } from 'vite'

const src = fs.readFileSync(new URL('../src/components/intel/briefingDoc.ts', import.meta.url), 'utf8')
const out = (await transformWithOxc(src, 'briefingDoc.ts', { lang: 'ts' })).code
const tmp = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'brf-')), 'briefingDoc.mjs')
fs.writeFileSync(tmp, out)
const { briefingDocument, normalize, safeUrl } = await import(pathToFileURL(tmp).href)

const anchors = (html) => [...html.matchAll(/<a [^>]*href="([^"]*)"/g)].map((m) => m[1])
const NOW = '2026-11-17T12:00:00+00:00'
const ref = (name, url, title = 'Article', kind = 'news') => ({ name, url, title, published: '2026-11-17T08:00:00+00:00', kind })
const KREBS = 'https://krebsonsecurity.com/2026/11/qilin-hospital/'
const NVD7001 = 'https://nvd.nist.gov/vuln/detail/CVE-2026-7001'

function make(hours = 24, over = {}) {
  const label = { 24: 'Last 24 hours', 48: 'Last 48 hours', 168: 'Last 7 days' }[hours]
  const cov = { status: 'partial', articles: 40, events: 12, sources_configured: 65, sources_enabled: 60, sources_disabled: 5, sources_operational: 58, sources_quiet: 20, sources_failed: 2, sources_contributing: 31, last_sync: NOW, hours_since_sync: 0.5, warnings: ['2 feed(s) failed'] }
  return {
    schema_version: 1, id: 'brf_1', title: 'MORNING CYBER BRIEFING', generated_at: NOW, disclaimer: 'Fixed templates only.', references: [], format: 2,
    period: { hours, label, since: '2026-11-16T12:00:00+00:00', until: NOW }, coverage: cov,
    cover: { title: 'CYBER RISK PYRAMID', subtitle: 'MORNING CYBER BRIEFING', period_label: label, since: '2026-11-16T12:00:00+00:00', until: NOW, generated_at: NOW, scope: 'Scope text', unique_events: 12, contributing_sources: 31, cves_identified: 7, cves_in_kev: 2, coverage_status: 'partial', note: 'Open-source cybersecurity intelligence compiled from verified data sources.' },
    sections: [
      { id: 'executive_summary', title: 'A. Executive Summary', bullets: ['b1'], blocks: [{ id: 'overview', title: 'Overview', text: 'Overview text.' }, { id: 'key_events', title: 'Key events', items: ['E1', 'E2'] }] },
      { id: 'top_stories', title: 'B', items: [{ rank: 1, event_id: 'e1', title: 'Qilin <b>claims</b> hospital', description: 'Desc', category: 'Ransomware', first_published: NOW, publishers: 3, articles: 3, cves: ['CVE-2026-7001'], technologies: ['Fortinet'],
        priority: { score: 71, why: ['Cross-source — 3 publishers', 'KEV — listed'] }, sources: [ref('KrebsOnSecurity', KREBS), ref('The Hacker News', 'https://thehackernews.com/2026/11/qilin.html'), ref('SecurityWeek', 'http://www.securityweek.com/qilin-claims')] }] },
      { id: 'vulnerability_watch', title: 'C', items: [{ cve: 'CVE-2026-7001', cvss: null, epss: 0.91, in_kev: true, kev: { ransomware: true, date_added: '2026-11-16' }, products: [], products_origin: null, unavailable: ['cvss'], events: [],
        references: [{ label: 'NVD', url: NVD7001, kind: 'nvd' }, { label: 'FIRST EPSS', url: 'https://api.first.org/data/v1/epss?cve=CVE-2026-7001', kind: 'epss' }, { label: 'CISA KEV catalog', url: 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog', kind: 'kev' }, { label: 'Fortinet PSIRT', url: 'https://www.fortiguard.com/psirt/FG-IR-26-001', kind: 'advisory', title: 'FG-IR-26-001' }] }] },
      { id: 'threat_landscape', title: 'D', themes: [{ theme: 'Ransomware', events: 1, named_families: [{ name: 'Qilin', events: 1 }], more: 0, items: [{ id: 'e1', title: 'Qilin claims hospital', priority: 71, also_in_top: 1, sources: [ref('KrebsOnSecurity', KREBS)] }] }, { theme: 'Malware', events: 0, items: [], more: 0 }] },
      { id: 'technology_watchlist', title: 'E', note: 'n', items: [{ id: 'fortinet', name: 'Fortinet', events: 1, articles: 3, media_signal: 'm', kev_cves: ['CVE-2026-7001'], verified_signals: [], pyramid_threat_signal: null,
        news: [{ name: 'KrebsOnSecurity', title: 'Qilin claims hospital', url: KREBS, kind: 'news' }], cves: [{ cve: 'CVE-2026-7001', in_kev: true, url: NVD7001 }],
        signals: { media_attention: 'Media text.', threat_signal: 'Pyramid Threat Signal 40 (separate metric)', vulnerability_applicability: 'Not assessed here.' }, coverage: 'Monitored' }] },
      { id: 'sources_quality', title: 'F', coverage: cov, failed_sources: [{ id: 'x', name: 'Broken Feed', error: 'HTTP 403' }], used_sources: [], methodology: ['M1', 'M2'] },
    ],
    ...over,
  }
}
let n = 0
const t = (name, fn) => { fn(); n++; console.log('ok -', name) }

t('story sources are the specific article links, one anchor per outlet, never a home page', () => {
  const a = anchors(briefingDocument(make()))
  for (const u of [KREBS, 'https://thehackernews.com/2026/11/qilin.html', 'http://www.securityweek.com/qilin-claims']) assert.ok(a.includes(u), u)
  assert.ok(!a.some((u) => /^https?:\/\/[^/]+\/?$/.test(u)))
})

t('CVEs link to NVD; NVD, advisory and KEV references are told apart', () => {
  const h = briefingDocument(make())
  assert.ok(anchors(h).includes(NVD7001))
  assert.match(h, /Fortinet PSIRT/); assert.match(h, /\(advisory\)/); assert.match(h, /\(record\)/); assert.match(h, /\(catalog\)/)
  assert.ok(!anchors(h).some((u) => u.includes('api.first.org')))
  assert.match(h, /<td><span class="na">N\/A<\/span><\/td><td>0\.91/)
})

t('bibliography lists each URL once and says which parts rely on it', () => {
  const doc = normalize(make())
  const krebs = doc.bib.filter((e) => e.url.includes('krebsonsecurity'))
  assert.equal(krebs.length, 1)
  assert.deepEqual([...krebs[0].supports].sort(), ['Landscape: Ransomware', 'Story 1', 'Watchlist: Fortinet'])
  assert.deepEqual(doc.bib.map((e) => e.id), doc.bib.map((_, i) => `R${i + 1}`))
  assert.ok(doc.bib.some((e) => e.kind === 'advisory') && doc.bib.some((e) => e.kind === 'nvd') && doc.bib.some((e) => e.kind === 'kev'))
  assert.equal(new Set(doc.bib.map((e) => e.url)).size, doc.bib.length)
})

t('unsafe or malformed URLs never become anchors and text is escaped', () => {
  for (const u of ['javascript:alert(1)', 'data:text/html,<script>alert(1)</script>', '//evil.test/x', 'ftp://x.test/a', 'https://u:p@x.test/', 'https://x.test/"onmouseover="x', 'https://x.test/a b', 'vbscript:x', '', null, 42]) assert.equal(safeUrl(u), null, String(u))
  const b = make()
  b.sections[1].items[0].sources.push(ref('Evil', 'javascript:alert(1)'), ref('Evil2', 'data:text/html;base64,AAAA'), ref('Evil3', 'https://x.test/"><img src=x onerror=alert(1)>'))
  const h = briefingDocument(b)
  assert.ok(!/href="javascript:|href="data:|<img src=x|<script|<b>claims/i.test(h))
  assert.match(h, /Qilin &lt;b&gt;claims&lt;\/b&gt; hospital/)
  assert.ok(anchors(h).every((u) => /^https?:\/\//.test(u)))
})

t('24 h, 48 h and 7 d briefings share the layout and show their own period', () => {
  const docs = [24, 48, 168].map((h) => briefingDocument(make(h)))
  const labels = ['Last 24 hours', 'Last 48 hours', 'Last 7 days']
  docs.forEach((d, i) => {
    assert.match(d, new RegExp(labels[i]))
    for (const s of ['CYBER RISK PYRAMID', 'MORNING CYBER BRIEFING', 'Top Security Stories', 'Critical Vulnerability Watch', 'Threat Landscape', 'Technology Watchlist', 'Sources &amp; Data Quality', 'Sources &amp; References']) assert.ok(d.includes(s), s)
  })
  assert.ok(!docs[0].includes('Last 48 hours') && !docs[2].includes('Last 24 hours'))
})

t('cover carries the required figures and the no-overclaim note', () => {
  const h = briefingDocument(make())
  for (const s of ['Unique events', 'Contributing sources', 'CVEs identified', 'CVEs in CISA KEV', 'Coverage status', 'Partial', 'Open-source cybersecurity intelligence compiled from verified data sources.', 'not all confirmed incidents']) assert.ok(h.includes(s), s)
})

t('briefings stored before this layout still render (cover, summary and references are derived)', () => {
  const old = make()
  delete old.cover; delete old.bibliography; delete old.format
  old.sections[0] = { id: 'executive_summary', title: 'A. Executive Summary', bullets: ['Old bullet one', 'Old bullet two'] }
  old.sections[3].themes[0].items[0] = { id: 'e1', title: 'Qilin claims hospital', priority: 71, first_url: KREBS }
  old.sections[2].items[0].references = [{ label: 'NVD', url: NVD7001 }, { label: 'CISA KEV catalog', url: 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog' }]
  delete old.sections[4].items[0].news; delete old.sections[4].items[0].signals
  old.sections[4].items[0].top_events = [{ id: 'e1', title: 'Qilin claims hospital', url: KREBS }]
  const h = briefingDocument(old)
  assert.match(h, /Old bullet one/); assert.match(h, /Sources &amp; References/); assert.match(h, /CVEs identified/); assert.ok(anchors(h).includes(NVD7001))
})

t('no references: nothing is invented and no empty bibliography is printed', () => {
  const b = make()
  b.sections[1].items[0].sources = []; b.sections[2].items[0].references = []; b.sections[3].themes[0].items[0].sources = []; b.sections[4].items[0].news = []; b.sections[4].items[0].cves = []
  const h = briefingDocument(b)
  assert.match(h, /No original link available/); assert.ok(!h.includes('Sources &amp; References</h2>')); assert.match(h, /None cited/); assert.match(h, /No linked article/)
})

t('incomplete data does not break the document', () => {
  const b = make()
  b.sections = b.sections.filter((s) => s.id === 'top_stories'); delete b.sections[0].items[0].priority; b.sections[0].items[0].cves = undefined
  const h = briefingDocument(b)
  assert.match(h, /No CVEs cited in the period/); assert.match(h, /No watched technology/); assert.match(h, /Priority N\/A/)
  assert.doesNotThrow(() => briefingDocument({ ...make(), sections: [], coverage: make().coverage }))
})

t('a 200-row vulnerability table keeps fixed columns, repeats its header and keeps rows whole', () => {
  const b = make()
  const row = b.sections[2].items[0]
  b.sections[2].items = Array.from({ length: 200 }, (_, i) => ({ ...row, cve: `CVE-2026-${1000 + i}`, products: ['x'.repeat(300)], references: [{ label: 'NVD', url: `https://nvd.nist.gov/vuln/detail/CVE-2026-${1000 + i}`, kind: 'nvd' }] }))
  const h = briefingDocument(b)
  assert.equal((h.match(/<tr><td><b>/g) || []).length, 200)
  assert.match(h, /table-layout:fixed/); assert.match(h, /thead\{display:table-header-group\}/); assert.match(h, /tr\{break-inside:avoid/); assert.match(h, /overflow-wrap:anywhere/)
})

t('print styles: A4, margins, page numbers, no cut blocks, no remote resources, no script', () => {
  const h = briefingDocument(make())
  for (const s of ['@page{size:A4;margin:18mm 16mm 20mm}', '@media print', 'counter(page)', 'break-inside:avoid', 'break-after:avoid', 'print-color-adjust:exact', '.cover{min-height:240mm']) assert.ok(h.includes(s), s)
  assert.ok(!/<script|@import|url\(|<link|<img|<iframe|src=/i.test(h))
  assert.match(h, /Content-Security-Policy[^>]*default-src 'none'/)
  assert.match(h, /background:#fff/); assert.match(h, /#0b1f3a/); assert.match(h, /#0891b2/)
})

t('building the document never changes the briefing', () => {
  const b = make()
  const before = JSON.stringify(b)
  briefingDocument(b)
  assert.equal(JSON.stringify(b), before)
})

console.log(`\n${n} tests passed`)
