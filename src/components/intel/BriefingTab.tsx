/* eslint-disable @typescript-eslint/no-explicit-any */
import { useCallback, useEffect, useRef, useState } from 'react'
import { AlertTriangle, CheckCircle2, Clipboard, Eye, FileText, Loader2, Printer, RefreshCw, Sparkles } from 'lucide-react'
import { fetchBriefing, fetchBriefingMarkdown, fetchBriefings, fetchNewsStats, generateBriefing, triggerNewsSync } from '../../data/api'
import type { Briefing, BriefingListItem, NewsStats } from '../../data/types'
import { ago } from '../IntelligenceFeed'
import { printBriefing } from './briefingPrint'
import { normalize, safeUrl } from './briefingDoc'
import BriefingPreview from './BriefingPreview'
import { Chip, ExtLink, Note, Segmented, card, fmt } from './ui'

const COV: Record<string, string> = { complete: 'border-emerald-400/30 bg-emerald-400/10 text-emerald-300', partial: 'border-amber-400/30 bg-amber-400/10 text-amber-300', stale: 'border-amber-400/30 bg-amber-400/10 text-amber-300', insufficient: 'border-red-400/30 bg-red-400/10 text-red-300' }

function H({ id, children }: { id: string; children: string }) {
  return <h2 id={`brf-${id}`} className="mb-3 scroll-mt-4 border-b border-line pb-2 text-sm font-semibold uppercase tracking-wider text-accent">{children}</h2>
}

function Sections({ b }: { b: Briefing }) {
  const S = (id: string) => b.sections.find((s) => s.id === id) as any
  const top = S('top_stories'), vw = S('vulnerability_watch'), tl = S('threat_landscape'), tw = S('technology_watchlist'), sq = S('sources_quality')
  const n = normalize(b), ex = n.ex
  const A = ({ href, children }: { href: unknown; children: string }) => (safeUrl(href) ? <ExtLink href={safeUrl(href) as string}>{children}</ExtLink> : <span>{children}</span>)
  return (
    <div className="space-y-8">
      <section><H id="executive_summary">{ex.title}</H>
        <div className="space-y-3 text-sm text-ink">{ex.blocks.map((k: any) => <div key={k.id}><div className="text-[11px] font-semibold uppercase tracking-wider text-accent">{k.title}</div>{k.text && <p className="mt-0.5">{k.text}</p>}{k.items?.length > 0 && <ul className="mt-1 list-disc space-y-0.5 pl-5 text-[13px] text-mute">{k.items.map((x: string) => <li key={x}>{x}</li>)}</ul>}</div>)}</div></section>

      <section><H id="top_stories">{top.title}</H>
        {top.items.length === 0 && <p className="text-sm text-mute">No events in the selected period.</p>}
        <div className="space-y-3">
          {top.items.map((i: any) => (
            <article key={i.event_id} className="rounded-lg border border-line bg-bg/40 p-4">
              <div className="flex flex-wrap items-center gap-2 text-xs text-mute"><span className="font-semibold text-ink">#{i.rank}</span><Chip tone="accent">{i.category}</Chip>
                <Chip title="News Priority Score — reading priority, not risk">Priority {i.priority.score}</Chip><span>{fmt(i.first_published)}</span><span>· {i.publishers} publisher(s) / {i.articles} article(s)</span></div>
              <h3 className="mt-1.5 text-[15px] font-semibold text-ink">{i.title}</h3>
              <p className="mt-1 text-[13px] text-mute">{i.description}</p>
              <div className="mt-2 flex flex-wrap gap-1.5">{i.cves.map((c: string) => <Chip key={c} tone="red">{c}</Chip>)}{i.technologies.map((t: string) => <Chip key={t} tone="accent">{t}</Chip>)}</div>
              <details className="mt-2 text-xs text-mute"><summary className="cursor-pointer text-accent">Why this priority?</summary>
                <ul className="mt-1 list-disc space-y-0.5 pl-5">{i.priority.why.map((w: string) => <li key={w}>{w}</li>)}</ul></details>
              <div className="mt-2 flex flex-wrap gap-x-4 gap-y-1 text-xs">{n.stories.find((x: any) => x.event_id === i.event_id)?.sources.map((s: any) => <A key={s.url} href={s.url}>{s.name}</A>)}</div>
            </article>
          ))}
        </div></section>

      <section><H id="vulnerability_watch">{vw.title}</H>
        {vw.items.length === 0 ? <p className="text-sm text-mute">No CVEs cited in the period.</p> : (
          <div className="overflow-x-auto"><table className="w-full text-left text-xs">
            <thead className="text-mute"><tr><th className="py-2">CVE</th><th>CVSS</th><th>EPSS</th><th>CISA KEV</th><th>Affected products</th><th>References</th></tr></thead>
            <tbody>{vw.items.map((w: any) => (
              <tr key={w.cve} className="border-t border-line align-top text-ink">
                <td className="py-2 font-medium">{w.cve}<div className="text-[10px] font-normal text-mute">{w.events[0]?.title.slice(0, 60)}</div></td>
                <td>{w.cvss ?? <span className="text-mute">n/a</span>}</td><td>{w.epss != null ? w.epss.toFixed(2) : <span className="text-mute">n/a</span>}</td>
                <td>{w.in_kev ? <Chip tone="red" title={`Added ${w.kev.date_added}`}>{w.kev.ransomware ? 'KEV · ransomware' : 'KEV'}</Chip> : <span className="text-mute">not listed</span>}</td>
                <td className="text-mute">{w.products.slice(0, 3).join(', ') || 'no evidence'}{w.products_origin && <div className="text-[10px]">via {w.products_origin}</div>}</td>
                <td className="space-y-0.5">{n.watch.find((x: any) => x.cve === w.cve)?.references.filter((r: any) => ['nvd', 'advisory', 'kev'].includes(r.kind)).map((r: any) => <div key={r.url}><A href={r.url}>{r.kind === 'nvd' ? 'NVD' : r.kind === 'kev' ? 'CISA KEV' : r.label}</A> <span className="text-[10px] text-mute">{r.kind === 'advisory' ? 'advisory' : r.kind === 'nvd' ? 'record' : 'catalog'}</span></div>)}</td>
              </tr>))}</tbody></table></div>)}
        <p className="mt-2 text-[11px] text-mute">{vw.note}</p></section>

      <section><H id="threat_landscape">{tl.title}</H>
        <div className="grid gap-3 lg:grid-cols-2">
          {tl.themes.map((t: any) => (
            <div key={t.theme} className="rounded-lg border border-line bg-bg/40 p-4">
              <div className="flex items-center justify-between text-sm font-semibold text-ink">{t.theme}<span className="text-xs font-normal text-mute">{t.events} event(s)</span></div>
              {t.named_families.length > 0 && <div className="mt-1 flex flex-wrap gap-1">{t.named_families.map((f: any) => <Chip key={f.name} tone="violet">{f.name}</Chip>)}</div>}
              <ul className="mt-2 space-y-1.5 text-[13px]">
                {t.items.length === 0 && <li className="text-mute">No events in this period.</li>}
                {n.themes.find((x: any) => x.theme === t.theme)?.items.map((i: any) => <li key={i.id}>{i.sources[0] ? <A href={i.sources[0].url}>{i.title}</A> : <span>{i.title}</span>}
                  <span className="text-[11px] text-mute"> · priority {i.priority}{i.also_in_top ? ` · also Top #${i.also_in_top}` : ''}{i.sources.slice(0, 4).map((s: any) => <span key={s.url}> · <A href={s.url}>{s.name}</A></span>)}</span></li>)}
              </ul>
              {t.more > 0 && <div className="mt-1 text-[11px] text-mute">+{t.more} more event(s)</div>}
            </div>))}
        </div></section>

      <section><H id="technology_watchlist">{tw.title}</H>
        {tw.items.length === 0 ? <p className="text-sm text-mute">No watched technology appears in the period.</p> : (
          <div className="grid gap-3 lg:grid-cols-2">{tw.items.map((t: any) => (
            <div key={t.id} className="rounded-lg border border-line bg-bg/40 p-4 text-sm">
              <div className="font-semibold text-ink">{t.name}</div>
              <div className="mt-0.5 text-xs text-mute">{t.media_signal}</div>
              {t.kev_cves.length > 0 && <div className="mt-2 flex flex-wrap gap-1"><span className="text-xs text-mute">Verified (CISA KEV):</span>{t.kev_cves.map((c: string) => <Chip key={c} tone="red">{c}</Chip>)}</div>}
              {t.verified_signals.length > 0 && <ul className="mt-1 text-[11px] text-mute">{t.verified_signals.map((v: any) => <li key={v.cve}>{v.cve}: {v.summary}</li>)}</ul>}
              <ul className="mt-2 space-y-0.5 text-[13px]">{(n.techs.find((x: any) => x.id === t.id)?.news ?? []).map((e: any) => <li key={e.url}><A href={e.url}>{e.title}</A> <span className="text-[11px] text-mute">— {e.name}</span></li>)}</ul>
              {(n.techs.find((x: any) => x.id === t.id)?.cves ?? []).length > 0 && <div className="mt-1 flex flex-wrap gap-1 text-[11px]"><span className="text-mute">CVEs mentioned:</span>{n.techs.find((x: any) => x.id === t.id).cves.map((v: any) => <A key={v.cve} href={v.url}>{v.cve}</A>)}</div>}
              {t.pyramid_threat_signal && <div className="mt-2 text-[11px] text-mute">Pyramid Threat Signal: {t.pyramid_threat_signal.score ?? 'N/A'} (separate metric, not changed by news)</div>}
            </div>))}</div>)}
        <p className="mt-2 text-[11px] text-mute">{tw.note} Media mentions are not confirmed risk.</p></section>

      <section><H id="sources_quality">{sq.title}</H>
        <div className="grid gap-3 text-sm sm:grid-cols-2 lg:grid-cols-4">
          {([['Articles in period', sq.coverage.articles], ['Sources contributing', `${sq.coverage.sources_contributing}/${sq.coverage.sources_operational}`], ['Last news sync', sq.coverage.last_sync ? ago(sq.coverage.last_sync) : 'never'], ['Failed feeds', sq.failed_sources.length]] as [string, string | number][]).map(([l, v]) => (
            <div key={l} className="rounded-lg border border-line p-3"><div className="text-[11px] text-mute">{l}</div><div className="text-lg font-semibold text-ink">{v}</div></div>))}
        </div>
        <p className="mt-3 text-[11px] text-mute">{sq.coverage.sources_enabled} enabled · {sq.coverage.sources_disabled} disabled (excluded from coverage) · {sq.coverage.sources_quiet} healthy but quiet in this period (not failures)</p>
        {sq.failed_sources.length > 0 && <p className="mt-3 text-xs text-amber-300">Failed: {sq.failed_sources.map((f: any) => `${f.name} (${f.error})`).join(', ')}</p>}
        {sq.coverage.warnings.map((w: string) => <div key={w} className="mt-2"><Note tone="warn">{w}</Note></div>)}
        <div className="mt-3 flex flex-wrap gap-1.5 text-[11px]">{sq.used_sources.map((s: any) => <Chip key={s.id}>{s.name} · {s.articles}</Chip>)}</div></section>
      {n.bib.length > 0 && <section><H id="sources_references">Sources &amp; References</H><details><summary className="cursor-pointer text-xs text-accent">{n.bib.length} distinct reference(s), listed once each</summary>
        <table className="mt-2 w-full text-left text-xs"><thead className="text-mute"><tr><th className="py-1">#</th><th>Outlet</th><th>Title</th><th>Date</th><th>Supports</th></tr></thead><tbody>{n.bib.map((e: any) => <tr key={e.url} className="border-t border-line align-top text-ink"><td className="py-1 text-mute">{e.id}</td><td>{e.outlet}</td><td><A href={e.url}>{e.title.length > 90 ? e.title.slice(0, 90) + '…' : e.title}</A></td><td className="text-mute">{e.published ? String(e.published).slice(0, 10) : 'N/A'}</td><td className="text-mute">{e.supports.join(', ')}</td></tr>)}</tbody></table></details></section>}
      <p className="border-t border-line pt-3 text-[11px] text-mute">{b.disclaimer}</p>
    </div>
  )
}

export default function BriefingTab({ autoToken }: { autoToken: number }) {
  const [hours, setHours] = useState(24)
  const [b, setB] = useState<Briefing | null>(null)
  const [hist, setHist] = useState<BriefingListItem[]>([])
  const [stats, setStats] = useState<NewsStats | null>(null)
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState<string | null>(null)
  const [msg, setMsg] = useState<string | null>(null)
  const [copied, setCopied] = useState(false)
  const [preview, setPreview] = useState(false)
  const lastAuto = useRef(0)

  const loadMeta = useCallback(() => {
    fetchNewsStats().then(setStats).catch(() => setStats(null))
    return fetchBriefings().then((r) => { setHist(r.items); return r.items }).catch(() => [] as BriefingListItem[])
  }, [])

  useEffect(() => { loadMeta().then((items) => { if (items[0]) fetchBriefing(items[0].id).then(setB).catch(() => undefined) }) }, [loadMeta])
  useEffect(() => { if (!stats?.syncing) return; const t = setInterval(loadMeta, 5000); return () => clearInterval(t) }, [stats?.syncing, loadMeta])

  const generate = useCallback(async (force = false, h = hours) => {
    setBusy(true); setErr(null); setMsg(null)
    try {
      const r = await generateBriefing(h, force)
      setB(r)
      setMsg(r.reused ? 'The stored data has not changed since this briefing was generated, so the existing briefing is shown.' : null)
      loadMeta()
    } catch (e: any) { setErr(String(e.message ?? e)) } finally { setBusy(false) }
  }, [hours, loadMeta])

  useEffect(() => { if (autoToken && autoToken !== lastAuto.current) { lastAuto.current = autoToken; generate() } }, [autoToken, generate])

  const ageMin = stats?.last_success ? (Date.now() - new Date(stats.last_success).getTime()) / 60000 : null
  const stale = ageMin === null || ageMin > 2 * (stats?.interval_minutes ?? 30)
  const toc = b?.sections ?? []

  const copy = async () => {
    if (!b) return
    try { const m = await fetchBriefingMarkdown(b.id); await navigator.clipboard.writeText(m.text); setCopied(true); setTimeout(() => setCopied(false), 2000) }
    catch { setErr('Could not copy to the clipboard.') }
  }

  return (
    <div className="space-y-5 p-6">
      <div className={`${card} space-y-4 p-5`}>
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div><div className="flex items-center gap-2 text-sm font-semibold text-ink"><FileText size={16} className="text-accent" /> Morning Briefing</div>
            <p className="mt-0.5 text-xs text-mute">Generated on demand from stored news and local NVD / CISA KEV / EPSS data. No AI; fixed templates.</p></div>
          <div className="flex flex-wrap items-center gap-3">
            <Segmented options={[['24', '24h'], ['48', '48h'], ['168', '7d']]} value={String(hours)} onChange={(v) => setHours(Number(v))} />
            <button onClick={() => generate(false)} disabled={busy} className="flex items-center gap-2 rounded-lg border border-accent/40 bg-accent/15 px-4 py-2 text-sm font-medium text-accent transition-colors hover:bg-accent/25 disabled:opacity-50">
              {busy ? <Loader2 size={15} className="animate-spin" /> : <Sparkles size={15} />} {busy ? 'Generating…' : 'Generate Morning Briefing'}</button>
          </div>
        </div>
        <div className={`flex flex-wrap items-center gap-3 rounded-lg border px-3 py-2 text-xs ${stale ? 'border-amber-400/30 bg-amber-400/10 text-amber-300' : 'border-line bg-bg/40 text-mute'}`}>
          {stale ? <AlertTriangle size={14} /> : <CheckCircle2 size={14} className="text-emerald-400" />}
          <span>News last updated: <b>{stats?.last_success ? `${fmt(stats.last_success)} (${ago(stats.last_success)})` : 'never'}</b>{stats && stats.sources_failed > 0 ? ` · ${stats.sources_failed} feed(s) failing` : ''}{stale ? ' — data may be outdated.' : ''}</span>
          <button onClick={() => triggerNewsSync().then(() => setTimeout(loadMeta, 800))} disabled={!!stats?.syncing} className="ml-auto flex items-center gap-1.5 rounded border border-current px-2 py-1 disabled:opacity-40">
            <RefreshCw size={12} className={stats?.syncing ? 'animate-spin' : ''} /> {stats?.syncing ? 'Updating sources…' : 'Update sources'}</button>
          <span className="text-mute">Generating never waits for feeds: it uses the latest stored data.</span>
        </div>
        {err && <Note tone="warn">Briefing error: {err}</Note>}
        {msg && <div className="flex items-center gap-3"><Note>{msg}</Note><button onClick={() => generate(true)} className="shrink-0 rounded border border-line px-2 py-1 text-xs text-ink hover:border-accent/40">Regenerate anyway</button></div>}
      </div>

      {!b && !busy && <div className="rounded-xl border border-dashed border-line py-16 text-center text-sm text-mute">No briefing yet. Choose a period and press <b className="text-ink">Generate Morning Briefing</b>.</div>}
      {busy && !b && <div className="flex items-center justify-center gap-2 py-16 text-sm text-mute"><Loader2 size={16} className="animate-spin" /> Building briefing…</div>}

      {b && (
        <div className="grid gap-5 xl:grid-cols-[220px_1fr]">
          <aside className="space-y-4 xl:sticky xl:top-4 xl:self-start">
            <nav className={`${card} p-3 text-sm`} aria-label="Briefing contents">
              <div className="mb-2 px-2 text-[11px] uppercase tracking-wider text-mute">Contents</div>
              {toc.map((s) => <button key={s.id} onClick={() => document.getElementById(`brf-${s.id}`)?.scrollIntoView({ behavior: 'smooth' })} className="block w-full rounded px-2 py-1.5 text-left text-xs text-mute hover:bg-accent/10 hover:text-ink">{s.title}</button>)}
            </nav>
            <div className={`${card} p-3`}>
              <div className="mb-2 px-2 text-[11px] uppercase tracking-wider text-mute">Recent briefings</div>
              {hist.map((h) => <button key={h.id} onClick={() => fetchBriefing(h.id).then(setB)} className={`block w-full rounded px-2 py-1.5 text-left text-[11px] hover:bg-accent/10 ${h.id === b.id ? 'text-accent' : 'text-mute'}`}>{fmt(h.generated_at)} · {h.period_hours}h · {h.coverage_status}</button>)}
            </div>
          </aside>
          <article className={`${card} p-6`}>
            <div className="mb-5 flex flex-wrap items-start justify-between gap-3 border-b border-line pb-4">
              <div><h1 className="text-lg font-semibold tracking-wide text-ink">{b.title}</h1>
                <p className="mt-0.5 text-xs text-mute">{b.period.label} · {fmt(b.period.since)} → {fmt(b.period.until)}</p>
                <p className="text-xs text-mute">Generated {fmt(b.generated_at)} · {b.coverage.events} events · {b.coverage.articles} articles</p></div>
              <div className="flex flex-wrap items-center gap-2">
                <span className={`rounded-full border px-2.5 py-1 text-[11px] ${COV[b.coverage.status]}`}>Coverage: {b.coverage.status}</span>
                <button onClick={copy} className="flex items-center gap-1.5 rounded-lg border border-line px-3 py-1.5 text-xs text-ink hover:border-accent/40"><Clipboard size={13} /> {copied ? 'Copied' : 'Copy Briefing'}</button>
                <button onClick={() => setPreview(true)} className="flex items-center gap-1.5 rounded-lg border border-line px-3 py-1.5 text-xs text-ink hover:border-accent/40"><Eye size={13} /> Preview</button>
                <button onClick={() => { if (!printBriefing(b)) setErr('The browser blocked the print window. Allow pop-ups for this site and try again.') }} className="flex items-center gap-1.5 rounded-lg border border-line px-3 py-1.5 text-xs text-ink hover:border-accent/40"><Printer size={13} /> Print / Save as PDF</button>
              </div>
            </div>
            {b.coverage.status !== 'complete' && <div className="mb-5"><Note tone="warn">Coverage is <b>{b.coverage.status}</b>. {b.coverage.warnings[0] ?? ''} See “Sources &amp; Data Quality”.</Note></div>}
            <Sections b={b} />
          </article>
        </div>
      )}
      {preview && b && <BriefingPreview b={b} onClose={() => setPreview(false)} />}
    </div>
  )
}
