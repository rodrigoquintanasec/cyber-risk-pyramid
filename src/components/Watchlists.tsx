import { useEffect, useState } from 'react'
import { Bug, ListChecks, Newspaper, Pencil, Plus, Radar, Trash2, X } from 'lucide-react'
import { addWatchTech, createWatchlist, deleteWatchlist, fetchNews, fetchWatchlist, fetchWatchlists, removeWatchTech, renameWatchlist } from '../data/api'
import type { NewsItem } from '../data/types'
import { getLevel } from '../lib/risk'
import { ago } from './IntelligenceFeed'
import { Chip, ExtLink, Note, Status, card, sel, useAsync } from './intel/ui'

export default function Watchlists({ onFeed, onVulns, onTech }: { onFeed: (watchlist: number) => void; onVulns: (watchlist: number) => void; onTech: (t: string) => void }) {
  const lists = useAsync(fetchWatchlists, [])
  const [selId, setSelId] = useState<number | null>(null)
  const [name, setName] = useState('')
  const [err, setErr] = useState<string | null>(null)
  const [editing, setEditing] = useState<string | null>(null)
  const items = lists.data?.items ?? []
  const avail = lists.data?.available_technologies ?? []
  const cur = items.find((w) => w.id === selId) ?? null
  useEffect(() => { if (!cur && items.length) setSelId(items[0].id) }, [items, cur])
  const sum = useAsync(() => (selId ? fetchWatchlist(selId) : Promise.resolve(null)), [selId, cur?.updated_at])
  const [news, setNews] = useState<NewsItem[] | null>(null)
  useEffect(() => {
    setNews(null)
    if (!selId) return
    let alive = true
    fetchNews({ watchlist: selId, page_size: 5 }).then((p) => alive && setNews(p.items)).catch(() => alive && setNews([]))
    return () => { alive = false }
  }, [selId, cur?.updated_at])

  const run = (p: Promise<unknown>, after?: () => void) => { setErr(null); p.then(() => { lists.reload(); after?.() }).catch((e) => setErr(String(e.message ?? e))) }
  const create = () => {
    if (!name.trim()) return
    setErr(null)
    createWatchlist(name.trim(), []).then((w) => { setName(''); lists.reload(); setSelId(w.id) }).catch((e) => setErr(String(e.message ?? e)))
  }
  const s = sum.data
  return (
    <div className="grid gap-5 p-6 xl:grid-cols-[280px_1fr]">
      <aside className="space-y-3">
        <div className={`${card} p-4`}>
          <div className="mb-2 text-xs uppercase tracking-wider text-mute">New watchlist</div>
          <div className="flex gap-2"><input value={name} onChange={(e) => setName(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && create()} maxLength={60} placeholder="e.g. Edge infrastructure" className={`${sel} min-w-0 flex-1`} />
            <button onClick={create} aria-label="Create watchlist" className="rounded-lg border border-accent/40 bg-accent/15 px-3 text-accent"><Plus size={16} /></button></div>
          {err && <p className="mt-2 text-xs text-red-300">{err}</p>}
        </div>
        <div className={`${card} p-2`}>
          <Status loading={lists.loading && !lists.data} error={lists.error} onRetry={lists.reload} empty={!!lists.data && items.length === 0} emptyText="No watchlists yet. Create your first one above." />
          {items.map((w) => (
            <button key={w.id} onClick={() => setSelId(w.id)} className={`flex w-full items-center justify-between rounded-lg px-3 py-2.5 text-left text-sm ${w.id === selId ? 'bg-accent/10 text-accent' : 'text-ink hover:bg-bg/50'}`}>
              <span className="flex items-center gap-2 truncate"><ListChecks size={14} /> {w.name}</span><span className="text-xs text-mute">{w.technologies.length}</span>
            </button>
          ))}
        </div>
        <Note>Watchlists are stored locally in SQLite. They contain monitored technologies only; notifications are not part of this phase.</Note>
      </aside>

      <section className="min-w-0 space-y-5">
        {!cur && !lists.loading && <div className="rounded-xl border border-dashed border-line py-16 text-center text-sm text-mute">Select or create a watchlist.</div>}
        {cur && (
          <>
            <div className="flex flex-wrap items-center justify-between gap-3">
              {editing === null ? (
                <h2 className="flex items-center gap-2 text-lg font-semibold text-ink">{cur.name}<button aria-label="Rename" onClick={() => setEditing(cur.name)} className="text-mute hover:text-accent"><Pencil size={14} /></button></h2>
              ) : (
                <div className="flex gap-2"><input autoFocus value={editing} onChange={(e) => setEditing(e.target.value)} maxLength={60} className={sel} />
                  <button onClick={() => run(renameWatchlist(cur.id, editing), () => setEditing(null))} className="rounded-lg border border-accent/40 px-3 text-xs text-accent">Save</button>
                  <button onClick={() => setEditing(null)} className="rounded-lg border border-line px-3 text-xs text-mute">Cancel</button></div>
              )}
              <div className="flex flex-wrap gap-2 text-xs">
                <button onClick={() => onFeed(cur.id)} className="flex items-center gap-1.5 rounded-lg border border-line px-3 py-1.5 text-ink hover:border-accent/40"><Radar size={13} /> Filter Intelligence Feed</button>
                <button onClick={() => onVulns(cur.id)} className="flex items-center gap-1.5 rounded-lg border border-line px-3 py-1.5 text-ink hover:border-accent/40"><Bug size={13} /> Explore CVEs</button>
                <button onClick={() => { if (confirm(`Delete watchlist "${cur.name}"?`)) run(deleteWatchlist(cur.id), () => setSelId(null)) }} className="flex items-center gap-1.5 rounded-lg border border-red-400/30 px-3 py-1.5 text-red-300 hover:bg-red-400/10"><Trash2 size={13} /> Delete</button>
              </div>
            </div>

            <div className={`${card} p-4`}>
              <div className="mb-2 text-xs uppercase tracking-wider text-mute">Technologies</div>
              <div className="flex flex-wrap gap-2">
                {cur.technologies.map((t) => (
                  <span key={t} className="flex items-center gap-1.5 rounded-full border border-accent/30 bg-accent/10 py-1 pl-3 pr-1.5 text-xs text-accent">{avail.find((a) => a.id === t)?.name ?? t}
                    <button aria-label={`Remove ${t}`} onClick={() => run(removeWatchTech(cur.id, t))} className="rounded-full p-0.5 hover:bg-accent/20"><X size={12} /></button></span>
                ))}
                {cur.technologies.length === 0 && <span className="text-xs text-mute">No technologies yet.</span>}
                <select value="" onChange={(e) => e.target.value && run(addWatchTech(cur.id, e.target.value))} className={`${sel} !py-1 text-xs`} aria-label="Add technology">
                  <option value="">+ Add technology</option>{[...new Set(avail.map((a) => a.category ?? 'Other'))].sort().map((cat) => <optgroup key={cat} label={cat}>{avail.filter((a) => (a.category ?? 'Other') === cat && !cur.technologies.includes(a.id)).map((a) => <option key={a.id} value={a.id}>{a.name}</option>)}</optgroup>)}</select>
              </div>
              <p className="mt-2 text-[11px] text-mute">Any technology of the catalogue can be added ({avail.length} available); adding it to a watchlist starts monitoring it.</p>
            </div>

            {s && (
              <>
                <div className="grid grid-cols-2 gap-3 xl:grid-cols-4">
                  {([['Technologies', s.totals.technologies], ['Unique CVEs', s.totals.unique_cves], ['In CISA KEV', s.totals.kev_cves], ['Related news', s.totals.news]] as [string, number][]).map(([l, v]) => (
                    <div key={l} className={`${card} px-4 py-3`}><div className="text-[11px] uppercase tracking-wider text-mute">{l}</div><div className="text-2xl font-semibold tabular-nums text-ink">{v}</div></div>
                  ))}
                </div>
                {s.highest && <p className="text-xs text-mute">Highest Threat Signal Score: <b className="text-ink">{s.highest.name}</b> ({Math.round(s.highest.score)}){s.totals.without_score > 0 ? ` · ${s.totals.without_score} technolog${s.totals.without_score === 1 ? 'y has' : 'ies have'} insufficient data (no score)` : ''}</p>}
                <div className={`${card} overflow-hidden`}>
                  <table className="w-full text-sm">
                    <thead className="border-b border-line text-left text-xs uppercase tracking-wider text-mute"><tr><th className="px-4 py-3">Technology</th><th className="px-4 py-3">Threat Signal</th><th className="px-4 py-3">CVEs</th><th className="px-4 py-3">KEV</th><th className="px-4 py-3">News</th><th className="px-4 py-3">Data</th></tr></thead>
                    <tbody>
                      {s.technology_details.map((t) => { const l = getLevel(t.score); return (
                        <tr key={t.id} className="border-b border-line/60 last:border-0 hover:bg-bg/40">
                          <td className="px-4 py-3"><button onClick={() => onTech(t.id)} className="font-medium text-ink hover:text-accent">{t.name}</button></td>
                          <td className="px-4 py-3 tabular-nums" style={{ color: l.color }} title={t.insufficient_reason ?? undefined}>{t.score === null ? 'N/A' : `${Math.round(t.score)} · ${l.label}`}{t.coverage_label && <div className="text-[10px] font-normal text-mute">{t.coverage_label}{t.cves_complete === false ? ` · backfill ${(t.sync_status ?? '').toLowerCase()}` : ''}</div>}</td>
                          <td className="px-4 py-3 tabular-nums text-mute" title={t.cves_complete === false ? 'Vulnerability data is still being collected: not the absence of vulnerabilities' : undefined}>{t.cves_complete === false && t.cve_count === 0 ? 'pending' : t.cve_count}</td><td className="px-4 py-3 tabular-nums text-mute">{t.kev_count}</td><td className="px-4 py-3 tabular-nums text-mute">{t.news_count}</td>
                          <td className="px-4 py-3 text-xs text-mute">{t.quality ?? '-'}</td></tr>) })}
                      {s.technology_details.length === 0 && <tr><td colSpan={6} className="px-4 py-8 text-center text-sm text-mute">Add technologies to see their summary.</td></tr>}
                    </tbody>
                  </table>
                </div>
                <p className="text-[11px] text-mute">{s.note}</p>
              </>
            )}

            <div className={`${card} p-4`}>
              <div className="mb-2 flex items-center gap-1.5 text-xs uppercase tracking-wider text-mute"><Newspaper size={13} /> Latest related news</div>
              {news === null && <div className="text-xs text-mute">Loading…</div>}
              {news && news.length === 0 && <div className="text-xs text-mute">No related news yet.</div>}
              <ul className="space-y-2.5">{news?.map((n) => (
                <li key={n.id} className="text-[13px]"><ExtLink href={n.url}>{n.title}</ExtLink><div className="mt-0.5 flex flex-wrap items-center gap-2 text-[11px] text-mute">{n.source.name} · {ago(n.published ?? n.collected_at)}{n.cves.slice(0, 3).map((c) => <Chip key={c} tone="red">{c}</Chip>)}</div></li>))}</ul>
            </div>
          </>
        )}
      </section>
    </div>
  )
}
