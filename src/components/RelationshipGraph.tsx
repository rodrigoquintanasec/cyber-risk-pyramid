import { useCallback, useEffect, useRef, useState } from 'react'
import cytoscape, { type Core, type ElementDefinition } from 'cytoscape'
import { ArrowRight, Crosshair, ExternalLink, Layers, Loader2, Maximize2, Minimize2, Network, RotateCcw, Search, ShieldCheck, Trash2 } from 'lucide-react'
import { fetchGraphEdge, fetchGraphMeta, fetchGraphNode, fetchNeighbors, searchGraph } from '../data/api'
import type { GraphEdgeDetail, GraphMeta, GraphNode, GraphNodeDetail, GraphNodeType, GraphResult } from '../data/types'
import { Chip, ExtLink, Note, fmt, sel, useAsync } from './intel/ui'

const COLOR: Record<GraphNodeType, string> = {
  threat_actor: '#EF4444', campaign: '#F97316', technique: '#3B82F6', malware: '#8B5CF6', tool: '#22D3EE',
  cve: '#EAB308', technology: '#22C55E', product: '#64A0B8', vendor: '#9CA3AF', news: '#7DD3FC',
}
const SHAPE: Record<GraphNodeType, string> = {
  threat_actor: 'ellipse', campaign: 'hexagon', technique: 'round-rectangle', malware: 'diamond', tool: 'round-triangle',
  cve: 'round-pentagon', technology: 'octagon', product: 'barrel', vendor: 'cut-rectangle', news: 'round-tag',
}
const LABEL: Record<GraphNodeType, string> = {
  threat_actor: 'Threat Actor', campaign: 'Campaign', technique: 'ATT&CK Technique', malware: 'Malware', tool: 'Tool',
  cve: 'CVE', technology: 'Technology', product: 'Product', vendor: 'Vendor', news: 'News Article',
}
const REL_LABEL: Record<string, string> = { uses: 'uses', 'attributed-to': 'attributed to', 'subtechnique-of': 'sub-technique of', affects: 'affects', belongs_to: 'belongs to', mentions: 'mentions (news)' }
const SUGGEST = ['APT29', 'Lazarus Group', 'SolarWinds Compromise', 'Cobalt Strike', 'T1059.001']
const short = (s: string) => (s.length > 22 ? s.slice(0, 21) + '…' : s)

const STYLE = [
  { selector: 'node', style: { width: 26, height: 26, 'background-color': 'data(color)', shape: 'data(shape)', label: 'data(short)', color: '#E5EDF7', 'font-size': 10, 'text-valign': 'bottom', 'text-margin-y': 5, 'text-outline-color': '#090D16', 'text-outline-width': 2.5, 'border-width': 1.5, 'border-color': '#0D1420', 'min-zoomed-font-size': 7, 'text-max-width': '110px', 'text-wrap': 'ellipsis', 'transition-property': 'opacity', 'transition-duration': 150 } },
  { selector: 'node.root', style: { width: 36, height: 36, 'border-color': '#E5EDF7', 'border-width': 2.5, 'font-size': 12, 'font-weight': 600 } },
  { selector: 'node:selected', style: { 'border-color': '#22D3EE', 'border-width': 4, 'overlay-color': '#22D3EE', 'overlay-opacity': 0.12, 'overlay-padding': 6 } },
  { selector: 'edge', style: { width: 1.3, 'line-color': '#3A4C66', 'target-arrow-color': '#3A4C66', 'target-arrow-shape': 'triangle', 'arrow-scale': 0.8, 'curve-style': 'bezier', opacity: 0.8 } },
  { selector: 'edge[status = "candidate"]', style: { 'line-style': 'dashed', 'line-color': '#B45309', 'target-arrow-color': '#B45309' } },
  { selector: 'edge.hl', style: { 'line-color': '#22D3EE', 'target-arrow-color': '#22D3EE', width: 2, opacity: 1 } },
  { selector: 'edge.lbl, edge:selected', style: { 'line-color': '#22D3EE', 'target-arrow-color': '#22D3EE', width: 2.2, opacity: 1, label: 'data(type)', 'font-size': 8.5, color: '#94A3B8', 'text-rotation': 'autorotate', 'text-background-color': '#090D16', 'text-background-opacity': 0.9, 'text-background-padding': '2px', 'min-zoomed-font-size': 6 } },
  { selector: '.faded', style: { opacity: 0.1 } },
  { selector: '.hidden', style: { display: 'none' } },
] as unknown as cytoscape.Stylesheet[]

export default function RelationshipGraph({ start, onOpen }: { start: { n: number; id: string } | null; onOpen: (n: GraphNode) => void }) {
  const box = useRef<HTMLDivElement>(null)
  const cyRef = useRef<Core | null>(null)
  const { data: meta } = useAsync<GraphMeta>(fetchGraphMeta, [])
  const [q, setQ] = useState(''); const [qType, setQType] = useState('')
  const [results, setResults] = useState<GraphNode[] | null>(null)
  const [rels, setRels] = useState<Set<string>>(new Set(['uses', 'attributed-to', 'subtechnique-of', 'affects', 'belongs_to', 'mentions']))
  const [hiddenTypes, setHiddenTypes] = useState<Set<GraphNodeType>>(new Set())
  const [depth, setDepth] = useState(1)
  const [cand, setCand] = useState(false)
  const [counts, setCounts] = useState({ nodes: 0, edges: 0 })
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState<string | null>(null)
  const [note, setNote] = useState<string | null>(null)
  const [sel_, setSel] = useState<{ kind: 'node' | 'edge'; id: string } | null>(null)
  const [nd, setNd] = useState<GraphNodeDetail | null>(null)
  const [ed, setEd] = useState<GraphEdgeDetail | null>(null)
  const [more, setMore] = useState<Record<string, { offset: number; total: number }>>({})
  const P = useRef({ rels, depth, cand, more, hiddenTypes })
  P.current = { rels, depth, cand, more, hiddenTypes }

  const refresh = useCallback(() => {
    const cy = cyRef.current
    if (cy) setCounts({ nodes: cy.nodes(':visible').length, edges: cy.edges(':visible').length })
  }, [])

  const applyFilters = useCallback(() => {
    const cy = cyRef.current
    if (!cy) return
    const { rels: r, hiddenTypes: ht } = P.current
    cy.batch(() => {
      cy.edges().forEach((e) => { e.toggleClass('hidden', !r.has(e.data('type'))) })
      cy.nodes().forEach((n) => {
        const typeHidden = ht.has(n.data('type'))
        const ce = n.connectedEdges()
        const orphan = !n.hasClass('root') && ce.length > 0 && ce.toArray().every((e) => e.hasClass('hidden'))
        n.toggleClass('hidden', typeHidden || orphan)
      })
      cy.edges().forEach((e) => { if (e.source().hasClass('hidden') || e.target().hasClass('hidden')) e.addClass('hidden') })
    })
    refresh()
  }, [refresh])

  const layout = useCallback((fit: boolean) => {
    const cy = cyRef.current
    if (!cy || cy.nodes().length === 0) return
    cy.layout({ name: 'cose', animate: cy.nodes().length < 120, animationDuration: 380, fit, padding: 40, randomize: false, nodeRepulsion: () => 11000, idealEdgeLength: () => 100, nodeOverlap: 14, gravity: 0.5, numIter: 600 } as cytoscape.LayoutOptions).run()
  }, [])

  const highlight = useCallback((id: string | null) => {
    const cy = cyRef.current
    if (!cy) return
    cy.elements().removeClass('faded hl lbl')
    if (!id) return
    const el = cy.getElementById(id)
    if (el.empty()) return
    if (el.isNode()) {
      const n = el as cytoscape.NodeSingular
      cy.elements().not(n.closedNeighborhood()).addClass('faded')
      n.connectedEdges().addClass('hl')
      if (n.connectedEdges().length <= 8) n.connectedEdges().addClass('lbl')
    } else {
      const e = el as cytoscape.EdgeSingular
      cy.elements().not(e.connectedNodes().union(e)).addClass('faded')
      e.addClass('hl lbl')
    }
  }, [])

  const add = useCallback((res: GraphResult, from: string | null) => {
    const cy = cyRef.current
    if (!cy) return 0
    const anchor = from ? cy.getElementById(from) : null
    const base = anchor && !anchor.empty() ? anchor.position() : { x: 0, y: 0 }
    const els: ElementDefinition[] = []
    let added = 0
    res.nodes.forEach((n, i) => {
      if (cy.getElementById(n.id).nonempty()) return
      added++
      els.push({ group: 'nodes', data: { id: n.id, label: n.label, short: short(n.label), type: n.type, color: COLOR[n.type], shape: SHAPE[n.type], raw: n, via: from },
        position: { x: base.x + 90 * Math.cos(i * 2.4), y: base.y + 90 * Math.sin(i * 2.4) }, classes: n.id === res.center && !from ? 'root' : '' })
    })
    res.edges.forEach((e) => {
      if (cy.getElementById(e.id).nonempty()) return
      const ok = (id: string) => cy.getElementById(id).nonempty() || els.some((x) => x.data.id === id)
      if (ok(e.source) && ok(e.target)) els.push({ group: 'edges', data: { ...e } })
    })
    cy.add(els)
    return added
  }, [])

  const select = useCallback((kind: 'node' | 'edge', id: string) => {
    setSel({ kind, id }); setNd(null); setEd(null)
    highlight(id)
    if (kind === 'node') fetchGraphNode(id).then(setNd).catch(() => setNd(null))
    else fetchGraphEdge(id).then(setEd).catch(() => setEd(null))
  }, [highlight])

  const expand = useCallback(async (id: string, loadMore = false, fresh = false) => {
    const { rels: r, depth: d, cand: c, more: m } = P.current
    setBusy(true); setErr(null); setNote(null)
    try {
      const offset = loadMore ? m[id]?.offset ?? 0 : 0
      const res = await fetchNeighbors({ node: id, depth: d, rel: [...r].join(','), include_candidates: c, limit: 40, offset })
      const cy = cyRef.current
      if (!cy) return
      if (fresh) cy.elements().remove()
      const added = add(res, fresh ? null : id)
      setMore((s) => ({ ...s, [id]: { offset: offset + res.page.returned, total: res.page.total_neighbors } }))
      layout(fresh || cy.nodes().length <= 3)
      applyFilters()
      setNote(res.page.total_neighbors === 0 ? 'No documented relationships for this entity with the current filters.'
        : `${res.page.has_more ? `Showing ${Math.min(offset + res.page.returned, res.page.total_neighbors)} of ${res.page.total_neighbors} direct neighbours. ` : ''}${added === 0 && !fresh ? 'Nothing new to add. ' : ''}${res.omitted_nodes > 0 ? `${res.omitted_nodes} nodes omitted by the ${res.limits.max_nodes}-node limit.` : ''}`)
      if (fresh) { cy.getElementById(id).select(); select('node', id); setTimeout(() => cy.fit(undefined, 50), 450) }
    } catch (e) { setErr(String((e as Error).message ?? e)) } finally { setBusy(false) }
  }, [add, layout, applyFilters, select])

  const loadCenter = useCallback((id: string) => { setSel(null); setNd(null); setEd(null); setMore({}); setResults(null); expand(id, false, true) }, [expand])

  // cytoscape instance
  useEffect(() => {
    if (!box.current) return
    const cy = cytoscape({ container: box.current, elements: [], style: STYLE, wheelSensitivity: 0.25, minZoom: 0.1, maxZoom: 3, boxSelectionEnabled: false })
    cyRef.current = cy
    if (import.meta.env.DEV) (window as unknown as { __cy?: Core }).__cy = cy
    cy.on('tap', 'node', (ev) => select('node', ev.target.id()))
    cy.on('tap', 'edge', (ev) => select('edge', ev.target.id()))
    cy.on('tap', (ev) => { if (ev.target === cy) { cy.elements().unselect(); setSel(null); setNd(null); setEd(null); highlight(null) } })
    cy.on('dbltap', 'node', (ev) => expand(ev.target.id(), false, false))
    return () => { cy.destroy(); cyRef.current = null }
  }, []) // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => { if (start) loadCenter(start.id) }, [start?.n]) // eslint-disable-line react-hooks/exhaustive-deps
  useEffect(() => { applyFilters() }, [rels, hiddenTypes, applyFilters])
  useEffect(() => {
    if (q.trim().length < 2) { setResults(null); return }
    let alive = true
    const t = setTimeout(() => searchGraph(q, qType || undefined).then((r) => alive && setResults(r.items)).catch(() => alive && setResults([])), 300)
    return () => { alive = false; clearTimeout(t) }
  }, [q, qType])

  const cy = () => cyRef.current
  const selNode = sel_?.kind === 'node' ? sel_.id : null
  const collapse = (id: string) => {
    const c = cy(); if (!c) return
    const n = c.getElementById(id)
    n.neighborhood('node').filter((o: cytoscape.NodeSingular) => !o.hasClass('root') && o.connectedEdges().toArray().every((e) => (e as cytoscape.EdgeSingular).source().id() === id || (e as cytoscape.EdgeSingular).target().id() === id)).remove()
    setMore((s) => { const x = { ...s }; delete x[id]; return x }); highlight(id); refresh(); setNote(null)
  }
  const reset = () => { cy()?.elements().remove(); setSel(null); setNd(null); setEd(null); setMore({}); setCounts({ nodes: 0, edges: 0 }); setNote(null); setErr(null); setQ(''); setResults(null) }
  const center = () => { const c = cy(); if (c && selNode) c.animate({ center: { eles: c.getElementById(selNode) }, zoom: Math.max(c.zoom(), 1) }, { duration: 300 }) }
  const toggleRel = (r: string) => setRels((s) => { const x = new Set(s); if (x.has(r)) x.delete(r); else x.add(r); return x })
  const toggleType = (t: GraphNodeType) => setHiddenTypes((s) => { const x = new Set(s); if (x.has(t)) x.delete(t); else x.add(t); return x })
  const btn = 'flex items-center gap-1.5 rounded-lg border border-line bg-surface px-2.5 py-1.5 text-xs text-ink transition-colors hover:border-accent/40 disabled:opacity-40'
  const empty = counts.nodes === 0 && !busy
  const mo = selNode ? more[selNode] : undefined

  return (
    <div className="flex h-full min-h-0 flex-col">
      <div className="flex flex-wrap items-center gap-x-6 gap-y-1 border-b border-line px-6 py-2.5 text-xs text-mute">
        <span className="text-ink">Explore verified cyber threat intelligence relationships</span>
        {meta && <span className="flex items-center gap-1.5"><ShieldCheck size={13} className="text-accent" /> Dataset: {meta.dataset.name}{meta.dataset.version ? ` v${meta.dataset.version}` : ''} · {meta.dataset.counts.relationships.toLocaleString()} STIX relationships{meta.dataset.imported ? '' : ' (not imported)'}</span>}
        <span className="ml-auto tabular-nums text-ink">{counts.nodes} nodes · {counts.edges} connections visible</span>
      </div>
      <div className="grid min-h-0 flex-1 grid-cols-[270px_1fr_320px]">
        {/* left */}
        <aside className="space-y-4 overflow-y-auto border-r border-line p-4">
          <div>
            <div className="relative"><Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-mute" /><input value={q} onChange={(e) => setQ(e.target.value)} maxLength={80} placeholder="APT29, T1059, CVE-…, Cobalt Strike" aria-label="Search entities" className={`${sel} w-full pl-9`} /></div>
            <select value={qType} onChange={(e) => setQType(e.target.value)} className={`${sel} mt-2 w-full`} aria-label="Entity type">
              <option value="">All entity types</option>{(meta?.node_types ?? []).map((t) => <option key={t} value={t}>{LABEL[t]}</option>)}</select>
            {results && (
              <ul className="mt-2 max-h-64 space-y-0.5 overflow-auto rounded-lg border border-line bg-bg/60 p-1">
                {results.length === 0 && <li className="px-2 py-2 text-xs text-mute">No entity found.</li>}
                {results.map((n) => <li key={n.id}><button onClick={() => loadCenter(n.id)} className="flex w-full items-center gap-2 rounded px-2 py-1.5 text-left text-xs text-ink hover:bg-accent/10">
                  <span className="h-2 w-2 shrink-0 rounded-full" style={{ background: COLOR[n.type] }} /><span className="truncate">{n.label}</span><span className="ml-auto shrink-0 text-[10px] text-mute">{n.external_id && n.type !== 'news' ? n.external_id : LABEL[n.type]}</span></button></li>)}
              </ul>
            )}
            {!results && empty && <div className="mt-2 flex flex-wrap gap-1.5">{SUGGEST.map((s) => <button key={s} onClick={() => setQ(s)} className="rounded-full border border-line px-2 py-0.5 text-[11px] text-mute hover:border-accent/40 hover:text-ink">{s}</button>)}</div>}
          </div>
          <div>
            <div className="mb-1.5 text-[11px] uppercase tracking-wider text-mute">Relationships</div>
            {(meta?.relation_types ?? ['uses', 'attributed-to', 'subtechnique-of', 'affects', 'belongs_to', 'mentions']).map((r) => (
              <label key={r} title={meta?.relation_notes[r]} className="flex cursor-pointer items-center gap-2 py-1 text-xs text-ink"><input type="checkbox" checked={rels.has(r)} onChange={() => toggleRel(r)} className="accent-cyan-400" />{REL_LABEL[r] ?? r}</label>))}
            <label className="mt-2 flex cursor-pointer items-start gap-2 text-xs text-amber-300" title="Keyword or name mentions that no structured source confirms"><input type="checkbox" checked={cand} onChange={(e) => setCand(e.target.checked)} className="mt-0.5 accent-amber-400" />Include unverified candidate relationships (dashed)</label>
            <p className="mt-1 text-[10px] text-mute">Applies to the next expansion. Verified relationships are shown by default.</p>
          </div>
          <div>
            <div className="mb-1.5 text-[11px] uppercase tracking-wider text-mute">Expansion depth</div>
            <div className="inline-flex rounded-lg border border-line bg-surface p-0.5">{[1, 2].map((d) => <button key={d} onClick={() => setDepth(d)} className={`rounded-md px-4 py-1 text-xs ${depth === d ? 'bg-accent/15 text-accent' : 'text-mute hover:text-ink'}`}>{d} level{d > 1 ? 's' : ''}</button>)}</div>
          </div>
          <button onClick={reset} className={`${btn} w-full justify-center`}><Trash2 size={13} /> Reset Graph</button>
          <div>
            <div className="mb-1.5 text-[11px] uppercase tracking-wider text-mute">Legend <span className="normal-case">(click to hide a type)</span></div>
            <div className="grid grid-cols-1 gap-0.5">{(Object.keys(COLOR) as GraphNodeType[]).map((t) => (
              <button key={t} onClick={() => toggleType(t)} className={`flex items-center gap-2 rounded px-1.5 py-1 text-left text-xs ${hiddenTypes.has(t) ? 'text-mute/50 line-through' : 'text-ink'} hover:bg-surface`}>
                <span className="h-2.5 w-2.5 rounded-full" style={{ background: COLOR[t] }} />{LABEL[t]}</button>))}</div>
            <p className="mt-2 text-[10px] leading-snug text-mute">Colours identify entity types, not risk. Arrows follow the source's relationship direction. Dashed amber lines are unverified.</p>
          </div>
        </aside>

        {/* centre */}
        <div className="relative min-h-0 bg-bg">
          <div ref={box} className="absolute inset-0" />
          <div className="absolute left-3 top-3 flex flex-wrap gap-2">
            <button className={btn} onClick={() => cy()?.fit(cy()!.elements(':visible'), 50)}><Maximize2 size={13} /> Fit to Screen</button>
            <button className={btn} onClick={() => { cy()?.zoom(1); cy()?.center() }}><RotateCcw size={13} /> Reset View</button>
            <button className={btn} onClick={center} disabled={!selNode}><Crosshair size={13} /> Center Selected</button>
            <button className={btn} onClick={() => layout(true)} disabled={counts.nodes === 0}><Layers size={13} /> Re-layout</button>
          </div>
          {busy && <div className="absolute right-3 top-3 flex items-center gap-2 rounded-lg border border-line bg-surface px-3 py-1.5 text-xs text-mute"><Loader2 size={13} className="animate-spin" /> Loading…</div>}
          {empty && (
            <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center gap-3 text-center text-sm text-mute">
              <Network size={36} className="text-line" /><div><div className="text-ink">Search an entity to start exploring</div><div className="mt-1 text-xs">Groups, campaigns, techniques, malware, tools, CVEs, technologies, vendors, products or news.<br />Relationships load progressively; the full catalogue is never loaded.</div></div>
            </div>
          )}
          {(err || note) && <div className="absolute bottom-3 left-3 right-3">{err ? <Note tone="warn">{err}</Note> : <Note>{note}</Note>}</div>}
        </div>

        {/* right */}
        <aside className="space-y-4 overflow-y-auto border-l border-line p-4">
          {!sel_ && <p className="text-sm text-mute">Select a node or a connection to see its details, evidence and sources. Double-click a node to expand it.</p>}
          {sel_?.kind === 'node' && !nd && <div className="flex items-center gap-2 text-sm text-mute"><Loader2 size={14} className="animate-spin" /> Loading…</div>}
          {nd && sel_?.kind === 'node' && (
            <>
              <div>
                <div className="flex items-center gap-2 text-[11px] uppercase tracking-wider text-mute"><span className="h-2.5 w-2.5 rounded-full" style={{ background: COLOR[nd.type] }} />{LABEL[nd.type]}</div>
                <h3 className="mt-1 text-lg font-semibold leading-snug text-ink">{nd.label}</h3>
                <div className="mt-1 flex flex-wrap items-center gap-1.5"><Chip tone="accent">{nd.external_id ?? nd.id}</Chip><Chip>{nd.source}</Chip>{nd.revoked && <Chip tone="orange">revoked</Chip>}{nd.in_kev && <Chip tone="red">CISA KEV</Chip>}</div>
              </div>
              {nd.aliases.length > 0 && <div className="flex flex-wrap gap-1">{nd.aliases.slice(0, 8).map((a) => <Chip key={a}>{a}</Chip>)}</div>}
              {nd.description && <p className="line-clamp-6 text-xs leading-relaxed text-mute">{nd.description}</p>}
              {Object.keys(nd.details).length > 0 && <div className="space-y-0.5 text-xs">{Object.entries(nd.details).map(([k, v]) => <div key={k} className="flex justify-between gap-3"><span className="text-mute">{k.replace(/_/g, ' ')}</span><span className="truncate text-ink">{Array.isArray(v) ? v.join(', ') : String(v)}</span></div>)}</div>}
              <div className="grid grid-cols-2 gap-2">
                <button className={`${btn} col-span-2 justify-center border-accent/40 bg-accent/10 text-accent`} onClick={() => expand(nd.id, false, false)} disabled={busy}><Network size={13} /> Expand Relationships</button>
                {mo && mo.offset < mo.total && <button className={`${btn} col-span-2 justify-center`} onClick={() => expand(nd.id, true, false)} disabled={busy}>Load more ({mo.total - mo.offset} remaining)</button>}
                <button className={btn} onClick={() => collapse(nd.id)}><Minimize2 size={13} /> Collapse Node</button>
                <button className={btn} onClick={center}><Crosshair size={13} /> Center</button>
                <button className={`${btn} col-span-2 justify-center`} onClick={() => onOpen(nd)}><ExternalLink size={13} /> Open Entity Details</button>
              </div>
              <div>
                <div className="mb-1 text-[11px] uppercase tracking-wider text-mute">Available documented relationships</div>
                {nd.available_relations.length === 0 && <p className="text-xs text-mute">None found in the local data.</p>}
                {nd.available_relations.map((r) => <div key={r.relation} className="py-0.5 text-xs"><span className="text-ink">{r.relation}</span> <span className="text-mute">→ {Object.entries(r.counts).map(([t, n]) => `${n} ${LABEL[t as GraphNodeType]?.toLowerCase() ?? t}`).join(', ')}</span></div>)}
              </div>
              {nd.references.length > 0 && <div><div className="mb-1 text-[11px] uppercase tracking-wider text-mute">References</div><ul className="space-y-1 text-xs">{nd.references.filter((r) => r.url).slice(0, 6).map((r, i) => <li key={i}><ExtLink href={r.url!}>{r.source_name}</ExtLink></li>)}</ul></div>}
            </>
          )}
          {sel_?.kind === 'edge' && !ed && <div className="flex items-center gap-2 text-sm text-mute"><Loader2 size={14} className="animate-spin" /> Loading…</div>}
          {ed && sel_?.kind === 'edge' && (
            <>
              <div className="text-[11px] uppercase tracking-wider text-mute">Relationship</div>
              <div className="space-y-1 text-sm">
                <button onClick={() => ed.source && select('node', ed.source.id)} className="block text-left text-ink hover:text-accent">{ed.source?.label}</button>
                <div className="flex items-center gap-2 text-xs text-accent"><ArrowRight size={14} />{REL_LABEL[ed.edge.type] ?? ed.edge.type}</div>
                <button onClick={() => ed.target && select('node', ed.target.id)} className="block text-left text-ink hover:text-accent">{ed.target?.label}</button>
              </div>
              <div className="flex flex-wrap gap-1.5"><Chip tone={ed.edge.status === 'verified' ? 'accent' : 'orange'}>{ed.edge.status}</Chip><Chip>{ed.edge.type}</Chip></div>
              <div className="space-y-1.5 text-xs">
                {([['Source dataset', ed.edge.dataset], ['Evidence', ed.edge.evidence], ['Evidence id', ed.evidence_id], ['Last updated', ed.edge.modified ? fmt(ed.edge.modified) : 'not provided']] as [string, string][]).map(([k, v]) => <div key={k}><div className="text-mute">{k}</div><div className="break-all text-ink">{v}</div></div>)}
              </div>
              {ed.description && <p className="line-clamp-6 text-xs leading-relaxed text-mute">{ed.description}</p>}
              <Note tone={ed.edge.status === 'verified' ? 'info' : 'warn'}>{ed.interpretation}</Note>
              {ed.references.length > 0 && <div><div className="mb-1 text-[11px] uppercase tracking-wider text-mute">Original references</div><ul className="space-y-1.5 text-xs">{ed.references.map((r, i) => <li key={i}>{r.url ? <ExtLink href={r.url}>{r.source_name || r.url}</ExtLink> : <span className="text-mute">{r.source_name}</span>}{r.description && <div className="text-mute">{r.description}</div>}</li>)}</ul></div>}
            </>
          )}
        </aside>
      </div>
    </div>
  )
}
