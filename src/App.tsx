import { useCallback, useEffect, useMemo, useState } from 'react'
import { Cpu, AlertOctagon, Bug, Newspaper } from 'lucide-react'
import Sidebar, { type View } from './components/Sidebar'
import Header from './components/Header'
import MetricCard from './components/MetricCard'
import Scene from './components/Scene'
import Legend from './components/Legend'
import DetailPanel from './components/DetailPanel'
import DataStatus from './components/DataStatus'
import SimpleView from './components/SimpleViews'
import IntelligenceHub, { type HubTab } from './components/IntelligenceHub'
import VulnExplorer, { type VulnPreset } from './components/VulnExplorer'
import Watchlists from './components/Watchlists'
import AttackViews, { type AttackRef } from './components/AttackViews'
import type { ExplorerFilters } from './components/intel/ExplorerTab'
import RelationshipGraph from './components/RelationshipGraph'
import CompaniesView from './components/CompaniesView'
import TechCatalog, { DashboardPicker } from './components/TechCatalog'
import IntelligenceAnalytics from './components/IntelligenceAnalytics'
import NewsPyramids from './components/NewsPyramids'
import type { Nav } from './components/analytics/shared'
import type { GraphNode } from './data/types'
import { fetchNews, fetchOverview, fetchTechnology, triggerSync } from './data/api'
import type { DataState, NewsItem, Overview, TechnologyDetail } from './data/types'

export default function App() {
  const [view, setView] = useState<View>('dashboard')
  const [data, setData] = useState<Overview | null>(null)
  const [apiError, setApiError] = useState(false)
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const [detail, setDetail] = useState<TechnologyDetail | null>(null)
  const [feedTech, setFeedTech] = useState('')
  const [hub, setHub] = useState<{ n: number; tab: HubTab; watchlist: string; cve: string; explorer?: Partial<ExplorerFilters> }>({ n: 0, tab: 'news', watchlist: '', cve: '' })
  const [graphStart, setGraphStart] = useState<{ n: number; id: string } | null>(null)
  const [attackStack, setAttackStack] = useState<AttackRef[]>([])
  const [vulnPreset, setVulnPreset] = useState<{ n: number; p: VulnPreset }>({ n: 0, p: {} })
  const [related, setRelated] = useState<NewsItem[] | null>(null)
  const [picker, setPicker] = useState(false)

  const load = useCallback(() => {
    fetchOverview().then((d) => { setData(d); setApiError(false) }).catch(() => setApiError(true))
  }, [])

  const syncing = data?.status.syncing
  useEffect(() => {
    load()
    const id = setInterval(load, syncing ? 5_000 : 60_000)
    return () => clearInterval(id)
  }, [load, syncing])

  const techs = data?.technologies ?? []
  const selected = techs.find((t) => t.id === selectedId) ?? null
  const score = selected?.score
  const cveCount = selected?.cve_count

  useEffect(() => {
    if (!selectedId) { setDetail(null); return }
    let alive = true
    fetchTechnology(selectedId).then((d) => alive && setDetail(d)).catch(() => alive && setDetail(null))
    return () => { alive = false }
  }, [selectedId, score, cveCount])

  useEffect(() => {
    setRelated(null)
    if (!selectedId) return
    let alive = true
    fetchNews({ tech: selectedId, page_size: 5 }).then((p) => alive && setRelated(p.items)).catch(() => alive && setRelated([]))
    return () => { alive = false }
  }, [selectedId])

  const openHub = (o: Partial<{ tab: HubTab; watchlist: string; cve: string; explorer: Partial<ExplorerFilters> }>, tech = '') => { setFeedTech(tech); setHub((h) => ({ n: h.n + 1, tab: 'news', watchlist: '', cve: '', explorer: undefined, ...o })); setSelectedId(null); setView(o.tab === 'briefing' ? 'briefing' : 'feed') }
  const openFeed = (tech: string) => openHub({}, tech)
  const goAttack = (kind: AttackRef['kind'], id: string) => {
    setAttackStack((st) => [...st, { kind, id }]); setSelectedId(null)
    setView((v) => (kind === 'actor' ? 'actors' : kind === 'campaign' ? 'campaigns' : v === 'campaigns' ? 'campaigns' : 'actors'))
  }
  const openGraph = (id: string) => { setGraphStart((g) => ({ n: (g?.n ?? 0) + 1, id })); setSelectedId(null); setView('graph') }
  const openFromGraph = (n: GraphNode) => {
    const { kind, id, vendor } = n.ref
    if (kind === 'actor' || kind === 'campaign' || kind === 'technique' || kind === 'malware' || kind === 'tool') goAttack(kind, id)
    else if (kind === 'cve') openVulns({ open: id })
    else if (kind === 'technology') { setView('technologies'); setSelectedId(null) }
    else if (kind === 'vendor') openVulns({ vendor: id })
    else if (kind === 'product') openVulns({ vendor, product: id.split(':')[1] })
    else if (n.url) window.open(n.url, '_blank', 'noopener,noreferrer')
  }
  const openVulns = (p: VulnPreset) => { setVulnPreset((v) => ({ n: v.n + 1, p })); setSelectedId(null); setView('vulns') }

  const analyticsNav: Nav = {
    feed: (f) => { setFeedTech(''); setHub((h) => ({ n: h.n + 1, tab: 'explorer', watchlist: '', cve: f.cve ?? '', explorer: f })); setSelectedId(null); setView('feed') },
    vuln: (cve) => openVulns(cve ? { open: cve } : {}),
    vulnVendor: (vendor) => openVulns({ vendor }),
    attack: goAttack,
    graph: openGraph,
    watchlists: () => { setSelectedId(null); setView('watchlists') },
    techNews: (id) => openFeed(id),
  }

  const companyNav = {
    explorer: (p: { tech?: string; vendor?: string; product?: string; open?: string }) => openVulns(p),
    graph: openGraph,
  }

  const state: DataState = apiError ? (data ? 'stale' : 'error') : data ? data.status.state : 'loading'
  const m = useMemo(() => ({
    monitored: techs.length,
    critical: techs.filter((t) => t.score !== null && t.score >= 75).length,
    cves: data?.totals.unique_cves ?? 0,
  }), [techs, data])

  return (
    <div className="flex h-full bg-bg text-ink">
      <Sidebar view={view} onChange={(v) => { if (v === 'feed') openHub({}); else if (v === 'briefing') openHub({ tab: 'briefing' }); else if (v === 'vulns') openVulns({}); else if (v === 'graph') { setView('graph'); setSelectedId(null) } else if (v === 'actors' || v === 'campaigns') { setAttackStack([]); setView(v); setSelectedId(null) } else { setView(v); setSelectedId(null) } }} />
      <div className="flex min-w-0 flex-1 flex-col">
        {view === 'feed' || view === 'briefing' ? (
          <Header updated={null} title={view === 'briefing' ? 'Morning Briefing' : 'Intelligence Feed'} subtitle="Real-time cybersecurity news and threat intelligence monitoring" />
        ) : view === 'vulns' ? (
          <Header updated={null} title="Vulnerability Explorer" subtitle="Search the local CVE catalogue enriched with NVD, CISA KEV and EPSS signals." />
        ) : view === 'graph' ? (
          <Header updated={null} title="Relationship Graph" subtitle="Explore verified cyber threat intelligence relationships" />
        ) : view === 'actors' || view === 'campaigns' ? (
          <Header updated={null} title={view === 'actors' ? 'Threat Actors' : 'Threat Campaigns'} subtitle="Groups and campaigns documented by MITRE ATT&CK, with sourced relationships." />
        ) : view === 'newsdash' ? (
          <Header updated={null} title="News Intelligence Pyramid" subtitle="Monitor cybersecurity topics through news coverage and customizable 3D pyramids." />
        ) : view === 'analytics' ? (
          <Header updated={null} title="Intelligence Analytics" subtitle="Threat intelligence trends & coverage analysis" />
        ) : view === 'technologies' ? (
          <Header updated={null} title="Technology Catalog" subtitle="Catalogue of technologies, their monitoring state and data coverage" />
        ) : view === 'companies' ? (
          <Header updated={null} title="Companies" subtitle="Organisation profiles, technology inventories and personalised threat monitoring" />
        ) : view === 'watchlists' ? (
          <Header updated={null} title="Technology Watchlists" subtitle="Custom groups of monitored technologies with their CVEs, news and Threat Signal Scores." />
        ) : (
          <Header updated={data?.updated_at ? new Date(data.updated_at) : null}>
            <DataStatus state={state} status={data?.status ?? null} onRefresh={() => triggerSync().then(() => setTimeout(load, 500))} />
          </Header>
        )}
        {view === 'dashboard' ? (
          <div className="flex min-h-0 flex-1">
            <main className="flex min-w-0 flex-1 flex-col gap-5 p-6">
              <div className="grid grid-cols-2 gap-4 xl:grid-cols-4">
                <MetricCard label="Technologies Monitored" value={m.monitored} icon={Cpu} />
                <MetricCard label="Critical Technologies" value={m.critical} icon={AlertOctagon} tone="#EF4444" />
                <MetricCard label="CVEs Monitored" value={m.cves} icon={Bug} tone="#F97316" hint={`${data?.totals.kev_cves ?? 0} in CISA KEV`} />
                <MetricCard label="Security News" value="N/A" icon={Newspaper} hint="Not connected yet" />
              </div>
              <div className="relative min-h-0 flex-1 overflow-hidden rounded-xl border border-line bg-bg">
                <Scene technologies={techs} selectedId={selectedId} onSelect={setSelectedId} />
                <Legend />
                <button onClick={() => setPicker(true)} className="absolute left-4 top-4 rounded-lg border border-line bg-surface/90 px-3 py-1.5 text-xs text-ink hover:border-accent/50">Select technologies · {techs.length} shown</button>
                <div className="pointer-events-none absolute right-4 top-4 text-[11px] text-mute">
                  Drag to rotate · Scroll to zoom · Click a pyramid
                </div>
              </div>
            </main>
            {picker && <DashboardPicker onClose={() => setPicker(false)} onChanged={load} />}
            {selected && <DetailPanel key={selected.id} tech={selected} detail={detail} loading={!detail} news={related} onViewAllNews={() => openFeed(selected.id)} onClose={() => setSelectedId(null)} />}
          </div>
        ) : view === 'feed' || view === 'briefing' ? (
          <div className="min-h-0 flex-1 overflow-y-auto">
            <IntelligenceHub key={`${hub.n}`} initialTech={feedTech} initialTab={hub.tab} initialWatchlist={hub.watchlist} initialCve={hub.cve} initialExplorer={hub.explorer} />
          </div>
        ) : view === 'vulns' ? (
          <div className="min-h-0 flex-1 overflow-y-auto">
            <VulnExplorer key={vulnPreset.n} preset={vulnPreset.p} onNews={(cve) => openHub({ tab: 'explorer', cve })} onTech={() => setView('technologies')} onGraph={openGraph} />
          </div>
        ) : view === 'graph' ? (
          <div className="min-h-0 flex-1"><RelationshipGraph start={graphStart} onOpen={openFromGraph} /></div>
        ) : view === 'actors' || view === 'campaigns' ? (
          <div className="min-h-0 flex-1 overflow-y-auto">
            <AttackViews mode={view} stack={attackStack} onNavigate={goAttack} onBack={() => setAttackStack((st) => st.slice(0, -1))} onGraph={openGraph} />
          </div>
        ) : view === 'newsdash' ? (
          <NewsPyramids />
        ) : view === 'analytics' ? (
          <div className="min-h-0 flex-1 overflow-y-auto"><IntelligenceAnalytics nav={analyticsNav} /></div>
        ) : view === 'technologies' ? (
          <div className="min-h-0 flex-1 overflow-y-auto"><TechCatalog /></div>
        ) : view === 'companies' ? (
          <div className="min-h-0 flex-1 overflow-y-auto"><CompaniesView nav={companyNav} /></div>
        ) : view === 'watchlists' ? (
          <div className="min-h-0 flex-1 overflow-y-auto">
            <Watchlists onFeed={(id) => openHub({ watchlist: String(id) })} onVulns={(id) => openVulns({ watchlist: String(id) })} onTech={() => setView('technologies')} />
          </div>
        ) : (
          <div className="min-h-0 flex-1 overflow-y-auto">
            <SimpleView view={view} technologies={techs} />
          </div>
        )}
      </div>
    </div>
  )
}
