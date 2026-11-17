import { useState } from 'react'
import { BarChart3, FileText, Layers, Network, Newspaper, Search, Sparkles, TrendingUp } from 'lucide-react'
import IntelligenceFeed from './IntelligenceFeed'
import BriefingTab from './intel/BriefingTab'
import ClustersTab from './intel/ClustersTab'
import ExplorerTab, { type ExplorerFilters } from './intel/ExplorerTab'
import { MitreTab, ObservatoryTab, TrendingTab } from './intel/InsightTabs'
import { Tabs, useAsync } from './intel/ui'
import { fetchFacets } from '../data/api'

export type HubTab = 'news' | 'events' | 'trending' | 'explorer' | 'observatory' | 'mitre' | 'briefing'
const TABS: { id: HubTab; label: string; icon: typeof Newspaper }[] = [
  { id: 'news', label: 'Latest News', icon: Newspaper },
  { id: 'events', label: 'Event Clusters', icon: Layers },
  { id: 'trending', label: 'Trending', icon: TrendingUp },
  { id: 'explorer', label: 'Threat Explorer', icon: Search },
  { id: 'observatory', label: 'Observatory', icon: BarChart3 },
  { id: 'mitre', label: 'MITRE ATT&CK', icon: Network },
  { id: 'briefing', label: 'Morning Briefing', icon: FileText },
]

export default function IntelligenceHub({ initialTech, initialTab = 'news', initialWatchlist = '', initialCve = '', initialExplorer }: { initialTech: string; initialTab?: HubTab; initialWatchlist?: string; initialCve?: string; initialExplorer?: Partial<ExplorerFilters> }) {
  const [tab, setTab] = useState<HubTab>(initialTab)
  const [newsTech, setNewsTech] = useState(initialTech)
  const [preset, setPreset] = useState<{ n: number; f: Partial<ExplorerFilters> }>({ n: 0, f: { ...(initialCve ? { cve: initialCve } : {}), ...(initialExplorer ?? {}) } })
  const [autoToken, setAutoToken] = useState(0)
  const { data: facets } = useAsync(fetchFacets, [])

  const explore = (f: Partial<ExplorerFilters>) => { setPreset((p) => ({ n: p.n + 1, f })); setTab('explorer') }
  return (
    <div className="flex min-h-full flex-col">
      <div className="flex items-center justify-between gap-3 px-6 pt-4">
        <p className="text-xs text-mute">Cyber threat intelligence from RSS/Atom sources · independent of the pyramid risk scores</p>
        <button onClick={() => { setTab('briefing'); setAutoToken((t) => t + 1) }}
          className="flex items-center gap-2 rounded-lg border border-accent/40 bg-accent/15 px-4 py-2 text-sm font-medium text-accent transition-colors hover:bg-accent/25">
          <Sparkles size={15} /> Generate Morning Briefing
        </button>
      </div>
      <Tabs tabs={TABS} value={tab} onChange={setTab} />
      <div className="min-h-0 flex-1">
        {tab === 'news' && <IntelligenceFeed key={newsTech} initialTech={newsTech} initialWatchlist={initialWatchlist} />}
        {tab === 'events' && <ClustersTab facets={facets} initialTech="" />}
        {tab === 'trending' && <TrendingTab />}
        {tab === 'explorer' && <ExplorerTab key={preset.n} facets={facets} preset={preset.f} />}
        {tab === 'observatory' && <ObservatoryTab onOpen={(kind, id) => (kind === 'tech' ? (setNewsTech(id), setTab('news')) : explore({ vendor: id }))} />}
        {tab === 'mitre' && <MitreTab onFilter={(id) => explore({ mitre: id })} />}
        <div className={tab === 'briefing' ? '' : 'hidden'}><BriefingTab autoToken={autoToken} /></div>
      </div>
    </div>
  )
}
