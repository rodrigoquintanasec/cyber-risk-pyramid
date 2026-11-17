import { BarChart3, Boxes, Building2, Bug, Cpu, FileText, Flag, LayoutDashboard, ListChecks, Network, Radar, Settings, Skull, Triangle } from 'lucide-react'

export type View = 'dashboard' | 'feed' | 'briefing' | 'vulns' | 'actors' | 'campaigns' | 'graph' | 'analytics' | 'companies' | 'technologies' | 'watchlists' | 'newsdash' | 'settings'

const groups: { title: string; items: { id: View; label: string; icon: typeof Cpu }[] }[] = [
  { title: 'Overview', items: [
    { id: 'dashboard', label: 'Dashboard', icon: LayoutDashboard },
    { id: 'feed', label: 'Intelligence Feed', icon: Radar },
    { id: 'briefing', label: 'Morning Briefing', icon: FileText },
  ] },
  { title: 'Intelligence', items: [
    { id: 'vulns', label: 'Vulnerability Explorer', icon: Bug },
    { id: 'actors', label: 'Threat Actors', icon: Skull },
    { id: 'campaigns', label: 'Threat Campaigns', icon: Flag },
    { id: 'graph', label: 'Relationship Graph', icon: Network },
    { id: 'analytics', label: 'Intelligence Analytics', icon: BarChart3 },
    { id: 'newsdash', label: 'Custom Dashboards', icon: Boxes },
  ] },
  { title: 'Management', items: [
    { id: 'companies', label: 'Companies', icon: Building2 },
    { id: 'technologies', label: 'Technologies', icon: Cpu },
    { id: 'watchlists', label: 'Watchlists', icon: ListChecks },
    { id: 'settings', label: 'Settings', icon: Settings },
  ] },
]

export default function Sidebar({ view, onChange }: { view: View; onChange: (v: View) => void }) {
  return (
    <aside className="flex w-60 shrink-0 flex-col border-r border-line bg-sidebar">
      <div className="flex items-center gap-3 px-5 py-5">
        <div className="flex h-9 w-9 items-center justify-center rounded-lg border border-accent/30 bg-accent/10">
          <Triangle size={18} className="text-accent" />
        </div>
        <div className="leading-tight">
          <div className="text-sm font-semibold text-ink">Cyber Risk</div>
          <div className="text-sm font-semibold text-accent">Pyramid</div>
        </div>
      </div>
      <nav className="mt-1 flex flex-1 flex-col gap-4 overflow-y-auto px-3">
        {groups.map((g) => (
          <div key={g.title} className="flex flex-col gap-1">
            <div className="px-3 pb-1 text-[10px] font-semibold uppercase tracking-[0.14em] text-mute/70">{g.title}</div>
            {g.items.map(({ id, label, icon: Icon }) => {
              const on = view === id
              return (
                <button
                  key={id}
                  onClick={() => onChange(id)}
                  className={`flex items-center gap-3 rounded-lg border px-3 py-2.5 text-sm transition-colors ${
                    on ? 'border-accent/25 bg-accent/10 text-accent' : 'border-transparent text-mute hover:bg-surface hover:text-ink'
                  }`}
                >
                  <Icon size={17} />
                  {label}
                </button>
              )
            })}
          </div>
        ))}
      </nav>
      <div className="m-3 flex items-center gap-2.5 rounded-lg border border-line bg-surface px-3 py-2.5">
        <span className="relative flex h-2 w-2">
          <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-amber-400 opacity-50" />
          <span className="relative inline-flex h-2 w-2 rounded-full bg-amber-400" />
        </span>
        <span className="text-xs text-mute">Demo Environment</span>
      </div>
    </aside>
  )
}
