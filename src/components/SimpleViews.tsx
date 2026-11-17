import type { Technology } from '../data/types'
import { getLevel } from '../lib/risk'
import type { View } from './Sidebar'
import SourcesSettings from './SourcesSettings'
import IntelDbSettings from './IntelDbSettings'

export default function SimpleView({ view, technologies }: { view: Exclude<View, 'dashboard' | 'feed' | 'briefing' | 'vulns' | 'watchlists' | 'actors' | 'campaigns' | 'graph'>; technologies: Technology[] }) {
  if (view === 'technologies') {
    return (
      <div className="p-8">
        <div className="overflow-hidden rounded-xl border border-line bg-surface">
          <table className="w-full text-sm">
            <thead className="border-b border-line text-left text-xs uppercase tracking-wider text-mute">
              <tr>
                <th className="px-5 py-3">Technology</th>
                <th className="px-5 py-3">Score</th>
                <th className="px-5 py-3">Level</th>
                <th className="px-5 py-3">Unique CVEs</th>
                <th className="px-5 py-3">In KEV</th>
              </tr>
            </thead>
            <tbody>
              {[...technologies]
                .sort((a, b) => (b.score ?? -1) - (a.score ?? -1))
                .map((t) => {
                  const l = getLevel(t.score)
                  return (
                    <tr key={t.id} className="border-b border-line/60 last:border-0 hover:bg-bg/40">
                      <td className="px-5 py-3 font-medium text-ink">{t.name}</td>
                      <td className="px-5 py-3 tabular-nums" style={{ color: l.color }}>{t.score === null ? 'N/A' : Math.round(t.score)}</td>
                      <td className="px-5 py-3 text-mute">{l.label}</td>
                      <td className="px-5 py-3 tabular-nums text-mute">{t.cve_count}</td>
                      <td className="px-5 py-3 tabular-nums text-mute">{t.kev_count}</td>
                    </tr>
                  )
                })}
            </tbody>
          </table>
        </div>
      </div>
    )
  }
  return <><IntelDbSettings /><SourcesSettings /></>
}
