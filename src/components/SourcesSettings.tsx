import { useState } from 'react'
import { Segmented } from './intel/ui'
import SourceManager from './sources/SourceManager'
import { SourceCoverage, SourceOnboarding } from './sources/SourceCoverage'

/** Settings → Intelligence Sources: registry manager, coverage report and batch onboarding (all backed by the single news pipeline). */
export default function SourcesSettings() {
  const [tab, setTab] = useState('manage')
  return (
    <div className="space-y-4 p-8">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h2 className="text-base font-semibold text-ink">Intelligence Sources</h2>
          <p className="mt-0.5 max-w-3xl text-xs text-mute">Manage every feed without touching code. Disabled feeds are not fetched and never count as failed; their stored articles are kept. A source is shown as operational only if its last validation and its last sync succeeded.</p>
        </div>
        <Segmented options={[['manage', 'Manage Sources'], ['coverage', 'Source Coverage'], ['onboarding', 'Onboarding']]} value={tab} onChange={setTab} />
      </div>
      {tab === 'manage' ? <SourceManager /> : tab === 'coverage' ? <SourceCoverage /> : <SourceOnboarding />}
    </div>
  )
}
