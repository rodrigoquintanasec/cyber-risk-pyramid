import type { ReactNode } from 'react'
import { Clock } from 'lucide-react'

interface HeaderProps {
  updated: Date | null
  children?: ReactNode
  title?: string
  subtitle?: string
}

export default function Header({ updated, children, title = 'Technology Risk Overview', subtitle = 'Threat signals from CISA KEV, NVD and EPSS across monitored infrastructure technologies.' }: HeaderProps) {
  return (
    <header className="flex items-center justify-between gap-4 border-b border-line px-8 py-5">
      <div>
        <h1 className="text-xl font-semibold text-ink">{title}</h1>
        <p className="mt-0.5 text-sm text-mute">{subtitle}</p>
      </div>
      <div className="flex items-center gap-4">
        {children}
        <div className="flex items-center gap-2 text-xs text-mute">
          <Clock size={13} />
          Last updated {updated ? updated.toLocaleString('en-US', { dateStyle: 'medium', timeStyle: 'short' }) : '-'}
        </div>
      </div>
    </header>
  )
}
