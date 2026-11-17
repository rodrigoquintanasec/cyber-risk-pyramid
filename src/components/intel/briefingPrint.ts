import type { Briefing } from '../../data/types'
import { briefingDocument } from './briefingDoc'

export { briefingDocument }

/** Opens the editorial document in a new tab and starts the browser's print dialog (Save as PDF). The document carries no script: printing is triggered from here. */
export function printBriefing(b: Briefing): boolean {
  const url = URL.createObjectURL(new Blob([briefingDocument(b)], { type: 'text/html' }))
  const w = window.open(url, '_blank')
  if (w) w.addEventListener('load', () => { try { w.focus(); w.print() } catch { /* the user can still print from the tab */ } })
  setTimeout(() => URL.revokeObjectURL(url), 120_000)
  return !!w
}
