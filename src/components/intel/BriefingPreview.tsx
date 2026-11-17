import { useMemo, useRef, useState } from 'react'
import { Clipboard, Printer, X } from 'lucide-react'
import { fetchBriefingMarkdown } from '../../data/api'
import type { Briefing } from '../../data/types'
import { briefingDocument } from './briefingDoc'

/** Read-only preview of exactly the document that Print / Save as PDF produces (same builder, A4 sheet, dashed page-break markers). It never changes the briefing. */
export default function BriefingPreview({ b, onClose }: { b: Briefing; onClose: () => void }) {
  const html = useMemo(() => briefingDocument(b), [b])
  const ref = useRef<HTMLIFrameElement>(null)
  const [msg, setMsg] = useState<string | null>(null)
  const print = () => { try { ref.current?.contentWindow?.focus(); ref.current?.contentWindow?.print() } catch { setMsg('The browser blocked printing from the preview. Use "Print / Save as PDF" in the briefing header instead.') } }
  const copy = async () => {
    try { const m = await fetchBriefingMarkdown(b.id); await navigator.clipboard.writeText(m.text); setMsg('Summary copied.') } catch { setMsg('Could not copy to the clipboard.') }
    setTimeout(() => setMsg(null), 2500)
  }
  return (
    <div className="fixed inset-0 z-50 flex flex-col bg-black/70" role="dialog" aria-label="Briefing preview">
      <div className="flex flex-wrap items-center gap-3 border-b border-line bg-surface px-5 py-3">
        <div className="mr-auto"><div className="text-sm font-semibold text-ink">Preview — {b.period.label}</div><div className="text-[11px] text-mute">Same document as Print / Save as PDF. Links open the original sources in a new tab. Dashed lines mark page breaks of the cover and references; other pages flow automatically at A4.</div></div>
        {msg && <span className="text-xs text-accent">{msg}</span>}
        <button onClick={copy} className="flex items-center gap-1.5 rounded-lg border border-line px-3 py-1.5 text-xs text-ink hover:border-accent/40"><Clipboard size={13} /> Copy summary</button>
        <button onClick={print} className="flex items-center gap-1.5 rounded-lg border border-accent/40 bg-accent/15 px-3 py-1.5 text-xs font-medium text-accent hover:bg-accent/25"><Printer size={13} /> Print / Save as PDF</button>
        <button onClick={onClose} aria-label="Close preview" className="rounded-lg border border-line p-1.5 text-mute hover:text-ink"><X size={14} /></button>
      </div>
      <iframe ref={ref} title="Briefing preview" srcDoc={html} sandbox="allow-same-origin allow-popups allow-popups-to-escape-sandbox allow-modals" className="w-full flex-1 bg-[#e9eef3]" />
      <div className="border-t border-line bg-surface px-5 py-2 text-[11px] text-mute">Browser headers and footers (date, URL) depend on the print dialog: untick "Headers and footers" to remove them.</div>
    </div>
  )
}
