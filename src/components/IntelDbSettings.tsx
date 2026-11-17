import { useEffect, useState } from 'react'
import { Database, HardDrive } from 'lucide-react'
import { DS_LABEL, DS_TONE, bytes, fetchEstimate, fetchIntelStatus, initializeDb, resumeImport, stopImport, syncNow, updateEpss, updateKev, type Estimate } from '../data/intelDb'
import { btn, btn2, Modal } from './company/common'
import { Note, card, fmt, useAsync } from './intel/ui'

const n = (v: number | undefined) => (v === undefined ? '-' : v.toLocaleString())
const LABEL: Record<string, string> = { not_initialized: 'Not Initialized', importing: 'Importing', partial: 'Partial', complete: 'Complete', updating: 'Updating', stale: 'Stale', failed: 'Failed' }

function InitModal({ onClose, onStarted }: { onClose: () => void; onStarted: () => void }) {
  const [sel, setSel] = useState<string[]>(['cve', 'cpe', 'cpematch', 'kev', 'epss'])
  const [est, setEst] = useState<Estimate | null>(null)
  const [err, setErr] = useState<string | null>(null)
  const [ok, setOk] = useState(false)
  const [busy, setBusy] = useState(false)
  useEffect(() => { fetchEstimate().then(setEst).catch((e) => setErr(String(e.message))) }, [])
  const chosen = est?.datasets.filter((d) => sel.includes(d.dataset)) ?? []
  const dl = chosen.reduce((a, d) => a + d.download_bytes, 0)
  const unc = chosen.reduce((a, d) => a + d.uncompressed_bytes, 0)
  const start = () => { setBusy(true); setErr(null); initializeDb(sel).then(() => { onStarted(); onClose() }).catch((e) => setErr(String(e.message))).finally(() => setBusy(false)) }
  return (
    <Modal title="Initialize Local Intelligence Database" onClose={onClose}>
      <p className="mb-3 text-xs text-mute">Downloads the official bulk datasets and imports them into SQLite. Nothing is downloaded until you confirm below.</p>
      <div className="space-y-1.5">{Object.entries(DS_LABEL).map(([k, l]) => {
        const d = est?.datasets.find((x) => x.dataset === k)
        return <label key={k} className="flex items-center gap-3 rounded-lg border border-line px-3 py-2 text-sm"><input type="checkbox" checked={sel.includes(k)} onChange={(e) => setSel((s) => (e.target.checked ? [...s, k] : s.filter((x) => x !== k)))} /><span className="flex-1 text-ink">{l}</span><span className="text-xs text-mute">{d ? `${bytes(d.download_bytes)} download · ${bytes(d.uncompressed_bytes)} raw` : est ? '' : '…'}</span></label>
      })}</div>
      {est && (
        <div className="mt-3 space-y-1 rounded-lg border border-line p-3 text-xs">
          <div className="flex justify-between"><span className="text-mute">Download (compressed)</span><span className="text-ink">{bytes(dl)}</span></div>
          <div className="flex justify-between"><span className="text-mute">Uncompressed data to process</span><span className="text-ink">{bytes(unc)}</span></div>
          <div className="flex justify-between"><span className="text-mute">Estimated database size (rule of thumb)</span><span className="text-ink">≈ {bytes(Math.round(unc * 0.55))}</span></div>
          <div className="flex justify-between"><span className="text-mute">Disk free</span><span className={est.enough_space ? 'text-ink' : 'text-red-300'}>{bytes(est.disk_free_bytes)}</span></div>
          <div className="flex justify-between"><span className="text-mute">Recommended free space</span><span className="text-ink">{bytes(est.disk_needed_bytes)}</span></div>
        </div>
      )}
      <div className="mt-3"><Note tone="warn">{est?.warning ?? 'The full import downloads several GB and can take hours; it uses CPU, disk and bandwidth. The app stays usable and the import can be paused and resumed.'}</Note></div>
      {est && !est.enough_space && <div className="mt-2"><Note tone="warn">There may not be enough free disk space for the full import.</Note></div>}
      {err && <div className="mt-2"><Note tone="warn">{err}</Note></div>}
      <label className="mt-3 flex items-start gap-2 text-xs text-ink"><input type="checkbox" checked={ok} onChange={(e) => setOk(e.target.checked)} className="mt-0.5" />I understand the size, duration and resource use, and want to start the download now.</label>
      <div className="mt-4 flex justify-end gap-2"><button onClick={onClose} className={btn2}>Cancel</button><button disabled={!ok || busy || sel.length === 0 || !est} onClick={start} className={btn}>Start import</button></div>
    </Modal>
  )
}

export default function IntelDbSettings() {
  const { data: s, error, reload } = useAsync(fetchIntelStatus, [])
  const [modal, setModal] = useState(false)
  const [msg, setMsg] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const running = !!s?.active_run
  useEffect(() => { const t = setInterval(reload, running ? 3000 : 20000); return () => clearInterval(t) }, [running]) // eslint-disable-line react-hooks/exhaustive-deps
  const act = (p: Promise<unknown>) => { setBusy(true); setMsg(null); p.then(() => setTimeout(reload, 500)).catch((e) => setMsg(String(e.message))).finally(() => setBusy(false)) }
  const initialised = !!s && Object.values(s.datasets).some((d) => d.units_done > 0)
  const resumable = !!s && Object.values(s.datasets).some((d) => d.resumable && d.status !== 'complete') && !running
  const ds = s ? Object.values(s.datasets) : []
  const run = s?.active_run
  const kpis: [string, string][] = s ? [['Total CVEs', n(s.counts.cves)], ['Total CPE Records', n(s.counts.cpe_records)], ['CPE Match Criteria', n(s.counts.cpe_match_criteria)], ['NVD Vendors', n(s.counts.nvd_vendors)], ['NVD Products', n(s.counts.nvd_products)], ['CVEs With CVSS', n(s.counts.cves_with_cvss)],
    ['CVEs With CWE', n(s.counts.cves_with_cwe)], ['CVEs In KEV', n(s.counts.cves_in_kev)], ['CVEs With EPSS', `${n(s.counts.cves_with_epss)}${s.counts.epss_score_date ? ` · ${s.counts.epss_score_date}` : ''}`], ['Last Successful Sync', s.last_successful_sync ? fmt(s.last_successful_sync) : 'never'],
    ['Database Size', bytes(s.database_bytes)], ['Storage Available', bytes(s.disk_free_bytes)]] : []
  return (
    <div className="space-y-4 p-8 pb-0">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h2 className="flex items-center gap-2 text-base font-semibold text-ink"><Database size={16} className="text-accent" /> Local Intelligence Database</h2>
          <p className="mt-0.5 max-w-3xl text-xs text-mute">Official NVD, CISA KEV and FIRST EPSS data stored once in SQLite and shared by every module. Technologies show their known vulnerabilities immediately from this database, without asking NVD.</p>
        </div>
        {s && <span className={`rounded-full border px-3 py-1 text-xs font-medium ${DS_TONE[s.overall]}`}>{LABEL[s.overall]}</span>}
      </div>
      {error && <Note tone="warn">Could not load the database status ({error}).</Note>}
      {s && (
        <>
          <div className="grid grid-cols-2 gap-3 md:grid-cols-5">{kpis.map(([l, v]) => <div key={l} className={`${card} px-4 py-3`}><div className="text-[11px] uppercase tracking-wider text-mute">{l}</div><div className="mt-0.5 text-lg font-semibold tabular-nums text-ink">{v}</div></div>)}</div>
          <div className="flex flex-wrap items-center gap-2">
            <button disabled={busy || running} onClick={() => setModal(true)} className={btn}>Initialize Database</button>
            <button disabled={busy || running || !initialised} onClick={() => act(syncNow())} className={btn2} title={initialised ? '' : 'Initialize the database first'}>Sync Now</button>
            <button disabled={busy || running} onClick={() => act(updateEpss())} className={btn2}>Update EPSS</button>
            <button disabled={busy || running} onClick={() => act(updateKev())} className={btn2}>Update KEV</button>
            <button disabled={busy || !resumable} onClick={() => act(resumeImport())} className={btn2} title={resumable ? '' : 'Nothing to resume'}>Resume Import</button>
            {running && <button onClick={() => act(stopImport())} className={btn2}>Stop (resumable)</button>}
            <span className="ml-auto flex items-center gap-1.5 text-xs text-mute"><HardDrive size={12} /> imports run in the background; the app stays usable</span>
          </div>
          {msg && <Note tone="warn">{msg}</Note>}
          {run && (
            <div className={`${card} p-4`}>
              <div className="flex items-center justify-between text-sm"><span className="font-medium text-ink">Import in progress · {run.mode}</span><span className="text-xs text-mute">started {fmt(run.started_at)}</span></div>
              <div className="mt-2 text-xs text-mute">{run.message ?? run.current ?? 'working…'}</div>
              <div className="mt-2 h-1.5 overflow-hidden rounded bg-bg"><div className="h-full animate-pulse rounded bg-accent/70" style={{ width: `${Math.min(100, 100 * ds.reduce((a, d) => a + d.units_done, 0) / Math.max(1, ds.reduce((a, d) => a + d.units_total, 0)))}%` }} /></div>
              <div className="mt-2 flex flex-wrap gap-5 text-xs text-mute"><span>Processed <b className="text-ink">{n(run.processed)}</b></span><span>New <b className="text-ink">{n(run.new_items)}</b></span><span>Updated <b className="text-ink">{n(run.updated_items)}</b></span><span>Errors <b className={run.errors ? 'text-red-300' : 'text-ink'}>{run.errors}</b></span></div>
            </div>
          )}
          <div className={`${card} overflow-x-auto`}>
            <table className="w-full min-w-[760px] text-sm"><thead className="border-b border-line text-left text-xs uppercase tracking-wider text-mute"><tr><th className="px-4 py-2.5">Dataset</th><th className="px-4 py-2.5">Status</th><th className="px-4 py-2.5 text-right">Records</th><th className="px-4 py-2.5">Units</th><th className="px-4 py-2.5">Dataset date</th><th className="px-4 py-2.5">Last success (freshness)</th><th className="px-4 py-2.5">Last error</th></tr></thead>
              <tbody>{ds.map((d) => (
                <tr key={d.key} className="border-b border-line/60 last:border-0 align-top"><td className="px-4 py-2 font-medium text-ink">{DS_LABEL[d.key]}</td><td className="px-4 py-2"><span className={`rounded-full border px-2 py-0.5 text-[11px] ${DS_TONE[d.status]}`}>{LABEL[d.status]}</span></td>
                  <td className="px-4 py-2 text-right tabular-nums text-ink">{n(d.records)}</td><td className="px-4 py-2 text-xs tabular-nums text-mute">{d.units_done}/{d.units_total}</td><td className="px-4 py-2 text-xs text-mute">{d.dataset_date ? fmt(d.dataset_date) : '-'}</td>
                  <td className="px-4 py-2 text-xs text-mute">{d.last_success ? fmt(d.last_success) : 'never'}</td><td className="max-w-[260px] px-4 py-2 text-xs text-red-300">{d.last_error ?? ''}</td></tr>))}</tbody></table>
          </div>
          {s.recent_errors.length > 0 && <div className={`${card} p-4`}><div className="mb-1 text-xs font-semibold text-ink">Recent import errors</div><ul className="space-y-0.5 text-[11px] text-mute">{s.recent_errors.slice(0, 6).map((e, i) => <li key={i}>{fmt(e.at)} · {e.dataset} · {e.item}: {e.message}</li>)}</ul></div>}
          {s.recent_runs.length > 0 && <div className={`${card} p-4`}><div className="mb-1 text-xs font-semibold text-ink">Recent runs</div><table className="w-full text-[11px]"><tbody>{s.recent_runs.slice(0, 5).map((r) => <tr key={r.id} className="border-t border-line/60 first:border-0"><td className="py-1 text-mute">{fmt(r.started_at)}</td><td className="text-ink">{r.mode}</td><td className="text-mute">{r.status}</td><td className="text-right tabular-nums text-mute">{n(r.processed)} processed · {n(r.new_items)} new · {n(r.updated_items)} updated · {r.errors} errors</td></tr>)}</tbody></table></div>}
          <Note>{s.note} Datasets are marked Stale when older than their refresh window; Partial means some files or datasets are still missing.</Note>
        </>
      )}
      {modal && <InitModal onClose={() => setModal(false)} onStarted={() => setTimeout(reload, 800)} />}
    </div>
  )
}
