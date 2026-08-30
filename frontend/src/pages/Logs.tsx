import React, { useState, useEffect, useRef } from 'react'
import { useTranslation } from 'react-i18next'
import { FileCode, List, Activity, Terminal, ChevronRight, Search } from 'lucide-react'
import { logDestinations, loggedFields, listeners, logs, geoip } from '../services/api'
import { decodeUniqueId } from '../lib/uniqueId'
import { decodeReqFp } from '../lib/reqFp'
import { decodeJa4 } from '../lib/ja4'
import { computePopoverPosition } from '../lib/popover'
import useApiList from '../hooks/useApiList'
import Modal from '../components/Modal'
import { Tabs } from '../components/ui'
import { useDateTime } from '../contexts/DateTimeContext'

interface LogLine {
  raw: string
  docker_ts?: string
  parsed?: Record<string, any>
}

const TERMINATION_CODE_KEYS: Record<string, string> = {
  '--': 'normal',
  'cD': 'clientDisconnected',
  'sD': 'serverDown',
  'cR': 'clientReset',
  'sR': 'serverReset',
  'cQ': 'clientQueueTimeout',
  'sQ': 'serverQueueTimeout',
  'cC': 'clientConnectionTimeout',
  'sC': 'serverConnectionTimeout',
  'cH': 'clientHandshakeTimeout',
  'sH': 'serverHandshakeTimeout',
  'cL': 'clientClosedPrematurely',
  'sL': 'serverClosedPrematurely',
  'cT': 'clientTarpitTimeout',
  'sT': 'serverTarpitTimeout',
  'cS': 'clientServerTimeout',
  'sS': 'serverTimeout',
  'cI': 'clientInternalError',
  'sI': 'serverInternalError',
  'PR': 'proxyProtocolError',
  'ND': 'noBackendAvailable',
  'NI': 'noBackendAvailableInternal',
  'LR': 'localRedirect',
}

export default function Logs() {
  const { t } = useTranslation(['pages', 'common'])
  const { formatLogTimestamp } = useDateTime()
  const [tab, setTab] = useState<'config' | 'live'>('live')

  const formatTermination = (code: string | undefined): string => {
    if (!code || code === '-') return '-'
    const key = TERMINATION_CODE_KEYS[code]
    return key ? `${code} — ${t(`pages:logs.terminationCodes.${key}`)}` : code
  }
  const { items: dests, reload: rd } = useApiList(logDestinations.list)
  const { items: fields, reload: rf } = useApiList(loggedFields.list)
  const { items: listenerList } = useApiList(listeners.list)
  const [open, setOpen] = useState(false)
  const [editing, setEditing] = useState<number | null>(null)
  const initialForm = { name: '', listener_id: null as number | null, target: '', facility: 'local0', level: 'info', format: '', enabled: true }
  const [form, setForm] = useState<any>(initialForm)

  const [fOpen, setFOpen] = useState(false)
  const [fEditing, setFEditing] = useState<number | null>(null)
  const initialFform = { name: '', listener_id: null as number | null, field: '', enabled: true }
  const [fform, setFform] = useState<any>(initialFform)

  // Live logs state
  const [logLines, setLogLines] = useState<LogLine[]>([])
  const [logLimit, setLogLimit] = useState(100)
  const [logLoading, setLogLoading] = useState(false)
  const [logError, setLogError] = useState('')
  const [expandedLogRow, setExpandedLogRow] = useState<number | null>(null)
  const [logSearch, setLogSearch] = useState('')
  const [skippedNonJson, setSkippedNonJson] = useState(0)
  const [skippedControl, setSkippedControl] = useState(0)

  // ASN popover state
  const [asnPopover, setAsnPopover] = useState<{ rowIndex: number; ip: string; asn: string; rect: DOMRect } | null>(null)
  const [asnResult, setAsnResult] = useState<{ organization: string | null; network: string | null; city: string | null; country: string | null } | null>(null)
  const [asnLoading, setAsnLoading] = useState(false)
  const asnPopoverRef = useRef<HTMLDivElement>(null)

  // Unique ID popover state
  const [uidPopover, setUidPopover] = useState<{ rowIndex: number; uid: string; rect: DOMRect } | null>(null)
  const [uidDecoded, setUidDecoded] = useState<{ decoded?: ReturnType<typeof decodeUniqueId>['decoded']; error?: string } | null>(null)
  const uidPopoverRef = useRef<HTMLDivElement>(null)

  // Request Fingerprint popover state
  const [reqFpPopover, setReqFpPopover] = useState<{ rowIndex: number; fp: string; rect: DOMRect } | null>(null)
  const [reqFpDecoded, setReqFpDecoded] = useState<{ decoded?: ReturnType<typeof decodeReqFp>['decoded']; error?: string } | null>(null)
  const reqFpPopoverRef = useRef<HTMLDivElement>(null)

  // JA4 popover state
  const [ja4Popover, setJa4Popover] = useState<{ rowIndex: number; ja4: string; rect: DOMRect } | null>(null)
  const [ja4Decoded, setJa4Decoded] = useState<{ decoded?: ReturnType<typeof decodeJa4>['decoded']; error?: string } | null>(null)
  const ja4PopoverRef = useRef<HTMLDivElement>(null)

  const openAdd = () => { setEditing(null); setForm(initialForm); setOpen(true) }
  const openEdit = (d: any) => { setEditing(d.id); setForm({ ...d }); setOpen(true) }

  const openFAdd = () => { setFEditing(null); setFform(initialFform); setFOpen(true) }
  const openFEdit = (f: any) => { setFEditing(f.id); setFform({ ...f }); setFOpen(true) }

  const submit = async (e: React.FormEvent) => { e.preventDefault(); if (editing) await logDestinations.update(editing, form); else await logDestinations.create(form); setEditing(null); setForm(initialForm); setOpen(false); rd() }
  const fsubmit = async (e: React.FormEvent) => { e.preventDefault(); if (fEditing) await loggedFields.update(fEditing, fform); else await loggedFields.create(fform); setFEditing(null); setFform(initialFform); setFOpen(false); rf() }

  const loadLogs = async () => {
    setLogLoading(true)
    setLogError('')
    try {
      const res = await logs.recent(logLimit)
      setLogLines([...(res.data.lines || [])].reverse())
      setSkippedNonJson(res.data.skipped_non_json || 0)
      setSkippedControl(res.data.skipped_control || 0)
      if (res.data.error) setLogError(res.data.error)
    } catch (err: any) {
      setLogError(err?.response?.data?.detail || err?.message || t('pages:logs.error'))
      setLogLines([])
      setSkippedNonJson(0)
      setSkippedControl(0)
    } finally {
      setLogLoading(false)
    }
  }

  useEffect(() => {
    if (tab !== 'live') return
    loadLogs()
    const id = setInterval(loadLogs, 5000)
    return () => clearInterval(id)
  }, [tab, logLimit])

  const actionColor = (action: string | undefined): string => {
    if (!action) return 'text-slate-400'
    if (action === 'block' || action === 'blocked') return 'text-red-400'
    if (action === 'allow') return 'text-green-400'
    if (action.startsWith('skip')) return 'text-blue-400'
    if (action === 'deny' || action === 'drop') return 'text-red-400'
    return 'text-amber-400'
  }

  const filteredLogLines = React.useMemo(() => {
    if (!logSearch.trim()) return logLines
    const lower = logSearch.toLowerCase()
    return logLines.filter(line => {
      const p = line.parsed
      if (!p) return line.raw.toLowerCase().includes(lower)
      return Object.values(p).some(v => String(v).toLowerCase().includes(lower))
    })
  }, [logLines, logSearch])

  const handleAsnClick = async (e: React.MouseEvent, rowIndex: number, ip: string, asn: string) => {
    if (asnPopover && asnPopover.rowIndex === rowIndex) {
      setAsnPopover(null)
      setAsnResult(null)
      return
    }
    const rect = (e.currentTarget as HTMLElement).getBoundingClientRect()
    setAsnPopover({ rowIndex, ip, asn, rect })
    setAsnResult(null)
    setAsnLoading(true)
    try {
      const res = await geoip.lookupAsn(ip)
      setAsnResult({ organization: res.data.organization, network: res.data.network, city: res.data.city, country: res.data.country })
    } catch {
      setAsnResult({ organization: null, network: null, city: null, country: null })
    } finally {
      setAsnLoading(false)
    }
  }

  const handleUniqueIdClick = (e: React.MouseEvent, rowIndex: number, uid: string) => {
    e.stopPropagation()
    if (uidPopover && uidPopover.rowIndex === rowIndex) {
      setUidPopover(null)
      setUidDecoded(null)
      return
    }
    const rect = (e.currentTarget as HTMLElement).getBoundingClientRect()
    const res = decodeUniqueId(uid)
    if (res.valid && res.decoded) {
      setUidDecoded({ decoded: res.decoded })
    } else {
      setUidDecoded({ error: res.error || t('pages:uniqueIdDecoder.invalidUniqueId') })
    }
    setUidPopover({ rowIndex, uid, rect })
  }

  const handleReqFpClick = (e: React.MouseEvent, rowIndex: number, fp: string) => {
    e.stopPropagation()
    if (reqFpPopover && reqFpPopover.rowIndex === rowIndex) {
      setReqFpPopover(null)
      setReqFpDecoded(null)
      return
    }
    const rect = (e.currentTarget as HTMLElement).getBoundingClientRect()
    const res = decodeReqFp(fp)
    if (res.valid && res.decoded) {
      setReqFpDecoded({ decoded: res.decoded })
    } else {
      setReqFpDecoded({ error: res.error || t('pages:reqFpDecoder.invalidReqFp') })
    }
    setReqFpPopover({ rowIndex, fp, rect })
  }

  const handleJa4Click = (e: React.MouseEvent, rowIndex: number, ja4: string) => {
    e.stopPropagation()
    if (ja4Popover && ja4Popover.rowIndex === rowIndex) {
      setJa4Popover(null)
      setJa4Decoded(null)
      return
    }
    const rect = (e.currentTarget as HTMLElement).getBoundingClientRect()
    const res = decodeJa4(ja4)
    if (res.valid && res.decoded) {
      setJa4Decoded({ decoded: res.decoded })
    } else {
      setJa4Decoded({ error: res.error || t('pages:ja4Decoder.invalidJa4') })
    }
    setJa4Popover({ rowIndex, ja4, rect })
  }

  // Normalize ASN display: ensure "AS" prefix (Rust module + map_ip return
  // "AS17858"; native geoip2 converter returns bare "17858")
  const formatAsn = (asn: string) => asn.toUpperCase().startsWith('AS') ? asn : `AS${asn}`

  useEffect(() => {
    const handler = (e: MouseEvent) => {
      if (asnPopoverRef.current && !asnPopoverRef.current.contains(e.target as Node)) {
        setAsnPopover(null)
        setAsnResult(null)
      }
      if (uidPopoverRef.current && !uidPopoverRef.current.contains(e.target as Node)) {
        setUidPopover(null)
        setUidDecoded(null)
      }
      if (reqFpPopoverRef.current && !reqFpPopoverRef.current.contains(e.target as Node)) {
        setReqFpPopover(null)
        setReqFpDecoded(null)
      }
      if (ja4PopoverRef.current && !ja4PopoverRef.current.contains(e.target as Node)) {
        setJa4Popover(null)
        setJa4Decoded(null)
      }
    }
    if (asnPopover || uidPopover || reqFpPopover || ja4Popover) document.addEventListener('mousedown', handler)
    return () => document.removeEventListener('mousedown', handler)
  }, [asnPopover, uidPopover, reqFpPopover, ja4Popover])

  return (
    <div className="space-y-6">
      {/* Tab switcher */}
      <Tabs
        tabs={[
          { id: 'live', label: t('pages:logs.tabs.liveLogs'), icon: Terminal },
          { id: 'config', label: t('pages:logs.tabs.configuration'), icon: FileCode },
        ]}
        active={tab}
        onChange={(id) => setTab(id as 'config' | 'live')}
      />

      {tab === 'config' && (
        <>
          <div className="flex items-center justify-between"><h2 className="text-2xl font-bold flex items-center gap-2"><FileCode className="h-5 w-5 text-primary" /> {t('pages:logs.logDestinations')}</h2><button onClick={openAdd} className="btn-primary">{t('pages:logs.addDestination')}</button></div>
          <div className="card overflow-x-auto">
            <table className="w-full text-sm text-start"><thead className="text-slate-400 border-b border-slate-800"><tr><th>{t('pages:logs.modal.name')}</th><th>{t('pages:logs.modal.listener')}</th><th>{t('pages:logs.modal.target')}</th><th>{t('pages:logs.modal.facility')}</th><th>{t('pages:logs.modal.level')}</th><th>{t('pages:logs.modal.enabled')}</th><th></th></tr></thead>
              <tbody>{dests.map((d: any) => (<tr key={d.id} className="border-b border-slate-800 last:border-0"><td className="py-2">{d.name}</td><td>{d.listener_id ? listenerList.find((l: any) => l.id === d.listener_id)?.name : t('pages:logs.all')}</td><td>{d.target}</td><td>{d.facility}</td><td>{d.level}</td><td>{d.enabled ? t('common:actions.yes') : t('common:actions.no')}</td>
                <td className="space-x-2">
                  <button onClick={() => openEdit(d)} className="text-primary hover:underline">{t('common:actions.edit')}</button>
                  <button onClick={() => logDestinations.remove(d.id).then(rd)} className="text-red-400 hover:underline">{t('common:actions.delete')}</button>
                </td></tr>))}</tbody>
            </table>
          </div>
          <div className="flex items-center justify-between"><h2 className="text-2xl font-bold flex items-center gap-2"><List className="h-5 w-5 text-primary" /> {t('pages:logs.loggedFields')}</h2><button onClick={openFAdd} className="btn-primary">{t('pages:logs.addField')}</button></div>
          <div className="card overflow-x-auto">
            <table className="w-full text-sm text-start"><thead className="text-slate-400 border-b border-slate-800"><tr><th>{t('pages:logs.modal.name')}</th><th>{t('pages:logs.modal.listener')}</th><th>{t('pages:logs.modal.field')}</th><th>{t('pages:logs.modal.enabled')}</th><th></th></tr></thead>
              <tbody>{fields.map((f: any) => (<tr key={f.id} className="border-b border-slate-800 last:border-0"><td className="py-2">{f.name}</td><td>{f.listener_id ? listenerList.find((l: any) => l.id === f.listener_id)?.name : t('pages:logs.all')}</td><td className="font-mono">{f.field}</td><td>{f.enabled ? t('common:actions.yes') : t('common:actions.no')}</td>
                <td className="space-x-2">
                  <button onClick={() => openFEdit(f)} className="text-primary hover:underline">{t('common:actions.edit')}</button>
                  <button onClick={() => loggedFields.remove(f.id).then(rf)} className="text-red-400 hover:underline">{t('common:actions.delete')}</button>
                </td></tr>))}</tbody>
            </table>
          </div>
          <Modal open={open} onClose={() => setOpen(false)} title={editing ? t('pages:logs.modal.editLogDestination') : t('pages:logs.modal.addLogDestination')}>
            <form onSubmit={submit} className="space-y-3">
              <div className="grid grid-cols-2 gap-3">
                <div><label className="label">{t('pages:logs.modal.name')}</label><input className="input" value={form.name} onChange={e => setForm({ ...form, name: e.target.value })} /></div>
                <div><label className="label">{t('pages:logs.modal.listener')}</label><select className="input" value={form.listener_id || ''} onChange={e => setForm({ ...form, listener_id: e.target.value ? Number(e.target.value) : null })}><option value="">{t('pages:logs.modal.selectListener')}</option>{listenerList.map((l: any) => <option key={l.id} value={l.id}>{l.name}</option>)}</select></div>
                <div><label className="label">{t('pages:logs.modal.target')}</label><input className="input" value={form.target} onChange={e => setForm({ ...form, target: e.target.value })} placeholder={t('pages:logs.modal.targetPlaceholder')} /></div>
                <div><label className="label">{t('pages:logs.modal.facility')}</label><input className="input" value={form.facility} onChange={e => setForm({ ...form, facility: e.target.value })} /></div>
                <div><label className="label">{t('pages:logs.modal.level')}</label><select className="input" value={form.level} onChange={e => setForm({ ...form, level: e.target.value })}><option>emerg</option><option>alert</option><option>crit</option><option>err</option><option>warning</option><option>notice</option><option>info</option><option>debug</option></select></div>
              </div>
              <div><label className="label">{t('pages:logs.modal.format')}</label><textarea className="input opacity-50" rows={2} value={form.format} onChange={e => setForm({ ...form, format: e.target.value })} disabled /></div>
              <label className="flex items-center gap-2"><input type="checkbox" checked={form.enabled} onChange={e => setForm({ ...form, enabled: e.target.checked })} /> {t('pages:logs.modal.enabled')}</label>
              <button className="btn-primary w-full">{t('common:actions.save')}</button>
            </form>
          </Modal>
          <Modal open={fOpen} onClose={() => setFOpen(false)} title={fEditing ? t('pages:logs.modal.editLoggedField') : t('pages:logs.modal.addLoggedField')}>
            <form onSubmit={fsubmit} className="space-y-3">
              <div className="grid grid-cols-2 gap-3"><div><label className="label">{t('pages:logs.modal.name')}</label><input className="input" value={fform.name} onChange={e => setFform({ ...fform, name: e.target.value })} /></div><div><label className="label">{t('pages:logs.modal.listener')}</label><select className="input" value={fform.listener_id || ''} onChange={e => setFform({ ...fform, listener_id: e.target.value ? Number(e.target.value) : null })}><option value="">{t('pages:logs.modal.selectListener')}</option>{listenerList.map((l: any) => <option key={l.id} value={l.id}>{l.name}</option>)}</select></div><div><label className="label">{t('pages:logs.modal.field')}</label><input className="input" value={fform.field} onChange={e => setFform({ ...fform, field: e.target.value })} placeholder={t('pages:logs.modal.fieldPlaceholder')} /></div></div>
              <label className="flex items-center gap-2"><input type="checkbox" checked={fform.enabled} onChange={e => setFform({ ...fform, enabled: e.target.checked })} /> {t('pages:logs.modal.enabled')}</label>
              <button className="btn-primary w-full">{t('common:actions.save')}</button>
            </form>
          </Modal>
        </>
      )}

      {tab === 'live' && (
        <>
          <div className="flex items-center justify-between">
            <h2 className="text-2xl font-bold flex items-center gap-2">
              <Activity className="h-5 w-5 text-primary" /> {t('pages:logs.liveHaproxyLogs')}
            </h2>
            <div className="flex items-center gap-2">
              <select className="input" value={logLimit} onChange={(e) => setLogLimit(Number(e.target.value))}>
                <option value={50}>{t('pages:logs.last50')}</option>
                <option value={100}>{t('pages:logs.last100')}</option>
                <option value={250}>{t('pages:logs.last250')}</option>
                <option value={500}>{t('pages:logs.last500')}</option>
              </select>
              <button onClick={loadLogs} className="btn-secondary" disabled={logLoading}>
                {logLoading ? t('pages:logs.loadingEllipsis') : t('pages:logs.refresh')}
              </button>
            </div>
          </div>

          {logError && (
            <div className="card text-sm">
              <span className="text-slate-400">{t('pages:logs.error')}</span>
              <p className="text-red-400 break-words">{logError}</p>
            </div>
          )}

          <div className="flex items-center gap-2">
            <div className="relative flex-1 max-w-md">
              <Search className="absolute start-2 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
              <input
                type="search"
                className="input !ps-8 py-1 text-sm"
                placeholder={t('pages:logs.filterLogs')}
                value={logSearch}
                onChange={e => setLogSearch(e.target.value)}
              />
            </div>
            <span className="text-xs text-slate-500">
              {t('pages:logs.linesCount', { filtered: filteredLogLines.length, total: logLines.length })}
              {(skippedNonJson > 0 || skippedControl > 0) && (
                <span className="ms-2 text-amber-500" title="Lines filtered out of the last fetch">
                  {t('pages:logs.filteredCount', { nonJson: skippedNonJson, controlSuffix: skippedControl > 0 ? `, ${skippedControl} control-char` : '' })}
                </span>
              )}
            </span>
          </div>

          <div className="card overflow-x-auto max-h-[70vh] !p-0">
            <table className="w-full text-sm text-start">
              <thead className="text-slate-400 border-b border-slate-800 sticky top-0 bg-slate-900 z-10">
                <tr>
                  <th className="px-2 py-2 w-8"></th>
                  <th className="px-3 py-2">{t('pages:logs.tableHeaders.timestamp')}</th>
                  <th className="px-3 py-2">{t('pages:logs.tableHeaders.client')}</th>
                  <th className="px-3 py-2">{t('pages:logs.tableHeaders.city')}</th>
                  <th className="px-3 py-2">{t('pages:logs.tableHeaders.country')}</th>
                  <th className="px-3 py-2">{t('pages:logs.tableHeaders.asn')}</th>
                  <th className="px-3 py-2">{t('pages:logs.tableHeaders.host')}</th>
                  <th className="px-3 py-2">{t('pages:logs.tableHeaders.path')}</th>
                  <th className="px-3 py-2">{t('pages:logs.tableHeaders.method')}</th>
                  <th className="px-3 py-2">{t('pages:logs.tableHeaders.status')}</th>
                  <th className="px-3 py-2">{t('pages:logs.tableHeaders.bytesOut')}</th>
                </tr>
              </thead>
              <tbody>
                {filteredLogLines.map((line, i) => {
                  const p = line.parsed
                  if (!p) {
                    return (
                      <tr key={i} className="border-b border-slate-800 last:border-0">
                        <td className="px-2 py-2"></td>
                        <td colSpan={10} className="px-3 py-2 font-mono text-xs text-slate-400 break-all">{line.raw}</td>
                      </tr>
                    )
                  }
                  const isExpanded = expandedLogRow === i
                  return (
                    <React.Fragment key={i}>
                      <tr
                        className={`border-b border-slate-800 last:border-0 cursor-pointer hover:bg-slate-800/30 ${isExpanded ? 'bg-slate-800/40' : ''}`}
                        onClick={() => setExpandedLogRow(isExpanded ? null : i)}
                      >
                        <td className="px-2 py-2 w-8">
                          <ChevronRight className={`w-4 h-4 text-slate-500 transition-transform ${isExpanded ? 'rotate-90' : ''}`} />
                        </td>
                        <td className="px-3 py-2 whitespace-nowrap text-xs">{formatLogTimestamp(p.ts || line.docker_ts)}</td>
                        <td className="px-3 py-2 whitespace-nowrap">
                          {p.client && p.client !== '-' ? (
                            <button
                              onClick={(e) => { e.stopPropagation(); handleAsnClick(e, i, p.client, p.asn && p.asn !== '-' ? p.asn : '') }}
                              className="text-primary hover:underline cursor-pointer"
                            >
                              {p.client}
                            </button>
                          ) : '-'}
                        </td>
                        <td className="px-3 py-2">{p.city || '-'}</td>
                        <td className="px-3 py-2">{p.country || '-'}</td>
                        <td className="px-3 py-2">
                          {p.asn && p.asn !== '-' ? (
                            <button
                              onClick={(e) => { e.stopPropagation(); handleAsnClick(e, i, p.client, p.asn) }}
                              className="text-primary hover:underline cursor-pointer"
                            >
                              {p.asn}
                            </button>
                          ) : '-'}
                        </td>
                        <td className="px-3 py-2 max-w-xs truncate" title={p.host}>{p.host || '-'}</td>
                        <td className="px-3 py-2 max-w-xs truncate" title={p.path}>{p.path || '-'}</td>
                        <td className="px-3 py-2">{p.method || '-'}</td>
                        <td className="px-3 py-2 whitespace-nowrap">
                          <span>{p.status || '-'}</span>
                          {p.status_source && p.status_source !== '-' && (
                            <span
                              className={`ms-1.5 text-[10px] px-1 py-0.5 rounded font-mono ${p.status_source === 'haproxy' ? 'bg-amber-500/20 text-amber-400' : 'bg-blue-500/20 text-blue-400'}`}
                              title={p.status_source === 'haproxy' ? t('pages:logs.statusSource.haproxyTooltip') : t('pages:logs.statusSource.backendTooltip')}
                            >
                              {p.status_source === 'haproxy' ? 'FE' : 'BE'}
                            </span>
                          )}
                        </td>
                        <td className="px-3 py-2">{p.bytes_out || '-'}</td>
                      </tr>
                      {isExpanded && (
                        <tr className="bg-slate-900/60">
                          <td colSpan={11} className="px-6 py-4">
                            <div className="grid grid-cols-2 md:grid-cols-3 gap-4 text-sm">
                              <div>
                                <span className="text-slate-400 text-xs">{t('pages:logs.expandedFields.fullPath')}</span>
                                <code className="block text-xs mt-1 font-mono break-all">{p.path || '-'}</code>
                              </div>
                              <div>
                                <span className="text-slate-400 text-xs">{t('pages:logs.expandedFields.queryString')}</span>
                                <code className="block text-xs mt-1 font-mono break-all">{p.query || '-'}</code>
                              </div>
                              <div className="col-span-2 md:col-span-3">
                                <span className="text-slate-400 text-xs">{t('pages:logs.expandedFields.userAgent')}</span>
                                <code className="block text-xs mt-1 font-mono break-all">{p.user_agent || '-'}</code>
                              </div>
                              <div>
                                <span className="text-slate-400 text-xs">{t('pages:logs.expandedFields.ja4Fingerprint')}</span>
                                {p.ja4 && p.ja4 !== '-' ? (
                                  <button onClick={(e) => handleJa4Click(e, i, p.ja4)} className="block text-xs mt-1 font-mono break-all text-primary hover:underline cursor-pointer text-start">{p.ja4}</button>
                                ) : <code className="block text-xs mt-1 font-mono break-all">-</code>}
                              </div>
                              <div>
                                <span className="text-slate-400 text-xs">{t('pages:logs.expandedFields.requestFingerprint')}</span>
                                {p.req_fp && p.req_fp !== '-' ? (
                                  <button onClick={(e) => handleReqFpClick(e, i, p.req_fp)} className="block text-xs mt-1 font-mono break-all text-primary hover:underline cursor-pointer text-start">{p.req_fp}</button>
                                ) : <code className="block text-xs mt-1 font-mono break-all">-</code>}
                              </div>
                              <div>
                                <span className="text-slate-400 text-xs">{t('pages:logs.expandedFields.frontend')}</span>
                                <code className="block text-xs mt-1 font-mono break-all">{p.frontend || '-'}</code>
                              </div>
                              <div>
                                <span className="text-slate-400 text-xs">{t('pages:logs.expandedFields.backend')}</span>
                                <code className="block text-xs mt-1 font-mono break-all">{p.backend || '-'}</code>
                              </div>
                              <div>
                                <span className="text-slate-400 text-xs">{t('pages:logs.expandedFields.server')}</span>
                                <code className="block text-xs mt-1 font-mono break-all">{p.server || '-'}</code>
                              </div>
                              <div>
                                <span className="text-slate-400 text-xs">{t('pages:logs.expandedFields.uniqueId')}</span>
                                {p.unique_id && p.unique_id !== '-' ? (
                                  <button onClick={(e) => handleUniqueIdClick(e, i, p.unique_id)} className="block text-xs mt-1 font-mono break-all text-primary hover:underline cursor-pointer text-start">{p.unique_id}</button>
                                ) : <code className="block text-xs mt-1 font-mono break-all">-</code>}
                              </div>
                              <div>
                                <span className="text-slate-400 text-xs">{t('pages:logs.expandedFields.responseTime')}</span>
                                <code className="block text-xs mt-1 font-mono break-all">{p.rt || '-'}</code>
                              </div>
                              <div>
                                <span className="text-slate-400 text-xs">{t('pages:logs.expandedFields.connectTime')}</span>
                                <code className="block text-xs mt-1 font-mono break-all">{p.ct || '-'}</code>
                              </div>
                              <div>
                                <span className="text-slate-400 text-xs">{t('pages:logs.expandedFields.totalTime')}</span>
                                <code className="block text-xs mt-1 font-mono break-all">{p.tt || '-'}</code>
                              </div>
                              <div>
                                <span className="text-slate-400 text-xs">{t('pages:logs.expandedFields.termination')}</span>
                                <code className="block text-xs mt-1 font-mono break-all">{formatTermination(p.termination)}</code>
                              </div>
                              <div>
                                <span className="text-slate-400 text-xs">{t('pages:logs.expandedFields.statusSource')}</span>
                                <code className={`block text-xs mt-1 font-mono break-all ${p.status_source === 'haproxy' ? 'text-amber-400' : p.status_source === 'backend' ? 'text-blue-400' : ''}`}>
                                  {p.status_source && p.status_source !== '-' ? t(`pages:logs.statusSource.${p.status_source}`) : '-'}
                                </code>
                              </div>
                              <div>
                                <span className="text-slate-400 text-xs">{t('pages:logs.expandedFields.secAction')}</span>
                                <code className={`block text-xs mt-1 font-mono break-all ${actionColor(p.sec_action)}`}>{p.sec_action || '-'}</code>
                              </div>
                              <div>
                                <span className="text-slate-400 text-xs">{t('pages:logs.expandedFields.secRule')}</span>
                                <code className="block text-xs mt-1 font-mono break-all">{p.sec_rule || '-'}</code>
                              </div>
                              <div>
                                <span className="text-slate-400 text-xs">{t('pages:logs.expandedFields.riskScore')}</span>
                                <code className={`block text-xs mt-1 font-mono break-all ${Number(p.risk_score) > 60 ? 'text-red-400' : Number(p.risk_score) > 35 ? 'text-orange-400' : Number(p.risk_score) > 15 ? 'text-amber-400' : Number(p.risk_score) > 0 ? 'text-green-400' : ''}`}>{p.risk_score && p.risk_score !== '-' ? p.risk_score : '-'}</code>
                              </div>
                              <div>
                                <span className="text-slate-400 text-xs">{t('pages:logs.expandedFields.riskRulesHitCount')}</span>
                                <code className="block text-xs mt-1 font-mono break-all">{p.risk_rules_hit_count && p.risk_rules_hit_count !== '-' ? p.risk_rules_hit_count : '-'}</code>
                              </div>
                              <div>
                                <span className="text-slate-400 text-xs">{t('pages:logs.expandedFields.riskHitDensity')}</span>
                                <code className={`block text-xs mt-1 font-mono break-all ${Number(p.risk_hit_density) > 50 ? 'text-red-400' : Number(p.risk_hit_density) > 25 ? 'text-orange-400' : Number(p.risk_hit_density) > 10 ? 'text-amber-400' : ''}`}>{p.risk_hit_density && p.risk_hit_density !== '-' ? `${p.risk_hit_density}%` : '-'}</code>
                              </div>
                              <div className="col-span-2 md:col-span-3">
                                <span className="text-slate-400 text-xs">{t('pages:logs.expandedFields.riskRulesHit')}</span>
                                <code className="block text-xs mt-1 font-mono break-all">{p.risk_rules_hit && p.risk_rules_hit !== '-' ? p.risk_rules_hit : '-'}</code>
                              </div>
                              <div>
                                <span className="text-slate-400 text-xs">{t('pages:logs.expandedFields.rlAction')}</span>
                                <code className={`block text-xs mt-1 font-mono break-all ${actionColor(p.rl_action)}`}>{p.rl_action || '-'}</code>
                              </div>
                              <div>
                                <span className="text-slate-400 text-xs">{t('pages:logs.expandedFields.rlName')}</span>
                                <code className="block text-xs mt-1 font-mono break-all">{p.rl_name || '-'}</code>
                              </div>
                              <div>
                                <span className="text-slate-400 text-xs">{t('pages:logs.expandedFields.wafAction')}</span>
                                <code className={`block text-xs mt-1 font-mono break-all ${actionColor(p.waf_action)}`}>{p.waf_action || '-'}</code>
                              </div>
                              <div>
                                <span className="text-slate-400 text-xs">{t('pages:logs.expandedFields.clientPort')}</span>
                                <code className="block text-xs mt-1 font-mono break-all">{p.client_port || '-'}</code>
                              </div>
                              <div>
                                <span className="text-slate-400 text-xs">{t('pages:logs.expandedFields.wafStatus')}</span>
                                <code className="block text-xs mt-1 font-mono break-all">{p.waf_status || '-'}</code>
                              </div>
                              <div>
                                <span className="text-slate-400 text-xs">{t('pages:logs.expandedFields.wafAnomalyScore')}</span>
                                <code className="block text-xs mt-1 font-mono break-all">{p.waf_anomaly_score || '-'}</code>
                              </div>
                              <div>
                                <span className="text-slate-400 text-xs">{t('pages:logs.expandedFields.wafRulesHit')}</span>
                                <code className="block text-xs mt-1 font-mono break-all">{p.waf_rules_hit || '-'}</code>
                              </div>
                              <div>
                                <span className="text-slate-400 text-xs">{t('pages:logs.expandedFields.wafRuleIds')}</span>
                                <code className="block text-xs mt-1 font-mono break-all">{p.waf_rule_ids || '-'}</code>
                              </div>
                            </div>
                            <div className="mt-3">
                              <span className="text-slate-400 text-xs">{t('pages:logs.expandedFields.rawLogLine')}</span>
                              <pre className="text-xs mt-1 bg-slate-950 p-2 rounded overflow-auto max-h-40 break-all whitespace-pre-wrap">{line.raw}</pre>
                            </div>
                          </td>
                        </tr>
                      )}
                    </React.Fragment>
                  )
                })}
                {filteredLogLines.length === 0 && !logError && (
                  <tr>
                    <td colSpan={11} className="px-3 py-6 text-slate-500">{logLines.length === 0 ? t('pages:logs.noLogsCaptured') : t('pages:logs.noLogsMatchFilter')}</td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </>
      )}

      {/* ASN popover — rendered with fixed positioning to avoid table overflow clipping */}
      {asnPopover && (
        <div
          ref={asnPopoverRef}
          className="fixed z-50 w-64 bg-slate-800 border border-slate-700 rounded-lg shadow-xl p-3 text-sm"
          style={computePopoverPosition(asnPopover.rect, 256, 200)}
        >
          <div className="flex items-center justify-between mb-2">
            <span className="font-semibold text-slate-200">
              {asnPopover.asn && asnPopover.asn !== '-' ? formatAsn(asnPopover.asn) : t('pages:logs.asnLookup')}
            </span>
            <button
              onClick={() => { setAsnPopover(null); setAsnResult(null) }}
              className="text-slate-400 hover:text-slate-200"
            >&times;</button>
          </div>
          {asnLoading ? (
            <p className="text-slate-400">{t('pages:logs.lookingUp')}</p>
          ) : asnResult ? (
            <div className="space-y-1">
              <div><span className="text-slate-500">{t('pages:logs.asnFields.country')}</span> <span className="text-slate-200">{asnResult.country || t('common:status.unknown')}</span></div>
              <div><span className="text-slate-500">{t('pages:logs.asnFields.city')}</span> <span className="text-slate-200">{asnResult.city || t('common:status.unknown')}</span></div>
              <div><span className="text-slate-500">{t('pages:logs.asnFields.organization')}</span> <span className="text-slate-200">{asnResult.organization || t('common:status.unknown')}</span></div>
              <div><span className="text-slate-500">{t('pages:logs.asnFields.network')}</span> <span className="text-slate-200 font-mono text-xs">{asnResult.network || t('common:status.unknown')}</span></div>
              <div><span className="text-slate-500">{t('pages:logs.asnFields.ip')}</span> <span className="text-slate-200 font-mono text-xs">{asnPopover.ip}</span></div>
            </div>
          ) : (
            <p className="text-slate-400">{t('common:table.empty')}</p>
          )}
        </div>
      )}

      {/* Unique ID decoder popover */}
      {uidPopover && (
        <div
          ref={uidPopoverRef}
          className="fixed z-50 w-80 bg-slate-800 border border-slate-700 rounded-lg shadow-xl p-3 text-sm"
          style={computePopoverPosition(uidPopover.rect, 320, 220)}
        >
          <div className="flex items-center justify-between mb-2">
            <span className="font-semibold text-slate-200">{t('pages:uniqueIdDecoder.title')}</span>
            <button onClick={() => { setUidPopover(null); setUidDecoded(null) }} className="text-slate-400 hover:text-slate-200">&times;</button>
          </div>
          <div className="mb-2"><code className="text-xs font-mono text-slate-400 break-all">{uidPopover.uid}</code></div>
          {uidDecoded?.error ? (
            <p className="text-red-400 text-xs">{uidDecoded.error}</p>
          ) : uidDecoded?.decoded ? (
            <div className="space-y-1">
              <div><span className="text-slate-500">{t('pages:uniqueIdDecoder.fields.clientIp')}:</span> <span className="text-slate-200 font-mono text-xs">{uidDecoded.decoded.clientIp}</span></div>
              <div><span className="text-slate-500">{t('pages:uniqueIdDecoder.fields.clientPort')}:</span> <span className="text-slate-200 font-mono text-xs">{uidDecoded.decoded.clientPort}</span></div>
              <div><span className="text-slate-500">{t('pages:uniqueIdDecoder.fields.timestamp')}:</span> <span className="text-slate-200 font-mono text-xs">{uidDecoded.decoded.timestampFormatted}</span></div>
              <div><span className="text-slate-500">{t('pages:uniqueIdDecoder.fields.requestCounter')}:</span> <span className="text-slate-200 font-mono text-xs">{uidDecoded.decoded.requestCounter}</span></div>
              <div><span className="text-slate-500">{t('pages:uniqueIdDecoder.fields.processId')}:</span> <span className="text-slate-200 font-mono text-xs">{uidDecoded.decoded.pid}</span></div>
            </div>
          ) : <p className="text-slate-400">{t('common:table.empty')}</p>}
        </div>
      )}

      {/* Request Fingerprint decoder popover */}
      {reqFpPopover && (
        <div
          ref={reqFpPopoverRef}
          className="fixed z-50 w-96 bg-slate-800 border border-slate-700 rounded-lg shadow-xl p-3 text-sm max-h-[70vh] overflow-y-auto"
          style={computePopoverPosition(reqFpPopover.rect, 384, 400)}
        >
          <div className="flex items-center justify-between mb-2">
            <span className="font-semibold text-slate-200">{t('pages:reqFpDecoder.title')}</span>
            <button onClick={() => { setReqFpPopover(null); setReqFpDecoded(null) }} className="text-slate-400 hover:text-slate-200">&times;</button>
          </div>
          <div className="mb-2"><code className="text-xs font-mono text-slate-400 break-all">{reqFpPopover.fp}</code></div>
          {reqFpDecoded?.error ? (
            <p className="text-red-400 text-xs">{reqFpDecoded.error}</p>
          ) : reqFpDecoded?.decoded ? (
            <div className="space-y-1">
              <div><span className="text-slate-500">{t('pages:reqFpDecoder.fields.pathBase62')}:</span> <span className="text-slate-200 font-mono text-xs break-all">{reqFpDecoded.decoded.pathB62}</span></div>
              {reqFpDecoded.decoded.pathDecoded && <div><span className="text-slate-500">{t('pages:reqFpDecoder.decodedPrefix', { value: reqFpDecoded.decoded.pathDecoded })}</span></div>}
              <div><span className="text-slate-500">{t('pages:reqFpDecoder.fields.method')}:</span> <span className="text-slate-200 font-mono text-xs">{reqFpDecoded.decoded.method}</span></div>
              <div><span className="text-slate-500">{t('pages:reqFpDecoder.fields.httpVersion')}:</span> <span className="text-slate-200 font-mono text-xs">{reqFpDecoded.decoded.httpVersion}</span></div>
              <div><span className="text-slate-500">{t('pages:reqFpDecoder.fields.pathDepth')}:</span> <span className="text-slate-200 font-mono text-xs">{reqFpDecoded.decoded.pathDepth}</span></div>
              <div><span className="text-slate-500">{t('pages:reqFpDecoder.fields.paramKeys')}:</span> <span className="text-slate-200 font-mono text-xs">{reqFpDecoded.decoded.paramKeys}</span></div>
              <div><span className="text-slate-500">{t('pages:reqFpDecoder.fields.paramTypes')}:</span> <span className="text-slate-200 font-mono text-xs">{reqFpDecoded.decoded.paramTypes}</span></div>
              <div><span className="text-slate-500">{t('pages:reqFpDecoder.fields.paramLengths')}:</span> <span className="text-slate-200 font-mono text-xs">{reqFpDecoded.decoded.paramLens}</span></div>
              <div><span className="text-slate-500">{t('pages:reqFpDecoder.fields.reqContentType')}:</span> <span className="text-slate-200 font-mono text-xs">{reqFpDecoded.decoded.reqContentType}</span></div>
              <div><span className="text-slate-500">{t('pages:reqFpDecoder.fields.headerCount')}:</span> <span className="text-slate-200 font-mono text-xs">{reqFpDecoded.decoded.headerCount}</span></div>
              <div><span className="text-slate-500">{t('pages:reqFpDecoder.fields.headerList')}:</span> <span className="text-slate-200 font-mono text-xs">{reqFpDecoded.decoded.headerList}</span></div>
              <div><span className="text-slate-500">{t('pages:reqFpDecoder.fields.acceptLanguage')}:</span> <span className="text-slate-200 font-mono text-xs">{reqFpDecoded.decoded.acceptLanguage}</span></div>
              <div><span className="text-slate-500">{t('pages:reqFpDecoder.fields.authType')}:</span> <span className="text-slate-200 font-mono text-xs">{reqFpDecoded.decoded.authType}</span></div>
              <div><span className="text-slate-500">{t('pages:reqFpDecoder.fields.cookie')}:</span> <span className="text-slate-200 font-mono text-xs">{reqFpDecoded.decoded.cookie}</span></div>
              <div><span className="text-slate-500">{t('pages:reqFpDecoder.fields.cookieFields')}:</span> <span className="text-slate-200 font-mono text-xs">{reqFpDecoded.decoded.cookieFields}</span></div>
              <div><span className="text-slate-500">{t('pages:reqFpDecoder.fields.referer')}:</span> <span className="text-slate-200 font-mono text-xs">{reqFpDecoded.decoded.referer}</span></div>
              <div><span className="text-slate-500">{t('pages:reqFpDecoder.fields.responseStatus')}:</span> <span className="text-slate-200 font-mono text-xs">{reqFpDecoded.decoded.status}</span></div>
              <div><span className="text-slate-500">{t('pages:reqFpDecoder.fields.responseBodyBytes')}:</span> <span className="text-slate-200 font-mono text-xs">{reqFpDecoded.decoded.bodyBytes}</span></div>
            </div>
          ) : <p className="text-slate-400">{t('common:table.empty')}</p>}
        </div>
      )}

      {/* JA4 decoder popover */}
      {ja4Popover && (
        <div
          ref={ja4PopoverRef}
          className="fixed z-50 w-72 bg-slate-800 border border-slate-700 rounded-lg shadow-xl p-3 text-sm"
          style={computePopoverPosition(ja4Popover.rect, 288, 280)}
        >
          <div className="flex items-center justify-between mb-2">
            <span className="font-semibold text-slate-200">{t('pages:ja4Decoder.title')}</span>
            <button onClick={() => { setJa4Popover(null); setJa4Decoded(null) }} className="text-slate-400 hover:text-slate-200">&times;</button>
          </div>
          <div className="mb-2"><code className="text-xs font-mono text-slate-400 break-all">{ja4Popover.ja4}</code></div>
          {ja4Decoded?.error ? (
            <p className="text-red-400 text-xs">{ja4Decoded.error}</p>
          ) : ja4Decoded?.decoded ? (
            <div className="space-y-1">
              <div><span className="text-slate-500">{t('pages:ja4Decoder.fields.protocol')}:</span> <span className="text-slate-200 font-mono text-xs">{ja4Decoded.decoded.protocol}</span></div>
              <div><span className="text-slate-500">{t('pages:ja4Decoder.fields.tlsVersion')}:</span> <span className="text-slate-200 font-mono text-xs">{ja4Decoded.decoded.tlsVersion}</span></div>
              <div><span className="text-slate-500">{t('pages:ja4Decoder.fields.sni')}:</span> <span className="text-slate-200 font-mono text-xs">{ja4Decoded.decoded.sni}</span></div>
              <div><span className="text-slate-500">{t('pages:ja4Decoder.fields.alpn')}:</span> <span className="text-slate-200 font-mono text-xs">{ja4Decoded.decoded.alpn}</span></div>
              <div><span className="text-slate-500">{t('pages:ja4Decoder.fields.cipherCount')}:</span> <span className="text-slate-200 font-mono text-xs">{ja4Decoded.decoded.cipherCount}</span></div>
              <div><span className="text-slate-500">{t('pages:ja4Decoder.fields.extensionCount')}:</span> <span className="text-slate-200 font-mono text-xs">{ja4Decoded.decoded.extensionCount}</span></div>
              <div><span className="text-slate-500">{t('pages:ja4Decoder.fields.cipherHash')}:</span> <span className="text-slate-200 font-mono text-xs break-all">{ja4Decoded.decoded.cipherHash}</span></div>
              <div><span className="text-slate-500">{t('pages:ja4Decoder.fields.extensionHash')}:</span> <span className="text-slate-200 font-mono text-xs break-all">{ja4Decoded.decoded.extensionHash}</span></div>
            </div>
          ) : <p className="text-slate-400">{t('common:table.empty')}</p>}
        </div>
      )}
    </div>
  )
}
