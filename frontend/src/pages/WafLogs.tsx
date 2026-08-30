import React, { useEffect, useMemo, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { waf, geoip } from '../services/api'
import { decodeUniqueId } from '../lib/uniqueId'
import { computePopoverPosition } from '../lib/popover'
import { ChevronRight, Search } from 'lucide-react'
import { useDateTime } from '../contexts/DateTimeContext'

interface WafLogEvent {
  time?: string
  timestamp?: string
  unique_id?: string
  action?: string
  rule_id?: string
  id?: string
  severity?: string
  client?: string
  client_ip?: string
  uri?: string
  path?: string
  msg?: string
  message?: string
  raw?: string
}

export default function WafLogs() {
  const { t } = useTranslation(['pages', 'common'])
  const { formatLogTimestamp } = useDateTime()
  const [events, setEvents] = useState<WafLogEvent[]>([])
  const [loading, setLoading] = useState(false)
  const [limit, setLimit] = useState(100)
  const [error, setError] = useState<string | null>(null)
  const [expandedRow, setExpandedRow] = useState<number | null>(null)
  const [search, setSearch] = useState('')

  // ASN popover state
  const [asnPopover, setAsnPopover] = useState<{ rowIndex: number; ip: string; rect: DOMRect } | null>(null)
  const [asnResult, setAsnResult] = useState<{ organization: string | null; network: string | null; city: string | null; country: string | null } | null>(null)
  const [asnLoading, setAsnLoading] = useState(false)
  const asnPopoverRef = useRef<HTMLDivElement>(null)

  // Unique ID popover state
  const [uidPopover, setUidPopover] = useState<{ rowIndex: number; uid: string; rect: DOMRect } | null>(null)
  const [uidDecoded, setUidDecoded] = useState<{ decoded?: ReturnType<typeof decodeUniqueId>['decoded']; error?: string } | null>(null)
  const uidPopoverRef = useRef<HTMLDivElement>(null)

  const handleIpClick = async (e: React.MouseEvent, rowIndex: number, ip: string) => {
    e.stopPropagation()
    if (asnPopover && asnPopover.rowIndex === rowIndex) {
      setAsnPopover(null)
      setAsnResult(null)
      return
    }
    const rect = (e.currentTarget as HTMLElement).getBoundingClientRect()
    setAsnPopover({ rowIndex, ip, rect })
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
    }
    if (asnPopover || uidPopover) document.addEventListener('mousedown', handler)
    return () => document.removeEventListener('mousedown', handler)
  }, [asnPopover, uidPopover])

  const load = async () => {
    setLoading(true)
    setError(null)
    try {
      const logsRes = await waf.logs(limit)
      setEvents(logsRes.data.events || [])
    } catch (err: any) {
      setError(err?.response?.data?.detail || t('pages:wafLogs.failedToLoadWafLogs'))
    }
    setLoading(false)
  }

  useEffect(() => {
    load()
    const id = setInterval(load, 10000)
    return () => clearInterval(id)
  }, [limit])

  const parsed = useMemo(() => {
    const sorted = [...events].sort(
      (a, b) => String(b.time || '').localeCompare(String(a.time || ''))
    )
    if (!search.trim()) return sorted
    const lower = search.toLowerCase()
    return sorted.filter(row =>
      Object.values(row).some(v => String(v ?? '').toLowerCase().includes(lower))
    )
  }, [events, search])

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-end">
        <div className="flex items-center gap-2">
          <select
            className="input"
            value={limit}
            onChange={(e) => setLimit(Number(e.target.value))}
          >
            <option value={50}>{t('pages:wafLogs.last50')}</option>
            <option value={100}>{t('pages:wafLogs.last100')}</option>
            <option value={250}>{t('pages:wafLogs.last250')}</option>
            <option value={500}>{t('pages:wafLogs.last500')}</option>
          </select>
          <button onClick={load} className="btn-secondary" disabled={loading}>
            {loading ? t('pages:wafLogs.loadingEllipsis') : t('pages:wafLogs.refresh')}
          </button>
        </div>
      </div>

      {error && (
        <div className="card text-sm">
          <span className="text-slate-400">{t('pages:wafLogs.error')}</span>
          <p className="text-red-400 break-words">{error}</p>
        </div>
      )}

      <div className="flex items-center gap-2">
        <div className="relative flex-1 max-w-md">
          <Search className="absolute start-2 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
          <input
            type="search"
            className="input !ps-8 py-1 text-sm"
            placeholder={t('pages:wafLogs.filterWafEvents')}
            value={search}
            onChange={e => setSearch(e.target.value)}
          />
        </div>
        <span className="text-xs text-slate-500">{t('pages:wafLogs.eventsCount', { filtered: parsed.length, total: events.length })}</span>
      </div>

      <div className="card overflow-x-auto max-h-[70vh] !p-0">
        <table className="w-full text-sm text-start">
          <thead className="text-slate-400 border-b border-slate-800 sticky top-0 bg-slate-900 z-10">
            <tr>
              <th className="px-2 py-3 w-8"></th>
              <th className="px-4 py-3">{t('pages:wafLogs.tableHeaders.time')}</th>
              <th className="px-4 py-3">{t('pages:wafLogs.tableHeaders.eventId')}</th>
              <th className="px-4 py-3">{t('pages:wafLogs.tableHeaders.action')}</th>
              <th className="px-4 py-3">{t('pages:wafLogs.tableHeaders.ruleId')}</th>
              <th className="px-4 py-3">{t('pages:wafLogs.tableHeaders.severity')}</th>
              <th className="px-4 py-3">{t('pages:wafLogs.tableHeaders.client')}</th>
              <th className="px-4 py-3">{t('pages:wafLogs.tableHeaders.uri')}</th>
              <th className="px-4 py-3">{t('pages:wafLogs.tableHeaders.message')}</th>
            </tr>
          </thead>
          <tbody>
            {parsed.map((row, i) => {
              const isExpanded = expandedRow === i
              return (
                <React.Fragment key={i}>
                  <tr
                    className={`border-b border-slate-800 last:border-0 cursor-pointer hover:bg-slate-800/30 ${isExpanded ? 'bg-slate-800/40' : ''}`}
                    onClick={() => setExpandedRow(isExpanded ? null : i)}
                  >
                    <td className="px-2 py-2 w-8">
                      <ChevronRight className={`w-4 h-4 text-slate-500 transition-transform ${isExpanded ? 'rotate-90' : ''}`} />
                    </td>
                    <td className="px-4 py-2 whitespace-nowrap">{formatLogTimestamp(row.time || row.timestamp)}</td>
                    <td className="px-4 py-2 max-w-xs truncate font-mono" title={row.unique_id}>
                      {row.unique_id ? (
                        <button onClick={(e) => handleUniqueIdClick(e, i, row.unique_id!)} className="text-primary hover:underline cursor-pointer">
                          {row.unique_id}
                        </button>
                      ) : '-'}
                    </td>
                    <td className="px-4 py-2">{row.action || '-'}</td>
                    <td className="px-4 py-2">{row.rule_id || row.id || '-'}</td>
                    <td className="px-4 py-2">{row.severity || '-'}</td>
                    <td className="px-4 py-2">
                      {(row.client || row.client_ip) ? (
                        <button onClick={(e) => handleIpClick(e, i, row.client || row.client_ip!)} className="text-primary hover:underline cursor-pointer">
                          {row.client || row.client_ip}
                        </button>
                      ) : '-'}
                    </td>
                    <td className="px-4 py-2 max-w-xs truncate" title={row.uri || row.path}>
                      {row.uri || row.path || '-'}
                    </td>
                    <td className="px-4 py-2 max-w-md truncate" title={row.msg || row.message || row.raw}>
                      {row.msg || row.message || row.raw || '-'}
                    </td>
                  </tr>
                  {isExpanded && (
                    <tr className="bg-slate-900/60">
                      <td colSpan={9} className="px-6 py-4">
                        <div className="grid grid-cols-2 md:grid-cols-3 gap-4 text-sm">
                          <div>
                            <span className="text-slate-400 text-xs">{t('pages:wafLogs.expandedFields.fullTime')}</span>
                            <code className="block text-xs mt-1 font-mono break-all">{formatLogTimestamp(row.time || row.timestamp)}</code>
                          </div>
                          <div>
                            <span className="text-slate-400 text-xs">{t('pages:wafLogs.expandedFields.uniqueId')}</span>
                            <code className="block text-xs mt-1 font-mono break-all">{row.unique_id || '-'}</code>
                          </div>
                          <div>
                            <span className="text-slate-400 text-xs">{t('pages:wafLogs.expandedFields.action')}</span>
                            <code className="block text-xs mt-1 font-mono break-all">{row.action || '-'}</code>
                          </div>
                          <div>
                            <span className="text-slate-400 text-xs">{t('pages:wafLogs.expandedFields.ruleId')}</span>
                            <code className="block text-xs mt-1 font-mono break-all">{row.rule_id || row.id || '-'}</code>
                          </div>
                          <div>
                            <span className="text-slate-400 text-xs">{t('pages:wafLogs.expandedFields.severity')}</span>
                            <code className="block text-xs mt-1 font-mono break-all">{row.severity || '-'}</code>
                          </div>
                          <div>
                            <span className="text-slate-400 text-xs">{t('pages:wafLogs.expandedFields.clientIp')}</span>
                            <code className="block text-xs mt-1 font-mono break-all">{row.client || row.client_ip || '-'}</code>
                          </div>
                          <div className="col-span-2 md:col-span-3">
                            <span className="text-slate-400 text-xs">{t('pages:wafLogs.expandedFields.fullUri')}</span>
                            <code className="block text-xs mt-1 font-mono break-all">{row.uri || row.path || '-'}</code>
                          </div>
                          <div className="col-span-2 md:col-span-3">
                            <span className="text-slate-400 text-xs">{t('pages:wafLogs.expandedFields.fullMessage')}</span>
                            <p className="text-xs mt-1 break-all">{row.msg || row.message || '-'}</p>
                          </div>
                        </div>
                        {row.raw && (
                          <div className="mt-3">
                            <span className="text-slate-400 text-xs">{t('pages:wafLogs.expandedFields.rawLogLine')}</span>
                            <pre className="text-xs mt-1 bg-slate-950 p-2 rounded overflow-auto max-h-40 break-all whitespace-pre-wrap">{row.raw}</pre>
                          </div>
                        )}
                      </td>
                    </tr>
                  )}
                </React.Fragment>
              )
            })}
            {parsed.length === 0 && (
              <tr>
                <td colSpan={9} className="px-4 py-6 text-slate-500">{events.length === 0 ? t('pages:wafLogs.noWafEvents') : t('pages:wafLogs.noEventsMatchFilter')}</td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      {/* ASN popover — rendered with fixed positioning to avoid table overflow clipping */}
      {asnPopover && (
        <div
          ref={asnPopoverRef}
          className="fixed z-50 w-64 bg-slate-800 border border-slate-700 rounded-lg shadow-xl p-3 text-sm"
          style={computePopoverPosition(asnPopover.rect, 256, 200)}
        >
          <div className="flex items-center justify-between mb-2">
            <span className="font-semibold text-slate-200">ASN Lookup</span>
            <button
              onClick={() => { setAsnPopover(null); setAsnResult(null) }}
              className="text-slate-400 hover:text-slate-200"
            >&times;</button>
          </div>
          {asnLoading ? (
            <p className="text-slate-400">Looking up...</p>
          ) : asnResult ? (
            <div className="space-y-1">
              <div><span className="text-slate-500">Country:</span> <span className="text-slate-200">{asnResult.country || 'Unknown'}</span></div>
              <div><span className="text-slate-500">City:</span> <span className="text-slate-200">{asnResult.city || 'Unknown'}</span></div>
              <div><span className="text-slate-500">Organization:</span> <span className="text-slate-200">{asnResult.organization || 'Unknown'}</span></div>
              <div><span className="text-slate-500">Network:</span> <span className="text-slate-200 font-mono text-xs">{asnResult.network || 'Unknown'}</span></div>
              <div><span className="text-slate-500">IP:</span> <span className="text-slate-200 font-mono text-xs">{asnPopover.ip}</span></div>
            </div>
          ) : (
            <p className="text-slate-400">No data available</p>
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
            <span className="font-semibold text-slate-200">Unique ID Decoder</span>
            <button
              onClick={() => { setUidPopover(null); setUidDecoded(null) }}
              className="text-slate-400 hover:text-slate-200"
            >&times;</button>
          </div>
          <div className="mb-2">
            <code className="text-xs font-mono text-slate-400 break-all">{uidPopover.uid}</code>
          </div>
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
          ) : (
            <p className="text-slate-400">No data available</p>
          )}
        </div>
      )}
    </div>
  )
}
