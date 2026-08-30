import { useCallback, useEffect, useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { ClipboardList, ChevronDown, ChevronRight, Clock, CheckCircle, Package, Activity } from 'lucide-react'
import { auditEvents, type AuditEvent, type AuditEventFilters, type AuditEventFilterOptions } from '../services/api'
import useApiList from '../hooks/useApiList'
import { useDateTime } from '../contexts/DateTimeContext'
import { toDatetimeLocalInTz, fromDatetimeLocalToUtc } from '../lib/dateTime'

const emptyFilters: AuditEventFilters = { username: '', action: '', resource: '', ip: '' }

interface SnapshotGroup {
  snapshotId: number | null  // null = "Earlier applies" (snapshot pruned)
  comment: string | null
  createdAt: string | null
  events: AuditEvent[]
}

export default function AuditLogs() {
  const { t } = useTranslation(['pages', 'common'])
  const { formatDateTime, timezone } = useDateTime()
  const [limit, setLimit] = useState(100)
  const [start, setStart] = useState('')
  const [end, setEnd] = useState('')
  const [filterInputs, setFilterInputs] = useState<AuditEventFilters>(emptyFilters)
  const [filters, setFilters] = useState<AuditEventFilters>(emptyFilters)
  const [snapshotFilter, setSnapshotFilter] = useState<'all' | 'pending' | 'applied'>('all')
  const [expandedPayload, setExpandedPayload] = useState<number | null>(null)
  const [expandedGroups, setExpandedGroups] = useState<Set<number>>(new Set())
  const [filterOptions, setFilterOptions] = useState<AuditEventFilterOptions>({ usernames: [], actions: [], resource_types: [], ip_addresses: [] })

  useEffect(() => {
    const now = new Date()
    const yesterday = new Date(now.getTime() - 24 * 60 * 60 * 1000)
    setEnd(toDatetimeLocalInTz(now, timezone))
    setStart(toDatetimeLocalInTz(yesterday, timezone))
  }, [timezone])

  useEffect(() => {
    auditEvents.filterOptions()
      .then(res => setFilterOptions(res.data))
      .catch(() => {})
  }, [])

  const fetcherFilters = useMemo<AuditEventFilters>(() => ({
    ...filters,
    hasSnapshot: snapshotFilter === 'pending' ? false : snapshotFilter === 'applied' ? true : undefined,
  }), [filters, snapshotFilter])

  const fetcher = useCallback(() => {
    const fromIso = start ? fromDatetimeLocalToUtc(start, timezone).toISOString() : undefined
    const toIso = end ? fromDatetimeLocalToUtc(end, timezone).toISOString() : undefined
    return auditEvents.list(limit, fetcherFilters, fromIso, toIso)
  }, [limit, fetcherFilters, start, end, timezone])
  const { items, reload, loading } = useApiList<AuditEvent>(fetcher)

  const applyFilters = () => setFilters({ ...filterInputs })
  const clearFilters = () => {
    setFilterInputs(emptyFilters)
    setFilters(emptyFilters)
  }

  const exportCsv = async () => {
    try {
      const res = await auditEvents.export(
        start ? fromDatetimeLocalToUtc(start, timezone).toISOString() : undefined,
        end ? fromDatetimeLocalToUtc(end, timezone).toISOString() : undefined,
        filters,
      )
      const blob = new Blob([res.data], { type: 'text/csv' })
      const url = window.URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      const startName = start ? start.replace('T', ' ') : 'start'
      const endName = end ? end.replace('T', ' ') : 'end'
      a.download = `audit-events ${startName} to ${endName}.csv`
      document.body.appendChild(a)
      a.click()
      document.body.removeChild(a)
      window.URL.revokeObjectURL(url)
    } catch (e) {
      console.error(e)
      alert(t('pages:auditLogs.exportFailed'))
    }
  }

  const toggleGroup = (snapshotId: number | null) => {
    const key = snapshotId ?? -1
    setExpandedGroups(prev => {
      const next = new Set(prev)
      if (next.has(key)) next.delete(key)
      else next.add(key)
      return next
    })
  }

  // Split events into pending (no snapshot, config-affecting), other (no
  // snapshot, non-config), and grouped by snapshot (applied).
  // Applied events with snapshot_id are grouped by snapshot.
  // Applied events without snapshot_id (snapshot pruned) go to "Earlier applies".
  const { pendingEvents, otherEvents, snapshotGroups } = useMemo(() => {
    const pending: AuditEvent[] = []
    const other: AuditEvent[] = []
    const groupsMap = new Map<number, SnapshotGroup>()
    let earlierGroup: SnapshotGroup | null = null
    for (const event of items) {
      if (event.snapshot_created_at == null) {
        // Not applied — split into pending vs other by config_change
        if (event.config_change === false) {
          other.push(event)
        } else {
          pending.push(event)
        }
      } else if (event.snapshot_id != null) {
        // Applied with a known snapshot — group by snapshot ID
        let group = groupsMap.get(event.snapshot_id)
        if (!group) {
          group = {
            snapshotId: event.snapshot_id,
            comment: event.snapshot_comment,
            createdAt: event.snapshot_created_at,
            events: [],
          }
          groupsMap.set(event.snapshot_id, group)
        }
        group.events.push(event)
      } else {
        // Applied but snapshot record was pruned — "Earlier applies" bucket
        if (!earlierGroup) {
          earlierGroup = {
            snapshotId: null,
            comment: null,
            createdAt: event.snapshot_created_at,
            events: [],
          }
        }
        earlierGroup.events.push(event)
      }
    }
    // Sort groups by snapshot created_at descending; earlier group goes last
    const groups = Array.from(groupsMap.values()).sort((a, b) => {
      const aTime = a.createdAt ? new Date(a.createdAt).getTime() : 0
      const bTime = b.createdAt ? new Date(b.createdAt).getTime() : 0
      return bTime - aTime
    })
    if (earlierGroup) {
      groups.push(earlierGroup)
    }
    return { pendingEvents: pending, otherEvents: other, snapshotGroups: groups }
  }, [items])

  const renderPayload = (event: AuditEvent) => {
    if (!event.payload) return null
    const isExpanded = expandedPayload === event.id
    const payloadStr = JSON.stringify(event.payload, null, 2)
    const isTruncated = !!(event.payload as Record<string, unknown>)?._truncated
    return (
      <div className="mt-1">
        <button
          onClick={() => setExpandedPayload(isExpanded ? null : event.id)}
          className="text-xs text-primary hover:underline"
        >
          {isExpanded ? 'Hide' : 'Show'} payload{isTruncated ? ' (truncated)' : ''}
        </button>
        {isExpanded && (
          <pre className="mt-1 p-2 bg-slate-900 rounded text-xs overflow-x-auto max-h-64 overflow-y-auto">
            {payloadStr}
          </pre>
        )}
      </div>
    )
  }

  const renderEventRow = (event: AuditEvent) => (
    <div key={event.id} className="border-b border-slate-800 last:border-0 py-2 px-3">
      <div className="flex items-center gap-3 text-sm flex-wrap">
        <span className="text-slate-400 whitespace-nowrap">{formatDateTime(event.created_at)}</span>
        <span className="font-mono text-xs px-1.5 py-0.5 rounded bg-slate-700 text-slate-200">{event.method}</span>
        <span className="font-medium text-primary">{event.action}</span>
        {event.resource_type && (
          <span className="text-slate-300">
            {event.resource_type}{event.resource_id ? ` #${event.resource_id}` : ''}
          </span>
        )}
        <span className="text-slate-500 font-mono text-xs flex-1 truncate">{event.path}</span>
        <span className={`text-xs font-mono ${event.status_code && event.status_code < 400 ? 'text-green-400' : 'text-red-400'}`}>
          {event.status_code}
        </span>
        <span className="text-slate-400 text-xs">{event.ip_address || '-'}</span>
        <span className="text-slate-300 text-xs">{event.username || 'anonymous'}</span>
      </div>
      {renderPayload(event)}
    </div>
  )

  return (
    <div className="space-y-4">
      <h2 className="text-2xl font-bold flex items-center gap-2"><ClipboardList className="h-5 w-5 text-primary" /> {t('pages:auditLogs.title')}</h2>
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 items-start">
        {/* Filter form */}
        <div className="card space-y-3">
          <h3 className="text-sm font-semibold text-slate-300">{t('pages:auditLogs.filters.title')}</h3>
          <div className="flex flex-wrap items-center gap-2">
            <label className="text-sm text-slate-400">{t('pages:auditLogs.filters.username')}</label>
            <select
              className="input py-1 w-36"
              value={filterInputs.username || ''}
              onChange={e => setFilterInputs({ ...filterInputs, username: e.target.value })}
            >
              <option value="">{t('pages:auditLogs.filters.any')}</option>
              {filterOptions.usernames.map(u => <option key={u} value={u}>{u}</option>)}
            </select>
            <label className="text-sm text-slate-400">{t('pages:auditLogs.filters.action')}</label>
            <select
              className="input py-1 w-44"
              value={filterInputs.action || ''}
              onChange={e => setFilterInputs({ ...filterInputs, action: e.target.value })}
            >
              <option value="">{t('pages:auditLogs.filters.any')}</option>
              {filterOptions.actions.map(a => <option key={a} value={a}>{a}</option>)}
            </select>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <label className="text-sm text-slate-400">{t('pages:auditLogs.filters.resource')}</label>
            <select
              className="input py-1 w-36"
              value={filterInputs.resource || ''}
              onChange={e => setFilterInputs({ ...filterInputs, resource: e.target.value })}
            >
              <option value="">{t('pages:auditLogs.filters.any')}</option>
              {filterOptions.resource_types.map(r => <option key={r} value={r}>{r}</option>)}
            </select>
            <label className="text-sm text-slate-400">{t('pages:auditLogs.filters.ipAddress')}</label>
            <select
              className="input py-1 w-36"
              value={filterInputs.ip || ''}
              onChange={e => setFilterInputs({ ...filterInputs, ip: e.target.value })}
            >
              <option value="">{t('pages:auditLogs.filters.any')}</option>
              {filterOptions.ip_addresses.map(ip => <option key={ip} value={ip}>{ip}</option>)}
            </select>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <label className="text-sm text-slate-400">{t('pages:auditLogs.filters.status')}</label>
            <select
              className="input py-1"
              value={snapshotFilter}
              onChange={e => setSnapshotFilter(e.target.value as 'all' | 'pending' | 'applied')}
            >
              <option value="all">{t('pages:auditLogs.filters.statusAll')}</option>
              <option value="pending">{t('pages:auditLogs.filters.statusPending')}</option>
              <option value="applied">{t('pages:auditLogs.filters.statusApplied')}</option>
            </select>
            <button onClick={applyFilters} className="btn-primary">{t('common:actions.apply')}</button>
            <button onClick={clearFilters} className="btn-secondary">{t('pages:auditLogs.filters.clear')}</button>
          </div>
        </div>
        {/* Export form */}
        <div className="card space-y-3">
          <h3 className="text-sm font-semibold text-slate-300">{t('pages:auditLogs.exportCsv')}</h3>
          <div className="flex flex-wrap items-center gap-2">
            <label className="text-sm text-slate-400">{t('pages:auditLogs.filters.limit')}</label>
            <select className="input py-1 w-24" value={limit} onChange={e => setLimit(Number(e.target.value))}>
              <option value={50}>50</option>
              <option value={100}>100</option>
              <option value={250}>250</option>
              <option value={500}>500</option>
            </select>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <label className="text-sm text-slate-400">{t('pages:auditLogs.filters.from')}</label>
            <input
              type="datetime-local"
              className="input py-1"
              value={start}
              onChange={e => setStart(e.target.value)}
            />
            <label className="text-sm text-slate-400">{t('pages:auditLogs.filters.to')}</label>
            <input
              type="datetime-local"
              className="input py-1"
              value={end}
              onChange={e => setEnd(e.target.value)}
            />
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <button onClick={exportCsv} className="btn-primary">{t('pages:auditLogs.exportCsv')}</button>
            <button onClick={reload} className="btn-secondary">{t('common:actions.refresh')}</button>
          </div>
        </div>
      </div>
      {loading ? (
        <p>{t('pages:auditLogs.loading')}</p>
      ) : items.length === 0 ? (
        <p className="text-slate-400">{t('pages:auditLogs.noEvents')}</p>
      ) : (
        <div className="space-y-4">
          {/* Pending changes (not yet applied) */}
          {(snapshotFilter === 'all' || snapshotFilter === 'pending') && pendingEvents.length > 0 && (
            <div className="card">
              <div className="flex items-center gap-2 px-4 py-3 border-b border-slate-800 bg-amber-900/20">
                <Clock className="h-4 w-4 text-amber-400" />
                <h3 className="font-semibold text-amber-300">{t('pages:auditLogs.pendingChanges')}</h3>
                <span className="text-xs text-amber-400/70">{t('pages:auditLogs.pendingChanges')}</span>
                <span className="ms-auto text-sm text-slate-400">{pendingEvents.length} event{pendingEvents.length !== 1 ? 's' : ''}</span>
              </div>
              <div>
                {pendingEvents.map(renderEventRow)}
              </div>
            </div>
          )}

          {/* Other activity (non-config, no snapshot) */}
          {snapshotFilter === 'all' && otherEvents.length > 0 && (
            <div className="card">
              <div className="flex items-center gap-2 px-4 py-3 border-b border-slate-800 bg-slate-800/40">
                <Activity className="h-4 w-4 text-slate-400" />
                <h3 className="font-semibold text-slate-300">{t('pages:auditLogs.otherActivity')}</h3>
                <span className="ms-auto text-sm text-slate-400">{otherEvents.length} event{otherEvents.length !== 1 ? 's' : ''}</span>
              </div>
              <div>
                {otherEvents.map(renderEventRow)}
              </div>
            </div>
          )}

          {/* Applied changes grouped by snapshot */}
          {(snapshotFilter === 'all' || snapshotFilter === 'applied') && snapshotGroups.length > 0 && (
            <div className="space-y-3">
              <div className="flex items-center gap-2 text-slate-400 text-sm">
                <CheckCircle className="h-4 w-4 text-green-400" />
                {t('pages:auditLogs.appliedChanges')}
              </div>
              {snapshotGroups.map(group => {
                const groupKey = group.snapshotId ?? -1
                const isExpanded = expandedGroups.has(groupKey)
                const isEarlier = group.snapshotId == null
                return (
                  <div key={groupKey} className="card">
                    <button
                      onClick={() => toggleGroup(group.snapshotId)}
                      className="flex items-center gap-2 w-full px-4 py-3 border-b border-slate-800 hover:bg-slate-800/50"
                    >
                      {isExpanded ? <ChevronDown className="h-4 w-4 text-slate-400" /> : <ChevronRight className="h-4 w-4 text-slate-400" />}
                      <Package className="h-4 w-4 text-primary" />
                      <span className="font-semibold text-slate-200">
                        {isEarlier
                          ? t('pages:auditLogs.earlierApplies')
                          : t('pages:auditLogs.snapshotGroup', { id: group.snapshotId, comment: group.comment || t('pages:auditLogs.noComment') })}
                      </span>
                      <span className="ms-auto text-sm text-slate-400">
                        {group.createdAt ? formatDateTime(group.createdAt) : ''}
                      </span>
                      <span className="text-xs text-slate-500 ms-3">{group.events.length} event{group.events.length !== 1 ? 's' : ''}</span>
                    </button>
                    {isExpanded && (
                      <div>
                        {group.events.map(renderEventRow)}
                      </div>
                    )}
                  </div>
                )
              })}
            </div>
          )}
        </div>
      )}
    </div>
  )
}
