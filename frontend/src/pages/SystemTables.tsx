import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Table as TableIcon, Trash2, ChevronRight, ChevronDown, RefreshCw, Search, X } from 'lucide-react'
import { stickTables, getErrorDetail } from '../services/api'
import { useNotifications } from '../contexts/NotificationContext'
import { useDateTime } from '../contexts/DateTimeContext'
import { IconButton } from '../components/ui'

interface StickTableSummary {
  name: string
  type: string
  size: number
  used: number
}

interface StickTableEntry {
  key: string
  use: number | string
  exp: number | string
  stores: Record<string, string>
}

interface StickTableDetail {
  name: string
  type: string
  size: number
  used: number
  total: number
  offset: number
  limit: number
  entries: StickTableEntry[]
}

const PAGE_SIZES = [50, 100, 200, 500]
const AUTO_REFRESH_MS = 5000

/** Format a stick-table entry's `exp` (milliseconds remaining) as a wall-clock time.
 *
 * The expire time is computed as `now + exp ms` and formatted using the
 * user's profile time-format preference (via `formatTime` from DateTimeContext).
 * Only the time portion is shown — all default stick-table TTLs are ≤ 1 hour,
 * so the date is not needed.
 */
function formatExpireTime(
  exp: number | string,
  formatTime: (iso: string | number | Date) => string,
): string {
  const expNum = typeof exp === 'number' ? exp : parseInt(exp, 10)
  if (!Number.isFinite(expNum) || expNum <= 0) return '-'
  const expiresAt = Date.now() + expNum
  return formatTime(expiresAt)
}

export default function SystemTables() {
  const { t } = useTranslation(['pages', 'common'])
  const { addNotification } = useNotifications()

  const [tables, setTables] = useState<StickTableSummary[]>([])
  const [loadingTables, setLoadingTables] = useState(true)
  const [expanded, setExpanded] = useState<string | null>(null)

  const loadTables = useCallback(async () => {
    setLoadingTables(true)
    try {
      const r = await stickTables.list()
      setTables(r.data)
    } catch (err) {
      addNotification({ type: 'error', title: t('pages:systemTables.title'), message: getErrorDetail(err, t('common:errors.loadFailed')) })
    } finally {
      setLoadingTables(false)
    }
  }, [addNotification, t])

  useEffect(() => {
    loadTables()
  }, [loadTables])

  const toggleExpand = (name: string) => {
    setExpanded((prev) => (prev === name ? null : name))
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h2 className="text-lg font-semibold flex items-center gap-2">
          <TableIcon className="h-5 w-5 text-primary" /> {t('pages:systemTables.title')}
        </h2>
        <button onClick={loadTables} className="btn-secondary text-sm" disabled={loadingTables}>
          {loadingTables ? t('common:actions.loading') : t('common:actions.refresh')}
        </button>
      </div>

      <p className="text-sm text-slate-400">{t('pages:systemTables.description')}</p>

      {loadingTables ? (
        <p>{t('common:actions.loading')}</p>
      ) : tables.length === 0 ? (
        <p className="text-slate-400">{t('pages:systemTables.noTables')}</p>
      ) : (
        <div className="card overflow-x-auto">
          <table className="w-full text-sm text-start">
            <thead className="text-slate-400 border-b border-slate-800">
              <tr>
                <th className="pb-2 w-8"></th>
                <th className="pb-2">{t('pages:systemTables.tableName')}</th>
                <th className="pb-2">{t('pages:systemTables.type')}</th>
                <th className="pb-2 text-end">{t('pages:systemTables.size')}</th>
                <th className="pb-2 text-end">{t('pages:systemTables.used')}</th>
              </tr>
            </thead>
            <tbody>
              {tables.map((tbl) => (
                <TableRow
                  key={tbl.name}
                  table={tbl}
                  expanded={expanded === tbl.name}
                  onToggle={() => toggleExpand(tbl.name)}
                />
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}

function TableRow({
  table,
  expanded,
  onToggle,
}: {
  table: StickTableSummary
  expanded: boolean
  onToggle: () => void
}) {
  const { t } = useTranslation(['pages', 'common'])
  const { addNotification } = useNotifications()

  return (
    <>
      <tr className="border-b border-slate-800 last:border-0 hover:bg-slate-800/30">
        <td className="py-2">
          <button onClick={onToggle} className="text-slate-400 hover:text-slate-200" aria-label={expanded ? t('common:actions.collapse') : t('common:actions.expand')}>
            {expanded ? <ChevronDown className="w-4 h-4" /> : <ChevronRight className="w-4 h-4" />}
          </button>
        </td>
        <td className="py-2 font-mono">{table.name}</td>
        <td className="font-mono text-slate-300">{table.type}</td>
        <td className="text-end font-mono text-slate-300">{table.size.toLocaleString()}</td>
        <td className="text-end font-mono">
          <span className="px-2 py-0.5 rounded-full bg-slate-800 text-xs">{table.used.toLocaleString()}</span>
        </td>
      </tr>
      {expanded && (
        <tr className="border-b border-slate-800">
          <td colSpan={5} className="p-4 bg-slate-900/40">
            <TableEntries table={table} addNotification={addNotification} />
          </td>
        </tr>
      )}
    </>
  )
}

function TableEntries({
  table,
  addNotification,
}: {
  table: StickTableSummary
  addNotification: ReturnType<typeof useNotifications>['addNotification']
}) {
  const { t } = useTranslation(['pages', 'common'])
  const { formatTime } = useDateTime()
  const [detail, setDetail] = useState<StickTableDetail | null>(null)
  const [loading, setLoading] = useState(true)
  const [page, setPage] = useState(0) // 0-based page index
  const [pageSize, setPageSize] = useState(100)
  const [search, setSearch] = useState('')
  const [autoRefresh, setAutoRefresh] = useState(false)
  const [clearingAll, setClearingAll] = useState(false)
  const searchTimer = useRef<ReturnType<typeof setTimeout> | null>(null)
  const [searchInput, setSearchInput] = useState('')

  const offset = page * pageSize

  const fetchEntries = useCallback(async () => {
    setLoading(true)
    try {
      const r = await stickTables.get(table.name, { limit: pageSize, offset, search: search || undefined })
      setDetail(r.data)
    } catch (err) {
      addNotification({ type: 'error', title: table.name, message: getErrorDetail(err, t('common:errors.loadFailed')) })
    } finally {
      setLoading(false)
    }
  }, [table.name, pageSize, offset, search, addNotification, t])

  useEffect(() => {
    fetchEntries()
  }, [fetchEntries])

  // Auto-refresh
  useEffect(() => {
    if (!autoRefresh) return
    const id = setInterval(() => {
      stickTables
        .get(table.name, { limit: pageSize, offset, search: search || undefined })
        .then((r) => setDetail(r.data))
        .catch(() => {})
    }, AUTO_REFRESH_MS)
    return () => clearInterval(id)
  }, [autoRefresh, table.name, pageSize, offset, search])

  // Debounced search
  const onSearchChange = (val: string) => {
    setSearchInput(val)
    if (searchTimer.current) clearTimeout(searchTimer.current)
    searchTimer.current = setTimeout(() => {
      setPage(0)
      setSearch(val)
    }, 300)
  }

  useEffect(() => {
    return () => {
      if (searchTimer.current) clearTimeout(searchTimer.current)
    }
  }, [])

  const totalPages = detail ? Math.max(1, Math.ceil(detail.total / pageSize)) : 1

  const storeKeys = useMemo(() => {
    if (!detail || detail.entries.length === 0) return []
    // Derive columns from the first entry's stores; merge keys across all
    // visible entries so we don't lose columns if the first entry lacks one.
    const keys = new Set<string>()
    for (const e of detail.entries) {
      for (const k of Object.keys(e.stores)) keys.add(k)
    }
    return Array.from(keys)
  }, [detail])

  const handleClearEntry = async (key: string) => {
    if (!window.confirm(t('pages:systemTables.confirmClearEntry', { key }))) return
    try {
      await stickTables.clearEntry(table.name, key)
      addNotification({ type: 'success', title: table.name, message: t('pages:systemTables.entryCleared') })
      fetchEntries()
    } catch (err) {
      addNotification({ type: 'error', title: table.name, message: getErrorDetail(err, t('pages:systemTables.clearFailed')) })
    }
  }

  const handleClearAll = async () => {
    if (!window.confirm(t('pages:systemTables.confirmClearAll', { name: table.name }))) return
    setClearingAll(true)
    try {
      await stickTables.clearAll(table.name)
      addNotification({ type: 'success', title: table.name, message: t('pages:systemTables.tableCleared') })
      setPage(0)
      fetchEntries()
    } catch (err) {
      addNotification({ type: 'error', title: table.name, message: getErrorDetail(err, t('pages:systemTables.clearFailed')) })
    } finally {
      setClearingAll(false)
    }
  }

  return (
    <div className="space-y-3">
      {/* Toolbar */}
      <div className="flex flex-wrap items-center gap-3">
        <div className="relative">
          <Search className="absolute start-2 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500 pointer-events-none" />
          <input
            type="text"
            placeholder={t('pages:systemTables.searchPlaceholder')}
            value={searchInput}
            onChange={(e) => onSearchChange(e.target.value)}
            className="input !ps-8 !pe-8 w-64"
          />
          {searchInput && (
            <button
              onClick={() => { setSearchInput(''); setPage(0); setSearch('') }}
              className="absolute end-2 top-1/2 -translate-y-1/2 text-slate-500 hover:text-slate-300"
              aria-label={t('pages:systemTables.clearSearch')}
            >
              <X className="w-4 h-4" />
            </button>
          )}
        </div>

        <select
          value={pageSize}
          onChange={(e) => { setPageSize(Number(e.target.value)); setPage(0) }}
          className="input w-28"
        >
          {PAGE_SIZES.map((s) => (
            <option key={s} value={s}>{s} / {t('pages:systemTables.page')}</option>
          ))}
        </select>

        <label className="flex items-center gap-2 text-sm text-slate-300">
          <input
            type="checkbox"
            checked={autoRefresh}
            onChange={(e) => setAutoRefresh(e.target.checked)}
            className="rounded"
          />
          {t('pages:systemTables.autoRefresh')}
        </label>

        <div className="flex-1" />

        <button
          onClick={fetchEntries}
          className="btn-secondary text-sm flex items-center gap-1"
          disabled={loading}
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
          {t('common:actions.refresh')}
        </button>

        <button
          onClick={handleClearAll}
          className="btn-secondary text-sm flex items-center gap-1 text-red-400 hover:text-red-300"
          disabled={clearingAll || (detail?.total ?? 0) === 0}
        >
          <Trash2 className="w-3.5 h-3.5" />
          {t('pages:systemTables.clearAll')}
        </button>
      </div>

      {/* Entries table */}
      {loading ? (
        <p>{t('common:actions.loading')}</p>
      ) : !detail || detail.entries.length === 0 ? (
        <p className="text-slate-400">{t('pages:systemTables.noEntries')}</p>
      ) : (
        <div className="overflow-x-auto border border-slate-800 rounded-lg">
          <table className="w-full text-xs text-start">
            <thead className="text-slate-400 bg-slate-900/60 border-b border-slate-800">
              <tr>
                <th className="px-2 py-1.5 text-start">{t('pages:systemTables.key')}</th>
                <th className="px-2 py-1.5 text-end">{t('pages:systemTables.use')}</th>
                <th className="px-2 py-1.5 text-end">{t('pages:systemTables.exp')}</th>
                <th className="px-2 py-1.5 text-end">{t('pages:systemTables.expiresAt')}</th>
                {storeKeys.map((k) => (
                  <th key={k} className="px-2 py-1.5 text-end font-mono">{k}</th>
                ))}
                <th className="px-2 py-1.5 text-end">{t('pages:systemTables.actions')}</th>
              </tr>
            </thead>
            <tbody>
              {detail.entries.map((e) => (
                <tr key={e.key} className="border-b border-slate-800 last:border-0 hover:bg-slate-800/30">
                  <td className="px-2 py-1.5 font-mono text-slate-200 break-all">{e.key}</td>
                  <td className="px-2 py-1.5 text-end font-mono text-slate-300">{String(e.use)}</td>
                  <td className="px-2 py-1.5 text-end font-mono text-slate-300">{String(e.exp)}</td>
                  <td className="px-2 py-1.5 text-end text-slate-300">{formatExpireTime(e.exp, formatTime)}</td>
                  {storeKeys.map((k) => (
                    <td key={k} className="px-2 py-1.5 text-end font-mono text-slate-300">{e.stores[k] ?? '-'}</td>
                  ))}
                  <td className="px-2 py-1.5 text-end">
                    <IconButton icon={Trash2} variant="danger" aria-label={t('pages:systemTables.clearEntry')} onClick={() => handleClearEntry(e.key)} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Pagination */}
      {detail && (
        <div className="flex items-center justify-between text-sm">
          <span className="text-slate-400">
            {t('pages:systemTables.showing', { from: detail.total === 0 ? 0 : offset + 1, to: Math.min(offset + pageSize, detail.total), total: detail.total })}
          </span>
          <div className="flex items-center gap-2">
            <button
              onClick={() => setPage((p) => Math.max(0, p - 1))}
              disabled={page === 0}
              className="btn-secondary text-sm disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {t('common:actions.previous')}
            </button>
            <span className="text-slate-300">
              {t('pages:systemTables.pageOf', { page: page + 1, total: totalPages })}
            </span>
            <button
              onClick={() => setPage((p) => Math.min(totalPages - 1, p + 1))}
              disabled={page >= totalPages - 1}
              className="btn-secondary text-sm disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {t('common:actions.next')}
            </button>
          </div>
        </div>
      )}
    </div>
  )
}
