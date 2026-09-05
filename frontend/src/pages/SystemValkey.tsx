import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Database as DatabaseIcon, Trash2, ChevronRight, ChevronDown, RefreshCw, Search, X } from 'lucide-react'
import { valkey, getErrorDetail } from '../services/api'
import { useNotifications } from '../contexts/NotificationContext'
import { useDateTime } from '../contexts/DateTimeContext'
import { Badge, IconButton } from '../components/ui'

interface ValkeyServerInfo {
  available: boolean
  version?: string | null
  uptime_seconds: number
  connected_clients: number
  used_memory_human: string
  used_memory_peak_human: string
  total_keys: number
  db_count: number
  role: string
  error?: string | null
}

interface ValkeyNamespaceSummary {
  prefix: string
  count: number
  sample_keys: string[]
}

interface ValkeyKeyEntry {
  key: string
  type: string
  ttl: number
  size: number | null
  preview: string
}

interface ValkeyNamespaceDetail {
  prefix: string
  total: number
  offset: number
  limit: number
  keys: ValkeyKeyEntry[]
}

const PAGE_SIZES = [50, 100, 200, 500]
const AUTO_REFRESH_MS = 5000

/** Humanize a byte count from `MEMORY USAGE`. */
function formatBytes(n: number | null | undefined): string {
  if (n == null) return '-'
  if (n < 1024) return `${n} B`
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`
  if (n < 1024 * 1024 * 1024) return `${(n / (1024 * 1024)).toFixed(1)} MB`
  return `${(n / (1024 * 1024 * 1024)).toFixed(2)} GB`
}

/** Format a Valkey TTL (seconds). -1 = persistent, -2 = missing. */
function formatTtl(ttl: number): string {
  if (ttl === -1) return '\u221e' // ∞ — no expiry
  if (ttl === -2) return '-'
  if (ttl < 60) return `${ttl}s`
  if (ttl < 3600) return `${Math.floor(ttl / 60)}m ${ttl % 60}s`
  if (ttl < 86400) return `${Math.floor(ttl / 3600)}h ${Math.floor((ttl % 3600) / 60)}m`
  return `${Math.floor(ttl / 86400)}d ${Math.floor((ttl % 86400) / 3600)}h`
}

/** Format the wall-clock expiry time from a TTL (seconds) using the user's prefs. */
function formatExpiresAt(
  ttl: number,
  formatTime: (iso: string | number | Date) => string,
): string {
  if (ttl <= 0) return '-' // -1 (persistent) or -2 (missing)
  const expiresAt = Date.now() + ttl * 1000
  return formatTime(expiresAt)
}

/** Format uptime seconds as "1d 03h 14m". */
function formatUptime(seconds: number): string {
  if (!seconds) return '-'
  const d = Math.floor(seconds / 86400)
  const h = Math.floor((seconds % 86400) / 3600)
  const m = Math.floor((seconds % 3600) / 60)
  if (d > 0) return `${d}d ${String(h).padStart(2, '0')}h ${String(m).padStart(2, '0')}m`
  if (h > 0) return `${h}h ${String(m).padStart(2, '0')}m`
  return `${m}m`
}

const TYPE_BADGE_VARIANT: Record<string, 'default' | 'success' | 'warning' | 'error' | 'info'> = {
  string: 'info',
  list: 'success',
  hash: 'success',
  set: 'warning',
  zset: 'warning',
  stream: 'default',
  none: 'error',
}

export default function SystemValkey() {
  const { t } = useTranslation(['pages', 'common'])
  const { addNotification } = useNotifications()

  const [info, setInfo] = useState<ValkeyServerInfo | null>(null)
  const [namespaces, setNamespaces] = useState<ValkeyNamespaceSummary[]>([])
  const [loading, setLoading] = useState(true)
  const [expanded, setExpanded] = useState<string | null>(null)

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const [infoRes, nsRes] = await Promise.all([valkey.info(), valkey.namespaces()])
      setInfo(infoRes.data)
      setNamespaces(nsRes.data)
    } catch (err) {
      addNotification({
        type: 'error',
        title: t('pages:systemValkey.title'),
        message: getErrorDetail(err, t('common:errors.loadFailed')),
      })
    } finally {
      setLoading(false)
    }
  }, [addNotification, t])

  useEffect(() => {
    load()
  }, [load])

  const toggleExpand = (prefix: string) => {
    setExpanded((prev) => (prev === prefix ? null : prefix))
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h2 className="text-lg font-semibold flex items-center gap-2">
          <DatabaseIcon className="h-5 w-5 text-primary" /> {t('pages:systemValkey.title')}
        </h2>
        <button onClick={load} className="btn-secondary text-sm" disabled={loading}>
          {loading ? t('common:actions.loading') : t('common:actions.refresh')}
        </button>
      </div>

      <p className="text-sm text-slate-400">{t('pages:systemValkey.description')}</p>

      {/* Server info card */}
      <ServerInfoCard info={info} loading={loading} />

      {/* Namespaces */}
      {loading ? (
        <p>{t('common:actions.loading')}</p>
      ) : !info || !info.available ? (
        <p className="text-slate-400">{t('pages:systemValkey.unavailable')}</p>
      ) : namespaces.length === 0 ? (
        <p className="text-slate-400">{t('pages:systemValkey.noNamespaces')}</p>
      ) : (
        <div className="card overflow-x-auto">
          <table className="w-full text-sm text-start">
            <thead className="text-slate-400 border-b border-slate-800">
              <tr>
                <th className="pb-2 w-8"></th>
                <th className="pb-2">{t('pages:systemValkey.namespace')}</th>
                <th className="pb-2 text-end">{t('pages:systemValkey.keys')}</th>
                <th className="pb-2">{t('pages:systemValkey.sample')}</th>
              </tr>
            </thead>
            <tbody>
              {namespaces.map((ns) => (
                <NamespaceRow
                  key={ns.prefix}
                  ns={ns}
                  expanded={expanded === ns.prefix}
                  onToggle={() => toggleExpand(ns.prefix)}
                />
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}

function ServerInfoCard({ info, loading }: { info: ValkeyServerInfo | null; loading: boolean }) {
  const { t } = useTranslation(['pages'])

  if (loading && !info) {
    return <div className="card p-4 text-sm text-slate-400">{t('pages:common.loading', { defaultValue: 'Loading\u2026' })}</div>
  }
  if (!info) return null

  if (!info.available) {
    return (
      <div className="card p-4 border border-amber-800/50 bg-amber-900/10">
        <p className="text-sm text-amber-300">
          {t('pages:systemValkey.unavailable')}
          {info.error ? `: ${info.error}` : ''}
        </p>
      </div>
    )
  }

  const stats: Array<{ label: string; value: string }> = [
    { label: t('pages:systemValkey.version'), value: info.version || '-' },
    { label: t('pages:systemValkey.role'), value: info.role || '-' },
    { label: t('pages:systemValkey.uptime'), value: formatUptime(info.uptime_seconds) },
    { label: t('pages:systemValkey.connectedClients'), value: info.connected_clients.toLocaleString() },
    { label: t('pages:systemValkey.usedMemory'), value: info.used_memory_human || '-' },
    { label: t('pages:systemValkey.peakMemory'), value: info.used_memory_peak_human || '-' },
    { label: t('pages:systemValkey.totalKeys'), value: info.total_keys.toLocaleString() },
    { label: t('pages:systemValkey.databases'), value: info.db_count.toLocaleString() },
  ]

  return (
    <div className="card p-4">
      <h3 className="text-sm font-semibold text-slate-200 mb-3">{t('pages:systemValkey.serverInfo')}</h3>
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        {stats.map((s) => (
          <div key={s.label} className="space-y-0.5">
            <div className="text-xs text-slate-400">{s.label}</div>
            <div className="text-sm font-mono text-slate-200 break-all">{s.value}</div>
          </div>
        ))}
      </div>
    </div>
  )
}

function NamespaceRow({
  ns,
  expanded,
  onToggle,
}: {
  ns: ValkeyNamespaceSummary
  expanded: boolean
  onToggle: () => void
}) {
  const { t } = useTranslation(['pages', 'common'])
  return (
    <>
      <tr className="border-b border-slate-800 last:border-0 hover:bg-slate-800/30">
        <td className="py-2">
          <button
            onClick={onToggle}
            className="text-slate-400 hover:text-slate-200"
            aria-label={expanded ? t('common:actions.collapse') : t('common:actions.expand')}
          >
            {expanded ? <ChevronDown className="w-4 h-4" /> : <ChevronRight className="w-4 h-4" />}
          </button>
        </td>
        <td className="py-2 font-mono">{ns.prefix}</td>
        <td className="text-end font-mono">
          <span className="px-2 py-0.5 rounded-full bg-slate-800 text-xs">{ns.count.toLocaleString()}</span>
        </td>
        <td className="py-2 font-mono text-xs text-slate-400 break-all max-w-md">
          {ns.sample_keys.join(', ') || '-'}
        </td>
      </tr>
      {expanded && (
        <tr className="border-b border-slate-800">
          <td colSpan={4} className="p-4 bg-slate-900/40">
            <NamespaceEntries prefix={ns.prefix} />
          </td>
        </tr>
      )}
    </>
  )
}

function NamespaceEntries({ prefix }: { prefix: string }) {
  const { t } = useTranslation(['pages', 'common'])
  const { addNotification } = useNotifications()
  const { formatTime } = useDateTime()

  const [detail, setDetail] = useState<ValkeyNamespaceDetail | null>(null)
  const [loading, setLoading] = useState(true)
  const [page, setPage] = useState(0)
  const [pageSize, setPageSize] = useState(100)
  const [search, setSearch] = useState('')
  const [searchInput, setSearchInput] = useState('')
  const [autoRefresh, setAutoRefresh] = useState(false)
  const searchTimer = useRef<ReturnType<typeof setTimeout> | null>(null)

  const offset = page * pageSize

  const fetchEntries = useCallback(async () => {
    setLoading(true)
    try {
      const r = await valkey.namespace(prefix, { limit: pageSize, offset, search: search || undefined })
      setDetail(r.data)
    } catch (err) {
      addNotification({ type: 'error', title: prefix, message: getErrorDetail(err, t('common:errors.loadFailed')) })
    } finally {
      setLoading(false)
    }
  }, [prefix, pageSize, offset, search, addNotification, t])

  useEffect(() => {
    fetchEntries()
  }, [fetchEntries])

  // Auto-refresh
  useEffect(() => {
    if (!autoRefresh) return
    const id = setInterval(() => {
      valkey
        .namespace(prefix, { limit: pageSize, offset, search: search || undefined })
        .then((r) => setDetail(r.data))
        .catch(() => {})
    }, AUTO_REFRESH_MS)
    return () => clearInterval(id)
  }, [autoRefresh, prefix, pageSize, offset, search])

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

  const handleDeleteKey = async (key: string) => {
    if (!window.confirm(t('pages:systemValkey.confirmDeleteKey', { key }))) return
    try {
      await valkey.deleteKey(key)
      addNotification({ type: 'success', title: prefix, message: t('pages:systemValkey.keyDeleted') })
      fetchEntries()
    } catch (err) {
      addNotification({ type: 'error', title: prefix, message: getErrorDetail(err, t('pages:systemValkey.deleteFailed')) })
    }
  }

  const previewKeys = useMemo(() => detail?.keys ?? [], [detail])

  return (
    <div className="space-y-3">
      {/* Toolbar */}
      <div className="flex flex-wrap items-center gap-3">
        <div className="relative">
          <Search className="absolute start-2 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500 pointer-events-none" />
          <input
            type="text"
            placeholder={t('pages:systemValkey.searchPlaceholder')}
            value={searchInput}
            onChange={(e) => onSearchChange(e.target.value)}
            className="input !ps-8 !pe-8 w-64"
          />
          {searchInput && (
            <button
              onClick={() => { setSearchInput(''); setPage(0); setSearch('') }}
              className="absolute end-2 top-1/2 -translate-y-1/2 text-slate-500 hover:text-slate-300"
              aria-label={t('pages:systemValkey.clearSearch')}
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
            <option key={s} value={s}>{s} / {t('pages:systemValkey.page')}</option>
          ))}
        </select>

        <label className="flex items-center gap-2 text-sm text-slate-300">
          <input
            type="checkbox"
            checked={autoRefresh}
            onChange={(e) => setAutoRefresh(e.target.checked)}
            className="rounded"
          />
          {t('pages:systemValkey.autoRefresh')}
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
      </div>

      {/* Keys table */}
      {loading ? (
        <p>{t('common:actions.loading')}</p>
      ) : !detail || detail.keys.length === 0 ? (
        <p className="text-slate-400">{t('pages:systemValkey.noKeys')}</p>
      ) : (
        <div className="overflow-x-auto border border-slate-800 rounded-lg">
          <table className="w-full text-xs text-start">
            <thead className="text-slate-400 bg-slate-900/60 border-b border-slate-800">
              <tr>
                <th className="px-2 py-1.5 text-start">{t('pages:systemValkey.key')}</th>
                <th className="px-2 py-1.5 text-start">{t('pages:systemValkey.type')}</th>
                <th className="px-2 py-1.5 text-end">{t('pages:systemValkey.ttl')}</th>
                <th className="px-2 py-1.5 text-end">{t('pages:systemValkey.expiresAt')}</th>
                <th className="px-2 py-1.5 text-end">{t('pages:systemValkey.size')}</th>
                <th className="px-2 py-1.5 text-start">{t('pages:systemValkey.preview')}</th>
                <th className="px-2 py-1.5 text-end">{t('pages:systemValkey.actions')}</th>
              </tr>
            </thead>
            <tbody>
              {previewKeys.map((e) => (
                <tr key={e.key} className="border-b border-slate-800 last:border-0 hover:bg-slate-800/30">
                  <td className="px-2 py-1.5 font-mono text-slate-200 break-all">{e.key}</td>
                  <td className="px-2 py-1.5">
                    <Badge variant={TYPE_BADGE_VARIANT[e.type] || 'default'} size="sm">{e.type}</Badge>
                  </td>
                  <td className="px-2 py-1.5 text-end font-mono text-slate-300">{formatTtl(e.ttl)}</td>
                  <td className="px-2 py-1.5 text-end text-slate-300">{formatExpiresAt(e.ttl, formatTime)}</td>
                  <td className="px-2 py-1.5 text-end font-mono text-slate-300">{formatBytes(e.size)}</td>
                  <td className="px-2 py-1.5 font-mono text-slate-300 break-all max-w-md">{e.preview || '-'}</td>
                  <td className="px-2 py-1.5 text-end">
                    <IconButton
                      icon={Trash2}
                      variant="danger"
                      aria-label={t('pages:systemValkey.deleteKey')}
                      onClick={() => handleDeleteKey(e.key)}
                    />
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
            {t('pages:systemValkey.showing', {
              from: detail.total === 0 ? 0 : offset + 1,
              to: Math.min(offset + pageSize, detail.total),
              total: detail.total,
            })}
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
              {t('pages:systemValkey.pageOf', { page: page + 1, total: totalPages })}
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
