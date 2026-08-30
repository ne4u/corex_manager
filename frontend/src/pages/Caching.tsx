import { useEffect, useState, useCallback } from 'react'
import { useTranslation } from 'react-i18next'
import LabelWithTooltip from '../components/LabelWithTooltip'
import InfoTooltip from '../components/InfoTooltip'
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  Tooltip,
  Legend,
  ResponsiveContainer,
  CartesianGrid,
  AreaChart,
  Area,
} from 'recharts'
import { Database, Trash2, Settings, HardDrive, X, AlertTriangle, GripVertical, Plus, Pencil } from 'lucide-react'
import { cache, backends, getErrorDetail } from '../services/api'
import { useDateTime } from '../contexts/DateTimeContext'

interface CacheConfig {
  id: number
  backend_id: number
  backend_name: string
  haproxy_enabled: boolean
  haproxy_total_max_size: number
  haproxy_max_object_size: number
  haproxy_max_age: number
  haproxy_process_vary: boolean
  haproxy_max_secondary_entries: number
  haproxy_cache_condition: string | null
  haproxy_rfc7234_compliance: boolean
  disk_cache_enabled: boolean
  disk_cache_ttl: number
  disk_cache_grace: number
  disk_cache_purge_enabled: boolean
  rule_count: number
  created_at: string
  updated_at: string
}

type MatchType = 'path' | 'filename' | 'extension' | 'method' | 'query_string' | 'content_type' | 'status_code'
type RuleAction = 'cache' | 'bypass'
type CacheTier = 'memory' | 'disk'

interface CacheRule {
  id: number
  cache_config_id: number
  priority: number
  enabled: boolean
  match_type: MatchType
  pattern: string
  action: RuleAction
  tier: CacheTier
}

const MATCH_TYPE_HINTS: Record<MatchType, string> = {
  path: 'e.g. /downloads/  — matches any URL starting with this path',
  filename: 'e.g. linux.iso  — matches this exact file name',
  extension: 'e.g. png  — matches any file with this extension (case-insensitive)',
  method: 'e.g. GET, POST, PUT  — matches HTTP method (request phase)',
  query_string: 'e.g. nocache, format=json, *  — matches query parameter (request phase)',
  content_type: 'e.g. application/json, image/*  — matches response Content-Type header (response phase)',
  status_code: 'e.g. 200, 404, 2xx, 200,301,404  — matches HTTP status code (response phase)',
}

const MATCH_TYPE_PHASES: Record<MatchType, 'request' | 'response'> = {
  path: 'request',
  filename: 'request',
  extension: 'request',
  method: 'request',
  query_string: 'request',
  content_type: 'response',
  status_code: 'response',
}


interface Backend {
  id: number
  name: string
  protocol: string
  mode: string
}

interface CacheStatus {
  disk_cache_globally_enabled: boolean
}

interface MetricSnapshot {
  timestamp: string
  haproxy_cache_hit: number
  haproxy_cache_miss: number
  disk_cache_hit: number
  disk_cache_miss: number
  disk_cache_objects: number
  haproxy_hit_rate: number
  disk_hit_rate: number
}

interface MetricsResponse {
  snapshots: MetricSnapshot[]
  summary: {
    haproxy_hit_rate: number
    disk_hit_rate: number
    total_haproxy_hits: number
    total_haproxy_miss: number
    total_disk_hits: number
    total_disk_miss: number
  }
}

const RANGES = [
  { label: '1h', seconds: 3600 },
  { label: '6h', seconds: 21600 },
  { label: '24h', seconds: 86400 },
  { label: '7d', seconds: 604800 },
]

export default function Caching() {
  const { t } = useTranslation(['pages', 'common'])
  const { formatTimeCompact } = useDateTime()
  const [configs, setConfigs] = useState<CacheConfig[]>([])
  const [allBackends, setAllBackends] = useState<Backend[]>([])
  const [status, setStatus] = useState<CacheStatus>({ disk_cache_globally_enabled: false })
  const [loading, setLoading] = useState(true)
  const [message, setMessage] = useState('')
  const [editing, setEditing] = useState<CacheConfig | null>(null)
  const [editingRules, setEditingRules] = useState<CacheConfig | null>(null)
  const [creating, setCreating] = useState(false)
  const [metricsData, setMetricsData] = useState<MetricsResponse | null>(null)
  const [range, setRange] = useState(3600)
  const [metricsLoading, setMetricsLoading] = useState(false)

  const loadData = useCallback(async () => {
    setLoading(true)
    try {
      const [cfgRes, beRes, statRes] = await Promise.all([
        cache.listConfigs(),
        backends.list(),
        cache.status(),
      ])
      setConfigs(cfgRes.data)
      setAllBackends(beRes.data)
      setStatus(statRes.data)
    } catch (err: any) {
      setMessage(getErrorDetail(err, t('pages:caching.failedToLoadCacheData')))
    } finally {
      setLoading(false)
    }
  }, [])

  const loadMetrics = useCallback(async () => {
    setMetricsLoading(true)
    try {
      const now = Date.now()
      const from = new Date(now - range * 1000).toISOString()
      const to = new Date(now).toISOString()
      const res = await cache.metrics({ from, to })
      setMetricsData(res.data)
    } catch {
      // metrics are optional
    } finally {
      setMetricsLoading(false)
    }
  }, [range])

  useEffect(() => { loadData() }, [loadData])
  useEffect(() => { loadMetrics() }, [loadMetrics])

  const handleClear = async (backendId: number, name: string) => {
    if (!confirm(t('pages:caching.confirmClear', { name }))) return
    try {
      const res = await cache.clearBackend(backendId)
      const d = res.data
      alert(d.message || t('pages:caching.cacheCleared', { memory: d.memory_cleared, disk: d.disk_cleared }))
    } catch (err: any) {
      alert(getErrorDetail(err, t('pages:caching.failedToClearCache')))
    }
  }

  const handleClearAll = async () => {
    if (!confirm(t('pages:caching.confirmClearAll'))) return
    try {
      const res = await cache.clearAll()
      const d = res.data
      alert(d.message || t('pages:caching.allCachesCleared', { memory: d.memory_cleared, disk: d.disk_cleared }))
    } catch (err: any) {
      alert(getErrorDetail(err, t('pages:caching.failedToClearAllCaches')))
    }
  }

  const handleDelete = async (backendId: number, name: string) => {
    if (!confirm(t('pages:caching.confirmDelete', { name }))) return
    try {
      await cache.removeConfig(backendId)
      setMessage(t('pages:caching.cacheConfigDeleted'))
      loadData()
    } catch (err: any) {
      setMessage(getErrorDetail(err, t('pages:caching.failedToDeleteCacheConfig')))
    }
  }

  const backendsWithCache = new Set(configs.map(c => c.backend_id))
  const backendsWithoutCache = allBackends.filter(b => !backendsWithCache.has(b.id) && b.protocol !== 'tcp')

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold flex items-center gap-2">
        <Database className="h-5 w-5 text-primary" /> {t('pages:caching.title')}
      </h1>

      {message && (
        <div className="card p-3 text-sm text-amber-400">{message}</div>
      )}

      {/* Cache Configuration Table */}
      <div className="card space-y-4">
        <div className="flex items-center justify-between">
          <h2 className="text-lg font-semibold">{t('pages:caching.cacheConfiguration')}</h2>
          <div className="flex gap-2">
            <button
              className="btn-secondary"
              onClick={handleClearAll}
              disabled={configs.length === 0}
            >
              <Trash2 className="h-4 w-4 me-1" /> {t('pages:caching.clearAllCaches')}
            </button>
            <button
              className="btn-primary"
              onClick={() => setCreating(true)}
              disabled={backendsWithoutCache.length === 0}
            >
              <Settings className="h-4 w-4 me-1" /> {t('pages:caching.addCacheConfig')}
            </button>
          </div>
        </div>

        {loading ? (
          <p className="text-sm text-slate-400">{t('pages:caching.loading')}</p>
        ) : configs.length === 0 ? (
          <p className="text-sm text-slate-400">{t('pages:caching.noCacheConfigs')}</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-start text-slate-400 border-b border-slate-700">
                  <th className="py-2 pe-4">{t('pages:caching.tableHeaders.backend')}</th>
                  <th className="py-2 pe-4">{t('pages:caching.tableHeaders.memoryCache')}</th>
                  <th className="py-2 pe-4">{t('pages:caching.tableHeaders.diskCache')}</th>
                  <th className="py-2 pe-4">{t('pages:caching.tableHeaders.rules')}</th>
                  <th className="py-2 pe-4">{t('pages:caching.tableHeaders.details')}</th>
                  <th className="py-2 pe-4">{t('pages:caching.tableHeaders.actions')}</th>
                </tr>
              </thead>
              <tbody>
                {configs.map((cc) => (
                  <tr key={cc.id} className="border-b border-slate-800">
                    <td className="py-2 pe-4 font-medium">{cc.backend_name}</td>
                    <td className="py-2 pe-4">
                      {cc.haproxy_enabled ? (
                        <span className="badge badge-blue">{t('pages:caching.enabled')}</span>
                      ) : (
                        <span className="text-slate-500">-</span>
                      )}
                    </td>
                    <td className="py-2 pe-4">
                      {cc.disk_cache_enabled ? (
                        <span className="badge badge-green">{t('pages:caching.enabled')}</span>
                      ) : (
                        <span className="text-slate-500">-</span>
                      )}
                    </td>
                    <td className="py-2 pe-4">
                      {(cc.haproxy_enabled || cc.disk_cache_enabled) && cc.rule_count === 0 ? (
                        <span
                          className="inline-flex items-center gap-1 text-amber-400 text-xs"
                          title={t('pages:caching.rulesWarning')}
                        >
                          <AlertTriangle size={13} /> {t('pages:caching.noRules')}
                        </span>
                      ) : (
                        <span className="text-xs text-slate-400">
                          {t('pages:caching.ruleCount', { count: cc.rule_count })}
                        </span>
                      )}
                    </td>
                    <td className="py-2 pe-4 text-xs text-slate-400">
                      {cc.haproxy_enabled && <span>{t('pages:caching.memoryDetails', { size: cc.haproxy_total_max_size, age: cc.haproxy_max_age })}</span>}
                      {cc.haproxy_enabled && cc.disk_cache_enabled && <br />}
                      {cc.disk_cache_enabled && <span>{t('pages:caching.diskDetails', { ttl: cc.disk_cache_ttl, grace: cc.disk_cache_grace })}</span>}
                    </td>
                    <td className="py-2 pe-4">
                      <div className="flex gap-1">
                        <button
                          className="btn-secondary text-xs px-2 py-1"
                          onClick={() => setEditing(cc)}
                        >
                          {t('pages:caching.actions.edit')}
                        </button>
                        <button
                          className="btn-secondary text-xs px-2 py-1"
                          onClick={() => setEditingRules(cc)}
                        >
                          {t('pages:caching.actions.rules')}
                        </button>
                        <button
                          className="btn-secondary text-xs px-2 py-1"
                          onClick={() => handleClear(cc.backend_id, cc.backend_name)}
                        >
                          {t('pages:caching.actions.clear')}
                        </button>
                        <button
                          className="btn-secondary text-xs px-2 py-1 text-red-400"
                          onClick={() => handleDelete(cc.backend_id, cc.backend_name)}
                        >
                          {t('pages:caching.actions.remove')}
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Cache Metrics Charts */}
      <div className="card space-y-4">
        <div className="flex items-center justify-between">
          <h2 className="text-lg font-semibold">{t('pages:caching.cacheMetrics')}</h2>
          <div className="flex gap-1">
            {RANGES.map(r => (
              <button
                key={r.label}
                className={`btn-secondary text-xs px-2 py-1 ${range === r.seconds ? 'bg-primary text-white' : ''}`}
                onClick={() => setRange(r.seconds)}
              >
                {r.label}
              </button>
            ))}
          </div>
        </div>

        {metricsLoading ? (
          <p className="text-sm text-slate-400">{t('pages:caching.loadingMetrics')}</p>
        ) : !metricsData || metricsData.snapshots.length === 0 ? (
          <p className="text-sm text-slate-400">{t('pages:caching.noCacheMetrics')}</p>
        ) : (
          <div className="space-y-6">
            {/* Summary cards — counts are deltas within the selected range, not cumulative since startup */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              <div className="card p-3">
                <p className="text-xs text-slate-400">{t('pages:caching.memoryHitRate')}</p>
                <p className="text-xl font-bold text-blue-400">{metricsData.summary.haproxy_hit_rate.toFixed(1)}%</p>
              </div>
              <div className="card p-3">
                <p className="text-xs text-slate-400">{t('pages:caching.diskHitRate')}</p>
                <p className="text-xl font-bold text-green-400">{metricsData.summary.disk_hit_rate.toFixed(1)}%</p>
              </div>
              <div className="card p-3">
                <p className="text-xs text-slate-400">{t('pages:caching.memoryHits')}</p>
                <p className="text-xl font-bold">{metricsData.summary.total_haproxy_hits.toLocaleString()}</p>
              </div>
              <div className="card p-3">
                <p className="text-xs text-slate-400">{t('pages:caching.diskHits')}</p>
                <p className="text-xl font-bold">{metricsData.summary.total_disk_hits.toLocaleString()}</p>
              </div>
            </div>

            {/* Hit-rate-over-time chart — the primary cache health indicator */}
            <div>
              <h3 className="text-sm font-semibold mb-2">{t('pages:caching.cacheHitRateOverTime')}</h3>
              <ResponsiveContainer width="100%" height={250}>
                <LineChart data={metricsData.snapshots}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                  <XAxis dataKey="timestamp" tickFormatter={formatTimeCompact} stroke="#64748b" fontSize={11} />
                  <YAxis stroke="#64748b" fontSize={11} domain={[0, 100]} unit="%" />
                  <Tooltip labelFormatter={formatTimeCompact} formatter={(v: number) => `${v.toFixed(1)}%`} />
                  <Legend />
                  <Line type="monotone" dataKey="haproxy_hit_rate" name="Memory Hit Rate" stroke="#3b82f6" dot={false} strokeWidth={2} />
                  <Line type="monotone" dataKey="disk_hit_rate" name="Disk Hit Rate" stroke="#22c55e" dot={false} strokeWidth={2} />
                </LineChart>
              </ResponsiveContainer>
            </div>

            {/* Hits chart — hits that occurred during each interval */}
            <div>
              <h3 className="text-sm font-semibold mb-2">{t('pages:caching.cacheHitsOverTime')}</h3>
              <ResponsiveContainer width="100%" height={250}>
                <AreaChart data={metricsData.snapshots}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                  <XAxis dataKey="timestamp" tickFormatter={formatTimeCompact} stroke="#64748b" fontSize={11} />
                  <YAxis stroke="#64748b" fontSize={11} />
                  <Tooltip labelFormatter={formatTimeCompact} />
                  <Legend />
                  <Area type="monotone" dataKey="haproxy_cache_hit" name="Memory Hits" stroke="#3b82f6" fill="#3b82f6" fillOpacity={0.3} />
                  <Area type="monotone" dataKey="disk_cache_hit" name="Disk Hits" stroke="#22c55e" fill="#22c55e" fillOpacity={0.3} />
                </AreaChart>
              </ResponsiveContainer>
            </div>

            {/* Miss chart — misses that occurred during each interval */}
            <div>
              <h3 className="text-sm font-semibold mb-2">{t('pages:caching.cacheMissesOverTime')}</h3>
              <ResponsiveContainer width="100%" height={200}>
                <LineChart data={metricsData.snapshots}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                  <XAxis dataKey="timestamp" tickFormatter={formatTimeCompact} stroke="#64748b" fontSize={11} />
                  <YAxis stroke="#64748b" fontSize={11} />
                  <Tooltip labelFormatter={formatTimeCompact} />
                  <Legend />
                  <Line type="monotone" dataKey="haproxy_cache_miss" name="Memory Misses" stroke="#ef4444" dot={false} />
                  <Line type="monotone" dataKey="disk_cache_miss" name="Disk Misses" stroke="#f97316" dot={false} />
                </LineChart>
              </ResponsiveContainer>
            </div>

            {/* Disk objects chart */}
            {metricsData.snapshots.some(s => s.disk_cache_objects > 0) && (
              <div>
                <h3 className="text-sm font-semibold mb-2">{t('pages:caching.diskCacheObjects')}</h3>
                <ResponsiveContainer width="100%" height={150}>
                  <LineChart data={metricsData.snapshots}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                    <XAxis dataKey="timestamp" tickFormatter={formatTimeCompact} stroke="#64748b" fontSize={11} />
                    <YAxis stroke="#64748b" fontSize={11} />
                    <Tooltip labelFormatter={formatTimeCompact} />
                    <Line type="monotone" dataKey="disk_cache_objects" name="Objects" stroke="#22c55e" dot={false} />
                  </LineChart>
                </ResponsiveContainer>
              </div>
            )}
          </div>
        )}
      </div>

      {/* Disk Cache Status Panel (only if globally enabled) */}
      {status.disk_cache_globally_enabled && (
        <div className="card space-y-4">
          <h2 className="text-lg font-semibold flex items-center gap-2">
            <HardDrive className="h-5 w-5 text-primary" /> {t('pages:caching.diskCacheStatus')}
          </h2>
          <div className="grid grid-cols-2 md:grid-cols-3 gap-4">
            <div className="card p-3">
              <p className="text-xs text-slate-400">{t('common:table.status')}</p>
              <p className="text-sm font-semibold text-green-400">{t('pages:caching.diskCacheStatusAvailable')}</p>
            </div>
            <div className="card p-3">
              <p className="text-xs text-slate-400">{t('pages:caching.backendsUsingDiskCache')}</p>
              <p className="text-sm font-semibold">{configs.filter(c => c.disk_cache_enabled).length}</p>
            </div>
            <div className="card p-3">
              <p className="text-xs text-slate-400">{t('pages:caching.storage')}</p>
              <p className="text-sm font-semibold">{t('pages:caching.storageFileBacked')}</p>
            </div>
          </div>
        </div>
      )}

      {/* Edit/Create Modal */}
      {(editing || creating) && (
        <CacheConfigModal
          config={editing}
          backends={creating ? backendsWithoutCache : []}
          diskCacheGloballyEnabled={status.disk_cache_globally_enabled}
          onClose={() => { setEditing(null); setCreating(false) }}
          onSaved={() => { setEditing(null); setCreating(false); loadData() }}
        />
      )}

      {/* Cacheability Rules Modal */}
      {editingRules && (
        <CacheRulesModal
          config={editingRules}
          onClose={() => { setEditingRules(null); loadData() }}
        />
      )}
    </div>
  )
}

// ---------------------------------------------------------------------------
// Cache Config Modal
// ---------------------------------------------------------------------------

interface CacheConfigModalProps {
  config: CacheConfig | null
  backends: Backend[]
  diskCacheGloballyEnabled: boolean
  onClose: () => void
  onSaved: () => void
}

function CacheConfigModal({ config, backends, diskCacheGloballyEnabled, onClose, onSaved }: CacheConfigModalProps) {
  const { t } = useTranslation(['pages', 'common'])
  const isEdit = config !== null
  const [selectedBackendId, setSelectedBackendId] = useState<number>(config?.backend_id || (backends[0]?.id ?? 0))
  const [haproxyEnabled, setHaproxyEnabled] = useState(config?.haproxy_enabled ?? true)
  const [haproxyTotalMaxSize, setHaproxyTotalMaxSize] = useState(config?.haproxy_total_max_size ?? 100)
  const [haproxyMaxObjectSize, setHaproxyMaxObjectSize] = useState(config?.haproxy_max_object_size ?? 1000000)
  const [haproxyMaxAge, setHaproxyMaxAge] = useState(config?.haproxy_max_age ?? 300)
  const [haproxyProcessVary, setHaproxyProcessVary] = useState(config?.haproxy_process_vary ?? true)
  const [haproxyMaxSecondaryEntries, setHaproxyMaxSecondaryEntries] = useState(config?.haproxy_max_secondary_entries ?? 10)
  const [haproxyCacheCondition, setHaproxyCacheCondition] = useState(config?.haproxy_cache_condition ?? '')
  const [haproxyRfc7234Compliance, setHaproxyRfc7234Compliance] = useState(config?.haproxy_rfc7234_compliance ?? false)
  const [advancedOpen, setAdvancedOpen] = useState(!!config?.haproxy_cache_condition)
  const [diskCacheEnabled, setDiskCacheEnabled] = useState(config?.disk_cache_enabled ?? false)
  const [diskCacheTtl, setDiskCacheTtl] = useState(config?.disk_cache_ttl ?? 120)
  const [diskCacheGrace, setDiskCacheGrace] = useState(config?.disk_cache_grace ?? 600)
  const [diskCachePurgeEnabled, setDiskCachePurgeEnabled] = useState(config?.disk_cache_purge_enabled ?? true)
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState('')

  const handleSave = async () => {
    setSaving(true)
    setError('')
    try {
      const data = {
        backend_id: selectedBackendId,
        haproxy_enabled: haproxyEnabled,
        haproxy_total_max_size: Number(haproxyTotalMaxSize),
        haproxy_max_object_size: Number(haproxyMaxObjectSize),
        haproxy_max_age: Number(haproxyMaxAge),
        haproxy_process_vary: haproxyProcessVary,
        haproxy_max_secondary_entries: Number(haproxyMaxSecondaryEntries),
        haproxy_cache_condition: haproxyCacheCondition || null,
        haproxy_rfc7234_compliance: haproxyRfc7234Compliance,
        disk_cache_enabled: diskCacheEnabled,
        disk_cache_ttl: Number(diskCacheTtl),
        disk_cache_grace: Number(diskCacheGrace),
        disk_cache_purge_enabled: diskCachePurgeEnabled,
      }
      if (isEdit) {
        await cache.updateConfig(config!.backend_id, data)
      } else {
        await cache.createConfig(data)
      }
      onSaved()
    } catch (err: any) {
      setError(getErrorDetail(err, t('pages:caching.modal.failedToSave')))
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 p-4">
      <div className="card max-w-2xl w-full max-h-[90vh] overflow-y-auto space-y-4">
        <div className="flex items-center justify-between">
          <h2 className="text-lg font-semibold">
            {isEdit ? t('pages:caching.modal.editTitle', { name: config!.backend_name }) : t('pages:caching.modal.addTitle')}
          </h2>
          <button onClick={onClose} className="text-slate-400 hover:text-white">
            <X className="h-5 w-5" />
          </button>
        </div>

        {error && <div className="text-sm text-red-400">{error}</div>}

        {/* Backend selector (only for create) */}
        {!isEdit && (
          <div>
            <LabelWithTooltip tooltip={t('pages:caching.tooltips.backend')} textClassName="text-sm text-slate-400">{t('pages:caching.modal.backend')}</LabelWithTooltip>
            <select
              className="input w-full"
              value={selectedBackendId}
              onChange={(e) => setSelectedBackendId(Number(e.target.value))}
            >
              {backends.map(b => (
                <option key={b.id} value={b.id}>{b.name}</option>
              ))}
            </select>
          </div>
        )}

        {/* Memory Cache Section */}
        <div className="border border-slate-700 rounded p-4 space-y-3">
          <label className="flex items-center gap-2">
            <input
              type="checkbox"
              checked={haproxyEnabled}
              onChange={(e) => setHaproxyEnabled(e.target.checked)}
            />
            <span className="text-sm font-semibold">{t('pages:caching.modal.memory.title')}</span>
            <span className="text-xs text-slate-500">{t('pages:caching.modal.memory.subtitle')}</span>
            <InfoTooltip content={t('pages:caching.tooltips.memoryCache')} />
          </label>

          {haproxyEnabled && (
            <div className="grid grid-cols-2 gap-3">
              <div>
                <LabelWithTooltip tooltip={t('pages:caching.tooltips.totalMaxSize')} textClassName="text-xs text-slate-400">{t('pages:caching.modal.memory.totalMaxSize')}</LabelWithTooltip>
                <input
                  type="number"
                  className="input w-full"
                  min={1}
                  max={4095}
                  value={haproxyTotalMaxSize}
                  onChange={(e) => setHaproxyTotalMaxSize(Number(e.target.value))}
                />
              </div>
              <div>
                <LabelWithTooltip tooltip={t('pages:caching.tooltips.maxObjectSize')} textClassName="text-xs text-slate-400">{t('pages:caching.modal.memory.maxObjectSize')}</LabelWithTooltip>
                <input
                  type="number"
                  className="input w-full"
                  min={1}
                  value={haproxyMaxObjectSize}
                  onChange={(e) => setHaproxyMaxObjectSize(Number(e.target.value))}
                />
              </div>
              <div>
                <LabelWithTooltip tooltip={t('pages:caching.tooltips.maxAge')} textClassName="text-xs text-slate-400">{t('pages:caching.modal.memory.maxAge')}</LabelWithTooltip>
                <input
                  type="number"
                  className="input w-full"
                  min={1}
                  value={haproxyMaxAge}
                  onChange={(e) => setHaproxyMaxAge(Number(e.target.value))}
                />
              </div>
              <div>
                <LabelWithTooltip tooltip={t('pages:caching.tooltips.maxSecondaryEntries')} textClassName="text-xs text-slate-400">{t('pages:caching.modal.memory.maxSecondaryEntries')}</LabelWithTooltip>
                <input
                  type="number"
                  className="input w-full"
                  min={0}
                  value={haproxyMaxSecondaryEntries}
                  onChange={(e) => setHaproxyMaxSecondaryEntries(Number(e.target.value))}
                />
              </div>
              <div className="col-span-2">
                <label className="flex items-center gap-2">
                  <input
                    type="checkbox"
                    checked={haproxyProcessVary}
                    onChange={(e) => setHaproxyProcessVary(e.target.checked)}
                  />
                  <span className="text-xs">{t('pages:caching.modal.memory.processVary')}</span>
                  <InfoTooltip content={t('pages:caching.tooltips.processVary')} />
                </label>
              </div>
              <div className="col-span-2">
                <label className="flex items-center gap-2">
                  <input
                    type="checkbox"
                    checked={haproxyRfc7234Compliance}
                    onChange={(e) => setHaproxyRfc7234Compliance(e.target.checked)}
                  />
                  <span className="text-xs">{t('pages:caching.modal.memory.rfc7234Compliance')}</span>
                  <InfoTooltip content={t('pages:caching.tooltips.rfc7234Compliance')} />
                </label>
              </div>
            </div>
          )}
        </div>

        {/* Disk Cache Section */}
        <div className="border border-slate-700 rounded p-4 space-y-3">
          <label className="flex items-center gap-2">
            <input
              type="checkbox"
              checked={diskCacheEnabled}
              onChange={(e) => setDiskCacheEnabled(e.target.checked)}
              disabled={!diskCacheGloballyEnabled}
            />
            <span className="text-sm font-semibold">{t('pages:caching.modal.disk.title')}</span>
            <span className="text-xs text-slate-500">{t('pages:caching.modal.disk.subtitle')}</span>
            <InfoTooltip content={t('pages:caching.tooltips.diskCache')} />
          </label>

          {!diskCacheGloballyEnabled && (
            <p className="text-xs text-amber-400">
              {t('pages:caching.modal.disk.notEnabledWarning')}
            </p>
          )}

          {diskCacheEnabled && diskCacheGloballyEnabled && (
            <div className="grid grid-cols-2 gap-3">
              <div>
                <LabelWithTooltip tooltip={t('pages:caching.tooltips.ttl')} textClassName="text-xs text-slate-400">{t('pages:caching.modal.disk.ttl')}</LabelWithTooltip>
                <input
                  type="number"
                  className="input w-full"
                  min={1}
                  value={diskCacheTtl}
                  onChange={(e) => setDiskCacheTtl(Number(e.target.value))}
                />
              </div>
              <div>
                <LabelWithTooltip tooltip={t('pages:caching.tooltips.grace')} textClassName="text-xs text-slate-400">{t('pages:caching.modal.disk.grace')}</LabelWithTooltip>
                <input
                  type="number"
                  className="input w-full"
                  min={0}
                  value={diskCacheGrace}
                  onChange={(e) => setDiskCacheGrace(Number(e.target.value))}
                />
              </div>
              <div className="col-span-2">
                <label className="flex items-center gap-2">
                  <input
                    type="checkbox"
                    checked={diskCachePurgeEnabled}
                    onChange={(e) => setDiskCachePurgeEnabled(e.target.checked)}
                  />
                  <span className="text-xs">{t('pages:caching.modal.disk.purge')}</span>
                  <InfoTooltip content={t('pages:caching.tooltips.purge')} />
                </label>
              </div>
            </div>
          )}
        </div>

        {/* Advanced Options Section */}
        <div className="border border-slate-700 rounded p-4 space-y-3">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-sm font-semibold">{t('pages:caching.modal.advanced.title')}</h3>
              <p className="text-xs text-slate-500">
                {t('pages:caching.modal.advanced.description')}
              </p>
            </div>
            <button
              type="button"
              className="btn-secondary text-xs px-3 py-1"
              onClick={() => setAdvancedOpen(!advancedOpen)}
            >
              {advancedOpen ? t('pages:caching.modal.advanced.hide') : t('pages:caching.modal.advanced.show')}
            </button>
          </div>

          {advancedOpen && (
            <div className="space-y-2">
              <div>
                <LabelWithTooltip tooltip={t('pages:caching.tooltips.memoryCacheCondition')} textClassName="text-xs text-slate-400">{t('pages:caching.modal.advanced.memoryCacheCondition')}</LabelWithTooltip>
                <input
                  type="text"
                  className="input w-full"
                  placeholder={t('pages:caching.modal.advanced.memoryCacheConditionPlaceholder')}
                  value={haproxyCacheCondition}
                  onChange={(e) => setHaproxyCacheCondition(e.target.value)}
                />
              </div>
              <p className="text-xs text-slate-500">
                {t('pages:caching.modal.advanced.memoryCacheConditionHelp')}
              </p>
            </div>
          )}
        </div>

        <div className="flex justify-end gap-2">
          <button className="btn-secondary" onClick={onClose}>{t('common:actions.cancel')}</button>
          <button className="btn-primary" onClick={handleSave} disabled={saving}>
            {saving ? t('common:actions.saving') : t('common:actions.save')}
          </button>
        </div>
      </div>
    </div>
  )
}

// ---------------------------------------------------------------------------
// Cacheability Rules Modal
// ---------------------------------------------------------------------------

interface CacheRulesModalProps {
  config: CacheConfig
  onClose: () => void
}

function CacheRulesModal({ config, onClose }: CacheRulesModalProps) {
  const { t } = useTranslation(['pages', 'common'])
  const [rules, setRules] = useState<CacheRule[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const [matchType, setMatchType] = useState<MatchType>('extension')
  const [pattern, setPattern] = useState('')
  const [action, setAction] = useState<RuleAction>('cache')
  const [tier, setTier] = useState<CacheTier>('memory')
  const [editingRuleId, setEditingRuleId] = useState<number | null>(null)
  const [dragOverId, setDragOverId] = useState<number | null>(null)

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const r = await cache.listRules(config.backend_id)
      setRules(r.data)
      setError('')
    } catch (e) {
      setError(getErrorDetail(e))
    } finally {
      setLoading(false)
    }
  }, [config.backend_id])

  useEffect(() => { load() }, [load])

  async function withBusy(fn: () => Promise<unknown>) {
    setBusy(true)
    setError('')
    try {
      await fn()
      await load()
    } catch (e) {
      setError(getErrorDetail(e))
    } finally {
      setBusy(false)
    }
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    if (!pattern.trim()) return
    await withBusy(async () => {
      if (editingRuleId !== null) {
        await cache.updateRule(config.backend_id, editingRuleId, { match_type: matchType, pattern, action, tier })
      } else {
        await cache.createRule(config.backend_id, { match_type: matchType, pattern, action, tier })
      }
      resetForm()
    })
  }

  function startEdit(rule: CacheRule) {
    setEditingRuleId(rule.id)
    setMatchType(rule.match_type)
    setPattern(rule.pattern)
    setAction(rule.action)
    setTier(rule.tier)
  }

  function resetForm() {
    setEditingRuleId(null)
    setMatchType('extension')
    setPattern('')
    setAction('cache')
    setTier('memory')
  }

  const reorder = (draggedId: number, targetId: number) => {
    if (draggedId === targetId) return
    const from = rules.findIndex(r => r.id === draggedId)
    const to = rules.findIndex(r => r.id === targetId)
    if (from < 0 || to < 0) return
    const reordered = [...rules]
    const [moved] = reordered.splice(from, 1)
    const insertAt = from < to ? to - 1 : to
    reordered.splice(insertAt, 0, moved)
    // Optimistic reorder so the list does not jump while the request is in flight.
    setRules(reordered)
    withBusy(() => cache.reorderRules(config.backend_id, reordered.map(r => r.id)))
  }

  const enabledCount = rules.filter(r => r.enabled).length
  const cacheableCount = rules.filter(r => r.enabled && r.action === 'cache').length
  const tierEnabled = config.haproxy_enabled || config.disk_cache_enabled

  return (
    <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 p-4">
      <div className="card max-w-3xl w-full max-h-[90vh] overflow-y-auto space-y-4">
        <div className="flex items-center justify-between">
          <h2 className="text-lg font-semibold">{t('pages:caching.rules.title', { name: config.backend_name })}</h2>
          <button onClick={onClose} className="text-slate-400 hover:text-white">
            <X className="h-5 w-5" />
          </button>
        </div>

        <p className="text-xs text-slate-400">
          {t('pages:caching.rules.description')}
        </p>

        {tierEnabled && cacheableCount === 0 && !loading && (
          <div className="flex items-start gap-2 text-xs text-amber-400 border border-amber-500/40 bg-amber-500/10 rounded p-2">
            <AlertTriangle size={14} className="mt-0.5 shrink-0" />
            <span>
              {t('pages:caching.rules.noCacheableWarning')}
            </span>
          </div>
        )}

        {error && <div className="text-sm text-red-400">{error}</div>}

        {loading ? (
          <p className="text-sm text-slate-400">{t('pages:caching.rules.loading')}</p>
        ) : rules.length === 0 ? (
          <p className="text-sm text-slate-400">{t('pages:caching.rules.noRules')}</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-start text-slate-400 border-b border-slate-700">
                  <th className="py-2 pe-2 w-16">{t('pages:caching.rules.tableHeaders.order')}</th>
                  <th className="py-2 pe-4">{t('pages:caching.rules.tableHeaders.match')}</th>
                  <th className="py-2 pe-4">{t('pages:caching.rules.tableHeaders.phase')}</th>
                  <th className="py-2 pe-4">{t('pages:caching.rules.tableHeaders.pattern')}</th>
                  <th className="py-2 pe-4">{t('pages:caching.rules.tableHeaders.action')}</th>
                  <th className="py-2 pe-4">{t('pages:caching.rules.tableHeaders.tier')}</th>
                  <th className="py-2 pe-4">{t('pages:caching.rules.tableHeaders.enabled')}</th>
                  <th className="py-2 pe-4"></th>
                </tr>
              </thead>
              <tbody>
                {rules.map((rule, i) => (
                  <tr
                    key={rule.id}
                    className={`border-b border-slate-800 ${rule.enabled ? '' : 'opacity-50'} ${editingRuleId === rule.id ? 'bg-primary/10' : ''} ${dragOverId === rule.id ? 'bg-slate-800' : ''}`}
                    draggable
                    onDragStart={(e) => { e.dataTransfer.setData('text/plain', String(rule.id)); e.dataTransfer.effectAllowed = 'move' }}
                    onDragOver={(e) => { e.preventDefault(); setDragOverId(rule.id) }}
                    onDrop={(e) => { e.preventDefault(); const dragged = Number(e.dataTransfer.getData('text/plain')); if (dragged !== rule.id) { setDragOverId(null); reorder(dragged, rule.id) } }}
                    onDragEnd={() => setDragOverId(null)}
                  >
                    <td className="py-2 pe-2">
                      <div className="flex items-center gap-1">
                        <span className="cursor-grab" title={t('pages:caching.rules.dragToReorder')}>
                          <GripVertical size={14} className="text-slate-500" />
                        </span>
                        <span className="text-slate-500 text-xs">{i + 1}</span>
                      </div>
                    </td>
                    <td className="py-2 pe-4 text-slate-300">{t(`pages:caching.matchTypes.${rule.match_type}`)}</td>
                    <td className="py-2 pe-4">
                      <span className={`badge ${MATCH_TYPE_PHASES[rule.match_type] === 'request' ? 'badge-neutral' : 'badge-amber'}`}
                            title={MATCH_TYPE_PHASES[rule.match_type] === 'request' ? t('pages:caching.rules.phaseRequest') : t('pages:caching.rules.phaseResponse')}>
                        {MATCH_TYPE_PHASES[rule.match_type]}
                      </span>
                    </td>
                    <td className="py-2 pe-4 font-mono text-xs">{rule.pattern}</td>
                    <td className="py-2 pe-4">
                      <span className={`badge ${rule.action === 'cache' ? 'badge-green' : 'badge-yellow'}`}>
                        {rule.action === 'cache' ? t('pages:caching.rules.actions.cache') : t('pages:caching.rules.actions.bypass')}
                      </span>
                    </td>
                    <td className="py-2 pe-4">
                      <span className={`badge ${rule.tier === 'memory' ? 'badge-blue' : 'badge-purple'}`} title={t(`pages:caching.tierDescriptions.${rule.tier}`)}>
                        {t(`pages:caching.tierLabels.${rule.tier}`)}
                      </span>
                    </td>
                    <td className="py-2 pe-4">
                      <input
                        type="checkbox"
                        checked={rule.enabled}
                        disabled={busy}
                        onChange={() => withBusy(() =>
                          cache.updateRule(config.backend_id, rule.id, { enabled: !rule.enabled })
                        )}
                      />
                    </td>
                    <td className="py-2 pe-4">
                      <div className="flex gap-1">
                        <button
                          className="btn-secondary text-xs px-2 py-1"
                          disabled={busy}
                          onClick={() => startEdit(rule)}
                          title={t('pages:caching.rules.editRule')}
                        >
                          <Pencil size={12} />
                        </button>
                        <button
                          className="btn-secondary text-xs px-2 py-1 text-red-400"
                          disabled={busy}
                          onClick={() => withBusy(() => cache.removeRule(config.backend_id, rule.id))}
                        >
                          <Trash2 size={12} />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            <p className="text-xs text-slate-500 mt-2">
              {t('pages:caching.rules.enabledCount', { enabled: enabledCount, total: rules.length })}
            </p>
          </div>
        )}

        <form onSubmit={handleSubmit} className="border-t border-slate-700 pt-4 space-y-2">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-semibold">{editingRuleId !== null ? t('pages:caching.rules.editTitle') : t('pages:caching.rules.addTitle')}</h3>
            {editingRuleId !== null && (
              <button
                type="button"
                className="btn-secondary text-xs px-2 py-1"
                onClick={resetForm}
              >
                {t('pages:caching.rules.cancelEdit')}
              </button>
            )}
          </div>
          <div className="flex flex-wrap gap-2 items-start">
            <div className="w-full">
              <LabelWithTooltip tooltip={t('pages:caching.tooltips.matchType')}>{t('pages:caching.rules.form.matchType')}</LabelWithTooltip>
              <select
                className="input"
                value={matchType}
                onChange={(e) => setMatchType(e.target.value as MatchType)}
              >
                {((['path', 'filename', 'extension', 'method', 'query_string', 'content_type', 'status_code'] as MatchType[]) as MatchType[]).map(mt => (
                  <option key={mt} value={mt}>{t(`pages:caching.matchTypes.${mt}`)}</option>
                ))}
              </select>
            </div>
            <div className="w-full">
              <LabelWithTooltip tooltip={t('pages:caching.tooltips.pattern')}>{t('pages:caching.rules.form.pattern')}</LabelWithTooltip>
              <input
                className="input font-mono"
                value={pattern}
                onChange={(e) => setPattern(e.target.value)}
                placeholder={matchType === 'path' ? '/downloads/' : matchType === 'filename' ? 'linux.iso' : 'png'}
              />
            </div>
            <div className="w-full">
              <LabelWithTooltip tooltip={t('pages:caching.tooltips.action')}>{t('pages:caching.rules.form.action')}</LabelWithTooltip>
              <select
                className="input"
                value={action}
                onChange={(e) => setAction(e.target.value as RuleAction)}
              >
                <option value="cache">{t('pages:caching.rules.actions.cache')}</option>
                <option value="bypass">{t('pages:caching.rules.actions.bypass')}</option>
              </select>
            </div>
            <div className="w-full">
              <LabelWithTooltip tooltip={t('pages:caching.tooltips.tier')}>{t('pages:caching.rules.form.tier')}</LabelWithTooltip>
              <select
                className="input"
                value={tier}
                onChange={(e) => setTier(e.target.value as CacheTier)}
              >
                {((['memory', 'disk'] as CacheTier[]) as CacheTier[]).map(ct => (
                  <option key={ct} value={ct}>{t(`pages:caching.tierLabels.${ct}`)}</option>
                ))}
              </select>
            </div>
            <button type="submit" className="btn-primary text-sm px-3 py-2" disabled={busy || !pattern.trim()}>
              {editingRuleId !== null
                ? <><Pencil size={14} className="inline me-1" />{t('pages:caching.rules.form.update')}</>
                : <><Plus size={14} className="inline me-1" />{t('pages:caching.rules.form.add')}</>
              }
            </button>
          </div>
          <p className="text-xs text-slate-500">{MATCH_TYPE_HINTS[matchType]}</p>
        </form>

        <div className="flex justify-end border-t border-slate-700 pt-4">
          <button className="btn-secondary" onClick={onClose}>{t('pages:caching.rules.done')}</button>
        </div>
      </div>
    </div>
  )
}
