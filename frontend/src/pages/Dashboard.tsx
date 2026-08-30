import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import {
  getStats, applyConfig, previewAllConfigs, getSystemHealth, cache, metrics,
} from '../services/api'
import { useNotifications } from '../contexts/NotificationContext'
import {
  LayoutDashboard, Server, Users, ArrowUpDown, Play, Eye, Cpu, MemoryStick,
  Gauge, CheckCircle, XCircle, FileText, X,
} from 'lucide-react'
import { Tabs } from '../components/ui'

function fmtBytes(bytes: number): string {
  if (bytes >= 1e9) return (bytes / 1e9).toFixed(2) + ' GB'
  if (bytes >= 1e6) return (bytes / 1e6).toFixed(2) + ' MB'
  if (bytes >= 1e3) return (bytes / 1e3).toFixed(2) + ' KB'
  return bytes.toFixed(0) + ' B'
}

function fmtBytesRate(bps: number): string {
  if (bps >= 1e9) return (bps / 1e9).toFixed(2) + ' GB/s'
  if (bps >= 1e6) return (bps / 1e6).toFixed(2) + ' MB/s'
  if (bps >= 1e3) return (bps / 1e3).toFixed(2) + ' KB/s'
  return bps.toFixed(0) + ' B/s'
}

export default function Dashboard() {
  const { t } = useTranslation(['pages', 'common'])
  const [stats, setStats] = useState<any>({})
  const [previewConfigs, setPreviewConfigs] = useState<Record<string, string>>({})
  const [activeConfigTab, setActiveConfigTab] = useState('haproxy.cfg')
  const [loading, setLoading] = useState(false)
  const [bandwidthSaved, setBandwidthSaved] = useState<number | null>(null)
  const [health, setHealth] = useState<any>(null)
  const [serverRows, setServerRows] = useState<{ backend: string; server: string; status: string; scur: number; rtime: number; requests_rate: number; bytes_in_rate: number; bytes_out_rate: number }[]>([])
  const [rateMetrics, setRateMetrics] = useState<{ rps: number; throughputBps: number } | null>(null)
  const { addNotification, trackTask } = useNotifications()

  useEffect(() => {
    getStats().then((r) => setStats(r.data)).catch(() => setStats({}))
  }, [])

  useEffect(() => {
    const load = async () => {
      const to = new Date().toISOString()
      const from = new Date(Date.now() - 300 * 1000).toISOString()
      try {
        const res = await metrics.get(from, to)
        const points = res.data?.data || []
        const latest = points[points.length - 1]
        if (!latest) {
          setServerRows([])
          setRateMetrics(null)
          return
        }
        const rows: { backend: string; server: string; status: string; scur: number; rtime: number; requests_rate: number; bytes_in_rate: number; bytes_out_rate: number }[] = []
        for (const [backend, servers] of Object.entries(latest.servers || {})) {
          for (const [server, info] of Object.entries(servers as Record<string, any>)) {
            rows.push({ backend, server, status: info.status, scur: info.scur, rtime: info.rtime_ms, requests_rate: info.requests_rate, bytes_in_rate: info.bytes_in_rate, bytes_out_rate: info.bytes_out_rate })
          }
        }
        setServerRows(rows)
        const fe = latest.frontend || {}
        setRateMetrics({
          rps: fe.requests_rate ?? 0,
          throughputBps: (fe.bytes_in_rate ?? 0) + (fe.bytes_out_rate ?? 0),
        })
      } catch {
        setServerRows([])
        setRateMetrics(null)
      }
    }
    load()
    const id = setInterval(load, 30000)
    return () => clearInterval(id)
  }, [])

  useEffect(() => {
    const load = async () => {
      const to = new Date().toISOString()
      const from = new Date(Date.now() - 86400 * 1000).toISOString()
      try {
        const res = await cache.metrics({ from, to })
        setBandwidthSaved(res.data?.summary?.total_bandwidth_saved ?? 0)
      } catch {
        setBandwidthSaved(null)
      }
    }
    load()
    const id = setInterval(load, 60000)
    return () => clearInterval(id)
  }, [])

  useEffect(() => {
    const loadHealth = () => {
      getSystemHealth()
        .then((r) => setHealth(r.data))
        .catch(() => setHealth(null))
    }
    loadHealth()
    const id = setInterval(loadHealth, 30000)
    return () => clearInterval(id)
  }, [])

  const handlePreview = async () => {
    try {
      const r = await previewAllConfigs()
      const configs = r.data
      setPreviewConfigs(configs)
      const keys = Object.keys(configs)
      if (keys.length > 0 && !keys.includes(activeConfigTab)) {
        setActiveConfigTab(keys[0])
      }
    } catch {
      setPreviewConfigs({})
    }
  }

  const handleApply = async () => {
    setLoading(true)
    try {
      const r = await applyConfig()
      const id = addNotification({
        type: 'info',
        title: t('pages:dashboard.configApply'),
        message: r.data.message || t('pages:dashboard.configApplyStarted'),
      })
      trackTask(r.data.task_id, id, {
        title: t('pages:dashboard.configApply'),
        successMessage: r.data.message || t('pages:dashboard.configAppliedSuccessfully'),
      })
    } catch (err: any) {
      const detail = err?.response?.data?.detail
      addNotification({
        type: 'error',
        title: t('pages:dashboard.configApplyFailed'),
        message: typeof detail === 'object' ? detail?.message : (detail || t('pages:dashboard.applyFailed')),
        detail: typeof detail === 'object' ? (detail?.error || JSON.stringify(detail, null, 2)) : (err.message),
      })
    } finally {
      setLoading(false)
    }
  }

  const configTabs = Object.keys(previewConfigs)

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h2 className="text-2xl font-bold flex items-center gap-2"><LayoutDashboard className="h-5 w-5 text-primary" /> {t('pages:dashboard.title')}</h2>
        <div className="flex gap-2">
          <button onClick={handlePreview} className="btn-secondary"><Eye className="w-4 h-4 me-2" /> {t('pages:dashboard.preview')}</button>
          <button onClick={handleApply} disabled={loading} className="btn-primary"><Play className="w-4 h-4 me-2" /> {t('pages:dashboard.applyConfig')}</button>
        </div>
      </div>

      {configTabs.length > 0 && (
        <div className="card space-y-3">
          <div className="flex items-center justify-between">
            <h3 className="font-semibold flex items-center gap-2"><FileText className="h-4 w-4 text-primary" /> {t('pages:dashboard.configPreview')}</h3>
            <button onClick={() => setPreviewConfigs({})} className="text-slate-400 hover:text-slate-200" aria-label={t('pages:dashboard.closePreview')}><X className="w-4 h-4" /></button>
          </div>
          <Tabs
            tabs={configTabs.map((key) => ({ id: key, label: key }))}
            active={activeConfigTab}
            onChange={setActiveConfigTab}
          />
          <pre className="bg-slate-950 p-4 rounded-lg overflow-auto text-xs text-slate-300 max-h-96">{maskConfig(previewConfigs[activeConfigTab] || '')}</pre>
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
        {/* Stat cards */}
        <div className="lg:col-span-2 grid grid-cols-1 sm:grid-cols-2 gap-4">
          <StatCard icon={Cpu} label={t('pages:dashboard.statCards.cpuLoad')} value={typeof stats.cpu_load === 'number' ? `${stats.cpu_load.toFixed(1)}%` : 'N/A'} />
          <StatCard icon={MemoryStick} label={t('pages:dashboard.statCards.memoryUsage')} value={typeof stats.memory_usage === 'number' ? `${stats.memory_usage.toFixed(1)} MB` : 'N/A'} />
          <StatCard icon={Users} label={t('pages:dashboard.statCards.currentConnections')} value={stats.current_connections ?? 'N/A'} />
          <StatCard icon={ArrowUpDown} label={t('pages:dashboard.statCards.totalRps')} value={rateMetrics ? `${rateMetrics.rps.toFixed(1)}/s` : 'N/A'} />
          <StatCard icon={Server} label={t('pages:dashboard.statCards.totalThroughput')} value={rateMetrics ? fmtBytesRate(rateMetrics.throughputBps) : 'N/A'} />
          <StatCard icon={Gauge} label={t('pages:dashboard.statCards.bandwidthSaved24h')} value={bandwidthSaved !== null ? fmtBytes(bandwidthSaved) : 'N/A'} />
        </div>

        {/* System Health */}
        <div className="card lg:col-span-2">
          <h3 className="font-semibold mb-4">{t('pages:dashboard.systemHealth')}</h3>
          {!health ? (
            <p className="text-slate-400 text-sm">N/A</p>
          ) : (
            <div className="space-y-3">
              <HealthRow
                label={t('pages:dashboard.healthChecks.haproxySocket')}
                ok={health.haproxy_socket?.available}
                okText={t('pages:dashboard.healthChecks.available')}
                failText={t('pages:dashboard.healthChecks.notAvailable')}
              />
              <HealthRow
                label={t('pages:dashboard.healthChecks.valkeyRedis')}
                ok={health.valkey?.available}
                okText={t('pages:dashboard.healthChecks.available')}
                failText={t('pages:dashboard.healthChecks.notAvailable')}
              />
              <HealthRow
                label={t('pages:dashboard.healthChecks.docker')}
                ok={health.docker?.available}
                okText={t('pages:dashboard.healthChecks.available')}
                failText={health.docker?.error || t('pages:dashboard.healthChecks.notAvailable')}
              />
              <HealthRow
                label={t('pages:dashboard.healthChecks.corazaSpoa')}
                ok={health.coraza_spoa?.enabled}
                okText={t('pages:dashboard.healthChecks.enabled')}
                failText={t('pages:dashboard.healthChecks.disabled')}
              />
              <div className="pt-2 border-t border-slate-800">
                <p className="text-xs text-slate-400 mb-2">{t('pages:dashboard.healthChecks.geoipDatabases')}</p>
                <div className="grid grid-cols-3 gap-2">
                  <HealthRow
                    label={t('pages:dashboard.healthChecks.countryDb')}
                    ok={health.geoip?.country_db_exists}
                    okText={t('pages:dashboard.healthChecks.available')}
                    failText={t('pages:dashboard.healthChecks.notAvailable')}
                    compact
                  />
                  <HealthRow
                    label={t('pages:dashboard.healthChecks.cityDb')}
                    ok={health.geoip?.city_db_exists}
                    okText={t('pages:dashboard.healthChecks.available')}
                    failText={t('pages:dashboard.healthChecks.notAvailable')}
                    compact
                  />
                  <HealthRow
                    label={t('pages:dashboard.healthChecks.asnDb')}
                    ok={health.geoip?.asn_db_exists}
                    okText={t('pages:dashboard.healthChecks.available')}
                    failText={t('pages:dashboard.healthChecks.notAvailable')}
                    compact
                  />
                </div>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* HAProxy servers by status */}
      <div className="card p-4 space-y-2">
        <div className="flex items-center gap-2">
          <Server className="h-4 w-4 text-slate-400" />
          <h3 className="text-sm font-semibold text-slate-200">{t('pages:dashboard.serverStatus')}</h3>
        </div>
        {serverRows.length === 0 ? (
          <p className="text-slate-400 text-sm">{t('pages:dashboard.noServerData')}</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm text-start">
              <thead className="text-slate-400 border-b border-slate-800">
                <tr>
                  <th>{t('pages:dashboard.serverTableHeaders.backend')}</th>
                  <th>{t('pages:dashboard.serverTableHeaders.server')}</th>
                  <th>{t('pages:dashboard.serverTableHeaders.status')}</th>
                  <th>{t('pages:dashboard.serverTableHeaders.sessions')}</th>
                  <th>{t('pages:dashboard.serverTableHeaders.responseMs')}</th>
                  <th>{t('pages:dashboard.serverTableHeaders.rps')}</th>
                  <th>{t('pages:dashboard.serverTableHeaders.inPerSec')}</th>
                  <th>{t('pages:dashboard.serverTableHeaders.outPerSec')}</th>
                </tr>
              </thead>
              <tbody>
                {serverRows.map((row, idx) => (
                  <tr key={idx} className="border-b border-slate-800 last:border-0">
                    <td>{row.backend}</td>
                    <td>{row.server}</td>
                    <td>
                      <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium ${
                        row.status === 'UP' ? 'bg-emerald-500/20 text-emerald-400' : 'bg-red-500/20 text-red-400'
                      }`}>
                        {row.status}
                      </span>
                    </td>
                    <td>{row.scur}</td>
                    <td>{row.rtime}</td>
                    <td>{row.requests_rate.toFixed(1)}</td>
                    <td>{fmtBytesRate(row.bytes_in_rate)}</td>
                    <td>{fmtBytesRate(row.bytes_out_rate)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  )
}

const SENSITIVE_RE = /\b(auth|user|username|password|passwd|secret|token|credential)\b/i

function maskConfig(config: string): string {
  return config
    .split('\n')
    .map((line) => {
      if (!SENSITIVE_RE.test(line)) return line
      const match = line.match(/^(\s*\S+\s+\S+\s+)/)
      if (!match) return line
      return match[1] + '***'
    })
    .join('\n')
}

function StatCard({ icon: Icon, label, value }: { icon: any, label: string, value: any }) {
  return (
    <div className="card flex items-center gap-4">
      <div className="p-3 rounded-lg bg-primary/10 text-primary"><Icon className="w-6 h-6" /></div>
      <div>
        <p className="text-xs text-slate-400">{label}</p>
        <p className="text-xl font-bold">{value}</p>
      </div>
    </div>
  )
}

function HealthRow({
  label, ok, okText, failText, compact,
}: {
  label: string
  ok: boolean | undefined
  okText: string
  failText: string
  compact?: boolean
}) {
  const isOk = !!ok
  return (
    <div className={`flex items-center justify-between ${compact ? '' : 'py-1'}`}>
      <span className="text-sm text-slate-300">{label}</span>
      <span className={`flex items-center gap-1.5 text-xs font-medium ${isOk ? 'text-emerald-400' : 'text-red-400'}`}>
        {isOk ? <CheckCircle className="w-4 h-4" /> : <XCircle className="w-4 h-4" />}
        {isOk ? okText : failText}
      </span>
    </div>
  )
}
