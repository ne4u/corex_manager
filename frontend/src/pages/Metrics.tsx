import { useEffect, useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
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
  BarChart,
  Bar,
} from 'recharts'
import { Activity, Shield, Globe, Gauge } from 'lucide-react'
import { ComposableMap, Geographies } from 'react-simple-maps'
import { numericToAlpha2, alpha2ToName } from '../countryCodes'
import { metrics, wafMetrics, cache } from '../services/api'
import { Tabs } from '../components/ui'
import { useDateTime } from '../contexts/DateTimeContext'

interface MetricPoint {
  time: string
  frontend: Record<string, number>
  backend: Record<string, number>
  frontends: Record<string, Record<string, number>>
  backends: Record<string, Record<string, number>>
  servers: Record<string, Record<string, { status: string; scur: number; rtime_ms: number; requests_rate: number; bytes_in_rate: number; bytes_out_rate: number }>>
  process: Record<string, number>
}

const GEO_URL = 'https://cdn.jsdelivr.net/npm/world-atlas@2/countries-110m.json'

const RANGES = [
  { label: '5m', seconds: 300 },
  { label: '15m', seconds: 900 },
  { label: '1h', seconds: 3600 },
  { label: '6h', seconds: 21600 },
  { label: '1d', seconds: 86400 },
  { label: '7d', seconds: 604800 },
]

function fmtBytesRate(bps: number): string {
  if (bps >= 1e9) return (bps / 1e9).toFixed(2) + ' GB/s'
  if (bps >= 1e6) return (bps / 1e6).toFixed(2) + ' MB/s'
  if (bps >= 1e3) return (bps / 1e3).toFixed(2) + ' KB/s'
  return bps.toFixed(0) + ' B/s'
}

function fmtBytes(bytes: number): string {
  if (bytes >= 1e9) return (bytes / 1e9).toFixed(2) + ' GB'
  if (bytes >= 1e6) return (bytes / 1e6).toFixed(2) + ' MB'
  if (bytes >= 1e3) return (bytes / 1e3).toFixed(2) + ' KB'
  return bytes.toFixed(0) + ' B'
}

function getNum(point: MetricPoint, path: string): number {
  const parts = path.split('.')
  let v: unknown = point
  for (const p of parts) {
    if (v && typeof v === 'object') v = (v as Record<string, unknown>)[p]
    else return 0
  }
  return typeof v === 'number' ? v : 0
}

function buildSeries(data: MetricPoint[], defs: { key: string; path: string }[], fmtTime: (iso: string) => string) {
  return data.map((d) => {
    const row: Record<string, number | string> = { time: fmtTime(d.time) }
    for (const { key, path } of defs) row[key] = getNum(d, path)
    return row
  })
}

interface ChartDef {
  title: string
  type: 'line' | 'area'
  unit?: string
  format?: 'bytes'
  defs: { key: string; path: string; color: string }[]
  yDomain?: [number | string, number | string]
}

const FRONTEND_METRICS: ChartDef[] = [
  { title: 'pages:metrics.frontendCharts.frontStatusCodeCount', type: 'line', defs: [
    { key: '1xx', path: 'frontend.1xx', color: '#6366f1' },
    { key: '2xx', path: 'frontend.2xx', color: '#10b981' },
    { key: '3xx', path: 'frontend.3xx', color: '#3b82f6' },
    { key: '4xx', path: 'frontend.4xx', color: '#f59e0b' },
    { key: '5xx', path: 'frontend.5xx', color: '#ef4444' },
    { key: 'other', path: 'frontend.other', color: '#94a3b8' },
  ]},
  { title: 'pages:metrics.frontendCharts.frontSessions', type: 'line', defs: [{ key: 'Sessions', path: 'frontend.sessions', color: '#8b5cf6' }] },
  { title: 'pages:metrics.frontendCharts.frontSessionsPct', type: 'line', unit: '%', defs: [{ key: 'Sessions %', path: 'frontend.sessions_pct', color: '#f43f5e' }], yDomain: [0, 100] },
  { title: 'pages:metrics.frontendCharts.frontSessionsPerSec', type: 'line', unit: '/s', defs: [{ key: 'Sessions/s', path: 'frontend.sessions_rate', color: '#06b6d4' }] },
  { title: 'pages:metrics.frontendCharts.frontRequestsPerSec', type: 'line', unit: '/s', defs: [{ key: 'Requests/s', path: 'frontend.requests_rate', color: '#22c55e' }] },
  { title: 'pages:metrics.frontendCharts.frontNetwork', type: 'line', format: 'bytes', defs: [
    { key: 'In/s', path: 'frontend.bytes_in_rate', color: '#3b82f6' },
    { key: 'Out/s', path: 'frontend.bytes_out_rate', color: '#10b981' },
  ]},
  { title: 'pages:metrics.frontendCharts.frontDenials', type: 'line', unit: '/s', defs: [{ key: 'Denials/s', path: 'frontend.denials_rate', color: '#ef4444' }] },
]

const BACKEND_METRICS: ChartDef[] = [
  { title: 'pages:metrics.backendCharts.backStatusCodeCount', type: 'line', defs: [
    { key: '1xx', path: 'backend.1xx', color: '#6366f1' },
    { key: '2xx', path: 'backend.2xx', color: '#10b981' },
    { key: '3xx', path: 'backend.3xx', color: '#3b82f6' },
    { key: '4xx', path: 'backend.4xx', color: '#f59e0b' },
    { key: '5xx', path: 'backend.5xx', color: '#ef4444' },
    { key: 'other', path: 'backend.other', color: '#94a3b8' },
  ]},
  { title: 'pages:metrics.backendCharts.backSessions', type: 'line', defs: [{ key: 'Sessions', path: 'backend.sessions', color: '#8b5cf6' }] },
  { title: 'pages:metrics.backendCharts.backSessionsPct', type: 'line', unit: '%', defs: [{ key: 'Sessions %', path: 'backend.sessions_pct', color: '#f43f5e' }], yDomain: [0, 100] },
  { title: 'pages:metrics.backendCharts.backSessionsPerSec', type: 'line', unit: '/s', defs: [{ key: 'Sessions/s', path: 'backend.sessions_rate', color: '#06b6d4' }] },
  { title: 'pages:metrics.backendCharts.backRequestsPerSec', type: 'line', unit: '/s', defs: [{ key: 'Requests/s', path: 'backend.responses_rate', color: '#22c55e' }] },
  { title: 'pages:metrics.backendCharts.backendQueue', type: 'line', defs: [{ key: 'Queue', path: 'backend.queue', color: '#f59e0b' }] },
  { title: 'pages:metrics.backendCharts.connectionErrorsPerSec', type: 'line', unit: '/s', defs: [{ key: 'Conn errors/s', path: 'backend.connection_errors_rate', color: '#ef4444' }] },
  { title: 'pages:metrics.backendCharts.backNetwork', type: 'line', format: 'bytes', defs: [
    { key: 'In/s', path: 'backend.bytes_in_rate', color: '#3b82f6' },
    { key: 'Out/s', path: 'backend.bytes_out_rate', color: '#10b981' },
  ]},
  { title: 'pages:metrics.backendCharts.avgResponseTime', type: 'line', unit: 'ms', defs: [{ key: 'Response (ms)', path: 'backend.avg_response_time_ms', color: '#ec4899' }] },
  { title: 'pages:metrics.backendCharts.timeToConnect', type: 'line', unit: 'ms', defs: [{ key: 'Connect (ms)', path: 'backend.avg_connect_time_ms', color: '#06b6d4' }] },
  { title: 'pages:metrics.backendCharts.avgQueueTime', type: 'line', unit: 'ms', defs: [{ key: 'Queue (ms)', path: 'backend.avg_queue_time_ms', color: '#f59e0b' }] },
  { title: 'pages:metrics.backendCharts.retriesRedispatchesPerSec', type: 'line', unit: '/s', defs: [{ key: 'Retries/s', path: 'backend.retries_and_redispatches_rate', color: '#a855f7' }] },
  { title: 'pages:metrics.backendCharts.backDenials', type: 'line', unit: '/s', defs: [{ key: 'Denials/s', path: 'backend.denials_rate', color: '#ef4444' }] },
]

const PROCESS_METRICS: ChartDef[] = [
  { title: 'pages:metrics.processCharts.haproxyCpuLoad', type: 'line', unit: '%', defs: [{ key: 'CPU load', path: 'process.cpu_load', color: '#f59e0b' }], yDomain: [0, 100] },
  { title: 'pages:metrics.processCharts.haproxyMemoryUsage', type: 'line', unit: 'MB', defs: [{ key: 'Memory', path: 'process.memory_usage', color: '#3b82f6' }] },
]

const PROXY_PALETTE = ['#22c55e', '#3b82f6', '#f59e0b', '#ef4444', '#a855f7', '#06b6d4', '#ec4899', '#8b5cf6', '#f43f5e', '#84cc16', '#14b8a6', '#eab308']

interface WafMetricData {
  time: string[]
  series: { key: string; data: { time: string; count: number }[] }[]
  breakdown: string
  totals: Record<string, number>
}

interface BandwidthSnapshot {
  timestamp: string
  memory_cache_bytes_saved: number
  native_compression_bytes_saved: number
  disk_cache_bytes_saved: number
  brotli_zstd_bytes_saved: number
  webp_bytes_saved: number
  total_bandwidth_saved: number
  haproxy_cache_hit: number
  haproxy_cache_miss: number
  disk_cache_hit: number
  disk_cache_miss: number
  disk_cache_objects: number
  haproxy_hit_rate: number
  disk_hit_rate: number
}

interface BandwidthMetricData {
  snapshots: BandwidthSnapshot[]
  summary: {
    total_memory_cache_bytes_saved: number
    total_native_compression_bytes_saved: number
    total_disk_cache_bytes_saved: number
    total_brotli_zstd_bytes_saved: number
    total_webp_bytes_saved: number
    total_bandwidth_saved: number
    total_haproxy_hits: number
    total_haproxy_miss: number
    total_disk_hits: number
    total_disk_miss: number
    haproxy_hit_rate: number
    disk_hit_rate: number
  }
}

export default function Metrics() {
  const { t } = useTranslation(['pages', 'common'])
  const { formatTimeCompact } = useDateTime()
  const [range, setRange] = useState(300)
  const [tab, setTab] = useState<'haproxy' | 'waf' | 'bandwidth'>('haproxy')
  const [data, setData] = useState<MetricPoint[]>([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [wafData, setWafData] = useState<WafMetricData | null>(null)
  const [wafBreakdown, setWafBreakdown] = useState('action')
  const [wafLoading, setWafLoading] = useState(false)
  const [countryData, setCountryData] = useState<WafMetricData | null>(null)
  const [visibleCodes, setVisibleCodes] = useState<Record<string, Record<string, boolean>>>({})
  const [bandwidthData, setBandwidthData] = useState<BandwidthMetricData | null>(null)
  const [bandwidthLoading, setBandwidthLoading] = useState(false)

  useEffect(() => {
    if (tab !== 'haproxy') return
    const load = async () => {
      setLoading(true)
      setError(null)
      const to = new Date().toISOString()
      const from = new Date(Date.now() - range * 1000).toISOString()
      try {
        const res = await metrics.get(from, to)
        setData(res.data.data || [])
      } catch (err: any) {
        const msg = err?.response?.data?.detail || err?.message || t('pages:metrics.failedToLoadMetrics')
        setError(msg)
        console.error('Metrics fetch error:', err)
      } finally {
        setLoading(false)
      }
    }
    load()
    const id = setInterval(load, 30000)
    return () => clearInterval(id)
  }, [range, tab])

  useEffect(() => {
    if (tab !== 'waf') return
    const load = async () => {
      setWafLoading(true)
      const to = new Date().toISOString()
      const from = new Date(Date.now() - range * 1000).toISOString()
      try {
        const res = await wafMetrics.get(from, to, undefined, wafBreakdown)
        setWafData(res.data)
      } catch (err) {
        console.error(err)
      } finally {
        setWafLoading(false)
      }
    }
    load()
    const id = setInterval(load, 30000)
    return () => clearInterval(id)
  }, [range, wafBreakdown, tab])

  useEffect(() => {
    if (tab !== 'waf') return
    const load = async () => {
      const to = new Date().toISOString()
      const from = new Date(Date.now() - range * 1000).toISOString()
      try {
        const res = await wafMetrics.get(from, to, undefined, 'country')
        setCountryData(res.data)
      } catch (err) {
        console.error(err)
      }
    }
    load()
    const id = setInterval(load, 30000)
    return () => clearInterval(id)
  }, [range, tab])

  useEffect(() => {
    if (tab !== 'bandwidth') return
    const load = async () => {
      setBandwidthLoading(true)
      const to = new Date().toISOString()
      const from = new Date(Date.now() - range * 1000).toISOString()
      try {
        const res = await cache.metrics({ from, to })
        setBandwidthData(res.data)
      } catch (err) {
        console.error('Bandwidth metrics fetch error:', err)
      } finally {
        setBandwidthLoading(false)
      }
    }
    load()
    const id = setInterval(load, 30000)
    return () => clearInterval(id)
  }, [range, tab])

  const latest = data[data.length - 1]

  const proxyNames = useMemo(() => {
    const collect = (kind: 'frontends' | 'backends') => {
      const names = new Set<string>()
      for (const pt of data) {
        const proxies = (pt[kind] || {}) as Record<string, Record<string, number>>
        for (const name of Object.keys(proxies)) names.add(name)
      }
      return Array.from(names).sort()
    }
    return { frontends: collect('frontends'), backends: collect('backends') }
  }, [data])

  function renderChart(m: ChartDef) {
    const activeDefs = m.defs.filter((d) => !['1xx', '2xx', '3xx', '4xx', '5xx', 'other'].includes(d.key) || (visibleCodes[m.title]?.[d.key] ?? true))
    const series = buildSeries(data, activeDefs, formatTimeCompact)
    const isArea = m.type === 'area'
    const isBytes = m.format === 'bytes'
    const yAxisUnit = isBytes ? undefined : m.unit
    const tickFmt = isBytes ? (v: number) => fmtBytesRate(v) : undefined
    const tooltipFmt = isBytes ? (v: number) => fmtBytesRate(v) : undefined
    return (
      <div key={m.title} className="card p-4 space-y-2">
        <h3 className="text-sm font-semibold text-slate-200">{t(m.title)}</h3>
        <ResponsiveContainer width="100%" height={180}>
          {isArea ? (
            <AreaChart data={series}>
              <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
              <XAxis dataKey="time" tick={{ fontSize: 10 }} stroke="#94a3b8" />
              <YAxis tick={{ fontSize: 10 }} stroke="#94a3b8" unit={yAxisUnit} tickFormatter={tickFmt} domain={m.yDomain || ['auto', 'auto']} />
              <Tooltip contentStyle={{ backgroundColor: '#1e293b', borderColor: '#334155' }} formatter={tooltipFmt} />
              <Legend
                content={() => (
                  <div className="flex flex-wrap justify-center gap-3 mt-1">
                    {m.defs.map((d) => (
                      <span
                        key={d.key}
                        className={`cursor-pointer text-[11px] flex items-center gap-1 ${
                          visibleCodes[m.title]?.[d.key] === false ? 'text-slate-600 line-through' : 'text-slate-300'
                        }`}
                        onClick={() => {
                          if (!['1xx', '2xx', '3xx', '4xx', '5xx', 'other'].includes(d.key)) return
                          setVisibleCodes((prev: Record<string, Record<string, boolean>>) => ({
                            ...prev,
                            [m.title]: { ...prev[m.title], [d.key]: !((prev[m.title]?.[d.key]) ?? true) },
                          }))
                        }}
                      >
                        <span className="inline-block w-2 h-2 rounded-full" style={{ background: d.color }} />
                        {d.key}
                      </span>
                    ))}
                  </div>
                )}
              />
              {activeDefs.map((d) => (
                <Area
                  key={d.key}
                  type="monotone"
                  dataKey={d.key}
                  stroke={d.color}
                  fill={d.color}
                  stackId="1"
                  isAnimationActive={false}
                />
              ))}
            </AreaChart>
          ) : (
            <LineChart data={series}>
              <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
              <XAxis dataKey="time" tick={{ fontSize: 10 }} stroke="#94a3b8" />
              <YAxis tick={{ fontSize: 10 }} stroke="#94a3b8" unit={yAxisUnit} tickFormatter={tickFmt} domain={m.yDomain || ['auto', 'auto']} />
              <Tooltip contentStyle={{ backgroundColor: '#1e293b', borderColor: '#334155' }} formatter={tooltipFmt} />
              <Legend
                content={() => (
                  <div className="flex flex-wrap justify-center gap-3 mt-1">
                    {m.defs.map((d) => (
                      <span
                        key={d.key}
                        className={`cursor-pointer text-[11px] flex items-center gap-1 ${
                          visibleCodes[m.title]?.[d.key] === false ? 'text-slate-600 line-through' : 'text-slate-300'
                        }`}
                        onClick={() => {
                          if (!['1xx', '2xx', '3xx', '4xx', '5xx', 'other'].includes(d.key)) return
                          setVisibleCodes((prev: Record<string, Record<string, boolean>>) => ({
                            ...prev,
                            [m.title]: { ...prev[m.title], [d.key]: !((prev[m.title]?.[d.key]) ?? true) },
                          }))
                        }}
                      >
                        <span className="inline-block w-2 h-2 rounded-full" style={{ background: d.color }} />
                        {d.key}
                      </span>
                    ))}
                  </div>
                )}
              />
              {activeDefs.map((d) => (
                <Line
                  key={d.key}
                  type="monotone"
                  dataKey={d.key}
                  stroke={d.color}
                  dot={false}
                  isAnimationActive={false}
                  strokeWidth={2}
                />
              ))}
            </LineChart>
          )}
        </ResponsiveContainer>
      </div>
    )
  }

  function renderMultiSeriesChart(title: string, kind: 'frontends' | 'backends', metric: string, format?: 'bytes') {
    const allNames = proxyNames[kind]
    const activeNames = allNames.filter((name) => visibleCodes[title]?.[name] !== false)
    const isBytes = format === 'bytes'
    const tickFmt = isBytes ? (v: number) => fmtBytesRate(v) : undefined
    const tooltipFmt = isBytes ? (v: number) => fmtBytesRate(v) : undefined
    const series = data.map((pt) => {
      const row: Record<string, number | string> = { time: formatTimeCompact(pt.time) }
      const proxies = (pt[kind] || {}) as Record<string, Record<string, number>>
      for (const name of activeNames) {
        row[name] = proxies[name]?.[metric] ?? 0
      }
      return row
    })
    return (
      <div key={title} className="card p-4 space-y-2">
        <h3 className="text-sm font-semibold text-slate-200">{title}</h3>
        <ResponsiveContainer width="100%" height={180}>
          <LineChart data={series}>
            <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
            <XAxis dataKey="time" tick={{ fontSize: 10 }} stroke="#94a3b8" />
            <YAxis tick={{ fontSize: 10 }} stroke="#94a3b8" unit={isBytes ? undefined : '/s'} tickFormatter={tickFmt} domain={['auto', 'auto']} />
            <Tooltip contentStyle={{ backgroundColor: '#1e293b', borderColor: '#334155' }} formatter={tooltipFmt} />
            <Legend
              content={() => (
                <div className="flex flex-wrap justify-center gap-3 mt-1">
                  {allNames.map((name, i) => (
                    <span
                      key={name}
                      className={`cursor-pointer text-[11px] flex items-center gap-1 ${
                        visibleCodes[title]?.[name] === false ? 'text-slate-600 line-through' : 'text-slate-300'
                      }`}
                      onClick={() => {
                        setVisibleCodes((prev: Record<string, Record<string, boolean>>) => ({
                          ...prev,
                          [title]: { ...prev[title], [name]: !((prev[title]?.[name]) ?? true) },
                        }))
                      }}
                    >
                      <span className="inline-block w-2 h-2 rounded-full" style={{ background: PROXY_PALETTE[i % PROXY_PALETTE.length] }} />
                      {name}
                    </span>
                  ))}
                </div>
              )}
            />
            {activeNames.map((name) => {
              const i = allNames.indexOf(name)
              return (
                <Line
                  key={name}
                  type="monotone"
                  dataKey={name}
                  stroke={PROXY_PALETTE[i % PROXY_PALETTE.length]}
                  dot={false}
                  isAnimationActive={false}
                  strokeWidth={2}
                />
              )
            })}
          </LineChart>
        </ResponsiveContainer>
      </div>
    )
  }

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div className="flex items-center gap-2">
          <Activity className="h-5 w-5 text-emerald-400" />
          <h2 className="text-2xl font-bold">Metrics</h2>
        </div>
        <div className="flex items-center gap-2 flex-wrap">
          {RANGES.map((opt) => (
            <button
              key={opt.seconds}
              onClick={() => setRange(opt.seconds)}
              className={`px-2 py-1 text-xs rounded ${
                range === opt.seconds
                  ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/40'
                  : 'bg-slate-800 text-slate-400 border border-slate-700 hover:bg-slate-700'
              }`}
            >
              {opt.label}
            </button>
          ))}
          {loading && tab === 'haproxy' && <span className="text-xs text-slate-500">Loading…</span>}
          {wafLoading && tab === 'waf' && <span className="text-xs text-slate-500">Loading…</span>}
          {bandwidthLoading && tab === 'bandwidth' && <span className="text-xs text-slate-500">Loading…</span>}
        </div>
      </div>

      <Tabs
        tabs={[
          { id: 'haproxy', label: t('pages:metrics.tabs.haproxy'), icon: Activity },
          { id: 'waf', label: t('pages:metrics.tabs.waf'), icon: Shield },
          { id: 'bandwidth', label: t('pages:metrics.tabs.bandwidth'), icon: Gauge },
        ]}
        active={tab}
        onChange={(id) => setTab(id as 'haproxy' | 'waf' | 'bandwidth')}
      />

      {tab === 'haproxy' && (
        <>
          {error && (
            <div className="card p-4 border border-red-500/30 bg-red-500/10 text-red-400 text-sm">
              <p className="font-semibold">Error loading metrics</p>
              <p>{error}</p>
            </div>
          )}

          {!loading && !error && data.length === 0 && (
            <div className="card p-4 border border-amber-500/30 bg-amber-500/10 text-amber-400 text-sm">
              <p>No metric data available for the selected time range. The metrics sampler may still be collecting initial data.</p>
            </div>
          )}

          {latest && (
            <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4">
              <div className="card p-3"><p className="text-xs text-slate-400">Frontend sessions</p><p className="text-xl font-semibold">{latest.frontend.sessions}</p></div>
              <div className="card p-3"><p className="text-xs text-slate-400">Frontend sessions %</p><p className="text-xl font-semibold">{latest.frontend.sessions_pct.toFixed(2)}%</p></div>
              <div className="card p-3"><p className="text-xs text-slate-400">Total RPS</p><p className="text-xl font-semibold">{latest.frontend.requests_rate.toFixed(1)}/s</p></div>
              <div className="card p-3"><p className="text-xs text-slate-400">Total throughput</p><p className="text-xl font-semibold">{fmtBytesRate(latest.frontend.bytes_in_rate + latest.frontend.bytes_out_rate)}</p></div>
              <div className="card p-3"><p className="text-xs text-slate-400">Backend queue</p><p className="text-xl font-semibold">{latest.backend.queue}</p></div>
              <div className="card p-3"><p className="text-xs text-slate-400">Backend response time</p><p className="text-xl font-semibold">{latest.backend.avg_response_time_ms} ms</p></div>
            </div>
          )}

          <h3 className="text-lg font-semibold text-slate-200">Process metrics</h3>
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">{PROCESS_METRICS.map(renderChart)}</div>

          <h3 className="text-lg font-semibold text-slate-200">Per-proxy metrics</h3>
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            {renderMultiSeriesChart('Per-frontend requests/sec', 'frontends', 'responses_rate')}
            {renderMultiSeriesChart('Per-frontend throughput (in)', 'frontends', 'bytes_in_rate', 'bytes')}
            {renderMultiSeriesChart('Per-backend requests/sec', 'backends', 'responses_rate')}
            {renderMultiSeriesChart('Per-backend throughput (in)', 'backends', 'bytes_in_rate', 'bytes')}
          </div>

          <h3 className="text-lg font-semibold text-slate-200">Frontend metrics</h3>
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">{FRONTEND_METRICS.map(renderChart)}</div>

          <h3 className="text-lg font-semibold text-slate-200">Backend metrics</h3>
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">{BACKEND_METRICS.map(renderChart)}</div>
        </>
      )}

      {tab === 'waf' && (
        <>
          {wafData && wafData.time.length > 0 ? (
            <>
              <div className="card p-4 space-y-4">
                <div className="flex flex-wrap items-center justify-between gap-4">
                  <div className="flex items-center gap-2">
                    <Shield className="h-5 w-5 text-amber-400" />
                    <h3 className="text-lg font-semibold text-slate-200">WAF events</h3>
                  </div>
                  <div className="flex items-center gap-2 flex-wrap">
                    <select
                      value={wafBreakdown}
                      onChange={(e) => setWafBreakdown(e.target.value)}
                      className="bg-slate-800 text-slate-200 text-xs rounded border border-slate-700 px-2 py-1"
                    >
                      <option value="action">By action</option>
                      <option value="rule_id">By rule ID</option>
                      <option value="severity">By severity</option>
                      <option value="msg">By message</option>
                      <option value="country">By country</option>
                    </select>
                    {wafLoading && <span className="text-xs text-slate-500">Loading…</span>}
                  </div>
                </div>

                <div className="h-56">
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart data={wafData.time.map((t, i) => {
                      const row: Record<string, number | string> = { time: formatTimeCompact(t) }
                      for (const s of wafData.series) {
                        row[s.key] = s.data[i]?.count ?? 0
                      }
                      return row
                    })}>
                      <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                      <XAxis dataKey="time" tick={{ fontSize: 10 }} stroke="#94a3b8" />
                      <YAxis tick={{ fontSize: 10 }} stroke="#94a3b8" />
                      <Tooltip contentStyle={{ backgroundColor: '#1e293b', borderColor: '#334155' }} />
                      <Legend wrapperStyle={{ fontSize: 10 }} />
                      {wafData.series.map((s, i) => (
                        <Bar
                          key={s.key}
                          dataKey={s.key}
                          stackId="waf"
                          fill={['#10b981', '#3b82f6', '#f59e0b', '#ef4444', '#a855f7', '#06b6d4', '#ec4899', '#22c55e'][i % 8]}
                          isAnimationActive={false}
                        />
                      ))}
                    </BarChart>
                  </ResponsiveContainer>
                </div>

                <div className="overflow-x-auto max-h-64 overflow-y-auto">
                  <table className="w-full text-sm text-start">
                    <thead className="text-slate-400 border-b border-slate-800 sticky top-0 bg-slate-900">
                      <tr>
                        <th className="py-2">{wafData.breakdown}</th>
                        <th className="py-2">Count</th>
                      </tr>
                    </thead>
                    <tbody>
                      {(() => {
                        const totalValues = Object.values(wafData.totals).map(Number)
                        const max = Math.max(1, ...totalValues)
                        return Object.entries(wafData.totals)
                          .sort(([, a], [, b]) => (b as number) - (a as number))
                          .map(([key, count]) => {
                            const ratio = (count as number) / max
                            return (
                              <tr key={key} className="border-b border-slate-800 last:border-0">
                                <td className="py-1 break-all max-w-md">{key}</td>
                                <td className="py-1">
                                  <div className="flex items-center gap-2">
                                    <span className="w-10 text-end tabular-nums">{count}</span>
                                    <div className="h-2 rounded bg-rose-500" style={{ width: `${ratio * 100}%`, opacity: Math.max(0.25, ratio) }} />
                                  </div>
                                </td>
                              </tr>
                            )
                          })
                      })()}
                    </tbody>
                  </table>
                </div>
              </div>

              <div className="card p-4 space-y-4">
                <div className="flex items-center gap-2">
                  <Globe className="h-5 w-5 text-sky-400" />
                  <h3 className="text-lg font-semibold text-slate-200">WAF events by country</h3>
                  <div className="flex items-center gap-2 ms-auto text-xs text-slate-400">
                    <span>Low</span>
                    <div className="flex h-3 w-32 rounded overflow-hidden">
                      {[0.2, 0.4, 0.6, 0.8, 1.0].map((o) => (
                        <div key={o} className="flex-1" style={{ background: `rgba(239,68,68,${o})` }} />
                      ))}
                    </div>
                    <span>High</span>
                  </div>
                </div>
                <div className="h-[36rem] w-full overflow-hidden">
                  <ComposableMap
                    projection="geoMercator"
                    width={1200}
                    height={750}
                    projectionConfig={{ scale: 210 }}
                    style={{ width: '100%', height: '100%' }}
                  >
                    <Geographies geography={GEO_URL}>
                      {({ geographies }: any) => {
                        const totals = (countryData?.totals || {}) as Record<string, number>
                        const max = Math.max(1, ...Object.values(totals).map(Number))
                        return geographies.map((geo: any) => {
                          const code = numericToAlpha2(geo.id ?? geo.properties?.id)
                          const count = (code && totals[code]) || 0
                          const ratio = count / max
                          const fill = count ? `rgba(239,68,68,${0.2 + ratio * 0.8})` : '#334155'
                          const name = geo.properties?.name || code || ''
                          return (
                            <path
                              key={geo.rsmKey}
                              d={geo.svgPath}
                              fill={fill}
                              stroke="#1e293b"
                              strokeWidth={0.5}
                            >
                              {count > 0 && <title>{`${name} (${code}): ${count}`}</title>}
                            </path>
                          )
                        })
                      }}
                    </Geographies>
                  </ComposableMap>
                </div>
                <div className="overflow-x-auto max-h-48 overflow-y-auto">
                  <table className="w-full text-sm text-start">
                    <thead className="text-slate-400 border-b border-slate-800 sticky top-0 bg-slate-900">
                      <tr><th className="py-2">Country</th><th className="py-2">Code</th><th className="py-2">Count</th></tr>
                    </thead>
                    <tbody>
                      {(() => {
                        const totals = (countryData?.totals || {}) as Record<string, number>
                        const entries = Object.entries(totals)
                          .filter(([k]) => k !== 'unknown' && k !== 'None' && k !== '')
                          .sort(([, a], [, b]) => (b as number) - (a as number))
                        const max = Math.max(1, ...entries.map(([, v]) => Number(v)))
                        return entries.map(([code, count]) => {
                          const ratio = Number(count) / max
                          const name = alpha2ToName(code) || code
                          return (
                            <tr key={code} className="border-b border-slate-800 last:border-0">
                              <td className="py-1">{name}</td>
                              <td className="py-1 text-slate-500">{code}</td>
                              <td className="py-1">
                                <div className="flex items-center gap-2">
                                  <span className="w-12 text-end tabular-nums">{count}</span>
                                  <div className="h-2 rounded bg-rose-500" style={{ width: `${ratio * 100}%`, opacity: Math.max(0.25, ratio) }} />
                                </div>
                              </td>
                            </tr>
                          )
                        })
                      })()}
                    </tbody>
                  </table>
                </div>
              </div>
            </>
          ) : (
            <div className="card p-4">
              <div className="flex items-center gap-2 mb-2">
                <Shield className="h-5 w-5 text-amber-400" />
                <h3 className="text-lg font-semibold text-slate-200">WAF events</h3>
              </div>
              <p className="text-slate-400 text-sm">No WAF events captured in the selected time range.</p>
            </div>
          )}
        </>
      )}

      {tab === 'bandwidth' && (
        <>
          {bandwidthLoading && !bandwidthData ? (
            <div className="card p-4">
              <p className="text-slate-400 text-sm">Loading bandwidth metrics…</p>
            </div>
          ) : !bandwidthData || bandwidthData.snapshots.length === 0 ? (
            <div className="card p-4">
              <div className="flex items-center gap-2 mb-2">
                <Gauge className="h-5 w-5 text-emerald-400" />
                <h3 className="text-lg font-semibold text-slate-200">{t('pages:metrics.bandwidthSaved')}</h3>
              </div>
              <p className="text-slate-400 text-sm">{t('pages:metrics.noBandwidthMetrics')}</p>
            </div>
          ) : (
            <div className="space-y-6">
              {/* Summary cards */}
              <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4">
                <div className="card p-3">
                  <p className="text-xs text-slate-400">{t('pages:metrics.bandwidth.totalSaved')}</p>
                  <p className="text-xl font-bold text-emerald-400">{fmtBytes(bandwidthData.summary.total_bandwidth_saved)}</p>
                </div>
                <div className="card p-3">
                  <p className="text-xs text-slate-400">{t('pages:metrics.bandwidth.memoryCache')}</p>
                  <p className="text-xl font-semibold text-blue-400">{fmtBytes(bandwidthData.summary.total_memory_cache_bytes_saved)}</p>
                </div>
                <div className="card p-3">
                  <p className="text-xs text-slate-400">{t('pages:metrics.bandwidth.diskCache')}</p>
                  <p className="text-xl font-semibold text-green-400">{fmtBytes(bandwidthData.summary.total_disk_cache_bytes_saved)}</p>
                </div>
                <div className="card p-3">
                  <p className="text-xs text-slate-400">{t('pages:metrics.bandwidth.nativeCompression')}</p>
                  <p className="text-xl font-semibold text-purple-400">{fmtBytes(bandwidthData.summary.total_native_compression_bytes_saved)}</p>
                </div>
                <div className="card p-3">
                  <p className="text-xs text-slate-400">{t('pages:metrics.bandwidth.brotliZstd')}</p>
                  <p className="text-xl font-semibold text-cyan-400">{fmtBytes(bandwidthData.summary.total_brotli_zstd_bytes_saved)}</p>
                </div>
                <div className="card p-3">
                  <p className="text-xs text-slate-400">{t('pages:metrics.bandwidth.webp')}</p>
                  <p className="text-xl font-semibold text-amber-400">{fmtBytes(bandwidthData.summary.total_webp_bytes_saved)}</p>
                </div>
              </div>

              {/* Stacked area chart: bandwidth saved over time by category */}
              <div className="card p-4 space-y-2">
                <h3 className="text-sm font-semibold text-slate-200">{t('pages:metrics.bandwidth.savedOverTime')}</h3>
                <ResponsiveContainer width="100%" height={300}>
                  <AreaChart data={bandwidthData.snapshots.map(s => ({
                    time: formatTimeCompact(s.timestamp),
                    memory_cache: s.memory_cache_bytes_saved,
                    disk_cache: s.disk_cache_bytes_saved,
                    native_compression: s.native_compression_bytes_saved,
                    brotli_zstd: s.brotli_zstd_bytes_saved,
                    webp: s.webp_bytes_saved,
                  }))}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                    <XAxis dataKey="time" tick={{ fontSize: 10 }} stroke="#94a3b8" />
                    <YAxis tick={{ fontSize: 10 }} stroke="#94a3b8" tickFormatter={(v: number) => fmtBytesRate(v)} />
                    <Tooltip
                      contentStyle={{ backgroundColor: '#1e293b', borderColor: '#334155' }}
                      formatter={(v: number) => fmtBytes(v)}
                    />
                    <Legend wrapperStyle={{ fontSize: 10 }} />
                    <Area type="monotone" dataKey="memory_cache" name={t('pages:metrics.bandwidth.memoryCache')} stackId="bw" stroke="#3b82f6" fill="#3b82f6" fillOpacity={0.6} isAnimationActive={false} />
                    <Area type="monotone" dataKey="disk_cache" name={t('pages:metrics.bandwidth.diskCache')} stackId="bw" stroke="#22c55e" fill="#22c55e" fillOpacity={0.6} isAnimationActive={false} />
                    <Area type="monotone" dataKey="native_compression" name={t('pages:metrics.bandwidth.nativeCompression')} stackId="bw" stroke="#a855f7" fill="#a855f7" fillOpacity={0.6} isAnimationActive={false} />
                    <Area type="monotone" dataKey="brotli_zstd" name={t('pages:metrics.bandwidth.brotliZstd')} stackId="bw" stroke="#06b6d4" fill="#06b6d4" fillOpacity={0.6} isAnimationActive={false} />
                    <Area type="monotone" dataKey="webp" name={t('pages:metrics.bandwidth.webp')} stackId="bw" stroke="#f59e0b" fill="#f59e0b" fillOpacity={0.6} isAnimationActive={false} />
                  </AreaChart>
                </ResponsiveContainer>
              </div>

              {/* Per-category line charts */}
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                {([
                  { key: 'memory_cache_bytes_saved', label: t('pages:metrics.bandwidth.memoryCache'), color: '#3b82f6' },
                  { key: 'disk_cache_bytes_saved', label: t('pages:metrics.bandwidth.diskCache'), color: '#22c55e' },
                  { key: 'native_compression_bytes_saved', label: t('pages:metrics.bandwidth.nativeCompression'), color: '#a855f7' },
                  { key: 'brotli_zstd_bytes_saved', label: t('pages:metrics.bandwidth.brotliZstd'), color: '#06b6d4' },
                  { key: 'webp_bytes_saved', label: t('pages:metrics.bandwidth.webp'), color: '#f59e0b' },
                ] as const).map(({ key, label, color }) => (
                  <div key={key} className="card p-4 space-y-2">
                    <h3 className="text-sm font-semibold text-slate-200">{label}</h3>
                    <ResponsiveContainer width="100%" height={180}>
                      <LineChart data={bandwidthData.snapshots.map(s => ({
                        time: formatTimeCompact(s.timestamp),
                        value: s[key],
                      }))}>
                        <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                        <XAxis dataKey="time" tick={{ fontSize: 10 }} stroke="#94a3b8" />
                        <YAxis tick={{ fontSize: 10 }} stroke="#94a3b8" tickFormatter={(v: number) => fmtBytesRate(v)} />
                        <Tooltip
                          contentStyle={{ backgroundColor: '#1e293b', borderColor: '#334155' }}
                          formatter={(v: number) => fmtBytes(v)}
                        />
                        <Line type="monotone" dataKey="value" stroke={color} dot={false} strokeWidth={2} isAnimationActive={false} />
                      </LineChart>
                    </ResponsiveContainer>
                  </div>
                ))}
              </div>
            </div>
          )}
        </>
      )}
    </div>
  )
}

