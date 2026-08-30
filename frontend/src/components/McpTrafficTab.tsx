import { useEffect, useState, useCallback } from 'react'
import { useTranslation } from 'react-i18next'
import {
  BarChart, Bar, LineChart, Line, XAxis, YAxis, Tooltip, Legend,
  ResponsiveContainer, CartesianGrid,
} from 'recharts'
import { Activity } from 'lucide-react'
import { mcp } from '../services/api'
import { useDateTime } from '../contexts/DateTimeContext'

interface MetricsResponse {
  time: string[]
  series: { key: string; data: { time: string; count: number }[] }[]
  breakdown: string
  totals: Record<string, number>
  latency: { time: string; p50: number; p99: number; avg: number; count: number }[]
}

const RANGES = [
  { label: '5m', seconds: 300 },
  { label: '15m', seconds: 900 },
  { label: '1h', seconds: 3600 },
  { label: '6h', seconds: 21600 },
  { label: '1d', seconds: 86400 },
  { label: '7d', seconds: 604800 },
]

const BREAKDOWNS = ['action', 'method', 'tool', 'identity', 'server', 'status']

const COLORS = [
  '#3b82f6', '#ef4444', '#f59e0b', '#10b981', '#8b5cf6',
  '#ec4899', '#14b8a6', '#f97316', '#6366f1', '#84cc16',
]

export default function McpTrafficTab() {
  const { t } = useTranslation(['pages', 'common'])
  const { formatTimeCompact, formatDateTime } = useDateTime()
  const [data, setData] = useState<MetricsResponse | null>(null)
  const [loading, setLoading] = useState(true)
  const [range, setRange] = useState(300)
  const [breakdown, setBreakdown] = useState('action')

  const fetchData = useCallback(async () => {
    setLoading(true)
    try {
      const from = new Date(Date.now() - range * 1000).toISOString()
      const resp = await mcp.metrics.get({ from, breakdown })
      setData(resp.data)
    } catch {
      setData(null)
    } finally {
      setLoading(false)
    }
  }, [range, breakdown])

  useEffect(() => {
    fetchData()
    const interval = setInterval(fetchData, 15000)
    return () => clearInterval(interval)
  }, [fetchData])

  // Build chart data: merge series into flat array for Recharts
  const chartData = data?.time.map((time, i) => {
    const row: Record<string, string | number> = { time }
    for (const s of data.series) {
      row[s.key] = s.data[i]?.count ?? 0
    }
    return row
  }) ?? []

  const latencyData = data?.latency.map(l => ({
    time: formatTimeCompact(l.time),
    p50: l.p50,
    p99: l.p99,
    avg: l.avg,
  })) ?? []

  const totalsEntries = data ? Object.entries(data.totals).sort((a, b) => b[1] - a[1]) : []

  return (
    <div className="space-y-6">
      {/* Controls */}
      <div className="flex items-center gap-4 flex-wrap">
        <div className="flex gap-1">
          {RANGES.map(r => (
            <button
              key={r.seconds}
              onClick={() => setRange(r.seconds)}
              className={`px-3 py-1 text-xs rounded-md border transition-colors ${
                range === r.seconds
                  ? 'bg-primary text-primary-foreground border-primary'
                  : 'border-border text-muted-foreground hover:bg-muted'
              }`}
            >
              {r.label}
            </button>
          ))}
        </div>
        <select
          value={breakdown}
          onChange={e => setBreakdown(e.target.value)}
          className="px-3 py-1 text-xs rounded-md border border-border bg-card text-foreground"
        >
          {BREAKDOWNS.map(b => (
            <option key={b} value={b}>{b}</option>
          ))}
        </select>
        <button
          onClick={fetchData}
          className="px-3 py-1 text-xs rounded-md border border-border text-muted-foreground hover:bg-muted"
        >
          {t('common:actions.refresh')}
        </button>
      </div>

      {loading && !data ? (
        <div className="rounded-lg border border-border bg-card p-8 text-center">
          <p className="text-sm text-muted-foreground">{t('common:actions.loading')}</p>
        </div>
      ) : !data || data.time.length === 0 ? (
        <div className="rounded-lg border border-border bg-card p-8 text-center">
          <Activity className="h-8 w-8 mx-auto mb-2 text-muted-foreground" />
          <p className="text-sm text-muted-foreground">
            {t('pages:mcpGateway.traffic.noMetrics')}
          </p>
        </div>
      ) : (
        <>
          {/* Totals */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            {totalsEntries.slice(0, 8).map(([key, count]) => (
              <div key={key} className="rounded-lg border border-border bg-card p-3">
                <div className="text-xs text-muted-foreground truncate">{key}</div>
                <div className="text-2xl font-bold">{count}</div>
              </div>
            ))}
          </div>

          {/* Stacked bar chart */}
          <div className="rounded-lg border border-border bg-card p-4">
            <h3 className="text-sm font-medium mb-3">
              {t('pages:mcpGateway.traffic.eventsByBreakdown')} {breakdown}
            </h3>
            <ResponsiveContainer width="100%" height={280}>
              <BarChart data={chartData}>
                <CartesianGrid strokeDasharray="3 3" className="opacity-30" />
                <XAxis dataKey="time" tickFormatter={formatTimeCompact} fontSize={11} />
                <YAxis fontSize={11} allowDecimals={false} />
                <Tooltip
                  labelFormatter={(label) => formatDateTime(label as string)}
                  contentStyle={{ backgroundColor: 'var(--color-card)', border: '1px solid var(--color-border)', borderRadius: '6px' }}
                />
                <Legend />
                {data.series.map((s, i) => (
                  <Bar
                    key={s.key}
                    dataKey={s.key}
                    stackId="a"
                    fill={COLORS[i % COLORS.length]}
                  />
                ))}
              </BarChart>
            </ResponsiveContainer>
          </div>

          {/* Latency chart */}
          <div className="rounded-lg border border-border bg-card p-4">
            <h3 className="text-sm font-medium mb-3">
              {t('pages:mcpGateway.traffic.latency')}
            </h3>
            <ResponsiveContainer width="100%" height={200}>
              <LineChart data={latencyData}>
                <CartesianGrid strokeDasharray="3 3" className="opacity-30" />
                <XAxis dataKey="time" fontSize={11} />
                <YAxis fontSize={11} allowDecimals={false} />
                <Tooltip
                  contentStyle={{ backgroundColor: 'var(--color-card)', border: '1px solid var(--color-border)', borderRadius: '6px' }}
                />
                <Legend />
                <Line type="monotone" dataKey="p50" stroke="#10b981" strokeWidth={2} dot={false} name="p50" />
                <Line type="monotone" dataKey="p99" stroke="#ef4444" strokeWidth={2} dot={false} name="p99" />
                <Line type="monotone" dataKey="avg" stroke="#3b82f6" strokeWidth={1} strokeDasharray="4 4" dot={false} name="avg" />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </>
      )}
    </div>
  )
}
