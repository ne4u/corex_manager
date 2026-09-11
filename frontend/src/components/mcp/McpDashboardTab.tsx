import { useEffect, useState, useCallback } from 'react'
import { useTranslation } from 'react-i18next'
import { RefreshCw, Bell, Activity, Zap, AlertTriangle, Gauge, Clock, ServerCrash, Server } from 'lucide-react'
import { mcp } from '../../services/api'
import { Badge } from '../ui'
import { useDateTime } from '../../contexts/DateTimeContext'

interface AlertConfig {
  webhook_url: string | null
  thresholds: Record<string, number>
}

interface AlertHistoryItem {
  id: number
  event_type: string
  message: string
  created_at: string
  webhook_sent: boolean
  webhook_status: number | null
}

interface GatewayMetrics {
  requests_total: number
  auth_success_total: number
  auth_failure_total: number
  policy_denied_total: number
  rate_limited_total: number
  dlp_blocked_total: number
  guardrail_blocked_total: number
  upstream_errors_total: number
  tools_listed_total: number
  tools_called_total: number
  latency_sum_ms: number
  latency_count: number
  latency_buckets: { le: number; count: number }[]
  latency_inf_bucket: number
}

interface GatewayCircuit {
  server_id: number
  failures: number
  open_until: number
}

interface GatewayCatalog {
  server_id: number
  fetched_at: number
  tools: number
  resources: number
  prompts: number
}

interface GatewayAlert {
  event_type: string
  recent_count: number
  threshold: number
  last_alert_ts: number | null
}

interface McpServerInfo {
  id: number
  name: string
  display_name: string | null
  namespace: string
  url: string | null
  enabled: boolean
  transport_type: string
  health_status: string | null
  last_seen_at: string | null
  last_error: string | null
  last_catalog_at: string | null
}

interface GatewayStatus {
  status: string
  configured: boolean
  backend: string
  reachable: boolean
  metrics: GatewayMetrics | null
  active_sessions: number
  open_circuits: GatewayCircuit[]
  catalog_freshness: GatewayCatalog[]
  alerts: GatewayAlert[]
  error: string | null
}

const ALERT_EVENT_TYPES = [
  'guardrail_blocked',
  'dlp_blocked',
  'policy_denied',
  'auth_failed',
  'rate_limited',
]

export default function McpDashboardTab() {
  const { t } = useTranslation(['pages', 'common'])
  const { formatDateTime } = useDateTime()
  const [gatewayStatus, setGatewayStatus] = useState<GatewayStatus | null>(null)
  const [gatewayLoading, setGatewayLoading] = useState(false)
  const [servers, setServers] = useState<McpServerInfo[]>([])
  const [serverNames, setServerNames] = useState<Record<number, string>>({})

  const [alertConfig, setAlertConfig] = useState<AlertConfig>({ webhook_url: '', thresholds: {} })
  const [alertHistory, setAlertHistory] = useState<AlertHistoryItem[]>([])
  const [alertSaving, setAlertSaving] = useState(false)
  const [alertMessage, setAlertMessage] = useState('')

  const fetchServerNames = useCallback(async () => {
    try {
      const resp = await mcp.servers.list()
      const list = resp.data as McpServerInfo[]
      setServers(list)
      const map: Record<number, string> = {}
      for (const s of list) {
        map[s.id] = s.display_name || s.name
      }
      setServerNames(map)
    } catch { /* ignore */ }
  }, [])

  const serverLabel = (id: number) => serverNames[id] || `server #${id}`

  const fetchGatewayStatus = useCallback(async () => {
    setGatewayLoading(true)
    try {
      const resp = await mcp.gateway.status()
      setGatewayStatus(resp.data)
    } catch { setGatewayStatus(null) }
    finally { setGatewayLoading(false) }
  }, [])

  const fetchAlertConfig = useCallback(async () => {
    try {
      const [cfgResp, histResp] = await Promise.all([
        mcp.alerts.getConfig(),
        mcp.alerts.history({ limit: 20 }).catch(() => ({ data: [] })),
      ])
      setAlertConfig(cfgResp.data)
      setAlertHistory(histResp.data)
    } catch { /* ignore */ }
  }, [])

  useEffect(() => {
    fetchServerNames()
    fetchGatewayStatus()
    fetchAlertConfig()
    const interval = setInterval(() => {
      fetchGatewayStatus()
      fetchAlertConfig()
    }, 15000)
    return () => clearInterval(interval)
  }, [fetchServerNames, fetchGatewayStatus, fetchAlertConfig])

  const saveAlertConfig = async () => {
    setAlertSaving(true)
    setAlertMessage('')
    try {
      await mcp.alerts.updateConfig(alertConfig as unknown as Record<string, unknown>)
      setAlertMessage(t('pages:mcpGateway.settings.alertConfigSaved'))
    } catch (err: any) {
      setAlertMessage(err?.response?.data?.detail || t('pages:mcpGateway.settings.saveAlertConfigFailed'))
    } finally { setAlertSaving(false) }
  }

  return (
    <div className="space-y-6">
      {/* Gateway Live Status */}
      <div className="rounded-lg border border-border bg-card p-6 shadow-sm space-y-4">
        <div className="flex items-center justify-between">
          <h2 className="text-lg font-semibold flex items-center gap-2"><Activity className="h-5 w-5 text-primary" /> {t('pages:mcpGateway.settings.gatewayStatus')}</h2>
          <button className="text-muted-foreground hover:text-foreground" onClick={fetchGatewayStatus} disabled={gatewayLoading}>
            <RefreshCw className={`w-4 h-4 ${gatewayLoading ? 'animate-spin' : ''}`} />
          </button>
        </div>

        {!gatewayStatus ? (
          <p className="text-sm text-muted-foreground">{t('pages:mcpGateway.settings.gatewayUnreachable')}</p>
        ) : (
          <>
            <div className="flex items-center gap-3 flex-wrap">
              <Badge variant={gatewayStatus.reachable ? 'success' : 'error'} size="sm">
                {gatewayStatus.reachable ? t('pages:mcpGateway.settings.reachable') : t('pages:mcpGateway.settings.unreachable')}
              </Badge>
              <Badge variant="default" size="sm">{gatewayStatus.backend}</Badge>
              {gatewayStatus.configured && <Badge variant="info" size="sm">{t('pages:mcpGateway.settings.configured')}</Badge>}
              {gatewayStatus.error && <span className="text-xs text-red-400">{gatewayStatus.error}</span>}
            </div>

            {gatewayStatus.metrics && (
              <>
                {/* Counter grid */}
                <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
                  <MetricChip icon={Zap} label={t('pages:mcpGateway.settings.mRequests')} value={gatewayStatus.metrics.requests_total} />
                  <MetricChip icon={Gauge} label={t('pages:mcpGateway.settings.mToolsCalled')} value={gatewayStatus.metrics.tools_called_total} />
                  <MetricChip icon={Gauge} label={t('pages:mcpGateway.settings.mToolsListed')} value={gatewayStatus.metrics.tools_listed_total} />
                  <MetricChip icon={AlertTriangle} label={t('pages:mcpGateway.settings.mAuthFail')} value={gatewayStatus.metrics.auth_failure_total} variant="error" />
                  <MetricChip icon={AlertTriangle} label={t('pages:mcpGateway.settings.mPolicyDenied')} value={gatewayStatus.metrics.policy_denied_total} variant="error" />
                  <MetricChip icon={AlertTriangle} label={t('pages:mcpGateway.settings.mRateLimited')} value={gatewayStatus.metrics.rate_limited_total} variant="warning" />
                  <MetricChip icon={AlertTriangle} label={t('pages:mcpGateway.settings.mDlpBlocked')} value={gatewayStatus.metrics.dlp_blocked_total} variant="error" />
                  <MetricChip icon={AlertTriangle} label={t('pages:mcpGateway.settings.mGuardrailBlocked')} value={gatewayStatus.metrics.guardrail_blocked_total} variant="error" />
                  <MetricChip icon={ServerCrash} label={t('pages:mcpGateway.settings.mUpstreamErrors')} value={gatewayStatus.metrics.upstream_errors_total} variant="error" />
                  <MetricChip icon={Activity} label={t('pages:mcpGateway.settings.mAuthSuccess')} value={gatewayStatus.metrics.auth_success_total} variant="success" />
                </div>

                {/* Latency histogram */}
                {gatewayStatus.metrics.latency_count > 0 && (
                  <div className="border-t border-border pt-3">
                    <h3 className="text-sm font-semibold mb-2 flex items-center gap-2"><Clock className="w-4 h-4" /> {t('pages:mcpGateway.settings.latencyHistogram')}</h3>
                    <LatencyHistogram metrics={gatewayStatus.metrics} />
                    <p className="text-xs text-muted-foreground mt-1">
                      {t('pages:mcpGateway.settings.avgLatency')}: {gatewayStatus.metrics.latency_count > 0 ? (gatewayStatus.metrics.latency_sum_ms / gatewayStatus.metrics.latency_count).toFixed(1) : 0} ms · {t('pages:mcpGateway.settings.samples')}: {gatewayStatus.metrics.latency_count}
                    </p>
                  </div>
                )}
              </>
            )}

            {/* Active sessions */}
            <div className="border-t border-border pt-3 flex items-center gap-2 text-sm">
              <Activity className="w-4 h-4 text-muted-foreground" />
              <span className="text-muted-foreground">{t('pages:mcpGateway.settings.activeSessions')}:</span>
              <span className="font-mono font-semibold">{gatewayStatus.active_sessions}</span>
            </div>

            {/* Open circuit breakers */}
            {gatewayStatus.open_circuits.length > 0 && (
              <div className="border-t border-border pt-3">
                <h3 className="text-sm font-semibold mb-2 flex items-center gap-2 text-red-400"><ServerCrash className="w-4 h-4" /> {t('pages:mcpGateway.settings.openCircuits')}</h3>
                <div className="space-y-1">
                  {gatewayStatus.open_circuits.map(c => (
                    <div key={c.server_id} className="text-xs rounded border border-border px-2 py-1 flex items-center justify-between">
                      <span className="font-mono">{serverLabel(c.server_id)}</span>
                      <span className="text-muted-foreground">{c.failures} failures · resets {new Date(c.open_until * 1000).toLocaleTimeString()}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Catalog freshness */}
            {gatewayStatus.catalog_freshness.length > 0 && (
              <div className="border-t border-border pt-3">
                <h3 className="text-sm font-semibold mb-2">{t('pages:mcpGateway.settings.catalogFreshness')}</h3>
                <div className="space-y-1">
                  {gatewayStatus.catalog_freshness.map(c => (
                    <div key={c.server_id} className="text-xs rounded border border-border px-2 py-1 flex items-center justify-between">
                      <span className="font-mono">{serverLabel(c.server_id)}</span>
                      <span className="text-muted-foreground">
                        {c.tools} tools · {c.resources} resources · {c.prompts} prompts · {c.fetched_at > 0 ? new Date(c.fetched_at * 1000).toLocaleTimeString() : '-'}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Alert state */}
            {gatewayStatus.alerts.length > 0 && (
              <div className="border-t border-border pt-3">
                <h3 className="text-sm font-semibold mb-2 flex items-center gap-2"><AlertTriangle className="w-4 h-4" /> {t('pages:mcpGateway.settings.alertState')}</h3>
                <div className="space-y-1">
                  {gatewayStatus.alerts.map(a => (
                    <div key={a.event_type} className="text-xs rounded border border-border px-2 py-1 flex items-center justify-between">
                      <span className="font-mono">{a.event_type}</span>
                      <span className="text-muted-foreground">
                        {a.recent_count}/{a.threshold}
                        {a.recent_count >= a.threshold && <Badge variant="error" size="sm" className="ms-2">{t('pages:mcpGateway.settings.thresholdExceeded')}</Badge>}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </>
        )}
      </div>

      {/* MCP Server Status */}
      <div className="rounded-lg border border-border bg-card p-6 shadow-sm space-y-4">
        <div className="flex items-center justify-between">
          <h2 className="text-lg font-semibold flex items-center gap-2"><Server className="h-5 w-5 text-primary" /> {t('pages:mcpGateway.settings.serverStatus')}</h2>
          <button className="text-muted-foreground hover:text-foreground" onClick={fetchServerNames}>
            <RefreshCw className="w-4 h-4" />
          </button>
        </div>
        {servers.length === 0 ? (
          <p className="text-sm text-muted-foreground">{t('pages:mcpGateway.settings.noServers')}</p>
        ) : (
          <div className="space-y-1">
            {servers.map(s => {
              const circuit = gatewayStatus?.open_circuits.find(c => c.server_id === s.id)
              const catalog = gatewayStatus?.catalog_freshness.find(c => c.server_id === s.id)
              const healthVariant = s.health_status === 'healthy' ? 'success' : s.health_status === 'unhealthy' || s.health_status === 'stopped' ? 'error' : 'default'
              return (
                <div key={s.id} className="rounded border border-border px-3 py-2 space-y-1">
                  <div className="flex items-center justify-between gap-2">
                    <div className="flex items-center gap-2 min-w-0">
                      <span className="font-medium truncate">{s.display_name || s.name}</span>
                      <Badge variant={s.enabled ? 'success' : 'default'} size="sm">
                        {s.enabled ? t('common:status.enabled') : t('common:status.disabled')}
                      </Badge>
                      <Badge variant={healthVariant} size="sm">{s.health_status || t('common:status.unknown')}</Badge>
                      <Badge variant={s.transport_type === 'stdio' ? 'info' : 'default'} size="sm">
                        {s.transport_type === 'stdio' ? t('pages:mcpGateway.servers.transportStdio') : t('pages:mcpGateway.servers.transportHttp')}
                      </Badge>
                      {circuit && (
                        <Badge variant="error" size="sm">{t('pages:mcpGateway.settings.circuitOpen')}</Badge>
                      )}
                    </div>
                    <div className="flex items-center gap-3 text-xs text-muted-foreground shrink-0">
                      {catalog && (
                        <span>{catalog.tools}T · {catalog.resources}R · {catalog.prompts}P</span>
                      )}
                      {s.last_seen_at && (
                        <span>{t('pages:mcpGateway.settings.lastSeen')}: {formatDateTime(s.last_seen_at)}</span>
                      )}
                    </div>
                  </div>
                  <div className="text-xs text-muted-foreground truncate">{s.namespace} · {s.transport_type === 'stdio' ? t('pages:mcpGateway.servers.transportStdio') : s.url}</div>
                  {s.last_error && <div className="text-xs text-red-400 truncate">{s.last_error}</div>}
                </div>
              )
            })}
          </div>
        )}
      </div>

      {/* Alerting Configuration */}
      <div className="rounded-lg border border-border bg-card p-6 shadow-sm space-y-4">
        <h2 className="text-lg font-semibold flex items-center gap-2"><Bell className="h-5 w-5 text-primary" /> {t('pages:mcpGateway.settings.alerting')}</h2>
        <div>
          <label className="label">{t('pages:mcpGateway.settings.alertWebhookUrl')}</label>
          <input className="input w-full" value={alertConfig.webhook_url || ''} onChange={e => setAlertConfig({ ...alertConfig, webhook_url: e.target.value })} placeholder="https://hooks.slack.com/services/..." />
          <p className="text-xs text-muted-foreground mt-1">{t('pages:mcpGateway.settings.alertWebhookHelp')}</p>
        </div>
        <div>
          <label className="label">{t('pages:mcpGateway.settings.thresholds')}</label>
          <div className="space-y-1">
            {ALERT_EVENT_TYPES.map(evt => (
              <div key={evt} className="flex items-center gap-3">
                <span className="text-sm w-40 font-mono">{evt}</span>
                <input
                  type="number"
                  min={0}
                  className="input w-24"
                  value={alertConfig.thresholds[evt] ?? ''}
                  placeholder="0 = disabled"
                  onChange={e => {
                    const val = e.target.value ? Number(e.target.value) : 0
                    setAlertConfig(prev => ({
                      ...prev,
                      thresholds: { ...prev.thresholds, [evt]: val },
                    }))
                  }}
                />
              </div>
            ))}
          </div>
        </div>
        {alertMessage && <p className={`text-sm ${alertMessage.includes('saved') ? 'text-green-400' : 'text-red-400'}`}>{alertMessage}</p>}
        <button className="btn-primary" onClick={saveAlertConfig} disabled={alertSaving}>{alertSaving ? 'Saving...' : 'Save Alert Config'}</button>

        {alertHistory.length > 0 && (
          <div className="border-t border-border pt-4">
            <h3 className="text-sm font-semibold mb-2">{t('pages:mcpGateway.settings.recentAlerts')}</h3>
            <div className="space-y-1 max-h-48 overflow-y-auto">
              {alertHistory.map(a => (
                <div key={a.id} className="text-xs rounded border border-border px-2 py-1 flex items-center justify-between">
                  <div>
                    <span className="font-mono">{a.event_type}</span>
                    <span className="text-muted-foreground ms-2">{a.message}</span>
                  </div>
                  <div className="flex items-center gap-2">
                    {a.webhook_sent ? (
                      <Badge variant={a.webhook_status === 200 ? 'success' : 'warning'} size="sm">{t('pages:mcpGateway.settings.webhookStatus', { status: a.webhook_status })}</Badge>
                    ) : <Badge variant="default" size="sm">{t('pages:mcpGateway.settings.noWebhook')}</Badge>}
                    <span className="text-muted-foreground">{formatDateTime(a.created_at)}</span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  )
}

function MetricChip({ icon: Icon, label, value, variant }: { icon: typeof Zap; label: string; value: number; variant?: 'success' | 'error' | 'warning' }) {
  const color = variant === 'error' ? 'text-red-400' : variant === 'warning' ? 'text-yellow-400' : variant === 'success' ? 'text-green-400' : 'text-foreground'
  return (
    <div className="rounded border border-border px-2 py-1.5 flex items-center gap-2">
      <Icon className={`w-3.5 h-3.5 ${color}`} />
      <div className="min-w-0">
        <div className="text-xs text-muted-foreground truncate">{label}</div>
        <div className={`text-sm font-mono font-semibold ${color}`}>{value.toLocaleString()}</div>
      </div>
    </div>
  )
}

function LatencyHistogram({ metrics }: { metrics: GatewayMetrics }) {
  const buckets = [...(metrics.latency_buckets || [])]
  if (metrics.latency_inf_bucket > 0) {
    buckets.push({ le: Infinity, count: metrics.latency_inf_bucket })
  }
  const maxCount = Math.max(...buckets.map(b => b.count), 1)
  return (
    <div className="flex items-end gap-1 h-20">
      {buckets.map((b, i) => {
        const heightPct = (b.count / maxCount) * 100
        const label = b.le === Infinity ? '+Inf' : b.le <= 1 ? `${b.le}ms` : `${b.le}ms`
        return (
          <div key={i} className="flex-1 flex flex-col items-center justify-end gap-0.5" title={`${label}: ${b.count}`}>
            <div className="text-[10px] text-muted-foreground">{b.count}</div>
            <div
              className="w-full rounded-t bg-primary/60 hover:bg-primary"
              style={{ height: `${Math.max(heightPct, 2)}%` }}
            />
            <div className="text-[10px] text-muted-foreground truncate w-full text-center">{label}</div>
          </div>
        )
      })}
    </div>
  )
}
