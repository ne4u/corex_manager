import { useEffect, useState, useCallback } from 'react'
import { useTranslation } from 'react-i18next'
import { Settings as SettingsIcon, RefreshCw, Bell } from 'lucide-react'
import { settings, mcp } from '../../services/api'
import { Badge } from '../ui'
import { useDateTime } from '../../contexts/DateTimeContext'

interface Team { id: number; name: string; slug: string }

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

const ALERT_EVENT_TYPES = [
  'guardrail_blocked',
  'dlp_blocked',
  'policy_denied',
  'auth_failed',
  'rate_limited',
]

export default function McpSettingsTab() {
  const { t } = useTranslation(['pages', 'common'])
  const { formatDateTime } = useDateTime()
  const [allowedOrigins, setAllowedOrigins] = useState('')
  const [jwtIssuer, setJwtIssuer] = useState('')
  const [jwtAudience, setJwtAudience] = useState('')
  const [jwtJwksUrl, setJwtJwksUrl] = useState('')
  const [logPayloads, setLogPayloads] = useState(false)
  const [defaultRpm, setDefaultRpm] = useState(60)
  const [perIpLimit, setPerIpLimit] = useState(120)
  const [concurrentLimit, setConcurrentLimit] = useState(10)
  const [teams, setTeams] = useState<Team[]>([])
  const [teamRpmOverrides, setTeamRpmOverrides] = useState<Record<number, number>>({})
  const [saving, setSaving] = useState(false)
  const [message, setMessage] = useState('')

  const [configStatus, setConfigStatus] = useState<{ last_generated: string | null; bundle_size: number | null } | null>(null)
  const [regenerating, setRegenerating] = useState(false)
  const [regenMessage, setRegenMessage] = useState('')

  const [alertConfig, setAlertConfig] = useState<AlertConfig>({ webhook_url: '', thresholds: {} })
  const [alertHistory, setAlertHistory] = useState<AlertHistoryItem[]>([])
  const [alertSaving, setAlertSaving] = useState(false)
  const [alertMessage, setAlertMessage] = useState('')

  const fetchSettings = useCallback(async () => {
    try {
      const [teamsResp] = await Promise.all([mcp.teams.list()])
      setTeams(teamsResp.data)

      const keys = ['mcp_allowed_origins', 'mcp_jwt_issuer', 'mcp_jwt_audience', 'mcp_jwt_jwks_url', 'mcp_log_payloads', 'mcp_default_rpm', 'mcp_per_ip_limit', 'mcp_concurrent_limit', 'mcp_team_rpm_overrides']
      const results = await Promise.all(keys.map(k => settings.get(k).catch(() => ({ data: { value: '' } }))))
      setAllowedOrigins(results[0].data.value || '')
      setJwtIssuer(results[1].data.value || '')
      setJwtAudience(results[2].data.value || '')
      setJwtJwksUrl(results[3].data.value || '')
      setLogPayloads((results[4].data.value || 'false').toLowerCase() === 'true')
      setDefaultRpm(Number(results[5].data.value) || 60)
      setPerIpLimit(Number(results[6].data.value) || 120)
      setConcurrentLimit(Number(results[7].data.value) || 10)
      try {
        const overrides = JSON.parse(results[8].data.value || '{}')
        setTeamRpmOverrides(overrides)
      } catch { setTeamRpmOverrides({}) }
    } catch { /* ignore */ }
  }, [])

  const fetchConfigStatus = useCallback(async () => {
    try {
      const resp = await mcp.config.status()
      setConfigStatus(resp.data)
    } catch { setConfigStatus(null) }
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
    fetchSettings()
    fetchConfigStatus()
    fetchAlertConfig()
  }, [fetchSettings, fetchConfigStatus, fetchAlertConfig])

  const saveSettings = async () => {
    setSaving(true)
    setMessage('')
    try {
      await Promise.all([
        settings.update('mcp_allowed_origins', { value: allowedOrigins }),
        settings.update('mcp_jwt_issuer', { value: jwtIssuer }),
        settings.update('mcp_jwt_audience', { value: jwtAudience }),
        settings.update('mcp_jwt_jwks_url', { value: jwtJwksUrl }),
        settings.update('mcp_log_payloads', { value: String(logPayloads) }),
        settings.update('mcp_default_rpm', { value: String(defaultRpm) }),
        settings.update('mcp_per_ip_limit', { value: String(perIpLimit) }),
        settings.update('mcp_concurrent_limit', { value: String(concurrentLimit) }),
        settings.update('mcp_team_rpm_overrides', { value: JSON.stringify(teamRpmOverrides) }),
      ])
      setMessage(t('pages:mcpGateway.settings.settingsSaved'))
    } catch (err: any) {
      setMessage(err?.response?.data?.detail || t('pages:mcpGateway.settings.saveSettingsFailed'))
    } finally { setSaving(false) }
  }

  const regenerate = async () => {
    setRegenerating(true)
    setRegenMessage('')
    try {
      await mcp.config.regenerate()
      setRegenMessage(t('pages:mcpGateway.settings.regenerated'))
      fetchConfigStatus()
    } catch (err: any) {
      setRegenMessage(err?.response?.data?.detail || t('pages:mcpGateway.settings.regenerateFailed'))
    } finally { setRegenerating(false) }
  }

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
      {/* General Settings */}
      <div className="card space-y-4 max-w-3xl">
        <h2 className="text-lg font-semibold flex items-center gap-2"><SettingsIcon className="h-5 w-5 text-primary" /> {t('pages:mcpGateway.settings.generalTitle')}</h2>

        <div>
          <label className="label">{t('pages:mcpGateway.settings.allowedOrigins')}</label>
          <input className="input w-full" value={allowedOrigins} onChange={e => setAllowedOrigins(e.target.value)} placeholder="https://claude.ai,https://cursor.sh" />
          <p className="text-xs text-muted-foreground mt-1">{t('pages:mcpGateway.settings.allowedOriginsHelp')}</p>
        </div>

        <div className="border-t border-border pt-4">
          <h3 className="text-sm font-semibold mb-2">{t('pages:mcpGateway.settings.jwtConfig')}</h3>
          <div className="space-y-3">
            <div>
              <label className="label">{t('pages:mcpGateway.settings.jwtIssuer')}</label>
              <input className="input w-full" value={jwtIssuer} onChange={e => setJwtIssuer(e.target.value)} placeholder="https://auth.example.com" />
            </div>
            <div>
              <label className="label">{t('pages:mcpGateway.settings.jwtAudience')}</label>
              <input className="input w-full" value={jwtAudience} onChange={e => setJwtAudience(e.target.value)} placeholder="mcp-gateway" />
            </div>
            <div>
              <label className="label">{t('pages:mcpGateway.settings.jwksUrl')}</label>
              <input className="input w-full" value={jwtJwksUrl} onChange={e => setJwtJwksUrl(e.target.value)} placeholder="https://auth.example.com/.well-known/jwks.json" />
            </div>
          </div>
        </div>

        <div className="border-t border-border pt-4">
          <h3 className="text-sm font-semibold mb-2">{t('pages:mcpGateway.settings.rateLimiting')}</h3>
          <div className="grid grid-cols-3 gap-4">
            <div>
              <label className="label">{t('pages:mcpGateway.settings.defaultRpm')}</label>
              <input type="number" min={0} className="input w-full" value={defaultRpm} onChange={e => setDefaultRpm(Number(e.target.value))} />
            </div>
            <div>
              <label className="label">{t('pages:mcpGateway.settings.perIpLimit')}</label>
              <input type="number" min={0} className="input w-full" value={perIpLimit} onChange={e => setPerIpLimit(Number(e.target.value))} />
            </div>
            <div>
              <label className="label">{t('pages:mcpGateway.settings.concurrentLimit')}</label>
              <input type="number" min={0} className="input w-full" value={concurrentLimit} onChange={e => setConcurrentLimit(Number(e.target.value))} />
            </div>
          </div>
          {teams.length > 0 && (
            <div className="mt-3">
              <label className="label">{t('pages:mcpGateway.settings.teamRpmOverrides')}</label>
              <div className="space-y-1">
                {teams.map(tm => (
                  <div key={tm.id} className="flex items-center gap-3">
                    <span className="text-sm w-32 truncate">{tm.name}</span>
                    <input
                      type="number"
                      min={0}
                      className="input w-24"
                      value={teamRpmOverrides[tm.id] ?? ''}
                      placeholder={String(defaultRpm)}
                      onChange={e => {
                        const val = e.target.value ? Number(e.target.value) : undefined
                        setTeamRpmOverrides(prev => {
                          const next = { ...prev }
                          if (val === undefined) delete next[tm.id]
                          else next[tm.id] = val
                          return next
                        })
                      }}
                    />
                    <span className="text-xs text-muted-foreground">{t('pages:mcpGateway.settings.rpm')}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>

        <div className="border-t border-border pt-4">
          <label className="flex items-center gap-2">
            <input type="checkbox" checked={logPayloads} onChange={e => setLogPayloads(e.target.checked)} />
            <span className="text-sm">{t('pages:mcpGateway.settings.logPayloads')}</span>
          </label>
        </div>

        {message && <p className={`text-sm ${message.includes('saved') ? 'text-green-400' : 'text-red-400'}`}>{message}</p>}
        <button className="btn-primary" onClick={saveSettings} disabled={saving}>{saving ? t('common:actions.saving') : t('pages:mcpGateway.settings.saveSettings')}</button>
      </div>

      {/* Config Bundle Status */}
      <div className="card space-y-4 max-w-3xl">
        <h2 className="text-lg font-semibold flex items-center gap-2"><RefreshCw className="h-5 w-5 text-primary" /> {t('pages:mcpGateway.settings.configBundle')}</h2>
        <div className="flex items-center gap-4 text-sm">
          {configStatus?.last_generated ? (
            <>
              <Badge variant="success" size="sm">{t('pages:mcpGateway.settings.generated')}</Badge>
              <span className="text-muted-foreground">{t('pages:mcpGateway.settings.lastGenerated')} {formatDateTime(configStatus.last_generated)}</span>
              {configStatus.bundle_size != null && <span className="text-muted-foreground">({(configStatus.bundle_size / 1024).toFixed(1)} KB)</span>}
            </>
          ) : (
            <Badge variant="warning" size="sm">{t('common:status.unknown')}</Badge>
          )}
        </div>
        <button className="btn-secondary" onClick={regenerate} disabled={regenerating}>
          {regenerating ? <RefreshCw className="w-4 h-4 inline me-1 animate-spin" /> : <RefreshCw className="w-4 h-4 inline me-1" />}
          {t('pages:mcpGateway.settings.regenerate')}
        </button>
        {regenMessage && <p className={`text-sm ${regenMessage.includes('regenerated') ? 'text-green-400' : 'text-red-400'}`}>{regenMessage}</p>}
      </div>

      {/* Alerting Configuration */}
      <div className="card space-y-4 max-w-3xl">
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
