import { useState, useEffect, useCallback } from 'react'
import { useTranslation } from 'react-i18next'
import { Bot, Settings as SettingsIcon, BarChart3, KeyRound, Plus, Trash2, Save, RefreshCw, Copy, RotateCw } from 'lucide-react'
import { captcha, getErrorDetail } from '../services/api'
import { Tabs } from '../components/ui'
import { useDateTime } from '../contexts/DateTimeContext'
import {
  LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend,
} from 'recharts'

interface CaptchaSettings {
  captcha_provider: string
  captcha_valid_seconds: number
  cap_site_key: string | null
  cap_secret_configured: boolean
  cap_service_url: string
  cap_widget_cdn_url: string
  recaptcha_site_key: string | null
  recaptcha_secret_configured: boolean
  recaptcha_version: string
  recaptcha_min_score: number
  turnstile_site_key: string | null
  turnstile_secret_configured: boolean
  challenge_url: string
  proxy_path: string
}

interface ChallengeStatRow {
  rule_type: string
  rule_id: number | null
  rule_name: string | null
  issued: number
  solved: number
  failed: number
  solve_rate: number
}

interface ChallengeEventRow {
  id: number
  created_at: string
  rule_type: string
  rule_id: number | null
  rule_name: string | null
  event_type: string
  request_id: string | null
  client_ip: string | null
}

interface TimeSeriesPoint {
  bucket: number
  issued: number
  solved: number
  failed: number
}

interface CapKey {
  siteKey: string
  name?: string
  created?: number
  solvesLast24h?: number
  difference?: { value: string; direction: string }
  // Populated from the per-key detail endpoint
  challenges?: number
  verified?: number
  failed?: number
  avgLatency?: number
  rateLimited?: number
}

const PROVIDERS = [
  { value: 'cap', label: 'pages:captcha.settings.providerNative' },
  { value: 'recaptcha', label: 'pages:captcha.settings.providerRecaptcha' },
  { value: 'turnstile', label: 'pages:captcha.settings.providerTurnstile' },
] as const

const TABS_BASE = [
  { id: 'settings', label: 'pages:captcha.tabs.settings', icon: SettingsIcon },
  { id: 'stats', label: 'pages:captcha.tabs.stats', icon: BarChart3 },
] as const

type TabId = 'settings' | 'stats' | 'keys'

export default function Captcha() {
  const { t } = useTranslation(['pages', 'common'])
  const [tab, setTab] = useState<TabId>('settings')
  const [settings, setSettings] = useState<CaptchaSettings | null>(null)
  const [error, setError] = useState('')
  const [success, setSuccess] = useState('')

  const loadSettings = useCallback(async () => {
    try {
      const res = await captcha.settings.get()
      setSettings(res.data)
    } catch (e) {
      setError(getErrorDetail(e))
    }
  }, [])

  useEffect(() => { loadSettings() }, [loadSettings])

  const tabs = settings?.captcha_provider === 'cap'
    ? [...TABS_BASE, { id: 'keys' as const, label: 'pages:captcha.tabs.keys', icon: KeyRound }]
    : TABS_BASE

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-3">
        <Bot className="w-6 h-6 text-primary" />
        <h1 className="text-2xl font-bold">{t('pages:captcha.title')}</h1>
      </div>

      {error && <div className="bg-red-500/10 border border-red-500/30 text-red-400 rounded p-3 text-sm">{error}</div>}
      {success && <div className="bg-green-500/10 border border-green-500/30 text-green-400 rounded p-3 text-sm">{success}</div>}

      {/* Tabs */}
      <Tabs
        tabs={tabs.map(tab => ({ id: tab.id, label: t(tab.label), icon: tab.icon }))}
        active={tab}
        onChange={(id) => setTab(id as TabId)}
      />

      {tab === 'settings' && settings && (
        <SettingsTab
          settings={settings}
          onChange={loadSettings}
          onError={setError}
          onSuccess={setSuccess}
        />
      )}
      {tab === 'stats' && <StatsTab />}
      {tab === 'keys' && settings?.captcha_provider === 'cap' && <KeysTab siteKey={settings.cap_site_key} />}
    </div>
  )
}

// ---------------------------------------------------------------------------
// Settings Tab
// ---------------------------------------------------------------------------

function SettingsTab({ settings, onChange, onError, onSuccess }: {
  settings: CaptchaSettings
  onChange: () => void
  onError: (msg: string) => void
  onSuccess: (msg: string) => void
}) {
  const { t } = useTranslation(['pages', 'common'])
  const [provider, setProvider] = useState(settings.captcha_provider)
  const [ttl, setTtl] = useState(settings.captcha_valid_seconds)
  const [saving, setSaving] = useState(false)

  // Cap fields
  const [capSiteKey, setCapSiteKey] = useState(settings.cap_site_key || '')
  const [capSecret, setCapSecret] = useState('')
  // reCAPTCHA fields
  const [recaptchaSiteKey, setRecaptchaSiteKey] = useState(settings.recaptcha_site_key || '')
  const [recaptchaSecret, setRecaptchaSecret] = useState('')
  const [recaptchaVersion, setRecaptchaVersion] = useState(settings.recaptcha_version)
  const [recaptchaMinScore, setRecaptchaMinScore] = useState(settings.recaptcha_min_score)
  // Turnstile fields
  const [turnstileSiteKey, setTurnstileSiteKey] = useState(settings.turnstile_site_key || '')
  const [turnstileSecret, setTurnstileSecret] = useState('')

  // Sync local state when settings reload
  useEffect(() => {
    setProvider(settings.captcha_provider)
    setTtl(settings.captcha_valid_seconds)
    setCapSiteKey(settings.cap_site_key || '')
    setRecaptchaSiteKey(settings.recaptcha_site_key || '')
    setRecaptchaVersion(settings.recaptcha_version)
    setRecaptchaMinScore(settings.recaptcha_min_score)
    setTurnstileSiteKey(settings.turnstile_site_key || '')
  }, [settings])

  const save = async () => {
    setSaving(true)
    onError('')
    onSuccess('')
    try {
      const payload: Record<string, unknown> = {
        captcha_provider: provider,
        captcha_valid_seconds: ttl,
      }
      if (provider === 'cap') {
        if (capSiteKey) payload.cap_site_key = capSiteKey
        if (capSecret) payload.cap_secret = capSecret
      } else if (provider === 'recaptcha') {
        if (recaptchaSiteKey) payload.recaptcha_site_key = recaptchaSiteKey
        if (recaptchaSecret) payload.recaptcha_secret = recaptchaSecret
        payload.recaptcha_version = recaptchaVersion
        if (recaptchaVersion === 'v3') payload.recaptcha_min_score = recaptchaMinScore
      } else if (provider === 'turnstile') {
        if (turnstileSiteKey) payload.turnstile_site_key = turnstileSiteKey
        if (turnstileSecret) payload.turnstile_secret = turnstileSecret
      }
      await captcha.settings.update(payload)
      onSuccess(t('pages:captcha.settings.settingsSaved'))
      onChange()
    } catch (e) {
      onError(getErrorDetail(e))
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="space-y-6 max-w-2xl">
      {/* Provider selector */}
      <div className="card p-5 space-y-4">
        <h2 className="text-lg font-semibold">{t('pages:captcha.settings.providerTitle')}</h2>
        <div>
          <label className="block text-sm text-slate-400 mb-1">{t('pages:captcha.settings.provider')}</label>
          <select
            className="input w-full"
            value={provider}
            onChange={e => setProvider(e.target.value)}
          >
            {PROVIDERS.map(p => (
              <option key={p.value} value={p.value}>{t(p.label)}</option>
            ))}
          </select>
          <p className="text-xs text-slate-500 mt-1">
            {t('pages:captcha.settings.providerHelp')}
          </p>
        </div>
        <div>
          <label className="block text-sm text-slate-400 mb-1">{t('pages:captcha.settings.challengeValidDuration')}</label>
          <input
            type="number"
            className="input w-full"
            min={0}
            value={ttl}
            onChange={e => setTtl(Number(e.target.value))}
          />
          <p className="text-xs text-slate-500 mt-1">
            {t('pages:captcha.settings.challengeValidDurationHelp')}
          </p>
        </div>
      </div>

      {/* Provider-specific config */}
      {provider === 'cap' && (
        <div className="card p-5 space-y-4">
          <h2 className="text-lg font-semibold">{t('pages:captcha.settings.nativeConfig')}</h2>
          <div>
            <label className="block text-sm text-slate-400 mb-1">{t('pages:captcha.settings.siteKey')}</label>
            <input className="input w-full" value={capSiteKey} onChange={e => setCapSiteKey(e.target.value)} placeholder={t('pages:captcha.settings.siteKeyPlaceholderCap')} />
          </div>
          <div>
            <label className="block text-sm text-slate-400 mb-1">{t('pages:captcha.settings.secret')} {settings.cap_secret_configured && <span className="text-green-400 text-xs">{t('pages:captcha.settings.secretConfigured')}</span>}</label>
            <input className="input w-full" type="password" value={capSecret} onChange={e => setCapSecret(e.target.value)} placeholder={t('pages:captcha.settings.secretPlaceholder')} />
          </div>
          <div className="grid grid-cols-2 gap-3 text-sm pt-2 border-t border-slate-800">
            <div className="text-slate-400">{t('pages:captcha.settings.serviceUrl')}</div>
            <div className="font-mono text-slate-200 text-xs">{settings.cap_service_url}</div>
            <div className="text-slate-400">{t('pages:captcha.settings.widgetCdn')}</div>
            <div className="font-mono text-slate-200 text-xs break-all">{settings.cap_widget_cdn_url}</div>
            <div className="text-slate-400">{t('pages:captcha.settings.challengeUrl')}</div>
            <div className="font-mono text-slate-200 text-xs">{settings.challenge_url}</div>
            <div className="text-slate-400">{t('pages:captcha.settings.proxyPath')}</div>
            <div className="font-mono text-slate-200 text-xs">{settings.proxy_path}</div>
          </div>
        </div>
      )}

      {provider === 'recaptcha' && (
        <div className="card p-5 space-y-4">
          <h2 className="text-lg font-semibold">{t('pages:captcha.settings.recaptchaConfig')}</h2>
          <div>
            <label className="block text-sm text-slate-400 mb-1">{t('pages:captcha.settings.siteKey')}</label>
            <input className="input w-full" value={recaptchaSiteKey} onChange={e => setRecaptchaSiteKey(e.target.value)} placeholder={t('pages:captcha.settings.siteKeyPlaceholderRecaptcha')} />
          </div>
          <div>
            <label className="block text-sm text-slate-400 mb-1">{t('pages:captcha.settings.secret')} {settings.recaptcha_secret_configured && <span className="text-green-400 text-xs">{t('pages:captcha.settings.secretConfigured')}</span>}</label>
            <input className="input w-full" type="password" value={recaptchaSecret} onChange={e => setRecaptchaSecret(e.target.value)} placeholder={t('pages:captcha.settings.secretPlaceholder')} />
          </div>
          <div>
            <label className="block text-sm text-slate-400 mb-1">{t('pages:captcha.settings.version')}</label>
            <select className="input w-full" value={recaptchaVersion} onChange={e => setRecaptchaVersion(e.target.value)}>
              <option value="v2">{t('pages:captcha.settings.versionV2')}</option>
              <option value="v3">{t('pages:captcha.settings.versionV3')}</option>
            </select>
          </div>
          {recaptchaVersion === 'v3' && (
            <div>
              <label className="block text-sm text-slate-400 mb-1">{t('pages:captcha.settings.minimumScore')}</label>
              <input
                type="number"
                className="input w-full"
                min={0}
                max={1}
                step={0.1}
                value={recaptchaMinScore}
                onChange={e => setRecaptchaMinScore(Number(e.target.value))}
              />
              <p className="text-xs text-slate-500 mt-1">
                {t('pages:captcha.settings.minimumScoreHelp')}
              </p>
            </div>
          )}
        </div>
      )}

      {provider === 'turnstile' && (
        <div className="card p-5 space-y-4">
          <h2 className="text-lg font-semibold">{t('pages:captcha.settings.turnstileConfig')}</h2>
          <div>
            <label className="block text-sm text-slate-400 mb-1">{t('pages:captcha.settings.siteKey')}</label>
            <input className="input w-full" value={turnstileSiteKey} onChange={e => setTurnstileSiteKey(e.target.value)} placeholder={t('pages:captcha.settings.siteKeyPlaceholderTurnstile')} />
          </div>
          <div>
            <label className="block text-sm text-slate-400 mb-1">{t('pages:captcha.settings.secret')} {settings.turnstile_secret_configured && <span className="text-green-400 text-xs">{t('pages:captcha.settings.secretConfigured')}</span>}</label>
            <input className="input w-full" type="password" value={turnstileSecret} onChange={e => setTurnstileSecret(e.target.value)} placeholder={t('pages:captcha.settings.secretPlaceholder')} />
          </div>
        </div>
      )}

      {/* Save button */}
      <div className="flex justify-end">
        <button onClick={save} disabled={saving} className="btn-primary px-4 py-2 text-sm flex items-center gap-1.5">
          <Save className="w-4 h-4" />
          {saving ? t('pages:captcha.settings.saving') : t('pages:captcha.settings.saveSettings')}
        </button>
      </div>
    </div>
  )
}

// ---------------------------------------------------------------------------
// Stats Tab
// ---------------------------------------------------------------------------

function StatsTab() {
  const { t } = useTranslation(['pages', 'common'])
  const { formatDateTime } = useDateTime()
  const [stats, setStats] = useState<ChallengeStatRow[]>([])
  const [events, setEvents] = useState<ChallengeEventRow[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [selectedRule, setSelectedRule] = useState<{ type: string; id: number; name: string } | null>(null)
  const [showEvents, setShowEvents] = useState(false)

  const load = useCallback(async () => {
    setLoading(true)
    setError('')
    try {
      const [statsRes, eventsRes] = await Promise.all([
        captcha.stats.list(),
        captcha.stats.events({ limit: 50 }),
      ])
      setStats(statsRes.data)
      setEvents(eventsRes.data)
    } catch (e) {
      setError(getErrorDetail(e))
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { load() }, [load])

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-lg font-semibold">{t('pages:captcha.stats.perRuleSolveRate')}</h2>
          <p className="text-xs text-slate-500 mt-0.5">{t('pages:captcha.stats.last7Days')}</p>
        </div>
        <div className="flex gap-2">
          <button onClick={() => setShowEvents(!showEvents)} className="btn-secondary px-3 py-1.5 text-sm">
            {showEvents ? t('pages:captcha.stats.showSummary') : t('pages:captcha.stats.showEvents')}
          </button>
          <button onClick={load} className="btn-secondary px-3 py-1.5 text-sm flex items-center gap-1.5">
            <RefreshCw className="w-4 h-4" /> {t('pages:captcha.stats.refresh')}
          </button>
        </div>
      </div>
      {error && <div className="bg-red-500/10 border border-red-500/30 text-red-400 rounded p-3 text-sm">{error}</div>}

      {!showEvents ? (
        <>
          {loading ? (
            <div className="text-slate-500 text-sm">{t('pages:captcha.stats.loading')}</div>
          ) : stats.length === 0 ? (
            <div className="text-slate-500 text-sm">{t('pages:captcha.stats.noEvents')}</div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="text-start text-slate-400 border-b border-slate-800">
                    <th className="py-2 px-3">{t('pages:captcha.stats.tableHeaders.ruleType')}</th>
                    <th className="py-2 px-3">{t('pages:captcha.stats.tableHeaders.ruleName')}</th>
                    <th className="py-2 px-3 text-end">{t('pages:captcha.stats.tableHeaders.issued')}</th>
                    <th className="py-2 px-3 text-end">{t('pages:captcha.stats.tableHeaders.solved')}</th>
                    <th className="py-2 px-3 text-end">{t('pages:captcha.stats.tableHeaders.failed')}</th>
                    <th className="py-2 px-3 text-end">{t('pages:captcha.stats.tableHeaders.solveRate')}</th>
                    <th className="py-2 px-3"></th>
                  </tr>
                </thead>
                <tbody>
                  {stats.map((s, i) => (
                    <tr key={i} className="border-b border-slate-800/50 hover:bg-slate-800/30">
                      <td className="py-2 px-3">
                        <span className={`px-2 py-0.5 rounded text-xs ${
                          s.rule_type === 'waf' ? 'bg-orange-500/20 text-orange-400' :
                          s.rule_type === 'security' ? 'bg-cyan-500/20 text-cyan-400' :
                          'bg-purple-500/20 text-purple-400'
                        }`}>{s.rule_type}</span>
                      </td>
                      <td className="py-2 px-3">{s.rule_name || t('pages:captcha.stats.ruleNumber', { id: s.rule_id })}</td>
                      <td className="py-2 px-3 text-end">{s.issued}</td>
                      <td className="py-2 px-3 text-end text-green-400">{s.solved}</td>
                      <td className="py-2 px-3 text-end text-red-400">{s.failed}</td>
                      <td className="py-2 px-3 text-end">{s.solve_rate}%</td>
                      <td className="py-2 px-3">
                        {s.rule_id != null && (
                          <button
                            onClick={() => setSelectedRule({ type: s.rule_type, id: s.rule_id!, name: s.rule_name || t('pages:captcha.stats.ruleNumber', { id: s.rule_id }) })}
                            className="text-primary hover:underline text-xs"
                          >
                            {t('pages:captcha.stats.chart')}
                          </button>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          {selectedRule && (
            <RuleChart ruleType={selectedRule.type} ruleId={selectedRule.id} ruleName={selectedRule.name} onClose={() => setSelectedRule(null)} />
          )}
        </>
      ) : (
        <>
          {loading ? (
            <div className="text-slate-500 text-sm">{t('pages:captcha.stats.loading')}</div>
          ) : events.length === 0 ? (
            <div className="text-slate-500 text-sm">{t('pages:captcha.stats.noEvents')}</div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="text-start text-slate-400 border-b border-slate-800">
                    <th className="py-2 px-3">{t('pages:captcha.stats.eventTableHeaders.time')}</th>
                    <th className="py-2 px-3">{t('pages:captcha.stats.eventTableHeaders.type')}</th>
                    <th className="py-2 px-3">{t('pages:captcha.stats.eventTableHeaders.rule')}</th>
                    <th className="py-2 px-3">{t('pages:captcha.stats.eventTableHeaders.event')}</th>
                    <th className="py-2 px-3">{t('pages:captcha.stats.eventTableHeaders.requestId')}</th>
                  </tr>
                </thead>
                <tbody>
                  {events.map((e) => (
                    <tr key={e.id} className="border-b border-slate-800/50 hover:bg-slate-800/30">
                      <td className="py-2 px-3 text-xs text-slate-400">{formatDateTime(e.created_at)}</td>
                      <td className="py-2 px-3">
                        <span className={`px-2 py-0.5 rounded text-xs ${
                          e.rule_type === 'waf' ? 'bg-orange-500/20 text-orange-400' :
                          e.rule_type === 'security' ? 'bg-cyan-500/20 text-cyan-400' :
                          'bg-purple-500/20 text-purple-400'
                        }`}>{e.rule_type}</span>
                      </td>
                      <td className="py-2 px-3">{e.rule_name || t('pages:captcha.stats.ruleNumber', { id: e.rule_id })}</td>
                      <td className="py-2 px-3">
                        <span className={`text-xs font-medium ${
                          e.event_type === 'solved' ? 'text-green-400' :
                          e.event_type === 'failed' ? 'text-red-400' :
                          'text-blue-400'
                        }`}>{e.event_type}</span>
                      </td>
                      <td className="py-2 px-3 font-mono text-xs text-slate-400">{e.request_id || '—'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </>
      )}
    </div>
  )
}

function RuleChart({ ruleType, ruleId, ruleName, onClose }: {
  ruleType: string
  ruleId: number
  ruleName: string
  onClose: () => void
}) {
  const { t } = useTranslation(['pages', 'common'])
  const { formatDateTimeCompact } = useDateTime()
  const [data, setData] = useState<TimeSeriesPoint[]>([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    let cancelled = false;
    (async () => {
      setLoading(true)
      try {
        const res = await captcha.stats.timeseries(ruleType, ruleId, 168)
        if (!cancelled) setData(res.data)
      } catch { /* ignore */ } finally {
        if (!cancelled) setLoading(false)
      }
    })()
    return () => { cancelled = true }
  }, [ruleType, ruleId])

  const chartData = data.map(d => ({
    ...d,
    time: formatDateTimeCompact(d.bucket * 1000),
  }))

  return (
    <div className="card p-5 space-y-3">
      <div className="flex items-center justify-between">
        <h3 className="font-semibold">{t('pages:captcha.stats.chartTitle', { name: ruleName })}</h3>
        <button onClick={onClose} className="text-slate-400 hover:text-slate-200 text-sm">{t('pages:captcha.stats.close')}</button>
      </div>
      {loading ? (
        <div className="text-slate-500 text-sm">{t('pages:captcha.stats.loading')}</div>
      ) : (
        <ResponsiveContainer width="100%" height={250}>
          <LineChart data={chartData}>
            <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
            <XAxis dataKey="time" stroke="#64748b" fontSize={11} interval={23} />
            <YAxis stroke="#64748b" fontSize={11} allowDecimals={false} />
            <Tooltip contentStyle={{ backgroundColor: '#1e293b', border: '1px solid #334155' }} />
            <Legend />
            <Line type="monotone" dataKey="issued" stroke="#3b82f6" strokeWidth={2} dot={false} />
            <Line type="monotone" dataKey="solved" stroke="#22c55e" strokeWidth={2} dot={false} />
            <Line type="monotone" dataKey="failed" stroke="#ef4444" strokeWidth={2} dot={false} />
          </LineChart>
        </ResponsiveContainer>
      )}
    </div>
  )
}

// ---------------------------------------------------------------------------
// Keys Tab (Cap only)
// ---------------------------------------------------------------------------

function KeysTab({ siteKey }: { siteKey?: string | null }) {
  const { t } = useTranslation(['pages', 'common'])
  const [keys, setKeys] = useState<CapKey[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [showCreate, setShowCreate] = useState(false)
  const [newKeyName, setNewKeyName] = useState('')
  const [createdSecret, setCreatedSecret] = useState<{ siteKey: string; secretKey: string } | null>(null)
  const [rotatedSecret, setRotatedSecret] = useState<{ siteKey: string; secretKey: string } | null>(null)
  const [busy, setBusy] = useState(false)

  const load = useCallback(async () => {
    setLoading(true)
    setError('')
    try {
      const res = await captcha.keys.list()
      const list: CapKey[] = Array.isArray(res.data) ? res.data : []
      // Fetch per-key detail stats in parallel (challenges, verified, failed, etc.)
      const detailed = await Promise.all(
        list.map(async (k) => {
          try {
            const detail = await captcha.keys.get(k.siteKey, 'today')
            const stats = detail.data?.stats
            return { ...k, ...stats }
          } catch {
            return k
          }
        }),
      )
      setKeys(detailed)
    } catch (e) {
      setError(getErrorDetail(e))
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { load() }, [load])

  const copyToClipboard = (text: string) => {
    navigator.clipboard?.writeText(text).catch(() => {})
  }

  const createKey = async () => {
    setBusy(true)
    setError('')
    try {
      const res = await captcha.keys.create({ name: newKeyName || undefined })
      setShowCreate(false)
      setNewKeyName('')
      if (res.data?.secretKey) {
        setCreatedSecret({ siteKey: res.data.siteKey, secretKey: res.data.secretKey })
      }
      load()
    } catch (e) {
      setError(getErrorDetail(e))
    } finally {
      setBusy(false)
    }
  }

  const rotateSecret = async (sk: string) => {
    if (!confirm(t('pages:captcha.keys.confirmRotateSecret', { key: sk }))) return
    setBusy(true)
    setError('')
    try {
      const res = await captcha.keys.rotateSecret(sk)
      if (res.data?.secretKey) {
        setRotatedSecret({ siteKey: sk, secretKey: res.data.secretKey })
      }
    } catch (e) {
      setError(getErrorDetail(e))
    } finally {
      setBusy(false)
    }
  }

  const deleteKey = async (sk: string) => {
    if (!confirm(t('pages:captcha.keys.confirmDeleteKey', { key: sk }))) return
    try {
      await captcha.keys.delete(sk)
      load()
    } catch (e) {
      setError(getErrorDetail(e))
    }
  }

  const SecretBanner = ({ data, onClose }: { data: { siteKey: string; secretKey: string }; onClose: () => void }) => (
    <div className="card p-4 space-y-3 border-amber-500/40">
      <div className="flex items-center justify-between">
        <h3 className="font-semibold text-amber-400">{t('pages:captcha.keys.secretCreatedTitle')}</h3>
        <button onClick={onClose} className="text-slate-400 hover:text-slate-200 text-sm">{t('pages:captcha.stats.close')}</button>
      </div>
      <p className="text-sm text-amber-300/80">{t('pages:captcha.keys.secretWarning')}</p>
      <div className="space-y-2">
        <div>
          <span className="text-xs text-slate-400">{t('pages:captcha.keys.tableHeaders.key')}</span>
          <div className="flex items-center gap-2 mt-0.5">
            <code className="text-slate-200 text-xs flex-1 break-all">{data.siteKey}</code>
            <button onClick={() => copyToClipboard(data.siteKey)} className="text-slate-400 hover:text-slate-200">
              <Copy className="w-4 h-4" />
            </button>
          </div>
        </div>
        <div>
          <span className="text-xs text-slate-400">{t('pages:captcha.keys.secretKey')}</span>
          <div className="flex items-center gap-2 mt-0.5">
            <code className="text-amber-200 text-xs flex-1 break-all">{data.secretKey}</code>
            <button onClick={() => copyToClipboard(data.secretKey)} className="text-slate-400 hover:text-slate-200">
              <Copy className="w-4 h-4" />
            </button>
          </div>
        </div>
      </div>
    </div>
  )

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h2 className="text-lg font-semibold">{t('pages:captcha.keys.title')}</h2>
        <div className="flex gap-2">
          <button onClick={load} className="btn-secondary px-3 py-1.5 text-sm flex items-center gap-1.5">
            <RefreshCw className="w-4 h-4" /> {t('pages:captcha.keys.refresh')}
          </button>
          <button onClick={() => setShowCreate(true)} className="btn-primary px-3 py-1.5 text-sm flex items-center gap-1.5">
            <Plus className="w-4 h-4" /> {t('pages:captcha.keys.newKey')}
          </button>
        </div>
      </div>
      {error && <div className="bg-red-500/10 border border-red-500/30 text-red-400 rounded p-3 text-sm">{error}</div>}
      {createdSecret && <SecretBanner data={createdSecret} onClose={() => setCreatedSecret(null)} />}
      {rotatedSecret && <SecretBanner data={rotatedSecret} onClose={() => setRotatedSecret(null)} />}
      {loading ? (
        <div className="text-slate-500 text-sm">{t('pages:captcha.keys.loading')}</div>
      ) : keys.length === 0 ? (
        <div className="text-slate-500 text-sm">
          {t('pages:captcha.keys.noKeys')}
          {siteKey && <div className="mt-2">{t('pages:captcha.keys.currentSiteKey')} <code className="text-slate-300">{siteKey}</code></div>}
        </div>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-start text-slate-400 border-b border-slate-800">
                <th className="py-2 px-3">{t('pages:captcha.keys.tableHeaders.key')}</th>
                <th className="py-2 px-3">{t('pages:captcha.keys.tableHeaders.name')}</th>
                <th className="py-2 px-3 text-end">{t('pages:captcha.keys.tableHeaders.challenges')}</th>
                <th className="py-2 px-3 text-end">{t('pages:captcha.keys.tableHeaders.verified')}</th>
                <th className="py-2 px-3 text-end">{t('pages:captcha.keys.tableHeaders.failed')}</th>
                <th className="py-2 px-3"></th>
              </tr>
            </thead>
            <tbody>
              {keys.map((k, i) => (
                <tr key={i} className="border-b border-slate-800/50 hover:bg-slate-800/30">
                  <td className="py-2 px-3 font-mono text-xs">{k.siteKey}</td>
                  <td className="py-2 px-3">{k.name || '-'}</td>
                  <td className="py-2 px-3 text-end">{k.challenges ?? '-'}</td>
                  <td className="py-2 px-3 text-end text-green-400">{k.verified ?? '-'}</td>
                  <td className="py-2 px-3 text-end text-red-400">{k.failed ?? '-'}</td>
                  <td className="py-2 px-3">
                    <div className="flex items-center gap-2">
                      <button
                        onClick={() => rotateSecret(k.siteKey)}
                        disabled={busy}
                        title={t('pages:captcha.keys.rotateSecret')}
                        className="text-amber-400 hover:text-amber-300 disabled:opacity-50"
                      >
                        <RotateCw className="w-4 h-4" />
                      </button>
                      <button
                        onClick={() => deleteKey(k.siteKey)}
                        title={t('pages:captcha.keys.deleteKey')}
                        className="text-red-400 hover:text-red-300"
                      >
                        <Trash2 className="w-4 h-4" />
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {showCreate && (
        <div className="card p-5 space-y-3 max-w-md">
          <h3 className="font-semibold">{t('pages:captcha.keys.createNewSiteKey')}</h3>
          <div>
            <label className="block text-sm text-slate-400 mb-1">{t('pages:captcha.keys.nameOptional')}</label>
            <input className="input w-full" value={newKeyName} onChange={e => setNewKeyName(e.target.value)} placeholder={t('pages:captcha.keys.namePlaceholder')} />
          </div>
          <div className="flex gap-2">
            <button onClick={createKey} disabled={busy} className="btn-primary px-4 py-2 text-sm disabled:opacity-50">{t('pages:captcha.keys.create')}</button>
            <button onClick={() => setShowCreate(false)} className="btn-secondary px-4 py-2 text-sm">{t('pages:captcha.keys.cancel')}</button>
          </div>
        </div>
      )}
    </div>
  )
}
