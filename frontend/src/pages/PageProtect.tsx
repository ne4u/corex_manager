import React, { useState, useEffect, useCallback } from 'react'
import { useTranslation } from 'react-i18next'
import { ScanEye, Plus, Trash2, RefreshCw, Download, AlertTriangle, CheckCircle2, Play, Square, Wand2, LayoutDashboard, Shield, FileCode, ClipboardList, Settings as SettingsIcon, History, Pencil, Activity, RotateCcw, ChevronUp, ChevronDown, ArrowUpDown } from 'lucide-react'
import { pageProtect, backends, getErrorDetail, settings as settingsApi } from '../services/api'
import useApiList from '../hooks/useApiList'
import Modal from '../components/Modal'
import { Tabs, IconButton } from '../components/ui'
import { useDateTime } from '../contexts/DateTimeContext'

interface PageProtectPolicy {
  id: number
  name: string
  enabled: boolean
  backend_ids: number[]
  mode: string
  sample_rate_percent: number
  report_path: string
  directives: Record<string, string[]>
  created_at: string
  updated_at: string
}

interface CspReport {
  id: number
  policy_id: number | null
  captured_at: string
  client_ip: string | null
  document_uri: string | null
  referrer: string | null
  violated_directive: string | null
  effective_directive: string | null
  original_policy: string | null
  blocked_uri: string | null
  source_file: string | null
  line_number: number | null
  column_number: number | null
  status_code: number | null
  script_sample: string | null
  backend_name: string | null
  listener_name: string | null
  report_type: string | null
}

interface PageProtectScript {
  id: number
  url: string
  resource_type: string | null
  first_seen: string
  last_seen: string
  occurrence_count: number
  domain: string | null
  first_hash: string | null
  first_hash_at: string | null
  last_hash: string | null
  last_hash_at: string | null
  hash_checked_at: string | null
  hash_changed: boolean
  notes: string | null
  source: string | null
}

interface PageProtectStats {
  total_scripts: number
  total_reports: number
  changed_scripts: number
  active_policies: number
  reports_24h: number
  top_violated_directives: { directive: string; count: number }[]
  top_blocked_uris: { uri: string; count: number }[]
}

interface PageProtectSettings {
  monitoring_enabled: boolean
  change_detection_enabled: boolean
  change_detection_interval_hours: number
  report_retention_days: number
  report_path: string
  beacon_injection_enabled: boolean
  beacon_path: string
  beacon_script_path: string
  beacon_content_types: string
  beacon_path_patterns: string
  beacon_backend_ids: number[]
  auto_prune_stale_days: number
}

interface BaselineStatus {
  status: 'idle' | 'baselining' | 'complete'
  start?: string
  end?: string
  note: string
  elapsed_seconds?: number
  duration_seconds?: number
  scripts_count?: number
  reports_count?: number
  distinct_ips?: number
  distinct_pages?: number
}

interface RecommendSource {
  origin: string
  occurrence_count: number
  distinct_ips: number
  sample_url: string
}

interface RecommendSummary {
  scripts_analyzed: number
  reports_analyzed: number
  baseline_start: string
  baseline_end: string
  directives_count: number
  backend_filter: string[] | null
}

interface RecommendResponse {
  directives: Record<string, string[]>
  warnings: string[]
  sources: Record<string, RecommendSource[]>
  summary: RecommendSummary
}

const CSP_DIRECTIVES = [
  'default-src', 'script-src', 'connect-src', 'img-src', 'style-src',
  'font-src', 'frame-src', 'object-src', 'media-src', 'worker-src',
  'base-uri', 'form-action', 'report-uri', 'upgrade-insecure-requests',
]

const COMMON_SOURCES = ["'self'", "'none'", "'unsafe-inline'", "'unsafe-eval'", "'strict-dynamic'"]
void COMMON_SOURCES

type Tab = 'dashboard' | 'policies' | 'scripts' | 'reports' | 'settings' | 'baseline'

export default function PageProtect() {
  const { t } = useTranslation(['pages', 'common'])
  const [tab, setTab] = useState<Tab>('dashboard')
  const [stats, setStats] = useState<PageProtectStats | null>(null)
  const { items: backendList } = useApiList<any>(backends.list)

  const loadStats = useCallback(async () => {
    try {
      const r = await pageProtect.stats()
      setStats(r.data)
    } catch (e) {
      console.error(e)
    }
  }, [])

  useEffect(() => {
    if (tab === 'dashboard') loadStats()
  }, [tab, loadStats])

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-2">
        <h2 className="text-2xl font-bold flex items-center gap-2">
          <ScanEye className="h-5 w-5 text-primary" /> {t('pages:pageProtect.title')}
        </h2>
      </div>
      <p className="text-sm text-slate-400">
        {t('pages:pageProtect.description')}
      </p>
      <Tabs
        tabs={[
          { id: 'dashboard', label: t('pages:pageProtect.tabs.dashboard'), icon: LayoutDashboard },
          { id: 'policies', label: t('pages:pageProtect.tabs.policies'), icon: Shield },
          { id: 'scripts', label: t('pages:pageProtect.tabs.scripts'), icon: FileCode },
          { id: 'reports', label: t('pages:pageProtect.tabs.reports'), icon: ClipboardList },
          { id: 'baseline', label: t('pages:pageProtect.tabs.baseline'), icon: History },
          { id: 'settings', label: t('pages:pageProtect.tabs.settings'), icon: SettingsIcon },
        ]}
        active={tab}
        onChange={(id) => setTab(id as Tab)}
      />

      {tab === 'dashboard' && <DashboardTab stats={stats} reload={loadStats} />}
      {tab === 'policies' && <PoliciesTab backendList={backendList} />}
      {tab === 'scripts' && <ScriptsTab />}
      {tab === 'reports' && <ReportsTab />}
      {tab === 'settings' && <SettingsTab reloadStats={loadStats} />}
      {tab === 'baseline' && <BaselineTab />}
    </div>
  )
}

function DashboardTab({ stats, reload }: { stats: PageProtectStats | null; reload: () => void }) {
  const { t } = useTranslation(['pages', 'common'])
  useEffect(() => {
    const iv = setInterval(reload, 15000)
    return () => clearInterval(iv)
  }, [reload])

  if (!stats) return <div className="text-slate-400">{t('pages:pageProtect.dashboard.loading')}</div>

  const cards = [
    { label: t('pages:pageProtect.dashboard.totalScripts'), value: stats.total_scripts, color: 'text-blue-400' },
    { label: t('pages:pageProtect.dashboard.violations24h'), value: stats.reports_24h, color: 'text-amber-400' },
    { label: t('pages:pageProtect.dashboard.changedScripts'), value: stats.changed_scripts, color: stats.changed_scripts > 0 ? 'text-red-400' : 'text-green-400' },
    { label: t('pages:pageProtect.dashboard.activePolicies'), value: stats.active_policies, color: 'text-primary' },
  ]

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {cards.map(c => (
          <div key={c.label} className="card p-4">
            <div className="text-sm text-slate-400">{c.label}</div>
            <div className={`text-3xl font-bold ${c.color}`}>{c.value}</div>
          </div>
        ))}
      </div>
      <div className="grid md:grid-cols-2 gap-4">
        <div className="card p-4">
          <h3 className="font-semibold mb-3">{t('pages:pageProtect.dashboard.topViolatedDirectives')}</h3>
          {stats.top_violated_directives.length === 0 ? (
            <div className="text-sm text-slate-500">{t('pages:pageProtect.dashboard.noData')}</div>
          ) : (
            <table className="w-full text-sm">
              <tbody>
                {stats.top_violated_directives.map((d, i) => (
                  <tr key={i} className="border-b border-slate-800 last:border-0">
                    <td className="py-2 font-mono text-slate-300">{d.directive}</td>
                    <td className="py-2 text-end text-slate-400">{d.count}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
        <div className="card p-4">
          <h3 className="font-semibold mb-3">{t('pages:pageProtect.dashboard.topBlockedUris')}</h3>
          {stats.top_blocked_uris.length === 0 ? (
            <div className="text-sm text-slate-500">{t('pages:pageProtect.dashboard.noData')}</div>
          ) : (
            <table className="w-full text-sm">
              <tbody>
                {stats.top_blocked_uris.map((u, i) => (
                  <tr key={i} className="border-b border-slate-800 last:border-0">
                    <td className="py-2 font-mono text-slate-300 truncate max-w-xs">{u.uri}</td>
                    <td className="py-2 text-end text-slate-400">{u.count}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>
    </div>
  )
}

function BaselineTab() {
  const { t } = useTranslation(['pages', 'common'])
  const { formatDateTime } = useDateTime()
  const [baseline, setBaseline] = useState<BaselineStatus | null>(null)
  const [loading, setLoading] = useState(false)
  const [note, setNote] = useState('')
  const [error, setError] = useState('')

  const load = useCallback(async () => {
    try {
      const r = await pageProtect.baseline.get()
      setBaseline(r.data)
      setNote(r.data.note || '')
    } catch (e) {
      console.error(e)
    }
  }, [])

  useEffect(() => {
    load()
    const iv = setInterval(load, 5000)
    return () => clearInterval(iv)
  }, [load])

  const startBaseline = async () => {
    setLoading(true); setError('')
    try {
      const r = await pageProtect.baseline.start(note)
      setBaseline(r.data)
    } catch (e) { setError(getErrorDetail(e)) }
    finally { setLoading(false) }
  }

  const stopBaseline = async () => {
    setLoading(true); setError('')
    try {
      const r = await pageProtect.baseline.stop()
      setBaseline(r.data)
    } catch (e) { setError(getErrorDetail(e)) }
    finally { setLoading(false) }
  }

  const clearBaseline = async () => {
    if (!window.confirm(t('pages:pageProtect.baseline.confirmClear'))) return
    setLoading(true); setError('')
    try {
      const r = await pageProtect.baseline.clear()
      setBaseline(r.data)
      setNote('')
    } catch (e) { setError(getErrorDetail(e)) }
    finally { setLoading(false) }
  }

  if (!baseline) return <div className="text-slate-400">{t('pages:pageProtect.dashboard.loading')}</div>

  const status = baseline.status
  const elapsed = baseline.elapsed_seconds || 0
  const duration = baseline.duration_seconds || 0
  const fmtTime = (s: number) => {
    const h = Math.floor(s / 3600)
    const m = Math.floor((s % 3600) / 60)
    const sec = s % 60
    return h > 0 ? `${h}h ${m}m` : m > 0 ? `${m}m ${sec}s` : `${sec}s`
  }

  return (
    <div className="space-y-4">
      <div className="card p-6 space-y-4">
        <div className="flex items-center justify-between">
          <h3 className="text-lg font-semibold flex items-center gap-2">
            <ScanEye className="h-5 w-5 text-primary" /> {t('pages:pageProtect.baseline.title')}
          </h3>
          <div className="flex items-center gap-2">
            {status === 'baselining' && (
              <span className="flex items-center gap-1 text-sm text-amber-400">
                <span className="inline-block w-2 h-2 rounded-full bg-amber-400 animate-pulse" />
                {t('pages:pageProtect.baseline.baselining', { elapsed: fmtTime(elapsed) })}
              </span>
            )}
            {status === 'complete' && (
              <span className="flex items-center gap-1 text-sm text-green-400">
                <CheckCircle2 className="w-4 h-4" /> {t('pages:pageProtect.baseline.complete', { duration: fmtTime(duration) })}
              </span>
            )}
            {status === 'idle' && (
              <span className="text-sm text-slate-500">{t('pages:pageProtect.baseline.noBaselineWindow')}</span>
            )}
          </div>
        </div>

        <p className="text-sm text-slate-400">
          {t('pages:pageProtect.baseline.description')}
        </p>

        {error && <div className="text-sm text-red-400">{error}</div>}

        <div className="grid grid-cols-2 gap-3">
          <div>
            <label className="label">{t('pages:pageProtect.baseline.noteOptional')}</label>
            <input
              className="input"
              value={note}
              onChange={e => setNote(e.target.value)}
              placeholder={t('pages:pageProtect.baseline.notePlaceholder')}
              disabled={status === 'baselining'}
            />
          </div>
          <div>
            <label className="label">{t('pages:pageProtect.baseline.window')}</label>
            <div className="input text-sm text-slate-400">
              {baseline.start ? (
                <>
                  {formatDateTime(baseline.start)}
                  {baseline.end ? <> → {formatDateTime(baseline.end)}</> : ` → ${t('pages:pageProtect.baseline.windowInProgress')}`}
                </>
              ) : '—'}
            </div>
          </div>
        </div>

        {(baseline.scripts_count !== undefined || baseline.reports_count !== undefined) && (
          <div className="grid grid-cols-4 gap-3">
            <div className="bg-slate-800/50 rounded-lg p-3 text-center">
              <div className="text-2xl font-bold text-blue-400">{baseline.scripts_count ?? 0}</div>
              <div className="text-xs text-slate-400">{t('pages:pageProtect.baseline.scripts')}</div>
            </div>
            <div className="bg-slate-800/50 rounded-lg p-3 text-center">
              <div className="text-2xl font-bold text-amber-400">{baseline.reports_count ?? 0}</div>
              <div className="text-xs text-slate-400">{t('pages:pageProtect.baseline.reports')}</div>
            </div>
            <div className="bg-slate-800/50 rounded-lg p-3 text-center">
              <div className="text-2xl font-bold text-purple-400">{baseline.distinct_ips ?? 0}</div>
              <div className="text-xs text-slate-400">{t('pages:pageProtect.baseline.distinctIps')}</div>
            </div>
            <div className="bg-slate-800/50 rounded-lg p-3 text-center">
              <div className="text-2xl font-bold text-green-400">{baseline.distinct_pages ?? 0}</div>
              <div className="text-xs text-slate-400">{t('pages:pageProtect.baseline.pagesObserved')}</div>
            </div>
          </div>
        )}

        <div className="flex gap-2">
          {status === 'idle' && (
            <button onClick={startBaseline} disabled={loading} className="btn-primary flex items-center gap-2">
              <Play className="w-4 h-4" /> {t('pages:pageProtect.baseline.startBaselining')}
            </button>
          )}
          {status === 'baselining' && (
            <button onClick={stopBaseline} disabled={loading} className="btn-primary flex items-center gap-2">
              <Square className="w-4 h-4" /> {t('pages:pageProtect.baseline.stopBaselining')}
            </button>
          )}
          {status === 'complete' && (
            <>
              <button onClick={startBaseline} disabled={loading} className="btn-secondary flex items-center gap-2">
                <Play className="w-4 h-4" /> {t('pages:pageProtect.baseline.redo')}
              </button>
              <button onClick={clearBaseline} disabled={loading} className="btn-secondary text-red-400">
                {t('pages:pageProtect.baseline.clear')}
              </button>
            </>
          )}
        </div>

        {status === 'baselining' && (
          <div className="text-xs text-slate-500">
            Tip: Crawl your site (or have users browse all pages) during the window to ensure
            complete resource coverage. The counts above update every 5 seconds.
          </div>
        )}
      </div>
    </div>
  )
}

function PoliciesTab({ backendList }: { backendList: any[] }) {
  const { formatDateTime } = useDateTime()
  const { items: policies, reload } = useApiList<PageProtectPolicy>(pageProtect.policies.list)
  const { items: scripts } = useApiList<PageProtectScript>(pageProtect.scripts.list)
  const [open, setOpen] = useState(false)
  const [editing, setEditing] = useState<number | null>(null)
  const [recommendOpen, setRecommendOpen] = useState(false)
  const [recommendData, setRecommendData] = useState<RecommendResponse | null>(null)
  const [recommendLoading, setRecommendLoading] = useState(false)
  const [recommendError, setRecommendError] = useState('')
  const initialForm = {
    name: '',
    enabled: true,
    backend_ids: [] as number[],
    mode: 'monitor',
    sample_rate_percent: 100,
    report_path: '/_csp-report',
    directives: {} as Record<string, string[]>,
  }
  const [form, setForm] = useState<any>(initialForm)

  const openAdd = () => { setEditing(null); setForm(initialForm); setOpen(true) }
  const openEdit = (p: PageProtectPolicy) => {
    setEditing(p.id)
    setForm({ ...p, directives: p.directives || {} })
    setOpen(true)
  }

  const submit = async (e: React.FormEvent) => {
    e.preventDefault()
    try {
      if (editing) await pageProtect.policies.update(editing, form)
      else await pageProtect.policies.create(form)
      setOpen(false)
      reload()
    } catch (err) {
      alert(getErrorDetail(err))
    }
  }

  const remove = async (id: number) => {
    if (!window.confirm('Delete this policy?')) return
    try {
      await pageProtect.policies.remove(id)
      reload()
    } catch (err) {
      alert(getErrorDetail(err))
    }
  }

  const fetchRecommendation = async () => {
    setRecommendLoading(true); setRecommendError('')
    try {
      const r = await pageProtect.recommend(form.backend_ids.length ? form.backend_ids : undefined)
      setRecommendData(r.data)
      setRecommendOpen(true)
    } catch (e) {
      setRecommendError(getErrorDetail(e))
    } finally {
      setRecommendLoading(false)
    }
  }

  const applyRecommendation = () => {
    if (!recommendData) return
    setForm({ ...form, directives: { ...recommendData.directives } })
    setRecommendOpen(false)
  }

  const addDirective = () => {
    const d = { ...form.directives }
    const key = CSP_DIRECTIVES.find((dir) => !(dir in d)) || `directive-${Object.keys(d).length + 1}`
    d[key] = []
    setForm({ ...form, directives: d })
  }

  const updateDirectiveName = (oldKey: string, newKey: string) => {
    const d = { ...form.directives }
    if (oldKey !== newKey) {
      d[newKey] = d[oldKey] || []
      delete d[oldKey]
    }
    setForm({ ...form, directives: d })
  }

  const removeDirective = (key: string) => {
    const d = { ...form.directives }
    delete d[key]
    setForm({ ...form, directives: d })
  }

  const addSource = (key: string, source: string) => {
    if (!source.trim()) return
    const d = { ...form.directives }
    d[key] = [...(d[key] || []), source.trim()]
    setForm({ ...form, directives: d })
  }

  const removeSource = (key: string, idx: number) => {
    const d = { ...form.directives }
    d[key] = (d[key] || []).filter((_: string, i: number) => i !== idx)
    setForm({ ...form, directives: d })
  }

  const previewCsp = () => {
    const parts: string[] = []
    for (const [directive, sources] of Object.entries(form.directives)) {
      const srcList = sources as string[]
      if (srcList && srcList.length > 0) {
        parts.push(`${directive} ${srcList.join(' ')}`)
      } else {
        parts.push(directive)
      }
    }
    return parts.join('; ')
  }

  const suggestScripts = scripts.filter(s => s.resource_type === 'script')
  const suggestConnections = scripts.filter(s => s.resource_type === 'connect')

  const renderBackend = (p: PageProtectPolicy) =>
    p.backend_ids?.length ? p.backend_ids.map(id => backendList.find(b => b.id === id)?.name).filter(Boolean).join(', ') : 'All'

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h3 className="text-lg font-semibold">CSP Policies</h3>
        <button onClick={openAdd} className="btn-primary"><Plus className="w-4 h-4 inline me-1" /> Add Policy</button>
      </div>
      <div className="card overflow-x-auto">
        <table className="w-full text-sm text-start">
          <thead className="text-slate-400 border-b border-slate-800">
            <tr><th>Name</th><th>Backends</th><th>Mode</th><th>Sample</th><th>Enabled</th><th></th></tr>
          </thead>
          <tbody>
            {policies.map(p => (
              <tr key={p.id} className="border-b border-slate-800 last:border-0">
                <td className="py-2 font-medium">{p.name}</td>
                <td className="text-slate-400">{renderBackend(p)}</td>
                <td>
                  <span className={`px-2 py-0.5 rounded text-xs ${p.mode === 'enforce' ? 'bg-red-500/20 text-red-300' : 'bg-amber-500/20 text-amber-300'}`}>
                    {p.mode === 'enforce' ? 'Enforce' : 'Monitor'}
                  </span>
                </td>
                <td className="text-slate-400">{p.sample_rate_percent}%</td>
                <td>{p.enabled ? <CheckCircle2 className="w-4 h-4 text-green-400" /> : <span className="text-slate-500">off</span>}</td>
                <td>
                  <div className="flex gap-1">
                    <IconButton icon={Pencil} aria-label="Edit" onClick={() => openEdit(p)} />
                    <IconButton icon={Trash2} variant="danger" aria-label="Delete" onClick={() => remove(p.id)} />
                  </div>
                </td>
              </tr>
            ))}
            {policies.length === 0 && <tr><td colSpan={6} className="py-4 text-center text-slate-500">No policies yet</td></tr>}
          </tbody>
        </table>
      </div>

      <Modal open={open} onClose={() => setOpen(false)} title={editing ? 'Edit Policy' : 'Add Policy'}>
        <form onSubmit={submit} className="space-y-4">
          <div className="grid grid-cols-2 gap-3">
            <div><label className="label">Name</label><input className="input" value={form.name} onChange={e => setForm({ ...form, name: e.target.value })} required /></div>
            <div><label className="label">Mode</label><select className="input" value={form.mode} onChange={e => setForm({ ...form, mode: e.target.value })}><option value="monitor">Monitor (Report-Only)</option><option value="enforce">Enforce (Block)</option></select></div>
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div><label className="label">Sample Rate (%)</label><input type="number" min={1} max={100} className="input" value={form.sample_rate_percent} onChange={e => setForm({ ...form, sample_rate_percent: parseInt(e.target.value) || 100 })} /></div>
            <div><label className="label">Report Path</label><input className="input" value={form.report_path} onChange={e => setForm({ ...form, report_path: e.target.value })} /></div>
          </div>
          <div>
            <label className="label">Backends (none = all)</label>
            <div className="input h-auto max-h-32 overflow-y-auto p-2 space-y-1 text-sm text-slate-300">
              {backendList.map(b => (
                <label key={b.id} className="flex items-center gap-2">
                  <input type="checkbox" className="rounded border-slate-600 bg-slate-800 text-primary" checked={form.backend_ids.includes(b.id)} onChange={e => setForm({ ...form, backend_ids: e.target.checked ? [...form.backend_ids, b.id] : form.backend_ids.filter((id: number) => id !== b.id) })} />
                  {b.name}
                </label>
              ))}
              {backendList.length === 0 && <span className="text-slate-500">No backends configured</span>}
            </div>
          </div>
          <div className="flex items-center gap-2">
            <input type="checkbox" id="pp-enabled" className="rounded border-slate-600 bg-slate-800 text-primary" checked={form.enabled} onChange={e => setForm({ ...form, enabled: e.target.checked })} />
            <label htmlFor="pp-enabled" className="text-sm text-slate-300">Enabled</label>
          </div>

          <div className="border-t border-slate-800 pt-4">
            <div className="flex items-center justify-between mb-2">
              <h4 className="font-semibold">CSP Directives</h4>
              <div className="flex gap-2">
                <button
                  type="button"
                  onClick={fetchRecommendation}
                  disabled={recommendLoading}
                  className="btn-secondary text-sm flex items-center gap-1"
                  title="Generate a policy from observed scripts and violation reports"
                >
                  <Wand2 className="w-3 h-3" /> {recommendLoading ? 'Analyzing…' : 'Recommend Policy'}
                </button>
                <button type="button" onClick={addDirective} className="btn-secondary text-sm"><Plus className="w-3 h-3 inline me-1" /> Add Directive</button>
              </div>
            </div>
            {recommendError && <div className="text-xs text-red-400 mb-2">{recommendError}</div>}
            {Object.entries(form.directives).map(([key, sources]) => (
              <div key={key} className="mb-3 p-3 bg-slate-800/50 rounded-lg">
                <div className="flex items-center gap-2 mb-2">
                  <select className="input flex-1" value={key} onChange={e => updateDirectiveName(key, e.target.value)}>
                    {CSP_DIRECTIVES.map(d => <option key={d} value={d}>{d}</option>)}
                  </select>
                  <button type="button" onClick={() => removeDirective(key)} className="text-red-400 hover:underline"><Trash2 className="w-4 h-4" /></button>
                </div>
                <div className="flex flex-wrap gap-1 mb-2">
                  {(sources as string[]).map((s, i) => (
                    <span key={i} className="px-2 py-0.5 bg-slate-700 rounded text-xs flex items-center gap-1">
                      <span className="font-mono">{s}</span>
                      <button type="button" onClick={() => removeSource(key, i)} className="text-red-400">&times;</button>
                    </span>
                  ))}
                  {(sources as string[]).length === 0 && <span className="text-xs text-slate-500">No sources (flag-only directive)</span>}
                </div>
                <SourceInput onAdd={(src) => addSource(key, src)} />
              </div>
            ))}
            {Object.keys(form.directives).length === 0 && <div className="text-sm text-slate-500">No directives added yet</div>}
          </div>

          {(suggestScripts.length > 0 || suggestConnections.length > 0) && (
            <div className="border-t border-slate-800 pt-4">
              <h4 className="font-semibold mb-2">Auto-Suggest from Inventory</h4>
              {suggestScripts.length > 0 && (
                <div className="mb-2">
                  <div className="text-xs text-slate-400 mb-1">Detected scripts (add to script-src):</div>
                  <div className="flex flex-wrap gap-1">
                    {suggestScripts.slice(0, 20).map(s => (
                      <button key={s.id} type="button" onClick={() => {
                        const d = { ...form.directives }
                        const existing = d['script-src'] || []
                        if (!existing.includes(s.url)) d['script-src'] = [...existing, s.url]
                        setForm({ ...form, directives: d })
                      }} className="px-2 py-0.5 bg-blue-500/20 text-blue-300 rounded text-xs hover:bg-blue-500/30">
                        + {s.domain || s.url}
                      </button>
                    ))}
                  </div>
                </div>
              )}
              {suggestConnections.length > 0 && (
                <div>
                  <div className="text-xs text-slate-400 mb-1">Detected connections (add to connect-src):</div>
                  <div className="flex flex-wrap gap-1">
                    {suggestConnections.slice(0, 20).map(s => (
                      <button key={s.id} type="button" onClick={() => {
                        const d = { ...form.directives }
                        const existing = d['connect-src'] || []
                        if (!existing.includes(s.url)) d['connect-src'] = [...existing, s.url]
                        setForm({ ...form, directives: d })
                      }} className="px-2 py-0.5 bg-purple-500/20 text-purple-300 rounded text-xs hover:bg-purple-500/30">
                        + {s.domain || s.url}
                      </button>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}

          <div className="border-t border-slate-800 pt-4">
            <label className="label">CSP Header Preview</label>
            <pre className="bg-slate-800 p-3 rounded text-xs font-mono text-slate-300 overflow-x-auto">{previewCsp() || '(empty)'}</pre>
          </div>

          <button className="btn-primary w-full">Save</button>
        </form>
      </Modal>

      {/* Recommendation review modal */}
      <Modal open={recommendOpen} onClose={() => setRecommendOpen(false)} title="Recommended CSP Policy">
        {recommendData && (
          <div className="space-y-4">
            <div className="text-sm text-slate-400">
              Based on <span className="text-slate-200 font-medium">{recommendData.summary.scripts_analyzed}</span> scripts
              {' and '}
              <span className="text-slate-200 font-medium">{recommendData.summary.reports_analyzed}</span> violation reports
              {recommendData.summary.baseline_start && (
                <> within the baseline window ({recommendData.summary.baseline_start
                  ? formatDateTime(recommendData.summary.baseline_start)
                  : ''}{recommendData.summary.baseline_end
                  ? ` → ${formatDateTime(recommendData.summary.baseline_end)}`
                  : ' → now'})</>
              )}
              {recommendData.summary.backend_filter && (
                <> for backends: {recommendData.summary.backend_filter.join(', ')}</>
              )}
              .
            </div>

            {recommendData.warnings.length > 0 && (
              <div className="bg-amber-500/10 border border-amber-500/30 rounded-lg p-3 space-y-1">
                <div className="text-sm font-semibold text-amber-400 flex items-center gap-1">
                  <AlertTriangle className="w-4 h-4" /> Warnings ({recommendData.warnings.length})
                </div>
                {recommendData.warnings.map((w, i) => (
                  <div key={i} className="text-xs text-amber-300">{w}</div>
                ))}
              </div>
            )}

            <div>
              <label className="label">Recommended Directives</label>
              <pre className="bg-slate-800 p-3 rounded text-xs font-mono text-slate-300 overflow-x-auto max-h-60 overflow-y-auto">
                {Object.entries(recommendData.directives)
                  .map(([d, srcs]) => srcs.length > 0 ? `${d} ${srcs.join(' ')}` : d)
                  .join('; ')}
              </pre>
            </div>

            {/* Per-origin details */}
            {Object.keys(recommendData.sources).length > 0 && (
              <div>
                <label className="label">Origin Details</label>
                <div className="space-y-2 max-h-48 overflow-y-auto">
                  {Object.entries(recommendData.sources).map(([directive, origins]) => (
                    <div key={directive}>
                      <div className="text-xs text-slate-400 mb-1">{directive}</div>
                      <table className="w-full text-xs">
                        <thead className="text-slate-500">
                          <tr><th className="text-start py-1">Origin</th><th className="text-end py-1">Occurrences</th><th className="text-end py-1">Distinct IPs</th></tr>
                        </thead>
                        <tbody>
                          {origins.map((o, i) => (
                            <tr key={i} className="border-t border-slate-800">
                              <td className="py-1 font-mono text-slate-300">{o.origin}</td>
                              <td className="py-1 text-end text-slate-400">{o.occurrence_count}</td>
                              <td className={`py-1 text-end ${o.distinct_ips < 2 ? 'text-amber-400' : 'text-slate-400'}`}>{o.distinct_ips}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  ))}
                </div>
              </div>
            )}

            <div className="text-xs text-slate-500">
              Review the recommendations above. Click Apply to populate the policy form — you can
              edit further before saving. Origins seen from fewer than 2 distinct IPs are highlighted
              in amber and may be attacker probes.
            </div>

            <div className="flex gap-2">
              <button onClick={applyRecommendation} className="btn-primary flex-1">Apply to Form</button>
              <button onClick={() => setRecommendOpen(false)} className="btn-secondary">Cancel</button>
            </div>
          </div>
        )}
      </Modal>
    </div>
  )
}

function SourceInput({ onAdd }: { onAdd: (source: string) => void }) {
  const [value, setValue] = useState('')
  return (
    <div className="flex gap-2">
      <input
        className="input flex-1 text-sm"
        placeholder="Add source (e.g. 'self', https://cdn.example.com)"
        value={value}
        onChange={e => setValue(e.target.value)}
        onKeyDown={e => {
          if (e.key === 'Enter') {
            e.preventDefault()
            onAdd(value)
            setValue('')
          }
        }}
      />
      <button type="button" onClick={() => { onAdd(value); setValue('') }} className="btn-secondary text-sm">Add</button>
    </div>
  )
}

type ScriptSortKey = 'url' | 'resource_type' | 'domain' | 'source' | 'occurrence_count' | 'last_seen' | 'last_hash_at' | 'hash_status'
type SortDir = 'asc' | 'desc'

function SortTh({ label, sortKey, activeKey, dir, onSort }: {
  label: string
  sortKey: ScriptSortKey
  activeKey: ScriptSortKey | null
  dir: SortDir
  onSort: (key: ScriptSortKey) => void
}) {
  const isActive = activeKey === sortKey
  return (
    <th>
      <button
        onClick={() => onSort(sortKey)}
        className="inline-flex items-center gap-1 hover:text-slate-200 cursor-pointer select-none"
      >
        {label}
        {isActive ? (
          dir === 'asc'
            ? <ChevronUp className="w-3.5 h-3.5" />
            : <ChevronDown className="w-3.5 h-3.5" />
        ) : (
          <ArrowUpDown className="w-3 h-3 opacity-40" />
        )}
      </button>
    </th>
  )
}

function ScriptsTab() {
  const { formatDateTime } = useDateTime()
  const { items: scripts, reload } = useApiList<PageProtectScript>(pageProtect.scripts.list)
  const [filterType, setFilterType] = useState('')
  const [filterChanged, setFilterChanged] = useState('')
  const [checking, setChecking] = useState(false)
  const [showAddForm, setShowAddForm] = useState(false)
  const [newUrl, setNewUrl] = useState('')
  const [newType, setNewType] = useState('script')
  const [adding, setAdding] = useState(false)
  const [sortKey, setSortKey] = useState<ScriptSortKey | null>(null)
  const [sortDir, setSortDir] = useState<SortDir>('asc')

  const toggleSort = (key: ScriptSortKey) => {
    if (sortKey === key) {
      setSortDir(d => d === 'asc' ? 'desc' : 'asc')
    } else {
      setSortKey(key)
      setSortDir('asc')
    }
  }

  const filtered = scripts.filter(s => {
    if (filterType && s.resource_type !== filterType) return false
    if (filterChanged === 'changed' && !s.hash_changed) return false
    if (filterChanged === 'unchanged' && s.hash_changed) return false
    return true
  })

  const sorted = (() => {
    if (!sortKey) return filtered
    const dir = sortDir === 'asc' ? 1 : -1
    const getVal = (s: PageProtectScript): string | number => {
      switch (sortKey) {
        case 'url': return s.url || ''
        case 'resource_type': return s.resource_type || ''
        case 'domain': return s.domain || ''
        case 'source': return s.source || ''
        case 'occurrence_count': return s.occurrence_count || 0
        case 'last_seen': return s.last_seen || ''
        case 'last_hash_at': return s.last_hash_at || ''
        case 'hash_status': {
          // Derive a sortable rank: Error(0) < Changed(1) < Unchecked(2) < OK(3)
          const checkFailed = s.hash_checked_at && (!s.last_hash_at || s.hash_checked_at > s.last_hash_at)
          if (checkFailed) return 0
          if (s.hash_changed) return 1
          if (s.last_hash) return 3
          return 2
        }
      }
    }
    return [...filtered].sort((a, b) => {
      const va = getVal(a), vb = getVal(b)
      if (typeof va === 'number' && typeof vb === 'number') return (va - vb) * dir
      return String(va).localeCompare(String(vb)) * dir
    })
  })()

  const checkAll = async () => {
    setChecking(true)
    try {
      await pageProtect.scripts.checkAll()
      reload()
    } catch (err) {
      alert(getErrorDetail(err))
    } finally {
      setChecking(false)
    }
  }

  const checkOne = async (id: number) => {
    try {
      await pageProtect.scripts.check(id)
      reload()
    } catch (err) {
      alert(getErrorDetail(err))
    }
  }

  const remove = async (id: number) => {
    if (!window.confirm('Remove this script from inventory?')) return
    try {
      await pageProtect.scripts.remove(id)
      reload()
    } catch (err) {
      alert(getErrorDetail(err))
    }
  }

  const resetHash = async (id: number) => {
    if (!window.confirm('Reset hash baseline for this asset? The next check will establish a fresh baseline.')) return
    try {
      await pageProtect.scripts.resetHash(id)
      reload()
    } catch (err) {
      alert(getErrorDetail(err))
    }
  }

  const addAsset = async () => {
    if (!newUrl.trim()) return
    setAdding(true)
    try {
      await pageProtect.scripts.create({ url: newUrl.trim(), resource_type: newType })
      setNewUrl('')
      setNewType('script')
      setShowAddForm(false)
      reload()
    } catch (err) {
      alert(getErrorDetail(err))
    } finally {
      setAdding(false)
    }
  }

  const sourceBadge = (source: string | null) => {
    if (source === 'manual') return <span className="text-xs px-1.5 py-0.5 rounded bg-blue-500/20 text-blue-400">Manual</span>
    if (source === 'beacon') return <span className="text-xs px-1.5 py-0.5 rounded bg-purple-500/20 text-purple-400">Beacon</span>
    return <span className="text-xs px-1.5 py-0.5 rounded bg-slate-500/20 text-slate-400">CSP</span>
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between flex-wrap gap-2">
        <h3 className="text-lg font-semibold">Script & Connection Inventory</h3>
        <div className="flex gap-2 items-center">
          <select className="input text-sm" value={filterType} onChange={e => setFilterType(e.target.value)}>
            <option value="">All Types</option>
            <option value="script">Script</option>
            <option value="connect">Connect</option>
            <option value="img">Image</option>
            <option value="style">Style</option>
            <option value="font">Font</option>
            <option value="frame">Frame</option>
            <option value="object">Object</option>
            <option value="other">Other</option>
          </select>
          <select className="input text-sm" value={filterChanged} onChange={e => setFilterChanged(e.target.value)}>
            <option value="">All</option>
            <option value="changed">Changed</option>
            <option value="unchanged">Unchanged</option>
          </select>
          <button onClick={() => setShowAddForm(!showAddForm)} className="btn-secondary text-sm">
            <Plus className="w-4 h-4 inline me-1" /> Add Asset
          </button>
          <button onClick={checkAll} disabled={checking} className="btn-secondary text-sm">
            <RefreshCw className={`w-4 h-4 inline me-1 ${checking ? 'animate-spin' : ''}`} /> Check All
          </button>
        </div>
      </div>
      {showAddForm && (
        <div className="card flex flex-wrap gap-2 items-end">
          <div className="flex-1 min-w-[200px]">
            <label className="label">URL</label>
            <input
              className="input"
              placeholder="https://cdn.example.com/script.js"
              value={newUrl}
              onChange={e => setNewUrl(e.target.value)}
              onKeyDown={e => e.key === 'Enter' && addAsset()}
              autoFocus
            />
          </div>
          <div>
            <label className="label">Type</label>
            <select className="input" value={newType} onChange={e => setNewType(e.target.value)}>
              <option value="script">Script</option>
              <option value="connect">Connect</option>
              <option value="img">Image</option>
              <option value="style">Style</option>
              <option value="font">Font</option>
              <option value="frame">Frame</option>
              <option value="object">Object</option>
              <option value="other">Other</option>
            </select>
          </div>
          <button onClick={addAsset} disabled={adding || !newUrl.trim()} className="btn-primary text-sm">
            {adding ? 'Adding...' : 'Add'}
          </button>
          <button onClick={() => setShowAddForm(false)} className="btn-secondary text-sm">Cancel</button>
        </div>
      )}
      <div className="card overflow-x-auto">
        <table className="w-full text-sm text-start">
          <thead className="text-slate-400 border-b border-slate-800">
            <tr>
              <SortTh label="URL" sortKey="url" activeKey={sortKey} dir={sortDir} onSort={toggleSort} />
              <SortTh label="Type" sortKey="resource_type" activeKey={sortKey} dir={sortDir} onSort={toggleSort} />
              <SortTh label="Domain" sortKey="domain" activeKey={sortKey} dir={sortDir} onSort={toggleSort} />
              <SortTh label="Source" sortKey="source" activeKey={sortKey} dir={sortDir} onSort={toggleSort} />
              <SortTh label="Occurrences" sortKey="occurrence_count" activeKey={sortKey} dir={sortDir} onSort={toggleSort} />
              <SortTh label="Last Seen" sortKey="last_seen" activeKey={sortKey} dir={sortDir} onSort={toggleSort} />
              <SortTh label="Last Checked" sortKey="last_hash_at" activeKey={sortKey} dir={sortDir} onSort={toggleSort} />
              <SortTh label="Hash Status" sortKey="hash_status" activeKey={sortKey} dir={sortDir} onSort={toggleSort} />
              <th></th>
            </tr>
          </thead>
          <tbody>
            {sorted.map(s => (
              <tr key={s.id} className="border-b border-slate-800 last:border-0">
                <td className="py-2 font-mono text-xs truncate max-w-xs" title={s.url}>{s.url}</td>
                <td className="text-slate-400">{s.resource_type}</td>
                <td className="text-slate-400">{s.domain}</td>
                <td>{sourceBadge(s.source)}</td>
                <td className="text-slate-400">{s.occurrence_count}</td>
                <td className="text-slate-400 text-xs">{s.last_seen ? formatDateTime(s.last_seen) : ''}</td>
                <td className="text-slate-400 text-xs">{s.last_hash_at ? formatDateTime(s.last_hash_at) : ''}</td>
                <td>
                  {(() => {
                    // A check was attempted but failed if hash_checked_at is set
                    // and last_hash_at is None or older than hash_checked_at.
                    const checkFailed = s.hash_checked_at && (!s.last_hash_at || s.hash_checked_at > s.last_hash_at)
                    if (checkFailed) {
                      return <span className="flex items-center gap-1 text-amber-400 text-xs"><AlertTriangle className="w-3 h-3" /> Error</span>
                    }
                    if (s.hash_changed) {
                      return <span className="flex items-center gap-1 text-red-400 text-xs"><AlertTriangle className="w-3 h-3" /> Changed</span>
                    }
                    if (s.last_hash) {
                      return <span className="flex items-center gap-1 text-green-400 text-xs"><CheckCircle2 className="w-3 h-3" /> OK</span>
                    }
                    return <span className="text-slate-500 text-xs">Unchecked</span>
                  })()}
                </td>
                <td>
                  <div className="flex gap-1">
                    <IconButton icon={Activity} aria-label="Check" onClick={() => checkOne(s.id)} />
                    <IconButton icon={RotateCcw} aria-label="Reset Hash" onClick={() => resetHash(s.id)} />
                    <IconButton icon={Trash2} variant="danger" aria-label="Delete" onClick={() => remove(s.id)} />
                  </div>
                </td>
              </tr>
            ))}
            {sorted.length === 0 && <tr><td colSpan={9} className="py-4 text-center text-slate-500">No scripts detected yet</td></tr>}
          </tbody>
        </table>
      </div>
    </div>
  )
}

function extractHostname(uri: string | null): string {
  if (!uri) return '-'
  try { return new URL(uri).hostname || '-' } catch { return '-' }
}

function ReportsTab() {
  const { formatDateTime } = useDateTime()
  const [reports, setReports] = useState<CspReport[]>([])
  const [loading, setLoading] = useState(true)
  const [filters, setFilters] = useState({ violated_directive: '', host: '' })
  const [expanded, setExpanded] = useState<number | null>(null)

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const params: Record<string, unknown> = { limit: 200 }
      if (filters.violated_directive) params.violated_directive = filters.violated_directive
      const r = await pageProtect.reports.list(params)
      setReports(r.data)
    } catch (e) {
      console.error(e)
    } finally {
      setLoading(false)
    }
  }, [filters.violated_directive])

  useEffect(() => { load() }, [load])

  const exportCsv = async () => {
    try {
      const r = await pageProtect.reports.export()
      const url = URL.createObjectURL(new Blob([r.data]))
      const a = document.createElement('a')
      a.href = url
      a.download = 'csp_reports.csv'
      a.click()
      URL.revokeObjectURL(url)
    } catch (err) {
      alert(getErrorDetail(err))
    }
  }

  const clearAll = async () => {
    if (!window.confirm('Delete all CSP reports? This cannot be undone.')) return
    try {
      await pageProtect.reports.clear()
      load()
    } catch (err) {
      alert(getErrorDetail(err))
    }
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between flex-wrap gap-2">
        <h3 className="text-lg font-semibold">CSP Violation Reports</h3>
        <div className="flex gap-2">
          <button onClick={exportCsv} className="btn-secondary text-sm"><Download className="w-4 h-4 inline me-1" /> Export CSV</button>
          <button onClick={clearAll} className="btn-secondary text-sm text-red-400"><Trash2 className="w-4 h-4 inline me-1" /> Clear All</button>
        </div>
      </div>
      <div className="flex gap-2 flex-wrap">
        <input className="input text-sm flex-1" placeholder="Filter by violated directive..." value={filters.violated_directive} onChange={e => setFilters({ ...filters, violated_directive: e.target.value })} />
        <input className="input text-sm flex-1" placeholder="Filter by hostname..." value={filters.host} onChange={e => setFilters({ ...filters, host: e.target.value })} />
      </div>
      <div className="card overflow-x-auto">
        <table className="w-full text-sm text-start">
          <thead className="text-slate-400 border-b border-slate-800">
            <tr><th>Time</th><th>Client IP</th><th>Document URI</th><th>Directive</th><th>Blocked URI</th><th>Hostname</th></tr>
          </thead>
          <tbody>
            {loading ? (
              <tr><td colSpan={6} className="py-4 text-center text-slate-500">Loading...</td></tr>
            ) : reports.length === 0 ? (
              <tr><td colSpan={6} className="py-4 text-center text-slate-500">No reports</td></tr>
            ) : reports.filter(r => !filters.host || extractHostname(r.document_uri).includes(filters.host)).map(r => (
              <React.Fragment key={r.id}>
                <tr
                  className="border-b border-slate-800 last:border-0 cursor-pointer hover:bg-slate-800/50"
                  onClick={() => setExpanded(expanded === r.id ? null : r.id)}
                >
                  <td className="py-2 text-xs text-slate-400">{formatDateTime(r.captured_at)}</td>
                  <td className="text-slate-300 font-mono text-xs">{r.client_ip}</td>
                  <td className="font-mono text-xs truncate max-w-xs" title={r.document_uri || ''}>{r.document_uri}</td>
                  <td className="font-mono text-xs text-amber-300">{r.violated_directive}</td>
                  <td className="font-mono text-xs truncate max-w-xs" title={r.blocked_uri || ''}>{r.blocked_uri}</td>
                  <td className="text-slate-400 text-xs">{extractHostname(r.document_uri)}</td>
                </tr>
                {expanded === r.id && (
                  <tr className="bg-slate-800/30">
                    <td colSpan={6} className="p-4">
                      <pre className="text-xs font-mono text-slate-300 overflow-x-auto whitespace-pre-wrap">
                        {JSON.stringify(r, null, 2)}
                      </pre>
                    </td>
                  </tr>
                )}
              </React.Fragment>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}

function SettingsTab({ reloadStats }: { reloadStats: () => void }) {
  const [settings, setSettings] = useState<PageProtectSettings | null>(null)
  const [saving, setSaving] = useState(false)
  const [sampling, setSampling] = useState(false)
  const [respTransformEnabled, setRespTransformEnabled] = useState(false)

  const load = useCallback(async () => {
    try {
      const r = await pageProtect.settings.get()
      setSettings(r.data)
    } catch (e) {
      console.error(e)
    }
    try {
      const sr = await settingsApi.get('resp_transform_enabled')
      const val = sr.data?.value
      setRespTransformEnabled(typeof val === 'string' ? ['true', '1', 'yes'].includes(val.toLowerCase()) : !!val)
    } catch {
      setRespTransformEnabled(false)
    }
  }, [])

  useEffect(() => { load() }, [load])

  const save = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!settings) return
    setSaving(true)
    try {
      await pageProtect.settings.update(settings as unknown as Record<string, unknown>)
      alert('Settings saved. Apply config to take effect.')
    } catch (err) {
      alert(getErrorDetail(err))
    } finally {
      setSaving(false)
    }
  }

  const sampleNow = async () => {
    setSampling(true)
    try {
      const r = await pageProtect.sample()
      alert(`CSP report sample complete. ${r.data.stored} new reports stored.`)
      reloadStats()
    } catch (err) {
      alert(getErrorDetail(err))
    } finally {
      setSampling(false)
    }
  }

  if (!settings) return <div className="text-slate-400">Loading...</div>

  return (
    <div className="space-y-4 max-w-2xl">
      <h3 className="text-lg font-semibold">Page Armor Settings</h3>
      <form onSubmit={save} className="card p-6 space-y-4">
        <div className="flex items-center gap-2">
          <input type="checkbox" id="pp-mon" className="rounded border-slate-600 bg-slate-800 text-primary" checked={settings.monitoring_enabled} onChange={e => setSettings({ ...settings, monitoring_enabled: e.target.checked })} />
          <label htmlFor="pp-mon" className="text-sm">
            <span className="font-medium">Monitoring Enabled</span>
            <p className="text-xs text-slate-500">Enables CSP report capture in coreX and the background sampler.</p>
          </label>
        </div>
        <div className="flex items-center gap-2">
          <input type="checkbox" id="pp-hash" className="rounded border-slate-600 bg-slate-800 text-primary" checked={settings.change_detection_enabled} onChange={e => setSettings({ ...settings, change_detection_enabled: e.target.checked })} />
          <label htmlFor="pp-hash" className="text-sm">
            <span className="font-medium">Code Change Detection</span>
            <p className="text-xs text-slate-500">Periodically fetches detected scripts and hashes their content to detect supply-chain changes.</p>
          </label>
        </div>
        <div className="grid grid-cols-2 gap-4">
          <div>
            <label className="label">Change Detection Interval (hours)</label>
            <input type="number" min={1} className="input" value={settings.change_detection_interval_hours} onChange={e => setSettings({ ...settings, change_detection_interval_hours: parseInt(e.target.value) || 24 })} />
          </div>
          <div>
            <label className="label">Report Retention (days)</label>
            <input type="number" min={1} className="input" value={settings.report_retention_days} onChange={e => setSettings({ ...settings, report_retention_days: parseInt(e.target.value) || 7 })} />
          </div>
          <div>
            <label className="label">Auto-Prune Stale (days)</label>
            <input type="number" min={0} className="input" value={settings.auto_prune_stale_days} onChange={e => setSettings({ ...settings, auto_prune_stale_days: parseInt(e.target.value) || 0 })} />
            <p className="text-xs text-slate-500 mt-1">Assets not seen in traffic or successfully hashed within this many days are automatically removed. 0 = disabled. Changed assets are preserved.</p>
          </div>
        </div>
        <div>
          <label className="label">Report Path</label>
          <input className="input" value={settings.report_path} onChange={e => setSettings({ ...settings, report_path: e.target.value })} />
          <p className="text-xs text-slate-500 mt-1">The URL path browsers POST CSP violation reports to. Must match the report-uri in your CSP policies.</p>
        </div>
        <div className="border-t border-slate-800 pt-4">
          {!respTransformEnabled && (
            <div className="mb-3 p-3 rounded bg-amber-500/10 border border-amber-500/30 text-amber-400 text-xs">
              Response Transformations must be enabled in Global Options to use the Inventory Beacon.
            </div>
          )}
          <div className={`flex items-center gap-2 mb-3 ${!respTransformEnabled ? 'opacity-50 pointer-events-none' : ''}`}>
            <input type="checkbox" id="pp-beacon" className="rounded border-slate-600 bg-slate-800 text-primary" checked={settings.beacon_injection_enabled} onChange={e => setSettings({ ...settings, beacon_injection_enabled: e.target.checked })} disabled={!respTransformEnabled} />
            <label htmlFor="pp-beacon" className="text-sm">
              <span className="font-medium">Inventory Beacon</span>
              <p className="text-xs text-slate-500">Injects a JS beacon into HTML responses that collects all loaded resources via the Resource Timing API. Provides a complete asset inventory regardless of CSP mode.</p>
            </label>
          </div>
          <div className={`grid grid-cols-2 gap-4 ${!respTransformEnabled ? 'opacity-50 pointer-events-none' : ''}`}>
            <div>
              <label className="label">Beacon Endpoint Path</label>
              <input className="input" value={settings.beacon_path} onChange={e => setSettings({ ...settings, beacon_path: e.target.value })} disabled={!respTransformEnabled} />
              <p className="text-xs text-slate-500 mt-1">URL path the beacon JS POSTs resource lists to.</p>
            </div>
            <div>
              <label className="label">Beacon Script Path</label>
              <input className="input" value={settings.beacon_script_path} onChange={e => setSettings({ ...settings, beacon_script_path: e.target.value })} disabled={!respTransformEnabled} />
              <p className="text-xs text-slate-500 mt-1">URL path HAProxy serves the beacon JS file from.</p>
            </div>
          </div>
          <div className={`grid grid-cols-2 gap-4 mt-3 ${!respTransformEnabled ? 'opacity-50 pointer-events-none' : ''}`}>
            <div>
              <label className="label">Content Types (comma-sep)</label>
              <input className="input" value={settings.beacon_content_types} onChange={e => setSettings({ ...settings, beacon_content_types: e.target.value })} disabled={!respTransformEnabled} />
              <p className="text-xs text-slate-500 mt-1">Only inject into responses with these content-type prefixes. Default: text/html</p>
            </div>
            <div>
              <label className="label">Path Patterns (comma-sep)</label>
              <input className="input" value={settings.beacon_path_patterns} onChange={e => setSettings({ ...settings, beacon_path_patterns: e.target.value })} disabled={!respTransformEnabled} />
              <p className="text-xs text-slate-500 mt-1">Only inject into pages whose URL path starts with one of these prefixes. Empty = all paths.</p>
            </div>
          </div>
        </div>
        <button type="submit" disabled={saving} className="btn-primary w-full">{saving ? 'Saving...' : 'Save Settings'}</button>

        <div className="border-t border-slate-800 pt-4 mt-4">
          <h4 className="font-semibold mb-1">Manual Report Collection</h4>
          <p className="text-xs text-slate-500 mb-2">Trigger an immediate CSP report sample from coreX logs.</p>
          <button
            type="button"
            onClick={sampleNow}
            disabled={sampling}
            className="btn-secondary text-sm w-full"
          >
            <RefreshCw className={`w-4 h-4 inline me-1 ${sampling ? 'animate-spin' : ''}`} />
            {sampling ? 'Sampling...' : 'Sample Reports Now'}
          </button>
        </div>

        <p className="text-xs text-slate-500">After enabling monitoring, apply the coreX config to start capturing CSP reports.</p>
      </form>
    </div>
  )
}
