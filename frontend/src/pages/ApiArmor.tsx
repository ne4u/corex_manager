import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { ShieldCheck, Settings, FileText, Key, Users, Activity, AlertTriangle, Upload, Trash2, Check } from 'lucide-react'
import { apiArmor, settings as settingsApi } from '../services/api'
import { Tabs } from '../components/ui'

type Tab = 'settings' | 'specs' | 'schemas' | 'auth' | 'keys' | 'profiles' | 'anomalies' | 'presets'

const TABS: { key: Tab; labelKey: string; icon: typeof Settings }[] = [
  { key: 'settings', labelKey: 'pages:apiArmor.tabs.settings', icon: Settings },
  { key: 'presets', labelKey: 'pages:apiArmor.tabs.presets', icon: Check },
  { key: 'specs', labelKey: 'pages:apiArmor.tabs.specs', icon: FileText },
  { key: 'schemas', labelKey: 'pages:apiArmor.tabs.schemas', icon: FileText },
  { key: 'auth', labelKey: 'pages:apiArmor.tabs.auth', icon: Key },
  { key: 'keys', labelKey: 'pages:apiArmor.tabs.keys', icon: Users },
  { key: 'profiles', labelKey: 'pages:apiArmor.tabs.profiles', icon: Activity },
  { key: 'anomalies', labelKey: 'pages:apiArmor.tabs.anomalies', icon: AlertTriangle },
]

export default function ApiArmor() {
  const { t } = useTranslation(['pages', 'common'])
  const [tab, setTab] = useState<Tab>('settings')

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold flex items-center gap-2">
        <ShieldCheck className="h-5 w-5 text-primary" /> {t('pages:apiArmor.title')}
      </h1>
      <p className="text-sm text-slate-400 max-w-3xl">
        {t('pages:apiArmor.description')}
      </p>

      <Tabs
        tabs={TABS.map(tab => ({ id: tab.key, label: t(tab.labelKey), icon: tab.icon }))}
        active={tab}
        onChange={(id) => setTab(id as Tab)}
      />

      {tab === 'settings' && <SettingsTab />}
      {tab === 'presets' && <PresetsTab />}
      {tab === 'specs' && <SpecsTab />}
      {tab === 'schemas' && <SchemasTab />}
      {tab === 'auth' && <AuthTab />}
      {tab === 'keys' && <KeysTab />}
      {tab === 'profiles' && <ProfilesTab />}
      {tab === 'anomalies' && <AnomaliesTab />}
    </div>
  )
}

// --- Settings Tab ---

function SettingsTab() {
  const { t } = useTranslation(['pages', 'common'])
  const [settings, setSettings] = useState<Record<string, unknown>>({})
  const [saving, setSaving] = useState(false)
  const [msg, setMsg] = useState('')
  const [msgIsError, setMsgIsError] = useState(false)
  const [reqFpEnabled, setReqFpEnabled] = useState(false)

  useEffect(() => {
    apiArmor.settings.get().then((r) => setSettings(r.data)).catch(() => { setMsg(t('pages:apiArmor.settings.failedToLoadSettings')); setMsgIsError(true) })
    settingsApi.get('req_fp_enabled')
      .then((r) => setReqFpEnabled((r.data.value || 'false').toLowerCase() === 'true'))
      .catch(() => setReqFpEnabled(false))
  }, [t])

  const save = async () => {
    setSaving(true); setMsg(''); setMsgIsError(false)
    try {
      await apiArmor.settings.update(settings)
      setMsg(t('pages:apiArmor.settings.settingsSaved'))
      window.dispatchEvent(new Event('feature-flags-changed'))
    } catch (e: any) {
      setMsg(e?.response?.data?.detail || t('pages:apiArmor.settings.failedToSaveSettings'))
      setMsgIsError(true)
    } finally { setSaving(false) }
  }

  return (
    <div className="card space-y-4 max-w-3xl">
      {!reqFpEnabled && (
        <div className="flex items-start gap-2 rounded-md border border-amber-500/30 bg-amber-500/10 p-3">
          <AlertTriangle className="h-4 w-4 mt-0.5 shrink-0 text-amber-500" />
          <p className="text-sm text-amber-200">
            {t('pages:apiArmor.settings.requiresReqFp')}
          </p>
        </div>
      )}
      <label className="flex items-center gap-2">
        <input type="checkbox" checked={!!settings.api_armor_enabled}
          disabled={!reqFpEnabled}
          onChange={(e) => setSettings({ ...settings, api_armor_enabled: e.target.checked })} />
        <span className={`text-sm ${!reqFpEnabled ? 'text-slate-500' : ''}`}>{t('pages:apiArmor.settings.enableApiArmor')}</span>
      </label>
      <label className="flex items-center gap-2">
        <input type="checkbox" checked={!!settings.api_armor_schema_learning_enabled}
          onChange={(e) => setSettings({ ...settings, api_armor_schema_learning_enabled: e.target.checked })} />
        <span className="text-sm">{t('pages:apiArmor.settings.enableSchemaLearning')}</span>
      </label>
      <label className="flex items-center gap-2">
        <input type="checkbox" checked={!!settings.api_armor_profiling_learning_enabled}
          onChange={(e) => setSettings({ ...settings, api_armor_profiling_learning_enabled: e.target.checked })} />
        <span className="text-sm">{t('pages:apiArmor.settings.enableProfileLearning')}</span>
      </label>
      <div>
        <label className="text-sm block mb-1">{t('pages:apiArmor.settings.maxBodyBytes')}</label>
        <input className="input" type="number" value={settings.api_armor_max_body_bytes as number || 1048576}
          onChange={(e) => setSettings({ ...settings, api_armor_max_body_bytes: parseInt(e.target.value) || 1048576 })} />
      </div>
      <div>
        <label className="text-sm block mb-1">{t('pages:apiArmor.settings.profileRetentionDays')}</label>
        <input className="input" type="number" value={settings.api_armor_profile_retention_days as number || 30}
          onChange={(e) => setSettings({ ...settings, api_armor_profile_retention_days: parseInt(e.target.value) || 30 })} />
      </div>
      <button className="btn-primary" onClick={save} disabled={saving}>
        {saving ? t('pages:apiArmor.settings.saving') : t('pages:apiArmor.settings.saveSettings')}
      </button>
      {msg && <p className={`text-sm ${msgIsError ? 'text-red-400' : 'text-green-400'}`}>{msg}</p>}
    </div>
  )
}

// --- Presets Tab ---

function PresetsTab() {
  const { t } = useTranslation(['pages', 'common'])
  const [presets, setPresets] = useState<any[]>([])
  const [msg, setMsg] = useState('')
  const [msgIsError, setMsgIsError] = useState(false)

  useEffect(() => {
    apiArmor.presets.list().then((r) => setPresets(r.data)).catch(() => { setMsg(t('pages:apiArmor.presets.failedToLoadPresets')); setMsgIsError(true) })
  }, [t])

  const apply = async () => {
    setMsg(''); setMsgIsError(false)
    try {
      const r = await apiArmor.presets.apply()
      setMsg(t('pages:apiArmor.presets.appliedRules', { count: r.data.applied }))
    } catch (e: any) {
      setMsg(e?.response?.data?.detail || t('pages:apiArmor.presets.failedToApplyPresets'))
      setMsgIsError(true)
    }
  }

  return (
    <div className="card space-y-4 max-w-3xl">
      <div className="flex items-center justify-between">
        <h2 className="text-lg font-semibold">{t('pages:apiArmor.presets.title')}</h2>
        <button className="btn-primary" onClick={apply}>{t('pages:apiArmor.presets.applyAllPresets')}</button>
      </div>
      {msg && <p className={`text-sm ${msgIsError ? 'text-red-400' : 'text-green-400'}`}>{msg}</p>}
      <div className="space-y-2">
        {presets.map((p, i) => (
          <div key={i} className="border border-slate-700 rounded p-3">
            <div className="font-medium text-sm">{p.name}</div>
            <div className="text-xs text-slate-400">{p.description}</div>
            <div className="text-xs text-slate-500 mt-1">
              <code>{p.expression}</code> → <span className="text-primary">{p.action}</span>
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}

// --- Specs Tab ---

function SpecsTab() {
  const { t } = useTranslation(['pages', 'common'])
  const [specs, setSpecs] = useState<any[]>([])
  const [msg, setMsg] = useState('')
  const [msgIsError, setMsgIsError] = useState(false)
  const [showUpload, setShowUpload] = useState(false)
  const [name, setName] = useState('')
  const [specText, setSpecText] = useState('')

  const load = () => apiArmor.specs.list().then((r) => setSpecs(r.data)).catch(() => { setMsg(t('pages:apiArmor.specs.failedToLoadSpecs')); setMsgIsError(true) })

  useEffect(() => { load() }, [])

  const upload = async () => {
    setMsg(''); setMsgIsError(false)
    try {
      await apiArmor.specs.create({ name, spec: specText })
      setMsg(t('pages:apiArmor.specs.specImported'))
      setName(''); setSpecText(''); setShowUpload(false)
      load()
    } catch (e: any) {
      setMsg(e?.response?.data?.detail || t('pages:apiArmor.specs.failedToImportSpec'))
      setMsgIsError(true)
    }
  }

  const del = async (id: number) => {
    try { await apiArmor.specs.delete(id); load() } catch { /* ignore */ }
  }

  return (
    <div className="card space-y-4 max-w-3xl">
      <div className="flex items-center justify-between">
        <h2 className="text-lg font-semibold">{t('pages:apiArmor.specs.title')}</h2>
        <button className="btn-primary flex items-center gap-1" onClick={() => setShowUpload(!showUpload)}>
          <Upload className="h-4 w-4" /> {t('pages:apiArmor.specs.importSpec')}
        </button>
      </div>
      {msg && <p className={`text-sm ${msgIsError ? 'text-red-400' : 'text-green-400'}`}>{msg}</p>}
      {showUpload && (
        <div className="space-y-2 border border-slate-700 rounded p-3">
          <input className="input" placeholder={t('pages:apiArmor.specs.specName')} value={name} onChange={(e) => setName(e.target.value)} />
          <textarea className="input font-mono text-xs" rows={10} placeholder={t('pages:apiArmor.specs.pasteSpec')}
            value={specText} onChange={(e) => setSpecText(e.target.value)} />
          <button className="btn-primary" onClick={upload} disabled={!name || !specText}>{t('pages:apiArmor.specs.import')}</button>
        </div>
      )}
      <div className="space-y-2">
        {specs.map((s) => (
          <div key={s.id} className="border border-slate-700 rounded p-3 flex items-center justify-between">
            <div>
              <div className="font-medium text-sm">{s.name}</div>
              <div className="text-xs text-slate-400">{t('pages:apiArmor.specs.schemasCount', { version: s.version, count: s.schema_count })}</div>
            </div>
            <button onClick={() => del(s.id)} className="text-red-400 hover:underline text-xs flex items-center gap-1">
              <Trash2 className="h-3 w-3" /> {t('pages:apiArmor.specs.delete')}
            </button>
          </div>
        ))}
        {specs.length === 0 && <p className="text-sm text-slate-500">{t('pages:apiArmor.specs.noSpecs')}</p>}
      </div>
    </div>
  )
}

// --- Schemas Tab ---

function SchemasTab() {
  const { t } = useTranslation(['pages', 'common'])
  const [schemas, setSchemas] = useState<any[]>([])

  useEffect(() => {
    apiArmor.schemas.list().then((r) => setSchemas(r.data)).catch(() => setSchemas([]))
  }, [])

  return (
    <div className="card space-y-4 max-w-4xl">
      <h2 className="text-lg font-semibold">{t('pages:apiArmor.schemas.title')}</h2>
      <div className="space-y-2">
        {schemas.map((s) => (
          <div key={s.id} className="border border-slate-700 rounded p-3">
            <div className="flex items-center justify-between">
              <div className="font-medium text-sm">{s.method} {s.path}</div>
              <span className={`text-xs px-2 py-0.5 rounded ${s.source === 'openapi' ? 'bg-blue-900' : 'bg-green-900'}`}>{s.source}</span>
            </div>
            <div className="text-xs text-slate-400 mt-1">{s.name} • {t('pages:apiArmor.schemas.samples', { count: s.sample_count })}</div>
            <details className="mt-2">
              <summary className="text-xs text-slate-500 cursor-pointer">{t('pages:apiArmor.schemas.schemaJson')}</summary>
              <pre className="text-xs text-slate-400 mt-1 overflow-auto max-h-48">{JSON.stringify(s.schema_def, null, 2)}</pre>
            </details>
          </div>
        ))}
        {schemas.length === 0 && <p className="text-sm text-slate-500">{t('pages:apiArmor.schemas.noSchemas')}</p>}
      </div>
    </div>
  )
}

// --- Auth Tab ---

function AuthTab() {
  const { t } = useTranslation(['pages', 'common'])
  const [policies, setPolicies] = useState<any[]>([])

  useEffect(() => {
    apiArmor.authPolicies.list().then((r) => setPolicies(r.data)).catch(() => setPolicies([]))
  }, [])

  return (
    <div className="card space-y-4 max-w-3xl">
      <h2 className="text-lg font-semibold">{t('pages:apiArmor.auth.title')}</h2>
      <div className="space-y-2">
        {policies.map((p) => (
          <div key={p.id} className="border border-slate-700 rounded p-3">
            <div className="font-medium text-sm">{p.name}</div>
            <div className="text-xs text-slate-400">
              {t('pages:apiArmor.auth.type')}: {p.auth_type} • {t('pages:apiArmor.auth.algorithm')}: {p.jwt_algorithm} • {t('pages:apiArmor.auth.onFailure')}: {p.on_failure}
            </div>
            {p.jwt_issuer && <div className="text-xs text-slate-500">{t('pages:apiArmor.auth.issuer')}: {p.jwt_issuer}</div>}
          </div>
        ))}
        {policies.length === 0 && <p className="text-sm text-slate-500">{t('pages:apiArmor.auth.noPolicies')}</p>}
      </div>
    </div>
  )
}

// --- Keys Tab ---

function KeysTab() {
  const { t } = useTranslation(['pages', 'common'])
  const [lists, setLists] = useState<any[]>([])

  useEffect(() => {
    apiArmor.apiKeyLists.list().then((r) => setLists(r.data)).catch(() => setLists([]))
  }, [])

  return (
    <div className="card space-y-4 max-w-3xl">
      <h2 className="text-lg font-semibold">{t('pages:apiArmor.keys.title')}</h2>
      <div className="space-y-2">
        {lists.map((l) => (
          <div key={l.id} className="border border-slate-700 rounded p-3">
            <div className="font-medium text-sm">{l.name}</div>
            {l.description && <div className="text-xs text-slate-400">{l.description}</div>}
            <div className="text-xs text-slate-500 mt-1">{t('pages:apiArmor.keys.keysCount', { count: l.entries?.length || 0 })}</div>
          </div>
        ))}
        {lists.length === 0 && <p className="text-sm text-slate-500">{t('pages:apiArmor.keys.noLists')}</p>}
      </div>
    </div>
  )
}

// --- Profiles Tab ---

function ProfilesTab() {
  const { t } = useTranslation(['pages', 'common'])
  const [profiles, setProfiles] = useState<any[]>([])

  useEffect(() => {
    apiArmor.profiles.list().then((r) => setProfiles(r.data)).catch(() => setProfiles([]))
  }, [])

  return (
    <div className="card space-y-4 max-w-4xl">
      <h2 className="text-lg font-semibold">{t('pages:apiArmor.profiles.title')}</h2>
      <div className="space-y-2">
        {profiles.map((p) => (
          <div key={p.id} className="border border-slate-700 rounded p-3">
            <div className="flex items-center justify-between">
              <div className="font-medium text-sm">{p.method} {p.path}</div>
              <span className={`text-xs px-2 py-0.5 rounded ${p.learned ? 'bg-green-900' : 'bg-yellow-900'}`}>
                {p.learned ? t('pages:apiArmor.profiles.learned') : t('pages:apiArmor.profiles.learning')}
              </span>
            </div>
            <div className="text-xs text-slate-400 mt-1">{t('pages:apiArmor.profiles.samples', { count: p.sample_count })}</div>
            {Object.keys(p.dimensions || {}).length > 0 && (
              <div className="text-xs text-slate-500 mt-1">
                {t('pages:apiArmor.profiles.dimensions')}: {Object.keys(p.dimensions).join(', ')}
              </div>
            )}
          </div>
        ))}
        {profiles.length === 0 && <p className="text-sm text-slate-500">{t('pages:apiArmor.profiles.noProfiles')}</p>}
      </div>
    </div>
  )
}

// --- Anomalies Tab ---

function AnomaliesTab() {
  const { t } = useTranslation(['pages', 'common'])
  const [anomalies, setAnomalies] = useState<any[]>([])

  useEffect(() => {
    apiArmor.anomalies.list({ limit: 100 }).then((r) => setAnomalies(r.data)).catch(() => setAnomalies([]))
  }, [])

  const clear = async () => {
    try { await apiArmor.anomalies.clear(); setAnomalies([]) } catch { /* ignore */ }
  }

  return (
    <div className="card space-y-4 max-w-4xl">
      <div className="flex items-center justify-between">
        <h2 className="text-lg font-semibold">{t('pages:apiArmor.anomalies.title')}</h2>
        {anomalies.length > 0 && (
          <button className="text-red-400 hover:underline text-xs" onClick={clear}>{t('pages:apiArmor.anomalies.clearAll')}</button>
        )}
      </div>
      <div className="space-y-2">
        {anomalies.map((a) => (
          <div key={a.id} className="border border-slate-700 rounded p-3">
            <div className="flex items-center justify-between">
              <div className="font-medium text-sm">{a.method} {a.path}</div>
              <span className="text-xs text-yellow-400">{a.dimension}</span>
            </div>
            <div className="text-xs text-slate-400 mt-1">
              {t('pages:apiArmor.anomalies.observed')}: <code>{a.observed_value}</code>
            </div>
            {a.client_ip && <div className="text-xs text-slate-500">{t('pages:apiArmor.anomalies.ip')}: {a.client_ip}</div>}
            <div className="text-xs text-slate-500">{a.created_at}</div>
          </div>
        ))}
        {anomalies.length === 0 && <p className="text-sm text-slate-500">{t('pages:apiArmor.anomalies.noAnomalies')}</p>}
      </div>
    </div>
  )
}
