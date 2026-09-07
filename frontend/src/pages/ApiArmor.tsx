import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { ShieldCheck, Settings, FileText, Key, Users, Activity, AlertTriangle, Upload, Trash2, Check, Pencil, Plus, X } from 'lucide-react'
import { apiArmor, settings as settingsApi, listeners, backends } from '../services/api'
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

// --- Shared helpers ---

type Msg = { text: string; isError: boolean }

function parseIds(value: string): number[] {
  return value
    .split(/[,\s]+/)
    .map(s => parseInt(s.trim(), 10))
    .filter(n => !isNaN(n))
}

// --- Settings Tab ---

function SettingsTab() {
  const { t } = useTranslation(['pages', 'common'])
  const [settings, setSettings] = useState<Record<string, unknown>>({})
  const [saving, setSaving] = useState(false)
  const [msg, setMsg] = useState<Msg | null>(null)
  const [reqFpEnabled, setReqFpEnabled] = useState(false)
  const [backendList, setBackendList] = useState<any[]>([])

  useEffect(() => {
    apiArmor.settings.get().then((r) => setSettings(r.data)).catch(() => { setMsg({ text: t('pages:apiArmor.settings.failedToLoadSettings'), isError: true }) })
    settingsApi.get('req_fp_enabled')
      .then((r) => setReqFpEnabled((r.data.value || 'false').toLowerCase() === 'true'))
      .catch(() => setReqFpEnabled(false))
    backends.list().then((r) => setBackendList(r.data)).catch(() => setBackendList([]))
  }, [t])

  const save = async () => {
    setSaving(true); setMsg(null)
    try {
      await apiArmor.settings.update(settings)
      setMsg({ text: t('pages:apiArmor.settings.settingsSaved'), isError: false })
      window.dispatchEvent(new Event('feature-flags-changed'))
    } catch (e: any) {
      setMsg({ text: e?.response?.data?.detail || t('pages:apiArmor.settings.failedToSaveSettings'), isError: true })
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
        <label className="text-sm block mb-1">{t('pages:apiArmor.settings.scope')}</label>
        <select
          className="input"
          value={(settings.api_armor_scope as string) || 'listener'}
          disabled={!reqFpEnabled}
          onChange={(e) => setSettings({ ...settings, api_armor_scope: e.target.value })}
        >
          <option value="listener">{t('pages:apiArmor.settings.scopeListener')}</option>
          <option value="backend">{t('pages:apiArmor.settings.scopeBackend')}</option>
          <option value="path">{t('pages:apiArmor.settings.scopePath')}</option>
        </select>
      </div>
      <div
        className={`grid gap-4 ${
          settings.api_armor_scope === 'path' ? 'grid-cols-1 md:grid-cols-2' : 'grid-cols-1'
        }`}
      >
        {(settings.api_armor_scope === 'backend' || settings.api_armor_scope === 'path') && (
          <div>
            <label className="text-sm block mb-1">{t('pages:apiArmor.settings.backendIds')}</label>
            <select
              multiple
              className="input !h-48"
              disabled={!reqFpEnabled}
              value={(settings.api_armor_backend_ids as number[] || []).map(String)}
              onChange={(e) => {
                const selected = Array.from(e.target.selectedOptions).map((o) => parseInt(o.value, 10))
                setSettings({ ...settings, api_armor_backend_ids: selected })
              }}
            >
              {backendList.map((b) => (
                <option key={b.id} value={b.id}>{b.name}</option>
              ))}
            </select>
          </div>
        )}
        {settings.api_armor_scope === 'path' && (
          <div>
            <label className="text-sm block mb-1">{t('pages:apiArmor.settings.pathPatterns')}</label>
            <textarea
              className="input font-mono text-xs !h-48"
              disabled={!reqFpEnabled}
              placeholder={t('pages:apiArmor.settings.pathPatternsPlaceholder')}
              value={Array.isArray(settings.api_armor_path_patterns) ? (settings.api_armor_path_patterns as string[]).join('\n') : ''}
              onChange={(e) => {
                const patterns = e.target.value.split('\n').map((s) => s.trim()).filter(Boolean)
                setSettings({ ...settings, api_armor_path_patterns: patterns })
              }}
            />
          </div>
        )}
      </div>
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
      {msg && <p className={`text-sm ${msg.isError ? 'text-red-400' : 'text-green-400'}`}>{msg.text}</p>}
    </div>
  )
}

// --- Presets Tab ---

function PresetsTab() {
  const { t } = useTranslation(['pages', 'common'])
  const [presets, setPresets] = useState<any[]>([])
  const [msg, setMsg] = useState<Msg | null>(null)

  useEffect(() => {
    apiArmor.presets.list().then((r) => setPresets(r.data)).catch(() => { setMsg({ text: t('pages:apiArmor.presets.failedToLoadPresets'), isError: true }) })
  }, [t])

  const apply = async () => {
    setMsg(null)
    try {
      const r = await apiArmor.presets.apply()
      setMsg({ text: t('pages:apiArmor.presets.appliedRules', { count: r.data.applied }), isError: false })
    } catch (e: any) {
      setMsg({ text: e?.response?.data?.detail || t('pages:apiArmor.presets.failedToApplyPresets'), isError: true })
    }
  }

  return (
    <div className="card space-y-4 max-w-3xl">
      <div className="flex items-center justify-between">
        <h2 className="text-lg font-semibold">{t('pages:apiArmor.presets.title')}</h2>
        <button className="btn-primary" onClick={apply}>{t('pages:apiArmor.presets.applyAllPresets')}</button>
      </div>
      {msg && <p className={`text-sm ${msg.isError ? 'text-red-400' : 'text-green-400'}`}>{msg.text}</p>}
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
  const [msg, setMsg] = useState<Msg | null>(null)
  const [showUpload, setShowUpload] = useState(false)
  const [name, setName] = useState('')
  const [specText, setSpecText] = useState('')
  const [viewing, setViewing] = useState<number | null>(null)
  const [viewSchemas, setViewSchemas] = useState<any[]>([])

  const load = () => {
    setMsg(null)
    apiArmor.specs.list().then((r) => setSpecs(r.data)).catch(() => { setMsg({ text: t('pages:apiArmor.specs.failedToLoadSpecs'), isError: true }) })
  }

  useEffect(() => { load() }, [])

  const upload = async () => {
    setMsg(null)
    try {
      await apiArmor.specs.create({ name, spec: specText })
      setMsg({ text: t('pages:apiArmor.specs.specImported'), isError: false })
      setName(''); setSpecText(''); setShowUpload(false)
      load()
    } catch (e: any) {
      setMsg({ text: e?.response?.data?.detail || t('pages:apiArmor.specs.failedToImportSpec'), isError: true })
    }
  }

  const del = async (id: number) => {
    try { await apiArmor.specs.delete(id); load() } catch { /* ignore */ }
  }

  const view = async (id: number) => {
    if (viewing === id) {
      setViewing(null); setViewSchemas([]); return
    }
    try {
      const r = await apiArmor.specs.schemas(id)
      setViewSchemas(r.data)
      setViewing(id)
    } catch { setMsg({ text: t('pages:apiArmor.specs.failedToLoadSpecs'), isError: true }) }
  }

  return (
    <div className="card space-y-4 max-w-4xl">
      <div className="flex items-center justify-between">
        <h2 className="text-lg font-semibold">{t('pages:apiArmor.specs.title')}</h2>
        <button className="btn-primary flex items-center gap-1" onClick={() => setShowUpload(!showUpload)}>
          <Upload className="h-4 w-4" /> {t('pages:apiArmor.specs.importSpec')}
        </button>
      </div>
      {msg && <p className={`text-sm ${msg.isError ? 'text-red-400' : 'text-green-400'}`}>{msg.text}</p>}
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
          <div key={s.id} className="border border-slate-700 rounded p-3">
            <div className="flex items-center justify-between">
              <div>
                <div className="font-medium text-sm">{s.name}</div>
                <div className="text-xs text-slate-400">{t('pages:apiArmor.specs.schemasCount', { version: s.version, count: s.schema_count })}</div>
              </div>
              <div className="flex items-center gap-2">
                <button onClick={() => view(s.id)} className="text-primary hover:underline text-xs flex items-center gap-1">
                  {t('pages:apiArmor.specs.viewSchemas')}
                </button>
                <button onClick={() => del(s.id)} className="text-red-400 hover:underline text-xs flex items-center gap-1">
                  <Trash2 className="h-3 w-3" /> {t('pages:apiArmor.specs.delete')}
                </button>
              </div>
            </div>
            {viewing === s.id && (
              <div className="mt-2 border-t border-slate-700 pt-2">
                {viewSchemas.map((sch) => (
                  <div key={sch.id} className="text-xs text-slate-400 mb-1">
                    {sch.method} {sch.path} • {sch.name}
                  </div>
                ))}
              </div>
            )}
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
  const [msg, setMsg] = useState<Msg | null>(null)
  const [editing, setEditing] = useState<any | null>(null)
  const [learn, setLearn] = useState<any | null>(null)

  const load = () => {
    setMsg(null)
    apiArmor.schemas.list().then((r) => setSchemas(r.data)).catch(() => setMsg({ text: t('pages:apiArmor.schemas.failedToLoadSchemas'), isError: true }))
  }

  useEffect(() => { load() }, [])

  const save = async () => {
    if (!editing) return
    let schemaDef: any
    try {
      schemaDef = JSON.parse(editing.schemaJson)
    } catch {
      setMsg({ text: 'Invalid JSON in schema definition', isError: true }); return
    }
    try {
      await apiArmor.schemas.update(editing.id, { schema_def: schemaDef, enabled: editing.enabled })
      setMsg({ text: t('pages:apiArmor.schemas.saved'), isError: false })
      setEditing(null)
      load()
    } catch (e: any) {
      setMsg({ text: e?.response?.data?.detail || t('pages:apiArmor.schemas.failedToSaveSchema'), isError: true })
    }
  }

  const startEdit = (s: any) => {
    setEditing({
      ...s,
      schemaJson: JSON.stringify(s.schema_def, null, 2),
    })
    setLearn(null)
  }

  const doLearn = async () => {
    if (!learn) return
    try {
      await apiArmor.schemas.learn({
        method: learn.method,
        path: learn.path,
        body: JSON.parse(learn.body),
      })
      setMsg({ text: t('pages:apiArmor.schemas.learned', { count: 1 }), isError: false })
      setLearn(null)
      load()
    } catch (e: any) {
      setMsg({ text: e?.response?.data?.detail || t('pages:apiArmor.schemas.failedToLearn'), isError: true })
    }
  }

  return (
    <div className="card space-y-4 max-w-4xl">
      <div className="flex items-center justify-between">
        <h2 className="text-lg font-semibold">{t('pages:apiArmor.schemas.title')}</h2>
        <button className="btn-primary flex items-center gap-1" onClick={() => { setLearn({ method: 'POST', path: '/', body: '{}' }); setEditing(null) }}>
          <Plus className="h-4 w-4" /> {t('pages:apiArmor.schemas.learn')}
        </button>
      </div>
      {msg && <p className={`text-sm ${msg.isError ? 'text-red-400' : 'text-green-400'}`}>{msg.text}</p>}

      {learn && (
        <div className="space-y-2 border border-slate-700 rounded p-3">
          <h3 className="text-sm font-medium">{t('pages:apiArmor.schemas.learnTitle')}</h3>
          <div className="flex gap-2">
            <input className="input" placeholder="GET" value={learn.method} onChange={(e) => setLearn({ ...learn, method: e.target.value })} />
            <input className="input flex-1" placeholder="/api/v1/users" value={learn.path} onChange={(e) => setLearn({ ...learn, path: e.target.value })} />
          </div>
          <textarea className="input font-mono text-xs" rows={5} placeholder={t('pages:apiArmor.schemas.learnBody')}
            value={learn.body} onChange={(e) => setLearn({ ...learn, body: e.target.value })} />
          <div className="flex gap-2">
            <button className="btn-primary" onClick={doLearn}>{t('pages:apiArmor.schemas.learn')}</button>
            <button className="btn" onClick={() => setLearn(null)}><X className="h-4 w-4" /></button>
          </div>
        </div>
      )}

      {editing && (
        <div className="space-y-2 border border-slate-700 rounded p-3">
          <h3 className="text-sm font-medium">{t('pages:apiArmor.schemas.edit')}: {editing.method} {editing.path}</h3>
          <label className="flex items-center gap-2">
            <input type="checkbox" checked={!!editing.enabled} onChange={(e) => setEditing({ ...editing, enabled: e.target.checked })} />
            <span className="text-sm">{t('pages:apiArmor.schemas.enabled')}</span>
          </label>
          <textarea className="input font-mono text-xs" rows={12} value={editing.schemaJson}
            onChange={(e) => setEditing({ ...editing, schemaJson: e.target.value })} />
          <div className="flex gap-2">
            <button className="btn-primary" onClick={save}>{t('pages:apiArmor.schemas.save')}</button>
            <button className="btn" onClick={() => setEditing(null)}><X className="h-4 w-4" /></button>
          </div>
        </div>
      )}

      <div className="space-y-2">
        {schemas.map((s) => (
          <div key={s.id} className="border border-slate-700 rounded p-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <div className="font-medium text-sm">{s.method} {s.path}</div>
                <span className={`text-xs px-2 py-0.5 rounded ${s.source === 'openapi' ? 'bg-blue-900' : 'bg-green-900'}`}>{s.source}</span>
                {s.enabled === false && <span className="text-xs text-slate-500">({t('pages:apiArmor.schemas.enabled')}: off)</span>}
              </div>
              <button onClick={() => startEdit(s)} className="text-primary hover:underline text-xs flex items-center gap-1">
                <Pencil className="h-3 w-3" /> {t('pages:apiArmor.schemas.edit')}
              </button>
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

const defaultAuth: any = {
  name: '',
  auth_type: 'jwt',
  jwt_algorithm: 'HS256',
  jwt_secret_env: '',
  jwt_issuer: '',
  jwt_audience: '',
  api_key_header: 'X-Api-Key',
  api_key_list_id: null,
  on_failure: 'block',
  enabled: true,
  listener_ids_text: '',
  backend_ids_text: '',
}

function AuthTab() {
  const { t } = useTranslation(['pages', 'common'])
  const [policies, setPolicies] = useState<any[]>([])
  const [keyLists, setKeyLists] = useState<any[]>([])
  const [listenerOptions, setListenerOptions] = useState<any[]>([])
  const [msg, setMsg] = useState<Msg | null>(null)
  const [editing, setEditing] = useState<any | null>(null)
  const [confirmDelete, setConfirmDelete] = useState<any | null>(null)

  const load = () => {
    setMsg(null)
    apiArmor.authPolicies.list().then((r) => setPolicies(r.data)).catch(() => setMsg({ text: t('pages:apiArmor.auth.failedToLoadPolicies'), isError: true }))
    apiArmor.apiKeyLists.list().then((r) => setKeyLists(r.data)).catch(() => {})
    listeners.list().then((r) => setListenerOptions(r.data)).catch(() => {})
  }

  useEffect(() => { load() }, [])

  const startNew = () => {
    setEditing({ ...defaultAuth })
  }

  const startEdit = (p: any) => {
    setEditing({
      ...p,
      listener_ids_text: (p.listener_ids || []).join(', '),
      backend_ids_text: (p.backend_ids || []).join(', '),
    })
    setConfirmDelete(null)
  }

  const save = async () => {
    if (!editing) return
    const payload = {
      ...editing,
      listener_ids: parseIds(editing.listener_ids_text),
      backend_ids: parseIds(editing.backend_ids_text),
    }
    try {
      if (editing.id) {
        await apiArmor.authPolicies.update(editing.id, payload)
      } else {
        await apiArmor.authPolicies.create(payload)
      }
      setMsg({ text: t('pages:apiArmor.auth.saved'), isError: false })
      setEditing(null)
      load()
    } catch (e: any) {
      setMsg({ text: e?.response?.data?.detail || t('pages:apiArmor.auth.failedToSavePolicy'), isError: true })
    }
  }

  const del = async (p: any) => {
    try {
      await apiArmor.authPolicies.delete(p.id)
      setConfirmDelete(null)
      load()
    } catch (e: any) {
      setMsg({ text: e?.response?.data?.detail || 'Failed to delete policy', isError: true })
    }
  }

  return (
    <div className="card space-y-4 max-w-4xl">
      <div className="flex items-center justify-between">
        <h2 className="text-lg font-semibold">{t('pages:apiArmor.auth.title')}</h2>
        <button className="btn-primary flex items-center gap-1" onClick={startNew}>
          <Plus className="h-4 w-4" /> {t('pages:apiArmor.auth.addPolicy')}
        </button>
      </div>
      {msg && <p className={`text-sm ${msg.isError ? 'text-red-400' : 'text-green-400'}`}>{msg.text}</p>}

      {editing && (
        <div className="space-y-3 border border-slate-700 rounded p-3">
          <h3 className="text-sm font-medium">{editing.id ? t('pages:apiArmor.auth.editPolicy') : t('pages:apiArmor.auth.addPolicy')}</h3>
          <input className="input" placeholder={t('pages:apiArmor.auth.name')} value={editing.name} onChange={(e) => setEditing({ ...editing, name: e.target.value })} />
          <div className="grid grid-cols-2 gap-3">
            <select className="input" value={editing.auth_type} onChange={(e) => setEditing({ ...editing, auth_type: e.target.value })}>
              <option value="jwt">{t('pages:apiArmor.auth.typeJwt')}</option>
              <option value="api_key">{t('pages:apiArmor.auth.typeApiKey')}</option>
              <option value="none">{t('pages:apiArmor.auth.typeNone')}</option>
            </select>
            <select className="input" value={editing.on_failure} onChange={(e) => setEditing({ ...editing, on_failure: e.target.value })}>
              <option value="block">block</option>
              <option value="challenge">challenge</option>
              <option value="log_only">log_only</option>
            </select>
          </div>

          <div>
            <label className="text-xs text-slate-400 block mb-1">{t('pages:apiArmor.auth.listeners')}</label>
            <select multiple className="input h-24" value={(editing.listener_ids || []).map(String)}
              onChange={(e) => {
                const selected = Array.from(e.target.selectedOptions).map(o => parseInt(o.value))
                setEditing({ ...editing, listener_ids: selected, listener_ids_text: selected.join(', ') })
              }}>
              {listenerOptions.map((l) => <option key={l.id} value={l.id}>{l.name} ({l.address}:{l.port})</option>)}
            </select>
            <input className="input mt-1" placeholder="1, 2, 3" value={editing.listener_ids_text}
              onChange={(e) => {
                const ids = parseIds(e.target.value)
                setEditing({ ...editing, listener_ids_text: e.target.value, listener_ids: ids })
              }} />
          </div>

          <label className="flex items-center gap-2">
            <input type="checkbox" checked={!!editing.enabled} onChange={(e) => setEditing({ ...editing, enabled: e.target.checked })} />
            <span className="text-sm">{t('pages:apiArmor.schemas.enabled')}</span>
          </label>

          {editing.auth_type === 'jwt' && (
            <div className="space-y-3 border-t border-slate-700 pt-3">
              <div className="grid grid-cols-2 gap-3">
                <select className="input" value={editing.jwt_algorithm} onChange={(e) => setEditing({ ...editing, jwt_algorithm: e.target.value })}>
                  <option value="HS256">HS256</option>
                  <option value="HS384">HS384</option>
                  <option value="HS512">HS512</option>
                </select>
                <input className="input" placeholder={t('pages:apiArmor.auth.secretEnv')} value={editing.jwt_secret_env} onChange={(e) => setEditing({ ...editing, jwt_secret_env: e.target.value })} />
              </div>
              <div className="grid grid-cols-2 gap-3">
                <input className="input" placeholder={t('pages:apiArmor.auth.issuer')} value={editing.jwt_issuer} onChange={(e) => setEditing({ ...editing, jwt_issuer: e.target.value })} />
                <input className="input" placeholder={t('pages:apiArmor.auth.audience')} value={editing.jwt_audience} onChange={(e) => setEditing({ ...editing, jwt_audience: e.target.value })} />
              </div>
            </div>
          )}

          {editing.auth_type === 'api_key' && (
            <div className="space-y-3 border-t border-slate-700 pt-3">
              <input className="input" placeholder={t('pages:apiArmor.auth.apiKeyHeader')} value={editing.api_key_header} onChange={(e) => setEditing({ ...editing, api_key_header: e.target.value })} />
              <select className="input" value={editing.api_key_list_id || ''} onChange={(e) => setEditing({ ...editing, api_key_list_id: e.target.value ? parseInt(e.target.value) : null })}>
                <option value="">{t('pages:apiArmor.auth.apiKeyList')}</option>
                {keyLists.map((l) => <option key={l.id} value={l.id}>{l.name}</option>)}
              </select>
            </div>
          )}

          <div className="flex gap-2">
            <button className="btn-primary" onClick={save}>{t('pages:apiArmor.auth.save')}</button>
            <button className="btn" onClick={() => setEditing(null)}><X className="h-4 w-4" /></button>
          </div>
        </div>
      )}

      <div className="space-y-2">
        {policies.map((p) => (
          <div key={p.id} className="border border-slate-700 rounded p-3">
            <div className="flex items-center justify-between">
              <div>
                <div className="font-medium text-sm flex items-center gap-2">
                  {p.name}
                  {p.enabled === false && <span className="text-xs text-slate-500">(disabled)</span>}
                </div>
                <div className="text-xs text-slate-400">
                  {t('pages:apiArmor.auth.type')}: {p.auth_type} • {t('pages:apiArmor.auth.algorithm')}: {p.jwt_algorithm || '-'} • {t('pages:apiArmor.auth.onFailure')}: {p.on_failure}
                </div>
                {p.jwt_issuer && <div className="text-xs text-slate-500">{t('pages:apiArmor.auth.issuer')}: {p.jwt_issuer}</div>}
              </div>
              <div className="flex items-center gap-2">
                <button onClick={() => startEdit(p)} className="text-primary hover:underline text-xs flex items-center gap-1">
                  <Pencil className="h-3 w-3" /> {t('pages:apiArmor.schemas.edit')}
                </button>
                <button onClick={() => setConfirmDelete(p)} className="text-red-400 hover:underline text-xs flex items-center gap-1">
                  <Trash2 className="h-3 w-3" /> {t('pages:apiArmor.auth.delete')}
                </button>
              </div>
            </div>
            {confirmDelete?.id === p.id && (
              <div className="mt-2 flex items-center gap-2 text-xs">
                <span className="text-slate-400">{t('pages:apiArmor.auth.confirmDelete', { name: p.name })}</span>
                <button className="text-red-400 hover:underline" onClick={() => del(p)}>{t('common:yes', 'Yes')}</button>
                <button className="text-primary hover:underline" onClick={() => setConfirmDelete(null)}>{t('common:cancel', 'Cancel')}</button>
              </div>
            )}
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
  const [msg, setMsg] = useState<Msg | null>(null)
  const [editing, setEditing] = useState<any | null>(null)
  const [newEntry, setNewEntry] = useState('')
  const [confirmDelete, setConfirmDelete] = useState<any | null>(null)

  const load = () => {
    setMsg(null)
    apiArmor.apiKeyLists.list().then((r) => setLists(r.data)).catch(() => setMsg({ text: t('pages:apiArmor.keys.failedToLoadLists'), isError: true }))
  }

  useEffect(() => { load() }, [])

  const startNew = () => {
    setEditing({ name: '', description: '', entries: [] })
  }

  const startEdit = (l: any) => {
    setEditing({
      ...l,
      entries: l.entries ? [...l.entries] : [],
    })
    setConfirmDelete(null)
  }

  const save = async () => {
    if (!editing) return
    const payload = {
      name: editing.name,
      description: editing.description,
      entries: (editing.entries || []).map((e: any) => typeof e === 'string' ? e : e.value).filter(Boolean),
    }
    try {
      if (editing.id) {
        await apiArmor.apiKeyLists.update(editing.id, payload)
      } else {
        await apiArmor.apiKeyLists.create(payload)
      }
      setMsg({ text: t('pages:apiArmor.keys.saved'), isError: false })
      setEditing(null)
      load()
    } catch (e: any) {
      setMsg({ text: e?.response?.data?.detail || t('pages:apiArmor.keys.failedToSaveList'), isError: true })
    }
  }

  const del = async (l: any) => {
    try { await apiArmor.apiKeyLists.delete(l.id); setConfirmDelete(null); load() } catch { setConfirmDelete(null) }
  }

  const addEntry = () => {
    if (!newEntry.trim() || !editing) return
    setEditing({ ...editing, entries: [...(editing.entries || []), newEntry.trim()] })
    setNewEntry('')
  }

  const removeEntry = (idx: number) => {
    if (!editing) return
    const entries = [...editing.entries]
    entries.splice(idx, 1)
    setEditing({ ...editing, entries })
  }

  return (
    <div className="card space-y-4 max-w-4xl">
      <div className="flex items-center justify-between">
        <h2 className="text-lg font-semibold">{t('pages:apiArmor.keys.title')}</h2>
        <button className="btn-primary flex items-center gap-1" onClick={startNew}>
          <Plus className="h-4 w-4" /> {t('pages:apiArmor.keys.addList')}
        </button>
      </div>
      {msg && <p className={`text-sm ${msg.isError ? 'text-red-400' : 'text-green-400'}`}>{msg.text}</p>}

      {editing && (
        <div className="space-y-3 border border-slate-700 rounded p-3">
          <h3 className="text-sm font-medium">{editing.id ? t('pages:apiArmor.keys.editList') : t('pages:apiArmor.keys.addList')}</h3>
          <input className="input" placeholder={t('pages:apiArmor.keys.name')} value={editing.name} onChange={(e) => setEditing({ ...editing, name: e.target.value })} />
          <input className="input" placeholder={t('pages:apiArmor.keys.description')} value={editing.description || ''} onChange={(e) => setEditing({ ...editing, description: e.target.value })} />

          <div>
            <label className="text-xs text-slate-400 block mb-1">{t('pages:apiArmor.keys.entries')}</label>
            <div className="flex gap-2 mb-2">
              <input className="input flex-1" placeholder={t('pages:apiArmor.keys.newKey')} value={newEntry} onChange={(e) => setNewEntry(e.target.value)} />
              <button className="btn-primary" onClick={addEntry}>{t('pages:apiArmor.keys.addKey')}</button>
            </div>
            <div className="space-y-1 max-h-48 overflow-auto border border-slate-700 rounded p-2">
              {editing.entries?.map((e: any, idx: number) => (
                <div key={idx} className="flex items-center justify-between text-xs">
                  <code className="text-slate-300">{typeof e === 'string' ? e : e.value}</code>
                  <button onClick={() => removeEntry(idx)} className="text-red-400 hover:underline">{t('common:remove', 'Remove')}</button>
                </div>
              ))}
            </div>
          </div>

          <div className="flex gap-2">
            <button className="btn-primary" onClick={save}>{t('pages:apiArmor.keys.save')}</button>
            <button className="btn" onClick={() => setEditing(null)}><X className="h-4 w-4" /></button>
          </div>
        </div>
      )}

      <div className="space-y-2">
        {lists.map((l) => (
          <div key={l.id} className="border border-slate-700 rounded p-3">
            <div className="flex items-center justify-between">
              <div>
                <div className="font-medium text-sm">{l.name}</div>
                {l.description && <div className="text-xs text-slate-400">{l.description}</div>}
                <div className="text-xs text-slate-500 mt-1">{t('pages:apiArmor.keys.keysCount', { count: l.entries?.length || 0 })}</div>
              </div>
              <div className="flex items-center gap-2">
                <button onClick={() => startEdit(l)} className="text-primary hover:underline text-xs flex items-center gap-1">
                  <Pencil className="h-3 w-3" /> {t('pages:apiArmor.schemas.edit')}
                </button>
                <button onClick={() => setConfirmDelete(l)} className="text-red-400 hover:underline text-xs flex items-center gap-1">
                  <Trash2 className="h-3 w-3" /> {t('pages:apiArmor.keys.delete')}
                </button>
              </div>
            </div>
            {confirmDelete?.id === l.id && (
              <div className="mt-2 flex items-center gap-2 text-xs">
                <span className="text-slate-400">{t('pages:apiArmor.keys.confirmDelete', { name: l.name })}</span>
                <button className="text-red-400 hover:underline" onClick={() => del(l)}>{t('common:yes', 'Yes')}</button>
                <button className="text-primary hover:underline" onClick={() => setConfirmDelete(null)}>{t('common:cancel', 'Cancel')}</button>
              </div>
            )}
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
  const [msg, setMsg] = useState<Msg | null>(null)
  const [confirmDelete, setConfirmDelete] = useState<any | null>(null)

  const load = () => {
    setMsg(null)
    apiArmor.profiles.list().then((r) => setProfiles(r.data)).catch(() => setMsg({ text: t('pages:apiArmor.profiles.failedToLoadProfiles'), isError: true }))
  }

  useEffect(() => { load() }, [])

  const finalize = async (p: any) => {
    try {
      await apiArmor.profiles.finalize(p.id)
      setMsg({ text: t('pages:apiArmor.profiles.finalized'), isError: false })
      load()
    } catch (e: any) {
      setMsg({ text: e?.response?.data?.detail || t('pages:apiArmor.profiles.failedToFinalize'), isError: true })
    }
  }

  const del = async (p: any) => {
    try { await apiArmor.profiles.delete(p.id); setConfirmDelete(null); load() } catch { setConfirmDelete(null) }
  }

  return (
    <div className="card space-y-4 max-w-4xl">
      <h2 className="text-lg font-semibold">{t('pages:apiArmor.profiles.title')}</h2>
      {msg && <p className={`text-sm ${msg.isError ? 'text-red-400' : 'text-green-400'}`}>{msg.text}</p>}
      <div className="space-y-2">
        {profiles.map((p) => (
          <div key={p.id} className="border border-slate-700 rounded p-3">
            <div className="flex items-center justify-between">
              <div>
                <div className="font-medium text-sm">{p.method} {p.path}</div>
                <span className={`text-xs px-2 py-0.5 rounded ${p.learned ? 'bg-green-900' : 'bg-yellow-900'}`}>
                  {p.learned ? t('pages:apiArmor.profiles.learned') : t('pages:apiArmor.profiles.learning')}
                </span>
              </div>
              <div className="flex items-center gap-2">
                {!p.learned && (
                  <button onClick={() => finalize(p)} className="text-primary hover:underline text-xs flex items-center gap-1">
                    <Check className="h-3 w-3" /> {t('pages:apiArmor.profiles.finalize')}
                  </button>
                )}
                <button onClick={() => setConfirmDelete(p)} className="text-red-400 hover:underline text-xs flex items-center gap-1">
                  <Trash2 className="h-3 w-3" /> {t('pages:apiArmor.profiles.delete')}
                </button>
              </div>
            </div>
            <div className="text-xs text-slate-400 mt-1">{t('pages:apiArmor.profiles.samples', { count: p.sample_count })}</div>
            {Object.keys(p.dimensions || {}).length > 0 && (
              <div className="text-xs text-slate-500 mt-1">
                {t('pages:apiArmor.profiles.dimensions', { dims: Object.keys(p.dimensions).join(', ') })}
              </div>
            )}
            {confirmDelete?.id === p.id && (
              <div className="mt-2 flex items-center gap-2 text-xs">
                <span className="text-slate-400">{t('pages:apiArmor.profiles.confirmDelete', { method: p.method, path: p.path })}</span>
                <button className="text-red-400 hover:underline" onClick={() => del(p)}>{t('common:yes', 'Yes')}</button>
                <button className="text-primary hover:underline" onClick={() => setConfirmDelete(null)}>{t('common:cancel', 'Cancel')}</button>
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
  const [msg, setMsg] = useState<Msg | null>(null)
  const [filters, setFilters] = useState({ method: '', path: '', dimension: '' })

  const load = () => {
    setMsg(null)
    apiArmor.anomalies.list({ limit: 100, ...filters }).then((r) => setAnomalies(r.data)).catch(() => setMsg({ text: t('pages:apiArmor.anomalies.failedToLoadAnomalies'), isError: true }))
  }

  useEffect(() => { load() }, [])

  const clear = async () => {
    try { await apiArmor.anomalies.clear(filters); setAnomalies([]) } catch { /* ignore */ }
  }

  return (
    <div className="card space-y-4 max-w-4xl">
      <div className="flex items-center justify-between">
        <h2 className="text-lg font-semibold">{t('pages:apiArmor.anomalies.title')}</h2>
        {anomalies.length > 0 && (
          <button className="text-red-400 hover:underline text-xs" onClick={clear}>{t('pages:apiArmor.anomalies.clearAll')}</button>
        )}
      </div>
      <div className="flex gap-2">
        <input className="input" placeholder="Method" value={filters.method} onChange={(e) => setFilters({ ...filters, method: e.target.value })} />
        <input className="input" placeholder="Path" value={filters.path} onChange={(e) => setFilters({ ...filters, path: e.target.value })} />
        <input className="input" placeholder="Dimension" value={filters.dimension} onChange={(e) => setFilters({ ...filters, dimension: e.target.value })} />
        <button className="btn-primary" onClick={load}>{t('common:filter', 'Filter')}</button>
      </div>
      {msg && <p className={`text-sm ${msg.isError ? 'text-red-400' : 'text-green-400'}`}>{msg.text}</p>}
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
