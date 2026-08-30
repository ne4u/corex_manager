import React, { useEffect, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { Shield, FileText, Ban, Activity, GitBranch, Download, Upload, Heart, Pencil, Trash2, RefreshCw, Camera, RotateCcw, FileCode } from 'lucide-react'
import { wafRules, wafExceptions, listeners, waf, backends, settings } from '../services/api'
import useApiList from '../hooks/useApiList'
import Modal from '../components/Modal'
import LabelWithTooltip from '../components/LabelWithTooltip'
import InfoTooltip from '../components/InfoTooltip'
import { Tabs, IconButton } from '../components/ui'
import { useDateTime } from '../contexts/DateTimeContext'
import WafLogs from './WafLogs'

const actionOptions = ['block', 'allow', 'log', 'redirect', 'challenge']

// Rate-based WAF counting only runs for actions that produce a Coraza deny
// verdict (the generator's non-allow branch). "allow" short-circuits before
// the counters, so rate limiting is a no-op there.
const RATE_ENABLED_ACTIONS = ['block', 'log', 'redirect', 'challenge']

const wafRuleTooltips = {
  name: 'waf.tooltips.name',
  listener: 'waf.tooltips.listener',
  backendScope: 'waf.tooltips.backendScope',
  ruleSet: 'waf.tooltips.ruleSet',
  ruleSetVersion: 'waf.tooltips.ruleSetVersion',
  ruleSetUrl: 'waf.tooltips.ruleSetUrl',
  ruleSetSha256: 'waf.tooltips.ruleSetSha256',
  ruleSetUpdateIntervalHours: 'waf.tooltips.ruleSetUpdateIntervalHours',
  ruleSetAutoUpdate: 'waf.tooltips.ruleSetAutoUpdate',
  plugins: 'waf.tooltips.plugins',
  engine: 'waf.tooltips.engine',
  paranoiaLevel: 'waf.tooltips.paranoiaLevel',
  inboundAnomalyThreshold: 'waf.tooltips.inboundAnomalyThreshold',
  outboundAnomalyThreshold: 'waf.tooltips.outboundAnomalyThreshold',
  action: 'waf.tooltips.action',
  siemIntegration: 'waf.tooltips.siemIntegration',
  redirectUrl: 'waf.tooltips.redirectUrl',
  captchaValidSeconds: 'waf.tooltips.captchaValidSeconds',
  statusCode: 'waf.tooltips.statusCode',
  pathPattern: 'waf.tooltips.pathPattern',
  httpMethods: 'waf.tooltips.httpMethods',
  contentTypes: 'waf.tooltips.contentTypes',
  failOpen: 'waf.tooltips.failOpen',
  rateBasedRule: 'waf.tooltips.rateBasedRule',
  rateEvents: 'waf.tooltips.rateEvents',
  rateWindowSeconds: 'waf.tooltips.rateWindowSeconds',
  rateKey: 'waf.tooltips.rateKey',
  rateHeader: 'waf.tooltips.rateHeader',
  rateAction: 'waf.tooltips.rateAction',
  rateDurationSeconds: 'waf.tooltips.rateDurationSeconds',
  customSecRules: 'waf.tooltips.customSecRules',
  enabled: 'waf.tooltips.enabled',
  versionName: 'waf.tooltips.versionName',
}

const wafExceptionTooltips = {
  name: 'waf.tooltips.exName',
  wafRule: 'waf.tooltips.exWafRule',
  ruleId: 'waf.tooltips.exRuleId',
  ruleTag: 'waf.tooltips.exRuleTag',
  ruleMsg: 'waf.tooltips.exRuleMsg',
  exceptionAction: 'waf.tooltips.exExceptionAction',
  updateAction: 'waf.tooltips.exUpdateAction',
  updateTarget: 'waf.tooltips.exUpdateTarget',
  zone: 'waf.tooltips.exZone',
  variable: 'waf.tooltips.exVariable',
  matcher: 'waf.tooltips.exMatcher',
  value: 'waf.tooltips.exValue',
  conditionVariable: 'waf.tooltips.exConditionVariable',
  conditionOperator: 'waf.tooltips.exConditionOperator',
  conditionValue: 'waf.tooltips.exConditionValue',
  description: 'waf.tooltips.exDescription',
}

const wafSiemTooltips = {
  name: 'waf.tooltips.siemName',
  integrationType: 'waf.tooltips.siemIntegrationType',
  target: 'waf.tooltips.siemTarget',
  format: 'waf.tooltips.siemFormat',
  authHeader: 'waf.tooltips.siemAuthHeader',
  enabled: 'waf.tooltips.siemEnabled',
}

function emptyRule() {
  return {
    name: '', listener_id: null as number | null, backend_id: null as number | null,
    enabled: true, rule_set: 'crs', rule_set_version: '', rule_set_url: '',
    rule_set_sha256: '', rule_set_auto_update: false, rule_set_update_interval_hours: 24,
    rule_set_last_updated_at: null as string | null, rule_set_last_error: null as string | null,
    rule_set_plugins: [] as string[],
    engine: 'On', paranoia_level: 1, inbound_anomaly_threshold: 5,
    outbound_anomaly_threshold: 4, sec_rules: '', action: 'block', redirect_url: '',
    status_code: 403, captcha_valid_seconds: 3600,
    path_pattern: '', http_methods: '', content_types: '',
    rate_enabled: false, rate_events: 100, rate_window_seconds: 60, rate_key: 'src',
    rate_header: '', rate_action: 'block', rate_duration_seconds: 0, fail_open: false, siem_integration_id: null as number | null,
  }
}

function emptyException() {
  return {
    waf_rule_id: '' as number | string, name: '', rule_id: '', rule_tag: '', rule_msg: '',
    zone: '', variable: '', matcher: 'equals', value: '', description: '', action: 'remove',
    update_action: '', update_target: '', condition_variable: '', condition_operator: 'equals',
    condition_value: '',
  }
}

export default function Waf() {
  const { t } = useTranslation(['pages', 'common'])
  const { formatDateTime } = useDateTime()
  const { items: rules, reload: rr } = useApiList(wafRules.list)
  const { items: exceptions, reload: re } = useApiList(wafExceptions.list)
  const { items: listenerList } = useApiList(listeners.list)
  const { items: backendList } = useApiList(backends.list)
  const { items: siemIntegrations, reload: rSiem } = useApiList(waf.siem.list)
  const { items: ruleVersions, reload: rVersions } = useApiList(waf.ruleVersions.list)

  const [tab, setTab] = useState('rules')
  const [health, setHealth] = useState<any>(null)
  const [asnDbAvailable, setAsnDbAvailable] = useState(false)

  const [open, setOpen] = useState(false)
  const [editing, setEditing] = useState<number | null>(null)
  const [form, setForm] = useState<any>(emptyRule())

  const [exOpen, setExOpen] = useState(false)
  const [exEditing, setExEditing] = useState<number | null>(null)
  const [exForm, setExForm] = useState<any>(emptyException())

  const [siemOpen, setSiemOpen] = useState(false)
  const [siemEditing, setSiemEditing] = useState<number | null>(null)
  const [siemForm, setSiemForm] = useState<any>({ name: '', integration_type: 'webhook', target: '', format: 'json', auth_header: '', enabled: true })

  const [versionOpen, setVersionOpen] = useState(false)
  const [versionRuleId, setVersionRuleId] = useState<number | null>(null)
  const [versionName, setVersionName] = useState('')
  const [versionMax, setVersionMax] = useState<number | null>(null)
  const [versionMaxInput, setVersionMaxInput] = useState('')

  const [crsStatus, setCrsStatus] = useState<any>(null)
  const [crsSnapshots, setCrsSnapshots] = useState<any[]>([])
  const [crsPinnedInput, setCrsPinnedInput] = useState('')

  const [searchParams, setSearchParams] = useSearchParams()

  useEffect(() => {
    waf.health().then(res => setHealth(res.data)).catch(() => setHealth(null))
  }, [tab])

  useEffect(() => {
    settings.getGeoipStatus()
      .then(res => {
        const dbs = res.data?.databases || []
        setAsnDbAvailable(dbs.some((d: any) => d.name === 'ASN' && d.exists))
      })
      .catch(() => setAsnDbAvailable(false))
  }, [])

  useEffect(() => {
    if (tab !== 'versions') return
    waf.ruleVersions.getMax()
      .then(res => {
        const val = Number(res.data?.value)
        setVersionMax(Number.isNaN(val) ? null : val)
        setVersionMaxInput(Number.isNaN(val) ? '' : String(val))
      })
      .catch(() => { setVersionMax(null); setVersionMaxInput('') })
  }, [tab])

  useEffect(() => {
    if (tab !== 'crs') return
    waf.crs.status().then(res => setCrsStatus(res.data)).catch(() => setCrsStatus(null))
    waf.crs.snapshots().then(res => setCrsSnapshots(res.data || [])).catch(() => setCrsSnapshots([]))
    waf.crs.status().then(res => setCrsPinnedInput(res.data?.pinned_version || '')).catch(() => {})
  }, [tab])

  // Open the rule form from ?edit=<id> or ?listener=<id> deep links
  useEffect(() => {
    const editId = searchParams.get('edit')
    const listenerId = searchParams.get('listener')
    if (editId && rules.length) {
      const rule = rules.find((r: any) => r.id === Number(editId))
      if (rule) {
        openEdit(rule)
        setSearchParams({})
      }
    } else if (listenerId && listenerList.length) {
      const listener = listenerList.find((l: any) => l.id === Number(listenerId))
      if (listener) {
        setEditing(null)
        setForm({ ...emptyRule(), listener_id: listener.id, name: `waf-${listener.name}` })
        setOpen(true)
        setSearchParams({})
      }
    }
  }, [rules, listenerList, searchParams])

  const openAdd = () => { setEditing(null); setForm(emptyRule()); setOpen(true) }
  const openEdit = (r: any) => {
    setEditing(r.id)
    setForm({
      ...r,
      engine: r.engine || 'On',
      inbound_anomaly_threshold: r.inbound_anomaly_threshold ?? 5,
      outbound_anomaly_threshold: r.outbound_anomaly_threshold ?? 4,
      status_code: r.status_code ?? 403,
      redirect_url: r.redirect_url || '',
      captcha_valid_seconds: r.captcha_valid_seconds ?? 3600,
      rule_set_plugins: r.rule_set_plugins || [],
      rule_set_last_updated_at: r.rule_set_last_updated_at || null,
      rule_set_last_error: r.rule_set_last_error || null,
      rate_enabled: r.rate_enabled ?? false,
      rate_events: r.rate_events ?? 100,
      rate_window_seconds: r.rate_window_seconds ?? 60,
      rate_key: r.rate_key || 'src',
      rate_action: r.rate_action || 'block',
      rate_duration_seconds: r.rate_duration_seconds ?? 0,
      fail_open: r.fail_open ?? false,
    })
    setOpen(true)
  }

  const openExAdd = () => { setExEditing(null); setExForm(emptyException()); setExOpen(true) }
  const openExEdit = (e: any) => { setExEditing(e.id); setExForm({ ...e, waf_rule_id: e.waf_rule_id ? String(e.waf_rule_id) : '' }); setExOpen(true) }

  const handleExport = async () => {
    try {
      const res = await wafRules.export()
      const blob = new Blob([JSON.stringify(res.data, null, 2)], { type: 'application/json' })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = 'waf-rules.json'
      a.click()
      URL.revokeObjectURL(url)
    } catch (err) { alert(t('waf.errors.exportFailed')) }
  }

  const handleImport = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    if (!file) return
    try {
      const text = await file.text()
      const data = JSON.parse(text)
      await wafRules.import(data)
      rr(); re()
    } catch (err) { alert(t('waf.errors.importFailed')) }
  }

  const submit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (editing) await wafRules.update(editing, form)
    else await wafRules.create(form)
    setForm(emptyRule()); setEditing(null); setOpen(false); rr()
  }

  const exSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    const payload = { ...exForm, waf_rule_id: exForm.waf_rule_id ? Number(exForm.waf_rule_id) : null }
    if (exEditing) await wafExceptions.update(exEditing, payload)
    else await wafExceptions.create(payload)
    setExForm(emptyException()); setExEditing(null); setExOpen(false); re()
  }

  const siemSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (siemEditing) await waf.siem.update(siemEditing, siemForm)
    else await waf.siem.create(siemForm)
    setSiemForm({ name: '', integration_type: 'webhook', target: '', format: 'json', auth_header: '', enabled: true })
    setSiemEditing(null); setSiemOpen(false); rSiem()
  }

  const snapshotRule = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!versionRuleId || !versionName) return
    await waf.ruleVersions.snapshot(versionRuleId, versionName)
    setVersionName(''); setVersionRuleId(null); setVersionOpen(false); rVersions()
  }

  const restoreRule = async (ruleId: number, versionId: number) => {
    await waf.ruleVersions.restore(ruleId, versionId)
    rr()
  }

  const deleteVersion = async (v: any) => {
    const ruleName = rules.find((r: any) => r.id === v.waf_rule_id)?.name ?? `rule ${v.waf_rule_id}`
    if (!window.confirm(t('waf.versions.confirmDelete', { version: v.version, ruleName }))) return
    try {
      await waf.ruleVersions.remove(v.id)
      rVersions()
    } catch {
      alert(t('waf.versions.deleteFailed'))
    }
  }

  const saveVersionMax = async () => {
    const val = Number(versionMaxInput)
    if (Number.isNaN(val) || val < 0) {
      alert(t('waf.versions.maxInvalid'))
      return
    }
    try {
      const res = await waf.ruleVersions.setMax(val)
      const next = Number(res.data?.value)
      setVersionMax(Number.isNaN(next) ? null : next)
      setVersionMaxInput(Number.isNaN(next) ? '' : String(next))
      rVersions()
    } catch {
      alert(t('waf.versions.updateMaxFailed'))
    }
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h2 className="text-2xl font-bold flex items-center gap-2"><Shield className="h-5 w-5 text-primary" /> {t('waf.title')}</h2>
        <div className="flex items-center gap-2">
          <button onClick={handleExport} className="btn-secondary"><Download className="w-4 h-4 inline me-1" /> {t('waf.export')}</button>
          <label className="btn-secondary cursor-pointer">
            <Upload className="w-4 h-4 inline me-1" /> {t('waf.import')}
            <input type="file" className="hidden" onChange={handleImport} accept=".json" />
          </label>
        </div>
      </div>

      <Tabs
        tabs={[
          { id: 'rules', label: t('waf.tabs.rules'), icon: FileText },
          { id: 'exceptions', label: t('waf.tabs.exceptions'), icon: Ban },
          { id: 'siem', label: t('waf.tabs.siem'), icon: Activity },
          { id: 'versions', label: t('waf.tabs.versions'), icon: GitBranch },
          { id: 'crs', label: t('waf.tabs.crs'), icon: Download },
          { id: 'logs', label: t('waf.tabs.logs'), icon: FileCode },
          { id: 'health', label: t('waf.tabs.health'), icon: Heart },
        ]}
        active={tab}
        onChange={setTab}
      />

      {tab === 'rules' && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-xl font-bold">{t('waf.rules.title')}</h3>
            <button onClick={openAdd} className="btn-primary">{t('waf.rules.addRule')}</button>
          </div>
          <div className="card overflow-x-auto">
            <table className="w-full text-sm text-start">
              <thead className="text-slate-400 border-b border-slate-800"><tr><th>{t('waf.rules.tableHeaders.name')}</th><th>{t('waf.rules.tableHeaders.listener')}</th><th>{t('waf.rules.tableHeaders.backend')}</th><th>{t('waf.rules.tableHeaders.ruleSet')}</th><th>{t('waf.rules.tableHeaders.engine')}</th><th>{t('waf.rules.tableHeaders.paranoia')}</th><th>{t('waf.rules.tableHeaders.action')}</th><th>{t('waf.rules.tableHeaders.enabled')}</th><th className="w-40 whitespace-nowrap">{t('waf.rules.tableHeaders.updated')}</th><th></th></tr></thead>
              <tbody>
                {rules.map((r: any) => (
                  <tr key={r.id} className="border-b border-slate-800 last:border-0">
                    <td className="py-2">{r.name}</td>
                    <td>{r.listener_id ? listenerList.find((l: any) => l.id === r.listener_id)?.name : t('waf.rules.all')}</td>
                    <td>{r.backend_id ? backendList.find((b: any) => b.id === r.backend_id)?.name : t('waf.rules.any')}</td>
                    <td>{r.rule_set} {r.rule_set_version}</td>
                    <td>{r.engine}</td>
                    <td>{r.paranoia_level}</td>
                    <td>{r.action}</td>
                    <td>{r.enabled ? t('waf.rules.yes') : t('waf.rules.no')}</td>
                    <td className="py-2 text-xs text-slate-400 whitespace-nowrap">{r.updated_at ? formatDateTime(r.updated_at) : '-'}</td>
                    <td>
                      <div className="flex gap-1">
                        <IconButton icon={Pencil} aria-label={t('common:actions.edit')} onClick={() => openEdit(r)} />
                        {r.rule_set === 'remote' && <IconButton icon={RefreshCw} aria-label={t('common:actions.refresh')} onClick={() => wafRules.refreshRuleSet(r.id).then(rr)} />}
                        <IconButton icon={Camera} aria-label={t('waf.versions.title')} onClick={() => { setVersionRuleId(r.id); setVersionName(''); setVersionOpen(true) }} />
                        <IconButton icon={Trash2} variant="danger" aria-label={t('common:actions.delete')} onClick={() => wafRules.remove(r.id).then(rr)} />
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {tab === 'exceptions' && (
        <div className="space-y-4">
          <div className="flex items-center justify-between"><h3 className="text-xl font-bold">{t('waf.exceptions.title')}</h3><button onClick={openExAdd} className="btn-primary">{t('waf.exceptions.addException')}</button></div>
          <div className="card overflow-x-auto">
            <table className="w-full text-sm text-start">
              <thead className="text-slate-400 border-b border-slate-800"><tr><th>{t('waf.exceptions.tableHeaders.name')}</th><th>{t('waf.exceptions.tableHeaders.ruleId')}</th><th>{t('waf.exceptions.tableHeaders.tag')}</th><th>{t('waf.exceptions.tableHeaders.msg')}</th><th>{t('waf.exceptions.tableHeaders.action')}</th><th className="w-40 whitespace-nowrap">{t('waf.exceptions.tableHeaders.updated')}</th><th></th></tr></thead>
              <tbody>
                {exceptions.map((e: any) => (
                  <tr key={e.id} className="border-b border-slate-800 last:border-0">
                    <td className="py-2">{e.name}</td><td>{e.rule_id}</td><td>{e.rule_tag}</td><td>{e.rule_msg}</td><td>{e.action}</td><td className="py-2 text-xs text-slate-400 whitespace-nowrap">{e.updated_at ? formatDateTime(e.updated_at) : '-'}</td>
                    <td>
                      <div className="flex gap-1">
                        <IconButton icon={Pencil} aria-label={t('common:actions.edit')} onClick={() => openExEdit(e)} />
                        <IconButton icon={Trash2} variant="danger" aria-label={t('common:actions.delete')} onClick={() => wafExceptions.remove(e.id).then(re)} />
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {tab === 'siem' && (
        <div className="space-y-4">
          <div className="flex items-center justify-between"><h3 className="text-xl font-bold">{t('waf.siem.title')}</h3>
            <button onClick={() => { setSiemEditing(null); setSiemForm({ name: '', integration_type: 'webhook', target: '', format: 'json', auth_header: '', enabled: true }); setSiemOpen(true) }} className="btn-primary">{t('waf.siem.addSiem')}</button>
          </div>
          <div className="card overflow-x-auto">
            <table className="w-full text-sm text-start">
              <thead className="text-slate-400 border-b border-slate-800"><tr><th>{t('waf.siem.tableHeaders.name')}</th><th>{t('waf.siem.tableHeaders.type')}</th><th>{t('waf.siem.tableHeaders.target')}</th><th>{t('waf.siem.tableHeaders.format')}</th><th>{t('waf.siem.tableHeaders.enabled')}</th><th></th></tr></thead>
              <tbody>
                {siemIntegrations.map((s: any) => (
                  <tr key={s.id} className="border-b border-slate-800 last:border-0">
                    <td className="py-2">{s.name}</td><td>{s.integration_type}</td><td>{s.target}</td><td>{s.format}</td><td>{s.enabled ? t('waf.rules.yes') : t('waf.rules.no')}</td>
                    <td>
                      <div className="flex gap-1">
                        <IconButton icon={Pencil} aria-label={t('common:actions.edit')} onClick={() => { setSiemEditing(s.id); setSiemForm(s); setSiemOpen(true) }} />
                        <IconButton icon={Trash2} variant="danger" aria-label={t('common:actions.delete')} onClick={() => waf.siem.remove(s.id).then(rSiem)} />
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {tab === 'versions' && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-xl font-bold">{t('waf.versions.title')}</h3>
            <div className="flex items-center gap-2 text-sm">
              <label className="text-slate-400">{t('waf.versions.maxPerRule')}</label>
              <input
                type="number"
                min={0}
                className="input w-24"
                value={versionMaxInput}
                onChange={e => setVersionMaxInput(e.target.value)}
                placeholder="10"
              />
              <span className="text-xs text-slate-500">{t('waf.versions.unlimitedHint')}{versionMax !== null ? ` ${t('waf.versions.savedHint', { value: versionMax === 0 ? t('waf.versions.unlimited') : versionMax })}` : ''}</span>
              <button onClick={saveVersionMax} className="btn-primary">{t('waf.versions.save')}</button>
            </div>
          </div>
          <div className="card overflow-x-auto">
            <table className="w-full text-sm text-start">
              <thead className="text-slate-400 border-b border-slate-800"><tr><th>{t('waf.versions.tableHeaders.rule')}</th><th>{t('waf.versions.tableHeaders.version')}</th><th>{t('waf.versions.tableHeaders.created')}</th><th>{t('waf.versions.tableHeaders.by')}</th><th></th></tr></thead>
              <tbody>
                {ruleVersions.map((v: any) => (
                  <tr key={v.id} className="border-b border-slate-800 last:border-0">
                    <td className="py-2">{rules.find((r: any) => r.id === v.waf_rule_id)?.name}</td>
                    <td>{v.version}</td>
                    <td>{formatDateTime(v.created_at)}</td>
                    <td>{v.created_by}</td>
                    <td>
                      <div className="flex gap-1">
                        <IconButton icon={RotateCcw} aria-label={t('common:actions.revert')} onClick={() => restoreRule(v.waf_rule_id, v.id)} />
                        <IconButton icon={Trash2} variant="danger" aria-label={t('common:actions.delete')} onClick={() => deleteVersion(v)} />
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {tab === 'crs' && (
        <div className="space-y-4">
          <h3 className="text-xl font-bold">{t('waf.crs.title')}</h3>

          {/* Status section */}
          <div className="card space-y-2">
            <h4 className="font-semibold">{t('waf.crs.currentStatus')}</h4>
            {crsStatus ? (
              <div className="grid grid-cols-2 gap-2 text-sm">
                <div><span className="text-slate-400">{t('waf.crs.mode')}</span> <span className={crsStatus.mode === 'filesystem' ? 'text-green-400' : 'text-amber-400'}>{crsStatus.mode === 'filesystem' ? t('waf.crs.modeFilesystem') : t('waf.crs.modeEmbedded')}</span></div>
                <div><span className="text-slate-400">{t('waf.crs.activeVersion')}</span> {crsStatus.active_version || <span className="text-slate-500">—</span>}</div>
                <div><span className="text-slate-400">{t('waf.crs.pinnedVersion')}</span> {crsStatus.pinned_version || <span className="text-slate-500">{t('waf.crs.pinnedLatest')}</span>}</div>
                <div><span className="text-slate-400">{t('waf.crs.filesPresent')}</span> {crsStatus.files_present ? '✓' : '✗'}</div>
                {crsStatus.path && <div className="col-span-2"><span className="text-slate-400">{t('waf.crs.includePath')}</span> <code className="text-xs">{crsStatus.path}</code></div>}
              </div>
            ) : <div className="text-slate-500 text-sm">{t('waf.crs.loadingStatus')}</div>}
          </div>

          {/* Download + pin section */}
          <div className="card space-y-3">
            <h4 className="font-semibold">{t('waf.crs.downloadUpdate')}</h4>
            <div className="flex items-center gap-2">
              <button
                onClick={async () => {
                  try {
                    await waf.crs.download()
                    const [s, sn] = await Promise.all([waf.crs.status(), waf.crs.snapshots()])
                    setCrsStatus(s.data); setCrsSnapshots(sn.data || [])
                  } catch (e: any) { alert(e?.response?.data?.detail || t('waf.crs.downloadFailed')) }
                }}
                className="btn-primary"
              >
                {crsStatus?.pinned_version ? t('waf.crs.downloadVersion', { version: crsStatus.pinned_version }) : t('waf.crs.downloadLatest')}
              </button>
              <span className="text-xs text-slate-500">{t('waf.crs.downloadHint')}</span>
            </div>
            <div className="flex items-center gap-2 text-sm">
              <label className="text-slate-400">{t('waf.crs.pinVersion')}</label>
              <input
                className="input w-32"
                value={crsPinnedInput}
                onChange={e => setCrsPinnedInput(e.target.value)}
                placeholder={t('waf.crs.pinPlaceholder')}
              />
              <button
                onClick={async () => {
                  try {
                    await waf.crs.setPinnedVersion(crsPinnedInput.trim())
                    const res = await waf.crs.status()
                    setCrsStatus(res.data)
                  } catch (e: any) { alert(e?.response?.data?.detail || t('waf.crs.setPinnedFailed')) }
                }}
                className="btn-primary"
              >
                {t('waf.crs.pinSave')}
              </button>
              <span className="text-xs text-slate-500">{t('waf.crs.pinEmptyHint')}</span>
            </div>
          </div>

          {/* Snapshots table */}
          <div className="card overflow-x-auto">
            <h4 className="font-semibold mb-2">{t('waf.crs.snapshotsTitle')}</h4>
            <table className="w-full text-sm text-start">
              <thead className="text-slate-400 border-b border-slate-800"><tr><th>{t('waf.crs.tableHeaders.version')}</th><th>{t('waf.crs.tableHeaders.hash')}</th><th>{t('waf.crs.tableHeaders.created')}</th><th>{t('waf.crs.tableHeaders.by')}</th><th></th></tr></thead>
              <tbody>
                {crsSnapshots.length === 0 && (
                  <tr><td colSpan={5} className="py-4 text-center text-slate-500">{t('waf.crs.noSnapshots')}</td></tr>
                )}
                {crsSnapshots.map((s: any) => (
                  <tr key={s.id} className="border-b border-slate-800 last:border-0">
                    <td className="py-2">
                      {s.version}
                      {crsStatus?.active_version === s.dir_version && <span className="ms-2 text-xs text-green-400">{t('waf.crs.active')}</span>}
                    </td>
                    <td className="text-xs text-slate-500 font-mono">{(s.file_hash || '').slice(0, 12)}…</td>
                    <td>{s.created_at ? formatDateTime(s.created_at) : '—'}</td>
                    <td>{s.created_by || '—'}</td>
                    <td>
                      <div className="flex gap-1">
                        {crsStatus?.active_version !== s.dir_version && (
                          <IconButton
                            icon={RotateCcw}
                            aria-label={t('common:actions.revert')}
                            onClick={async () => {
                              if (!window.confirm(t('waf.crs.confirmRollback', { version: s.version }))) return
                              try {
                                await waf.crs.rollback(s.id)
                                const res = await waf.crs.status()
                                setCrsStatus(res.data)
                              } catch (e: any) { alert(e?.response?.data?.detail || t('waf.crs.rollbackFailed')) }
                            }}
                          />
                        )}
                        <IconButton
                          icon={Trash2}
                          variant="danger"
                          aria-label={t('common:actions.delete')}
                          onClick={async () => {
                            if (!window.confirm(t('waf.crs.confirmDelete', { version: s.version }))) return
                            try {
                              await waf.crs.deleteSnapshot(s.id)
                              const [st, sn] = await Promise.all([waf.crs.status(), waf.crs.snapshots()])
                              setCrsStatus(st.data); setCrsSnapshots(sn.data || [])
                            } catch (e: any) { alert(e?.response?.data?.detail || t('waf.crs.deleteFailed')) }
                          }}
                        />
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {tab === 'logs' && <WafLogs />}

      {tab === 'health' && (
        <div className="space-y-4">
          <h3 className="text-xl font-bold">{t('waf.health.title')}</h3>
          <div className="card">
            {health ? (
              <div className="space-y-4 text-sm">
                <div className="grid grid-cols-2 gap-4">
                  <div><strong>{t('waf.health.status')}</strong> <span className={health.status === 'ok' ? 'text-green-400' : 'text-yellow-400'}>{health.status}</span></div>
                  <div><strong>{t('waf.health.spoaReachable')}</strong> {health.coraza_spoa_reachable ? t('waf.rules.yes') : t('waf.rules.no')}</div>
                  <div><strong>{t('waf.health.spoaLatency')}</strong> {health.coraza_spoa_latency_ms ?? 'N/A'} ms</div>
                  <div><strong>{t('waf.health.configPresent')}</strong> {health.config_present ? t('waf.rules.yes') : t('waf.rules.no')}</div>
                  <div><strong>{t('waf.health.logPresent')}</strong> {health.log_present ? t('waf.rules.yes') : t('waf.rules.no')}</div>
                  <div><strong>{t('waf.health.configGenerated')}</strong> {health.config_generated ? t('waf.rules.yes') : t('waf.rules.no')}</div>
                  <div><strong>{t('waf.health.spoaTargets')}</strong> {health.spoa_targets}</div>
                </div>
                {health.counts && (
                  <div className="grid grid-cols-3 gap-4 border-t border-slate-800 pt-4">
                    {Object.entries(health.counts).map(([k, v]) => (
                      <div key={k}><strong>{k.replace(/_/g, ' ')}:</strong> {String(v)}</div>
                    ))}
                  </div>
                )}
                {health.last_error && <div className="text-red-400"><strong>{t('waf.health.lastError')}</strong> {health.last_error}</div>}
                {health.last_log_line && <div className="text-slate-400 break-all"><strong>{t('waf.health.lastLogLine')}</strong> {health.last_log_line}</div>}
              </div>
            ) : <p>{t('waf.health.unableToLoad')}</p>}
          </div>
        </div>
      )}

      <Modal open={open} onClose={() => setOpen(false)} title={editing ? t('waf.rules.editTitle') : t('waf.rules.addTitle')}>
        <form onSubmit={submit} className="space-y-3 max-h-[80vh] overflow-y-auto">
          <div className="grid grid-cols-2 gap-3">
            <div><LabelWithTooltip tooltip={t(wafRuleTooltips.name)} className="label">{t('waf.rules.fields.name')}</LabelWithTooltip><input className="input" value={form.name} onChange={e => setForm({ ...form, name: e.target.value })} /></div>
            <div><LabelWithTooltip tooltip={t(wafRuleTooltips.listener)} className="label">{t('waf.rules.fields.listener')}</LabelWithTooltip><select className="input" value={form.listener_id || ''} onChange={e => setForm({ ...form, listener_id: e.target.value ? Number(e.target.value) : null })}><option value="">{t('waf.rules.fields.allListeners')}</option>{listenerList.map((l: any) => <option key={l.id} value={l.id}>{l.name}</option>)}</select></div>
            <div className="col-span-2 text-xs text-slate-500 -mt-1">{t('waf.rules.fields.listenerHint')}</div>
            <div><LabelWithTooltip tooltip={t(wafRuleTooltips.backendScope)} className="label">{t('waf.rules.fields.backendScope')}</LabelWithTooltip><select className="input" value={form.backend_id || ''} onChange={e => setForm({ ...form, backend_id: e.target.value ? Number(e.target.value) : null })}><option value="">{t('waf.rules.fields.anyBackend')}</option>{backendList.map((b: any) => <option key={b.id} value={b.id}>{b.name}</option>)}</select></div>
            <div className="col-span-2 text-xs text-slate-500 -mt-1">{t('waf.rules.fields.backendScopeHint')}</div>
            <div><LabelWithTooltip tooltip={t(wafRuleTooltips.ruleSet)} className="label">{t('waf.rules.fields.ruleSet')}</LabelWithTooltip><select className="input" value={form.rule_set} onChange={e => setForm({ ...form, rule_set: e.target.value })}><option value="crs">{t('waf.rules.ruleSet.crs')}</option><option value="custom">{t('waf.rules.ruleSet.custom')}</option><option value="remote">{t('waf.rules.ruleSet.remote')}</option>{(form.rule_set === 'coraza' || form.rule_set === 'owasp-crs' || form.rule_set === 'commercial') && <option value={form.rule_set}>{form.rule_set}</option>}</select></div>
            <div><LabelWithTooltip tooltip={t(wafRuleTooltips.ruleSetVersion)} className="label">{t('waf.rules.fields.ruleSetVersion')}</LabelWithTooltip><input className="input" value={form.rule_set_version || ''} onChange={e => setForm({ ...form, rule_set_version: e.target.value })} /></div>
            {form.rule_set === 'remote' && (
              <>
                <div><LabelWithTooltip tooltip={t(wafRuleTooltips.ruleSetUrl)} className="label">{t('waf.rules.fields.ruleSetUrl')}</LabelWithTooltip><input className="input" value={form.rule_set_url || ''} onChange={e => setForm({ ...form, rule_set_url: e.target.value })} placeholder="https://example.com/rules.conf" /></div>
                <div><LabelWithTooltip tooltip={t(wafRuleTooltips.ruleSetSha256)} className="label">{t('waf.rules.fields.ruleSetSha256')}</LabelWithTooltip><input className="input" value={form.rule_set_sha256 || ''} onChange={e => setForm({ ...form, rule_set_sha256: e.target.value })} placeholder="abc123..." /></div>
                <div><LabelWithTooltip tooltip={t(wafRuleTooltips.ruleSetUpdateIntervalHours)} className="label">{t('waf.rules.fields.autoUpdateHours')}</LabelWithTooltip><input type="number" className="input" value={form.rule_set_update_interval_hours} onChange={e => setForm({ ...form, rule_set_update_interval_hours: Number(e.target.value), rule_set_auto_update: true })} disabled={!form.rule_set_auto_update} /></div>
                <div><label className="flex items-center gap-2 text-sm"><input type="checkbox" checked={form.rule_set_auto_update} onChange={e => setForm({ ...form, rule_set_auto_update: e.target.checked })} /> <span>{t('waf.rules.fields.enableAutoUpdate')}</span><InfoTooltip content={t(wafRuleTooltips.ruleSetAutoUpdate)} /></label></div>
                {form.rule_set_last_updated_at && <div className="col-span-2 text-xs text-slate-400">{t('waf.rules.fields.lastUpdated')} {formatDateTime(form.rule_set_last_updated_at)}</div>}
                {form.rule_set_last_error && <div className="col-span-2 text-xs text-red-400">{t('waf.rules.fields.lastError')} {form.rule_set_last_error}</div>}
              </>
            )}
            <div><LabelWithTooltip tooltip={t(wafRuleTooltips.plugins)} className="label">{t('waf.rules.fields.plugins')}</LabelWithTooltip><input className="input" value={(form.rule_set_plugins || []).join(', ')} onChange={e => setForm({ ...form, rule_set_plugins: e.target.value.split(',').map((x: string) => x.trim()).filter(Boolean) })} placeholder="plugin1, plugin2" /></div>
            <div><LabelWithTooltip tooltip={t(wafRuleTooltips.engine)} className="label">{t('waf.rules.fields.engine')}</LabelWithTooltip><select className="input" value={form.engine} onChange={e => setForm({ ...form, engine: e.target.value })}><option value="On">{t('waf.rules.fields.engineOn')}</option><option value="DetectionOnly">{t('waf.rules.fields.engineDetectionOnly')}</option><option value="Off">{t('waf.rules.fields.engineOff')}</option></select></div>
            <div><LabelWithTooltip tooltip={t(wafRuleTooltips.paranoiaLevel)} className="label">{t('waf.rules.fields.paranoiaLevel')}</LabelWithTooltip><input type="number" className="input" min={1} max={4} value={form.paranoia_level} onChange={e => setForm({ ...form, paranoia_level: Number(e.target.value) })} /></div>
            <div><LabelWithTooltip tooltip={t(wafRuleTooltips.inboundAnomalyThreshold)} className="label">{t('waf.rules.fields.inboundAnomalyThreshold')}</LabelWithTooltip><input type="number" className="input" min={0} value={form.inbound_anomaly_threshold} onChange={e => setForm({ ...form, inbound_anomaly_threshold: Number(e.target.value) })} /></div>
            <div><LabelWithTooltip tooltip={t(wafRuleTooltips.outboundAnomalyThreshold)} className="label">{t('waf.rules.fields.outboundAnomalyThreshold')}</LabelWithTooltip><input type="number" className="input" min={0} value={form.outbound_anomaly_threshold} onChange={e => setForm({ ...form, outbound_anomaly_threshold: Number(e.target.value) })} /></div>
            <div><LabelWithTooltip tooltip={t(wafRuleTooltips.action)} className="label">{t('waf.rules.fields.action')}</LabelWithTooltip><select className="input" value={form.action} onChange={e => {
              const next = e.target.value
              // Rate-based counting is a no-op for the "allow" action; clear it
              // so the checkbox doesn't stay checked for an unsupported action.
              setForm({ ...form, action: next, rate_enabled: RATE_ENABLED_ACTIONS.includes(next) ? form.rate_enabled : false })
            }}>{actionOptions.map(a => <option key={a} value={a}>{a}</option>)}</select></div>
            <div><LabelWithTooltip tooltip={t(wafRuleTooltips.siemIntegration)} className="label">{t('waf.rules.fields.siemIntegration')}</LabelWithTooltip><select className="input" value={form.siem_integration_id || ''} onChange={e => setForm({ ...form, siem_integration_id: e.target.value ? Number(e.target.value) : null })}><option value="">{t('waf.rules.fields.none')}</option>{siemIntegrations.map((s: any) => <option key={s.id} value={s.id}>{s.name}</option>)}</select></div>
          </div>
          {(form.action === 'redirect' || form.action === 'challenge') && (
            <div><LabelWithTooltip tooltip={t(wafRuleTooltips.redirectUrl)} className="label">{t('waf.rules.fields.redirectUrl')}</LabelWithTooltip><input className="input" placeholder="/_cap/challenge" value={form.redirect_url || ''} onChange={e => setForm({ ...form, redirect_url: e.target.value })} /></div>
          )}
          {form.action === 'challenge' && (
            <div className="text-xs text-slate-500"><span dangerouslySetInnerHTML={{ __html: t('waf.rules.challengeNote') }} /></div>
          )}
          <div><LabelWithTooltip tooltip={t(wafRuleTooltips.statusCode)} className="label">{t('waf.rules.fields.statusCode')}</LabelWithTooltip><input type="number" className="input" min={100} max={599} value={form.status_code} onChange={e => setForm({ ...form, status_code: Number(e.target.value) })} /></div>

          <div className="border-t border-slate-800 pt-3 space-y-3">
            <h4 className="font-semibold">{t('waf.rules.fields.scopeContext')}</h4>
            <div className="grid grid-cols-3 gap-3">
              <div><LabelWithTooltip tooltip={t(wafRuleTooltips.pathPattern)} className="label">{t('waf.rules.fields.pathPattern')}</LabelWithTooltip><input className="input" value={form.path_pattern || ''} onChange={e => setForm({ ...form, path_pattern: e.target.value })} placeholder="/api/" /></div>
              <div><LabelWithTooltip tooltip={t(wafRuleTooltips.httpMethods)} className="label">{t('waf.rules.fields.httpMethods')}</LabelWithTooltip><input className="input" value={form.http_methods || ''} onChange={e => setForm({ ...form, http_methods: e.target.value })} placeholder="GET,POST" /></div>
              <div><LabelWithTooltip tooltip={t(wafRuleTooltips.contentTypes)} className="label">{t('waf.rules.fields.contentTypes')}</LabelWithTooltip><input className="input" value={form.content_types || ''} onChange={e => setForm({ ...form, content_types: e.target.value })} placeholder="application/json" /></div>
            </div>
            <div className="grid grid-cols-3 gap-3">
              <label className="flex items-center gap-2"><input type="checkbox" checked={form.fail_open} onChange={e => setForm({ ...form, fail_open: e.target.checked })} /> <span>{t('waf.rules.fields.failOpen')}</span><InfoTooltip content={t(wafRuleTooltips.failOpen)} /></label>
              <label className="flex items-center gap-2"><input type="checkbox" checked={form.rate_enabled} onChange={e => setForm({ ...form, rate_enabled: e.target.checked })} disabled={!RATE_ENABLED_ACTIONS.includes(form.action)} /> <span>{t('waf.rules.fields.rateBasedRule')}</span><InfoTooltip content={t(wafRuleTooltips.rateBasedRule)} /></label>
            </div>
            {form.rate_enabled && (
              <div className="grid grid-cols-4 gap-3">
                <div><LabelWithTooltip tooltip={t(wafRuleTooltips.rateEvents)} className="label">{t('waf.rules.fields.rateEvents')}</LabelWithTooltip><input type="number" className="input" value={form.rate_events} onChange={e => setForm({ ...form, rate_events: Number(e.target.value) })} /></div>
                <div><LabelWithTooltip tooltip={t(wafRuleTooltips.rateWindowSeconds)} className="label">{t('waf.rules.fields.windowSeconds')}</LabelWithTooltip><input type="number" className="input" value={form.rate_window_seconds} onChange={e => setForm({ ...form, rate_window_seconds: Number(e.target.value) })} /></div>
                <div><LabelWithTooltip tooltip={t(wafRuleTooltips.rateKey)} className="label">{t('waf.rules.fields.rateKey')}</LabelWithTooltip><select className="input" value={form.rate_key} onChange={e => setForm({ ...form, rate_key: e.target.value })}><option value="src">{t('waf.rules.fields.rateKeySrc')}</option><option value="user_id">{t('waf.rules.fields.rateKeyUserId')}</option><option value="header">{t('waf.rules.fields.rateKeyHeader')}</option><option value="path">{t('waf.rules.fields.rateKeyPath')}</option>{asnDbAvailable && <option value="asn">{t('waf.rules.fields.rateKeyAsn')}</option>}</select></div>
                <div><LabelWithTooltip tooltip={t(wafRuleTooltips.rateHeader)} className="label">{t('waf.rules.fields.rateHeader')}</LabelWithTooltip><input className="input" value={form.rate_header || ''} onChange={e => setForm({ ...form, rate_header: e.target.value })} placeholder={form.rate_key === 'user_id' ? 'X-User-ID' : 'X-API-Key'} disabled={form.rate_key !== 'header' && form.rate_key !== 'user_id'} /></div>
                <div><LabelWithTooltip tooltip={t(wafRuleTooltips.rateAction)} className="label">{t('waf.rules.fields.rateAction')}</LabelWithTooltip><select className="input" value={form.rate_action} onChange={e => setForm({ ...form, rate_action: e.target.value })}><option value="block">{t('waf.rules.fields.rateActionBlock')}</option><option value="challenge">{t('waf.rules.fields.rateActionChallenge')}</option></select></div>
                <div><LabelWithTooltip tooltip={t(wafRuleTooltips.rateDurationSeconds)} className="label">{t('waf.rules.fields.blockDurationSeconds')}</LabelWithTooltip><input type="number" className="input" value={form.rate_duration_seconds} onChange={e => setForm({ ...form, rate_duration_seconds: Number(e.target.value) })} placeholder={t('waf.rules.blockDurationPlaceholder')} /></div>
              </div>
            )}
          </div>

          <div><LabelWithTooltip tooltip={t(wafRuleTooltips.customSecRules)} className="label">{t('waf.rules.fields.customSecRules')}</LabelWithTooltip><textarea className="input" rows={4} value={form.sec_rules} onChange={e => setForm({ ...form, sec_rules: e.target.value })} /></div>
          <label className="flex items-center gap-2"><input type="checkbox" checked={form.enabled} onChange={e => setForm({ ...form, enabled: e.target.checked })} /> <span>{t('waf.rules.fields.enabled')}</span><InfoTooltip content={t(wafRuleTooltips.enabled)} /></label>
          <button className="btn-primary w-full">{t('waf.rules.fields.save')}</button>
        </form>
      </Modal>

      <Modal open={exOpen} onClose={() => setExOpen(false)} title={exEditing ? t('waf.exceptions.editTitle') : t('waf.exceptions.addTitle')}>
        <form onSubmit={exSubmit} className="space-y-3">
          <div className="grid grid-cols-2 gap-3">
            <div><LabelWithTooltip tooltip={t(wafExceptionTooltips.name)} className="label">{t('waf.exceptions.fields.name')}</LabelWithTooltip><input className="input" value={exForm.name} onChange={e => setExForm({ ...exForm, name: e.target.value })} /></div>
            <div><LabelWithTooltip tooltip={t(wafExceptionTooltips.wafRule)} className="label">{t('waf.exceptions.fields.wafRule')}</LabelWithTooltip><select className="input" value={exForm.waf_rule_id} onChange={e => setExForm({ ...exForm, waf_rule_id: e.target.value })}><option value="">{t('waf.exceptions.fields.global')}</option>{rules.map((r: any) => <option key={r.id} value={r.id}>{r.name}</option>)}</select></div>
            <div><LabelWithTooltip tooltip={t(wafExceptionTooltips.ruleId)} className="label">{t('waf.exceptions.fields.ruleId')}</LabelWithTooltip><input className="input" value={exForm.rule_id} onChange={e => setExForm({ ...exForm, rule_id: e.target.value })} /></div>
            <div><LabelWithTooltip tooltip={t(wafExceptionTooltips.ruleTag)} className="label">{t('waf.exceptions.fields.ruleTag')}</LabelWithTooltip><input className="input" value={exForm.rule_tag || ''} onChange={e => setExForm({ ...exForm, rule_tag: e.target.value })} /></div>
            <div><LabelWithTooltip tooltip={t(wafExceptionTooltips.ruleMsg)} className="label">{t('waf.exceptions.fields.ruleMsg')}</LabelWithTooltip><input className="input" value={exForm.rule_msg || ''} onChange={e => setExForm({ ...exForm, rule_msg: e.target.value })} /></div>
            <div><LabelWithTooltip tooltip={t(wafExceptionTooltips.exceptionAction)} className="label">{t('waf.exceptions.fields.exceptionAction')}</LabelWithTooltip><select className="input" value={exForm.action} onChange={e => setExForm({ ...exForm, action: e.target.value })}><option value="remove">{t('waf.exceptions.fields.actionRemove')}</option><option value="allow">{t('waf.exceptions.fields.actionAllow')}</option><option value="comment">{t('waf.exceptions.fields.actionComment')}</option><option value="update">{t('waf.exceptions.fields.actionUpdate')}</option></select></div>
          </div>
          {exForm.action === 'update' && (
            <div className="grid grid-cols-2 gap-3">
              <div><LabelWithTooltip tooltip={t(wafExceptionTooltips.updateAction)} className="label">{t('waf.exceptions.fields.updateAction')}</LabelWithTooltip><input className="input" value={exForm.update_action || ''} onChange={e => setExForm({ ...exForm, update_action: e.target.value })} placeholder="pass" /></div>
              <div><LabelWithTooltip tooltip={t(wafExceptionTooltips.updateTarget)} className="label">{t('waf.exceptions.fields.updateTarget')}</LabelWithTooltip><input className="input" value={exForm.update_target || ''} onChange={e => setExForm({ ...exForm, update_target: e.target.value })} placeholder="ARGS:param" /></div>
            </div>
          )}
          <div className="grid grid-cols-2 gap-3">
            <div><LabelWithTooltip tooltip={t(wafExceptionTooltips.zone)} className="label">{t('waf.exceptions.fields.zone')}</LabelWithTooltip><input className="input" value={exForm.zone} onChange={e => setExForm({ ...exForm, zone: e.target.value })} placeholder="ARGS, HEADERS, etc" /></div>
            <div><LabelWithTooltip tooltip={t(wafExceptionTooltips.variable)} className="label">{t('waf.exceptions.fields.variable')}</LabelWithTooltip><input className="input" value={exForm.variable} onChange={e => setExForm({ ...exForm, variable: e.target.value })} /></div>
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div><LabelWithTooltip tooltip={t(wafExceptionTooltips.matcher)} className="label">{t('waf.exceptions.fields.matcher')}</LabelWithTooltip><select className="input" value={exForm.matcher} onChange={e => setExForm({ ...exForm, matcher: e.target.value })}><option>equals</option><option>contains</option><option>regex</option><option>startsWith</option></select></div>
            <div><LabelWithTooltip tooltip={t(wafExceptionTooltips.value)} className="label">{t('waf.exceptions.fields.value')}</LabelWithTooltip><input className="input" value={exForm.value} onChange={e => setExForm({ ...exForm, value: e.target.value })} /></div>
          </div>
          <div className="grid grid-cols-3 gap-3">
            <div><LabelWithTooltip tooltip={t(wafExceptionTooltips.conditionVariable)} className="label">{t('waf.exceptions.fields.conditionVariable')}</LabelWithTooltip><input className="input" value={exForm.condition_variable || ''} onChange={e => setExForm({ ...exForm, condition_variable: e.target.value })} placeholder="REMOTE_ADDR" /></div>
            <div><LabelWithTooltip tooltip={t(wafExceptionTooltips.conditionOperator)} className="label">{t('waf.exceptions.fields.conditionOperator')}</LabelWithTooltip><select className="input" value={exForm.condition_operator} onChange={e => setExForm({ ...exForm, condition_operator: e.target.value })}><option>equals</option><option>contains</option><option>startsWith</option><option>regex</option><option>gt</option><option>lt</option></select></div>
            <div><LabelWithTooltip tooltip={t(wafExceptionTooltips.conditionValue)} className="label">{t('waf.exceptions.fields.conditionValue')}</LabelWithTooltip><input className="input" value={exForm.condition_value || ''} onChange={e => setExForm({ ...exForm, condition_value: e.target.value })} /></div>
          </div>
          <div><LabelWithTooltip tooltip={t(wafExceptionTooltips.description)} className="label">{t('waf.exceptions.fields.description')}</LabelWithTooltip><input className="input" value={exForm.description || ''} onChange={e => setExForm({ ...exForm, description: e.target.value })} /></div>
          <button className="btn-primary w-full">{t('waf.exceptions.fields.save')}</button>
        </form>
      </Modal>

      <Modal open={siemOpen} onClose={() => setSiemOpen(false)} title={siemEditing ? t('waf.siem.editTitle') : t('waf.siem.addTitle')}>
        <form onSubmit={siemSubmit} className="space-y-3">
          <div className="grid grid-cols-2 gap-3">
            <div><LabelWithTooltip tooltip={t(wafSiemTooltips.name)} className="label">{t('waf.siem.fields.name')}</LabelWithTooltip><input className="input" value={siemForm.name} onChange={e => setSiemForm({ ...siemForm, name: e.target.value })} /></div>
            <div><LabelWithTooltip tooltip={t(wafSiemTooltips.integrationType)} className="label">{t('waf.siem.fields.type')}</LabelWithTooltip><select className="input" value={siemForm.integration_type} onChange={e => setSiemForm({ ...siemForm, integration_type: e.target.value })}><option value="webhook">{t('waf.siem.fields.typeWebhook')}</option><option value="syslog">{t('waf.siem.fields.typeSyslog')}</option><option value="elastic">{t('waf.siem.fields.typeElastic')}</option></select></div>
            <div><LabelWithTooltip tooltip={t(wafSiemTooltips.target)} className="label">{t('waf.siem.fields.target')}</LabelWithTooltip><input className="input" value={siemForm.target} onChange={e => setSiemForm({ ...siemForm, target: e.target.value })} /></div>
            <div><LabelWithTooltip tooltip={t(wafSiemTooltips.format)} className="label">{t('waf.siem.fields.format')}</LabelWithTooltip><select className="input" value={siemForm.format} onChange={e => setSiemForm({ ...siemForm, format: e.target.value })}><option value="json">{t('waf.siem.fields.formatJson')}</option><option value="syslog">{t('waf.siem.fields.formatSyslog')}</option><option value="cef">{t('waf.siem.fields.formatCef')}</option></select></div>
            <div><LabelWithTooltip tooltip={t(wafSiemTooltips.authHeader)} className="label">{t('waf.siem.fields.authHeader')}</LabelWithTooltip><input className="input" value={siemForm.auth_header || ''} onChange={e => setSiemForm({ ...siemForm, auth_header: e.target.value })} /></div>
          </div>
          <label className="flex items-center gap-2"><input type="checkbox" checked={siemForm.enabled} onChange={e => setSiemForm({ ...siemForm, enabled: e.target.checked })} /> <span>{t('waf.siem.fields.enabled')}</span><InfoTooltip content={t(wafSiemTooltips.enabled)} /></label>
          <button className="btn-primary w-full">{t('waf.siem.fields.save')}</button>
        </form>
      </Modal>

      <Modal open={versionOpen} onClose={() => setVersionOpen(false)} title={t('waf.versions.snapshotTitle')}>
        <form onSubmit={snapshotRule} className="space-y-3">
          <div><LabelWithTooltip tooltip={t(wafRuleTooltips.versionName)} className="label">{t('waf.versions.versionName')}</LabelWithTooltip><input className="input" value={versionName} onChange={e => setVersionName(e.target.value)} /></div>
          <button className="btn-primary w-full">{t('waf.versions.saveSnapshot')}</button>
        </form>
      </Modal>
    </div>
  )
}
