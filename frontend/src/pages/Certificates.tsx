import React, { useEffect, useMemo, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useNavigate } from 'react-router-dom'
import { Lock, Pencil, Trash2, Upload, FileUp, Ban, Radar } from 'lucide-react'
import { certificates, getErrorDetail, getTask } from '../services/api'
import useApiList from '../hooks/useApiList'
import InfoTooltip from '../components/InfoTooltip'
import LabelWithTooltip from '../components/LabelWithTooltip'
import Modal from '../components/Modal'
import { IconButton } from '../components/ui'
import { useDateTime } from '../contexts/DateTimeContext'

interface DnsProviderField {
  name: string
  label: string
  type: string
  required?: boolean
  help?: string
  options?: string[]
}

interface DnsProviderClient {
  code?: string
  plugin?: string
  env?: DnsProviderField[]
  credentials_keys?: DnsProviderField[]
  custom_code?: boolean
  custom_env?: boolean
  custom_plugin?: boolean
  custom_credentials?: boolean
}

interface DnsProvider {
  id: string
  name: string
  acme_sh?: DnsProviderClient
  certbot?: DnsProviderClient
}

interface DnsProviderResponse {
  client: 'acme.sh' | 'certbot'
  providers: DnsProvider[]
}

interface AcmeCa {
  id: string
  name: string
  url: string
  help?: string
}

export default function Certificates() {
  const { t } = useTranslation(['pages', 'common'])
  const { formatDateTime } = useDateTime()
  const navigate = useNavigate()
  const { items, reload, loading } = useApiList(certificates.list)
  const [open, setOpen] = useState(false)
  const [editing, setEditing] = useState<number | null>(null)
  const [dnsMeta, setDnsMeta] = useState<DnsProviderResponse | null>(null)
  const [dnsMetaLoading, setDnsMetaLoading] = useState(true)
  const [acmeCas, setAcmeCas] = useState<AcmeCa[]>([])
  const [acmeCasLoading, setAcmeCasLoading] = useState(true)
  const [customCa, setCustomCa] = useState('')

  const initialForm = {
    name: '',
    domain: '',
    kind: 'server',
    provider: 'letsencrypt',
    email: '',
    is_wildcard: false,
    auto_renew: true,
    key_type: 'ecdsa-p384',
    acme_challenge: 'dns',
    acme_ca: '',
    dns_provider: '',
    dns_credentials_set: false,
    fullchain: '',
    key: '',
    chain: ''
  }
  const [form, setForm] = useState<any>(initialForm)

  const [dnsCredentials, setDnsCredentials] = useState<Record<string, string>>({})
  const [customCode, setCustomCode] = useState('')
  const [customFields, setCustomFields] = useState<{ key: string; value: string }[]>([{ key: '', value: '' }])

  const [uploadOpen, setUploadOpen] = useState<number | null>(null)
  const [upload, setUpload] = useState({ fullchain: '', key: '', chain: '' })

  const [issueStatuses, setIssueStatuses] = useState<Record<number, any>>({})
  const [issuing, setIssuing] = useState<Record<number, boolean>>({})
  const pollTimers = useRef<Record<number, ReturnType<typeof setTimeout>>>({})

  const certificateTooltips: Record<string, string> = {
    name: t('pages:certificates.tooltips.name'),
    kind: t('pages:certificates.tooltips.kind'),
    domain: t('pages:certificates.tooltips.domain'),
    acmeCa: t('pages:certificates.tooltips.acmeCa'),
    acmeCaCustom: t('pages:certificates.tooltips.acmeCaCustom'),
    email: t('pages:certificates.tooltips.email'),
    keyType: t('pages:certificates.tooltips.keyType'),
    challenge: t('pages:certificates.tooltips.challenge'),
    dnsProvider: t('pages:certificates.tooltips.dnsProvider'),
    wildcard: t('pages:certificates.tooltips.wildcard'),
    autoRenew: t('pages:certificates.tooltips.autoRenew'),
    fullchain: t('pages:certificates.tooltips.fullchain'),
    privateKey: t('pages:certificates.tooltips.privateKey'),
    chain: t('pages:certificates.tooltips.chain'),
    caCertificates: t('pages:certificates.tooltips.caCertificates'),
    additionalCaChain: t('pages:certificates.tooltips.additionalCaChain'),
    dnsCredentials: t('pages:certificates.tooltips.dnsCredentials'),
    dnsCredentialFallback: t('pages:certificates.tooltips.dnsCredentialFallback'),
    customCode: t('pages:certificates.tooltips.customCode'),
    customCredentialKey: t('pages:certificates.tooltips.customCredentialKey'),
    customCredentialValue: t('pages:certificates.tooltips.customCredentialValue'),
  }

  const fetchIssueStatuses = async () => {
    try {
      const res = await certificates.issueStatus()
      setIssueStatuses(res.data.statuses || {})
    } catch {
      // non-fatal; status column just stays empty
    }
  }

  useEffect(() => {
    fetchIssueStatuses()
    return () => {
      Object.values(pollTimers.current).forEach(clearTimeout)
    }
  }, [])

  useEffect(() => {
    certificates.dnsProviders()
      .then((res: any) => {
        setDnsMeta(res.data)
      })
      .finally(() => setDnsMetaLoading(false))

    certificates.acmeCas()
      .then((res: any) => {
        setAcmeCas(res.data.cas)
      })
      .finally(() => setAcmeCasLoading(false))
  }, [])

  const selectedProvider = useMemo(() => {
    if (!dnsMeta || !form.dns_provider) return undefined
    return dnsMeta.providers.find((p) => p.id === form.dns_provider)
  }, [dnsMeta, form.dns_provider])

  const clientConfig = useMemo<DnsProviderClient | undefined>(() => {
    if (!selectedProvider || !dnsMeta) return undefined
    const key = dnsMeta.client === 'acme.sh' ? 'acme_sh' : 'certbot'
    return selectedProvider[key]
  }, [selectedProvider, dnsMeta])

  const isLetsEncrypt = useMemo(() => {
    if (form.acme_ca === 'letsencrypt') return true
    if (form.acme_ca === '__custom__') return false
    if (!form.acme_ca) return true // default ACME_SH_CA is letsencrypt
    const ca = acmeCas.find((c) => c.id === form.acme_ca)
    return ca?.url.includes('letsencrypt.org') ?? false
  }, [form.acme_ca, acmeCas])

  useEffect(() => {
    if (form.key_type === 'ecdsa-p521' && isLetsEncrypt && form.provider === 'letsencrypt') {
      setForm((prev: any) => (prev.key_type === 'ecdsa-p521' ? { ...prev, key_type: 'ecdsa-p384' } : prev))
    }
  }, [form.key_type, isLetsEncrypt, form.provider])

  const resetCredentials = () => {
    setDnsCredentials({})
    setCustomCode('')
    setCustomFields([{ key: '', value: '' }])
  }

  const initCredentialsForProvider = (provider: DnsProvider | undefined) => {
    if (!dnsMeta || !provider) {
      resetCredentials()
      return
    }
    const key = dnsMeta.client === 'acme.sh' ? 'acme_sh' : 'certbot'
    const client = provider[key]
    if (!client) {
      resetCredentials()
      return
    }
    if (client.custom_code || client.custom_plugin) {
      setCustomCode('')
      setCustomFields([{ key: '', value: '' }])
      setDnsCredentials({})
    } else {
      const fields = client.env || client.credentials_keys || []
      const initial: Record<string, string> = {}
      for (const f of fields) initial[f.name] = ''
      setDnsCredentials(initial)
      setCustomCode('')
      setCustomFields([{ key: '', value: '' }])
    }
  }

  const openAdd = () => {
    setEditing(null)
    setForm({ ...initialForm, provider: 'letsencrypt' })
    setCustomCa('')
    resetCredentials()
    setOpen(true)
  }
  const openAddCustom = () => {
    setEditing(null)
    setForm({ ...initialForm, provider: 'custom' })
    setCustomCa('')
    resetCredentials()
    setOpen(true)
  }

  const openEdit = (c: any) => {
    setEditing(c.id)
    const isCustomCa = c.acme_ca && !acmeCas.some((ca) => ca.id === c.acme_ca) && c.acme_ca !== '__custom__'
    setForm({
      ...initialForm,
      ...c,
      acme_ca: isCustomCa ? '__custom__' : (c.acme_ca || ''),
      fullchain: '',
      key: '',
      chain: ''
    })
    setCustomCa(isCustomCa ? c.acme_ca : '')
    resetCredentials()
    if (dnsMeta && c.dns_provider) {
      const provider = dnsMeta.providers.find((p) => p.id === c.dns_provider)
      initCredentialsForProvider(provider)
    }
    setOpen(true)
  }

  const handleProviderChange = (providerId: string) => {
    setForm({ ...form, dns_provider: providerId, dns_credentials_set: false })
    if (dnsMeta) {
      const provider = dnsMeta.providers.find((p) => p.id === providerId)
      initCredentialsForProvider(provider)
    } else {
      resetCredentials()
    }
  }

  const submit = async (e: React.FormEvent) => {
    e.preventDefault()
    const payload: any = { ...form }

    if (form.acme_ca === '__custom__') {
      payload.acme_ca = customCa.trim() || undefined
    }

    if (form.provider === 'letsencrypt' && form.acme_challenge === 'dns' && form.dns_provider && clientConfig) {
      let creds: Record<string, string> | undefined

      if (clientConfig.custom_code || clientConfig.custom_plugin) {
        if (customCode.trim()) {
          creds = {}
          const reservedKey = clientConfig.custom_code ? '_provider_code' : '_plugin'
          creds[reservedKey] = customCode.trim()
          for (const { key, value } of customFields) {
            if (key.trim() && value.trim()) creds[key.trim()] = value.trim()
          }
        }
      } else {
        const hasValues = Object.values(dnsCredentials).some((v) => v.trim())
        if (hasValues) {
          creds = {}
          for (const [k, v] of Object.entries(dnsCredentials)) {
            if (v.trim()) creds[k] = v.trim()
          }
        }
      }

      if (creds && Object.keys(creds).length) {
        payload.dns_credentials = creds
      }
    }

    if (editing) await certificates.update(editing, payload)
    else await certificates.create(payload)
    setForm(initialForm)
    setEditing(null)
    setOpen(false)
    setCustomCa('')
    resetCredentials()
    reload()
  }

  const uploadCert = async (e: React.FormEvent) => {
    e.preventDefault()
    if (uploadOpen) await certificates.upload(uploadOpen, upload)
    setUploadOpen(null)
    reload()
  }

  const [issueConfirm, setIssueConfirm] = useState<number | null>(null)
  const [renewConfirm, setRenewConfirm] = useState(false)
  const [sansOpen, setSansOpen] = useState<any>(null)

  const handleRenew = async () => {
    setRenewConfirm(false)
    try {
      await certificates.renew()
      reload()
    } catch (err: any) {
      alert(getErrorDetail(err, t('pages:certificates.errors.bulkRenewFailed')))
    }
  }

  const handleCancelIssue = async (certId: number) => {
    const s = issueStatuses[certId]
    if (!s || !s.task_id) return
    try {
      await certificates.cancelIssue(s.task_id)
      setIssuing((prev) => ({ ...prev, [certId]: false }))
      setIssueStatuses((prev) => ({ ...prev, [certId]: { ...s, status: 'cancelled', message: t('pages:certificates.errors.taskCancelled') } }))
      if (pollTimers.current[certId]) {
        clearTimeout(pollTimers.current[certId])
        delete pollTimers.current[certId]
      }
      reload()
    } catch (err: any) {
      // ignore — task may have already completed
      fetchIssueStatuses()
    }
  }

  const handleIssue = async (certId: number) => {
    setIssuing({ ...issuing, [certId]: true })
    setIssueStatuses({ ...issueStatuses, [certId]: { status: 'pending', created_at: new Date().toISOString(), message: t('pages:certificates.errors.queuedForBackgroundProcessing') } })
    setIssueConfirm(null)
    try {
      const res = await certificates.issue(certId)
      const taskId = res.data.task_id
      if (taskId) pollTask(certId, taskId)
    } catch (err: any) {
      setIssuing({ ...issuing, [certId]: false })
      setIssueStatuses({ ...issueStatuses, [certId]: { status: 'failed', message: err?.response?.data?.detail || t('pages:certificates.errors.failedToQueueIssueTask') } })
    }
  }

  const pollTask = (certId: number, taskId: number) => {
    const startTime = Date.now()
    const MAX_POLL_MS = 10 * 60 * 1000 // 10 minutes
    const poll = async () => {
      try {
        const res = await getTask(taskId)
        const task = res.data
        const status = task.status
        const message = task.result?.message
        const error = task.error
        setIssueStatuses((prev) => ({ ...prev, [certId]: { status, created_at: task.created_at, updated_at: task.updated_at, message, error } }))
        if (status === 'success' || status === 'failed') {
          setIssuing((prev) => ({ ...prev, [certId]: false }))
          reload()
          fetchIssueStatuses()
          return
        }
      } catch {
        // keep polling on transient errors
      }
      if (Date.now() - startTime > MAX_POLL_MS) {
        setIssuing((prev) => ({ ...prev, [certId]: false }))
        setIssueStatuses((prev) => ({ ...prev, [certId]: { status: 'running', message: t('pages:certificates.errors.timedOut') } }))
        return
      }
      pollTimers.current[certId] = setTimeout(poll, 3000)
    }
    poll()
  }

  const addCustomField = () => {
    setCustomFields([...customFields, { key: '', value: '' }])
  }

  const removeCustomField = (idx: number) => {
    setCustomFields(customFields.filter((_, i) => i !== idx))
  }

  const updateCustomField = (idx: number, field: 'key' | 'value', value: string) => {
    const next = [...customFields]
    next[idx][field] = value
    setCustomFields(next)
  }

  const renderCredentialFields = () => {
    if (!clientConfig) return null

    if (clientConfig.custom_code || clientConfig.custom_plugin) {
      const label = clientConfig.custom_code ? t('pages:certificates.modal.customCodeLabelAcmeSh') : t('pages:certificates.modal.customCodeLabelCertbot')
      return (
        <div className="space-y-3">
          <div>
            <LabelWithTooltip tooltip={certificateTooltips.customCode}>{label}</LabelWithTooltip>
            <input
              className="input"
              type="text"
              value={customCode}
              onChange={(e) => setCustomCode(e.target.value)}
              placeholder={clientConfig.custom_code ? t('pages:certificates.modal.customCodePlaceholderAcmeSh') : t('pages:certificates.modal.customCodePlaceholderCertbot')}
            />
          </div>
          <div>
            <LabelWithTooltip tooltip={certificateTooltips.dnsCredentials}>
              {t('pages:certificates.modal.dnsCredentialsLabel', { status: form.dns_credentials_set ? t('pages:certificates.modal.dnsCredentialsSet') : t('pages:certificates.modal.dnsCredentialsNotSet') })}
            </LabelWithTooltip>
            <div className="space-y-2">
              {customFields.map((f, i) => (
                <div key={i} className="grid grid-cols-5 gap-2 items-end">
                  <div className="col-span-2">
                    <LabelWithTooltip tooltip={certificateTooltips.customCredentialKey}>{t('pages:certificates.modal.envVarKeyName')}</LabelWithTooltip>
                    <input
                      className="input"
                      placeholder={t('pages:certificates.modal.envVarKeyName')}
                      value={f.key}
                      onChange={(e) => updateCustomField(i, 'key', e.target.value)}
                    />
                  </div>
                  <div className="col-span-2">
                    <LabelWithTooltip tooltip={certificateTooltips.customCredentialValue}>{t('pages:certificates.modal.value')}</LabelWithTooltip>
                    <input
                      className="input"
                      type="password"
                      placeholder={t('pages:certificates.modal.value')}
                      value={f.value}
                      onChange={(e) => updateCustomField(i, 'value', e.target.value)}
                    />
                  </div>
                  <button
                    type="button"
                    onClick={() => removeCustomField(i)}
                    className="text-red-400 hover:underline"
                    disabled={customFields.length === 1}
                  >
                    {t('common:actions.remove')}
                  </button>
                </div>
              ))}
              <button type="button" onClick={addCustomField} className="text-primary hover:underline">
                {t('pages:certificates.modal.addCredential')}
              </button>
            </div>
          </div>
        </div>
      )
    }

    const fields = clientConfig.env || clientConfig.credentials_keys || []
    return (
      <div className="space-y-3">
        <LabelWithTooltip tooltip={certificateTooltips.dnsCredentials}>
          {t('pages:certificates.modal.dnsCredentialsLabel', { status: form.dns_credentials_set ? t('pages:certificates.modal.dnsCredentialsSet') : t('pages:certificates.modal.dnsCredentialsNotSet') })}
        </LabelWithTooltip>
        {fields.map((field) => (
          <div key={field.name}>
            <LabelWithTooltip
              textClassName="text-sm font-semibold text-slate-400"
              tooltip={field.help || certificateTooltips.dnsCredentialFallback}
            >
              {field.label}
              {field.required && <span className="text-red-400 ms-1">*</span>}
            </LabelWithTooltip>
            {field.type === 'select' && field.options ? (
              <select
                className="input"
                value={dnsCredentials[field.name] || ''}
                onChange={(e) => setDnsCredentials({ ...dnsCredentials, [field.name]: e.target.value })}
              >
                <option value="">{t('pages:certificates.modal.selectEllipsis')}</option>
                {field.options.map((o) => (
                  <option key={o} value={o}>
                    {o}
                  </option>
                ))}
              </select>
            ) : (
              <input
                className="input"
                type={field.type === 'password' ? 'password' : field.type === 'email' ? 'email' : 'text'}
                value={dnsCredentials[field.name] || ''}
                onChange={(e) => setDnsCredentials({ ...dnsCredentials, [field.name]: e.target.value })}
                placeholder={field.help || field.label}
              />
            )}
            {field.help && field.type !== 'select' && <p className="text-xs text-slate-400 mt-1">{field.help}</p>}
          </div>
        ))}
      </div>
    )
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h2 className="text-2xl font-bold flex items-center gap-2"><Lock className="h-5 w-5 text-primary" /> {t('pages:certificates.title')}</h2>
        <div className="flex gap-2 items-center">
          <button onClick={openAdd} className="btn-primary">{t('pages:certificates.addCertificate')}</button>
          <button onClick={openAddCustom} className="btn-secondary">{t('pages:certificates.addCustomCertificate')}</button>
          <button onClick={() => setRenewConfirm(true)} className="btn-secondary">{t('pages:certificates.bulkRenewNow')}</button>
        </div>
      </div>
      {loading ? (
        <p>{t('pages:certificates.loading')}</p>
      ) : (
        <div className="card overflow-x-auto">
          <table className="w-full text-sm text-start">
            <thead className="text-slate-400 border-b border-slate-800">
              <tr>
                <th>{t('pages:certificates.tableHeaders.name')}</th>
                <th>{t('pages:certificates.tableHeaders.kind')}</th>
                <th>{t('pages:certificates.tableHeaders.expiration')}</th>
                <th>{t('pages:certificates.tableHeaders.cn')}</th>
                <th>{t('pages:certificates.tableHeaders.sans')}</th>
                <th>{t('pages:certificates.tableHeaders.provider')}</th>
                <th>{t('pages:certificates.tableHeaders.issueStatus')}</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {items.map((c: any) => (
                <tr key={c.id} className="border-b border-slate-800 last:border-0">
                  <td className="py-2">{c.name}</td>
                  <td>{c.kind || 'server'}</td>
                  <td>{c.not_after ? formatDateTime(c.not_after) : '-'}</td>
                  <td>{c.subject_cn || '-'}</td>
                  <td>
                    {c.sans ? (
                      <button
                        onClick={() => setSansOpen(c)}
                        className="text-primary hover:underline"
                      >
                        {(() => {
                          const n = c.sans.split(',').filter(Boolean).length
                          return t('pages:certificates.sansCount', { count: n })
                        })()}
                      </button>
                    ) : (
                      <span className="text-slate-500">-</span>
                    )}
                  </td>
                  <td>{c.provider}</td>
                  <td className="text-xs">
                    {(() => {
                      const s = issueStatuses[c.id]
                      if (!s) return <span className="text-slate-500">-</span>
                      const color = s.status === 'success' ? 'text-green-400' : s.status === 'failed' ? 'text-red-400' : s.status === 'running' ? 'text-blue-400' : s.status === 'cancelled' ? 'text-slate-400' : 'text-amber-400'
                      const label = s.status === 'success' ? t('pages:certificates.issueStatus.success') : s.status === 'failed' ? t('pages:certificates.issueStatus.failed') : s.status === 'running' ? t('pages:certificates.issueStatus.running') : s.status === 'pending' ? t('pages:certificates.issueStatus.pending') : s.status === 'cancelled' ? t('pages:certificates.issueStatus.cancelled') : s.status
                      const ts = s.updated_at || s.created_at
                      const errMsg = (s.status === 'failed' || s.status === 'cancelled') ? (s.message || s.error) : null
                      return (
                        <div title={errMsg || undefined}>
                          <span className={color}>{label}</span>
                          {issuing[c.id] && s.status !== 'success' && s.status !== 'failed' && <span className="text-slate-400 ms-1">{t('pages:certificates.issueStatus.polling')}</span>}
                          {ts && <div className="text-slate-500">{formatDateTime(ts)}</div>}
                          {errMsg && <div className="text-red-400 truncate max-w-xs">{errMsg}</div>}
                        </div>
                      )
                    })()}
                  </td>
                  <td className="text-end">
                    <div className="inline-flex items-center justify-end gap-2">
                      <IconButton icon={Radar} aria-label={t('pages:certificates.tableHeaders.sslLabs')} onClick={() => navigate(`/certificates/${c.id}/ssllabs`)} />
                      <IconButton icon={Pencil} aria-label={t('common:actions.edit')} onClick={() => openEdit(c)} />
                      {c.provider === 'letsencrypt' && (
                        <IconButton
                          icon={FileUp}
                          aria-label={t('pages:certificates.issueModal.issue')}
                          onClick={() => setIssueConfirm(c.id)}
                          disabled={issuing[c.id]}
                        />
                      )}
                      {issuing[c.id] && c.provider === 'letsencrypt' && (
                        <IconButton icon={Ban} aria-label={t('common:actions.cancel')} onClick={() => handleCancelIssue(c.id)} />
                      )}
                      {c.provider === 'custom' && (
                        <IconButton icon={Upload} aria-label={t('common:actions.upload')} onClick={() => setUploadOpen(c.id)} />
                      )}
                      <IconButton icon={Trash2} variant="danger" aria-label={t('common:actions.delete')} onClick={() => certificates.remove(c.id).then(reload)} />
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <p className="text-sm text-slate-400">
        {t('pages:certificates.bulkRenewDescription')}
      </p>
      <p className="text-sm text-amber-400">
        {t('pages:certificates.issueNote')}
      </p>
      <Modal
        open={open}
        onClose={() => setOpen(false)}
        title={editing ? t('pages:certificates.modal.editTitle') : (form.provider === 'custom' ? t('pages:certificates.modal.addCustomTitle') : t('pages:certificates.modal.addTitle'))}
      >
        <form onSubmit={submit} className="space-y-3">
          <div className="grid grid-cols-2 gap-3">
            <div>
              <LabelWithTooltip tooltip={certificateTooltips.name}>{t('pages:certificates.modal.name')}</LabelWithTooltip>
              <input className="input" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} />
            </div>
            {form.provider === 'custom' && (
              <div>
                <LabelWithTooltip tooltip={certificateTooltips.kind}>{t('pages:certificates.modal.kind')}</LabelWithTooltip>
                <select
                  className="input"
                  value={form.kind}
                  onChange={(e) => setForm({ ...form, kind: e.target.value })}
                >
                  <option value="server">{t('pages:certificates.modal.kindServer')}</option>
                  <option value="client">{t('pages:certificates.modal.kindClient')}</option>
                  <option value="ca">{t('pages:certificates.modal.kindCa')}</option>
                </select>
              </div>
            )}
            {form.provider !== 'custom' && (
              <div>
                <LabelWithTooltip tooltip={certificateTooltips.domain}>{t('pages:certificates.modal.domain')}</LabelWithTooltip>
                <input className="input" value={form.domain} onChange={(e) => setForm({ ...form, domain: e.target.value })} />
              </div>
            )}
            {form.provider === 'letsencrypt' && (
              <div>
                <LabelWithTooltip tooltip={certificateTooltips.acmeCa}>{t('pages:certificates.modal.acmeCa')}</LabelWithTooltip>
                {acmeCasLoading ? (
                  <p className="text-sm text-slate-400">{t('pages:certificates.loading')}</p>
                ) : (
                  <select
                    className="input"
                    value={form.acme_ca}
                    onChange={(e) => {
                      const v = e.target.value
                      setForm({ ...form, acme_ca: v })
                      if (v !== '__custom__') setCustomCa('')
                    }}
                  >
                    <option value="">{t('pages:certificates.modal.acmeCaDefault')}</option>
                    {acmeCas.map((ca) => (
                      <option key={ca.id} value={ca.id}>
                        {ca.name}
                      </option>
                    ))}
                    <option value="__custom__">{t('pages:certificates.modal.acmeCaOther')}</option>
                  </select>
                )}
                {form.acme_ca && form.acme_ca !== '__custom__' && (
                  (() => {
                    const ca = acmeCas.find((c) => c.id === form.acme_ca)
                    return ca?.help ? <p className="text-xs text-slate-400 mt-1">{ca.help}</p> : null
                  })()
                )}
                {form.acme_ca === '__custom__' && (
                  <>
                    <input
                      className="input mt-2"
                      type="url"
                      value={customCa}
                      onChange={(e) => setCustomCa(e.target.value)}
                      placeholder="https://acme.example.com/directory"
                    />
                    <p className="text-xs text-slate-400 mt-1">{t('pages:certificates.modal.acmeCaCustomHelp')}</p>
                  </>
                )}
              </div>
            )}
            {form.provider === 'letsencrypt' && (
              <div>
                <LabelWithTooltip tooltip={certificateTooltips.email}>{t('pages:certificates.modal.emailAddress')}</LabelWithTooltip>
                <input
                  type="email"
                  className="input"
                  value={form.email}
                  onChange={(e) => setForm({ ...form, email: e.target.value })}
                  placeholder={t('pages:certificates.modal.emailPlaceholder')}
                />
              </div>
            )}
            {form.provider === 'letsencrypt' && (
              <div>
                <LabelWithTooltip tooltip={certificateTooltips.keyType}>{t('pages:certificates.modal.keyType')}</LabelWithTooltip>
                <select
                  className="input"
                  value={form.key_type}
                  onChange={(e) => setForm({ ...form, key_type: e.target.value })}
                >
                  {[
                    { value: 'ecdsa-p384', label: 'ECDSA P-384' },
                    { value: 'ecdsa-p256', label: 'ECDSA P-256' },
                    { value: 'ecdsa-p521', label: 'ECDSA P-521' },
                    { value: 'rsa-4096', label: 'RSA 4096' },
                    { value: 'rsa-3072', label: 'RSA 3072' },
                    { value: 'rsa-2048', label: 'RSA 2048' },
                    { value: 'rsa-8192', label: 'RSA 8192' },
                  ]
                    .filter((o) => !isLetsEncrypt || o.value !== 'ecdsa-p521')
                    .map((o) => (
                      <option key={o.value} value={o.value}>{o.label}</option>
                    ))}
                </select>
              </div>
            )}
            {form.provider === 'letsencrypt' && (
              <div>
                <LabelWithTooltip tooltip={certificateTooltips.challenge}>{t('pages:certificates.modal.challenge')}</LabelWithTooltip>
                <select
                  className="input"
                  value={form.acme_challenge}
                  onChange={(e) => setForm({ ...form, acme_challenge: e.target.value })}
                >
                  <option value="http">{t('pages:certificates.modal.challengeHttp')}</option>
                  <option value="dns">{t('pages:certificates.modal.challengeDns')}</option>
                </select>
              </div>
            )}
            {form.provider === 'letsencrypt' && form.acme_challenge === 'dns' && (
              <div>
                <LabelWithTooltip tooltip={certificateTooltips.dnsProvider}>{t('pages:certificates.modal.dnsProvider')}</LabelWithTooltip>
                {dnsMetaLoading ? (
                  <p className="text-sm text-slate-400">{t('pages:certificates.loading')}</p>
                ) : (
                  <select
                    className="input"
                    value={form.dns_provider}
                    onChange={(e) => handleProviderChange(e.target.value)}
                  >
                    <option value="">{t('pages:certificates.modal.dnsProviderSelect')}</option>
                    {dnsMeta?.providers.map((p) => (
                      <option key={p.id} value={p.id}>
                        {p.name}
                      </option>
                    ))}
                  </select>
                )}
              </div>
            )}
          </div>
          {form.provider === 'letsencrypt' && (
            <>
              <div className="flex gap-4">
                <label className="flex items-center gap-2">
                  <input
                    type="checkbox"
                    checked={form.is_wildcard}
                    onChange={(e) => setForm({ ...form, is_wildcard: e.target.checked })}
                  />
                  <span>{t('pages:certificates.modal.wildcard')}</span>
                  <InfoTooltip content={certificateTooltips.wildcard} />
                </label>
                <label className="flex items-center gap-2">
                  <input
                    type="checkbox"
                    checked={form.auto_renew}
                    onChange={(e) => setForm({ ...form, auto_renew: e.target.checked })}
                  />
                  <span>{t('pages:certificates.modal.autoRenew')}</span>
                  <InfoTooltip content={certificateTooltips.autoRenew} />
                </label>
              </div>
              {form.acme_challenge === 'dns' && form.dns_provider && clientConfig && renderCredentialFields()}
            </>
          )}
          {form.provider === 'custom' && (
            <div className="space-y-2">
              <div>
                <LabelWithTooltip tooltip={form.kind === 'ca' ? certificateTooltips.caCertificates : certificateTooltips.fullchain}>
                  {form.kind === 'ca' ? t('pages:certificates.modal.caCertificatePem') : t('pages:certificates.modal.fullchainPem')}
                </LabelWithTooltip>
                <textarea
                  className="input"
                  rows={4}
                  value={form.fullchain}
                  onChange={(e) => setForm({ ...form, fullchain: e.target.value })}
                />
                <p className="text-xs text-slate-400 mt-1">
                  {form.kind === 'ca'
                    ? t('pages:certificates.modal.caCertificatesHelp')
                    : t('pages:certificates.modal.fullchainHelp')}
                </p>
              </div>
              {form.kind !== 'ca' && (
                <div>
                  <LabelWithTooltip tooltip={certificateTooltips.privateKey}>{t('pages:certificates.modal.privateKey')}</LabelWithTooltip>
                  <textarea
                    className="input"
                    rows={4}
                    value={form.key}
                    onChange={(e) => setForm({ ...form, key: e.target.value })}
                  />
                </div>
              )}
              <div>
                <LabelWithTooltip tooltip={form.kind === 'ca' ? certificateTooltips.additionalCaChain : certificateTooltips.chain}>
                  {form.kind === 'ca' ? t('pages:certificates.modal.additionalCaChainOptional') : t('pages:certificates.modal.chainOptional')}
                </LabelWithTooltip>
                <textarea
                  className="input"
                  rows={3}
                  value={form.chain}
                  onChange={(e) => setForm({ ...form, chain: e.target.value })}
                />
                <p className="text-xs text-slate-400 mt-1">
                  {form.kind === 'ca'
                    ? t('pages:certificates.modal.additionalCaChainHelp')
                    : t('pages:certificates.modal.chainHelp')}
                </p>
              </div>
            </div>
          )}
          <button className="btn-primary w-full" disabled={dnsMetaLoading}>{t('pages:certificates.modal.save')}</button>
        </form>
      </Modal>
      <Modal open={!!uploadOpen} onClose={() => setUploadOpen(null)} title={t('pages:certificates.uploadModal.title')}>
        {(() => {
          const uploadCertObj = items.find((c: any) => c.id === uploadOpen)
          const isCa = uploadCertObj?.kind === 'ca'
          return (
            <form onSubmit={uploadCert} className="space-y-3">
              <div>
                <LabelWithTooltip tooltip={isCa ? certificateTooltips.caCertificates : certificateTooltips.fullchain}>
                  {isCa ? t('pages:certificates.modal.caCertificatePem') : t('pages:certificates.modal.fullchainPem')}
                </LabelWithTooltip>
                <textarea
                  className="input"
                  rows={4}
                  value={upload.fullchain}
                  onChange={(e) => setUpload({ ...upload, fullchain: e.target.value })}
                />
                <p className="text-xs text-slate-400 mt-1">
                  {isCa
                    ? t('pages:certificates.modal.caCertificatesHelp')
                    : t('pages:certificates.modal.fullchainHelp')}
                </p>
              </div>
              {!isCa && (
                <div>
                  <LabelWithTooltip tooltip={certificateTooltips.privateKey}>{t('pages:certificates.modal.privateKey')}</LabelWithTooltip>
                  <textarea
                    className="input"
                    rows={4}
                    value={upload.key}
                    onChange={(e) => setUpload({ ...upload, key: e.target.value })}
                  />
                </div>
              )}
              <div>
                <LabelWithTooltip tooltip={isCa ? certificateTooltips.additionalCaChain : certificateTooltips.chain}>
                  {isCa ? t('pages:certificates.modal.additionalCaChainOptional') : t('pages:certificates.modal.chainOptional')}
                </LabelWithTooltip>
                <textarea
                  className="input"
                  rows={3}
                  value={upload.chain}
                  onChange={(e) => setUpload({ ...upload, chain: e.target.value })}
                />
                <p className="text-xs text-slate-400 mt-1">
                  {isCa
                    ? t('pages:certificates.modal.additionalCaChainHelp')
                    : t('pages:certificates.modal.chainHelp')}
                </p>
              </div>
              <button className="btn-primary w-full">{t('pages:certificates.uploadModal.upload')}</button>
            </form>
          )
        })()}
      </Modal>
      {(() => {
        const issueCert = issueConfirm !== null ? items.find((c: any) => c.id === issueConfirm) : null
        const isReissue = issueCert?.not_after
        return (
          <Modal open={issueConfirm !== null} onClose={() => setIssueConfirm(null)} title={isReissue ? t('pages:certificates.issueModal.reissueTitle') : t('pages:certificates.issueModal.issueTitle')}>
            <div className="space-y-4">
              <p className="text-sm text-slate-300">
                {isReissue
                  ? t('pages:certificates.issueModal.reissueDescription')
                  : t('pages:certificates.issueModal.issueDescription')}
                {t('pages:certificates.issueModal.backgroundNote')}
              </p>
              <div className="flex gap-2 justify-end">
                <button onClick={() => setIssueConfirm(null)} className="btn-secondary">{t('pages:certificates.issueModal.cancel')}</button>
                <button onClick={() => handleIssue(issueConfirm!)} className="btn-primary">{isReissue ? t('pages:certificates.issueModal.reissue') : t('pages:certificates.issueModal.issue')}</button>
              </div>
            </div>
          </Modal>
        )
      })()}
      <Modal open={renewConfirm} onClose={() => setRenewConfirm(false)} title={t('pages:certificates.renewModal.title')}>
        <div className="space-y-4">
          <p className="text-sm text-slate-300">
            {t('pages:certificates.renewModal.description')}
          </p>
          <div className="flex gap-2 justify-end">
            <button onClick={() => setRenewConfirm(false)} className="btn-secondary">{t('pages:certificates.renewModal.cancel')}</button>
            <button onClick={handleRenew} className="btn-primary">{t('pages:certificates.renewModal.renewNow')}</button>
          </div>
        </div>
      </Modal>
      <Modal open={!!sansOpen} onClose={() => setSansOpen(null)} title={sansOpen ? t('pages:certificates.sansModal.title', { name: sansOpen.name }) : t('pages:certificates.sansModal.titleDefault')}>
        {sansOpen && sansOpen.sans && (
          <ul className="list-disc ps-5 space-y-1">
            {sansOpen.sans
              .split(',')
              .map((s: string) => s.trim())
              .filter(Boolean)
              .map((san: string, i: number) => (
                <li key={i} className="text-sm break-all text-slate-200">{san}</li>
              ))}
          </ul>
        )}
      </Modal>
    </div>
  )
}
