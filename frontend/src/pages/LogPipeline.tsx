import React, { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { List, RefreshCw, CheckCircle2, XCircle, FileCode, Plus, Stethoscope, X } from 'lucide-react'
import { vector } from '../services/api'
import Modal from '../components/Modal'
import { Badge } from '../components/ui'

interface SinkRow {
  id: number
  name: string
  type: string
  source: string
  options: Record<string, any>
  enabled: boolean
}

interface FieldDef {
  key: string
  required?: boolean
  secret?: boolean
  kind?: 'text' | 'select' | 'bool' | 'list' | 'map'
  options?: { value: string; label: string }[]
  placeholder?: string
}

// Per-sink-type option fields. Keys map 1:1 to the backend's options dict;
// secret fields are masked by the API on read and re-encrypted on write.
const SINK_FIELDS: Record<string, FieldDef[]> = {
  aws_s3: [
    { key: 'bucket', required: true },
    { key: 'region', required: true },
    { key: 'key_prefix', placeholder: 'corex/{source}/%Y/%m/%d/' },
    { key: 'compression', kind: 'select', options: [{ value: 'gzip', label: 'gzip' }, { value: 'zstd', label: 'zstd' }, { value: 'none', label: 'none' }] },
    { key: 'endpoint', placeholder: 'https://s3-compatible-endpoint (optional)' },
    { key: 'access_key_id', secret: true },
    { key: 'secret_access_key', secret: true },
    { key: 'session_token', secret: true },
    { key: 'assume_role' },
  ],
  azure_logs_ingestion: [
    { key: 'endpoint', required: true, placeholder: 'https://<dce>.ingest.monitor.azure.com' },
    { key: 'dcr_immutable_id', required: true, placeholder: 'dcr-…' },
    { key: 'stream_name', required: true, placeholder: 'Custom-corex' },
    { key: 'azure_credential_kind', kind: 'select', options: [{ value: 'client_secret', label: 'client_secret' }, { value: 'managed_identity', label: 'managed_identity' }] },
    { key: 'tenant_id' },
    { key: 'client_id' },
    { key: 'client_secret', secret: true },
  ],
  datadog_logs: [
    { key: 'api_key', required: true, secret: true },
    { key: 'site', kind: 'select', options: [
      { value: 'datadoghq.com', label: 'US1 (datadoghq.com)' },
      { value: 'datadoghq.eu', label: 'EU (datadoghq.eu)' },
      { value: 'us3.datadoghq.com', label: 'US3' },
      { value: 'us5.datadoghq.com', label: 'US5' },
      { value: 'ap1.datadoghq.com', label: 'AP1' },
    ] },
    { key: 'endpoint', placeholder: 'https://http-intake.logs.<site> (optional)' },
    { key: 'compression', kind: 'select', options: [{ value: 'zstd', label: 'zstd' }, { value: 'gzip', label: 'gzip' }, { value: 'none', label: 'none' }] },
  ],
  elasticsearch: [
    { key: 'endpoints', required: true, kind: 'list', placeholder: 'https://es1:9200, https://es2:9200' },
    { key: 'index', placeholder: 'corex-log-%Y.%m.%d (per-source overrides: index_corex, index_waf, index_mcp)' },
    { key: 'auth_strategy', kind: 'select', options: [{ value: 'none', label: 'none' }, { value: 'basic', label: 'basic' }, { value: 'api_key', label: 'api_key' }] },
    { key: 'user' },
    { key: 'password', secret: true },
    { key: 'api_key', secret: true },
    { key: 'opensearch_service_type', kind: 'select', options: [{ value: '', label: '(elasticsearch)' }, { value: 'managed', label: 'managed (AWS OpenSearch)' }, { value: 'serverless', label: 'serverless' }] },
    { key: 'tls_verify_certificate', kind: 'bool' },
    { key: 'tls_verify_hostname', kind: 'bool' },
  ],
  http: [
    { key: 'uri', required: true, placeholder: 'https://logs.example.com/ingest' },
    { key: 'method', kind: 'select', options: [{ value: 'post', label: 'POST' }, { value: 'put', label: 'PUT' }, { value: 'patch', label: 'PATCH' }] },
    { key: 'encoding', kind: 'select', options: [{ value: 'ndjson', label: 'ndjson' }, { value: 'json', label: 'json' }, { value: 'text', label: 'text' }] },
    { key: 'compression', kind: 'select', options: [{ value: 'none', label: 'none' }, { value: 'gzip', label: 'gzip' }] },
    { key: 'auth_strategy', kind: 'select', options: [{ value: 'none', label: 'none' }, { value: 'basic', label: 'basic' }, { value: 'bearer', label: 'bearer' }] },
    { key: 'user' },
    { key: 'password', secret: true },
    { key: 'token', secret: true },
    { key: 'headers', kind: 'map', placeholder: 'X-Custom: value (one per line)' },
    { key: 'tls_verify_certificate', kind: 'bool' },
  ],
  new_relic: [
    { key: 'account_id', required: true },
    { key: 'license_key', required: true, secret: true },
    { key: 'region', kind: 'select', options: [{ value: 'us', label: 'US' }, { value: 'eu', label: 'EU' }] },
    { key: 'compression', kind: 'select', options: [{ value: 'gzip', label: 'gzip' }, { value: 'none', label: 'none' }] },
  ],
  splunk_hec_logs: [
    { key: 'endpoint', required: true, placeholder: 'https://splunk-hec:8088' },
    { key: 'token', required: true, secret: true },
    { key: 'index' },
    { key: 'sourcetype', placeholder: '_json' },
    { key: 'source' },
    { key: 'host_key', placeholder: 'hostname' },
    { key: 'endpoint_target', kind: 'select', options: [{ value: 'event', label: 'event' }, { value: 'raw', label: 'raw' }] },
    { key: 'tls_verify_certificate', kind: 'bool' },
  ],
}

const SINK_TYPES = Object.keys(SINK_FIELDS)
const SOURCE_IDS = ['corex', 'waf', 'mcp'] as const

function mapToText(v: any): string {
  if (!v || typeof v !== 'object') return ''
  return Object.entries(v).map(([k, val]) => `${k}: ${val}`).join('\n')
}

function textToMap(s: string): Record<string, string> {
  const out: Record<string, string> = {}
  for (const line of s.split('\n')) {
    const idx = line.indexOf(':')
    if (idx <= 0) continue
    const k = line.slice(0, idx).trim()
    const val = line.slice(idx + 1).trim()
    if (k) out[k] = val
  }
  return out
}

export default function LogPipeline() {
  const { t } = useTranslation(['pages', 'common'])
  const [sinks, setSinks] = useState<SinkRow[]>([])
  const [vectorStatus, setVectorStatus] = useState<{ available?: boolean; running?: boolean; error?: string | null }>({})
  const [loadError, setLoadError] = useState('')

  const [open, setOpen] = useState(false)
  const [editing, setEditing] = useState<SinkRow | null>(null)
  const [form, setForm] = useState<any>({ name: '', type: 'aws_s3', source: 'corex', options: {}, enabled: true })
  const [headersText, setHeadersText] = useState('')
  const [sendTestEvent, setSendTestEvent] = useState(false)
  const [checkResult, setCheckResult] = useState<{ ok: boolean; output: string } | null>(null)
  const [checking, setChecking] = useState(false)
  const [rowCheck, setRowCheck] = useState<{ id: number; ok: boolean; output: string } | null>(null)
  const [validating, setValidating] = useState(false)
  const [validateResult, setValidateResult] = useState<{ valid: boolean; output: string } | null>(null)
  const [preview, setPreview] = useState<string | null>(null)
  const [restarting, setRestarting] = useState(false)

  const load = async () => {
    try {
      const res = await vector.pipeline()
      setSinks(res.data.sinks || [])
      setVectorStatus(res.data.vector_status || {})
      setLoadError('')
    } catch (err: any) {
      setLoadError(err?.response?.data?.detail || err?.message || '')
    }
  }
  useEffect(() => { load() }, [])

  const openAdd = () => {
    setEditing(null)
    setForm({ name: '', type: 'aws_s3', source: 'corex', options: {}, enabled: true })
    setHeadersText('')
    setCheckResult(null)
    setOpen(true)
  }
  const openEdit = (s: SinkRow) => {
    setEditing(s)
    setForm({ name: s.name, type: s.type, source: s.source || 'corex', options: { ...(s.options || {}) }, enabled: s.enabled })
    setHeadersText(mapToText(s.options?.headers))
    setCheckResult(null)
    setOpen(true)
  }

  const setOpt = (key: string, val: any) => setForm({ ...form, options: { ...form.options, [key]: val } })

  const buildPayload = () => {
    const options: Record<string, any> = {}
    for (const f of SINK_FIELDS[form.type] || []) {
      let v = form.options[f.key]
      if (v === undefined || v === '') continue
      if (f.kind === 'list' && typeof v === 'string') v = v.split(',').map((s: string) => s.trim()).filter(Boolean)
      if (f.kind === 'map') v = textToMap(headersText)
      options[f.key] = v
    }
    return { name: form.name, type: form.type, source: form.source, options, enabled: form.enabled }
  }

  const submit = async (e: React.FormEvent) => {
    e.preventDefault()
    const payload = buildPayload()
    if (editing) await vector.updateSink(editing.id, payload)
    else await vector.createSink(payload)
    setOpen(false)
    setEditing(null)
    load()
  }

  const runCheck = async (row?: SinkRow) => {
    const payload = row
      ? { sink_id: row.id, name: row.name, type: row.type, source: row.source, options: row.options, send_test_event: sendTestEvent }
      : { ...buildPayload(), send_test_event: sendTestEvent }
    setChecking(true)
    setCheckResult(null)
    try {
      const res = await vector.testSink(payload)
      const r = { ok: res.data.ok, output: res.data.output || '' }
      if (row) setRowCheck({ id: row.id, ...r })
      else setCheckResult(r)
    } catch (err: any) {
      const msg = err?.response?.data?.detail || err?.message || 'check failed'
      if (row) setRowCheck({ id: row.id, ok: false, output: msg })
      else setCheckResult({ ok: false, output: msg })
    } finally {
      setChecking(false)
    }
  }

  const runValidate = async () => {
    setValidating(true)
    try {
      const res = await vector.validate()
      setValidateResult({ valid: res.data.valid, output: res.data.output || '' })
    } catch (err: any) {
      setValidateResult({ valid: false, output: err?.response?.data?.detail || err?.message })
    } finally { setValidating(false) }
  }

  const runRestart = async () => {
    setRestarting(true)
    try { await vector.restart() } catch { /* surfaced via runtime card */ }
    setRestarting(false)
  }

  const togglePreview = async () => {
    if (preview !== null) { setPreview(null); return }
    try {
      const res = await vector.preview()
      setPreview(res.data.config || '')
    } catch { setPreview('') }
  }

  const fields = SINK_FIELDS[form.type] || []

  return (
    <div className="space-y-6">
      {loadError && (
        <div className="rounded-lg border border-border bg-card p-4 text-sm text-red-400">{loadError}</div>
      )}

      {/* Status / actions card */}
      <div className="rounded-lg border border-border bg-card p-4 shadow-sm flex flex-wrap items-center gap-3">
        <div className="flex items-center gap-2">
          {vectorStatus.running
            ? <Badge variant="success">{t('pages:logs.pipeline.vectorRunning', 'Vector running')}</Badge>
            : vectorStatus.available
              ? <Badge variant="warning">{t('pages:logs.pipeline.vectorNotRunning', 'Vector container not running')}</Badge>
              : <Badge variant="error">{t('pages:logs.pipeline.vectorNotFound', 'Vector container not found')}</Badge>}
        </div>
        <div className="ms-auto flex items-center gap-2">
          <button onClick={runValidate} disabled={validating} className="btn-secondary flex items-center gap-1">
            <Stethoscope className="w-4 h-4" />{validating ? t('pages:logs.pipeline.checking', 'Checking…') : t('pages:logs.pipeline.validate', 'Validate config')}
          </button>
          <button onClick={togglePreview} className="btn-secondary flex items-center gap-1">
            <FileCode className="w-4 h-4" />{t('pages:logs.pipeline.preview', 'Preview vector.toml')}
          </button>
          <button onClick={runRestart} disabled={restarting} className="btn-secondary flex items-center gap-1">
            <RefreshCw className="w-4 h-4" />{t('pages:logs.pipeline.restart', 'Restart Vector')}
          </button>
        </div>
      </div>

      {validateResult && (
        <div className={`rounded-lg border p-4 text-sm font-mono whitespace-pre-wrap ${validateResult.valid ? 'border-green-500/40 bg-green-500/10' : 'border-red-500/40 bg-red-500/10'}`}>
          <div className="flex items-center justify-between mb-2">
            <span className={`text-sm font-sans ${validateResult.valid ? 'text-green-400' : 'text-red-400'}`}>
              {validateResult.valid ? t('pages:logs.pipeline.checkOk', 'Check passed') : t('pages:logs.pipeline.checkFailed', 'Check failed')}
            </span>
            <button type="button" onClick={() => setValidateResult(null)} className="text-muted-foreground hover:text-foreground" aria-label={t('common:actions.dismiss', 'Dismiss')}>
              <X className="w-4 h-4" />
            </button>
          </div>
          {validateResult.output || (validateResult.valid ? 'OK' : 'failed')}
        </div>
      )}
      {preview !== null && (
        <div className="rounded-lg border border-border bg-card p-4 shadow-sm">
          <div className="flex items-center justify-between mb-2">
            <span className="text-sm font-sans text-secondary-foreground">{t('pages:logs.pipeline.preview', 'Preview vector.toml')}</span>
            <button type="button" onClick={() => setPreview(null)} className="text-muted-foreground hover:text-foreground" aria-label={t('common:actions.dismiss', 'Dismiss')}>
              <X className="w-4 h-4" />
            </button>
          </div>
          <pre className="text-xs font-mono whitespace-pre-wrap text-secondary-foreground max-h-96 overflow-y-auto">{preview || t('common:table.empty')}</pre>
        </div>
      )}

      {/* Sinks */}
      <div className="flex items-center justify-between">
        <h2 className="text-2xl font-bold flex items-center gap-2"><List className="h-5 w-5 text-primary" /> {t('pages:logs.pipeline.sinks', 'Sinks')}</h2>
        <button onClick={openAdd} className="btn-primary flex items-center gap-1"><Plus className="w-4 h-4" />{t('pages:logs.pipeline.addSink', 'Add sink')}</button>
      </div>
      <div className="rounded-lg border border-border bg-card p-6 shadow-sm overflow-x-auto">
        <table className="w-full text-sm text-start">
          <thead className="text-muted-foreground border-b border-border">
            <tr>
              <th className="text-start pb-2">{t('pages:logs.modal.name', 'Name')}</th>
              <th className="text-start pb-2">{t('pages:logs.pipeline.type', 'Type')}</th>
              <th className="text-start pb-2">{t('pages:logs.pipeline.source', 'Source')}</th>
              <th className="text-start pb-2">{t('pages:logs.modal.enabled', 'Enabled')}</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {sinks.map(s => (
              <React.Fragment key={s.id}>
                <tr className="border-b border-border last:border-0">
                  <td className="py-2 font-medium">{s.name}</td>
                  <td><code className="text-xs">{s.type}</code></td>
                  <td className="text-xs">{t(`pages:logs.pipeline.source_${s.source || 'corex'}`, s.source || 'corex')}</td>
                  <td>{s.enabled ? t('common:actions.yes', 'Yes') : t('common:actions.no', 'No')}</td>
                  <td className="space-x-2 whitespace-nowrap text-end">
                    <button onClick={() => runCheck(s)} className="text-primary hover:underline">{t('pages:logs.pipeline.check', 'Check')}</button>
                    <button onClick={() => openEdit(s)} className="text-primary hover:underline">{t('common:actions.edit', 'Edit')}</button>
                    <button onClick={() => vector.removeSink(s.id).then(load)} className="text-red-400 hover:underline">{t('common:actions.delete', 'Delete')}</button>
                  </td>
                </tr>
                {rowCheck?.id === s.id && (
                  <tr><td colSpan={5} className="pb-3">
                    <div className={`rounded border p-3 text-xs font-mono whitespace-pre-wrap ${rowCheck.ok ? 'border-green-500/40 bg-green-500/10' : 'border-red-500/40 bg-red-500/10'}`}>
                      <div className="flex items-center justify-between mb-1">
                        <span className={`text-sm font-sans ${rowCheck.ok ? 'text-green-400' : 'text-red-400'}`}>
                          {rowCheck.ok ? t('pages:logs.pipeline.checkOk', 'Check passed') : t('pages:logs.pipeline.checkFailed', 'Check failed')}
                        </span>
                        <button type="button" onClick={() => setRowCheck(null)} className="text-muted-foreground hover:text-foreground" aria-label={t('common:actions.dismiss', 'Dismiss')}>
                          <X className="w-3.5 h-3.5" />
                        </button>
                      </div>
                      {rowCheck.output || (rowCheck.ok ? 'OK' : 'failed')}
                    </div>
                  </td></tr>
                )}
              </React.Fragment>
            ))}
            {sinks.length === 0 && (
              <tr><td colSpan={5} className="py-6 text-center text-muted-foreground">{t('common:table.empty', 'No items')}</td></tr>
            )}
          </tbody>
        </table>
      </div>

      {/* Sink modal */}
      <Modal open={open} onClose={() => setOpen(false)} title={editing ? t('pages:logs.pipeline.editSink', 'Edit sink') : t('pages:logs.pipeline.addSink', 'Add sink')} size="xl">
        <form onSubmit={submit} className="space-y-4">
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="label">{t('pages:logs.modal.name', 'Name')}</label>
              <input className="input" value={form.name} onChange={e => setForm({ ...form, name: e.target.value })} required />
            </div>
            <div>
              <label className="label">{t('pages:logs.pipeline.type', 'Type')}</label>
              <select className="input" value={form.type} onChange={e => setForm({ ...form, type: e.target.value, options: {} })}>
                {SINK_TYPES.map(st => <option key={st} value={st}>{st}</option>)}
              </select>
            </div>
          </div>

          <div>
            <label className="label">{t('pages:logs.pipeline.source', 'Source')}</label>
            <select className="input" value={form.source || 'corex'} onChange={e => setForm({ ...form, source: e.target.value })}>
              {SOURCE_IDS.map(id => <option key={id} value={id}>{t(`pages:logs.pipeline.source_${id}`, id)}</option>)}
            </select>
          </div>

          <div className="grid grid-cols-2 gap-3">
            {fields.map(f => (
              <div key={f.key} className={f.kind === 'map' ? 'col-span-2' : ''}>
                <label className="label">
                  {f.key}{f.required ? ' *' : ''}{f.secret ? ` (${t('pages:logs.pipeline.secret', 'secret')})` : ''}
                </label>
                {f.kind === 'select' ? (
                  <select className="input" value={form.options[f.key] ?? f.options?.[0]?.value ?? ''} onChange={e => setOpt(f.key, e.target.value)}>
                    {(f.options || []).map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
                  </select>
                ) : f.kind === 'bool' ? (
                  <select className="input" value={String(form.options[f.key] ?? '')} onChange={e => setOpt(f.key, e.target.value === '' ? undefined : e.target.value === 'true')}>
                    <option value="">{t('pages:logs.pipeline.default', 'default')}</option>
                    <option value="true">true</option>
                    <option value="false">false</option>
                  </select>
                ) : f.kind === 'map' ? (
                  <textarea className="input font-mono" rows={3} value={headersText} onChange={e => setHeadersText(e.target.value)} placeholder={f.placeholder} />
                ) : (
                  <input
                    className="input"
                    type={f.secret ? 'password' : 'text'}
                    value={f.kind === 'list' && Array.isArray(form.options[f.key]) ? (form.options[f.key] as any[]).join(', ') : (form.options[f.key] ?? '')}
                    onChange={e => setOpt(f.key, e.target.value)}
                    placeholder={f.secret && editing ? t('pages:logs.pipeline.keepSecret', 'leave masked to keep current') : f.placeholder}
                  />
                )}
              </div>
            ))}
          </div>

          <label className="flex items-center gap-2">
            <input type="checkbox" checked={form.enabled} onChange={e => setForm({ ...form, enabled: e.target.checked })} />
            {t('pages:logs.modal.enabled', 'Enabled')}
          </label>

          <div className="border-t border-border pt-3 space-y-3">
            <label className="flex items-center gap-2 text-sm">
              <input type="checkbox" checked={sendTestEvent} onChange={e => setSendTestEvent(e.target.checked)} />
              {t('pages:logs.pipeline.sendTestEvent', 'Send a test event (verifies end-to-end delivery)')}
            </label>
            {checkResult && (
              <div className={`rounded border p-3 text-xs font-mono whitespace-pre-wrap max-h-48 overflow-y-auto ${checkResult.ok ? 'border-green-500/40 bg-green-500/10' : 'border-red-500/40 bg-red-500/10'}`}>
                <div className="flex items-center justify-between mb-1">
                  <div className="flex items-center gap-1">
                    {checkResult.ok ? <CheckCircle2 className="w-4 h-4 text-green-400" /> : <XCircle className="w-4 h-4 text-red-400" />}
                    <span>{checkResult.ok ? t('pages:logs.pipeline.checkOk', 'Check passed') : t('pages:logs.pipeline.checkFailed', 'Check failed')}</span>
                  </div>
                  <button type="button" onClick={() => setCheckResult(null)} className="text-muted-foreground hover:text-foreground" aria-label={t('common:actions.dismiss', 'Dismiss')}>
                    <X className="w-3.5 h-3.5" />
                  </button>
                </div>
                {checkResult.output}
              </div>
            )}
            <div className="flex gap-2">
              <button type="button" onClick={() => runCheck()} disabled={checking} className="btn-secondary flex items-center gap-1">
                <Stethoscope className="w-4 h-4" />{checking ? t('pages:logs.pipeline.checking', 'Checking…') : t('pages:logs.pipeline.checkSink', 'Check sink')}
              </button>
              <button className="btn-primary flex-1">{t('common:actions.save', 'Save')}</button>
            </div>
          </div>
        </form>
      </Modal>
    </div>
  )
}
