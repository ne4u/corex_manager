import React, { useState, useEffect } from 'react'
import { useTranslation } from 'react-i18next'
import { Wand2, GripVertical, Pencil, Trash2, Shield } from 'lucide-react'
import { responseTransforms, backends, pageProtect } from '../services/api'
import useApiList from '../hooks/useApiList'
import Modal from '../components/Modal'
import { IconButton } from '../components/ui'
import LabelWithTooltip from '../components/LabelWithTooltip'
import InfoTooltip from '../components/InfoTooltip'

const initialForm = {
  name: '',
  backend_ids: [] as number[],
  priority: 0,
  enabled: true,
  transform_type: 'replace' as 'replace' | 'inject' | 'mask',
  content_types: '',
  max_body_size: 1048576,
  find_regex: '',
  replace_string: '',
  inject_string: '',
  inject_position: 'before' as 'before' | 'after' | 'replace',
  mask_mode: 'detector' as 'detector' | 'regex',
  detector: 'email' as 'email' | 'phone' | 'ssn' | 'credit_card' | 'ip',
  token_mode: 'tokenize' as 'tokenize' | 'encrypt',
  token_prefix: 'TOK_',
  token_ttl: 3600,
  encrypt_key_env: '',
  detokenize_query: false,
}

export default function ResponseTransforms() {
  const { t } = useTranslation(['pages', 'common'])
  const { items: transforms, reload } = useApiList(responseTransforms.list)
  const { items: backendList } = useApiList(backends.list)
  const [open, setOpen] = useState(false)
  const [editing, setEditing] = useState<number | null>(null)
  const [form, setForm] = useState<any>(initialForm)
  const [beaconSettings, setBeaconSettings] = useState<any>(null)

  useEffect(() => {
    pageProtect.settings.get().then(r => setBeaconSettings(r.data)).catch(() => {})
  }, [reload])

  // Build a synthetic read-only row for the Page Protect beacon injection rule
  const beaconRow = beaconSettings?.beacon_injection_enabled ? {
    id: '__beacon__',
    name: 'Page Protect Inventory Beacon',
    transform_type: 'inject',
    find_regex: '</head>|</body>',
    inject_string: `<script src="${beaconSettings.beacon_script_path || '/_cx-assets.js'}"></script>`,
    inject_position: 'before',
    content_types: beaconSettings.beacon_content_types || 'text/html',
    enabled: true,
    _system: true,
    backend_ids: beaconSettings.beacon_backend_ids || [],
  } : null

  const allRows = beaconRow ? [beaconRow, ...transforms] : transforms

  const openAdd = () => { setEditing(null); setForm(initialForm); setOpen(true) }
  const openEdit = (r: any) => {
    setEditing(r.id)
    setForm({
      ...r,
      backend_ids: r.backend_ids || (r.backend_id ? [r.backend_id] : []),
      content_types: r.content_types || '',
      find_regex: r.find_regex || '',
      replace_string: r.replace_string || '',
      inject_string: r.inject_string || '',
      inject_position: r.inject_position || 'before',
      mask_mode: r.mask_mode || 'detector',
      detector: r.detector || 'email',
      token_mode: r.token_mode || 'tokenize',
      token_prefix: r.token_prefix || 'TOK_',
      token_ttl: r.token_ttl || 3600,
      encrypt_key_env: r.encrypt_key_env || '',
      detokenize_query: r.detokenize_query ?? false,
    })
    setOpen(true)
  }

  const submit = async (e: React.FormEvent) => {
    e.preventDefault()
    const payload = { ...form, priority: editing ? form.priority : transforms.length }
    if (editing) await responseTransforms.update(editing, payload)
    else await responseTransforms.create(payload)
    setEditing(null)
    setForm(initialForm)
    setOpen(false)
    reload()
  }

  const handleDrop = async (fromId: number, toId: number) => {
    const list = [...transforms]
    const fromIndex = list.findIndex((x: any) => x.id === fromId)
    const toIndex = list.findIndex((x: any) => x.id === toId)
    if (fromIndex === -1 || toIndex === -1 || fromIndex === toIndex) return
    const [moved] = list.splice(fromIndex, 1)
    list.splice(toIndex, 0, moved)
    await responseTransforms.reorder(list.map((r: any) => r.id))
    reload()
  }

  const renderSummary = (r: any) => {
    if (r.transform_type === 'replace') return `${r.find_regex} → ${r.replace_string}`
    if (r.transform_type === 'inject') return `${r.inject_position} ${r.find_regex}: ${r.inject_string}`
    if (r.transform_type === 'mask') {
      const target = r.mask_mode === 'detector' ? r.detector : r.find_regex
      let summary = `mask ${r.mask_mode}(${target}) via ${r.token_mode}`
      if (r.detokenize_query) summary += ' +query'
      return summary
    }
    return '-'
  }

  const renderBackends = (r: any) => {
    if (r.backend_ids?.length) return r.backend_ids.map((id: number) => backendList.find((b: any) => b.id === id)?.name).filter(Boolean).join(', ')
    if (r.backend_id) return backendList.find((b: any) => b.id === r.backend_id)?.name
    return t('pages:responseTransforms.all')
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h2 className="text-2xl font-bold flex items-center gap-2">
          <Wand2 className="h-5 w-5 text-primary" /> {t('pages:responseTransforms.title')}
        </h2>
        <button onClick={openAdd} className="btn-primary">{t('pages:responseTransforms.addTransform')}</button>
      </div>
      <p className="text-sm text-slate-400">
        {t('pages:responseTransforms.description')}
      </p>
      <div className="card overflow-x-auto">
        <table className="w-full text-sm text-start">
          <thead className="text-slate-400 border-b border-slate-800">
            <tr>
              <th className="w-6"></th>
              <th>{t('pages:responseTransforms.tableHeaders.name')}</th>
              <th>{t('pages:responseTransforms.tableHeaders.backends')}</th>
              <th>{t('pages:responseTransforms.tableHeaders.type')}</th>
              <th>{t('pages:responseTransforms.tableHeaders.matchTarget')}</th>
              <th>{t('pages:responseTransforms.tableHeaders.enabled')}</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {allRows.map((r: any) => (
              <tr key={r.id}
                draggable={!r._system}
                onDragStart={(e: any) => { if (r._system) return; e.dataTransfer.setData('rt', String(r.id)); e.dataTransfer.effectAllowed = 'move' }}
                onDragOver={(e: any) => e.preventDefault()}
                onDrop={(e: any) => { e.preventDefault(); const fromId = Number(e.dataTransfer.getData('rt')); if (fromId && fromId !== r.id) handleDrop(fromId, r.id) }}
                className="border-b border-slate-800 last:border-0"
              >
                <td className="py-2 pe-2">
                  {r._system ? <Shield className="h-4 w-4 text-primary" /> : <GripVertical className="h-4 w-4 text-slate-500 cursor-grab" />}
                </td>
                <td className="py-2">
                  {r.name}
                  {r._system && <span className="ms-2 text-xs px-1.5 py-0.5 rounded bg-primary/20 text-primary">System</span>}
                </td>
                <td>{renderBackends(r)}</td>
                <td><span className="px-2 py-0.5 rounded bg-slate-800 text-xs">{r.transform_type}</span></td>
                <td className="max-w-md truncate text-slate-400">{renderSummary(r)}</td>
                <td>
                  {r._system ? (
                    <span className={r.enabled ? 'text-green-400' : 'text-slate-500'}>
                      {r.enabled ? t('pages:responseTransforms.enabled') : t('pages:responseTransforms.disabled')}
                    </span>
                  ) : (
                    <button
                      onClick={() => responseTransforms.update(r.id, { enabled: !r.enabled }).then(reload)}
                      className={r.enabled ? 'text-green-400' : 'text-slate-500'}
                    >
                      {r.enabled ? t('pages:responseTransforms.enabled') : t('pages:responseTransforms.disabled')}
                    </button>
                  )}
                </td>
                <td>
                  {!r._system && (
                    <div className="flex gap-1">
                      <IconButton icon={Pencil} aria-label={t('common:actions.edit')} onClick={() => openEdit(r)} />
                      <IconButton icon={Trash2} variant="danger" aria-label={t('common:actions.delete')} onClick={() => responseTransforms.remove(r.id).then(reload)} />
                    </div>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <Modal open={open} onClose={() => setOpen(false)} title={editing ? t('pages:responseTransforms.modal.editTitle') : t('pages:responseTransforms.modal.addTitle')}>
        <form onSubmit={submit} className="space-y-3">
          <div className="grid grid-cols-2 gap-3">
            <div>
              <LabelWithTooltip tooltip={t('pages:responseTransforms.tooltips.name')} className="label">{t('pages:responseTransforms.modal.name')}</LabelWithTooltip>
              <input className="input" value={form.name} onChange={e => setForm({ ...form, name: e.target.value })} required />
            </div>
            <div>
              <LabelWithTooltip tooltip={t('pages:responseTransforms.tooltips.backends')} className="label">{t('pages:responseTransforms.modal.backendsNoneAll')}</LabelWithTooltip>
              <div className="input h-auto max-h-32 overflow-y-auto p-2 space-y-1 text-sm text-slate-300">
                {backendList.map((b: any) => (
                  <label key={b.id} className="flex items-center gap-2">
                    <input type="checkbox" className="rounded border-slate-600 bg-slate-800 text-primary"
                      checked={form.backend_ids.includes(b.id)}
                      onChange={(e: any) => setForm({ ...form, backend_ids: e.target.checked ? [...form.backend_ids, b.id] : form.backend_ids.filter((id: number) => id !== b.id) })}
                    /> {b.name}
                  </label>
                ))}
              </div>
            </div>
            <div>
              <LabelWithTooltip tooltip={t('pages:responseTransforms.tooltips.transformType')} className="label">{t('pages:responseTransforms.modal.transformType')}</LabelWithTooltip>
              <select className="input" value={form.transform_type} onChange={e => setForm({ ...form, transform_type: e.target.value })}>
                <option value="replace">{t('pages:responseTransforms.modal.transformTypeReplace')}</option>
                <option value="inject">{t('pages:responseTransforms.modal.transformTypeInject')}</option>
                <option value="mask">{t('pages:responseTransforms.modal.transformTypeMask')}</option>
              </select>
            </div>
            <div>
              <LabelWithTooltip tooltip={t('pages:responseTransforms.tooltips.contentTypes')} className="label">{t('pages:responseTransforms.modal.contentTypes')}</LabelWithTooltip>
              <input className="input" placeholder={t('pages:responseTransforms.modal.contentTypesPlaceholder')} value={form.content_types} onChange={e => setForm({ ...form, content_types: e.target.value })} />
            </div>
          </div>

          {/* Replace fields */}
          {form.transform_type === 'replace' && (
            <div className="grid grid-cols-2 gap-3">
              <div>
                <LabelWithTooltip tooltip={t('pages:responseTransforms.tooltips.findRegex')} className="label">{t('pages:responseTransforms.modal.findRegex')}</LabelWithTooltip>
                <input className="input" value={form.find_regex} onChange={e => setForm({ ...form, find_regex: e.target.value })} required />
              </div>
              <div>
                <LabelWithTooltip tooltip={t('pages:responseTransforms.tooltips.replaceString')} className="label">{t('pages:responseTransforms.modal.replaceString')}</LabelWithTooltip>
                <input className="input" value={form.replace_string} onChange={e => setForm({ ...form, replace_string: e.target.value })} required />
              </div>
            </div>
          )}

          {/* Inject fields */}
          {form.transform_type === 'inject' && (
            <div className="grid grid-cols-2 gap-3">
              <div>
                <LabelWithTooltip tooltip={t('pages:responseTransforms.tooltips.findRegex')} className="label">Anchor Regex</LabelWithTooltip>
                <input className="input" value={form.find_regex} onChange={e => setForm({ ...form, find_regex: e.target.value })} required />
              </div>
              <div>
                <LabelWithTooltip tooltip={t('pages:responseTransforms.tooltips.injectPosition')} className="label">Inject Position</LabelWithTooltip>
                <select className="input" value={form.inject_position} onChange={e => setForm({ ...form, inject_position: e.target.value })}>
                  <option value="before">Before match</option>
                  <option value="after">After match</option>
                  <option value="replace">Replace match</option>
                </select>
              </div>
              <div className="col-span-2">
                <LabelWithTooltip tooltip={t('pages:responseTransforms.tooltips.injectString')} className="label">Inject String</LabelWithTooltip>
                <input className="input" value={form.inject_string} onChange={e => setForm({ ...form, inject_string: e.target.value })} required />
              </div>
            </div>
          )}

          {/* Mask fields */}
          {form.transform_type === 'mask' && (
            <>
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <LabelWithTooltip tooltip={t('pages:responseTransforms.tooltips.maskMode')} className="label">Mask Mode</LabelWithTooltip>
                  <select className="input" value={form.mask_mode} onChange={e => setForm({ ...form, mask_mode: e.target.value })}>
                    <option value="detector">Detector (built-in PII)</option>
                    <option value="regex">Custom Regex</option>
                  </select>
                </div>
                <div>
                  <LabelWithTooltip tooltip={t('pages:responseTransforms.tooltips.tokenMode')} className="label">Token Mode</LabelWithTooltip>
                  <select className="input" value={form.token_mode} onChange={e => setForm({ ...form, token_mode: e.target.value })}>
                    <option value="tokenize">Tokenize (Valkey store + TTL)</option>
                    <option value="encrypt">Encrypt (AES-256-GCM)</option>
                  </select>
                </div>
              </div>
              {form.mask_mode === 'detector' && (
                <div>
                  <LabelWithTooltip tooltip={t('pages:responseTransforms.tooltips.detector')} className="label">Detector</LabelWithTooltip>
                  <select className="input" value={form.detector} onChange={e => setForm({ ...form, detector: e.target.value })}>
                    <option value="email">Email</option>
                    <option value="phone">Phone</option>
                    <option value="ssn">SSN</option>
                    <option value="credit_card">Credit Card</option>
                    <option value="ip">IP Address</option>
                  </select>
                </div>
              )}
              {form.mask_mode === 'regex' && (
                <div>
                  <LabelWithTooltip tooltip={t('pages:responseTransforms.tooltips.findRegex')} className="label">Custom Regex</LabelWithTooltip>
                  <input className="input" value={form.find_regex} onChange={e => setForm({ ...form, find_regex: e.target.value })} required />
                </div>
              )}
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <LabelWithTooltip tooltip={t('pages:responseTransforms.tooltips.tokenPrefix')} className="label">Token Prefix</LabelWithTooltip>
                  <input className="input" value={form.token_prefix} onChange={e => setForm({ ...form, token_prefix: e.target.value })} required />
                </div>
                {form.token_mode === 'tokenize' && (
                  <div>
                    <LabelWithTooltip tooltip={t('pages:responseTransforms.tooltips.tokenTtl')} className="label">Token TTL (seconds)</LabelWithTooltip>
                    <input type="number" className="input" value={form.token_ttl} onChange={e => setForm({ ...form, token_ttl: Number(e.target.value) })} required />
                  </div>
                )}
                {form.token_mode === 'encrypt' && (
                  <div>
                    <LabelWithTooltip tooltip={t('pages:responseTransforms.tooltips.encryptKeyEnv')} className="label">Encrypt Key Env Var</LabelWithTooltip>
                    <input className="input" placeholder="RESP_TRANSFORM_KEY" value={form.encrypt_key_env} onChange={e => setForm({ ...form, encrypt_key_env: e.target.value })} required />
                  </div>
                )}
              </div>
              <label className="flex items-center gap-2 mt-1">
                <input type="checkbox" className="rounded border-slate-600 bg-slate-800 text-primary"
                  checked={form.detokenize_query}
                  onChange={e => setForm({ ...form, detokenize_query: e.target.checked })}
                />
                <span>{t('pages:responseTransforms.modal.detokenizeQuery')}</span>
                <InfoTooltip content={t('pages:responseTransforms.tooltips.detokenizeQuery')} />
              </label>
            </>
          )}

          <div className="grid grid-cols-2 gap-3">
            <div>
              <LabelWithTooltip tooltip={t('pages:responseTransforms.tooltips.maxBodySize')} className="label">Max Body Size (bytes)</LabelWithTooltip>
              <input type="number" className="input" value={form.max_body_size} onChange={e => setForm({ ...form, max_body_size: Number(e.target.value) })} />
            </div>
            <label className="flex items-center gap-2 mt-6">
              <input type="checkbox" checked={form.enabled} onChange={e => setForm({ ...form, enabled: e.target.checked })} />
              <span>Enabled</span>
              <InfoTooltip content={t('pages:responseTransforms.tooltips.enabled')} />
            </label>
          </div>
          <button className="btn-primary w-full">Save</button>
        </form>
      </Modal>
    </div>
  )
}
