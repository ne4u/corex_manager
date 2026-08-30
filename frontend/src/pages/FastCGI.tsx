import React, { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Pencil, Trash2 } from 'lucide-react'
import { fcgiApps, getErrorDetail } from '../services/api'
import useApiList from '../hooks/useApiList'
import Modal from '../components/Modal'
import LabelWithTooltip from '../components/LabelWithTooltip'
import InfoTooltip from '../components/InfoTooltip'
import { IconButton } from '../components/ui'

const initialForm = {
  name: '',
  description: '',
  docroot: '',
  index: '',
  path_info: '',
  log_stderr_enabled: false,
  log_stderr_target: '',
  keep_conn: true,
  mpxs_conns: false,
  max_reqs: 1,
  params: [] as any[],
}

export default function FastCGI() {
  const { t } = useTranslation(['pages', 'common'])
  const { items, reload, loading } = useApiList(fcgiApps.list)
  const [open, setOpen] = useState(false)
  const [editing, setEditing] = useState<number | null>(null)
  const [form, setForm] = useState<any>(initialForm)

  const reset = () => setForm(initialForm)

  const openAdd = () => { setEditing(null); reset(); setOpen(true) }
  const openEdit = (f: any) => {
    setEditing(f.id)
    setForm({
      ...initialForm,
      ...f,
      log_stderr_enabled: f.log_stderr_enabled ?? false,
      log_stderr_target: f.log_stderr_target || '',
      keep_conn: f.keep_conn ?? true,
      mpxs_conns: f.mpxs_conns ?? false,
      max_reqs: f.max_reqs ?? 1,
      params: f.params || [],
    })
    setOpen(true)
  }

  const addParam = () => setForm({ ...form, params: [...form.params, { name: '', value: '', enabled: true }] })
  const updateParam = (i: number, key: string, val: any) => {
    const updated = [...form.params]
    updated[i] = { ...updated[i], [key]: key === 'enabled' ? val : val }
    setForm({ ...form, params: updated })
  }
  const removeParam = (i: number) => setForm({ ...form, params: form.params.filter((_: any, idx: number) => idx !== i) })

  const submit = async (e: React.FormEvent) => {
    e.preventDefault()
    const payload = {
      ...form,
      max_reqs: Number(form.max_reqs),
    }
    try {
      if (editing) await fcgiApps.update(editing, payload)
      else await fcgiApps.create(payload)
      setOpen(false)
      reset()
      setEditing(null)
      reload()
    } catch (err) {
      alert(getErrorDetail(err, t('pages:fastcgi.failedToSaveFcgiApp')))
    }
  }

  return (
    <div className="space-y-4">
      <div className="flex justify-end">
        <button onClick={openAdd} className="btn-primary">{t('pages:fastcgi.addFcgiApp')}</button>
      </div>
      {loading ? <p>{t('pages:fastcgi.loading')}</p> : (
        <div className="card overflow-x-auto">
          <table className="w-full text-sm text-start">
            <thead className="text-slate-400 border-b border-slate-800"><tr><th>{t('pages:fastcgi.tableHeaders.name')}</th><th>{t('pages:fastcgi.tableHeaders.docroot')}</th><th>{t('pages:fastcgi.tableHeaders.index')}</th><th>{t('pages:fastcgi.tableHeaders.keepConn')}</th><th>{t('pages:fastcgi.tableHeaders.multiplex')}</th><th>{t('pages:fastcgi.tableHeaders.maxReqs')}</th><th></th></tr></thead>
            <tbody>
              {items.map((f: any) => (
                <tr key={f.id} className="border-b border-slate-800 last:border-0">
                  <td className="py-2">{f.name}</td>
                  <td>{f.docroot || '-'}</td>
                  <td>{f.index || '-'}</td>
                  <td>{f.keep_conn ? t('common:actions.yes') : t('common:actions.no')}</td>
                  <td>{f.mpxs_conns ? t('common:actions.yes') : t('common:actions.no')}</td>
                  <td>{f.max_reqs}</td>
                  <td className="space-x-1">
                    <IconButton icon={Pencil} aria-label={t('common:actions.edit')} onClick={() => openEdit(f)} />
                    <IconButton icon={Trash2} variant="danger" aria-label={t('common:actions.delete')} onClick={() => fcgiApps.remove(f.id).then(reload)} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <Modal open={open} onClose={() => setOpen(false)} title={editing ? t('pages:fastcgi.modal.editTitle') : t('pages:fastcgi.modal.addTitle')}>
        <form onSubmit={submit} className="space-y-3">
          <div className="grid grid-cols-2 gap-3">
            <div><LabelWithTooltip tooltip={t('pages:fastcgi.tooltips.name')} className="label">{t('pages:fastcgi.modal.name')}</LabelWithTooltip><input className="input" value={form.name} onChange={e => setForm({ ...form, name: e.target.value })} /></div>
            <div><LabelWithTooltip tooltip={t('pages:fastcgi.tooltips.index')} className="label">{t('pages:fastcgi.modal.index')}</LabelWithTooltip><input className="input" placeholder={t('pages:fastcgi.modal.indexPlaceholder')} value={form.index} onChange={e => setForm({ ...form, index: e.target.value })} /></div>
            <div className="col-span-2"><LabelWithTooltip tooltip={t('pages:fastcgi.tooltips.description')} className="label">{t('pages:fastcgi.modal.description')}</LabelWithTooltip><input className="input" value={form.description} onChange={e => setForm({ ...form, description: e.target.value })} /></div>
            <div className="col-span-2"><LabelWithTooltip tooltip={t('pages:fastcgi.tooltips.docroot')} className="label">{t('pages:fastcgi.modal.docroot')}</LabelWithTooltip><input className="input" placeholder={t('pages:fastcgi.modal.docrootPlaceholder')} value={form.docroot} onChange={e => setForm({ ...form, docroot: e.target.value })} /></div>
            <div className="col-span-2"><LabelWithTooltip tooltip={t('pages:fastcgi.tooltips.pathInfoRegex')} className="label">{t('pages:fastcgi.modal.pathInfoRegex')}</LabelWithTooltip><input className="input" placeholder={t('pages:fastcgi.modal.pathInfoRegexPlaceholder')} value={form.path_info} onChange={e => setForm({ ...form, path_info: e.target.value })} /></div>
            <div className="col-span-2">
              <LabelWithTooltip tooltip={t('pages:fastcgi.tooltips.maxConcurrentRequests')} className="label">{t('pages:fastcgi.modal.maxConcurrentRequests')}</LabelWithTooltip>
              <input type="number" min={1} className="input disabled:opacity-50" disabled={!form.mpxs_conns} value={form.max_reqs} onChange={e => setForm({ ...form, max_reqs: Number(e.target.value) })} />
              {!form.mpxs_conns && <p className="text-xs text-slate-500 mt-1">{t('pages:fastcgi.modal.maxReqsHint')}</p>}
            </div>
            <div className="col-span-2"><LabelWithTooltip tooltip={t('pages:fastcgi.tooltips.stderrLogTarget')} className="label">{t('pages:fastcgi.modal.stderrLogTarget')}</LabelWithTooltip><input className="input" placeholder={t('pages:fastcgi.modal.stderrLogTargetPlaceholder')} value={form.log_stderr_target} onChange={e => setForm({ ...form, log_stderr_target: e.target.value })} /></div>
          </div>
          <div className="flex gap-4 flex-wrap">
            <label className="flex items-center gap-2"><input type="checkbox" checked={form.log_stderr_enabled} onChange={e => setForm({ ...form, log_stderr_enabled: e.target.checked })} /> <span>{t('pages:fastcgi.modal.logStderr')}</span><InfoTooltip content={t('pages:fastcgi.tooltips.logStderr')} /></label>
            <label className="flex items-center gap-2"><input type="checkbox" checked={form.keep_conn} onChange={e => setForm({ ...form, keep_conn: e.target.checked })} /> <span>{t('pages:fastcgi.modal.keepConnectionOpen')}</span><InfoTooltip content={t('pages:fastcgi.tooltips.keepConnectionOpen')} /></label>
            <label className="flex items-center gap-2"><input type="checkbox" checked={form.mpxs_conns} onChange={e => setForm({ ...form, mpxs_conns: e.target.checked })} /> <span>{t('pages:fastcgi.modal.connectionMultiplexing')}</span><InfoTooltip content={t('pages:fastcgi.tooltips.connectionMultiplexing')} /></label>
          </div>

          <div>
            <div className="flex items-center justify-between mb-2"><h4 className="font-semibold">{t('pages:fastcgi.params.title')}</h4><button type="button" onClick={addParam} className="text-sm text-primary hover:underline">{t('pages:fastcgi.params.addParam')}</button></div>
            <div className="space-y-2">
              {form.params.map((p: any, i: number) => (
                <div key={i} className="grid grid-cols-12 gap-2 items-center bg-slate-900 p-2 rounded border border-slate-800">
                  <div className="col-span-3">
                    <LabelWithTooltip tooltip={t('pages:fastcgi.tooltips.paramName')}>{t('pages:fastcgi.params.name')}</LabelWithTooltip>
                    <input className="input text-xs" placeholder={t('pages:fastcgi.params.name')} value={p.name} onChange={e => updateParam(i, 'name', e.target.value)} />
                  </div>
                  <div className="col-span-7">
                    <LabelWithTooltip tooltip={t('pages:fastcgi.tooltips.paramValue')}>{t('pages:fastcgi.params.value')}</LabelWithTooltip>
                    <input className="input text-xs" placeholder={t('pages:fastcgi.params.valuePlaceholder')} value={p.value} onChange={e => updateParam(i, 'value', e.target.value)} />
                  </div>
                  <div className="col-span-1">
                    <LabelWithTooltip tooltip={t('pages:fastcgi.tooltips.paramEnabled')}>{t('pages:fastcgi.params.enabled')}</LabelWithTooltip>
                    <div className="flex justify-center"><input type="checkbox" checked={p.enabled} onChange={e => updateParam(i, 'enabled', e.target.checked)} /></div>
                  </div>
                  <div className="col-span-1"><button type="button" onClick={() => removeParam(i)} className="text-red-400 text-xs hover:underline">{t('pages:fastcgi.params.remove')}</button></div>
                </div>
              ))}
            </div>
            <p className="text-xs text-slate-500 mt-1">{t('pages:fastcgi.params.hint')}</p>
          </div>

          <button className="btn-primary w-full">{t('pages:fastcgi.modal.save')}</button>
        </form>
      </Modal>
    </div>
  )
}
