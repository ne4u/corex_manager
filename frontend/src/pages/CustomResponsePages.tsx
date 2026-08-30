import React, { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { FileText, Pencil, Trash2, Eye } from 'lucide-react'
import useApiList from '../hooks/useApiList'
import { errorPages, listeners } from '../services/api'
import Modal from '../components/Modal'
import { IconButton } from '../components/ui'

interface CustomResponsePage {
  id: number
  code: number
  content_type: string
  listener_id?: number | null
  listener_ids?: number[] | null
  content: string
}

export default function CustomResponsePages() {
  const { t } = useTranslation(['pages', 'common'])
  const { items, loading, reload } = useApiList<CustomResponsePage>(errorPages.list)
  const { items: listenerList } = useApiList(listeners.list)
  const [open, setOpen] = useState(false)
  const [editing, setEditing] = useState<number | null>(null)
  const initialForm = { code: 403, listener_ids: [] as number[], content_type: 'text/html', content: '' }
  const [form, setForm] = useState<any>(initialForm)

  const openAdd = () => { setEditing(null); setForm(initialForm); setOpen(true) }
  const openEdit = (p: any) => { setEditing(p.id); setForm({ ...p, listener_ids: p.listener_ids || (p.listener_id ? [p.listener_id] : []) }); setOpen(true) }

  const submit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (editing) await errorPages.update(editing, form)
    else await errorPages.create(form)
    setEditing(null)
    setForm(initialForm)
    setOpen(false)
    reload()
  }

  const remove = async (id: number) => {
    await errorPages.remove(id)
    reload()
  }

  const doPreview = async (p: any) => {
    try {
      const res = await errorPages.preview(p.id)
      const w = window.open('about:blank', '_blank')
      if (w) {
        w.document.open()
        w.document.write(res.data.content)
        w.document.close()
      }
    } catch (e) {
      console.error(e)
    }
  }

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold flex items-center gap-2">
        <FileText className="h-5 w-5 text-primary" /> {t('pages:customResponsePages.title')}
      </h1>

      <div className="card space-y-3 max-w-3xl">
        <h2 className="text-lg font-semibold">{t('pages:customResponsePages.templateVars.title')}</h2>
        <p className="text-sm text-slate-400">
          {t('pages:customResponsePages.templateVars.description', {
            placeholder: '{{ variable }}',
            requestId: '{{ request_id }}'
          })}
        </p>
        <p className="text-sm text-slate-400 font-semibold">{t('pages:customResponsePages.templateVars.common')}</p>
        <ul className="text-sm text-slate-400 list-disc ps-5 space-y-1">
          <li><code className="text-slate-200">{'{{ request_id }}'}</code> — {t('pages:customResponsePages.templateVars.vars.requestId')}</li>
          <li><code className="text-slate-200">{'{{ client_ip }}'}</code> — {t('pages:customResponsePages.templateVars.vars.clientIp')}</li>
          <li><code className="text-slate-200">{'{{ client_port }}'}</code> — {t('pages:customResponsePages.templateVars.vars.clientPort')}</li>
          <li><code className="text-slate-200">{'{{ method }}'}</code> — {t('pages:customResponsePages.templateVars.vars.method')}</li>
          <li><code className="text-slate-200">{'{{ uri }}'}</code> — {t('pages:customResponsePages.templateVars.vars.uri')}</li>
          <li><code className="text-slate-200">{'{{ path }}'}</code> — {t('pages:customResponsePages.templateVars.vars.path')}</li>
          <li><code className="text-slate-200">{'{{ query }}'}</code> — {t('pages:customResponsePages.templateVars.vars.query')}</li>
          <li><code className="text-slate-200">{'{{ host }}'}</code> — {t('pages:customResponsePages.templateVars.vars.host')}</li>
          <li><code className="text-slate-200">{'{{ user_agent }}'}</code> — {t('pages:customResponsePages.templateVars.vars.userAgent')}</li>
          <li><code className="text-slate-200">{'{{ referer }}'}</code> — {t('pages:customResponsePages.templateVars.vars.referer')}</li>
          <li><code className="text-slate-200">{'{{ timeout }}'}</code> — {t('pages:customResponsePages.templateVars.vars.timeout')}</li>
          <li><code className="text-slate-200">{'{{ timestamp }}'}</code> — {t('pages:customResponsePages.templateVars.vars.timestamp')}</li>
          <li><code className="text-slate-200">{'{{ frontend_name }}'}</code> / <code className="text-slate-200">{'{{ backend_name }}'}</code> — {t('pages:customResponsePages.templateVars.vars.proxyNames')}</li>
          <li><code className="text-slate-200">{'{{ rate_limit_window }}'}</code> — {t('pages:customResponsePages.templateVars.vars.rateLimitWindow')}</li>
          <li><code className="text-slate-200">{'{{ rate_limit_duration }}'}</code> — {t('pages:customResponsePages.templateVars.vars.rateLimitDuration')}</li>
        </ul>
        <p className="text-sm text-slate-400">
          {t('pages:customResponsePages.templateVars.advanced', {
            name: '{{ name }}'
          })}
        </p>
      </div>

      <div className="card space-y-3">
        <div className="flex items-center justify-between">
          <h2 className="text-lg font-semibold">{t('pages:customResponsePages.title')}</h2>
          <button onClick={openAdd} className="btn-primary">{t('pages:customResponsePages.addPage')}</button>
        </div>
        {loading ? (
          <p className="text-sm text-slate-400">{t('common:actions.loading')}</p>
        ) : items.length === 0 ? (
          <p className="text-sm text-slate-400">{t('pages:customResponsePages.noPages')}</p>
        ) : (
          <table className="w-full text-sm text-start">
            <thead className="text-slate-400 border-b border-slate-800"><tr><th>{t('pages:customResponsePages.tableHeaders.code')}</th><th>{t('pages:customResponsePages.tableHeaders.listener')}</th><th>{t('pages:customResponsePages.tableHeaders.contentType')}</th><th>{t('pages:customResponsePages.tableHeaders.length')}</th><th></th></tr></thead>
            <tbody>
              {items.map((ep) => (
                <tr key={ep.id} className="border-b border-slate-800 last:border-0">
                  <td className="py-2">{ep.code}</td>
                  <td>{ep.listener_ids?.length ? ep.listener_ids.map((id: number) => listenerList.find((l: any) => l.id === id)?.name).filter(Boolean).join(', ') : (ep.listener_id ? listenerList.find((l: any) => l.id === ep.listener_id)?.name : t('pages:customResponsePages.modal.all'))}</td>
                  <td>{ep.content_type}</td>
                  <td>{ep.content.length}</td>
                  <td className="space-x-1">
                    <IconButton icon={Pencil} aria-label={t('common:actions.edit')} onClick={() => openEdit(ep)} />
                    <IconButton icon={Eye} aria-label={t('pages:customResponsePages.actions.preview')} onClick={() => doPreview(ep)} />
                    <IconButton icon={Trash2} variant="danger" aria-label={t('common:actions.delete')} onClick={() => remove(ep.id)} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      <Modal open={open} onClose={() => setOpen(false)} title={editing ? t('pages:customResponsePages.modal.editTitle') : t('pages:customResponsePages.modal.addTitle')}>
        <form onSubmit={submit} className="space-y-3">
          <div className="grid grid-cols-2 gap-3">
            <div><label className="label">{t('pages:customResponsePages.modal.code')}</label><input type="number" className="input" value={form.code} onChange={e => setForm({ ...form, code: Number(e.target.value) })} /></div>
            <div><label className="label">{t('pages:customResponsePages.modal.contentType')}</label><input className="input" value={form.content_type} onChange={e => setForm({ ...form, content_type: e.target.value })} /></div>
          </div>
          <div><label className="label">{t('pages:customResponsePages.modal.listenersNoneAll')}</label><div className="input h-auto max-h-32 overflow-y-auto p-2 space-y-1 text-sm text-slate-300">{listenerList.map((l: any) => (<label key={l.id} className="flex items-center gap-2"><input type="checkbox" className="rounded border-slate-600 bg-slate-800 text-primary" checked={form.listener_ids.includes(l.id)} onChange={(e: any) => setForm({ ...form, listener_ids: e.target.checked ? [...form.listener_ids, l.id] : form.listener_ids.filter((id: number) => id !== l.id) })} /> {l.name}</label>))}</div></div>
          <div><label className="label">{t('pages:customResponsePages.modal.htmlContent')}</label><textarea className="input" rows={6} value={form.content} onChange={e => setForm({ ...form, content: e.target.value })} /></div>
          <button className="btn-primary w-full">{t('common:actions.save')}</button>
        </form>
      </Modal>
    </div>
  )
}
