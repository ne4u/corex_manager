import React, { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { AlignJustify, ArrowDownToLine, Pencil, Trash2 } from 'lucide-react'
import { responseHeaders, requestHeaders, listeners, backends } from '../services/api'
import useApiList from '../hooks/useApiList'
import Modal from '../components/Modal'
import { IconButton } from '../components/ui'

export default function Headers() {
  const { t } = useTranslation(['pages', 'common'])
  const { items: headers, reload: rh } = useApiList(responseHeaders.list)
  const { items: reqHeaders, reload: rrh } = useApiList(requestHeaders.list)
  const { items: listenerList } = useApiList(listeners.list)
  const { items: backendList } = useApiList(backends.list)
  const [open, setOpen] = useState(false)
  const [editing, setEditing] = useState<number | null>(null)
  const initialForm = { listener_ids: [] as number[], header: '', value: '', action: 'override', condition: '' }
  const [form, setForm] = useState<any>(initialForm)

  const [ropen, setRopen] = useState(false)
  const [rEditing, setREditing] = useState<number | null>(null)
  const initialRform = { backend_ids: [] as number[], header: '', value: '', action: 'override', condition: '' }
  const [rform, setRform] = useState<any>(initialRform)

  const openAdd = () => { setEditing(null); setForm(initialForm); setOpen(true) }
  const openEdit = (h: any) => { setEditing(h.id); setForm({ ...h, action: h.action === 'set' ? 'override' : h.action, listener_ids: h.listener_ids || (h.listener_id ? [h.listener_id] : []) }); setOpen(true) }

  const openRAdd = () => { setREditing(null); setRform(initialRform); setRopen(true) }
  const openREdit = (h: any) => { setREditing(h.id); setRform({ ...h, action: h.action === 'set' ? 'override' : h.action, backend_ids: h.backend_ids || (h.backend_id ? [h.backend_id] : []) }); setRopen(true) }

  const submit = async (e: React.FormEvent) => { e.preventDefault(); const payload = { ...form }; if (editing) await responseHeaders.update(editing, payload); else await responseHeaders.create(payload); setEditing(null); setForm(initialForm); setOpen(false); rh() }
  const rsubmit = async (e: React.FormEvent) => { e.preventDefault(); const payload = { ...rform }; if (rEditing) await requestHeaders.update(rEditing, payload); else await requestHeaders.create(payload); setREditing(null); setRform(initialRform); setRopen(false); rrh() }

  const renderListener = (h: any) => h.listener_ids?.length ? h.listener_ids.map((id: number) => listenerList.find((l: any) => l.id === id)?.name).filter(Boolean).join(', ') : (h.listener_id ? listenerList.find((l: any) => l.id === h.listener_id)?.name : t('pages:headers.all'))
  const renderBackend = (h: any) => h.backend_ids?.length ? h.backend_ids.map((id: number) => backendList.find((b: any) => b.id === id)?.name).filter(Boolean).join(', ') : (h.backend_id ? backendList.find((b: any) => b.id === h.backend_id)?.name : t('pages:headers.all'))

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between"><h2 className="text-2xl font-bold flex items-center gap-2"><AlignJustify className="h-5 w-5 text-primary" /> {t('pages:headers.responseHeaders')}</h2><button onClick={openAdd} className="btn-primary">{t('pages:headers.addHeader')}</button></div>
      <div className="card overflow-x-auto">
        <table className="w-full text-sm text-start"><thead className="text-slate-400 border-b border-slate-800"><tr><th>{t('pages:headers.tableHeaders.header')}</th><th>{t('pages:headers.tableHeaders.listener')}</th><th>{t('pages:headers.tableHeaders.value')}</th><th>{t('pages:headers.tableHeaders.action')}</th><th></th></tr></thead>
          <tbody>{headers.map((h: any) => (<tr key={h.id} className="border-b border-slate-800 last:border-0"><td className="py-2">{h.header}</td><td>{renderListener(h)}</td><td>{h.value}</td><td>{h.action === 'set' || h.action === 'override' ? t('pages:headers.actionOverride') : h.action}</td>
            <td>
              <div className="flex gap-1">
                <IconButton icon={Pencil} aria-label={t('common:actions.edit')} onClick={() => openEdit(h)} />
                <IconButton icon={Trash2} variant="danger" aria-label={t('common:actions.delete')} onClick={() => responseHeaders.remove(h.id).then(rh)} />
              </div>
            </td></tr>))}</tbody>
        </table>
      </div>
      <div className="flex items-center justify-between"><h2 className="text-2xl font-bold flex items-center gap-2"><ArrowDownToLine className="h-5 w-5 text-primary" /> {t('pages:headers.requestHeaders')}</h2><button onClick={openRAdd} className="btn-primary">{t('pages:headers.addHeader')}</button></div>
      <div className="card overflow-x-auto">
        <table className="w-full text-sm text-start"><thead className="text-slate-400 border-b border-slate-800"><tr><th>{t('pages:headers.tableHeaders.header')}</th><th>{t('pages:headers.tableHeaders.backend')}</th><th>{t('pages:headers.tableHeaders.value')}</th><th>{t('pages:headers.tableHeaders.action')}</th><th></th></tr></thead>
          <tbody>{reqHeaders.map((h: any) => (<tr key={h.id} className="border-b border-slate-800 last:border-0"><td className="py-2">{h.header}</td><td>{renderBackend(h)}</td><td>{h.value}</td><td>{h.action === 'set' || h.action === 'override' ? t('pages:headers.actionOverride') : h.action}</td>
            <td>
              <div className="flex gap-1">
                <IconButton icon={Pencil} aria-label={t('common:actions.edit')} onClick={() => openREdit(h)} />
                <IconButton icon={Trash2} variant="danger" aria-label={t('common:actions.delete')} onClick={() => requestHeaders.remove(h.id).then(rrh)} />
              </div>
            </td></tr>))}</tbody>
        </table>
      </div>
      <Modal open={open} onClose={() => setOpen(false)} title={editing ? t('pages:headers.modal.editResponseTitle') : t('pages:headers.modal.addResponseTitle')}>
        <form onSubmit={submit} className="space-y-3">
          <div className="grid grid-cols-2 gap-3">
            <div><label className="label">{t('pages:headers.modal.listenersNoneAll')}</label><div className="input h-auto max-h-32 overflow-y-auto p-2 space-y-1 text-sm text-slate-300">{listenerList.map((l: any) => (<label key={l.id} className="flex items-center gap-2"><input type="checkbox" className="rounded border-slate-600 bg-slate-800 text-primary" checked={form.listener_ids.includes(l.id)} onChange={(e: any) => setForm({ ...form, listener_ids: e.target.checked ? [...form.listener_ids, l.id] : form.listener_ids.filter((id: number) => id !== l.id) })} /> {l.name}</label>))}</div></div>
            <div><label className="label">{t('pages:headers.modal.action')}</label><select className="input" value={form.action} onChange={e => setForm({ ...form, action: e.target.value })}><option value="override">{t('pages:headers.actionOverride')}</option><option value="add">{t('pages:headers.actionAdd')}</option><option value="del">{t('pages:headers.actionDelete')}</option></select></div>
          </div>
          <div className="grid grid-cols-2 gap-3"><div><label className="label">{t('pages:headers.modal.header')}</label><input className="input" value={form.header} onChange={e => setForm({ ...form, header: e.target.value })} /></div><div><label className="label">{t('pages:headers.modal.value')}</label><input className="input" value={form.value} onChange={e => setForm({ ...form, value: e.target.value })} /></div></div>
          <div><label className="label">{t('pages:headers.modal.conditionOptional')}</label><input className="input" value={form.condition} onChange={e => setForm({ ...form, condition: e.target.value })} /></div>
          <button className="btn-primary w-full">{t('pages:headers.modal.save')}</button>
        </form>
      </Modal>
      <Modal open={ropen} onClose={() => setRopen(false)} title={rEditing ? t('pages:headers.modal.editRequestTitle') : t('pages:headers.modal.addRequestTitle')}>
        <form onSubmit={rsubmit} className="space-y-3">
          <div className="grid grid-cols-2 gap-3">
            <div><label className="label">{t('pages:headers.modal.backendsNoneAll')}</label><div className="input h-auto max-h-32 overflow-y-auto p-2 space-y-1 text-sm text-slate-300">{backendList.map((b: any) => (<label key={b.id} className="flex items-center gap-2"><input type="checkbox" className="rounded border-slate-600 bg-slate-800 text-primary" checked={rform.backend_ids.includes(b.id)} onChange={(e: any) => setRform({ ...rform, backend_ids: e.target.checked ? [...rform.backend_ids, b.id] : rform.backend_ids.filter((id: number) => id !== b.id) })} /> {b.name}</label>))}</div></div>
            <div><label className="label">{t('pages:headers.modal.action')}</label><select className="input" value={rform.action} onChange={e => setRform({ ...rform, action: e.target.value })}><option value="override">{t('pages:headers.actionOverride')}</option><option value="add">{t('pages:headers.actionAdd')}</option><option value="del">{t('pages:headers.actionDelete')}</option></select></div>
          </div>
          <div className="grid grid-cols-2 gap-3"><div><label className="label">{t('pages:headers.modal.header')}</label><input className="input" value={rform.header} onChange={e => setRform({ ...rform, header: e.target.value })} /></div><div><label className="label">{t('pages:headers.modal.value')}</label><input className="input" value={rform.value} onChange={e => setRform({ ...rform, value: e.target.value })} /></div></div>
          <div><label className="label">{t('pages:headers.modal.conditionOptional')}</label><input className="input" value={rform.condition} onChange={e => setRform({ ...rform, condition: e.target.value })} /></div>
          <button className="btn-primary w-full">{t('pages:headers.modal.save')}</button>
        </form>
      </Modal>
    </div>
  )
}
