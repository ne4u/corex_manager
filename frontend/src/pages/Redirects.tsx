import React, { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { ArrowLeftRight, Pencil, GripVertical, Trash2 } from 'lucide-react'
import { redirects, rewrites, listeners, errorPages } from '../services/api'
import useApiList from '../hooks/useApiList'
import Modal from '../components/Modal'
import { IconButton } from '../components/ui'
import LabelWithTooltip from '../components/LabelWithTooltip'
import InfoTooltip from '../components/InfoTooltip'

export default function Redirects() {
  const { t } = useTranslation(['pages', 'common'])

  const redirectTooltips: Record<string, string> = {
    name: t('pages:redirects.tooltips.name'),
    listeners: t('pages:redirects.tooltips.listeners'),
    source: t('pages:redirects.tooltips.source'),
    customResponsePage: t('pages:redirects.tooltips.customResponsePage'),
    target: t('pages:redirects.tooltips.target'),
    code: t('pages:redirects.tooltips.code'),
    responsePageQueryString: t('pages:redirects.tooltips.responsePageQueryString'),
    type: t('pages:redirects.tooltips.type'),
    preserveQuery: t('pages:redirects.tooltips.preserveQuery'),
  }

  const rewriteTooltips: Record<string, string> = {
    name: t('pages:redirects.tooltips.rewriteName'),
    listeners: t('pages:redirects.tooltips.rewriteListeners'),
    hostMatch: t('pages:redirects.tooltips.hostMatch'),
    regex: t('pages:redirects.tooltips.regex'),
    target: t('pages:redirects.tooltips.rewriteTarget'),
    type: t('pages:redirects.tooltips.rewriteType'),
  }
  const { items: reds, reload: rr } = useApiList(redirects.list)
  const { items: rews, reload: rw } = useApiList(rewrites.list)
  const { items: listenerList } = useApiList(listeners.list)
  const { items: errorPageList } = useApiList(errorPages.list)
  const [open, setOpen] = useState(false)
  const [editing, setEditing] = useState<number | null>(null)
  const initialForm = { name: '', listener_ids: [] as number[], source: '', target: '', type: 'permanent', code: 301, preserve_query: true, error_page_id: null as number | null, error_page_query: '' }
  const [form, setForm] = useState<any>(initialForm)

  const [wopen, setWopen] = useState(false)
  const [wEditing, setWEditing] = useState<number | null>(null)
  const initialWform = { name: '', listener_ids: [] as number[], host_match: '', source_regex: '', target: '', type: 'path' }
  const [wform, setWform] = useState<any>(initialWform)

  const openAdd = () => { setEditing(null); setForm(initialForm); setOpen(true) }
  const openEdit = (r: any) => { setEditing(r.id); setForm({ ...r, listener_ids: r.listener_ids || (r.listener_id ? [r.listener_id] : []), error_page_id: r.error_page_id || null, error_page_query: r.error_page_query || '' }); setOpen(true) }

  const openWAdd = () => { setWEditing(null); setWform(initialWform); setWopen(true) }
  const openWEdit = (r: any) => { setWEditing(r.id); setWform({ ...r, listener_ids: r.listener_ids || (r.listener_id ? [r.listener_id] : []), host_match: r.host_match || '' }); setWopen(true) }

  const submit = async (e: React.FormEvent) => {
    e.preventDefault()
    const payload = { ...form, target: form.error_page_id ? '' : form.target, code: form.error_page_id ? (errorPageList.find((ep: any) => ep.id === form.error_page_id)?.code || 403) : form.code, priority: editing ? form.priority : reds.length }
    if (editing) await redirects.update(editing, payload)
    else await redirects.create(payload)
    setEditing(null)
    setForm(initialForm)
    setOpen(false)
    rr()
  }
  const wsubmit = async (e: React.FormEvent) => { e.preventDefault(); const payload = { ...wform, priority: wEditing ? wform.priority : rews.length }; if (wEditing) await rewrites.update(wEditing, payload); else await rewrites.create(payload); setWEditing(null); setWform(initialWform); setWopen(false); rw() }

  const handleDrop = async (type: 'redirect' | 'rewrite', fromId: number, toId: number) => {
    const list = type === 'redirect' ? [...reds] : [...rews]
    const fromIndex = list.findIndex((x: any) => x.id === fromId)
    const toIndex = list.findIndex((x: any) => x.id === toId)
    if (fromIndex === -1 || toIndex === -1 || fromIndex === toIndex) return
    const [moved] = list.splice(fromIndex, 1)
    list.splice(toIndex, 0, moved)
    const api = type === 'redirect' ? redirects : rewrites
    const reload = type === 'redirect' ? rr : rw
    await Promise.all(list.map((r: any, i: number) => api.update(r.id, { priority: i })))
    reload()
  }

  const renderRedirectTarget = (r: any) => {
    if (r.error_page_id) {
      const ep = errorPageList.find((p: any) => p.id === r.error_page_id)
      return (
        <span className="text-amber-400" title={t('pages:redirects.responsePageLabel', { code: ep?.code })}>
          {t('pages:redirects.responsePageLabel', { code: ep ? ep.code : r.error_page_id })}
          {r.error_page_query ? <span className="text-slate-500 text-xs ms-1">?{r.error_page_query}</span> : null}
        </span>
      )
    }
    return r.target
  }

  const renderRedirectCode = (r: any) => {
    if (r.error_page_id) {
      const ep = errorPageList.find((p: any) => p.id === r.error_page_id)
      return ep ? ep.code : r.code
    }
    return r.code
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between"><h2 className="text-2xl font-bold flex items-center gap-2"><ArrowLeftRight className="h-5 w-5 text-primary" /> {t('pages:redirects.redirects')}</h2><button onClick={openAdd} className="btn-primary">{t('pages:redirects.addRedirect')}</button></div>
      <div className="card overflow-x-auto">
        <table className="w-full text-sm text-start"><thead className="text-slate-400 border-b border-slate-800"><tr><th className="w-6"></th><th>{t('pages:redirects.tableHeaders.name')}</th><th>{t('pages:redirects.tableHeaders.listener')}</th><th>{t('pages:redirects.tableHeaders.source')}</th><th>{t('pages:redirects.tableHeaders.target')}</th><th>{t('pages:redirects.tableHeaders.type')}</th><th>{t('pages:redirects.tableHeaders.code')}</th><th></th></tr></thead>
          <tbody>{reds.map((r: any) => (<tr key={r.id} draggable onDragStart={(e: any) => { e.dataTransfer.setData('redirect', String(r.id)); e.dataTransfer.effectAllowed = 'move' }} onDragOver={(e: any) => e.preventDefault()} onDrop={(e: any) => { e.preventDefault(); const fromId = Number(e.dataTransfer.getData('redirect')); if (fromId && fromId !== r.id) handleDrop('redirect', fromId, r.id) }} className="border-b border-slate-800 last:border-0"><td className="py-2 pe-2 cursor-grab"><GripVertical className="h-4 w-4 text-slate-500" /></td><td className="py-2">{r.name}</td><td>{r.listener_ids?.length ? r.listener_ids.map((id: number) => listenerList.find((l: any) => l.id === id)?.name).filter(Boolean).join(', ') : (r.listener_id ? listenerList.find((l: any) => l.id === r.listener_id)?.name : t('pages:redirects.all'))}</td><td>{r.source}</td><td>{renderRedirectTarget(r)}</td><td>{r.type}</td><td>{renderRedirectCode(r)}</td>
            <td>
              <div className="flex gap-1">
                <IconButton icon={Pencil} aria-label={t('common:actions.edit')} onClick={() => openEdit(r)} />
                <IconButton icon={Trash2} variant="danger" aria-label={t('common:actions.delete')} onClick={() => redirects.remove(r.id).then(rr)} />
              </div>
            </td></tr>))}</tbody>
        </table>
      </div>
      <div className="flex items-center justify-between"><h2 className="text-2xl font-bold flex items-center gap-2"><Pencil className="h-5 w-5 text-primary" /> {t('pages:redirects.rewrites')}</h2><button onClick={openWAdd} className="btn-primary">{t('pages:redirects.addRewrite')}</button></div>
      <div className="card overflow-x-auto">
        <table className="w-full text-sm text-start"><thead className="text-slate-400 border-b border-slate-800"><tr><th className="w-6"></th><th>{t('pages:redirects.tableHeaders.name')}</th><th>{t('pages:redirects.tableHeaders.listener')}</th><th>{t('pages:redirects.tableHeaders.host')}</th><th>{t('pages:redirects.tableHeaders.regex')}</th><th>{t('pages:redirects.tableHeaders.target')}</th><th>{t('pages:redirects.tableHeaders.type')}</th><th></th></tr></thead>
          <tbody>{rews.map((r: any) => (<tr key={r.id} draggable onDragStart={(e: any) => { e.dataTransfer.setData('rewrite', String(r.id)); e.dataTransfer.effectAllowed = 'move' }} onDragOver={(e: any) => e.preventDefault()} onDrop={(e: any) => { e.preventDefault(); const fromId = Number(e.dataTransfer.getData('rewrite')); if (fromId && fromId !== r.id) handleDrop('rewrite', fromId, r.id) }} className="border-b border-slate-800 last:border-0"><td className="py-2 pe-2 cursor-grab"><GripVertical className="h-4 w-4 text-slate-500" /></td><td className="py-2">{r.name}</td><td>{r.listener_ids?.length ? r.listener_ids.map((id: number) => listenerList.find((l: any) => l.id === id)?.name).filter(Boolean).join(', ') : (r.listener_id ? listenerList.find((l: any) => l.id === r.listener_id)?.name : t('pages:redirects.all'))}</td><td>{r.host_match || '-'}</td><td>{r.source_regex}</td><td>{r.target}</td><td>{r.type}</td>
            <td>
              <div className="flex gap-1">
                <IconButton icon={Pencil} aria-label={t('common:actions.edit')} onClick={() => openWEdit(r)} />
                <IconButton icon={Trash2} variant="danger" aria-label={t('common:actions.delete')} onClick={() => rewrites.remove(r.id).then(rw)} />
              </div>
            </td></tr>))}</tbody>
        </table>
      </div>
      <Modal open={open} onClose={() => setOpen(false)} title={editing ? t('pages:redirects.modal.editRedirectTitle') : t('pages:redirects.modal.addRedirectTitle')}>
        <form onSubmit={submit} className="space-y-3">
          <div className="grid grid-cols-2 gap-3">
            <div><LabelWithTooltip tooltip={redirectTooltips.name} className="label">{t('pages:redirects.modal.name')}</LabelWithTooltip><input className="input" value={form.name} onChange={e => setForm({ ...form, name: e.target.value })} /></div>
            <div><LabelWithTooltip tooltip={redirectTooltips.listeners} className="label">{t('pages:redirects.modal.listenersNoneAll')}</LabelWithTooltip><div className="input h-auto max-h-32 overflow-y-auto p-2 space-y-1 text-sm text-slate-300">{listenerList.map((l: any) => (<label key={l.id} className="flex items-center gap-2"><input type="checkbox" className="rounded border-slate-600 bg-slate-800 text-primary" checked={form.listener_ids.includes(l.id)} onChange={(e: any) => setForm({ ...form, listener_ids: e.target.checked ? [...form.listener_ids, l.id] : form.listener_ids.filter((id: number) => id !== l.id) })} /> {l.name}</label>))}</div></div>
            <div><LabelWithTooltip tooltip={redirectTooltips.source} className="label">{t('pages:redirects.modal.source')}</LabelWithTooltip><input className="input" value={form.source} onChange={e => setForm({ ...form, source: e.target.value })} /></div>
            <div>
              <LabelWithTooltip tooltip={redirectTooltips.customResponsePage} className="label">{t('pages:redirects.modal.customResponsePage')}</LabelWithTooltip>
              <select
                className="input"
                value={form.error_page_id || ''}
                onChange={e => setForm({ ...form, error_page_id: e.target.value ? Number(e.target.value) : null, target: e.target.value ? '' : form.target })}
              >
                <option value="">{t('pages:redirects.modal.urlRedirect')}</option>
                {errorPageList.map((ep: any) => (<option key={ep.id} value={ep.id}>HTTP {ep.code} — {ep.content_type}</option>))}
              </select>
            </div>
            {!form.error_page_id && (
              <>
                <div><LabelWithTooltip tooltip={redirectTooltips.target} className="label">{t('pages:redirects.modal.target')}</LabelWithTooltip><input className="input" value={form.target} onChange={e => setForm({ ...form, target: e.target.value })} /></div>
                <div><LabelWithTooltip tooltip={redirectTooltips.code} className="label">{t('pages:redirects.modal.code')}</LabelWithTooltip><input type="number" className="input" value={form.code} onChange={e => setForm({ ...form, code: Number(e.target.value) })} /></div>
              </>
            )}
            {form.error_page_id && (
              <div className="col-span-2 space-y-3">
                <div>
                  <LabelWithTooltip tooltip={redirectTooltips.responsePageQueryString} className="label">{t('pages:redirects.modal.responsePageQueryString')}</LabelWithTooltip>
                  <input
                    className="input"
                    placeholder={t('pages:redirects.modal.responsePageQueryPlaceholder')}
                    value={form.error_page_query}
                    onChange={e => setForm({ ...form, error_page_query: e.target.value })}
                  />
                  <p className="text-xs text-slate-500 mt-1">
                    {t('pages:redirects.modal.responsePageQueryHelp')}
                  </p>
                </div>
                <p className="p-2 rounded bg-slate-800/50 text-sm text-slate-400">
                  {t('pages:redirects.modal.responsePageNote')}
                </p>
              </div>
            )}
          </div>
          <div className="grid grid-cols-2 gap-3"><div><LabelWithTooltip tooltip={redirectTooltips.type} className="label">{t('pages:redirects.modal.type')}</LabelWithTooltip><select className="input" value={form.type} onChange={e => setForm({ ...form, type: e.target.value })}><option value="permanent">{t('pages:redirects.modal.typePermanent')}</option><option value="temporary">{t('pages:redirects.modal.typeTemporary')}</option><option value="regex">{t('pages:redirects.modal.typeRegex')}</option></select></div>{!form.error_page_id && <label className="flex items-center gap-2 mt-6"><input type="checkbox" checked={form.preserve_query} onChange={e => setForm({ ...form, preserve_query: e.target.checked })} /><span>{t('pages:redirects.modal.preserveQuery')}</span><InfoTooltip content={redirectTooltips.preserveQuery} /></label>}</div>
          <button className="btn-primary w-full">{t('pages:redirects.modal.save')}</button>
        </form>
      </Modal>
      <Modal open={wopen} onClose={() => setWopen(false)} title={wEditing ? t('pages:redirects.modal.editRewriteTitle') : t('pages:redirects.modal.addRewriteTitle')}>
        <form onSubmit={wsubmit} className="space-y-3">
          <div className="grid grid-cols-2 gap-3">
            <div><LabelWithTooltip tooltip={rewriteTooltips.name} className="label">{t('pages:redirects.modal.name')}</LabelWithTooltip><input className="input" value={wform.name} onChange={e => setWform({ ...wform, name: e.target.value })} /></div>
            <div><LabelWithTooltip tooltip={rewriteTooltips.listeners} className="label">{t('pages:redirects.modal.listenersNoneAll')}</LabelWithTooltip><div className="input h-auto max-h-32 overflow-y-auto p-2 space-y-1 text-sm text-slate-300">{listenerList.map((l: any) => (<label key={l.id} className="flex items-center gap-2"><input type="checkbox" className="rounded border-slate-600 bg-slate-800 text-primary" checked={wform.listener_ids.includes(l.id)} onChange={(e: any) => setWform({ ...wform, listener_ids: e.target.checked ? [...wform.listener_ids, l.id] : wform.listener_ids.filter((id: number) => id !== l.id) })} /> {l.name}</label>))}</div></div>
            <div><LabelWithTooltip tooltip={rewriteTooltips.hostMatch} className="label">{t('pages:redirects.modal.hostMatch')}</LabelWithTooltip><input className="input" placeholder={t('pages:redirects.modal.hostMatchPlaceholder')} value={wform.host_match} onChange={e => setWform({ ...wform, host_match: e.target.value })} /></div>
            <div><LabelWithTooltip tooltip={rewriteTooltips.regex} className="label">{t('pages:redirects.modal.regex')}</LabelWithTooltip><input className="input" value={wform.source_regex} onChange={e => setWform({ ...wform, source_regex: e.target.value })} /></div>
            <div><LabelWithTooltip tooltip={rewriteTooltips.target} className="label">{t('pages:redirects.modal.target')}</LabelWithTooltip><input className="input" value={wform.target} onChange={e => setWform({ ...wform, target: e.target.value })} /></div>
            <div><LabelWithTooltip tooltip={rewriteTooltips.type} className="label">{t('pages:redirects.modal.type')}</LabelWithTooltip><select className="input" value={wform.type} onChange={e => setWform({ ...wform, type: e.target.value })}><option value="path">{t('pages:redirects.modal.typePath')}</option><option value="query">{t('pages:redirects.modal.typeQuery')}</option><option value="both">{t('pages:redirects.modal.typeBoth')}</option></select></div>
          </div>
          <button className="btn-primary w-full">{t('pages:redirects.modal.save')}</button>
        </form>
      </Modal>
    </div>
  )
}
