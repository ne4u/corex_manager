import React, { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Pencil, Trash2 } from 'lucide-react'
import { ciphers } from '../services/api'
import useApiList from '../hooks/useApiList'
import Modal from '../components/Modal'
import { IconButton } from '../components/ui'

const CIPHER_BASELINES: Record<string, string> = {
  modern: 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:DHE-RSA-CHACHA20-POLY1305',
  fips: 'ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256',
  fedramp: 'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256',
  pci: 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:AES128-GCM-SHA256:AES256-GCM-SHA384',
  custom: '',
}

const defaultCiphers = (baseline: string) => CIPHER_BASELINES[baseline] || ''

export default function Ciphers() {
  const { t } = useTranslation(['pages', 'common'])
  const { items, reload, loading } = useApiList(ciphers.list)
  const [open, setOpen] = useState(false)
  const [editing, setEditing] = useState<number | null>(null)
  const initialForm = { name: '', baseline: 'modern', ciphers: defaultCiphers('modern'), tls_options: 'no-sslv3 no-tlsv10 no-tlsv11', min_tls_version: 'TLSv1.2', quantum_safe: false, hsts_enabled: true, hsts_max_age: 31536000, hsts_include_subdomains: true, hsts_preload: false }
  const [form, setForm] = useState<any>(initialForm)

  const openAdd = () => { setEditing(null); setForm(initialForm); setOpen(true) }
  const openEdit = (c: any) => { setEditing(c.id); setForm({ ...c }); setOpen(true) }

  const submit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (editing) await ciphers.update(editing, form)
    else await ciphers.create(form)
    setForm(initialForm)
    setEditing(null)
    setOpen(false)
    reload()
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-end">
        <button onClick={openAdd} className="btn-primary">{t('pages:ciphers.addCipherSuite')}</button>
      </div>
      {loading ? <p>{t('pages:ciphers.loading')}</p> : (
        <div className="card overflow-x-auto">
          <table className="w-full text-sm text-start"><thead className="text-slate-400 border-b border-slate-800"><tr><th>{t('pages:ciphers.tableHeaders.name')}</th><th>{t('pages:ciphers.tableHeaders.baseline')}</th><th>{t('pages:ciphers.tableHeaders.minTls')}</th><th>{t('pages:ciphers.tableHeaders.quantumSafe')}</th><th>{t('pages:ciphers.tableHeaders.hsts')}</th><th></th></tr></thead>
            <tbody>
              {items.map((c: any) => (
                <tr key={c.id} className="border-b border-slate-800 last:border-0"><td className="py-2">{c.name}</td><td>{c.baseline}</td><td>{c.min_tls_version}</td><td>{c.quantum_safe ? t('common:actions.yes') : t('common:actions.no')}</td><td>{c.hsts_enabled ? t('common:actions.yes') : t('common:actions.no')}</td>
                  <td className="space-x-1">
                    <IconButton icon={Pencil} aria-label={t('common:actions.edit')} onClick={() => openEdit(c)} />
                    <IconButton icon={Trash2} variant="danger" aria-label={t('common:actions.delete')} onClick={() => ciphers.remove(c.id).then(reload)} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <Modal open={open} onClose={() => setOpen(false)} title={editing ? t('pages:ciphers.modal.editTitle') : t('pages:ciphers.modal.addTitle')}>
        <form onSubmit={submit} className="space-y-3">
          <div className="grid grid-cols-2 gap-3">
            <div><label className="label">{t('pages:ciphers.modal.name')}</label><input className="input" value={form.name} onChange={e => setForm({ ...form, name: e.target.value })} /></div>
            <div><label className="label">{t('pages:ciphers.modal.baseline')}</label><select className="input" value={form.baseline} onChange={e => {
              const baseline = e.target.value
              setForm({ ...form, baseline, ciphers: baseline === 'custom' ? form.ciphers : defaultCiphers(baseline) })
            }}><option value="modern">{t('pages:ciphers.modal.baselineModern')}</option><option value="fips">{t('pages:ciphers.modal.baselineFips')}</option><option value="fedramp">{t('pages:ciphers.modal.baselineFedramp')}</option><option value="pci">{t('pages:ciphers.modal.baselinePci')}</option><option value="custom">{t('pages:ciphers.modal.baselineCustom')}</option></select></div>
            <div><label className="label">{t('pages:ciphers.modal.minTls')}</label><input className="input" value={form.min_tls_version} onChange={e => setForm({ ...form, min_tls_version: e.target.value })} /></div>
            <div><label className="label">{t('pages:ciphers.modal.hstsMaxAge')}</label><input type="number" className="input" value={form.hsts_max_age} onChange={e => setForm({ ...form, hsts_max_age: Number(e.target.value) })} /></div>
          </div>
          <div><label className="label">{t('pages:ciphers.modal.ciphers')}</label><textarea className="input" rows={2} value={form.ciphers} onChange={e => setForm({ ...form, ciphers: e.target.value })} /></div>
          <div className="flex gap-4">
            <label className="flex items-center gap-2"><input type="checkbox" checked={form.quantum_safe} onChange={e => setForm({ ...form, quantum_safe: e.target.checked })} /> {t('pages:ciphers.modal.quantumSafe')}</label>
            <label className="flex items-center gap-2"><input type="checkbox" checked={form.hsts_enabled} onChange={e => setForm({ ...form, hsts_enabled: e.target.checked })} /> {t('pages:ciphers.modal.hsts')}</label>
            <label className="flex items-center gap-2"><input type="checkbox" checked={form.hsts_include_subdomains} onChange={e => setForm({ ...form, hsts_include_subdomains: e.target.checked })} /> {t('pages:ciphers.modal.includeSubdomains')}</label>
            <label className="flex items-center gap-2"><input type="checkbox" checked={form.hsts_preload} onChange={e => setForm({ ...form, hsts_preload: e.target.checked })} /> {t('pages:ciphers.modal.preload')}</label>
          </div>
          <button className="btn-primary w-full">{t('pages:ciphers.modal.save')}</button>
        </form>
      </Modal>
    </div>
  )
}
