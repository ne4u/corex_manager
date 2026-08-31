import React, { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Users as UsersIcon, Pencil, Trash2 } from 'lucide-react'
import { users } from '../services/api'
import useApiList from '../hooks/useApiList'
import Modal from '../components/Modal'
import { IconButton } from '../components/ui'

interface User {
  id: number
  username: string
  role: string
  is_admin: boolean
  email?: string | null
  first_name?: string | null
  last_name?: string | null
  organization?: string | null
}

const ROLES = ['admin', 'operator', 'viewer']
const DEFAULT_ORG = 'coreX Platform'

export default function Users() {
  const { t } = useTranslation(['pages', 'common'])
  const { items, reload, loading } = useApiList<User>(users.list)
  const [open, setOpen] = useState(false)
  const [editing, setEditing] = useState<number | null>(null)
  const [error, setError] = useState('')
  const initialForm = {
    username: '',
    role: 'operator',
    password: '',
    email: '',
    first_name: '',
    last_name: '',
    organization: '',
  }
  const [form, setForm] = useState<Record<string, string>>(initialForm)

  const computeDefaultOrg = (): string => {
    const admins = items
      .filter((u) => u.role === 'admin')
      .sort((a, b) => a.id - b.id)
    const firstAdminOrg = admins[0]?.organization
    return firstAdminOrg?.trim() || DEFAULT_ORG
  }

  const openAdd = () => {
    setEditing(null)
    setForm({ ...initialForm, organization: computeDefaultOrg() })
    setError('')
    setOpen(true)
  }

  const openEdit = (u: User) => {
    setEditing(u.id)
    setForm({
      username: u.username,
      role: u.role,
      password: '',
      email: u.email || '',
      first_name: u.first_name || '',
      last_name: u.last_name || '',
      organization: u.organization || '',
    })
    setError('')
    setOpen(true)
  }

  const submit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError('')
    // Validate required contact fields
    const requiredFields = [
      { key: 'first_name', label: t('pages:users.modal.firstName') },
      { key: 'last_name', label: t('pages:users.modal.lastName') },
      { key: 'email', label: t('pages:users.modal.email') },
      { key: 'organization', label: t('pages:users.modal.organization') },
    ]
    for (const f of requiredFields) {
      if (!form[f.key]?.trim()) {
        setError(t('pages:users.modal.fieldRequired', { field: f.label }))
        return
      }
    }
    try {
      if (editing) {
        const updatePayload: Record<string, unknown> = {
          username: form.username,
          role: form.role,
          email: form.email.trim(),
          first_name: form.first_name.trim(),
          last_name: form.last_name.trim(),
          organization: form.organization.trim(),
        }
        if (form.password) updatePayload.password = form.password
        await users.update(editing, updatePayload)
      } else {
        if (!form.password) {
          setError(t('pages:users.modal.passwordRequired'))
          return
        }
        await users.create({
          username: form.username,
          role: form.role,
          password: form.password,
          email: form.email.trim(),
          first_name: form.first_name.trim(),
          last_name: form.last_name.trim(),
          organization: form.organization.trim(),
        })
      }
      setForm(initialForm)
      setEditing(null)
      setOpen(false)
      reload()
    } catch (err: any) {
      setError(err.response?.data?.detail || t('common:errors.saveFailed'))
    }
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h2 className="text-2xl font-bold flex items-center gap-2"><UsersIcon className="h-5 w-5 text-primary" /> {t('pages:users.title')}</h2>
        <button onClick={openAdd} className="btn-primary">{t('pages:users.addUser')}</button>
      </div>
      {loading ? (
        <p>{t('common:actions.loading')}</p>
      ) : (
        <div className="card overflow-x-auto">
          <table className="w-full text-sm text-start">
            <thead className="text-slate-400 border-b border-slate-800">
              <tr>
                <th>{t('pages:users.tableHeaders.username')}</th>
                <th>{t('pages:users.tableHeaders.role')}</th>
                <th>{t('pages:users.tableHeaders.email')}</th>
                <th>{t('pages:users.tableHeaders.organization')}</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {items.map((u: User) => (
                <tr key={u.id} className="border-b border-slate-800 last:border-0">
                  <td className="py-2">{u.username}</td>
                  <td className="capitalize">{u.role}</td>
                  <td className="text-slate-400">{u.email || '-'}</td>
                  <td className="text-slate-400">{u.organization || '-'}</td>
                  <td className="space-x-1">
                    <IconButton icon={Pencil} aria-label="Edit" onClick={() => openEdit(u)} />
                    <IconButton icon={Trash2} variant="danger" aria-label="Delete" onClick={() => users.remove(u.id).then(reload)} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <Modal open={open} onClose={() => setOpen(false)} title={editing ? t('pages:users.modal.editTitle') : t('pages:users.modal.addTitle')}>
        <form onSubmit={submit} className="space-y-3">
          {error && <p className="text-red-400 text-sm">{error}</p>}
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="label">{t('pages:users.modal.username')}</label>
              <input className="input" value={form.username} onChange={e => setForm({ ...form, username: e.target.value })} />
            </div>
            <div>
              <label className="label">{t('pages:users.modal.role')}</label>
              <select className="input" value={form.role} onChange={e => setForm({ ...form, role: e.target.value })}>
                {ROLES.map(r => <option key={r} value={r}>{r}</option>)}
              </select>
            </div>
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="label">{t('pages:users.modal.firstName')} <span className="text-red-400">*</span></label>
              <input className="input" value={form.first_name} onChange={e => setForm({ ...form, first_name: e.target.value })} required />
            </div>
            <div>
              <label className="label">{t('pages:users.modal.lastName')} <span className="text-red-400">*</span></label>
              <input className="input" value={form.last_name} onChange={e => setForm({ ...form, last_name: e.target.value })} required />
            </div>
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="label">{t('pages:users.modal.email')} <span className="text-red-400">*</span></label>
              <input type="email" className="input" value={form.email} onChange={e => setForm({ ...form, email: e.target.value })} required />
            </div>
            <div>
              <label className="label">{t('pages:users.modal.organization')} <span className="text-red-400">*</span></label>
              <input className="input" value={form.organization} onChange={e => setForm({ ...form, organization: e.target.value })} required />
            </div>
          </div>
          <div>
            <label className="label">{editing ? t('pages:users.modal.newPassword') : t('pages:users.modal.password')}</label>
            <input type="password" className="input" value={form.password} onChange={e => setForm({ ...form, password: e.target.value })} />
          </div>
          <button className="btn-primary w-full">{t('common:actions.save')}</button>
        </form>
      </Modal>
    </div>
  )
}
