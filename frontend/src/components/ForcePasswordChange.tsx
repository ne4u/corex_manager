import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Eye, EyeOff, Check, X } from 'lucide-react'
import Modal from './Modal'
import { auth } from '../services/api'

export interface PasswordPolicy {
  min_length: number
  require_uppercase: boolean
  require_lowercase: boolean
  require_digit: boolean
  require_symbol: boolean
  rotation_months: number
}

interface Props {
  open: boolean
  policy: PasswordPolicy | null
  onSuccess: () => void
}

function meetsPolicy(password: string, policy: PasswordPolicy | null): boolean {
  if (!policy) return password.length >= 8
  if (password.length < policy.min_length) return false
  if (policy.require_uppercase && !/[A-Z]/.test(password)) return false
  if (policy.require_lowercase && !/[a-z]/.test(password)) return false
  if (policy.require_digit && !/\d/.test(password)) return false
  if (policy.require_symbol && !/[^A-Za-z0-9]/.test(password)) return false
  return true
}

export default function ForcePasswordChange({ open, policy, onSuccess }: Props) {
  const { t } = useTranslation('auth')
  const [current, setCurrent] = useState('')
  const [next, setNext] = useState('')
  const [confirm, setConfirm] = useState('')
  const [showCurrent, setShowCurrent] = useState(false)
  const [showNew, setShowNew] = useState(false)
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

  const reset = () => {
    setCurrent('')
    setNext('')
    setConfirm('')
    setError('')
  }

  const submit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError('')
    if (!next) {
      setError(t('forceChange.failed'))
      return
    }
    if (next !== confirm) {
      setError(t('forceChange.mismatch'))
      return
    }
    if (!meetsPolicy(next, policy)) {
      setError(t('forceChange.failed'))
      return
    }
    setBusy(true)
    try {
      await auth.changePassword(current, next)
      // Refresh the token so the new JWT no longer carries pwd_exp=true.
      await auth.refresh()
      reset()
      onSuccess()
    } catch (err: any) {
      setError(err.response?.data?.detail || t('forceChange.failed'))
    } finally {
      setBusy(false)
    }
  }

  const reqs: { key: string; met: boolean }[] = [
    { key: t('forceChange.reqMinLength', { n: policy?.min_length ?? 8 }), met: next.length >= (policy?.min_length ?? 8) },
    { key: t('forceChange.reqUppercase'), met: !policy?.require_uppercase || /[A-Z]/.test(next) },
    { key: t('forceChange.reqLowercase'), met: !policy?.require_lowercase || /[a-z]/.test(next) },
    { key: t('forceChange.reqDigit'), met: !policy?.require_digit || /\d/.test(next) },
    { key: t('forceChange.reqSymbol'), met: !policy?.require_symbol || /[^A-Za-z0-9]/.test(next) },
  ]

  return (
    <Modal open={open} onClose={() => {}} title={t('forceChange.title')} showClose={false} size="md">
      <form onSubmit={submit} className="space-y-4">
        <p className="text-sm text-amber-300 bg-amber-500/10 border border-amber-500/20 rounded-lg p-3">
          {t('forceChange.message')}
        </p>
        {error && <p className="text-red-400 text-sm">{error}</p>}
        <div>
          <label className="label">{t('forceChange.currentPassword')}</label>
          <div className="relative">
            <input
              type={showCurrent ? 'text' : 'password'}
              className="input w-full pe-10"
              value={current}
              onChange={(e) => setCurrent(e.target.value)}
              required
              autoFocus
            />
            <button
              type="button"
              onClick={() => setShowCurrent((s) => !s)}
              className="absolute inset-y-0 end-0 px-3 text-slate-400 hover:text-slate-200"
              aria-label="toggle"
            >
              {showCurrent ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
            </button>
          </div>
        </div>
        <div>
          <label className="label">{t('forceChange.newPassword')}</label>
          <div className="relative">
            <input
              type={showNew ? 'text' : 'password'}
              className="input w-full pe-10"
              value={next}
              onChange={(e) => setNext(e.target.value)}
              required
            />
            <button
              type="button"
              onClick={() => setShowNew((s) => !s)}
              className="absolute inset-y-0 end-0 px-3 text-slate-400 hover:text-slate-200"
              aria-label="toggle"
            >
              {showNew ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
            </button>
          </div>
        </div>
        <div>
          <label className="label">{t('forceChange.confirmPassword')}</label>
          <input
            type="password"
            className="input w-full"
            value={confirm}
            onChange={(e) => setConfirm(e.target.value)}
            required
          />
        </div>
        {policy && (
          <div className="border-t border-slate-800 pt-3">
            <p className="text-xs text-slate-500 mb-2">{t('forceChange.requirements')}</p>
            <ul className="space-y-1">
              {reqs.map((r, i) => (
                <li key={i} className="flex items-center gap-2 text-xs">
                  {r.met ? (
                    <Check className="h-3.5 w-3.5 text-green-400" />
                  ) : (
                    <X className="h-3.5 w-3.5 text-slate-500" />
                  )}
                  <span className={r.met ? 'text-slate-300' : 'text-slate-500'}>{r.key}</span>
                </li>
              ))}
            </ul>
          </div>
        )}
        <button type="submit" className="btn-primary w-full" disabled={busy}>
          {busy ? t('forceChange.changing') : t('forceChange.submit')}
        </button>
      </form>
    </Modal>
  )
}
