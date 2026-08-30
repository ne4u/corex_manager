import { useState } from 'react'
import { Eye, EyeOff } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import { login } from '../services/api'
import { Logo } from '../components/Logo'

export default function Login({ onLogin }: { onLogin: (t: string) => void }) {
  const { t } = useTranslation('auth')
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [totpCode, setTotpCode] = useState('')
  const [showPassword, setShowPassword] = useState(false)
  const [error, setError] = useState('')

  const submit = async (e: React.FormEvent) => {
    e.preventDefault()
    try {
      const res = await login(username, password, totpCode || undefined)
      onLogin(res.data.access_token)
    } catch (err: any) {
      setError(err.response?.data?.detail || t('login.loginFailed'))
    }
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-slate-950 p-4">
      <form onSubmit={submit} className="card w-full max-w-md">
        <div className="flex justify-center mb-4">
          <Logo className="h-[225px] w-auto" />
        </div>
        <p className="text-slate-400 text-sm mb-6 text-center">{t('login.subtitle')}</p>
        {error && <div className="mb-4 p-3 rounded bg-red-500/10 text-red-400 text-sm">{error}</div>}
        <div className="mb-4">
          <label className="label">{t('login.username')}</label>
          <input className="input" value={username} onChange={(e) => setUsername(e.target.value)} />
        </div>
        <div className="mb-4">
          <label className="label">{t('login.password')}</label>
          <div className="relative">
            <input
              type={showPassword ? 'text' : 'password'}
              className="input w-full pe-10 rtl:pe-3 rtl:ps-10"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
            />
            <button
              type="button"
              onClick={() => setShowPassword((s) => !s)}
              className="absolute inset-y-0 end-0 rtl:right-auto rtl:start-0 px-3 text-slate-400 hover:text-slate-200 focus:outline-none"
              aria-label={showPassword ? t('login.hidePassword') : t('login.showPassword')}
            >
              {showPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
            </button>
          </div>
        </div>
        <div className="mb-6">
          <label className="label">{t('login.totpCode')} <span className="text-slate-500">{t('login.totpHint')}</span></label>
          <input
            className="input"
            value={totpCode}
            onChange={(e) => setTotpCode(e.target.value)}
            placeholder={t('login.totpPlaceholder')}
          />
        </div>
        <button type="submit" className="btn-primary w-full">{t('login.signIn')}</button>
      </form>
    </div>
  )
}
