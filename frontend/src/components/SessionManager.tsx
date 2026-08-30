import { useCallback, useEffect, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { auth } from '../services/api'
import Modal from './Modal'

interface SessionSettings {
  timeout_minutes: number
  warning_seconds: number
}

interface JwtPayload {
  exp?: number
  sub?: string
  role?: string
}

function decodeJwt(token: string): JwtPayload | null {
  try {
    const parts = token.split('.')
    if (parts.length !== 3) return null
    const base64 = parts[1].replace(/-/g, '+').replace(/_/g, '/')
    const json = window.atob(base64)
    return JSON.parse(json) as JwtPayload
  } catch {
    return null
  }
}

function formatDuration(seconds: number): string {
  if (seconds <= 0) return '0s'
  const m = Math.floor(seconds / 60)
  const s = Math.floor(seconds % 60)
  if (m > 0) return `${m}m ${s}s`
  return `${s}s`
}

export default function SessionManager({ onLogout }: { onLogout: () => void }) {
  const { t } = useTranslation('auth')
  const [settings, setSettings] = useState<SessionSettings | null>(null)
  const [settingsLoaded, setSettingsLoaded] = useState(false)
  const [remaining, setRemaining] = useState<number | null>(null)
  const [warningOpen, setWarningOpen] = useState(false)
  const [refreshing, setRefreshing] = useState(false)
  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null)
  const refreshInFlightRef = useRef(false)
  const lastActivityRef = useRef<number>(0)

  const refresh = useCallback(async () => {
    if (refreshInFlightRef.current) return
    refreshInFlightRef.current = true
    setRefreshing(true)
    try {
      const res = await auth.refresh()
      const newToken = res.data.access_token
      localStorage.setItem('token', newToken)
      window.dispatchEvent(new StorageEvent('storage'))
      setWarningOpen(false)
    } catch {
      onLogout()
    } finally {
      refreshInFlightRef.current = false
      setRefreshing(false)
    }
  }, [onLogout])

  useEffect(() => {
    const load = () => {
      auth.session()
        .then((res) => {
          setSettings({
            timeout_minutes: res.data.timeout_minutes ?? 30,
            warning_seconds: res.data.warning_seconds ?? 60,
          })
        })
        .catch(() => {
          setSettings({ timeout_minutes: 30, warning_seconds: 60 })
        })
        .finally(() => setSettingsLoaded(true))
    }

    load()
    const onUpdate = () => load()
    window.addEventListener('session-settings-updated', onUpdate)
    return () => window.removeEventListener('session-settings-updated', onUpdate)
  }, [])

  useEffect(() => {
    if (!settings) return

    const check = () => {
      const token = localStorage.getItem('token')
      if (!token) {
        onLogout()
        return
      }
      const payload = decodeJwt(token)
      if (!payload?.exp) {
        onLogout()
        return
      }
      const now = Date.now() / 1000
      const left = payload.exp - now
      setRemaining(Math.max(0, left))

      if (left <= 0) {
        onLogout()
      } else if (left <= settings.warning_seconds) {
        setWarningOpen(true)
      }
    }

    check()
    intervalRef.current = setInterval(check, 1000)
    return () => {
      if (intervalRef.current) clearInterval(intervalRef.current)
    }
  }, [settings, onLogout])

  useEffect(() => {
    if (!settings) return

    const handleActivity = () => {
      const now = Date.now()
      if (now - lastActivityRef.current < 1000) return
      lastActivityRef.current = now

      const token = localStorage.getItem('token')
      if (!token) return
      const payload = decodeJwt(token)
      if (!payload?.exp) return
      const left = payload.exp - now / 1000
      // Refresh when the token is within the warning window (plus a buffer).
      if (left <= Math.max(settings.warning_seconds + 10, 60)) {
        refresh()
      }
      setWarningOpen(false)
    }

    const events = ['mousedown', 'keydown', 'touchstart', 'scroll']
    events.forEach((e) => window.addEventListener(e, handleActivity))
    return () => {
      events.forEach((e) => window.removeEventListener(e, handleActivity))
    }
  }, [settings, refresh])

  if (!settingsLoaded) return null

  return (
    <Modal open={warningOpen} onClose={() => {}} title={t('session.timeoutTitle')} showClose={false}>
      <div className="space-y-4">
        <p className="text-slate-300">
          {t('session.expiringMessage')}
        </p>
        {remaining !== null && (
          <div className="text-center text-3xl font-bold text-amber-400">
            {formatDuration(Math.ceil(remaining))}
          </div>
        )}
        <p className="text-sm text-slate-500">
          {t('session.extendHint')}
        </p>
        <button
          className="btn-primary w-full"
          onClick={refresh}
          disabled={refreshing}
        >
          {refreshing ? t('session.extending') : t('session.ok')}
        </button>
      </div>
    </Modal>
  )
}
