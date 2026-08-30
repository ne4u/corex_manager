import { useEffect, useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import {
  UserCircle, X, Palette, Shield, Globe, LogOut, Plus, Pencil, Trash2, Clock,
} from 'lucide-react'
import { auth, totp } from '../services/api'
import { IconButton, Tabs, Badge } from './ui'
import { CustomThemeEditor } from './CustomThemeEditor'
import { useTheme } from '../themes/useTheme'
import { useLanguage } from '../contexts/LanguageContext'
import { useDateTime } from '../contexts/DateTimeContext'
import { themes as builtinThemes, Theme, cloneTheme } from '../themes/themeDefinitions'
import {
  DATE_FORMAT_PRESETS,
  TIME_FORMAT_PRESETS,
  getAvailableTimezones,
  isValidFormatString,
  isValidTimezone,
  systemTimezone,
} from '../lib/dateTime'

interface UserInfo {
  id: number
  username: string
  role: string
  is_admin: boolean
  totp_enabled: boolean
  created_at: string
}

function formatError(err: any, fallback: string): string {
  const detail = err?.response?.data?.detail
  if (Array.isArray(detail)) {
    return detail.map((d: any) => d.msg || String(d)).join('; ') || fallback
  }
  if (typeof detail === 'string') return detail
  return fallback
}

export default function ProfileDrawer() {
  const { t } = useTranslation(['profile', 'common'])
  const [open, setOpen] = useState(false)
  const [activeTab, setActiveTab] = useState('profile')
  const [user, setUser] = useState<UserInfo | null>(null)

  useEffect(() => {
    if (!open) return
    auth.me().then((r) => setUser(r.data)).catch(() => setUser(null))
  }, [open])

  const tabs = [
    { id: 'profile', label: t('profile:tabs.profile'), icon: UserCircle },
    { id: 'appearance', label: t('profile:tabs.appearance'), icon: Palette },
    { id: 'security', label: t('profile:tabs.security'), icon: Shield },
    { id: 'language', label: t('profile:tabs.language'), icon: Globe },
    { id: 'dateTime', label: t('profile:tabs.dateTime'), icon: Clock },
  ]

  return (
    <>
      {/* Floating Action Button — lower-right in LTR, lower-left in RTL */}
      <button
        onClick={() => setOpen(true)}
        className="fixed bottom-6 end-6 z-40 w-12 h-12 rounded-full bg-primary text-white shadow-lg hover:opacity-90 transition-opacity flex items-center justify-center"
        aria-label={t('profile:tabs.profile')}
      >
        <UserCircle className="w-6 h-6" />
      </button>

      {/* Backdrop */}
      {open && (
        <div
          className="fixed inset-0 z-50 bg-black/50"
          onClick={() => setOpen(false)}
        />
      )}

      {/* Drawer — right side in LTR, left side in RTL */}
      <aside
        className={`fixed inset-y-0 end-0 z-50 w-full max-w-md bg-slate-900 border-slate-800 shadow-2xl transform transition-transform duration-200 flex flex-col ${
          open ? 'translate-x-0' : 'translate-x-full rtl:-translate-x-full'
        } ${open ? 'border-e rtl:border-e-0 rtl:border-s' : ''}`}
      >
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-slate-800 shrink-0">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-full bg-primary/20 text-primary flex items-center justify-center font-semibold">
              {user?.username?.charAt(0).toUpperCase() ?? '?'}
            </div>
            <div>
              <p className="font-semibold text-slate-100">{user?.username ?? '...'}</p>
              {user && (
                <Badge variant={user.is_admin ? 'info' : 'default'} size="sm">
                  {user.role}
                </Badge>
              )}
            </div>
          </div>
          <button onClick={() => setOpen(false)} className="text-slate-400 hover:text-slate-200">
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Tabs */}
        <div className="px-6 pt-4 shrink-0">
          <Tabs tabs={tabs} active={activeTab} onChange={setActiveTab} />
        </div>

        {/* Content */}
        <div className="flex-1 overflow-y-auto p-6">
          {activeTab === 'profile' && <ProfileTab user={user} />}
          {activeTab === 'appearance' && <AppearanceTab />}
          {activeTab === 'security' && <SecurityTab user={user} />}
          {activeTab === 'language' && <LanguageTab />}
          {activeTab === 'dateTime' && <DateTimeTab />}
        </div>
      </aside>
    </>
  )
}

// ---------------------------------------------------------------------------
// Profile tab — identity card + logout
// ---------------------------------------------------------------------------
function ProfileTab({ user }: { user: UserInfo | null }) {
  const { t } = useTranslation(['profile', 'common'])
  const { formatDate } = useDateTime()
  if (!user) return <p className="text-sm text-slate-400">{t('common:actions.loading')}</p>

  return (
    <div className="space-y-6">
      <div className="card space-y-3">
        <h3 className="text-lg font-semibold">{user.username}</h3>
        <div className="space-y-2 text-sm">
          <div className="flex justify-between">
            <span className="text-slate-400">{t('profile:identity.role')}</span>
            <span className="capitalize text-slate-200">{user.role}</span>
          </div>
          <div className="flex justify-between">
            <span className="text-slate-400">{t('profile:identity.memberSince')}</span>
            <span className="text-slate-200">
              {formatDate(user.created_at)}
            </span>
          </div>
        </div>
      </div>
      <button
        className="btn-secondary w-full flex items-center justify-center gap-2"
        onClick={() => {
          localStorage.removeItem('token')
          window.location.href = '/login'
        }}
      >
        <LogOut className="w-4 h-4" />
        {t('profile:identity.logout')}
      </button>
    </div>
  )
}

// ---------------------------------------------------------------------------
// Appearance tab — theme selector + custom theme editor (moved from Settings)
// ---------------------------------------------------------------------------
function AppearanceTab() {
  const { t } = useTranslation(['profile', 'common'])
  const { theme, setTheme, allThemes, customThemes, saveCustomTheme, deleteCustomTheme } = useTheme()
  const [editorOpen, setEditorOpen] = useState(false)
  const [editingTheme, setEditingTheme] = useState<Theme | null>(null)

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h3 className="text-lg font-semibold">{t('profile:appearance.title')}</h3>
        <button
          className="btn-primary text-sm flex items-center gap-1.5"
          onClick={() => { setEditingTheme(null); setEditorOpen(true) }}
        >
          <Plus className="w-4 h-4" /> {t('profile:appearance.createCustom')}
        </button>
      </div>
      <p className="text-sm text-slate-400">{t('profile:appearance.description')}</p>

      {/* Built-in themes */}
      <div>
        <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-500 mb-2">
          {t('profile:appearance.builtinThemes')}
        </h4>
        <div className="grid grid-cols-2 gap-3">
          {Object.values(builtinThemes).sort((a, b) => a.displayName.localeCompare(b.displayName)).map((tm) => (
            <button
              key={tm.name}
              onClick={() => setTheme(tm.name)}
              className={`p-3 rounded-lg border text-start transition-colors ${
                theme === tm.name
                  ? 'border-primary bg-primary/10'
                  : 'border-slate-700 hover:border-slate-600 bg-slate-800/50'
              }`}
            >
              <div className="flex items-center gap-2 mb-2">
                <div
                  className="w-4 h-4 rounded-full border border-slate-600"
                  style={{ background: `rgb(${tm.colors.accentPrimary})` }}
                />
                <span className="text-sm font-medium">{tm.displayName}</span>
              </div>
              <div className="flex gap-1">
                <div className="w-3 h-3 rounded" style={{ background: `rgb(${tm.colors.bgPrimary})` }} title={t('profile:appearance.background')} />
                <div className="w-3 h-3 rounded" style={{ background: `rgb(${tm.colors.bgSecondary})` }} title={t('profile:appearance.surface')} />
                <div className="w-3 h-3 rounded" style={{ background: `rgb(${tm.colors.borderDefault})` }} title={t('profile:appearance.border')} />
                <div className="w-3 h-3 rounded" style={{ background: `rgb(${tm.colors.textPrimary})` }} title={t('profile:appearance.text')} />
                <div className="w-3 h-3 rounded" style={{ background: `rgb(${tm.colors.accentSuccess})` }} title={t('profile:appearance.success')} />
                <div className="w-3 h-3 rounded" style={{ background: `rgb(${tm.colors.accentError})` }} title={t('profile:appearance.error')} />
              </div>
            </button>
          ))}
        </div>
      </div>

      {/* Custom themes */}
      {Object.keys(customThemes).length > 0 && (
        <div>
          <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-500 mb-2">
            {t('profile:appearance.customThemes')}
          </h4>
          <div className="grid grid-cols-2 gap-3">
            {Object.values(customThemes).sort((a, b) => a.displayName.localeCompare(b.displayName)).map((tm) => (
              <div
                key={tm.name}
                className={`p-3 rounded-lg border text-start transition-colors ${
                  theme === tm.name
                    ? 'border-primary bg-primary/10'
                    : 'border-slate-700 hover:border-slate-600 bg-slate-800/50'
                }`}
              >
                <div className="flex items-center justify-between mb-2">
                  <button
                    onClick={() => setTheme(tm.name)}
                    className="flex items-center gap-2 flex-1 min-w-0 text-start"
                  >
                    <div
                      className="w-4 h-4 rounded-full border border-slate-600 shrink-0"
                      style={{ background: `rgb(${tm.colors.accentPrimary})` }}
                    />
                    <span className="text-sm font-medium truncate">{tm.displayName}</span>
                  </button>
                  <div className="flex gap-0.5 shrink-0">
                    <IconButton
                      icon={Pencil}
                      aria-label={t('profile:appearance.editTheme')}
                      onClick={() => { setEditingTheme(cloneTheme(tm)); setEditorOpen(true) }}
                    />
                    <IconButton
                      icon={Trash2}
                      variant="danger"
                      aria-label={t('profile:appearance.deleteTheme')}
                      onClick={() => deleteCustomTheme(tm.name)}
                    />
                  </div>
                </div>
                <div className="flex gap-1">
                  <div className="w-3 h-3 rounded" style={{ background: `rgb(${tm.colors.bgPrimary})` }} title={t('profile:appearance.background')} />
                  <div className="w-3 h-3 rounded" style={{ background: `rgb(${tm.colors.bgSecondary})` }} title={t('profile:appearance.surface')} />
                  <div className="w-3 h-3 rounded" style={{ background: `rgb(${tm.colors.borderDefault})` }} title={t('profile:appearance.border')} />
                  <div className="w-3 h-3 rounded" style={{ background: `rgb(${tm.colors.textPrimary})` }} title={t('profile:appearance.text')} />
                  <div className="w-3 h-3 rounded" style={{ background: `rgb(${tm.colors.accentSuccess})` }} title={t('profile:appearance.success')} />
                  <div className="w-3 h-3 rounded" style={{ background: `rgb(${tm.colors.accentError})` }} title={t('profile:appearance.error')} />
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      <CustomThemeEditor
        open={editorOpen}
        onClose={() => setEditorOpen(false)}
        editingTheme={editingTheme}
        onSave={saveCustomTheme}
        onDelete={deleteCustomTheme}
        existingNames={Object.keys(allThemes)}
      />
    </div>
  )
}

// ---------------------------------------------------------------------------
// Security tab — change password + 2FA (moved from Settings)
// ---------------------------------------------------------------------------
function SecurityTab({ user }: { user: UserInfo | null }) {
  const { t } = useTranslation(['profile', 'common'])

  // Change password state
  const [currentPwd, setCurrentPwd] = useState('')
  const [newPwd, setNewPwd] = useState('')
  const [confirmPwd, setConfirmPwd] = useState('')
  const [changingPwd, setChangingPwd] = useState(false)
  const [pwdMessage, setPwdMessage] = useState('')

  // 2FA state
  const [mfa, setMfa] = useState<{ enabled: boolean; setup: boolean } | null>(null)
  const [mfaLoading, setMfaLoading] = useState(true)
  const [mfaCode, setMfaCode] = useState('')
  const [mfaPassword, setMfaPassword] = useState('')
  const [mfaUri, setMfaUri] = useState('')
  const [mfaQr, setMfaQr] = useState('')
  const [mfaAlias, setMfaAlias] = useState('')
  const [mfaMessage, setMfaMessage] = useState('')

  useEffect(() => {
    if (user) {
      setMfa({ enabled: user.totp_enabled, setup: false })
      setMfaAlias(user.username)
      setMfaLoading(false)
    } else {
      setMfaLoading(true)
    }
  }, [user])

  const handleChangePassword = async (e: React.FormEvent) => {
    e.preventDefault()
    setPwdMessage('')
    if (newPwd !== confirmPwd) {
      setPwdMessage(t('profile:security.changePassword.mismatch'))
      return
    }
    if (newPwd.length < 8) {
      setPwdMessage(t('profile:security.changePassword.tooShort'))
      return
    }
    setChangingPwd(true)
    try {
      await auth.changePassword(currentPwd, newPwd)
      setPwdMessage(t('profile:security.changePassword.success'))
      setCurrentPwd('')
      setNewPwd('')
      setConfirmPwd('')
    } catch (err: any) {
      const detail = err?.response?.data?.detail
      if (typeof detail === 'string' && detail.includes('Current password')) {
        setPwdMessage(t('profile:security.changePassword.wrongCurrent'))
      } else {
        setPwdMessage(formatError(err, t('common:errors.saveFailed')))
      }
    } finally {
      setChangingPwd(false)
    }
  }

  const startMfaSetup = async () => {
    setMfaMessage('')
    try {
      const res = await totp.setup(mfaAlias.trim() || undefined)
      setMfaUri(res.data.provisioning_uri)
      setMfaQr(res.data.qr_code)
      setMfa({ enabled: false, setup: true })
    } catch (err: any) {
      setMfaMessage(formatError(err, t('profile:security.twoFactor.setupFailed')))
    }
  }

  const verifyMfaCode = async (e: React.FormEvent) => {
    e.preventDefault()
    setMfaMessage('')
    try {
      await totp.verify(mfaCode)
      setMfa({ enabled: true, setup: false })
      setMfaCode('')
      setMfaUri('')
      setMfaQr('')
      setMfaMessage(t('profile:security.twoFactor.mfaEnabled'))
    } catch (err: any) {
      setMfaMessage(formatError(err, t('profile:security.twoFactor.invalidCode')))
    }
  }

  const disableMfa = async (e: React.FormEvent) => {
    e.preventDefault()
    setMfaMessage('')
    try {
      await totp.disable(mfaPassword)
      setMfa({ enabled: false, setup: false })
      setMfaPassword('')
      setMfaUri('')
      setMfaQr('')
      setMfaMessage(t('profile:security.twoFactor.mfaDisabled'))
    } catch (err: any) {
      setMfaMessage(formatError(err, t('profile:security.twoFactor.disableFailed')))
    }
  }

  return (
    <div className="space-y-6">
      {/* Change Password */}
      <form onSubmit={handleChangePassword} className="card space-y-3">
        <h3 className="text-lg font-semibold flex items-center gap-2">
          <Shield className="h-5 w-5 text-primary" />
          {t('profile:security.changePassword.title')}
        </h3>
        <div>
          <label className="label">{t('profile:security.changePassword.currentPassword')}</label>
          <input
            type="password"
            className="input w-full"
            value={currentPwd}
            onChange={(e) => setCurrentPwd(e.target.value)}
            placeholder={t('profile:security.twoFactor.currentPasswordPlaceholder')}
            disabled={changingPwd}
          />
        </div>
        <div>
          <label className="label">{t('profile:security.changePassword.newPassword')}</label>
          <input
            type="password"
            className="input w-full"
            value={newPwd}
            onChange={(e) => setNewPwd(e.target.value)}
            disabled={changingPwd}
          />
        </div>
        <div>
          <label className="label">{t('profile:security.changePassword.confirmPassword')}</label>
          <input
            type="password"
            className="input w-full"
            value={confirmPwd}
            onChange={(e) => setConfirmPwd(e.target.value)}
            disabled={changingPwd}
          />
        </div>
        <button className="btn-primary" type="submit" disabled={changingPwd || !currentPwd || !newPwd || !confirmPwd}>
          {changingPwd ? t('profile:security.changePassword.changing') : t('profile:security.changePassword.submit')}
        </button>
        {pwdMessage && (
          <p className={`text-sm ${pwdMessage.includes(t('profile:security.changePassword.success')) ? 'text-green-400' : 'text-red-400'}`}>
            {pwdMessage}
          </p>
        )}
      </form>

      {/* Two-Factor Authentication */}
      <div className="card space-y-4">
        <h3 className="text-lg font-semibold flex items-center gap-2">
          <Shield className="h-5 w-5 text-primary" />
          {t('profile:security.twoFactor.title')}
        </h3>
        {mfaLoading ? (
          <p className="text-sm text-slate-400">{t('profile:security.twoFactor.loading')}</p>
        ) : !mfa ? (
          <p className="text-sm text-slate-400">{t('profile:security.twoFactor.loadFailed')}</p>
        ) : mfa.enabled ? (
          <form onSubmit={disableMfa} className="space-y-3">
            <p className="text-sm text-slate-400">{t('profile:security.twoFactor.enabled')}</p>
            <input
              type="password"
              className="input w-full"
              value={mfaPassword}
              onChange={(e) => setMfaPassword(e.target.value)}
              placeholder={t('profile:security.twoFactor.currentPasswordPlaceholder')}
            />
            <button className="btn-secondary" type="submit" disabled={!mfaPassword}>
              {t('profile:security.twoFactor.disableMfa')}
            </button>
          </form>
        ) : mfa.setup ? (
          <form onSubmit={verifyMfaCode} className="space-y-3">
            <p className="text-sm text-slate-400">{t('profile:security.twoFactor.setupHint')}</p>
            {mfaQr && <img src={mfaQr} alt={t('profile:security.twoFactor.mfaQrCode')} className="w-48 h-48 bg-white p-2 rounded" />}
            <pre className="text-xs text-slate-300 break-all bg-slate-800 p-2 rounded">{mfaUri}</pre>
            <input
              className="input w-full"
              value={mfaCode}
              onChange={(e) => setMfaCode(e.target.value)}
              placeholder={t('profile:security.twoFactor.codePlaceholder')}
            />
            <button className="btn-primary" type="submit" disabled={!mfaCode}>
              {t('profile:security.twoFactor.verifyEnable')}
            </button>
          </form>
        ) : (
          <div className="space-y-3">
            <p className="text-sm text-slate-400">{t('profile:security.twoFactor.disabled')}</p>
            <div>
              <label className="label">{t('profile:security.twoFactor.aliasLabel')}</label>
              <input
                className="input w-full"
                value={mfaAlias}
                onChange={(e) => setMfaAlias(e.target.value)}
                placeholder={t('profile:security.twoFactor.aliasPlaceholder')}
              />
            </div>
            <button className="btn-primary" type="button" onClick={startMfaSetup} disabled={!mfaAlias.trim()}>
              {t('profile:security.twoFactor.setUpMfa')}
            </button>
          </div>
        )}
        {mfaMessage && (
          <p className={`text-sm ${
            mfaMessage === t('profile:security.twoFactor.mfaEnabled') || mfaMessage === t('profile:security.twoFactor.mfaDisabled')
              ? 'text-green-400' : 'text-red-400'
          }`}>
            {mfaMessage}
          </p>
        )}
      </div>
    </div>
  )
}

// ---------------------------------------------------------------------------
// Language tab — flag-based selector
// ---------------------------------------------------------------------------
function LanguageTab() {
  const { t } = useTranslation(['profile', 'common'])
  const { language, setLanguage, languages } = useLanguage()

  return (
    <div className="space-y-4">
      <h3 className="text-lg font-semibold">{t('profile:language.title')}</h3>
      <p className="text-sm text-slate-400">{t('profile:language.description')}</p>
      <div className="grid grid-cols-2 gap-3">
        {languages.map((lang) => (
          <button
            key={lang.code}
            onClick={() => setLanguage(lang.code)}
            className={`p-3 rounded-lg border text-start transition-colors ${
              language === lang.code
                ? 'border-primary bg-primary/10'
                : 'border-slate-700 hover:border-slate-600 bg-slate-800/50'
            }`}
          >
            <div className="flex items-center gap-2 mb-1">
              <span className="text-2xl shrink-0">{lang.flag}</span>
              <div className="min-w-0">
                <div className="flex items-center gap-1">
                  <span className="text-sm font-medium truncate">{lang.nativeName}</span>
                  {lang.code === 'en' && (
                    <Badge variant="info" size="sm">{t('profile:language.default')}</Badge>
                  )}
                </div>
                <span className="text-xs text-slate-500 truncate">{lang.englishName}</span>
              </div>
            </div>
          </button>
        ))}
      </div>
    </div>
  )
}

// ---------------------------------------------------------------------------
// Date & Time tab — timezone + format selectors with live preview
// ---------------------------------------------------------------------------
function DateTimeTab() {
  const { t } = useTranslation(['profile', 'common'])
  const {
    dateFormat, timeFormat, timezone,
    setDateFormat, setTimeFormat, setTimezone,
    formatDateTime,
  } = useDateTime()

  const [now, setNow] = useState(() => new Date())
  useEffect(() => {
    const id = setInterval(() => setNow(new Date()), 1000)
    return () => clearInterval(id)
  }, [])

  const ianaZones = useMemo(() => getAvailableTimezones(), [])
  const [tzSearch, setTzSearch] = useState('')
  const filteredZones = useMemo(() => {
    if (!tzSearch.trim()) return ianaZones
    const q = tzSearch.toLowerCase()
    return ianaZones.filter((z) => z.toLowerCase().includes(q))
  }, [ianaZones, tzSearch])

  const [customDate, setCustomDate] = useState('')
  const [customTime, setCustomTime] = useState('')
  // Sync custom inputs when the stored format isn't a known preset.
  useEffect(() => {
    const isPreset = DATE_FORMAT_PRESETS.some((p) => p.format === dateFormat)
    setCustomDate(isPreset ? '' : dateFormat)
  }, [dateFormat])
  useEffect(() => {
    const isPreset = TIME_FORMAT_PRESETS.some((p) => p.format === timeFormat)
    setCustomTime(isPreset ? '' : timeFormat)
  }, [timeFormat])

  const datePresetId = DATE_FORMAT_PRESETS.find((p) => p.format === dateFormat)?.id ?? '__custom__'
  const timePresetId = TIME_FORMAT_PRESETS.find((p) => p.format === timeFormat)?.id ?? '__custom__'

  const localTzLabel = useMemo(() => {
    try {
      const tz = systemTimezone()
      return `${t('profile:dateTime.timezone.local')} (${tz})`
    } catch {
      return t('profile:dateTime.timezone.local')
    }
  }, [t])

  const handleCustomDate = (val: string) => {
    setCustomDate(val)
    if (isValidFormatString(val)) setDateFormat(val.trim())
  }
  const handleCustomTime = (val: string) => {
    setCustomTime(val)
    if (isValidFormatString(val)) setTimeFormat(val.trim())
  }

  return (
    <div className="space-y-4">
      <h3 className="text-lg font-semibold">{t('profile:dateTime.title')}</h3>
      <p className="text-sm text-slate-400">{t('profile:dateTime.description')}</p>

      {/* Timezone */}
      <div className="card space-y-3">
        <label className="label">{t('profile:dateTime.timezone.label')}</label>
        <div className="flex gap-2">
          <button
            className={`flex-1 px-3 py-2 rounded-lg border text-sm transition-colors ${
              timezone === 'local'
                ? 'border-primary bg-primary/10 text-primary'
                : 'border-slate-700 hover:border-slate-600 bg-slate-800/50 text-slate-300'
            }`}
            onClick={() => setTimezone('local')}
          >
            {localTzLabel}
          </button>
          <button
            className={`flex-1 px-3 py-2 rounded-lg border text-sm transition-colors ${
              timezone === 'utc'
                ? 'border-primary bg-primary/10 text-primary'
                : 'border-slate-700 hover:border-slate-600 bg-slate-800/50 text-slate-300'
            }`}
            onClick={() => setTimezone('utc')}
          >
            {t('profile:dateTime.timezone.utc')}
          </button>
        </div>
        <select
          className="input w-full"
          value={timezone === 'local' || timezone === 'utc' ? '' : timezone}
          onChange={(e) => e.target.value && setTimezone(e.target.value)}
        >
          <option value="">{t('profile:dateTime.timezone.iana')}</option>
          {filteredZones.map((z) => (
            <option key={z} value={z}>{z}</option>
          ))}
        </select>
        <input
          type="text"
          className="input w-full text-sm"
          placeholder={t('profile:dateTime.timezone.searchPlaceholder')}
          value={tzSearch}
          onChange={(e) => setTzSearch(e.target.value)}
        />
      </div>

      {/* Date format */}
      <div className="card space-y-3">
        <label className="label">{t('profile:dateTime.format.dateLabel')}</label>
        <select
          className="input w-full"
          value={datePresetId}
          onChange={(e) => {
            const preset = DATE_FORMAT_PRESETS.find((p) => p.id === e.target.value)
            if (preset) setDateFormat(preset.format)
          }}
        >
          {DATE_FORMAT_PRESETS.map((p) => (
            <option key={p.id} value={p.id}>{p.label}</option>
          ))}
          <option value="__custom__">{t('profile:dateTime.format.custom')}</option>
        </select>
        {(datePresetId === '__custom__' || customDate) && (
          <input
            type="text"
            className="input w-full text-sm font-mono"
            placeholder={t('profile:dateTime.format.customPlaceholder')}
            value={customDate}
            onChange={(e) => handleCustomDate(e.target.value)}
          />
        )}
      </div>

      {/* Time format */}
      <div className="card space-y-3">
        <label className="label">{t('profile:dateTime.format.timeLabel')}</label>
        <select
          className="input w-full"
          value={timePresetId}
          onChange={(e) => {
            const preset = TIME_FORMAT_PRESETS.find((p) => p.id === e.target.value)
            if (preset) setTimeFormat(preset.format)
          }}
        >
          {TIME_FORMAT_PRESETS.map((p) => (
            <option key={p.id} value={p.id}>{p.label}</option>
          ))}
          <option value="__custom__">{t('profile:dateTime.format.custom')}</option>
        </select>
        {(timePresetId === '__custom__' || customTime) && (
          <input
            type="text"
            className="input w-full text-sm font-mono"
            placeholder={t('profile:dateTime.format.customPlaceholder')}
            value={customTime}
            onChange={(e) => handleCustomTime(e.target.value)}
          />
        )}
        <p className="text-xs text-slate-500">{t('profile:dateTime.format.tokenHelp')}</p>
      </div>

      {/* Preview */}
      <div className="card space-y-2">
        <span className="label">{t('profile:dateTime.preview.label')}</span>
        <div className="text-sm font-mono text-slate-200 bg-slate-800/50 rounded px-3 py-2">
          {formatDateTime(now)}
        </div>
        <span className="text-xs text-slate-500">
          {t('profile:dateTime.preview.now')} · {isValidTimezone(timezone) ? (timezone === 'local' ? localTzLabel : timezone) : timezone}
        </span>
      </div>
    </div>
  )
}
