import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { SlidersHorizontal, Wrench, KeyRound, FileText } from 'lucide-react'
import { haproxy, getConfigStatus, auth } from '../services/api'
import HaproxyOptionsEditor, { HaproxyOption } from '../components/HaproxyOptionsEditor'
import { Tabs } from '../components/ui'
import Ciphers from './Ciphers'
import CustomResponsePages from './CustomResponsePages'

type GlobalOptionsTab = 'advanced' | 'ciphers' | 'customPages'

export default function GlobalOptions() {
  const { t } = useTranslation(['pages', 'common'])
  const [options, setOptions] = useState<HaproxyOption[]>([])
  const [loading, setLoading] = useState(false)
  const [saving, setSaving] = useState(false)
  const [message, setMessage] = useState('')
  const [isAdmin, setIsAdmin] = useState(false)

  const [tab, setTab] = useState<GlobalOptionsTab>('advanced')

  useEffect(() => {
    auth.me()
      .then((r) => {
        const admin = r.data.role === 'admin' || r.data.is_admin === true
        setIsAdmin(admin)
        // If the user is not an admin, default to the first visible tab
        // (ciphers) since the Advanced tab is hidden.
        if (!admin) setTab('ciphers')
      })
      .catch(() => setIsAdmin(false))
  }, [])

  useEffect(() => {
    setLoading(true)
    haproxy.globalOptions()
      .then((r) => setOptions(Array.isArray(r.data) ? r.data : []))
      .catch(() => setMessage(t('pages:globalOptions.couldNotLoad')))
      .finally(() => setLoading(false))
  }, [])

  const save = async () => {
    setSaving(true)
    setMessage('')
    try {
      await haproxy.updateGlobalOptions(options as any[])
      setMessage(t('pages:globalOptions.settingsSaved'))
      // Fetch config status immediately and pass the result to Layout via
      // event detail so the banner appears without waiting for polling and
      // without a race between the event handler and the 10s interval.
      let unapplied = true
      try {
        const sr = await getConfigStatus()
        unapplied = sr.data.unapplied
      } catch {
        // If the status check fails, assume unapplied so the banner shows.
        unapplied = true
      }
      window.dispatchEvent(new CustomEvent('config-status-changed', { detail: { unapplied } }))
    } catch (err: any) {
      setMessage(err?.response?.data?.detail || t('pages:globalOptions.failedToSaveSettings'))
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold flex items-center gap-2"><SlidersHorizontal className="h-5 w-5 text-primary" /> {t('pages:globalOptions.title')}</h1>

      <Tabs
        tabs={[
          ...(isAdmin ? [{ id: 'advanced' as const, label: t('pages:globalOptions.tabs.advanced'), icon: Wrench }] : []),
          { id: 'ciphers', label: t('pages:globalOptions.tabs.ciphers'), icon: KeyRound },
          { id: 'customPages', label: t('pages:globalOptions.tabs.customPages'), icon: FileText },
        ]}
        active={tab}
        onChange={(id) => setTab(id as GlobalOptionsTab)}
      />

      {tab === 'advanced' && (
      <div className="card space-y-4 max-w-3xl">
        <HaproxyOptionsEditor
          scope="global"
          value={options}
          onChange={setOptions}
        />
        <button
          className="btn-primary"
          onClick={save}
          disabled={saving || loading}
        >
          {saving ? t('common:actions.saving') : t('pages:globalOptions.saveSettings')}
        </button>
        {message && (
          <p className={`text-sm ${message === t('pages:globalOptions.settingsSaved') ? 'text-green-400' : 'text-red-400'}`}>
            {message}
          </p>
        )}
      </div>
      )}

      {tab === 'ciphers' && <Ciphers />}

      {tab === 'customPages' && <CustomResponsePages />}
    </div>
  )
}
