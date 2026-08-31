import React, { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Globe, Clock, AlertTriangle, Download, Upload, Package, FileArchive, Radar } from 'lucide-react'
import { settings, systemBackup } from '../services/api'
import Modal from '../components/Modal'
import { useDateTime } from '../contexts/DateTimeContext'

function formatError(err: any, fallback: string): string {
  const detail = err?.response?.data?.detail
  if (Array.isArray(detail)) {
    return detail.map((d: any) => d.msg || String(d)).join('; ') || fallback
  }
  if (typeof detail === 'string') return detail
  return fallback
}

export default function SystemSettings() {
  const { t } = useTranslation(['settings', 'common'])
  const { formatDateTime } = useDateTime()
  const [licenseKey, setLicenseKey] = useState('')
  const [loading, setLoading] = useState(false)
  const [saving, setSaving] = useState(false)
  const [downloading, setDownloading] = useState(false)
  const [message, setMessage] = useState('')
  const [sessionTimeout, setSessionTimeout] = useState(30)
  const [sessionWarning, setSessionWarning] = useState(60)
  const [sessionLoading, setSessionLoading] = useState(true)
  const [sessionSaving, setSessionSaving] = useState(false)
  const [sessionMessage, setSessionMessage] = useState('')
  const [geoipStatus, setGeoipStatus] = useState<{ last_download: string | null; databases: any[] } | null>(null)
  const [ssllabsMaxScans, setSsllabsMaxScans] = useState(5)
  const [ssllabsLoading, setSsllabsLoading] = useState(true)
  const [ssllabsSaving, setSsllabsSaving] = useState(false)
  const [ssllabsMessage, setSsllabsMessage] = useState('')

  // System Backup & Restore state
  const [exportSecrets, setExportSecrets] = useState(true)
  const [exportMetrics, setExportMetrics] = useState(false)
  const [exportPassword, setExportPassword] = useState('')
  const [exporting, setExporting] = useState(false)
  const [exportMessage, setExportMessage] = useState('')
  const [restoreFile, setRestoreFile] = useState<File | null>(null)
  const [restorePassword, setRestorePassword] = useState('')
  const [restoring, setRestoring] = useState(false)
  const [restoreMessage, setRestoreMessage] = useState('')
  const [confirmRestore, setConfirmRestore] = useState(false)
  const [confirmText, setConfirmText] = useState('')

  useEffect(() => {
    setLoading(true)
    settings.getMaxmindLicenseKey()
      .then((r) => setLicenseKey(r.data.value || ''))
      .catch(() => setMessage(t('settings:geoip.couldNotLoad')))
      .finally(() => setLoading(false))
    settings.getGeoipStatus()
      .then((r) => setGeoipStatus(r.data))
      .catch(() => {})
  }, [t])

  useEffect(() => {
    setSessionLoading(true)
    Promise.all([
      settings.get('session_timeout_minutes').then((r) => {
        const val = parseInt(r.data.value, 10)
        setSessionTimeout(isNaN(val) ? 30 : Math.max(1, val))
      }).catch(() => setSessionTimeout(30)),
      settings.get('session_warning_seconds').then((r) => {
        const val = parseInt(r.data.value, 10)
        setSessionWarning(isNaN(val) ? 60 : Math.max(0, val))
      }).catch(() => setSessionWarning(60)),
    ]).finally(() => setSessionLoading(false))
  }, [])

  useEffect(() => {
    setSsllabsLoading(true)
    settings.get('ssllabs_max_scans_per_host')
      .then((r) => {
        const val = parseInt(r.data.value, 10)
        setSsllabsMaxScans(isNaN(val) ? 5 : Math.max(1, val))
      })
      .catch(() => setSsllabsMaxScans(5))
      .finally(() => setSsllabsLoading(false))
  }, [])

  const save = async (e: React.FormEvent) => {
    e.preventDefault()
    setSaving(true)
    setMessage('')
    try {
      await settings.updateMaxmindLicenseKey({ value: licenseKey.trim() || null })
      setMessage(t('settings:geoip.saved'))
    } catch (err: any) {
      setMessage(formatError(err, t('settings:geoip.saveFailed')))
    } finally {
      setSaving(false)
    }
  }

  const saveSession = async (e: React.FormEvent) => {
    e.preventDefault()
    setSessionMessage('')
    if (sessionTimeout < 5 || sessionTimeout > 1440) {
      setSessionMessage(t('settings:session.timeoutInvalid'))
      return
    }
    if (sessionWarning < 5 || sessionWarning > 120) {
      setSessionMessage(t('settings:session.warningInvalid'))
      return
    }
    setSessionSaving(true)
    try {
      await Promise.all([
        settings.update('session_timeout_minutes', { value: String(sessionTimeout) }),
        settings.update('session_warning_seconds', { value: String(sessionWarning) }),
      ])
      setSessionMessage(t('settings:session.saved'))
      window.dispatchEvent(new CustomEvent('session-settings-updated'))
    } catch (err: any) {
      setSessionMessage(formatError(err, t('settings:session.saveFailed')))
    } finally {
      setSessionSaving(false)
    }
  }

  const saveSsllabs = async (e: React.FormEvent) => {
    e.preventDefault()
    setSsllabsMessage('')
    if (ssllabsMaxScans < 1 || ssllabsMaxScans > 100) {
      setSsllabsMessage(t('settings:ssllabs.invalid'))
      return
    }
    setSsllabsSaving(true)
    try {
      await settings.update('ssllabs_max_scans_per_host', { value: String(ssllabsMaxScans) })
      setSsllabsMessage(t('settings:ssllabs.saved'))
    } catch (err: any) {
      setSsllabsMessage(formatError(err, t('settings:ssllabs.saveFailed')))
    } finally {
      setSsllabsSaving(false)
    }
  }

  const download = async () => {
    setDownloading(true)
    setMessage('')
    try {
      const res = await settings.downloadGeoip()
      const { ok, results } = res.data
      if (ok) {
        setMessage(t('settings:geoip.downloaded', { count: results.length }))
        settings.getGeoipStatus()
          .then((r) => setGeoipStatus(r.data))
          .catch(() => {})
      } else {
        const errors = results.filter((r: any) => !r.ok).map((r: any) => r.error).join('; ')
        setMessage(t('settings:geoip.downloadFailed', { errors }))
      }
    } catch (err: any) {
      setMessage(err?.response?.data?.detail || t('settings:geoip.downloadTriggerFailed'))
    } finally {
      setDownloading(false)
    }
  }

  const handleExport = async () => {
    setExporting(true)
    setExportMessage('')
    try {
      const res = await systemBackup.export(exportSecrets, exportMetrics, exportPassword || undefined)
      const blob = new Blob([res.data])
      const url = window.URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      const ts = new Date().toISOString().replace(/[:.]/g, '').slice(0, 14)
      a.download = `haproxy-manager-export-${ts}.zip`
      document.body.appendChild(a)
      a.click()
      document.body.removeChild(a)
      window.URL.revokeObjectURL(url)
      setExportMessage(t('settings:backup.export.success'))
    } catch (err: any) {
      setExportMessage(formatError(err, t('settings:backup.export.failed')))
    } finally {
      setExporting(false)
    }
  }

  const handleRestoreClick = () => {
    if (!restoreFile) {
      setRestoreMessage(t('settings:backup.restore.selectFile'))
      return
    }
    setConfirmRestore(true)
    setConfirmText('')
  }

  const handleRestoreConfirm = async () => {
    if (confirmText !== 'RESTORE') return
    setRestoring(true)
    setRestoreMessage('')
    setConfirmRestore(false)
    try {
      const res = await systemBackup.restore(restoreFile!, restorePassword || undefined)
      const data = res.data
      setRestoreMessage(
        t('settings:backup.restore.complete', {
          tables: data.tables_restored,
          files: data.files_restored,
          applied: data.config_applied ? t('settings:backup.restore.configApplied') : t('settings:backup.restore.configNotApplied'),
        })
      )
      setRestoreFile(null)
      setRestorePassword('')
      // Reload the page after a short delay so the user sees the success message.
      setTimeout(() => window.location.reload(), 2500)
    } catch (err: any) {
      setRestoreMessage(formatError(err, t('settings:backup.restore.failed')))
    } finally {
      setRestoring(false)
    }
  }

  return (
    <div className="space-y-6">
      <form onSubmit={save} className="card space-y-4 max-w-2xl">
        <h2 className="text-lg font-semibold flex items-center gap-2"><Globe className="h-5 w-5 text-primary" /> {t('settings:geoip.title')}</h2>
        <p className="text-sm text-slate-400">
          {t('settings:geoip.description')}
        </p>
        <div>
          <label className="label">{t('settings:geoip.licenseKey')}</label>
          <input
            type="password"
            className="input w-full"
            value={licenseKey}
            onChange={(e) => setLicenseKey(e.target.value)}
            placeholder={t('settings:geoip.licenseKeyPlaceholder')}
            disabled={loading}
          />
        </div>
        <div className="flex items-center gap-3">
          <button className="btn-primary" type="submit" disabled={saving}>
            {saving ? t('common:actions.saving') : t('settings:geoip.saveLicenseKey')}
          </button>
          <button
            className="btn-secondary"
            type="button"
            onClick={download}
            disabled={downloading}
          >
            {downloading ? t('settings:geoip.downloading') : t('settings:geoip.downloadNow')}
          </button>
        </div>
        {message && (
          <p className={`text-sm ${message.startsWith(t('settings:geoip.saveFailed')) || message.startsWith(t('settings:geoip.couldNotLoad')) ? 'text-red-400' : 'text-green-400'}`}>
            {message}
          </p>
        )}
        {geoipStatus && (
          <div className="border-t border-slate-800 pt-4 space-y-2">
            <div className="flex items-center gap-2 text-sm text-slate-300">
              <Clock className="h-4 w-4 text-slate-400" />
              <span>{t('settings:geoip.lastUpdated')} </span>
              <span className="font-mono text-slate-100">
                {geoipStatus.last_download
                  ? formatDateTime(geoipStatus.last_download)
                  : t('settings:geoip.never')}
              </span>
            </div>
            {geoipStatus.databases.length > 0 && (
              <div className="space-y-1">
                {geoipStatus.databases.map((db) => (
                  <div key={db.name} className="flex items-center justify-between text-xs text-slate-400">
                    <span>{db.name} {t('settings:geoip.dbSuffix')}</span>
                    <span className={db.exists ? 'text-slate-300' : 'text-red-400'}>
                      {db.exists
                        ? `${formatDateTime(db.modified)} (${(db.size_bytes / 1048576).toFixed(1)} MB)`
                        : t('settings:geoip.missing')}
                    </span>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}
      </form>

      <form onSubmit={saveSession} className="card space-y-4 max-w-2xl">
        <h2 className="text-lg font-semibold flex items-center gap-2"><Clock className="h-5 w-5 text-primary" /> {t('settings:session.title')}</h2>
        <p className="text-sm text-slate-400">
          {t('settings:session.description')}
        </p>
        {sessionLoading ? (
          <p className="text-sm text-slate-400">{t('common:actions.loading')}</p>
        ) : (
          <div className="space-y-3">
            <div className="flex items-center gap-4">
              <label className="label w-52 shrink-0">{t('settings:session.timeoutLabel')}</label>
              <input
                type="number"
                min={5}
                max={1440}
                className="input w-32"
                value={sessionTimeout}
                onChange={(e) => setSessionTimeout(Number(e.target.value))}
                disabled={sessionSaving}
              />
              <span className="text-xs text-slate-500">{t('settings:session.timeoutRange')}</span>
            </div>
            <div className="flex items-center gap-4">
              <label className="label w-52 shrink-0 flex items-center gap-2">
                <AlertTriangle className="h-4 w-4 text-primary" />
                {t('settings:session.warningLabel')}
              </label>
              <input
                type="number"
                min={5}
                max={120}
                className="input w-32"
                value={sessionWarning}
                onChange={(e) => setSessionWarning(Number(e.target.value))}
                disabled={sessionSaving}
              />
              <span className="text-xs text-slate-500">{t('settings:session.warningRange')}</span>
            </div>
          </div>
        )}
        <button className="btn-primary" type="submit" disabled={sessionSaving || sessionLoading}>
          {sessionSaving ? t('common:actions.saving') : t('settings:session.save')}
        </button>
        {sessionMessage && (
          <p className={`text-sm ${sessionMessage.startsWith(t('settings:session.saveFailed')) || sessionMessage.startsWith(t('common:errors.loadFailed')) ? 'text-red-400' : 'text-green-400'}`}>
            {sessionMessage}
          </p>
        )}
      </form>

      <form onSubmit={saveSsllabs} className="card space-y-4 max-w-2xl">
        <h2 className="text-lg font-semibold flex items-center gap-2"><Radar className="h-5 w-5 text-primary" /> {t('settings:ssllabs.title')}</h2>
        <p className="text-sm text-slate-400">
          {t('settings:ssllabs.description')}
        </p>
        {ssllabsLoading ? (
          <p className="text-sm text-slate-400">{t('common:actions.loading')}</p>
        ) : (
          <div className="space-y-3">
            <div className="flex items-center gap-4">
              <label className="label w-52 shrink-0">{t('settings:ssllabs.maxScansLabel')}</label>
              <input
                type="number"
                min={1}
                max={100}
                className="input w-32"
                value={ssllabsMaxScans}
                onChange={(e) => setSsllabsMaxScans(Number(e.target.value))}
                disabled={ssllabsSaving}
              />
              <span className="text-xs text-slate-500">{t('settings:ssllabs.maxScansRange')}</span>
            </div>
          </div>
        )}
        <button className="btn-primary" type="submit" disabled={ssllabsSaving || ssllabsLoading}>
          {ssllabsSaving ? t('common:actions.saving') : t('settings:ssllabs.save')}
        </button>
        {ssllabsMessage && (
          <p className={`text-sm ${ssllabsMessage.startsWith(t('settings:ssllabs.saveFailed')) || ssllabsMessage.startsWith(t('settings:ssllabs.invalid')) ? 'text-red-400' : 'text-green-400'}`}>
            {ssllabsMessage}
          </p>
        )}
      </form>

      <div className="card space-y-4 max-w-2xl">
        <h2 className="text-lg font-semibold flex items-center gap-2"><Package className="h-5 w-5 text-primary" /> {t('settings:backup.title')}</h2>
        <p className="text-sm text-slate-400">
          {t('settings:backup.description')}
        </p>

        <div className="border-t border-slate-800 pt-4 space-y-4">
          <h3 className="text-sm font-semibold flex items-center gap-2"><Download className="h-4 w-4 text-primary" /> {t('settings:backup.export.title')}</h3>
          <div className="space-y-2">
            <label className="flex items-center gap-2 text-sm text-slate-300">
              <input
                type="checkbox"
                className="rounded border-slate-600 bg-slate-800 text-primary"
                checked={exportSecrets}
                onChange={(e) => setExportSecrets(e.target.checked)}
                disabled={exporting}
              />
              {t('settings:backup.export.exportSecrets')}
            </label>
            <label className="flex items-center gap-2 text-sm text-slate-300">
              <input
                type="checkbox"
                className="rounded border-slate-600 bg-slate-800 text-primary"
                checked={exportMetrics}
                onChange={(e) => setExportMetrics(e.target.checked)}
                disabled={exporting}
              />
              {t('settings:backup.export.exportMetrics')}
            </label>
          </div>
          <div>
            <label className="label">{t('settings:backup.export.passwordLabel')}</label>
            <input
              type="password"
              className="input w-full"
              value={exportPassword}
              onChange={(e) => setExportPassword(e.target.value)}
              placeholder={t('settings:backup.export.passwordPlaceholder')}
              disabled={exporting}
            />
          </div>
          <button className="btn-primary" type="button" onClick={handleExport} disabled={exporting}>
            {exporting ? t('settings:backup.export.exporting') : t('settings:backup.export.button')}
          </button>
          {exportMessage && (
            <p className={`text-sm ${exportMessage.startsWith(t('settings:backup.export.failed')) || exportMessage.startsWith(t('common:errors.saveFailed')) ? 'text-red-400' : 'text-green-400'}`}>
              {exportMessage}
            </p>
          )}
        </div>

        <div className="border-t border-slate-800 pt-4 space-y-4">
          <h3 className="text-sm font-semibold flex items-center gap-2"><Upload className="h-4 w-4 text-primary" /> {t('settings:backup.restore.title')}</h3>
          <div>
            <label className="label">{t('settings:backup.restore.fileLabel')}</label>
            <div className="flex items-center gap-2">
              <label className={`btn-secondary cursor-pointer flex items-center gap-2 ${restoring ? 'opacity-50 pointer-events-none' : ''}`}>
                <FileArchive className="w-4 h-4" />
                {t('settings:backup.restore.chooseFile')}
                <input
                  type="file"
                  accept=".zip,application/zip,application/octet-stream"
                  className="hidden"
                  onChange={(e) => setRestoreFile(e.target.files?.[0] || null)}
                  disabled={restoring}
                />
              </label>
              {restoreFile && (
                <span className="text-sm text-slate-400 truncate max-w-xs">{restoreFile.name}</span>
              )}
            </div>
          </div>
          <div>
            <label className="label">{t('settings:backup.restore.passwordLabel')}</label>
            <input
              type="password"
              className="input w-full"
              value={restorePassword}
              onChange={(e) => setRestorePassword(e.target.value)}
              placeholder={t('settings:backup.restore.passwordPlaceholder')}
              disabled={restoring}
            />
          </div>
          <button className="btn-secondary" type="button" onClick={handleRestoreClick} disabled={restoring || !restoreFile}>
            {restoring ? t('settings:backup.restore.restoring') : t('settings:backup.restore.button')}
          </button>
          {restoreMessage && (
            <p className={`text-sm ${restoreMessage.startsWith(t('settings:backup.restore.failed')) || restoreMessage.startsWith(t('common:errors.saveFailed')) ? 'text-red-400' : 'text-green-400'}`}>
              {restoreMessage}
            </p>
          )}
        </div>
      </div>

      <Modal open={confirmRestore} onClose={() => setConfirmRestore(false)} title={t('settings:backup.restore.confirmTitle')}>
        <div className="space-y-4">
          <div className="flex items-start gap-3 p-3 rounded-lg bg-red-500/10 border border-red-500/20 text-red-300">
            <AlertTriangle className="h-5 w-5 shrink-0 mt-0.5" />
            <p className="text-sm" dangerouslySetInnerHTML={{ __html: t('settings:backup.restore.confirmWarning') }} />
          </div>
          <div>
            <label className="label">{t('settings:backup.restore.typeConfirm')}</label>
            <input
              className="input w-full"
              value={confirmText}
              onChange={(e) => setConfirmText(e.target.value)}
              placeholder={t('settings:backup.restore.confirmPlaceholder')}
              autoFocus
            />
          </div>
          <div className="flex items-center gap-3">
            <button
              className="btn-primary"
              type="button"
              onClick={handleRestoreConfirm}
              disabled={confirmText !== 'RESTORE'}
            >
              {t('settings:backup.restore.restoreNow')}
            </button>
            <button className="btn-secondary" type="button" onClick={() => setConfirmRestore(false)}>
              {t('common:actions.cancel')}
            </button>
          </div>
        </div>
      </Modal>
    </div>
  )
}
