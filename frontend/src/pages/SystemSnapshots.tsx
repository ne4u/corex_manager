import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { History, RotateCcw, Eye } from 'lucide-react'
import { snapshots, getErrorDetail } from '../services/api'
import api from '../services/api'
import { useNotifications } from '../contexts/NotificationContext'
import { useDateTime } from '../contexts/DateTimeContext'
import Modal from '../components/Modal'
import { IconButton } from '../components/ui'

function formatError(err: any, fallback: string): string {
  const detail = err?.response?.data?.detail
  if (Array.isArray(detail)) {
    return detail.map((d: any) => d.msg || String(d)).join('; ') || fallback
  }
  if (typeof detail === 'string') return detail
  return fallback
}

interface Snapshot {
  id: number
  created_at: string
  created_by: string | null
  comment: string | null
  diff: string | null
  snapshot_path: string
}

export default function SystemSnapshots() {
  const { t } = useTranslation(['settings', 'pages', 'common'])
  const { formatDateTime } = useDateTime()
  const [items, setItems] = useState<Snapshot[]>([])
  const [loading, setLoading] = useState(true)
  const [selected, setSelected] = useState<Snapshot | null>(null)
  const { addNotification, trackTask } = useNotifications()

  // Max snapshots state
  const [maxSnapshots, setMaxSnapshots] = useState(10)
  const [maxSaving, setMaxSaving] = useState(false)
  const [snapshotMessage, setSnapshotMessage] = useState('')

  const load = async () => {
    setLoading(true)
    try {
      const r = await snapshots.list()
      setItems(r.data)
    } catch (err) {
      addNotification({ type: 'error', title: t('pages:snapshots.title'), message: getErrorDetail(err, t('common:errors.loadFailed')) })
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    load()
  }, [])

  useEffect(() => {
    api.get('/config/snapshots/max')
      .then((r) => {
        const val = parseInt(r.data.value, 10)
        setMaxSnapshots(isNaN(val) ? 10 : val)
      })
      .catch(() => setMaxSnapshots(10))
  }, [])

  const saveMaxSnapshots = async (e: React.FormEvent) => {
    e.preventDefault()
    setMaxSaving(true)
    setSnapshotMessage('')
    try {
      await api.put('/config/snapshots/max', { value: String(maxSnapshots) })
      setSnapshotMessage(t('settings:snapshots.saved'))
    } catch (err: any) {
      setSnapshotMessage(formatError(err, t('settings:snapshots.saveFailed')))
    } finally {
      setMaxSaving(false)
    }
  }

  const handleRollback = async (s: Snapshot) => {
    if (!window.confirm(t('pages:snapshots.confirmRevert'))) {
      return
    }
    try {
      const r = await snapshots.rollback(s.id)
      const id = addNotification({
        type: 'info',
        title: t('pages:snapshots.revert'),
        message: r.data.message || t('pages:snapshots.revertStarted'),
      })
      trackTask(r.data.task_id, id, {
        title: t('pages:snapshots.revert'),
        successMessage: r.data.message || t('pages:snapshots.revertedSuccessfully'),
      })
    } catch (err) {
      addNotification({ type: 'error', title: t('pages:snapshots.revert'), message: getErrorDetail(err, t('pages:snapshots.revertFailed')) })
    }
  }

  return (
    <div className="space-y-6">
      <form onSubmit={saveMaxSnapshots} className="card space-y-4 max-w-2xl">
        <h2 className="text-lg font-semibold flex items-center gap-2"><History className="h-5 w-5 text-primary" /> {t('settings:snapshots.title')}</h2>
        <p className="text-sm text-slate-400">
          {t('settings:snapshots.description')}
        </p>
        <div className="flex items-center gap-3">
          <input
            type="number"
            min={1}
            max={100}
            className="input w-24"
            value={maxSnapshots}
            onChange={(e) => setMaxSnapshots(Number(e.target.value))}
            disabled={maxSaving}
          />
          <button className="btn-primary" type="submit" disabled={maxSaving}>
            {maxSaving ? t('common:actions.saving') : t('common:actions.save')}
          </button>
        </div>
        {snapshotMessage && (
          <p className={`text-sm ${snapshotMessage.startsWith(t('settings:snapshots.saveFailed')) || snapshotMessage.startsWith(t('common:errors.loadFailed')) ? 'text-red-400' : 'text-green-400'}`}>
            {snapshotMessage}
          </p>
        )}
      </form>

      <div className="space-y-4">
        <div className="flex items-center justify-between">
          <h2 className="text-lg font-semibold">{t('pages:snapshots.title')}</h2>
          <button onClick={load} className="btn-secondary text-sm" disabled={loading}>{loading ? t('common:actions.loading') : t('common:actions.refresh')}</button>
        </div>

        {loading ? (
          <p>{t('common:actions.loading')}</p>
        ) : items.length === 0 ? (
          <p className="text-slate-400">{t('pages:snapshots.noSnapshots')}</p>
        ) : (
          <div className="card overflow-x-auto">
            <table className="w-full text-sm text-start">
              <thead className="text-slate-400 border-b border-slate-800">
                <tr>
                  <th className="pb-2">{t('pages:snapshots.tableHeaders.createdAt')}</th>
                  <th className="pb-2">{t('pages:snapshots.tableHeaders.createdBy')}</th>
                  <th className="pb-2">{t('pages:snapshots.tableHeaders.comment')}</th>
                  <th className="pb-2 text-end">{t('pages:snapshots.tableHeaders.actions')}</th>
                </tr>
              </thead>
              <tbody>
                {items.map((s) => (
                  <tr key={s.id} className="border-b border-slate-800 last:border-0">
                    <td className="py-2">{formatDateTime(s.created_at)}</td>
                    <td>{s.created_by || '-'}</td>
                    <td>{s.comment || '-'}</td>
                    <td className="text-end space-x-1">
                      <IconButton icon={Eye} aria-label={t('pages:snapshots.review')} onClick={() => setSelected(s)} />
                      <button
                        onClick={() => handleRollback(s)}
                        disabled={!s.snapshot_path}
                        className="text-amber-400 hover:underline flex items-center gap-1 inline-flex disabled:text-slate-600 disabled:cursor-not-allowed disabled:no-underline"
                        title={!s.snapshot_path ? t('pages:snapshots.snapshotPruned') : ''}
                      >
                        <RotateCcw className="w-3 h-3" /> {t('pages:snapshots.revert')}
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      <Modal open={!!selected} onClose={() => setSelected(null)} title={t('pages:snapshots.modalTitle', { date: selected ? formatDateTime(selected.created_at) : '' })}>
        {selected && (
          <div className="space-y-4">
            <div className="text-sm text-slate-400">
              <p><span className="font-medium text-slate-200">{t('pages:snapshots.tableHeaders.createdBy')}:</span> {selected.created_by || '-'}</p>
              {selected.comment && <p><span className="font-medium text-slate-200">{t('pages:snapshots.tableHeaders.comment')}:</span> {selected.comment}</p>}
            </div>
            <pre className="bg-slate-950 p-4 rounded-lg overflow-auto text-xs text-slate-300 max-h-96 whitespace-pre font-mono">{selected.diff || t('pages:snapshots.noDiff')}</pre>
            <div className="flex justify-end">
              <button onClick={() => { handleRollback(selected); setSelected(null) }} className="btn-primary">{t('pages:snapshots.revertToThis')}</button>
            </div>
          </div>
        )}
      </Modal>
    </div>
  )
}
