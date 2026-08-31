import { useEffect, useRef, useState } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { ArrowLeft, Radar, Trash2, Eye, AlertTriangle, Info } from 'lucide-react'
import { certificates, ssllabs, auth, getErrorDetail } from '../services/api'
import Modal from '../components/Modal'
import SslLabsReport from '../components/SslLabsReport'
import { IconButton } from '../components/ui'
import { useDateTime } from '../contexts/DateTimeContext'

interface Scan {
  id: number
  certificate_id: number
  host: string
  status: string
  status_message: string | null
  grade: string | null
  report: Record<string, any> | null
  start_time: number | null
  test_time: number | null
  engine_version: string | null
  criteria_version: string | null
  error: string | null
  created_at: string
  updated_at: string
}

interface UserInfo {
  id: number
  username: string
  role: string
  is_admin: boolean
  email?: string | null
  first_name?: string | null
  last_name?: string | null
  organization?: string | null
}

function statusColor(status: string): string {
  if (status === 'READY') return 'text-green-400'
  if (status === 'ERROR') return 'text-red-400'
  if (status === 'IN_PROGRESS') return 'text-blue-400'
  return 'text-amber-400'
}

function gradeColor(grade: string | null): string {
  if (!grade) return 'text-slate-500'
  if (grade.startsWith('A')) return 'text-green-400'
  if (grade.startsWith('B')) return 'text-amber-400'
  if (grade.startsWith('C') || grade.startsWith('D')) return 'text-orange-400'
  return 'text-red-400'
}

export default function CertificateSslLabs() {
  const { id } = useParams<{ id: string }>()
  const certId = Number(id)
  const navigate = useNavigate()
  const { t } = useTranslation(['pages', 'common'])
  const { formatDateTime } = useDateTime()

  const [cert, setCert] = useState<any>(null)
  const [hosts, setHosts] = useState<string[]>([])
  const [scans, setScans] = useState<Scan[]>([])
  const [user, setUser] = useState<UserInfo | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [scanning, setScanning] = useState<Record<number, boolean>>({})
  const [detailScan, setDetailScan] = useState<Scan | null>(null)
  const [deleteConfirm, setDeleteConfirm] = useState<Scan | null>(null)
  const pollTimers = useRef<Record<number, ReturnType<typeof setTimeout>>>({})
  const pollScanRef = useRef<(scanId: number) => void>(() => {})

  // Permission flags
  const canScan = user && (user.role === 'admin' || user.role === 'operator') &&
    !!(user.email && user.first_name && user.last_name && user.organization)
  const canDelete = user?.role === 'admin'
  const isViewer = user?.role === 'viewer'
  const contactIncomplete = user && (user.role === 'admin' || user.role === 'operator') && !canScan

  useEffect(() => {
    const load = async () => {
      setLoading(true)
      try {
        const [certRes, hostsRes, scansRes, userRes] = await Promise.all([
          certificates.list(),
          ssllabs.hosts(certId),
          ssllabs.listScans(certId),
          auth.me(),
        ])
        const foundCert = certRes.data.find((c: any) => c.id === certId)
        setCert(foundCert || null)
        setHosts(hostsRes.data.hosts || [])
        setScans(scansRes.data)
        setUser(userRes.data)
        // Resume polling for any scans that are still in progress
        const canScan = userRes.data && (userRes.data.role === 'admin' || userRes.data.role === 'operator') &&
          !!(userRes.data.email && userRes.data.first_name && userRes.data.last_name && userRes.data.organization)
        if (canScan) {
          for (const scan of scansRes.data) {
            if (scan.status !== 'READY' && scan.status !== 'ERROR') {
              setScanning((prev) => ({ ...prev, [scan.id]: true }))
              pollScanRef.current(scan.id)
            }
          }
        }
      } catch (err: any) {
        setError(getErrorDetail(err, t('pages:ssllabs.errors.loadFailed')))
      } finally {
        setLoading(false)
      }
    }
    load()
    return () => {
      Object.values(pollTimers.current).forEach(clearTimeout)
    }
  }, [certId])

  const handleScan = async (host: string) => {
    setError('')
    try {
      const res = await ssllabs.startScan(certId, host)
      const newScan = res.data
      setScans((prev) => [newScan, ...prev])
      setScanning((prev) => ({ ...prev, [newScan.id]: true }))
      pollScan(newScan.id)
    } catch (err: any) {
      setError(getErrorDetail(err, t('pages:ssllabs.errors.scanFailed')))
    }
  }

  const pollScan = (scanId: number) => {
    const startTime = Date.now()
    const MAX_POLL_MS = 10 * 60 * 1000
    let interval = 5000

    const poll = async () => {
      try {
        const res = await ssllabs.pollScan(certId, scanId)
        const updated = res.data
        setScans((prev) => prev.map((s) => (s.id === scanId ? updated : s)))
        if (updated.status === 'READY' || updated.status === 'ERROR') {
          setScanning((prev) => ({ ...prev, [scanId]: false }))
          return
        }
        // Switch to 10s once IN_PROGRESS
        interval = updated.status === 'IN_PROGRESS' ? 10000 : 5000
      } catch (err: any) {
        // On rate limit / service unavailable, keep the scan but stop polling
        const detail = getErrorDetail(err, '')
        if (err.response?.status === 429 || err.response?.status === 503) {
          setScanning((prev) => ({ ...prev, [scanId]: false }))
          setError(detail || t('pages:ssllabs.errors.serviceBusy'))
          return
        }
        // Transient errors: keep polling
      }
      if (Date.now() - startTime > MAX_POLL_MS) {
        setScanning((prev) => ({ ...prev, [scanId]: false }))
        return
      }
      pollTimers.current[scanId] = setTimeout(poll, interval)
    }
    poll()
  }
  pollScanRef.current = pollScan

  const handleDelete = async (scan: Scan) => {
    setDeleteConfirm(null)
    try {
      await ssllabs.deleteScan(certId, scan.id)
      setScans((prev) => prev.filter((s) => s.id !== scan.id))
    } catch (err: any) {
      setError(getErrorDetail(err, t('pages:ssllabs.errors.deleteFailed')))
    }
  }

  // Group scans by host
  const scansByHost = scans.reduce<Record<string, Scan[]>>((acc, s) => {
    if (!acc[s.host]) acc[s.host] = []
    acc[s.host].push(s)
    return acc
  }, {})

  const isHostScanning = (host: string) => {
    return Object.values(scansByHost[host] || []).some(
      (s) => scanning[s.id] || (s.status !== 'READY' && s.status !== 'ERROR')
    )
  }

  if (loading) {
    return (
      <div className="space-y-4">
        <button onClick={() => navigate('/certificates')} className="btn-secondary inline-flex items-center gap-1">
          <ArrowLeft className="h-4 w-4" /> {t('pages:ssllabs.back')}
        </button>
        <p>{t('common:actions.loading')}</p>
      </div>
    )
  }

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <button onClick={() => navigate('/certificates')} className="btn-secondary inline-flex items-center gap-1">
            <ArrowLeft className="h-4 w-4" /> {t('pages:ssllabs.back')}
          </button>
          <h2 className="text-2xl font-bold flex items-center gap-2">
            <Radar className="h-5 w-5 text-primary" />
            {t('pages:ssllabs.title')}
          </h2>
        </div>
      </div>

      {/* Certificate info */}
      {cert && (
        <div className="card space-y-1">
          <p className="text-sm"><span className="text-slate-400">{t('pages:ssllabs.certificate')}:</span> {cert.name}</p>
          <p className="text-sm"><span className="text-slate-400">{t('pages:certificates.tableHeaders.cn')}:</span> {cert.subject_cn || '-'}</p>
          {cert.sans && <p className="text-sm"><span className="text-slate-400">{t('pages:certificates.tableHeaders.sans')}:</span> {cert.sans}</p>}
        </div>
      )}

      {/* Permission banners */}
      {isViewer && (
        <div className="card border-amber-500/30 bg-amber-500/5 flex items-center gap-2 text-sm text-amber-400">
          <Info className="h-4 w-4 shrink-0" />
          {t('pages:ssllabs.viewOnlyAccess')}
        </div>
      )}
      {contactIncomplete && (
        <div className="card border-amber-500/30 bg-amber-500/5 flex items-center gap-2 text-sm text-amber-400">
          <AlertTriangle className="h-4 w-4 shrink-0" />
          {t('pages:ssllabs.contactFieldsRequired')}
        </div>
      )}

      {error && <p className="text-red-400 text-sm">{error}</p>}

      {/* Hosts panel */}
      <div className="card space-y-3">
        <h3 className="text-sm font-semibold uppercase tracking-wider text-slate-400">{t('pages:ssllabs.scannableHosts')}</h3>
        {hosts.length === 0 ? (
          <p className="text-sm text-slate-500">{t('pages:ssllabs.noHosts')}</p>
        ) : (
          <div className="space-y-2">
            {hosts.map((host) => (
              <div key={host} className="flex items-center justify-between">
                <span className="font-mono text-sm">{host}</span>
                <button
                  className="btn-primary text-sm inline-flex items-center gap-1"
                  onClick={() => handleScan(host)}
                  disabled={!canScan || isHostScanning(host)}
                  title={!canScan ? (isViewer ? t('pages:ssllabs.viewOnlyAccess') : t('pages:ssllabs.contactFieldsRequired')) : ''}
                >
                  <Radar className="h-3 w-3" />
                  {isHostScanning(host) ? t('pages:ssllabs.scanning') : t('pages:ssllabs.scan')}
                </button>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Scans table */}
      {Object.keys(scansByHost).length > 0 && (
        <div className="card space-y-4">
          <h3 className="text-sm font-semibold uppercase tracking-wider text-slate-400">{t('pages:ssllabs.scanHistory')}</h3>
          {Object.entries(scansByHost).map(([host, hostScans]) => (
            <div key={host} className="space-y-2">
              <p className="font-mono text-sm font-semibold text-slate-300">{host}</p>
              <div className="overflow-x-auto">
                <table className="w-full text-sm text-start">
                  <thead className="text-slate-400 border-b border-slate-800">
                    <tr>
                      <th>{t('pages:ssllabs.table.status')}</th>
                      <th>{t('pages:ssllabs.table.grade')}</th>
                      <th>{t('pages:ssllabs.table.lastCompleted')}</th>
                      <th></th>
                    </tr>
                  </thead>
                  <tbody>
                    {hostScans.map((scan) => (
                      <tr key={scan.id} className="border-b border-slate-800/50 last:border-0">
                        <td className="py-2">
                          <span className={statusColor(scan.status)}>{scan.status}</span>
                          {scanning[scan.id] && <span className="text-slate-400 ms-1 text-xs">({t('pages:ssllabs.polling')})</span>}
                          {scan.status_message && <div className="text-xs text-slate-500">{scan.status_message}</div>}
                        </td>
                        <td><span className={`font-bold ${gradeColor(scan.grade)}`}>{scan.grade || '-'}</span></td>
                        <td className="text-slate-400 text-xs">{scan.test_time ? formatDateTime(new Date(scan.test_time).toISOString()) : '-'}</td>
                        <td className="text-end">
                          <div className="inline-flex items-center gap-2">
                            {scan.status === 'READY' && scan.report && (
                              <IconButton icon={Eye} aria-label={t('pages:ssllabs.viewDetails')} onClick={() => setDetailScan(scan)} />
                            )}
                            {canDelete && (
                              <IconButton icon={Trash2} variant="danger" aria-label={t('common:actions.delete')} onClick={() => setDeleteConfirm(scan)} />
                            )}
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Detail modal */}
      <Modal
        open={!!detailScan}
        onClose={() => setDetailScan(null)}
        title={detailScan ? `${t('pages:ssllabs.reportTitle')} — ${detailScan.host}` : ''}
        size="xl"
      >
        {detailScan?.report && <SslLabsReport report={detailScan.report} />}
      </Modal>

      {/* Delete confirmation */}
      <Modal
        open={!!deleteConfirm}
        onClose={() => setDeleteConfirm(null)}
        title={t('pages:ssllabs.deleteConfirmTitle')}
      >
        <p className="text-sm text-slate-300">{t('pages:ssllabs.deleteConfirmText', { host: deleteConfirm?.host })}</p>
        <div className="flex gap-2 mt-4">
          <button className="btn-primary bg-red-500/80" onClick={() => deleteConfirm && handleDelete(deleteConfirm)}>
            {t('common:actions.delete')}
          </button>
          <button className="btn-secondary" onClick={() => setDeleteConfirm(null)}>
            {t('common:actions.cancel')}
          </button>
        </div>
      </Modal>
    </div>
  )
}
