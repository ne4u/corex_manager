import React, { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Clock, Pencil, Trash2 } from 'lucide-react'
import { rateLimits, listeners, settings } from '../services/api'
import useApiList from '../hooks/useApiList'
import Modal from '../components/Modal'
import LabelWithTooltip from '../components/LabelWithTooltip'
import InfoTooltip from '../components/InfoTooltip'
import { IconButton } from '../components/ui'
import { useDateTime } from '../contexts/DateTimeContext'

export default function RateLimits() {
  const { t } = useTranslation(['pages', 'common'])
  const { formatDateTime } = useDateTime()
  const { items, reload } = useApiList(rateLimits.list)
  const { items: listenerList } = useApiList(listeners.list)
  const [open, setOpen] = useState(false)
  const [editing, setEditing] = useState<number | null>(null)
  const [asnDbAvailable, setAsnDbAvailable] = useState(false)
  const initialForm = { name: '', listener_id: null as number | null, enabled: true, limit_type: 'basic', events: 100, window_seconds: 60, burst: 0, action: 'block', duration_seconds: 300, expression: '', response_code: '', match_status_code: 404, url_path: '', user_agent: '', waf_event_threshold: 5, waf_window_seconds: 60, waf_block_duration: 900, rate_key: 'src', rate_header: '', log: true, no_log: false }
  const [form, setForm] = useState<any>(initialForm)

  useEffect(() => {
    settings.getGeoipStatus()
      .then(res => {
        const dbs = res.data?.databases || []
        setAsnDbAvailable(dbs.some((d: any) => d.name === 'ASN' && d.exists))
      })
      .catch(() => setAsnDbAvailable(false))
  }, [])

  const openAdd = () => { setEditing(null); setForm(initialForm); setOpen(true) }
  const openEdit = (r: any) => { setEditing(r.id); setForm({ ...r, rate_key: r.rate_key || 'src', rate_header: r.rate_header || '' }); setOpen(true) }

  const submit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (editing) await rateLimits.update(editing, form)
    else await rateLimits.create(form)
    setForm(initialForm)
    setEditing(null)
    setOpen(false); reload()
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between"><h2 className="text-2xl font-bold flex items-center gap-2"><Clock className="h-5 w-5 text-primary" /> {t('pages:rateLimits.title')}</h2><button onClick={openAdd} className="btn-primary">{t('pages:rateLimits.addRateLimit')}</button></div>
      <div className="card overflow-x-auto">
        <table className="w-full text-sm text-start"><thead className="text-slate-400 border-b border-slate-800"><tr><th>{t('pages:rateLimits.tableHeaders.name')}</th><th>{t('pages:rateLimits.tableHeaders.listener')}</th><th>{t('pages:rateLimits.tableHeaders.type')}</th><th>{t('pages:rateLimits.tableHeaders.events')}</th><th>{t('pages:rateLimits.tableHeaders.window')}</th><th>{t('pages:rateLimits.tableHeaders.action')}</th><th>{t('pages:rateLimits.tableHeaders.duration')}</th><th>{t('pages:rateLimits.tableHeaders.log')}</th><th className="w-40 whitespace-nowrap">{t('pages:rateLimits.tableHeaders.updated')}</th><th></th></tr></thead>
          <tbody>
            {items.map((r: any) => (
              <tr key={r.id} className="border-b border-slate-800 last:border-0"><td className="py-2">{r.name}</td><td>{r.listener_id ? listenerList.find((l: any) => l.id === r.listener_id)?.name : t('pages:rateLimits.all')}</td><td>{r.limit_type}</td><td>{r.events}</td><td>{r.window_seconds}s</td><td>{r.action}</td><td>{r.duration_seconds}s</td><td>{r.no_log ? t('pages:rateLimits.suppressed') : (r.log ? t('common:actions.yes') : t('common:actions.no'))}</td><td className="py-2 text-xs text-slate-400 whitespace-nowrap">{r.updated_at ? formatDateTime(r.updated_at) : '-'}</td>
                <td className="space-x-1">
                  <IconButton icon={Pencil} aria-label={t('common:actions.edit')} onClick={() => openEdit(r)} />
                  <IconButton icon={Trash2} variant="danger" aria-label={t('common:actions.delete')} onClick={() => rateLimits.remove(r.id).then(reload)} />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <Modal open={open} onClose={() => setOpen(false)} title={editing ? t('pages:rateLimits.modal.editTitle') : t('pages:rateLimits.modal.addTitle')}>
        <form onSubmit={submit} className="space-y-3">
          <div className="grid grid-cols-2 gap-3">
            <div>
              <LabelWithTooltip tooltip={t('pages:rateLimits.tooltips.name')} className="label">{t('pages:rateLimits.modal.name')}</LabelWithTooltip>
              <input className="input" value={form.name} onChange={e => setForm({ ...form, name: e.target.value })} />
            </div>
            <div>
              <LabelWithTooltip tooltip={t('pages:rateLimits.tooltips.listener')} className="label">{t('pages:rateLimits.modal.listener')}</LabelWithTooltip>
              <select className="input" value={form.listener_id || ''} onChange={e => setForm({ ...form, listener_id: e.target.value ? Number(e.target.value) : null })}>
                <option value="">{t('pages:rateLimits.modal.selectListener')}</option>
                {listenerList.map((l: any) => <option key={l.id} value={l.id}>{l.name}</option>)}
              </select>
            </div>
            <div>
              <LabelWithTooltip tooltip={t('pages:rateLimits.tooltips.type')} className="label">{t('pages:rateLimits.modal.type')}</LabelWithTooltip>
              <select className="input" value={form.limit_type} onChange={e => setForm({ ...form, limit_type: e.target.value })}>
                <option value="basic">{t('pages:rateLimits.modal.typeBasic')}</option>
                <option value="advanced">{t('pages:rateLimits.modal.typeAdvanced')}</option>
                <option value="waf">{t('pages:rateLimits.modal.typeWaf')}</option>
                <option value="response_code">{t('pages:rateLimits.modal.typeResponseCode')}</option>
              </select>
            </div>
            <div>
              <LabelWithTooltip tooltip={t('pages:rateLimits.tooltips.events')} className="label">{t('pages:rateLimits.modal.events')}</LabelWithTooltip>
              <input type="number" className="input" value={form.events} onChange={e => setForm({ ...form, events: Number(e.target.value) })} />
            </div>
            <div>
              <LabelWithTooltip tooltip={t('pages:rateLimits.tooltips.windowSeconds')} className="label">{t('pages:rateLimits.modal.windowSeconds')}</LabelWithTooltip>
              <input type="number" className="input" value={form.window_seconds} onChange={e => setForm({ ...form, window_seconds: Number(e.target.value) })} />
            </div>
            <div>
              <LabelWithTooltip tooltip={t('pages:rateLimits.tooltips.burst')} className="label">{t('pages:rateLimits.modal.burst')}</LabelWithTooltip>
              <input type="number" className="input" value={form.burst} onChange={e => setForm({ ...form, burst: Number(e.target.value) })} />
            </div>
            <div>
              <LabelWithTooltip tooltip={t('pages:rateLimits.tooltips.durationSeconds')} className="label">{t('pages:rateLimits.modal.durationSeconds')}</LabelWithTooltip>
              <input type="number" className="input" value={form.action === 'tarpit' ? form.duration_seconds : 0} disabled={form.action !== 'tarpit'} onChange={e => setForm({ ...form, duration_seconds: Number(e.target.value) })} />
            </div>
            <div>
              <LabelWithTooltip tooltip={t('pages:rateLimits.tooltips.action')} className="label">{t('pages:rateLimits.modal.action')}</LabelWithTooltip>
              <select className="input" value={form.action} onChange={e => setForm({ ...form, action: e.target.value })}>
                <option value="block">{t('pages:rateLimits.modal.actionBlock')}</option>
                <option value="allow">{t('pages:rateLimits.modal.actionAllow')}</option>
                <option value="log">{t('pages:rateLimits.modal.actionLog')}</option>
                <option value="tarpit">{t('pages:rateLimits.modal.actionTarpit')}</option>
                <option value="challenge">{t('pages:rateLimits.modal.actionChallenge')}</option>
              </select>
            </div>
            <div>
              <LabelWithTooltip tooltip={t('pages:rateLimits.tooltips.logAction')} className="label">{t('pages:rateLimits.modal.logAction')}</LabelWithTooltip>
              <label className="flex items-center gap-2 mt-2">
                <input type="checkbox" checked={form.log} onChange={e => setForm({ ...form, log: e.target.checked })} />
                <span className="text-sm">{form.log ? t('common:actions.yes') : t('common:actions.no')}</span>
                <InfoTooltip content={t('pages:rateLimits.tooltips.logAction')} />
              </label>
            </div>
            <div>
              <LabelWithTooltip tooltip={t('pages:rateLimits.tooltips.suppressRequestLog')} className="label">{t('pages:rateLimits.modal.suppressRequestLog')}</LabelWithTooltip>
              <label className="flex items-center gap-2 mt-2">
                <input type="checkbox" checked={form.no_log} onChange={e => setForm({ ...form, no_log: e.target.checked })} />
                <span className="text-sm">{form.no_log ? t('common:actions.yes') : t('common:actions.no')}</span>
                <InfoTooltip content={t('pages:rateLimits.tooltips.suppressRequestLog')} />
              </label>
            </div>
          </div>
          {form.limit_type !== 'response_code' && (
            <div className="grid grid-cols-2 gap-3">
              <div>
                <LabelWithTooltip tooltip={t('pages:rateLimits.tooltips.rateKey')} className="label">{t('pages:rateLimits.modal.rateKey')}</LabelWithTooltip>
                <select className="input" value={form.rate_key} onChange={e => setForm({ ...form, rate_key: e.target.value })}>
                  <option value="src">{t('pages:rateLimits.modal.rateKeySourceIp')}</option>
                  <option value="user_id">{t('pages:rateLimits.modal.rateKeyUserId')}</option>
                  <option value="header">{t('pages:rateLimits.modal.rateKeyHeader')}</option>
                  <option value="path">{t('pages:rateLimits.modal.rateKeyPath')}</option>
                  {asnDbAvailable && <option value="asn">{t('pages:rateLimits.modal.rateKeyAsn')}</option>}
                </select>
              </div>
              <div>
                <LabelWithTooltip tooltip={t('pages:rateLimits.tooltips.rateHeader')} className="label">{t('pages:rateLimits.modal.rateHeader')}</LabelWithTooltip>
                <input className="input" value={form.rate_header || ''} onChange={e => setForm({ ...form, rate_header: e.target.value })} placeholder={form.rate_key === 'user_id' ? 'X-User-ID' : 'X-API-Key'} disabled={form.rate_key !== 'header' && form.rate_key !== 'user_id'} />
              </div>
            </div>
          )}
          {form.limit_type === 'advanced' && (
            <>
              <div>
                <LabelWithTooltip tooltip={t('pages:rateLimits.tooltips.expression')} className="label">{t('pages:rateLimits.modal.expression')}</LabelWithTooltip>
                <textarea className="input" rows={2} value={form.expression} onChange={e => setForm({ ...form, expression: e.target.value })} />
              </div>
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <LabelWithTooltip tooltip={t('pages:rateLimits.tooltips.advancedResponseCode')} className="label">{t('pages:rateLimits.modal.responseCode')}</LabelWithTooltip>
                  <input className="input" value={form.response_code} onChange={e => setForm({ ...form, response_code: e.target.value })} />
                </div>
                <div>
                  <LabelWithTooltip tooltip={t('pages:rateLimits.tooltips.urlPath')} className="label">{t('pages:rateLimits.modal.urlPath')}</LabelWithTooltip>
                  <input className="input" value={form.url_path} onChange={e => setForm({ ...form, url_path: e.target.value })} />
                </div>
                <div>
                  <LabelWithTooltip tooltip={t('pages:rateLimits.tooltips.userAgent')} className="label">{t('pages:rateLimits.modal.userAgent')}</LabelWithTooltip>
                  <input className="input" value={form.user_agent} onChange={e => setForm({ ...form, user_agent: e.target.value })} />
                </div>
              </div>
            </>
          )}
          {form.limit_type === 'waf' && (
            <div className="grid grid-cols-3 gap-3">
              <div>
                <LabelWithTooltip tooltip={t('pages:rateLimits.tooltips.wafThreshold')} className="label">{t('pages:rateLimits.modal.wafThreshold')}</LabelWithTooltip>
                <input type="number" className="input" value={form.waf_event_threshold} onChange={e => setForm({ ...form, waf_event_threshold: Number(e.target.value) })} />
              </div>
              <div>
                <LabelWithTooltip tooltip={t('pages:rateLimits.tooltips.wafWindow')} className="label">{t('pages:rateLimits.modal.window')}</LabelWithTooltip>
                <input type="number" className="input" value={form.waf_window_seconds} onChange={e => setForm({ ...form, waf_window_seconds: Number(e.target.value) })} />
              </div>
              <div>
                <LabelWithTooltip tooltip={t('pages:rateLimits.tooltips.wafBlockDuration')} className="label">{t('pages:rateLimits.modal.blockDuration')}</LabelWithTooltip>
                <input type="number" className="input" value={form.waf_block_duration} onChange={e => setForm({ ...form, waf_block_duration: Number(e.target.value) })} />
              </div>
            </div>
          )}
          {form.limit_type === 'response_code' && (
            <div className="space-y-2">
              <p className="text-sm text-slate-400">{t('pages:rateLimits.responseCodeDescription', { events: form.events, statusCode: form.match_status_code, window: form.window_seconds })}</p>
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <LabelWithTooltip tooltip={t('pages:rateLimits.tooltips.matchStatusCode')} className="label">{t('pages:rateLimits.modal.matchStatusCode')}</LabelWithTooltip>
                  <input type="number" className="input" value={form.match_status_code} onChange={e => setForm({ ...form, match_status_code: Number(e.target.value) })} placeholder="404" />
                </div>
                <div>
                  <LabelWithTooltip tooltip={t('pages:rateLimits.tooltips.blockStatusCode')} className="label">{t('pages:rateLimits.modal.blockStatusCode')}</LabelWithTooltip>
                  <input type="number" className="input" value={form.response_code} onChange={e => setForm({ ...form, response_code: e.target.value ? Number(e.target.value) : '' })} placeholder="429" />
                </div>
              </div>
            </div>
          )}
          <button className="btn-primary w-full">{t('pages:rateLimits.modal.save')}</button>
        </form>
      </Modal>
    </div>
  )
}
