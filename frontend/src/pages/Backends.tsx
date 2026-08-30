import React, { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Pencil, Trash2, PcCase } from 'lucide-react'
import InfoTooltip from '../components/InfoTooltip'
import { backends, certificates, fcgiApps, getErrorDetail, settings, cache } from '../services/api'
import useApiList from '../hooks/useApiList'
import Modal from '../components/Modal'
import { IconButton } from '../components/ui'
import LabelWithTooltip from '../components/LabelWithTooltip'
import HaproxyOptionsEditor, { HaproxyOption } from '../components/HaproxyOptionsEditor'

const initialBackend = { name: '', mode: 'http', protocol: 'http', algorithm: 'roundrobin', sticky_sessions: false, cookie_name: '', balance_args: '', health_check_enabled: true, health_check_interval: 2000, health_check_uri: '/', health_check_method: 'GET', health_check_expect_status: '', health_check_expect_body: '', retries: 3, redispatch: false, timeout_queue: null, timeout_check: null, timeout_tunnel: null, http_reuse: null as any, fullconn: null, stick_table: false, stick_table_size: '1m', stick_table_expire: '30m', stick_table_type: 'ip', resolvers: '', host_header: '', restore_client_ip: false, client_ip_header: 'X-Forwarded-For', fcgi_app_id: null as number | null, options: { compression_algorithm: 'none' } as any, haproxy_options: [] as HaproxyOption[] }
const initialServer = { name: '', address: '127.0.0.1', port: 80, weight: 100, maxconn: 1000, check: true, backup: false, inter: null, rise: null, fall: null, slowstart: null, maxqueue: null, ssl: false, verify: 'none', verifyhost: '', ca_certificate_id: null as number | null, client_certificate_id: null as number | null, ciphers: '', alpn: '', sni: '', check_ssl: false, check_sni: '', check_port: null, send_proxy: false, send_proxy_v2: false, resolve: false, init_addr: '', agent_check: false, agent_port: null, track: '', protocol: 'http' }

export default function Backends() {
  const { t } = useTranslation(['pages', 'common'])
  const { items, reload, loading } = useApiList(backends.list)
  const { items: fcgiAppList } = useApiList(fcgiApps.list)
  const { items: certList, loading: certsLoading } = useApiList(certificates.list)
  const [open, setOpen] = useState(false)
  const [editing, setEditing] = useState<number | null>(null)
  const [form, setForm] = useState<any>(initialBackend)

  const [managerOpen, setManagerOpen] = useState(false)
  const [serverFormOpen, setServerFormOpen] = useState(false)
  const [serverEditing, setServerEditing] = useState<number | null>(null)
  const [serverForm, setServerForm] = useState<any>(initialServer)
  const [serverAdvancedOpen, setServerAdvancedOpen] = useState(false)
  const [activeBackend, setActiveBackend] = useState<any>(null)
  const [serverPoolId, setServerPoolId] = useState<number | null>(null)

  const isTcp = form.protocol === 'tcp'
  const cookieNameRequired = form.sticky_sessions || (form.stick_table && form.stick_table_type === 'cookie')

  // Compression module toggle (fetched from settings to gate the algorithm dropdown)
  const [compressionEnabled, setCompressionEnabled] = useState(false)
  useEffect(() => {
    settings.get('compression_enabled')
      .then((r) => setCompressionEnabled((r.data.value || 'false').toLowerCase() === 'true'))
      .catch(() => setCompressionEnabled(false))
  }, [])

  // Image conversion module toggle (fetched from settings to gate per-backend options)
  const [img2WebpEnabled, setImg2WebpEnabled] = useState(false)
  useEffect(() => {
    settings.get('img_2_webp_enabled')
      .then((r) => setImg2WebpEnabled((r.data.value || 'false').toLowerCase() === 'true'))
      .catch(() => setImg2WebpEnabled(false))
  }, [])

  // Cache configs (for the read-only cache badge column)
  const [cacheConfigs, setCacheConfigs] = useState<Record<number, any>>({})
  useEffect(() => {
    cache.listConfigs()
      .then((r) => {
        const map: Record<number, any> = {}
        for (const cc of r.data) map[cc.backend_id] = cc
        setCacheConfigs(map)
      })
      .catch(() => {})
  }, [items])

  useEffect(() => {
    if (!activeBackend) return
    const updated = items.find((b: any) => b.id === activeBackend.id)
    if (updated) setActiveBackend(updated)
  }, [items])

  const resetBackend = () => setForm(initialBackend)
  const resetServer = () => setServerForm(initialServer)

  const openAdd = () => { setEditing(null); resetBackend(); setOpen(true) }
  const openEdit = (b: any) => { setEditing(b.id); setForm({ ...initialBackend, ...b, options: { ...(b.options || {}), compression_algorithm: b.options?.compression_algorithm || 'none' }, health_check_method: b.health_check_method || 'GET', retries: b.retries ?? 3, redispatch: b.redispatch ?? false, stick_table: b.stick_table ?? false, stick_table_size: b.stick_table_size || '1m', stick_table_expire: b.stick_table_expire || '30m', stick_table_type: b.stick_table_type || 'ip', host_header: b.host_header || '', restore_client_ip: b.restore_client_ip ?? false, client_ip_header: b.client_ip_header || 'X-Forwarded-For', fcgi_app_id: b.fcgi_app_id || null, haproxy_options: b.haproxy_options || [] }); setOpen(true) }

  const submitBackend = async (e: React.FormEvent) => {
    e.preventDefault()
    if (form.sticky_sessions && !form.cookie_name) {
      alert(t('pages:backends.errors.cookieNameRequiredSticky'))
      return
    }
    if (form.stick_table && form.stick_table_type === 'cookie' && !form.cookie_name) {
      alert(t('pages:backends.errors.cookieNameRequiredStickTable'))
      return
    }
    if (form.protocol === 'tcp' && form.sticky_sessions) {
      alert(t('pages:backends.errors.stickyNotSupportedTcp'))
      return
    }
    if (form.protocol === 'tcp' && form.stick_table && form.stick_table_type === 'cookie') {
      alert(t('pages:backends.errors.cookieStickTableNotSupportedTcp'))
      return
    }
    const payload = { ...form, mode: form.protocol === 'tcp' ? 'tcp' : 'http' } as any
    if (!payload.http_reuse) payload.http_reuse = null
    try {
      if (editing) await backends.update(editing, payload)
      else await backends.create(payload)
      setOpen(false)
      resetBackend()
      setEditing(null)
      reload()
    } catch (err) {
      alert(getErrorDetail(err, t('pages:backends.errors.failedToSaveBackend')))
    }
  }
  const openServerManager = (b: any) => { setActiveBackend(b); setManagerOpen(true) }
  const openAddServer = () => { setServerEditing(null); resetServer(); setServerAdvancedOpen(false); setServerFormOpen(true) }
  const openAddServerGlobal = () => { setServerEditing(null); resetServer(); setServerAdvancedOpen(false); setActiveBackend(null); setServerPoolId(null); setServerFormOpen(true) }
  const openEditServer = (s: any) => { setServerEditing(s.id); setServerAdvancedOpen(false); setServerForm({ ...initialServer, ...s, ca_file: undefined, client_cert: undefined, check: s.check ?? true, backup: s.backup ?? false, ssl: s.ssl ?? false, check_ssl: s.check_ssl ?? false, verify: s.verify || 'none', protocol: s.protocol || 'http' }); setServerFormOpen(true) }

  const submitServer = async (e: React.FormEvent) => {
    e.preventDefault()
    try {
      if (serverEditing) await backends.updateServer(serverEditing, serverForm)
      else if (activeBackend) await backends.addServer(activeBackend.id, serverForm)
      else if (serverPoolId) await backends.addServer(serverPoolId, serverForm)
      setServerFormOpen(false)
      resetServer()
      setServerEditing(null)
      setServerPoolId(null)
      reload()
    } catch (err) {
      alert(getErrorDetail(err, t('common:errors.saveFailed')))
    }
  }
  const deleteServer = (s: any) => backends.removeServer(s.id).then(reload)

  return (
    <div className="space-y-6">
      <div className="space-y-4">
        <div className="flex items-center justify-between">
          <h3 className="text-xl font-bold">{t('pages:loadBalancing.sections.backendPools')}</h3>
          <button onClick={openAdd} className="btn-primary">{t('pages:backends.addBackend')}</button>
        </div>
      {loading ? <p>{t('pages:backends.loading')}</p> : (
        <div className="card overflow-x-auto">
          <table className="w-full text-sm text-start">
            <thead className="text-slate-400 border-b border-slate-800"><tr><th>{t('pages:backends.tableHeaders.name')}</th><th>{t('pages:backends.tableHeaders.mode')}</th><th>{t('pages:backends.tableHeaders.algorithm')}</th><th>{t('pages:backends.tableHeaders.fcgiApp')}</th><th>{t('pages:backends.tableHeaders.sticky')}</th><th>{t('pages:backends.tableHeaders.servers')}</th><th>{t('pages:backends.tableHeaders.cache')}</th><th></th></tr></thead>
            <tbody>
              {[...items].sort((a: any, b: any) => (a.name || '').localeCompare(b.name || '')).map((b: any) => {
                const cc = cacheConfigs[b.id]
                const cacheBadge = cc ? (
                  cc.haproxy_enabled && cc.disk_cache_enabled
                    ? <span className="text-xs px-1.5 py-0.5 rounded bg-purple-900/50 text-purple-300">Memory + Disk</span>
                    : cc.haproxy_enabled
                    ? <span className="text-xs px-1.5 py-0.5 rounded bg-blue-900/50 text-blue-300">Memory</span>
                    : cc.disk_cache_enabled
                    ? <span className="text-xs px-1.5 py-0.5 rounded bg-green-900/50 text-green-300">Disk</span>
                    : <span className="text-slate-500">-</span>
                ) : <span className="text-slate-500">-</span>
                return (
                <tr key={b.id} className="border-b border-slate-800 last:border-0">
                  <td className="py-2">{b.name}</td><td>{b.mode}</td><td>{b.algorithm}</td><td>{fcgiAppList.find((f: any) => f.id === b.fcgi_app_id)?.name || '-'}</td><td>{b.sticky_sessions ? 'Yes' : 'No'}</td><td>{(b.servers || []).length}</td><td>{cacheBadge}</td>
                  <td>
                    <div className="flex gap-1">
                      <IconButton icon={Pencil} aria-label="Edit" onClick={() => openEdit(b)} />
                      <IconButton icon={PcCase} aria-label="Manage servers" onClick={() => openServerManager(b)} />
                      <IconButton icon={Trash2} variant="danger" aria-label="Delete" onClick={() => backends.remove(b.id).then(reload)} />
                    </div>
                  </td>
                </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      )}
      </div>

      <div className="space-y-4">
        <div className="flex items-center justify-between">
          <h3 className="text-xl font-bold">{t('pages:loadBalancing.sections.backendServers')}</h3>
          {items.length > 0 && <button onClick={openAddServerGlobal} className="btn-primary">{t('pages:backends.serverManager.addServer')}</button>}
        </div>
        <div className="card overflow-x-auto">
          <table className="w-full text-sm text-start">
            <thead className="text-slate-400 border-b border-slate-800"><tr><th>{t('pages:backends.serverTableHeaders.pool')}</th><th>{t('pages:backends.serverTableHeaders.name')}</th><th>{t('pages:backends.serverTableHeaders.address')}</th><th>{t('pages:backends.serverTableHeaders.port')}</th><th>{t('pages:backends.serverTableHeaders.protocol')}</th><th>{t('pages:backends.serverTableHeaders.weight')}</th><th>{t('pages:backends.serverTableHeaders.maxconn')}</th><th>{t('pages:backends.serverTableHeaders.check')}</th><th>{t('pages:backends.serverTableHeaders.backup')}</th><th>{t('pages:backends.serverTableHeaders.ssl')}</th><th>{t('pages:backends.serverTableHeaders.proxy')}</th><th></th></tr></thead>
            <tbody>
              {items.flatMap((b: any) => (b.servers || []).map((s: any) => ({ ...s, poolName: b.name }))).sort((a: any, b: any) => {
                const pc = (a.poolName || '').localeCompare(b.poolName || '')
                return pc !== 0 ? pc : (a.name || '').localeCompare(b.name || '')
              }).map((s: any) => (
                <tr key={s.id} className="border-b border-slate-800 last:border-0">
                  <td className="py-2">{s.poolName}</td>
                  <td>{s.name}</td><td>{s.address}</td><td>{s.port}</td><td>{s.protocol}</td><td>{s.weight}</td><td>{s.maxconn}</td><td>{s.check ? t('common:actions.yes') : t('common:actions.no')}</td><td>{s.backup ? t('common:actions.yes') : t('common:actions.no')}</td><td>{s.ssl ? t('common:actions.yes') : t('common:actions.no')}</td><td>{s.send_proxy ? 'v1' : s.send_proxy_v2 ? 'v2' : '-'}</td>
                  <td>
                    <div className="flex gap-1">
                      <IconButton icon={Pencil} aria-label={t('common:actions.edit')} onClick={() => openEditServer(s)} />
                      <IconButton icon={Trash2} variant="danger" aria-label={t('common:actions.delete')} onClick={() => deleteServer(s)} />
                    </div>
                  </td>
                </tr>
              ))}
              {items.flatMap((b: any) => b.servers || []).length === 0 && (
                <tr><td colSpan={12} className="py-4 text-center text-slate-500">{t('pages:backends.noServers')}</td></tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      <Modal open={open} onClose={() => setOpen(false)} title={editing ? t('pages:backends.modal.editTitle') : t('pages:backends.modal.addTitle')}>
        <form onSubmit={submitBackend} className="space-y-3">
          <div className="grid grid-cols-2 gap-3">
            <div><LabelWithTooltip tooltip={t('pages:backends.tooltips.name')}>{t('pages:backends.modal.name')}</LabelWithTooltip><input className="input" value={form.name} onChange={e => setForm({ ...form, name: e.target.value })} /></div>
            <div><LabelWithTooltip tooltip={t('pages:backends.tooltips.protocol')}>{t('pages:backends.modal.protocol')}</LabelWithTooltip><select className="input" value={form.protocol} onChange={e => {
              const protocol = e.target.value
              const updates: any = { protocol }
              if (protocol === 'tcp') {
                if (form.sticky_sessions) updates.sticky_sessions = false
                if (form.stick_table && form.stick_table_type === 'cookie') updates.stick_table_type = 'ip'
              }
              setForm({ ...form, ...updates })
            }}><option value="http">HTTP</option><option value="tcp">TCP</option><option value="grpc">gRPC</option><option value="jsonrpc">JSON-RPC</option><option value="fastcgi">FastCGI</option></select></div>
            <div><LabelWithTooltip tooltip={t('pages:backends.tooltips.fcgiApp')}>{t('pages:backends.modal.fcgiApp')}</LabelWithTooltip><select className="input" value={form.fcgi_app_id || ''} onChange={e => setForm({ ...form, fcgi_app_id: e.target.value ? Number(e.target.value) : null })}><option value="">{t('pages:backends.serverManager.none')}</option>{fcgiAppList.map((f: any) => <option key={f.id} value={f.id}>{f.name}</option>)}</select></div>
            <div><LabelWithTooltip tooltip={t('pages:backends.tooltips.algorithm')}>{t('pages:backends.modal.algorithm')}</LabelWithTooltip><select className="input" value={form.algorithm} onChange={e => setForm({ ...form, algorithm: e.target.value })}><option>roundrobin</option><option>leastconn</option><option>source</option><option>uri</option><option>static-rr</option><option>random</option><option>first</option><option>hdr</option><option>url_param</option><option>rdp-cookie</option></select></div>
            <div><LabelWithTooltip tooltip={t('pages:backends.tooltips.balanceArgs')}>{t('pages:backends.modal.balanceArgs')}</LabelWithTooltip><input className="input" placeholder={t('pages:backends.modal.balanceArgsPlaceholder')} value={form.balance_args || ''} onChange={e => setForm({ ...form, balance_args: e.target.value })} /></div>
            <div><LabelWithTooltip tooltip={t('pages:backends.tooltips.healthCheckMethod')}>{t('pages:backends.modal.healthCheckMethod')}</LabelWithTooltip><select className="input" value={form.health_check_method} onChange={e => setForm({ ...form, health_check_method: e.target.value })}><option>GET</option><option>POST</option><option>HEAD</option><option>PUT</option><option>DELETE</option></select></div>
            <div><LabelWithTooltip tooltip={t('pages:backends.tooltips.healthCheckUri')}>{t('pages:backends.modal.healthCheckUri')}</LabelWithTooltip><input className="input" value={form.health_check_uri} onChange={e => setForm({ ...form, health_check_uri: e.target.value })} /></div>
            <div><LabelWithTooltip tooltip={t('pages:backends.tooltips.expectStatus')}>{t('pages:backends.modal.expectStatus')}</LabelWithTooltip><input className="input" value={form.health_check_expect_status || ''} onChange={e => setForm({ ...form, health_check_expect_status: e.target.value })} /></div>
            <div><LabelWithTooltip tooltip={t('pages:backends.tooltips.expectBody')}>{t('pages:backends.modal.expectBody')}</LabelWithTooltip><input className="input" value={form.health_check_expect_body || ''} onChange={e => setForm({ ...form, health_check_expect_body: e.target.value })} /></div>
            <div><LabelWithTooltip tooltip={t('pages:backends.tooltips.cookieName')}>{cookieNameRequired ? t('pages:backends.modal.cookieNameRequired') : t('pages:backends.modal.cookieName')}</LabelWithTooltip><input className={`input ${cookieNameRequired && !form.cookie_name ? 'border-red-500' : ''}`} value={form.cookie_name} onChange={e => setForm({ ...form, cookie_name: e.target.value })} /></div>
            <div><LabelWithTooltip tooltip={t('pages:backends.tooltips.healthInterval')}>{t('pages:backends.modal.healthInterval')}</LabelWithTooltip><input type="number" className="input" value={form.health_check_interval} onChange={e => setForm({ ...form, health_check_interval: Number(e.target.value) })} /></div>
            <div><LabelWithTooltip tooltip={t('pages:backends.tooltips.retries')}>{t('pages:backends.modal.retries')}</LabelWithTooltip><input type="number" className="input" value={form.retries} onChange={e => setForm({ ...form, retries: Number(e.target.value) })} /></div>
            <div><LabelWithTooltip tooltip={t('pages:backends.tooltips.timeoutQueue')}>{t('pages:backends.modal.timeoutQueue')}</LabelWithTooltip><input type="number" className="input" value={form.timeout_queue || ''} onChange={e => setForm({ ...form, timeout_queue: e.target.value ? Number(e.target.value) : null })} /></div>
            <div><LabelWithTooltip tooltip={t('pages:backends.tooltips.timeoutCheck')}>{t('pages:backends.modal.timeoutCheck')}</LabelWithTooltip><input type="number" className="input" value={form.timeout_check || ''} onChange={e => setForm({ ...form, timeout_check: e.target.value ? Number(e.target.value) : null })} /></div>
            <div><LabelWithTooltip tooltip={t('pages:backends.tooltips.timeoutTunnel')}>{t('pages:backends.modal.timeoutTunnel')}</LabelWithTooltip><input type="number" className="input" value={form.timeout_tunnel || ''} onChange={e => setForm({ ...form, timeout_tunnel: e.target.value ? Number(e.target.value) : null })} /></div>
            <div><LabelWithTooltip tooltip={t('pages:backends.tooltips.httpReuse')}>{t('pages:backends.modal.httpReuse')}</LabelWithTooltip><select className="input" value={form.http_reuse || ''} onChange={e => setForm({ ...form, http_reuse: e.target.value })}><option value="">default</option><option value="aggressive">aggressive</option><option value="safe">safe</option><option value="never">never</option></select></div>
            <div><LabelWithTooltip tooltip={t('pages:backends.tooltips.fullconn')}>{t('pages:backends.modal.fullconn')}</LabelWithTooltip><input type="number" className="input" value={form.fullconn || ''} onChange={e => setForm({ ...form, fullconn: e.target.value ? Number(e.target.value) : null })} /></div>
            <div><LabelWithTooltip tooltip={t('pages:backends.tooltips.stickTableSize')}>{t('pages:backends.modal.stickTableSize')}</LabelWithTooltip><input className="input" disabled={!form.stick_table} value={form.stick_table_size || ''} onChange={e => setForm({ ...form, stick_table_size: e.target.value })} /></div>
            <div><LabelWithTooltip tooltip={t('pages:backends.tooltips.stickTableExpire')}>{t('pages:backends.modal.stickTableExpire')}</LabelWithTooltip><input className="input" disabled={!form.stick_table} value={form.stick_table_expire || ''} onChange={e => setForm({ ...form, stick_table_expire: e.target.value })} /></div>
            <div><LabelWithTooltip tooltip={t('pages:backends.tooltips.stickTableType')}>{t('pages:backends.modal.stickTableType')}</LabelWithTooltip><select className="input" disabled={!form.stick_table} value={form.stick_table_type || ''} onChange={e => setForm({ ...form, stick_table_type: e.target.value })}><option>ip</option><option disabled={isTcp}>cookie</option><option>binary</option><option>integer</option><option>string</option></select></div>
            <div><LabelWithTooltip tooltip={t('pages:backends.tooltips.resolvers')}>{t('pages:backends.modal.resolvers')}</LabelWithTooltip><input className="input" value={form.resolvers || ''} onChange={e => setForm({ ...form, resolvers: e.target.value })} /></div>
            <div><LabelWithTooltip tooltip={t('pages:backends.tooltips.hostHeader')}>{t('pages:backends.modal.hostHeader')}</LabelWithTooltip><input className="input" placeholder={t('pages:backends.modal.hostHeaderPlaceholder')} value={form.host_header || ''} onChange={e => setForm({ ...form, host_header: e.target.value })} /></div>
            {!isTcp && (
              <div><LabelWithTooltip tooltip={t('pages:backends.tooltips.clientIpHeader')}>{t('pages:backends.modal.clientIpHeader')}</LabelWithTooltip><input className="input" disabled={!form.restore_client_ip} placeholder={t('pages:backends.modal.clientIpHeaderPlaceholder')} value={form.client_ip_header || ''} onChange={e => setForm({ ...form, client_ip_header: e.target.value })} /></div>
            )}
          </div>
          <div className="flex gap-4 flex-wrap">
            <label className={`flex items-center gap-2 ${isTcp && !form.sticky_sessions ? 'text-slate-500' : ''}`}><input type="checkbox" disabled={isTcp && !form.sticky_sessions} checked={form.sticky_sessions} onChange={e => setForm({ ...form, sticky_sessions: e.target.checked })} /> {t('pages:backends.modal.stickySessions')}<InfoTooltip content={t('pages:backends.tooltips.stickySessions')} /></label>
            <label className="flex items-center gap-2"><input type="checkbox" checked={form.redispatch} onChange={e => setForm({ ...form, redispatch: e.target.checked })} /> {t('pages:backends.modal.redispatch')}<InfoTooltip content={t('pages:backends.tooltips.redispatch')} /></label>
            <label className="flex items-center gap-2"><input type="checkbox" checked={form.stick_table} onChange={e => setForm({ ...form, stick_table: e.target.checked })} /> {t('pages:backends.modal.stickTable')}<InfoTooltip content={t('pages:backends.tooltips.stickTable')} /></label>
            {!isTcp && (
              <label className="flex items-center gap-2"><input type="checkbox" checked={form.restore_client_ip} onChange={e => setForm({ ...form, restore_client_ip: e.target.checked })} /> {t('pages:backends.modal.restoreClientIp')}<InfoTooltip content={t('pages:backends.tooltips.restoreClientIp')} /></label>
            )}
          </div>
          {form.restore_client_ip && !isTcp && (
            <p className="text-xs text-amber-400">{t('pages:backends.modal.restoreClientIpWarning')}</p>
          )}
          {(form.algorithm === 'source' && form.stick_table && form.stick_table_type === 'ip') && (
            <p className="text-xs text-amber-400">{t('pages:backends.modal.sourceStickTableRedundant')}</p>
          )}
          {(form.sticky_sessions && form.stick_table && form.stick_table_type === 'cookie') && (
            <p className="text-xs text-amber-400">{t('pages:backends.modal.stickyCookieRedundant')}</p>
          )}
          {form.protocol === 'http' && (
            <div className="border-t border-slate-800 pt-3 space-y-3">
              <h3 className="text-sm font-semibold text-slate-300">{t('pages:backends.compression.title')}</h3>
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <LabelWithTooltip tooltip={t('pages:backends.tooltips.compressionAlgorithm')}>{t('pages:backends.compression.algorithm')}</LabelWithTooltip>
                  <select
                    className="input"
                    value={form.options?.compression_algorithm || 'none'}
                    onChange={e => setForm({ ...form, options: { ...form.options, compression_algorithm: e.target.value } })}
                  >
                    <option value="none">{t('pages:backends.compression.algorithmNone')}</option>
                    {compressionEnabled && <option value="zstd">{t('pages:backends.compression.algorithmZstd')}</option>}
                    <option value="gzip">{t('pages:backends.compression.algorithmGzip')}</option>
                    <option value="deflate">{t('pages:backends.compression.algorithmDeflate')}</option>
                    <option value="raw-deflate">{t('pages:backends.compression.algorithmRawDeflate')}</option>
                    {compressionEnabled && <option value="brotli">{t('pages:backends.compression.algorithmBrotli')}</option>}
                  </select>
                </div>
                <div>
                  <LabelWithTooltip tooltip={t('pages:backends.tooltips.compressionLevelQuality')}>
                    {form.options?.compression_algorithm === 'zstd' ? t('pages:backends.compression.levelQuality') : t('pages:backends.compression.quality')}
                  </LabelWithTooltip>
                  <input
                    type="number"
                    className="input"
                    min={form.options?.compression_algorithm === 'zstd' ? 1 : 0}
                    max={form.options?.compression_algorithm === 'zstd' ? 22 : 11}
                    value={form.options?.compression_quality ?? (form.options?.compression_algorithm === 'zstd' ? 3 : 5)}
                    onChange={e => {
                      const key = form.options?.compression_algorithm === 'zstd' ? 'compression_level' : 'compression_quality'
                      setForm({ ...form, options: { ...form.options, [key]: Number(e.target.value) } })
                    }}
                    disabled={['none', 'gzip', 'deflate', 'raw-deflate'].includes(form.options?.compression_algorithm || 'none')}
                  />
                </div>
                <div className="col-span-2">
                  <LabelWithTooltip tooltip={t('pages:backends.tooltips.compressionContentTypes')}>{t('pages:backends.compression.contentTypes')}</LabelWithTooltip>
                  <input
                    className="input"
                    placeholder={t('pages:backends.compression.contentTypesPlaceholder')}
                    value={form.options?.compression_content_types || ''}
                    onChange={e => setForm({ ...form, options: { ...form.options, compression_content_types: e.target.value } })}
                    disabled={!form.options?.compression_algorithm || form.options?.compression_algorithm === 'none'}
                  />
                </div>
                {form.options?.compression_algorithm === 'brotli' && (
                  <div>
                    <LabelWithTooltip tooltip={t('pages:backends.tooltips.compressionWindow')}>{t('pages:backends.compression.window')}</LabelWithTooltip>
                    <input
                      type="number"
                      className="input"
                      min={10}
                      max={24}
                      value={form.options?.compression_window ?? 22}
                      onChange={e => setForm({ ...form, options: { ...form.options, compression_window: Number(e.target.value) } })}
                    />
                  </div>
                )}
                <label className="flex items-center gap-2 col-span-2">
                  <input
                    type="checkbox"
                    checked={!!form.options?.compression_offload}
                    onChange={e => setForm({ ...form, options: { ...form.options, compression_offload: e.target.checked } })}
                    disabled={!form.options?.compression_algorithm || form.options?.compression_algorithm === 'none'}
                  />
                  <span className="text-sm">{t('pages:backends.compression.offload')}</span>
                  <InfoTooltip content={t('pages:backends.tooltips.compressionOffload')} />
                </label>
              </div>
              {form.options?.compression_algorithm && !['none', 'gzip', 'deflate', 'raw-deflate'].includes(form.options?.compression_algorithm) && !compressionEnabled && (
                <p className="text-xs text-amber-400">
                  {t('pages:backends.compression.notEnabledWarning', { algorithm: form.options?.compression_algorithm === 'brotli' ? t('pages:backends.compression.algorithmBrotli') : t('pages:backends.compression.algorithmZstd') })}
                </p>
              )}
            </div>
          )}
          {form.protocol === 'http' && img2WebpEnabled && (
            <div className="border-t border-slate-800 pt-3 space-y-3">
              <h3 className="text-sm font-semibold text-slate-300">{t('pages:backends.imageConversion.title')}</h3>
              <label className="flex items-center gap-2">
                <input
                  type="checkbox"
                  checked={!!form.options?.img_2_webp_enabled}
                  onChange={e => setForm({ ...form, options: { ...form.options, img_2_webp_enabled: e.target.checked } })}
                />
                <span className="text-sm">{t('pages:backends.imageConversion.description')}</span>
              </label>
              {form.options?.img_2_webp_enabled && (
                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <LabelWithTooltip tooltip={t('pages:backends.imageConversion.qualityHelp')}>{t('pages:backends.imageConversion.quality')}</LabelWithTooltip>
                    <input
                      type="number"
                      className="input"
                      min={0}
                      max={100}
                      value={form.options?.img_2_webp_quality ?? 80}
                      onChange={e => setForm({ ...form, options: { ...form.options, img_2_webp_quality: Number(e.target.value) } })}
                    />
                  </div>
                  <div>
                    <LabelWithTooltip tooltip={t('pages:backends.imageConversion.maxDimensionHelp')}>{t('pages:backends.imageConversion.maxDimension')}</LabelWithTooltip>
                    <input
                      type="number"
                      className="input"
                      min={1}
                      value={form.options?.img_2_webp_max_dim ?? 4096}
                      onChange={e => setForm({ ...form, options: { ...form.options, img_2_webp_max_dim: Number(e.target.value) } })}
                    />
                  </div>
                  <div>
                    <LabelWithTooltip tooltip={t('pages:backends.imageConversion.maxFileSizeHelp')}>{t('pages:backends.imageConversion.maxFileSize')}</LabelWithTooltip>
                    <input
                      type="number"
                      className="input"
                      min={1}
                      value={form.options?.img_2_webp_max_size ?? 10000000}
                      onChange={e => setForm({ ...form, options: { ...form.options, img_2_webp_max_size: Number(e.target.value) } })}
                    />
                  </div>
                  <div>
                    <LabelWithTooltip tooltip={t('pages:backends.imageConversion.sourceTypesHelp')}>{t('pages:backends.imageConversion.sourceTypes')}</LabelWithTooltip>
                    <input
                      className="input"
                      placeholder={t('pages:backends.imageConversion.sourceTypesPlaceholder')}
                      value={form.options?.img_2_webp_source_types || ''}
                      onChange={e => setForm({ ...form, options: { ...form.options, img_2_webp_source_types: e.target.value } })}
                    />
                  </div>
                </div>
              )}
            </div>
          )}
          <HaproxyOptionsEditor
            scope="backend"
            value={form.haproxy_options || []}
            onChange={(opts) => setForm({ ...form, haproxy_options: opts })}
          />
          <button className="btn-primary w-full">{t('pages:backends.modal.save')}</button>
        </form>
      </Modal>

      {activeBackend && (
        <Modal open={managerOpen} onClose={() => setManagerOpen(false)} title={t('pages:backends.serverManager.title', { name: activeBackend.name })}>
          <div className="space-y-4">
            <button onClick={openAddServer} className="btn-primary">{t('pages:backends.serverManager.addServer')}</button>
            <div className="card overflow-x-auto">
              <table className="w-full text-sm text-start">
                <thead className="text-slate-400 border-b border-slate-800"><tr><th>{t('pages:backends.serverManager.tableHeaders.name')}</th><th>{t('pages:backends.serverManager.tableHeaders.address')}</th><th>{t('pages:backends.serverManager.tableHeaders.port')}</th><th>{t('pages:backends.serverManager.tableHeaders.protocol')}</th><th>{t('pages:backends.serverManager.tableHeaders.weight')}</th><th>{t('pages:backends.serverManager.tableHeaders.maxconn')}</th><th>{t('pages:backends.serverManager.tableHeaders.check')}</th><th>{t('pages:backends.serverManager.tableHeaders.backup')}</th><th>{t('pages:backends.serverManager.tableHeaders.inter')}</th><th>{t('pages:backends.serverManager.tableHeaders.rise')}</th><th>{t('pages:backends.serverManager.tableHeaders.fall')}</th><th>{t('pages:backends.serverManager.tableHeaders.ssl')}</th><th>{t('pages:backends.serverManager.tableHeaders.proxy')}</th><th></th></tr></thead>
                <tbody>
                  {(activeBackend.servers || []).map((s: any) => (
                    <tr key={s.id} className="border-b border-slate-800 last:border-0">
                      <td className="py-2">{s.name}</td><td>{s.address}</td><td>{s.port}</td><td>{s.protocol}</td><td>{s.weight}</td><td>{s.maxconn}</td><td>{s.check ? t('common:actions.yes') : t('common:actions.no')}</td><td>{s.backup ? t('common:actions.yes') : t('common:actions.no')}</td><td>{s.inter}</td><td>{s.rise}</td><td>{s.fall}</td><td>{s.ssl ? t('common:actions.yes') : t('common:actions.no')}</td><td>{s.send_proxy ? 'v1' : s.send_proxy_v2 ? 'v2' : '-'}</td>
                      <td>
                        <div className="flex gap-1">
                          <IconButton icon={Pencil} aria-label={t('common:actions.edit')} onClick={() => openEditServer(s)} />
                          <IconButton icon={Trash2} variant="danger" aria-label={t('common:actions.delete')} onClick={() => deleteServer(s)} />
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </Modal>
      )}

      <Modal open={serverFormOpen} onClose={() => setServerFormOpen(false)} title={serverEditing ? t('pages:backends.serverManager.editTitle') : t('pages:backends.serverManager.addTitle')}>
        <form onSubmit={submitServer} className="space-y-3">
          {!serverEditing && !activeBackend && (
            <div>
              <LabelWithTooltip tooltip={t('pages:backends.serverManager.backendPoolHelp')}>{t('pages:backends.serverManager.backendPool')}</LabelWithTooltip>
              <select className="input" value={serverPoolId ?? ''} onChange={e => setServerPoolId(e.target.value ? Number(e.target.value) : null)}>
                <option value="">{t('pages:backends.serverManager.selectPool')}</option>
                {items.map((b: any) => <option key={b.id} value={b.id}>{b.name}</option>)}
              </select>
            </div>
          )}
          <div className="grid grid-cols-2 gap-3">
            <div>
              <LabelWithTooltip tooltip={t('pages:backends.tooltips.serverName')}>{t('pages:backends.serverManager.name')}</LabelWithTooltip>
              <input className="input" value={serverForm.name} onChange={e => setServerForm({ ...serverForm, name: e.target.value })} />
            </div>
            <div>
              <LabelWithTooltip tooltip={t('pages:backends.tooltips.serverAddress')}>{t('pages:backends.serverManager.address')}</LabelWithTooltip>
              <input className="input" value={serverForm.address} onChange={e => setServerForm({ ...serverForm, address: e.target.value })} />
            </div>
            <div>
              <LabelWithTooltip tooltip={t('pages:backends.tooltips.serverPort')}>{t('pages:backends.serverManager.port')}</LabelWithTooltip>
              <input type="number" className="input" value={serverForm.port} onChange={e => setServerForm({ ...serverForm, port: Number(e.target.value) })} />
            </div>
            <div>
              <LabelWithTooltip tooltip={t('pages:backends.tooltips.serverWeight')}>{t('pages:backends.serverManager.weight')}</LabelWithTooltip>
              <input type="number" className="input" value={serverForm.weight} onChange={e => setServerForm({ ...serverForm, weight: Number(e.target.value) })} />
            </div>
            <div>
              <LabelWithTooltip tooltip={t('pages:backends.tooltips.serverMaxconn')}>{t('pages:backends.serverManager.maxconn')}</LabelWithTooltip>
              <input type="number" className="input" value={serverForm.maxconn} onChange={e => setServerForm({ ...serverForm, maxconn: Number(e.target.value) })} />
            </div>
            <div>
              <LabelWithTooltip tooltip={t('pages:backends.tooltips.serverProtocol')}>{t('pages:backends.serverManager.protocol')}</LabelWithTooltip>
              <select className="input" value={serverForm.protocol} onChange={e => setServerForm({ ...serverForm, protocol: e.target.value })}>
                <option value="http">HTTP</option>
                <option value="tcp">TCP</option>
                <option value="grpc">gRPC</option>
                <option value="jsonrpc">JSON-RPC</option>
                <option value="fastcgi">FastCGI</option>
              </select>
            </div>
          </div>
          <div className="flex gap-4 flex-wrap">
            <label className="flex items-center gap-2">
              <input type="checkbox" checked={serverForm.check} onChange={e => setServerForm({ ...serverForm, check: e.target.checked })} />
              <span>{t('pages:backends.serverManager.check')}</span>
              <InfoTooltip content={t('pages:backends.tooltips.serverCheck')} />
            </label>
            <label className="flex items-center gap-2">
              <input type="checkbox" checked={serverForm.backup} onChange={e => setServerForm({ ...serverForm, backup: e.target.checked })} />
              <span>{t('pages:backends.serverManager.backup')}</span>
              <InfoTooltip content={t('pages:backends.tooltips.serverBackup')} />
            </label>
            <label className="flex items-center gap-2">
              <input type="checkbox" checked={serverForm.ssl} onChange={e => setServerForm({ ...serverForm, ssl: e.target.checked })} />
              <span>{t('pages:backends.serverManager.ssl')}</span>
              <InfoTooltip content={t('pages:backends.tooltips.serverSsl')} />
            </label>
          </div>

          <div className="border border-slate-700 rounded p-4 space-y-3">
            <div className="flex items-center justify-between">
              <div>
                <h3 className="text-sm font-semibold">{t('pages:backends.serverManager.advanced')}</h3>
                <p className="text-xs text-slate-500">
                  {t('pages:backends.serverManager.advancedDescription')}
                </p>
              </div>
              <button
                type="button"
                className="btn-secondary text-xs px-3 py-1"
                onClick={() => setServerAdvancedOpen(!serverAdvancedOpen)}
              >
                {serverAdvancedOpen ? t('pages:backends.serverManager.hide') : t('pages:backends.serverManager.show')}
              </button>
            </div>

            {serverAdvancedOpen && (
              <>
                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <LabelWithTooltip tooltip={t('pages:backends.tooltips.serverInter')}>{t('pages:backends.serverManager.interMs')}</LabelWithTooltip>
                    <input type="number" className="input" value={serverForm.inter || ''} onChange={e => setServerForm({ ...serverForm, inter: e.target.value ? Number(e.target.value) : null })} />
                  </div>
                  <div>
                    <LabelWithTooltip tooltip={t('pages:backends.tooltips.serverRise')}>{t('pages:backends.serverManager.rise')}</LabelWithTooltip>
                    <input type="number" className="input" value={serverForm.rise || ''} onChange={e => setServerForm({ ...serverForm, rise: e.target.value ? Number(e.target.value) : null })} />
                  </div>
                  <div>
                    <LabelWithTooltip tooltip={t('pages:backends.tooltips.serverFall')}>{t('pages:backends.serverManager.fall')}</LabelWithTooltip>
                    <input type="number" className="input" value={serverForm.fall || ''} onChange={e => setServerForm({ ...serverForm, fall: e.target.value ? Number(e.target.value) : null })} />
                  </div>
                  <div>
                    <LabelWithTooltip tooltip={t('pages:backends.tooltips.serverSlowstart')}>{t('pages:backends.serverManager.slowstartS')}</LabelWithTooltip>
                    <input type="number" className="input" value={serverForm.slowstart || ''} onChange={e => setServerForm({ ...serverForm, slowstart: e.target.value ? Number(e.target.value) : null })} />
                  </div>
                  <div>
                    <LabelWithTooltip tooltip={t('pages:backends.tooltips.serverMaxqueue')}>{t('pages:backends.serverManager.maxqueue')}</LabelWithTooltip>
                    <input type="number" className="input" value={serverForm.maxqueue || ''} onChange={e => setServerForm({ ...serverForm, maxqueue: e.target.value ? Number(e.target.value) : null })} />
                  </div>
                  <div>
                    <LabelWithTooltip tooltip={t('pages:backends.tooltips.serverVerify')}>{t('pages:backends.serverManager.verify')}</LabelWithTooltip>
                    <select className="input" value={serverForm.verify} onChange={e => setServerForm({ ...serverForm, verify: e.target.value })}>
                      <option value="none">none</option>
                      <option value="required">required</option>
                      <option value="optional">optional</option>
                    </select>
                  </div>
                  <div>
                    <LabelWithTooltip tooltip={t('pages:backends.tooltips.serverVerifyhost')}>{t('pages:backends.serverManager.verifyHost')}</LabelWithTooltip>
                    <input className="input" value={serverForm.verifyhost || ''} onChange={e => setServerForm({ ...serverForm, verifyhost: e.target.value })} />
                  </div>
                  <div>
                    <LabelWithTooltip tooltip={t('pages:backends.tooltips.serverCa_certificate')}>{t('pages:backends.serverManager.caFile')}</LabelWithTooltip>
                    <select
                      className="input"
                      value={serverForm.ca_certificate_id ? String(serverForm.ca_certificate_id) : ''}
                      onChange={e => {
                        const v = e.target.value
                        setServerForm({ ...serverForm, ca_certificate_id: v ? Number(v) : null })
                      }}
                    >
                      <option value="">{t('pages:backends.serverManager.none')}</option>
                      {certsLoading ? <option value="" disabled>{t('pages:backends.serverManager.loadingEllipsis')}</option> : certList.filter((c: any) => c.kind === 'ca').map((c: any) => <option key={c.id} value={String(c.id)}>{c.name}</option>)}
                    </select>
                  </div>
                  <div>
                    <LabelWithTooltip tooltip={t('pages:backends.tooltips.serverClient_certificate')}>{t('pages:backends.serverManager.clientCert')}</LabelWithTooltip>
                    <select
                      className="input"
                      value={serverForm.client_certificate_id ? String(serverForm.client_certificate_id) : ''}
                      onChange={e => {
                        const v = e.target.value
                        setServerForm({ ...serverForm, client_certificate_id: v ? Number(v) : null })
                      }}
                    >
                      <option value="">{t('pages:backends.serverManager.none')}</option>
                      {certsLoading ? <option value="" disabled>{t('pages:backends.serverManager.loadingEllipsis')}</option> : certList.filter((c: any) => c.kind === 'client').map((c: any) => <option key={c.id} value={String(c.id)}>{c.name}</option>)}
                    </select>
                  </div>
                  <div>
                    <LabelWithTooltip tooltip={t('pages:backends.tooltips.serverCiphers')}>{t('pages:backends.serverManager.ciphers')}</LabelWithTooltip>
                    <input className="input" value={serverForm.ciphers || ''} onChange={e => setServerForm({ ...serverForm, ciphers: e.target.value })} />
                  </div>
                  <div>
                    <LabelWithTooltip tooltip={t('pages:backends.tooltips.serverAlpn')}>{t('pages:backends.serverManager.alpn')}</LabelWithTooltip>
                    <input className="input" value={serverForm.alpn || ''} onChange={e => setServerForm({ ...serverForm, alpn: e.target.value })} />
                  </div>
                  <div>
                    <LabelWithTooltip tooltip={t('pages:backends.tooltips.serverSni')}>{t('pages:backends.serverManager.sni')}</LabelWithTooltip>
                    <input className="input" value={serverForm.sni || ''} onChange={e => setServerForm({ ...serverForm, sni: e.target.value })} />
                  </div>
                  <div>
                    <LabelWithTooltip tooltip={t('pages:backends.tooltips.serverCheck_sni')}>{t('pages:backends.serverManager.checkSni')}</LabelWithTooltip>
                    <input className="input" value={serverForm.check_sni || ''} onChange={e => setServerForm({ ...serverForm, check_sni: e.target.value })} />
                  </div>
                  <div>
                    <LabelWithTooltip tooltip={t('pages:backends.tooltips.serverCheck_port')}>{t('pages:backends.serverManager.checkPort')}</LabelWithTooltip>
                    <input type="number" className="input" value={serverForm.check_port || ''} onChange={e => setServerForm({ ...serverForm, check_port: e.target.value ? Number(e.target.value) : null })} />
                  </div>
                  <div>
                    <LabelWithTooltip tooltip={t('pages:backends.tooltips.serverAgent_port')}>{t('pages:backends.serverManager.agentPort')}</LabelWithTooltip>
                    <input type="number" className="input" value={serverForm.agent_port || ''} onChange={e => setServerForm({ ...serverForm, agent_port: e.target.value ? Number(e.target.value) : null })} />
                  </div>
                  <div>
                    <LabelWithTooltip tooltip={t('pages:backends.tooltips.serverInit_addr')}>{t('pages:backends.serverManager.initAddr')}</LabelWithTooltip>
                    <input className="input" value={serverForm.init_addr || ''} onChange={e => setServerForm({ ...serverForm, init_addr: e.target.value })} />
                  </div>
                  <div>
                    <LabelWithTooltip tooltip={t('pages:backends.tooltips.serverTrack')}>{t('pages:backends.serverManager.track')}</LabelWithTooltip>
                    <input className="input" value={serverForm.track || ''} onChange={e => setServerForm({ ...serverForm, track: e.target.value })} />
                  </div>
                </div>
                <div className="flex gap-4 flex-wrap">
                  <label className="flex items-center gap-2">
                    <input type="checkbox" checked={serverForm.check_ssl} onChange={e => setServerForm({ ...serverForm, check_ssl: e.target.checked })} />
                    <span>{t('pages:backends.serverManager.checkSsl')}</span>
                    <InfoTooltip content={t('pages:backends.tooltips.serverCheck_ssl')} />
                  </label>
                  <label className="flex items-center gap-2">
                    <input type="checkbox" checked={serverForm.send_proxy} onChange={e => setServerForm({ ...serverForm, send_proxy: e.target.checked })} />
                    <span>{t('pages:backends.serverManager.sendProxyV1')}</span>
                    <InfoTooltip content={t('pages:backends.tooltips.serverSend_proxy')} />
                  </label>
                  <label className="flex items-center gap-2">
                    <input type="checkbox" checked={serverForm.send_proxy_v2} onChange={e => setServerForm({ ...serverForm, send_proxy_v2: e.target.checked })} />
                    <span>{t('pages:backends.serverManager.sendProxyV2')}</span>
                    <InfoTooltip content={t('pages:backends.tooltips.serverSend_proxy_v2')} />
                  </label>
                  <label className="flex items-center gap-2">
                    <input type="checkbox" checked={serverForm.resolve} onChange={e => setServerForm({ ...serverForm, resolve: e.target.checked })} />
                    <span>{t('pages:backends.serverManager.resolve')}</span>
                    <InfoTooltip content={t('pages:backends.tooltips.serverResolve')} />
                  </label>
                  <label className="flex items-center gap-2">
                    <input type="checkbox" checked={serverForm.agent_check} onChange={e => setServerForm({ ...serverForm, agent_check: e.target.checked })} />
                    <span>{t('pages:backends.serverManager.agentCheck')}</span>
                    <InfoTooltip content={t('pages:backends.tooltips.serverAgent_check')} />
                  </label>
                </div>
              </>
            )}
          </div>

          <button className="btn-primary w-full">{t('pages:backends.serverManager.save')}</button>
        </form>
      </Modal>
    </div>
  )
}
