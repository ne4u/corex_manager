import React, { useEffect, useState, useCallback } from 'react'
import { useNavigate } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { GripVertical, Pencil, Trash2 } from 'lucide-react'
import { listeners, backends, certificates, ciphers, wafRules, backendRules, settings } from '../services/api'
import useApiList from '../hooks/useApiList'
import Modal from '../components/Modal'
import HaproxyOptionsEditor, { HaproxyOption } from '../components/HaproxyOptionsEditor'
import LabelWithTooltip from '../components/LabelWithTooltip'
import InfoTooltip from '../components/InfoTooltip'
import { IconButton } from '../components/ui'

export default function Listeners() {
  const { t } = useTranslation(['pages', 'common'])
  const navigate = useNavigate()
  const { items, reload, loading } = useApiList(listeners.list)
  const { items: backendList } = useApiList(backends.list)
  const { items: certList, loading: certListLoading } = useApiList(certificates.list)
  const { items: cipherList } = useApiList(ciphers.list)
  const { items: wafList, reload: reloadWaf } = useApiList(wafRules.list)
  const [open, setOpen] = useState(false)
  const [editing, setEditing] = useState<number | null>(null)
  const [mcpGatewayEnabled, setMcpGatewayEnabled] = useState(false)
  const initialForm = { name: '', bind_address: '0.0.0.0', bind_port: 80, mode: 'http', protocol: 'http', ssl_enabled: false, http2: false, quic: false, proxy_protocol: false, force_https: false, default_backend_id: null as number | null, certificate_id: null as number | null, certificate_ids: [] as number[], alpn: '', options: { cipher_suite: '', mcp_route_enabled: false } as any, haproxy_options: [] as HaproxyOption[] }
  const [form, setForm] = useState<any>(initialForm)

  useEffect(() => {
    settings.get('mcp_gateway_enabled')
      .then((r) => setMcpGatewayEnabled((r.data.value || 'false').toLowerCase() === 'true'))
      .catch(() => setMcpGatewayEnabled(false))
  }, [])

  const [ruleModal, setRuleModal] = useState(false)
  const [ruleList, setRuleList] = useState<any[]>([])
  const [ruleEditing, setRuleEditing] = useState<number | null>(null)
  const [dragOverId, setDragOverId] = useState<number | null>(null)
  const initialRule = { listener_id: '' as string | number, backend_id: '' as string | number, condition_type: 'path', condition_name: '', operator: 'beg', value: '', enabled: true, conditions: [] as any[] }
  const [ruleForm, setRuleForm] = useState<any>(initialRule)

  const reloadAllRules = useCallback(async () => {
    const res = await backendRules.list()
    setRuleList(res.data)
  }, [])

  useEffect(() => { reloadAllRules() }, [reloadAllRules])


  const getCertIds = (l: any) => {
    if (!l) return []
    let ids = l.certificate_ids
    if (typeof ids === 'string') {
      try { ids = JSON.parse(ids) } catch { ids = [] }
    }
    if (!Array.isArray(ids)) ids = []
    return (ids.length ? ids : (l.certificate_id ? [l.certificate_id] : [])).filter(Boolean)
  }

  const [certModal, setCertModal] = useState(false)
  const [certModalListener, setCertModalListener] = useState<any>(null)

  useEffect(() => {
    if ((form.ssl_enabled || form.proxy_protocol || form.http2 || form.quic) && form.force_https) {
      setForm((prev: any) => ({ ...prev, force_https: false }))
    }
  }, [form.ssl_enabled, form.proxy_protocol, form.http2, form.quic, form.force_https])

  const openAdd = () => { setEditing(null); setForm(initialForm); setOpen(true) }
  const openEdit = (l: any) => { setEditing(l.id); setForm({ ...l, options: { ...(l.options || {}), cipher_suite: l.options?.cipher_suite || '', compression_algorithm: l.options?.compression_algorithm || 'none', mcp_route_enabled: l.options?.mcp_route_enabled || false }, haproxy_options: l.haproxy_options || [], certificate_ids: l.certificate_ids || (l.certificate_id ? [l.certificate_id] : []) }); setOpen(true) }

  const openAddRule = () => {
    setRuleEditing(null)
    setRuleForm({ ...initialRule, listener_id: items.length > 0 ? String(items[0].id) : '' })
    setRuleModal(true)
  }

  const openEditRule = (r: any) => {
    setRuleEditing(r.id)
    setRuleForm({ ...r, listener_id: r.listener_id ? String(r.listener_id) : '', backend_id: r.backend_id ? String(r.backend_id) : '', conditions: r.conditions || [] })
    setRuleModal(true)
  }

  const addCondition = () => {
    if (ruleForm.conditions.length >= 4) return
    setRuleForm({ ...ruleForm, conditions: [...ruleForm.conditions, { condition_type: 'path', condition_name: '', operator: 'beg', value: '', join: 'and' }] })
  }

  const removeCondition = (idx: number) => {
    const next = [...ruleForm.conditions]
    next.splice(idx, 1)
    setRuleForm({ ...ruleForm, conditions: next })
  }

  const updateCondition = (idx: number, key: string, value: any) => {
    const next = [...ruleForm.conditions]
    next[idx] = { ...next[idx], [key]: value }
    setRuleForm({ ...ruleForm, conditions: next })
  }

  const submitRule = async (e: React.FormEvent) => {
    e.preventDefault()
    const listenerId = Number(ruleForm.listener_id)
    if (!listenerId) return
    const sameListenerRules = ruleList.filter((r: any) => r.listener_id === listenerId)
    const priority = ruleEditing ? ruleForm.priority : (sameListenerRules.length > 0 ? Math.max(...sameListenerRules.map((r: any) => r.priority || 0)) + 1 : 1)
    const payload = { ...ruleForm, listener_id: listenerId, backend_id: ruleForm.backend_id ? Number(ruleForm.backend_id) : null, priority }
    if (ruleEditing) await backendRules.update(ruleEditing, payload)
    else await backendRules.create(payload)
    setRuleEditing(null)
    setRuleForm(initialRule)
    setRuleModal(false)
    await reloadAllRules()
  }

  const deleteRule = async (id: number) => {
    await backendRules.remove(id)
    await reloadAllRules()
  }

  const reorderRules = async (draggedId: number, targetId: number) => {
    if (draggedId === targetId) return
    const dragged = ruleList.find(r => r.id === draggedId)
    if (!dragged) return
    const listenerId = dragged.listener_id
    // Only reorder within the same listener group
    const groupRules = ruleList
      .filter(r => r.listener_id === listenerId)
      .sort((a, b) => (a.priority || 0) - (b.priority || 0))
    const from = groupRules.findIndex(r => r.id === draggedId)
    const to = groupRules.findIndex(r => r.id === targetId)
    if (from < 0 || to < 0) return
    const newGroup = [...groupRules]
    const [moved] = newGroup.splice(from, 1)
    const insertAt = from < to ? to - 1 : to
    newGroup.splice(insertAt, 0, moved)
    for (let i = 0; i < newGroup.length; i++) {
      await backendRules.update(newGroup[i].id, { priority: i + 1 })
    }
    await reloadAllRules()
  }


  const submit = async (e: React.FormEvent) => {
    e.preventDefault()
    const payload = { ...form, mode: form.protocol === 'tcp' ? 'tcp' : 'http', certificate_id: (form.certificate_ids || [])[0] || null, certificate_ids: (form.certificate_ids || []).filter(Boolean), options: { ...(form.options || {}), cipher_suite: form.options?.cipher_suite } }
    if (editing) await listeners.update(editing, payload)
    else await listeners.create(payload)
    setForm(initialForm)
    setEditing(null)
    setOpen(false)
    reload()
  }

  return (
    <div className="space-y-6">
      {/* Listeners section */}
      <div className="space-y-4">
        <div className="flex items-center justify-between">
          <h2 className="text-lg font-semibold">{t('pages:listeners.title')}</h2>
          <button onClick={openAdd} className="btn-primary">{t('pages:listeners.addListener')}</button>
        </div>
      {loading ? <p>{t('pages:listeners.loading')}</p> : (
        <div className="card overflow-x-auto">
          <table className="w-full text-sm text-start">
            <thead className="text-slate-400 border-b border-slate-800"><tr><th>{t('pages:listeners.tableHeaders.name')}</th><th>{t('pages:listeners.tableHeaders.bind')}</th><th>{t('pages:listeners.tableHeaders.protocol')}</th><th>{t('pages:listeners.tableHeaders.mode')}</th><th>{t('pages:listeners.tableHeaders.ssl')}</th><th>{t('pages:listeners.tableHeaders.certs')}</th><th>{t('pages:listeners.tableHeaders.http2')}</th><th>{t('pages:listeners.tableHeaders.quic')}</th><th>{t('pages:listeners.tableHeaders.forceHttps')}</th><th>{t('pages:listeners.tableHeaders.defaultBackend')}</th><th>{t('pages:listeners.tableHeaders.waf')}</th><th></th></tr></thead>
            <tbody>
              {items.map((l: any) => {
                const waf = wafList.find((r: any) => r.listener_id === l.id)
                return (
                <tr key={l.id} className="border-b border-slate-800 last:border-0">
                  <td className="py-2">{l.name}</td>
                  <td>{l.bind_address}:{l.bind_port}</td>
                  <td>{l.protocol === 'mcp' ? 'MCP' : l.protocol}</td>
                  <td>{l.mode}</td>
                  <td>{l.ssl_enabled ? t('common:actions.yes') : t('common:actions.no')}</td>
                  <td>{(() => {
                    const ids = getCertIds(l)
                    const count = ids.length
                    if (count === 0) return '-'
                    return <button onClick={() => { setCertModalListener(l); setCertModal(true) }} className="text-primary hover:underline">{t('pages:listeners.certCount', { count })}</button>
                  })()}</td>
                  <td>{l.http2 ? t('common:actions.yes') : t('common:actions.no')}</td>
                  <td>{l.quic ? t('common:actions.yes') : t('common:actions.no')}</td>
                  <td>{l.force_https ? t('common:actions.yes') : t('common:actions.no')}</td>
                  <td>{l.protocol === 'mcp' ? t('pages:listeners.modal.mcpGatewayBuiltin') : (backendList.find((b: any) => b.id === l.default_backend_id)?.name || t('pages:listeners.modal.none'))}{mcpGatewayEnabled && l.protocol !== 'mcp' && l.protocol !== 'tcp' && l.options?.mcp_route_enabled && <span className="block text-xs text-primary">{t('pages:listeners.modal.mcpRouteEnabled')}</span>}</td>
                  <td>
                    {waf ? (
                      <div className="flex items-center gap-2">
                        <button
                          onClick={() => wafRules.update(waf.id, { enabled: !waf.enabled }).then(reloadWaf)}
                          className={`text-xs ${waf.enabled ? 'text-green-400' : 'text-slate-500'} hover:underline`}
                          title={`${t('pages:waf.rules.fields.engine')}: ${waf.engine || t('common:status.enabled')}, ${t('pages:waf.rules.fields.action')}: ${waf.action}`}
                        >
                          {waf.enabled ? `${waf.engine || t('common:status.enabled')} / ${waf.action}` : t('common:status.disabled')}
                        </button>
                        <button onClick={() => navigate(`/waf?edit=${waf.id}`)} className="text-xs text-primary hover:underline">{t('pages:listeners.configure')}</button>
                      </div>
                    ) : (
                      <button onClick={() => navigate(`/waf?listener=${l.id}`)} className="text-xs text-slate-500 hover:underline">{t('pages:listeners.attachWaf')}</button>
                    )}
                  </td>
                  <td className="text-end whitespace-nowrap">
                    <div className="flex gap-1 justify-end">
                      <IconButton icon={Pencil} aria-label={t('common:actions.edit')} onClick={() => openEdit(l)} />
                      <IconButton icon={Trash2} variant="danger" aria-label={t('common:actions.delete')} onClick={() => listeners.remove(l.id).then(reload)} />
                    </div>
                  </td>
                </tr>
              )})}
            </tbody>
          </table>
        </div>
      )}
      </div>

      {/* Routing Rules section */}
      <div className="space-y-4">
        <div className="flex items-center justify-between">
          <h2 className="text-lg font-semibold">{t('pages:listeners.routingRules')}</h2>
          <button
            onClick={openAddRule}
            disabled={items.length === 0}
            title={items.length === 0 ? t('pages:listeners.routingRulesNoListener') : undefined}
            className={`btn-primary ${items.length === 0 ? 'opacity-50 cursor-not-allowed' : ''}`}
          >{t('pages:listeners.routingRulesAdd')}</button>
        </div>
        <div className="space-y-4">
          {ruleList.length === 0 ? (
            <div className="card">
              <p className="text-sm text-slate-500 p-4">{t('pages:listeners.routingRulesEmpty')}</p>
            </div>
          ) : (
            items
              .filter(l => ruleList.some(r => r.listener_id === l.id))
              .map(l => {
                const groupRules = ruleList
                  .filter(r => r.listener_id === l.id)
                  .sort((a, b) => (a.priority || 0) - (b.priority || 0))
                return (
                  <div key={l.id} className="card overflow-x-auto">
                    <div className="px-3 py-2 border-b border-slate-800 font-semibold text-sm text-slate-300">{l.name}</div>
                    <table className="w-full text-sm text-start">
                      <thead className="text-slate-400 border-b border-slate-800"><tr><th className="w-8"></th><th>{t('pages:listeners.rules.tableHeaders.condition')}</th><th>{t('pages:listeners.rules.tableHeaders.backend')}</th><th>{t('pages:listeners.rules.tableHeaders.enabled')}</th><th></th></tr></thead>
                      <tbody>
                        {groupRules.map((r: any) => (
                          <tr key={r.id} className={`border-b border-slate-800 last:border-0 ${dragOverId === r.id ? 'bg-slate-800' : ''}`} draggable onDragStart={(e: any) => { e.dataTransfer.setData('text/plain', String(r.id)); e.dataTransfer.effectAllowed = 'move' }} onDragOver={(e: any) => { e.preventDefault(); setDragOverId(r.id) }} onDrop={(e: any) => { e.preventDefault(); const dragged = Number(e.dataTransfer.getData('text/plain')); if (dragged !== r.id) { setDragOverId(null); reorderRules(dragged, r.id) } }} onDragEnd={() => setDragOverId(null)}>
                            <td className="py-2 w-8 cursor-grab"><GripVertical className="w-4 h-4 text-slate-500" /></td>
                            <td>{r.condition_type} {r.condition_name} {r.operator} {r.value} {(r.conditions || []).map((c: any) => <span key={c.condition_type + c.operator} className="ms-2 text-slate-400">{c.join} {c.condition_type} {c.condition_name} {c.operator} {c.value}</span>)}</td>
                            <td>{backendList.find((b: any) => b.id === r.backend_id)?.name || 'None'}</td>
                            <td>{r.enabled ? t('common:actions.yes') : t('common:actions.no')}</td>
                            <td className="text-end whitespace-nowrap">
                              <div className="flex gap-1 justify-end">
                                <IconButton icon={Pencil} aria-label="Edit" onClick={() => openEditRule(r)} />
                                <IconButton icon={Trash2} variant="danger" aria-label="Delete" onClick={() => deleteRule(r.id)} />
                              </div>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )
              })
          )}
        </div>
      </div>

      <Modal open={open} onClose={() => setOpen(false)} title={editing ? t('pages:listeners.modal.editTitle') : t('pages:listeners.modal.addTitle')}>
        <form onSubmit={submit} className="space-y-3">
          <div className="grid grid-cols-2 gap-3">
            <div><LabelWithTooltip tooltip={t('pages:listeners.tooltips.name')} className="label">{t('pages:listeners.modal.name')}</LabelWithTooltip><input className="input" value={form.name} onChange={e => setForm({ ...form, name: e.target.value })} /></div>
            <div><LabelWithTooltip tooltip={t('pages:listeners.tooltips.bindAddress')} className="label">{t('pages:listeners.modal.bindAddress')}</LabelWithTooltip><input className="input" value={form.bind_address} onChange={e => setForm({ ...form, bind_address: e.target.value })} /></div>
            <div><LabelWithTooltip tooltip={t('pages:listeners.tooltips.port')} className="label">{t('pages:listeners.modal.port')}</LabelWithTooltip><input type="number" className="input" value={form.bind_port} onChange={e => setForm({ ...form, bind_port: Number(e.target.value) })} /></div>
            <div><LabelWithTooltip tooltip={t('pages:listeners.tooltips.protocol')} className="label">{t('pages:listeners.modal.protocol')}</LabelWithTooltip><select className="input" value={form.protocol} onChange={e => setForm({ ...form, protocol: e.target.value })}><option value="http">HTTP</option><option value="tcp">TCP</option><option value="grpc">gRPC</option><option value="jsonrpc">JSON-RPC</option><option value="mcp">MCP</option></select>{form.protocol === 'mcp' && <p className="text-xs text-muted-foreground mt-1">{t('pages:listeners.modal.mcpProtocolHelp')}</p>}</div>
            <div><LabelWithTooltip tooltip={t('pages:listeners.tooltips.defaultBackend')} className="label">{t('pages:listeners.modal.defaultBackend')}</LabelWithTooltip><select className="input" value={form.default_backend_id || ''} onChange={e => setForm({ ...form, default_backend_id: e.target.value ? Number(e.target.value) : null })}><option value="">{t('pages:listeners.modal.none')}</option>{backendList.map((b: any) => <option key={b.id} value={b.id}>{b.name}</option>)}</select></div>
            {mcpGatewayEnabled && form.protocol !== 'mcp' && form.protocol !== 'tcp' && (
              <div className="col-span-2">
                <label className="flex items-center gap-2">
                  <input type="checkbox" checked={form.options?.mcp_route_enabled || false} onChange={e => setForm({ ...form, options: { ...(form.options || {}), mcp_route_enabled: e.target.checked } })} />
                  <span>{t('pages:listeners.modal.routeMcp')}</span>
                  <InfoTooltip content={t('pages:listeners.modal.routeMcpHelp')} />
                </label>
              </div>
            )}
            <div className="col-span-2"><LabelWithTooltip tooltip={t('pages:listeners.tooltips.certificates')} className="label">{t('pages:listeners.modal.certificates')}</LabelWithTooltip><div className="max-h-32 overflow-y-auto card p-2 space-y-1">{certList.filter((c: any) => !c.kind || c.kind === 'server').map((c: any) => (
              <label key={c.id} className="flex items-center gap-2 text-sm cursor-pointer">
                <input type="checkbox" checked={(form.certificate_ids || []).includes(c.id)} onChange={(e) => { const ids = new Set<number>(form.certificate_ids || []); if (e.target.checked) ids.add(c.id); else ids.delete(c.id); const arr = [...ids].sort((a, b) => a - b); setForm({ ...form, certificate_ids: arr, certificate_id: arr[0] || null }); }} />
                <span>{c.name} <span className="text-slate-400">({c.subject_cn || '-'})</span></span>
              </label>
            ))}{certList.filter((c: any) => !c.kind || c.kind === 'server').length === 0 && <p className="text-sm text-slate-500">{t('pages:listeners.noCertificates')}</p>}</div></div>
            <div><LabelWithTooltip tooltip={t('pages:listeners.tooltips.cipherSuite')} className="label">{t('pages:listeners.modal.cipherSuite')}</LabelWithTooltip><select className="input" value={form.options?.cipher_suite || ''} onChange={e => setForm({ ...form, options: { ...(form.options || {}), cipher_suite: e.target.value } })}><option value="">{t('pages:listeners.modal.cipherSuiteDefault')}</option>{cipherList.map((c: any) => <option key={c.id} value={c.name}>{c.name}</option>)}</select></div>
          </div>
          <div className="grid grid-cols-4 gap-3">
            <label className="flex items-center gap-2"><input type="checkbox" checked={form.ssl_enabled} onChange={e => setForm({ ...form, ssl_enabled: e.target.checked })} /><span>{t('pages:listeners.modal.ssl')}</span><InfoTooltip content={t('pages:listeners.tooltips.ssl')} /></label>
            <label className="flex items-center gap-2"><input type="checkbox" checked={form.http2} onChange={e => setForm({ ...form, http2: e.target.checked })} /><span>{t('pages:listeners.modal.http2')}</span><InfoTooltip content={t('pages:listeners.tooltips.http2')} /></label>
            <label className="flex items-center gap-2"><input type="checkbox" checked={form.quic} onChange={e => setForm({ ...form, quic: e.target.checked })} /><span>{t('pages:listeners.modal.quic')}</span><InfoTooltip content={t('pages:listeners.tooltips.quic')} /></label>
            <label className="flex items-center gap-2"><input type="checkbox" checked={form.proxy_protocol} onChange={e => setForm({ ...form, proxy_protocol: e.target.checked })} /><span>{t('pages:listeners.modal.proxyProtocol')}</span><InfoTooltip content={t('pages:listeners.tooltips.proxyProtocol')} /></label>
            <label className={`flex items-center gap-2 ${(form.ssl_enabled || form.proxy_protocol || form.http2 || form.quic) ? 'text-slate-500 cursor-not-allowed' : ''}`}><input type="checkbox" checked={form.force_https} disabled={form.ssl_enabled || form.proxy_protocol || form.http2 || form.quic} onChange={e => setForm({ ...form, force_https: e.target.checked })} /><span>{t('pages:listeners.modal.forceHttps')}</span><InfoTooltip content={t('pages:listeners.tooltips.forceHttps')} /></label>
          </div>
          {form.ssl_enabled && (
            <div><LabelWithTooltip tooltip={t('pages:listeners.tooltips.alpn')} className="label">{t('pages:listeners.modal.alpn')}</LabelWithTooltip><input className="input" placeholder={t('pages:listeners.modal.alpnPlaceholder')} value={form.alpn || ''} onChange={e => setForm({ ...form, alpn: e.target.value })} /></div>
          )}
          {form.quic && (
            <div><LabelWithTooltip tooltip={t('pages:listeners.tooltips.altSvcHeader')} className="label">{t('pages:listeners.modal.altSvcHeader')}</LabelWithTooltip><input className="input" placeholder={t('pages:listeners.modal.altSvcPlaceholder')} value={form.options?.alt_svc || ''} onChange={e => setForm({ ...form, options: { ...form.options, alt_svc: e.target.value } })} /></div>
          )}
          <div><LabelWithTooltip tooltip={t('pages:listeners.tooltips.reqFpExcludePaths')} className="label">{t('pages:listeners.modal.reqFpExcludePaths')}</LabelWithTooltip><input className="input" placeholder="/bundles/,/static/" value={form.options?.req_fp_exclude_paths || ''} onChange={e => setForm({ ...form, options: { ...form.options, req_fp_exclude_paths: e.target.value } })} /></div>
          <HaproxyOptionsEditor
            scope="listener"
            value={form.haproxy_options || []}
            onChange={(opts) => setForm({ ...form, haproxy_options: opts })}
          />
          <button className="btn-primary w-full">{t('pages:listeners.modal.save')}</button>
        </form>
      </Modal>

      <Modal open={ruleModal} onClose={() => setRuleModal(false)} title={t('pages:listeners.rules.title')}>
        <form onSubmit={submitRule} className="space-y-3">
          <div className="space-y-3">
            <div className="grid grid-cols-2 gap-3">
              <div><LabelWithTooltip tooltip={t('pages:listeners.tooltips.conditionType')} className="label">{t('pages:listeners.rules.listener')}</LabelWithTooltip><select className="input" value={ruleForm.listener_id} onChange={e => setRuleForm({ ...ruleForm, listener_id: e.target.value })}>{items.map((l: any) => <option key={l.id} value={l.id}>{l.name}</option>)}</select></div>
              <div><LabelWithTooltip tooltip={t('pages:listeners.tooltips.conditionType')} className="label">{t('pages:listeners.rules.conditionType')}</LabelWithTooltip><select className="input" value={ruleForm.condition_type} onChange={e => setRuleForm({ ...ruleForm, condition_type: e.target.value })}><option value="path">Path</option><option value="host">Host</option><option value="hdr">Header</option><option value="cookie">Cookie</option><option value="url_param">URL Param</option><option value="src">Source IP</option></select></div>
                <div><LabelWithTooltip tooltip={t('pages:listeners.tooltips.operator')} className="label">{t('pages:listeners.rules.operator')}</LabelWithTooltip><select className="input" value={ruleForm.operator} onChange={e => setRuleForm({ ...ruleForm, operator: e.target.value })}><option value="beg">beg</option><option value="end">end</option><option value="sub">sub</option><option value="dir">dir</option><option value="eq">eq</option><option value="found">found</option><option value="reg">reg</option><option value="len">len</option></select></div>
                {['hdr', 'cookie', 'url_param'].includes(ruleForm.condition_type) && (
                  <div><LabelWithTooltip tooltip={t('pages:listeners.tooltips.conditionName')} className="label">{t('pages:listeners.rules.conditionName')}</LabelWithTooltip><input className="input" value={ruleForm.condition_name} onChange={e => setRuleForm({ ...ruleForm, condition_name: e.target.value })} /></div>
                )}
                <div><LabelWithTooltip tooltip={t('pages:listeners.tooltips.ruleValue')} className="label">{t('pages:listeners.rules.value')}</LabelWithTooltip><input className="input" value={ruleForm.value} onChange={e => setRuleForm({ ...ruleForm, value: e.target.value })} /></div>
              </div>
              {ruleForm.conditions.map((c: any, idx: number) => (
                <div key={idx} className="grid grid-cols-12 gap-3 items-end border-t border-slate-800 pt-3">
                  <div className="col-span-2"><LabelWithTooltip tooltip={t('pages:listeners.tooltips.join')} className="label">{t('pages:listeners.rules.join')}</LabelWithTooltip><select className="input" value={c.join} onChange={e => updateCondition(idx, 'join', e.target.value)}><option value="and">and</option><option value="or">or</option></select></div>
                  <div className="col-span-2"><LabelWithTooltip tooltip={t('pages:listeners.tooltips.additionalConditionType')} className="label">{t('pages:listeners.rules.type')}</LabelWithTooltip><select className="input" value={c.condition_type} onChange={e => updateCondition(idx, 'condition_type', e.target.value)}><option value="path">Path</option><option value="host">Host</option><option value="hdr">Header</option><option value="cookie">Cookie</option><option value="url_param">URL Param</option><option value="src">Source IP</option></select></div>
                  <div className="col-span-2"><LabelWithTooltip tooltip={t('pages:listeners.tooltips.operator')} className="label">{t('pages:listeners.rules.operator')}</LabelWithTooltip><select className="input" value={c.operator} onChange={e => updateCondition(idx, 'operator', e.target.value)}><option value="beg">beg</option><option value="end">end</option><option value="sub">sub</option><option value="dir">dir</option><option value="eq">eq</option><option value="found">found</option><option value="reg">reg</option><option value="len">len</option></select></div>
                  {['hdr', 'cookie', 'url_param'].includes(c.condition_type) && (
                    <div className="col-span-2"><LabelWithTooltip tooltip={t('pages:listeners.tooltips.additionalConditionName')} className="label">{t('pages:listeners.rules.name')}</LabelWithTooltip><input className="input" value={c.condition_name} onChange={e => updateCondition(idx, 'condition_name', e.target.value)} /></div>
                  )}
                  <div className="col-span-2"><LabelWithTooltip tooltip={t('pages:listeners.tooltips.additionalValue')} className="label">{t('pages:listeners.rules.value')}</LabelWithTooltip><input className="input" value={c.value} onChange={e => updateCondition(idx, 'value', e.target.value)} /></div>
                  <div className="col-span-2"><button type="button" onClick={() => removeCondition(idx)} className="text-red-400 hover:underline">{t('pages:listeners.rules.remove')}</button></div>
                </div>
              ))}
              {ruleForm.conditions.length < 4 && (
                <button type="button" onClick={addCondition} className="btn-primary">{t('pages:listeners.rules.addCondition')}</button>
              )}
              <div className="grid grid-cols-2 gap-3">
                <div><LabelWithTooltip tooltip={t('pages:listeners.tooltips.ruleBackend')} className="label">{t('pages:listeners.rules.backend')}</LabelWithTooltip><select className="input" value={ruleForm.backend_id || ''} onChange={e => setRuleForm({ ...ruleForm, backend_id: e.target.value })}><option value="">{t('pages:listeners.modal.none')}</option>{backendList.map((b: any) => <option key={b.id} value={b.id}>{b.name}</option>)}</select></div>
              </div>
            </div>
            <label className="flex items-center gap-2"><input type="checkbox" checked={ruleForm.enabled} onChange={e => setRuleForm({ ...ruleForm, enabled: e.target.checked })} /><span>{t('pages:listeners.rules.enabled')}</span><InfoTooltip content={t('pages:listeners.tooltips.ruleEnabled')} /></label>
            <button className="btn-primary w-full">{ruleEditing ? t('pages:listeners.rules.updateRule') : t('pages:listeners.rules.addRule')}</button>
          </form>
      </Modal>


      <Modal open={certModal} onClose={() => { setCertModal(false); setCertModalListener(null) }} title={t('pages:listeners.certModal.title', { name: certModalListener?.name || '' })}>
        <div className="space-y-2">
          {(() => {
            const ids = certModalListener ? getCertIds(certModalListener) : []
            if (certListLoading) return <p className="text-sm text-slate-500">{t('pages:listeners.certModal.loading')}</p>
            if (ids.length === 0) return <p className="text-sm text-slate-500">{t('pages:listeners.certModal.noCertificates')}</p>
            return (
              <ul className="divide-y divide-slate-800 border border-slate-800 rounded-lg">
                {ids.map((id: number) => {
                  const c = certList.find((c: any) => c.id === id)
                  if (!c) return null
                  return <li key={id} className="py-2 px-3 flex justify-between items-center"><span>{c.name}</span><span className="text-slate-400 text-sm">{c.subject_cn || '-'}</span></li>
                })}
              </ul>
            )
          })()}
        </div>
      </Modal>
    </div>
  )
}
