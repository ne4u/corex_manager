import { useEffect, useState, useCallback } from 'react'
import { useTranslation } from 'react-i18next'
import { Plus, Trash2, Pencil, Server, Package, KeyRound, Loader2, ExternalLink, BookOpen } from 'lucide-react'
import { mcp } from '../../services/api'
import Modal from '../Modal'
import { IconButton, Badge, Button } from '../ui'
import { useDateTime } from '../../contexts/DateTimeContext'

interface OAuthStatus {
  enabled: boolean
  auth_status: string | null
  client_id: string | null
  scopes: string | null
  token_expires_at: string | null
  authorization_url: string | null
}

function OAuthSection({ serverId, onRefresh }: { serverId: number; onRefresh: () => void }) {
  const { t } = useTranslation(['pages', 'common'])
  const { formatDateTime } = useDateTime()
  const [status, setStatus] = useState<OAuthStatus | null>(null)
  const [loading, setLoading] = useState(false)

  const fetchStatus = useCallback(async () => {
    try {
      const resp = await mcp.oauth.status(serverId)
      setStatus(resp.data)
    } catch { /* ignore */ }
  }, [serverId])

  useEffect(() => { fetchStatus() }, [fetchStatus])

  const handleAuthorize = async () => {
    setLoading(true)
    try {
      const resp = await mcp.oauth.authorize(serverId)
      if (resp.data.authorization_url) {
        window.open(resp.data.authorization_url, '_blank')
      }
    } catch { /* ignore */ }
    finally { setLoading(false) }
  }

  const handleDisable = async () => {
    if (!confirm(t('pages:mcpGateway.servers.oauth.disableConfirm'))) return
    try {
      await mcp.oauth.disable(serverId)
      onRefresh()
      fetchStatus()
    } catch { /* ignore */ }
  }

  if (!status) return null

  return (
    <div className="rounded-md border border-border bg-muted/30 p-3 space-y-2">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2 text-sm font-medium">
          <KeyRound className="w-4 h-4 text-primary" />
          {t('pages:mcpGateway.servers.oauth.configTitle')}
        </div>
        <Badge variant={status.auth_status === 'authorized' ? 'success' : status.auth_status === 'error' ? 'error' : 'warning'} size="sm">
          {status.auth_status || t('common:status.unknown')}
        </Badge>
      </div>
      <div className="grid grid-cols-2 gap-2 text-xs">
        <div><span className="text-muted-foreground">{t('pages:mcpGateway.servers.oauth.clientId')}</span> {status.client_id || '—'}</div>
        <div><span className="text-muted-foreground">{t('pages:mcpGateway.servers.oauth.scopes')}</span> {status.scopes || '—'}</div>
        {status.token_expires_at && <div><span className="text-muted-foreground">{t('pages:mcpGateway.servers.oauth.tokenExpires')}</span> {formatDateTime(status.token_expires_at)}</div>}
      </div>
      <div className="flex items-center gap-2">
        {status.auth_status !== 'authorized' && (
          <Button size="sm" onClick={handleAuthorize} disabled={loading}>
            {loading ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <ExternalLink className="w-3.5 h-3.5" />}
            {t('pages:mcpGateway.servers.oauth.authorize')}
          </Button>
        )}
        <Button size="sm" variant="secondary" onClick={handleDisable}>{t('pages:mcpGateway.servers.oauth.disable')}</Button>
      </div>
    </div>
  )
}

interface McpServer {
  id: number
  team_id: number
  name: string
  display_name: string | null
  description: string | null
  url: string | null
  enabled: boolean
  verify_tls: boolean
  auth_type: string
  auth_header: string | null
  has_secret: boolean
  timeout_ms: number
  max_body_bytes: number
  namespace: string
  health_status: string | null
  last_seen_at: string | null
  last_error: string | null
  last_catalog_at: string | null
  transport_type: string
  command: string | null
  args: string[] | null
  has_env_vars: boolean
  env_var_names: string[] | null
  package_manager: string | null
  source_package_name: string | null
  installed_version: string | null
  oauth_enabled: boolean
  oauth_auth_status: string | null
  oauth_client_id: string | null
  oauth_scopes: string | null
  created_at: string
  updated_at: string
}

interface McpServerReplica {
  id: number
  server_id: number
  url: string
  enabled: boolean
  verify_tls: boolean
  created_at: string
  updated_at: string
}

interface Team {
  id: number
  name: string
  slug: string
}

const emptyForm = {
  team_id: 0, name: '', display_name: '', description: '', url: '',
  enabled: true, verify_tls: true, auth_type: 'none', auth_header: '',
  auth_secret: '', timeout_ms: 30000, max_body_bytes: 1048576, namespace: '',
  transport_type: 'streamable_http', command: '', args: '', env_vars: '',
  oauth_enabled: false, oauth_client_id: '', oauth_client_secret: '', oauth_scopes: '',
  oauth_auth_server_metadata_url: '',
}

export default function McpServersTab() {
  const { t } = useTranslation(['pages', 'common'])
  const { formatDateTime } = useDateTime()
  const [servers, setServers] = useState<McpServer[]>([])
  const [teams, setTeams] = useState<Team[]>([])
  const [loading, setLoading] = useState(true)
  const [modalOpen, setModalOpen] = useState(false)
  const [editing, setEditing] = useState<McpServer | null>(null)
  const [form, setForm] = useState(emptyForm)
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState('')
  const [expandedId, setExpandedId] = useState<number | null>(null)
  const [replicas, setReplicas] = useState<Record<number, McpServerReplica[]>>({})
  const [replicaUrl, setReplicaUrl] = useState<Record<number, string>>({})
  const [installations, setInstallations] = useState<Record<number, any[]>>({})
  const [catalogs, setCatalogs] = useState<Record<number, any>>({})

  const fetchServers = useCallback(async () => {
    try {
      const [srvResp, teamResp] = await Promise.all([mcp.servers.list(), mcp.teams.list()])
      setServers(srvResp.data)
      setTeams(teamResp.data)
      if (teamResp.data.length > 0 && form.team_id === 0) {
        setForm(f => ({ ...f, team_id: teamResp.data[0].id }))
      }
    } catch {
      setServers([])
    } finally {
      setLoading(false)
    }
  }, [form.team_id])

  useEffect(() => { fetchServers() }, [fetchServers])

  const fetchReplicas = async (serverId: number) => {
    try {
      const resp = await mcp.servers.replicas.list(serverId)
      setReplicas(prev => ({ ...prev, [serverId]: resp.data }))
    } catch {
      setReplicas(prev => ({ ...prev, [serverId]: [] }))
    }
  }

  const openCreate = () => {
    setEditing(null)
    setForm({ ...emptyForm, team_id: teams[0]?.id || 0 })
    setError('')
    setModalOpen(true)
  }

  const openEdit = (s: McpServer) => {
    setEditing(s)
    setForm({
      team_id: s.team_id, name: s.name, display_name: s.display_name || '',
      description: s.description || '', url: s.url || '', enabled: s.enabled,
      verify_tls: s.verify_tls, auth_type: s.auth_type, auth_header: s.auth_header || '',
      auth_secret: '', timeout_ms: s.timeout_ms, max_body_bytes: s.max_body_bytes,
      namespace: s.namespace,
      transport_type: s.transport_type || 'streamable_http',
      command: s.command || '',
      args: s.args ? s.args.join(' ') : '',
      env_vars: s.env_var_names ? s.env_var_names.map((v: string) => `${v}=`).join('\n') : '',
      oauth_enabled: s.oauth_enabled || false,
      oauth_client_id: s.oauth_client_id || '',
      oauth_client_secret: '',
      oauth_scopes: s.oauth_scopes || '',
      oauth_auth_server_metadata_url: '',
    })
    setError('')
    setModalOpen(true)
  }

  const save = async () => {
    setSaving(true)
    setError('')
    try {
      const data: Record<string, unknown> = { ...form }
      if (!data.auth_secret) delete data.auth_secret
      if (!data.display_name) data.display_name = null
      if (!data.description) data.description = null
      if (!data.auth_header) data.auth_header = null
      if (!data.namespace) data.namespace = null
      // Parse args string into array
      if (typeof data.args === 'string' && data.args.trim()) {
        data.args = data.args.trim().split(/\s+/)
      } else {
        delete data.args
      }
      // Parse env_vars string (KEY=VALUE per line) into object
      if (typeof data.env_vars === 'string' && data.env_vars.trim()) {
        const envObj: Record<string, string> = {}
        data.env_vars.split('\n').forEach((line: string) => {
          const idx = line.indexOf('=')
          if (idx > 0) {
            envObj[line.slice(0, idx).trim()] = line.slice(idx + 1).trim()
          }
        })
        data.env_vars = Object.keys(envObj).length > 0 ? envObj : null
      } else {
        delete data.env_vars
      }
      // Clean up OAuth fields
      if (!data.oauth_client_id) delete data.oauth_client_id
      if (!data.oauth_client_secret) delete data.oauth_client_secret
      if (!data.oauth_scopes) delete data.oauth_scopes
      if (!data.oauth_auth_server_metadata_url) delete data.oauth_auth_server_metadata_url
      // stdio: url not needed; http: command not needed
      if (data.transport_type === 'stdio') {
        delete data.url
        if (!data.command) {
          setError(t('pages:mcpGateway.servers.commandRequired'))
          setSaving(false)
          return
        }
      } else {
        delete data.command
        delete data.args
        delete data.env_vars
      }
      if (editing) {
        await mcp.servers.update(editing.id, data)
      } else {
        await mcp.servers.create(data)
      }
      setModalOpen(false)
      fetchServers()
    } catch (err: any) {
      setError(err?.response?.data?.detail || t('pages:mcpGateway.servers.saveFailed'))
    } finally {
      setSaving(false)
    }
  }

  const del = async (id: number) => {
    if (!confirm(t('pages:mcpGateway.servers.deleteConfirm'))) return
    try {
      await mcp.servers.delete(id)
      fetchServers()
    } catch { /* ignore */ }
  }

  const addReplica = async (serverId: number) => {
    const url = replicaUrl[serverId]?.trim()
    if (!url) return
    try {
      await mcp.servers.replicas.create(serverId, { url, enabled: true, verify_tls: true })
      setReplicaUrl(prev => ({ ...prev, [serverId]: '' }))
      fetchReplicas(serverId)
    } catch { /* ignore */ }
  }

  const delReplica = async (serverId: number, replicaId: number) => {
    try {
      await mcp.servers.replicas.delete(serverId, replicaId)
      fetchReplicas(serverId)
    } catch { /* ignore */ }
  }

  const fetchInstallations = async (serverId: number) => {
    try {
      const resp = await mcp.installations.list(serverId)
      setInstallations(prev => ({ ...prev, [serverId]: resp.data }))
    } catch { setInstallations(prev => ({ ...prev, [serverId]: [] })) }
  }

  const fetchCatalog = async (serverId: number) => {
    try {
      const resp = await mcp.catalog.get(serverId)
      setCatalogs(prev => ({ ...prev, [serverId]: resp.data }))
    } catch { setCatalogs(prev => ({ ...prev, [serverId]: null })) }
  }

  const toggleExpand = (id: number) => {
    if (expandedId === id) {
      setExpandedId(null)
    } else {
      setExpandedId(id)
      fetchReplicas(id)
      fetchInstallations(id)
      fetchCatalog(id)
    }
  }

  if (loading) return <p className="text-sm text-muted-foreground">{t('common:actions.loading')}</p>

  return (
    <div className="space-y-4">
      <div className="flex justify-between items-center">
        <p className="text-sm text-muted-foreground">{t('pages:mcpGateway.servers.serverCount', { count: servers.length })}</p>
        <button className="btn-primary text-sm" onClick={openCreate}>
          <Plus className="w-4 h-4 inline me-1" /> {t('pages:mcpGateway.servers.addServer')}
        </button>
      </div>

      {servers.length === 0 ? (
        <div className="rounded-lg border border-border bg-card p-8 text-center">
          <Server className="h-8 w-8 mx-auto mb-2 text-muted-foreground" />
          <p className="text-sm text-muted-foreground">{t('pages:mcpGateway.servers.noServers')}</p>
        </div>
      ) : (
        <div className="space-y-2">
          {servers.map(s => (
            <div key={s.id} className="rounded-lg border border-border bg-card">
              <div
                className="flex items-center justify-between p-3 cursor-pointer hover:bg-muted/50"
                onClick={() => toggleExpand(s.id)}
              >
                <div className="flex items-center gap-3">
                  <div>
                    <div className="font-medium flex items-center gap-2">
                      {s.display_name || s.name}
                      <Badge variant={s.enabled ? 'success' : 'default'} size="sm">{s.enabled ? t('common:status.enabled') : t('common:status.disabled')}</Badge>
                      <Badge variant={s.transport_type === 'stdio' ? 'info' : 'default'} size="sm">
                        {s.transport_type === 'stdio' ? t('pages:mcpGateway.servers.transportStdio') : t('pages:mcpGateway.servers.transportHttp')}
                      </Badge>
                      {s.health_status && s.health_status !== 'unknown' && (
                        <Badge variant={s.health_status === 'healthy' ? 'success' : s.health_status === 'unhealthy' ? 'error' : 'default'} size="sm">
                          {s.health_status}
                        </Badge>
                      )}
                      {s.oauth_enabled && (
                        <Badge variant={s.oauth_auth_status === 'authorized' ? 'success' : 'warning'} size="sm">
                          {t('pages:mcpGateway.servers.oauthBadge', { status: s.oauth_auth_status })}
                        </Badge>
                      )}
                      {s.source_package_name && (
                        <Badge variant="default" size="sm">
                          <Package className="w-3 h-3 inline me-1" />{s.source_package_name}
                        </Badge>
                      )}
                    </div>
                    <div className="text-xs text-muted-foreground">
                      {s.namespace} · {s.transport_type === 'stdio' ? `${s.command || ''} ${(s.args || []).join(' ')}` : s.url}
                    </div>
                  </div>
                </div>
                <div className="flex items-center gap-1" onClick={e => e.stopPropagation()}>
                  <IconButton icon={Pencil} aria-label={t('pages:mcpGateway.servers.editServerLabel')} onClick={() => openEdit(s)} />
                  <IconButton icon={Trash2} variant="danger" aria-label={t('pages:mcpGateway.servers.deleteServerLabel')} onClick={() => del(s.id)} />
                </div>
              </div>
              {expandedId === s.id && (
                <div className="border-t border-border p-3 space-y-3">
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-2 text-xs">
                    <div><span className="text-muted-foreground">{t('pages:mcpGateway.servers.tableHeaders.transport')}</span> {s.transport_type}</div>
                    <div><span className="text-muted-foreground">{t('pages:mcpGateway.servers.tableHeaders.auth')}</span> {s.auth_type}{s.has_secret ? ` ${t('pages:mcpGateway.servers.secretSet')}` : ''}</div>
                    <div><span className="text-muted-foreground">{t('pages:mcpGateway.servers.tableHeaders.timeout')}</span> {s.timeout_ms}ms</div>
                    <div><span className="text-muted-foreground">{t('pages:mcpGateway.servers.tableHeaders.maxBody')}</span> {(s.max_body_bytes / 1024).toFixed(0)}KB</div>
                    {s.transport_type === 'stdio' && <div><span className="text-muted-foreground">{t('pages:mcpGateway.servers.tableHeaders.command')}</span> {s.command}</div>}
                    {s.transport_type === 'stdio' && <div><span className="text-muted-foreground">{t('pages:mcpGateway.servers.tableHeaders.envVars')}</span> {s.env_var_names && s.env_var_names.length > 0 ? s.env_var_names.join(', ') : t('common:status.none')}</div>}
                    {s.transport_type !== 'stdio' && <div><span className="text-muted-foreground">{t('pages:mcpGateway.servers.tableHeaders.verifyTls')}</span> {s.verify_tls ? t('common:actions.yes') : t('common:actions.no')}</div>}
                    {s.source_package_name && <div><span className="text-muted-foreground">{t('pages:mcpGateway.servers.tableHeaders.package')}</span> {s.package_manager}/{s.source_package_name}{s.installed_version ? `@${s.installed_version}` : ''}</div>}
                    {s.oauth_enabled && <div><span className="text-muted-foreground">{t('pages:mcpGateway.servers.tableHeaders.oauth')}</span> {s.oauth_auth_status} {s.oauth_client_id ? `(${s.oauth_client_id})` : ''}</div>}
                    {s.last_error && <div className="col-span-2 text-red-400">{t('pages:mcpGateway.servers.tableHeaders.error')} {s.last_error}</div>}
                    {s.last_catalog_at && <div className="col-span-2"><span className="text-muted-foreground">{t('pages:mcpGateway.servers.tableHeaders.lastCatalog')}</span> {formatDateTime(s.last_catalog_at)}</div>}
                  </div>
                  {s.oauth_enabled && (
                    <OAuthSection serverId={s.id} onRefresh={fetchServers} />
                  )}
                  {s.transport_type !== 'stdio' && (
                    <div className="space-y-2">
                      <h4 className="text-xs font-semibold text-muted-foreground uppercase">{t('pages:mcpGateway.servers.sections.replicas')}</h4>
                      {(replicas[s.id] || []).map(r => (
                        <div key={r.id} className="flex items-center justify-between text-sm bg-muted/30 rounded px-2 py-1">
                          <span className="flex items-center gap-2">
                            {r.url}
                            <Badge variant={r.enabled ? 'success' : 'default'} size="sm">{r.enabled ? t('common:status.on') : t('common:status.off')}</Badge>
                          </span>
                          <IconButton icon={Trash2} variant="danger" aria-label={t('pages:mcpGateway.servers.deleteReplicaLabel')} onClick={() => delReplica(s.id, r.id)} />
                        </div>
                      ))}
                      <div className="flex gap-2">
                        <input
                          type="text"
                          className="input flex-1 text-sm"
                          placeholder={t('pages:mcpGateway.servers.replicaPlaceholder')}
                          value={replicaUrl[s.id] || ''}
                          onChange={e => setReplicaUrl(prev => ({ ...prev, [s.id]: e.target.value }))}
                          onKeyDown={e => e.key === 'Enter' && addReplica(s.id)}
                        />
                        <button className="btn-secondary text-sm" onClick={() => addReplica(s.id)}>{t('pages:mcpGateway.servers.addReplica')}</button>
                      </div>
                    </div>
                  )}
                  {/* Installation History */}
                  {(installations[s.id] || []).length > 0 && (
                    <div className="space-y-2">
                      <h4 className="text-xs font-semibold text-muted-foreground uppercase">{t('pages:mcpGateway.servers.sections.installationHistory')}</h4>
                      <div className="space-y-1">
                        {(installations[s.id] || []).map(inst => (
                          <div key={inst.id} className="text-xs rounded border border-border px-2 py-1 flex items-center justify-between">
                            <div className="flex items-center gap-2">
                              <Package className="w-3 h-3 text-muted-foreground" />
                              <span className="font-mono">{inst.package_manager}/{inst.package_name}</span>
                              {inst.version && <Badge variant="info" size="sm">{t('pages:mcpGateway.servers.versionPrefix', { version: inst.version })}</Badge>}
                            </div>
                            <span className="text-muted-foreground">{formatDateTime(inst.created_at)}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                  {/* Catalog Detail */}
                  {catalogs[s.id] && (
                    <div className="space-y-2">
                      <h4 className="text-xs font-semibold text-muted-foreground uppercase flex items-center gap-1">
                        <BookOpen className="w-3 h-3" /> {t('pages:mcpGateway.servers.sections.catalog')}
                        {catalogs[s.id].last_refresh && <span className="text-muted-foreground normal-case font-normal">· {t('pages:mcpGateway.servers.sections.lastRefresh')} {formatDateTime(catalogs[s.id].last_refresh)}</span>}
                      </h4>
                      {catalogs[s.id].tools?.length > 0 && (
                        <div>
                          <span className="text-xs font-medium">{t('pages:mcpGateway.servers.sections.tools', { count: catalogs[s.id].tools.length })}</span>
                          <div className="space-y-1 mt-1">
                            {catalogs[s.id].tools.map((tool: any, i: number) => (
                              <div key={i} className="text-xs rounded border border-border px-2 py-1">
                                <span className="font-mono font-medium">{tool.name}</span>
                                {tool.description && <span className="text-muted-foreground ms-2">{tool.description}</span>}
                              </div>
                            ))}
                          </div>
                        </div>
                      )}
                      {catalogs[s.id].resources?.length > 0 && (
                        <div>
                          <span className="text-xs font-medium">{t('pages:mcpGateway.servers.sections.resources', { count: catalogs[s.id].resources.length })}</span>
                          <div className="space-y-1 mt-1">
                            {catalogs[s.id].resources.map((res: any, i: number) => (
                              <div key={i} className="text-xs rounded border border-border px-2 py-1">
                                <span className="font-mono font-medium">{res.uri || res.name}</span>
                                {res.description && <span className="text-muted-foreground ms-2">{res.description}</span>}
                              </div>
                            ))}
                          </div>
                        </div>
                      )}
                      {catalogs[s.id].prompts?.length > 0 && (
                        <div>
                          <span className="text-xs font-medium">{t('pages:mcpGateway.servers.sections.prompts', { count: catalogs[s.id].prompts.length })}</span>
                          <div className="space-y-1 mt-1">
                            {catalogs[s.id].prompts.map((p: any, i: number) => (
                              <div key={i} className="text-xs rounded border border-border px-2 py-1">
                                <span className="font-mono font-medium">{p.name}</span>
                                {p.description && <span className="text-muted-foreground ms-2">{p.description}</span>}
                              </div>
                            ))}
                          </div>
                        </div>
                      )}
                      {(!catalogs[s.id].tools?.length && !catalogs[s.id].resources?.length && !catalogs[s.id].prompts?.length) && (
                        <p className="text-xs text-muted-foreground">{t('pages:mcpGateway.servers.sections.noCatalog')}</p>
                      )}
                    </div>
                  )}
                </div>
              )}
            </div>
          ))}
        </div>
      )}

      <Modal open={modalOpen} onClose={() => setModalOpen(false)} title={editing ? t('pages:mcpGateway.servers.editServer') : t('pages:mcpGateway.servers.addServer')}>
        <div className="space-y-4">
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="label">{t('pages:mcpGateway.servers.modal.team')}</label>
              <select className="input w-full" value={form.team_id} onChange={e => setForm({ ...form, team_id: Number(e.target.value) })}>
                {teams.map(t => <option key={t.id} value={t.id}>{t.name}</option>)}
              </select>
            </div>
            <div>
              <label className="label">{t('pages:mcpGateway.servers.modal.name')}</label>
              <input className="input w-full" value={form.name} onChange={e => setForm({ ...form, name: e.target.value })} placeholder="jira" />
            </div>
          </div>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="label">{t('pages:mcpGateway.servers.modal.displayName')}</label>
              <input className="input w-full" value={form.display_name} onChange={e => setForm({ ...form, display_name: e.target.value })} placeholder="Jira MCP" />
            </div>
            <div>
              <label className="label">{t('pages:mcpGateway.servers.modal.namespace')}</label>
              <input className="input w-full" value={form.namespace} onChange={e => setForm({ ...form, namespace: e.target.value })} placeholder="defaults to name" />
            </div>
          </div>
          <div>
            <label className="label">{t('pages:mcpGateway.servers.modal.transportType')}</label>
            <select className="input w-full" value={form.transport_type} onChange={e => setForm({ ...form, transport_type: e.target.value })} disabled={!!editing?.source_package_name}>
              <option value="streamable_http">{t('pages:mcpGateway.servers.modal.transportStreamableHttp')}</option>
              <option value="stdio">{t('pages:mcpGateway.servers.modal.transportStdioOption')}</option>
            </select>
            {editing?.source_package_name && <p className="text-xs text-muted-foreground mt-1">{t('pages:mcpGateway.servers.modal.transportLocked')}</p>}
          </div>
          {form.transport_type === 'stdio' ? (
            <>
              <div>
                <label className="label">{t('pages:mcpGateway.servers.modal.command')}</label>
                <input className="input w-full font-mono text-sm" value={form.command} onChange={e => setForm({ ...form, command: e.target.value })} placeholder="npx -y @modelcontextprotocol/server-jira" disabled={!!editing?.source_package_name} />
                {editing?.source_package_name && <p className="text-xs text-muted-foreground mt-1">{t('pages:mcpGateway.servers.modal.commandManaged')}</p>}
              </div>
              <div>
                <label className="label">{t('pages:mcpGateway.servers.modal.arguments')}</label>
                <input className="input w-full font-mono text-sm" value={form.args} onChange={e => setForm({ ...form, args: e.target.value })} placeholder="--port 8080 --debug" />
              </div>
              <div>
                <label className="label">{t('pages:mcpGateway.servers.modal.envVars')}</label>
                <textarea className="input w-full font-mono text-sm" rows={3} value={form.env_vars} onChange={e => setForm({ ...form, env_vars: e.target.value })} placeholder={'API_KEY=your-key\nANOTHER_VAR=value'} />
                {editing?.has_env_vars && <p className="text-xs text-muted-foreground mt-1">{t('pages:mcpGateway.servers.modal.envVarsPrefilled')}</p>}
              </div>
            </>
          ) : (
            <div>
              <label className="label">{t('pages:mcpGateway.servers.modal.url')}</label>
              <input className="input w-full" value={form.url} onChange={e => setForm({ ...form, url: e.target.value })} placeholder="https://upstream:8080/mcp" />
            </div>
          )}
          <div>
            <label className="label">{t('pages:mcpGateway.servers.modal.description')}</label>
            <input className="input w-full" value={form.description} onChange={e => setForm({ ...form, description: e.target.value })} />
          </div>
          <div className="grid grid-cols-3 gap-4">
            <div>
              <label className="label">{t('pages:mcpGateway.servers.modal.authType')}</label>
              <select className="input w-full" value={form.auth_type} onChange={e => setForm({ ...form, auth_type: e.target.value })}>
                <option value="none">{t('pages:mcpGateway.servers.modal.authNone')}</option>
                <option value="bearer">{t('pages:mcpGateway.servers.modal.authBearer')}</option>
                <option value="header">{t('pages:mcpGateway.servers.modal.authHeader')}</option>
                <option value="oauth">{t('pages:mcpGateway.servers.modal.authOAuth')}</option>
              </select>
            </div>
            {form.auth_type !== 'none' && form.auth_type !== 'oauth' && (
              <>
                <div>
                  <label className="label">{t('pages:mcpGateway.servers.modal.authHeaderLabel')}</label>
                  <input className="input w-full" value={form.auth_header} onChange={e => setForm({ ...form, auth_header: e.target.value })} placeholder="Authorization" />
                </div>
                <div>
                  <label className="label">{t('pages:mcpGateway.servers.modal.authSecret')}</label>
                  <input className="input w-full" type="password" value={form.auth_secret} onChange={e => setForm({ ...form, auth_secret: e.target.value })} placeholder={editing ? t('pages:mcpGateway.servers.modal.authSecretKeep') : 'secret'} />
                </div>
              </>
            )}
          </div>
          {form.auth_type === 'oauth' && (
            <div className="rounded-md border border-border bg-muted/30 p-3 space-y-3">
              <div className="text-sm font-medium flex items-center gap-2">
                <KeyRound className="w-4 h-4 text-primary" /> {t('pages:mcpGateway.servers.modal.oauthConfig')}
              </div>
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="label">{t('pages:mcpGateway.servers.modal.clientId')}</label>
                  <input className="input w-full" value={form.oauth_client_id} onChange={e => setForm({ ...form, oauth_client_id: e.target.value })} placeholder="oauth-client-id" />
                </div>
                <div>
                  <label className="label">{t('pages:mcpGateway.servers.modal.clientSecret')}</label>
                  <input className="input w-full" type="password" value={form.oauth_client_secret} onChange={e => setForm({ ...form, oauth_client_secret: e.target.value })} placeholder={editing?.oauth_enabled ? t('pages:mcpGateway.servers.modal.authSecretKeep') : 'client secret'} />
                </div>
              </div>
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="label">{t('pages:mcpGateway.servers.modal.scopes')}</label>
                  <input className="input w-full" value={form.oauth_scopes} onChange={e => setForm({ ...form, oauth_scopes: e.target.value })} placeholder="read write" />
                </div>
                <div>
                  <label className="label">{t('pages:mcpGateway.servers.modal.authServerMetadataUrl')}</label>
                  <input className="input w-full" value={form.oauth_auth_server_metadata_url} onChange={e => setForm({ ...form, oauth_auth_server_metadata_url: e.target.value })} placeholder="https://auth-server/.well-known/oauth-authorization-server" />
                </div>
              </div>
              <p className="text-xs text-muted-foreground">{t('pages:mcpGateway.servers.modal.oauthAfterSave')}</p>
            </div>
          )}
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="label">{t('pages:mcpGateway.servers.modal.timeoutMs')}</label>
              <input className="input w-full" type="number" value={form.timeout_ms} onChange={e => setForm({ ...form, timeout_ms: Number(e.target.value) })} />
            </div>
            <div>
              <label className="label">{t('pages:mcpGateway.servers.modal.maxBodyBytes')}</label>
              <input className="input w-full" type="number" value={form.max_body_bytes} onChange={e => setForm({ ...form, max_body_bytes: Number(e.target.value) })} />
            </div>
          </div>
          <div className="flex items-center gap-4">
            <label className="flex items-center gap-2">
              <input type="checkbox" checked={form.enabled} onChange={e => setForm({ ...form, enabled: e.target.checked })} />
              <span className="text-sm">{t('pages:mcpGateway.servers.modal.enabled')}</span>
            </label>
            {form.transport_type !== 'stdio' && (
              <label className="flex items-center gap-2">
                <input type="checkbox" checked={form.verify_tls} onChange={e => setForm({ ...form, verify_tls: e.target.checked })} />
                <span className="text-sm">{t('pages:mcpGateway.servers.modal.verifyTls')}</span>
              </label>
            )}
          </div>
          {error && <p className="text-sm text-red-400">{error}</p>}
          <div className="flex justify-end gap-2">
            <button className="btn-secondary" onClick={() => setModalOpen(false)}>{t('common:actions.cancel')}</button>
            <button className="btn-primary" onClick={save} disabled={saving}>{saving ? t('common:actions.saving') : t('common:actions.save')}</button>
          </div>
        </div>
      </Modal>
    </div>
  )
}
