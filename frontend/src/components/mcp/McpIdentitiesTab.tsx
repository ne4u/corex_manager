import { useEffect, useState, useCallback } from 'react'
import { useTranslation } from 'react-i18next'
import { Plus, Trash2, Pencil, KeyRound, Copy, Check, ChevronDown, ChevronRight, Ban } from 'lucide-react'
import { mcp } from '../../services/api'
import Modal from '../Modal'
import { IconButton, Badge } from '../ui'
import { useDateTime } from '../../contexts/DateTimeContext'

interface McpIdentity {
  id: number
  team_id: number
  name: string
  description: string | null
  subject: string | null
  kind: string
  pat_prefix: string | null
  jwt_issuer: string | null
  jwt_audience: string | null
  jwt_jwks_url: string | null
  enabled: boolean
  expires_at: string | null
  created_at: string
  last_used_at: string | null
}

interface Team { id: number; name: string; slug: string }

const emptyForm = {
  team_id: 0, name: '', description: '', subject: '', kind: 'pat',
  jwt_issuer: '', jwt_audience: '', jwt_jwks_url: '', enabled: true, expires_at: '',
}

export default function McpIdentitiesTab() {
  const { t } = useTranslation(['pages', 'common'])
  const { formatDateTime } = useDateTime()
  const [identities, setIdentities] = useState<McpIdentity[]>([])
  const [teams, setTeams] = useState<Team[]>([])
  const [loading, setLoading] = useState(true)
  const [modalOpen, setModalOpen] = useState(false)
  const [editing, setEditing] = useState<McpIdentity | null>(null)
  const [form, setForm] = useState(emptyForm)
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState('')
  const [patResult, setPatResult] = useState<{ identity_id: number; pat: string; prefix: string } | null>(null)
  const [copied, setCopied] = useState(false)
  const [expandedId, setExpandedId] = useState<number | null>(null)
  const [sessions, setSessions] = useState<Record<number, any[]>>({})
  const [revoking, setRevoking] = useState(false)

  const fetch = useCallback(async () => {
    try {
      const [idResp, teamResp] = await Promise.all([mcp.identities.list(), mcp.teams.list()])
      setIdentities(idResp.data)
      setTeams(teamResp.data)
      if (teamResp.data.length > 0 && form.team_id === 0) {
        setForm(f => ({ ...f, team_id: teamResp.data[0].id }))
      }
    } catch { setIdentities([]) }
    finally { setLoading(false) }
  }, [form.team_id])

  useEffect(() => { fetch() }, [fetch])

  const openCreate = () => {
    setEditing(null)
    setForm({ ...emptyForm, team_id: teams[0]?.id || 0 })
    setError('')
    setModalOpen(true)
  }

  const openEdit = (i: McpIdentity) => {
    setEditing(i)
    setForm({
      team_id: i.team_id, name: i.name, description: i.description || '',
      subject: i.subject || '', kind: i.kind,
      jwt_issuer: i.jwt_issuer || '', jwt_audience: i.jwt_audience || '',
      jwt_jwks_url: i.jwt_jwks_url || '', enabled: i.enabled,
      expires_at: i.expires_at ? i.expires_at.slice(0, 19) : '',
    })
    setError('')
    setModalOpen(true)
  }

  const save = async () => {
    setSaving(true)
    setError('')
    try {
      const data: Record<string, unknown> = { ...form }
      if (!data.description) data.description = null
      if (!data.subject) data.subject = null
      if (!data.jwt_issuer) data.jwt_issuer = null
      if (!data.jwt_audience) data.jwt_audience = null
      if (!data.jwt_jwks_url) data.jwt_jwks_url = null
      if (!data.expires_at) data.expires_at = null
      if (editing) {
        await mcp.identities.update(editing.id, data)
      } else {
        await mcp.identities.create(data)
      }
      setModalOpen(false)
      fetch()
    } catch (err: any) {
      setError(err?.response?.data?.detail || t('pages:mcpGateway.identities.saveFailed'))
    } finally { setSaving(false) }
  }

  const del = async (id: number) => {
    if (!confirm(t('pages:mcpGateway.identities.deleteConfirm'))) return
    try { await mcp.identities.delete(id); fetch() } catch { /* ignore */ }
  }

  const issuePat = async (id: number) => {
    try {
      const resp = await mcp.identities.issuePat(id)
      setPatResult(resp.data)
      setCopied(false)
    } catch { /* ignore */ }
  }

  const copyPat = () => {
    if (patResult) {
      navigator.clipboard.writeText(patResult.pat)
      setCopied(true)
    }
  }

  const toggleExpand = async (identityId: number) => {
    if (expandedId === identityId) {
      setExpandedId(null)
    } else {
      setExpandedId(identityId)
      if (!sessions[identityId]) {
        try {
          const resp = await mcp.sessions.list({ identity_id: identityId })
          setSessions(prev => ({ ...prev, [identityId]: resp.data.sessions || resp.data }))
        } catch { setSessions(prev => ({ ...prev, [identityId]: [] })) }
      }
    }
  }

  const revokeSession = async (sessionId: string, identityId: number) => {
    setRevoking(true)
    try {
      await mcp.sessions.revoke(sessionId)
      const resp = await mcp.sessions.list({ identity_id: identityId })
      setSessions(prev => ({ ...prev, [identityId]: resp.data.sessions || resp.data }))
    } catch { /* ignore */ }
    finally { setRevoking(false) }
  }

  const revokeIdentity = async (identityId: number) => {
    if (!confirm(t('pages:mcpGateway.identities.revokeIdentityConfirm'))) return
    setRevoking(true)
    try {
      await mcp.sessions.revokeIdentity(identityId)
      setSessions(prev => ({ ...prev, [identityId]: [] }))
    } catch { /* ignore */ }
    finally { setRevoking(false) }
  }

  if (loading) return <p className="text-sm text-muted-foreground">{t('common:actions.loading')}</p>

  return (
    <div className="space-y-4">
      <div className="flex justify-between items-center">
        <p className="text-sm text-muted-foreground">{t('pages:mcpGateway.identities.count', { count: identities.length })}</p>
        <button className="btn-primary text-sm" onClick={openCreate}>
          <Plus className="w-4 h-4 inline me-1" /> {t('pages:mcpGateway.identities.addIdentity')}
        </button>
      </div>

      {identities.length === 0 ? (
        <div className="rounded-lg border border-border bg-card p-8 text-center">
          <KeyRound className="h-8 w-8 mx-auto mb-2 text-muted-foreground" />
          <p className="text-sm text-muted-foreground">{t('pages:mcpGateway.identities.noIdentities')}</p>
        </div>
      ) : (
        <div className="space-y-2">
          {identities.map(i => (
            <div key={i.id} className="rounded-lg border border-border bg-card">
              <div className="p-3 flex items-center justify-between">
                <div className="flex items-center gap-2 flex-1 min-w-0">
                  <button onClick={() => toggleExpand(i.id)} className="text-muted-foreground hover:text-foreground">
                    {expandedId === i.id ? <ChevronDown className="w-4 h-4" /> : <ChevronRight className="w-4 h-4" />}
                  </button>
                  <div className="flex-1 min-w-0">
                    <div className="font-medium flex items-center gap-2">
                      {i.name}
                      <Badge variant={i.enabled ? 'success' : 'default'} size="sm">{i.enabled ? t('pages:mcpGateway.identities.enabled') : t('pages:mcpGateway.identities.disabled')}</Badge>
                      <Badge variant="info" size="sm">{i.kind.toUpperCase()}</Badge>
                    </div>
                    <div className="text-xs text-muted-foreground">
                      {i.kind === 'pat' && i.pat_prefix ? t('pages:mcpGateway.identities.patPrefix', { prefix: i.pat_prefix }) : i.subject || t('pages:mcpGateway.identities.noSubject')}
                      {i.last_used_at && ` · ${t('pages:mcpGateway.identities.lastUsed', { date: formatDateTime(i.last_used_at) })}`}
                      {i.expires_at && ` · ${t('pages:mcpGateway.identities.expires', { date: formatDateTime(i.expires_at) })}`}
                    </div>
                  </div>
                </div>
                <div className="flex items-center gap-1">
                  {i.kind === 'pat' && (
                    <button className="btn-secondary text-xs" onClick={() => issuePat(i.id)}>{t('pages:mcpGateway.identities.issuePat')}</button>
                  )}
                  <IconButton icon={Ban} aria-label={t('pages:mcpGateway.identities.tooltips.revokeAllTokens')} onClick={() => revokeIdentity(i.id)} />
                  <IconButton icon={Pencil} aria-label={t('pages:mcpGateway.identities.tooltips.editIdentity')} onClick={() => openEdit(i)} />
                  <IconButton icon={Trash2} variant="danger" aria-label={t('pages:mcpGateway.identities.tooltips.deleteIdentity')} onClick={() => del(i.id)} />
                </div>
              </div>
              {expandedId === i.id && (
                <div className="border-t border-border p-3 space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="text-sm font-medium">{t('pages:mcpGateway.identities.activeSessions')}</span>
                    {(sessions[i.id] || []).length > 0 && (
                      <button className="btn-secondary text-xs" onClick={() => revokeIdentity(i.id)} disabled={revoking}>
                        <Ban className="w-3 h-3 inline me-1" /> {t('pages:mcpGateway.identities.revokeAll')}
                      </button>
                    )}
                  </div>
                  {(sessions[i.id] || []).length === 0 ? (
                    <p className="text-xs text-muted-foreground">{t('pages:mcpGateway.identities.noActiveSessions')}</p>
                  ) : (
                    <div className="space-y-1">
                      {(sessions[i.id] || []).map((s: any) => (
                        <div key={s.session_id || s.id} className="flex items-center justify-between text-sm rounded border border-border px-2 py-1">
                          <div className="flex items-center gap-2 min-w-0">
                            <code className="text-xs truncate">{s.session_id || s.id}</code>
                            <span className="text-xs text-muted-foreground">{t('pages:mcpGateway.identities.sessionCreated', { date: formatDateTime(s.created_at) })}</span>
                          </div>
                          <IconButton icon={Trash2} variant="danger" aria-label={t('pages:mcpGateway.identities.tooltips.revokeSession')} onClick={() => revokeSession(s.session_id || s.id, i.id)} />
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}
            </div>
          ))}
        </div>
      )}

      <Modal open={modalOpen} onClose={() => setModalOpen(false)} title={editing ? t('pages:mcpGateway.identities.editIdentity') : t('pages:mcpGateway.identities.addIdentity')}>
        <div className="space-y-4">
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="label">{t('pages:mcpGateway.identities.modal.team')}</label>
              <select className="input w-full" value={form.team_id} onChange={e => setForm({ ...form, team_id: Number(e.target.value) })}>
                {teams.map(t => <option key={t.id} value={t.id}>{t.name}</option>)}
              </select>
            </div>
            <div>
              <label className="label">{t('pages:mcpGateway.identities.modal.name')}</label>
              <input className="input w-full" value={form.name} onChange={e => setForm({ ...form, name: e.target.value })} placeholder={t('pages:mcpGateway.identities.modal.namePlaceholder')} />
            </div>
          </div>
          <div>
            <label className="label">{t('pages:mcpGateway.identities.modal.description')}</label>
            <input className="input w-full" value={form.description} onChange={e => setForm({ ...form, description: e.target.value })} />
          </div>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="label">{t('pages:mcpGateway.identities.modal.kind')}</label>
              <select className="input w-full" value={form.kind} onChange={e => setForm({ ...form, kind: e.target.value })}>
                <option value="pat">PAT</option>
                <option value="jwt">JWT</option>
              </select>
            </div>
            <div>
              <label className="label">{t('pages:mcpGateway.identities.modal.subject')}</label>
              <input className="input w-full" value={form.subject} onChange={e => setForm({ ...form, subject: e.target.value })} placeholder={t('pages:mcpGateway.identities.modal.subjectPlaceholder')} />
            </div>
          </div>
          {form.kind === 'jwt' && (
            <div className="grid grid-cols-1 gap-4">
              <div>
                <label className="label">{t('pages:mcpGateway.identities.modal.jwtIssuer')}</label>
                <input className="input w-full" value={form.jwt_issuer} onChange={e => setForm({ ...form, jwt_issuer: e.target.value })} />
              </div>
              <div>
                <label className="label">{t('pages:mcpGateway.identities.modal.jwtAudience')}</label>
                <input className="input w-full" value={form.jwt_audience} onChange={e => setForm({ ...form, jwt_audience: e.target.value })} />
              </div>
              <div>
                <label className="label">{t('pages:mcpGateway.identities.modal.jwksUrl')}</label>
                <input className="input w-full" value={form.jwt_jwks_url} onChange={e => setForm({ ...form, jwt_jwks_url: e.target.value })} />
              </div>
            </div>
          )}
          <div>
            <label className="label">{t('pages:mcpGateway.identities.modal.expiresAt')}</label>
            <input className="input w-full" type="datetime-local" value={form.expires_at} onChange={e => setForm({ ...form, expires_at: e.target.value })} />
          </div>
          <label className="flex items-center gap-2">
            <input type="checkbox" checked={form.enabled} onChange={e => setForm({ ...form, enabled: e.target.checked })} />
            <span className="text-sm">{t('pages:mcpGateway.identities.enabled')}</span>
          </label>
          {error && <p className="text-sm text-red-400">{error}</p>}
          <div className="flex justify-end gap-2">
            <button className="btn-secondary" onClick={() => setModalOpen(false)}>{t('common:actions.cancel')}</button>
            <button className="btn-primary" onClick={save} disabled={saving}>{saving ? t('common:actions.saving') : t('common:actions.save')}</button>
          </div>
        </div>
      </Modal>

      <Modal open={!!patResult} onClose={() => setPatResult(null)} title={t('pages:mcpGateway.identities.modal.patIssued')}>
        <div className="space-y-4">
          <p className="text-sm text-amber-400">{t('pages:mcpGateway.identities.modal.patWarning')}</p>
          <div className="flex items-center gap-2">
            <code className="flex-1 bg-muted px-3 py-2 rounded text-sm break-all">{patResult?.pat}</code>
            <button className="btn-secondary" onClick={copyPat}>
              {copied ? <Check className="w-4 h-4" /> : <Copy className="w-4 h-4" />}
            </button>
          </div>
          <div className="flex justify-end">
            <button className="btn-primary" onClick={() => setPatResult(null)}>{t('common:actions.done')}</button>
          </div>
        </div>
      </Modal>
    </div>
  )
}
