import { useEffect, useState, useCallback } from 'react'
import { useTranslation } from 'react-i18next'
import { Plus, Trash2, Pencil, Users, ChevronDown, ChevronRight, UserPlus } from 'lucide-react'
import { mcp, users as usersApi } from '../../services/api'
import Modal from '../Modal'
import { IconButton, Badge } from '../ui'

interface Team {
  id: number
  name: string
  slug: string
  description: string | null
  created_at: string
  updated_at: string
}

interface User {
  id: number
  username: string
  email: string | null
  is_admin: boolean
}

interface TeamMember {
  id: number
  user_id: number
  team_id: number
  created_at: string
}

const emptyForm = { name: '', slug: '', description: '' }

export default function McpTeamsTab() {
  const { t } = useTranslation(['pages', 'common'])
  const [teams, setTeams] = useState<Team[]>([])
  const [allUsers, setAllUsers] = useState<User[]>([])
  const [loading, setLoading] = useState(true)
  const [modalOpen, setModalOpen] = useState(false)
  const [editing, setEditing] = useState<Team | null>(null)
  const [form, setForm] = useState(emptyForm)
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState('')
  const [expandedId, setExpandedId] = useState<number | null>(null)
  const [members, setMembers] = useState<Record<number, TeamMember[]>>({})
  const [memberUserMap, setMemberUserMap] = useState<Record<number, User>>({})
  const [addMemberTeamId, setAddMemberTeamId] = useState<number | null>(null)
  const [selectedUserId, setSelectedUserId] = useState(0)
  const [memberError, setMemberError] = useState('')

  const fetch = useCallback(async () => {
    try {
      const [teamResp, userResp] = await Promise.all([mcp.teams.list(), usersApi.list()])
      setTeams(teamResp.data)
      setAllUsers(userResp.data)
    } catch { setTeams([]) }
    finally { setLoading(false) }
  }, [])

  useEffect(() => { fetch() }, [fetch])

  const fetchMembers = async (teamId: number) => {
    try {
      const resp = await mcp.teams.listMembers(teamId)
      setMembers(prev => ({ ...prev, [teamId]: resp.data }))
      const userMap: Record<number, User> = {}
      for (const m of resp.data) {
        const u = allUsers.find(u => u.id === m.user_id)
        if (u) userMap[m.user_id] = u
      }
      setMemberUserMap(prev => ({ ...prev, ...userMap }))
    } catch { setMembers(prev => ({ ...prev, [teamId]: [] })) }
  }

  const toggleExpand = (teamId: number) => {
    if (expandedId === teamId) {
      setExpandedId(null)
    } else {
      setExpandedId(teamId)
      if (!members[teamId]) fetchMembers(teamId)
    }
  }

  const openCreate = () => {
    setEditing(null)
    setForm(emptyForm)
    setError('')
    setModalOpen(true)
  }

  const openEdit = (t: Team) => {
    setEditing(t)
    setForm({ name: t.name, slug: t.slug, description: t.description || '' })
    setError('')
    setModalOpen(true)
  }

  const save = async () => {
    setSaving(true)
    setError('')
    try {
      const data: Record<string, unknown> = { ...form }
      if (!data.description) data.description = null
      if (editing) {
        await mcp.teams.update(editing.id, data)
      } else {
        await mcp.teams.create(data)
      }
      setModalOpen(false)
      fetch()
    } catch (err: any) {
      setError(err?.response?.data?.detail || t('pages:mcpGateway.teams.saveFailed'))
    } finally { setSaving(false) }
  }

  const del = async (id: number) => {
    if (!confirm(t('pages:mcpGateway.teams.deleteConfirm'))) return
    try { await mcp.teams.delete(id); fetch() } catch { /* ignore */ }
  }

  const addMember = async () => {
    if (!addMemberTeamId || !selectedUserId) return
    setMemberError('')
    try {
      await mcp.teams.addMember(addMemberTeamId, selectedUserId)
      setAddMemberTeamId(null)
      setSelectedUserId(0)
      fetchMembers(addMemberTeamId)
    } catch (err: any) {
      setMemberError(err?.response?.data?.detail || t('pages:mcpGateway.teams.addMemberFailed'))
    }
  }

  const removeMember = async (teamId: number, userId: number) => {
    try {
      await mcp.teams.removeMember(teamId, userId)
      fetchMembers(teamId)
    } catch { /* ignore */ }
  }

  if (loading) return <p className="text-sm text-muted-foreground">{t('common:actions.loading')}</p>

  return (
    <div className="space-y-4">
      <div className="flex justify-between items-center">
        <p className="text-sm text-muted-foreground">{t('pages:mcpGateway.teams.count', { count: teams.length })}</p>
        <button className="btn-primary text-sm" onClick={openCreate}>
          <Plus className="w-4 h-4 inline me-1" /> {t('pages:mcpGateway.teams.addTeam')}
        </button>
      </div>

      {teams.length === 0 ? (
        <div className="rounded-lg border border-border bg-card p-8 text-center">
          <Users className="h-8 w-8 mx-auto mb-2 text-muted-foreground" />
          <p className="text-sm text-muted-foreground">{t('pages:mcpGateway.teams.noTeams')}</p>
        </div>
      ) : (
        <div className="space-y-2">
          {teams.map(team => (
            <div key={team.id} className="rounded-lg border border-border bg-card">
              <div className="p-3 flex items-center justify-between">
                <div className="flex items-center gap-2 flex-1 min-w-0">
                  <button onClick={() => toggleExpand(team.id)} className="text-muted-foreground hover:text-foreground">
                    {expandedId === team.id ? <ChevronDown className="w-4 h-4" /> : <ChevronRight className="w-4 h-4" />}
                  </button>
                  <div className="flex-1 min-w-0">
                    <div className="font-medium flex items-center gap-2">
                      {team.name}
                      <Badge variant="default" size="sm">{team.slug}</Badge>
                    </div>
                    <div className="text-xs text-muted-foreground">{team.description || t('pages:mcpGateway.teams.noDescription')}</div>
                  </div>
                </div>
                <div className="flex items-center gap-1">
                  <IconButton icon={Pencil} aria-label={t('pages:mcpGateway.teams.tooltips.editTeam')} onClick={() => openEdit(team)} />
                  <IconButton icon={Trash2} variant="danger" aria-label={t('pages:mcpGateway.teams.tooltips.deleteTeam')} onClick={() => del(team.id)} />
                </div>
              </div>
              {expandedId === team.id && (
                <div className="border-t border-border p-3 space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="text-sm font-medium">{t('pages:mcpGateway.teams.members')}</span>
                    <button className="btn-secondary text-xs" onClick={() => { setAddMemberTeamId(team.id); setSelectedUserId(0); setMemberError('') }}>
                      <UserPlus className="w-3 h-3 inline me-1" /> {t('pages:mcpGateway.teams.addMember')}
                    </button>
                  </div>
                  {(members[team.id] || []).length === 0 ? (
                    <p className="text-xs text-muted-foreground">{t('pages:mcpGateway.teams.noMembers')}</p>
                  ) : (
                    <div className="space-y-1">
                      {(members[team.id] || []).map(m => {
                        const u = memberUserMap[m.user_id]
                        return (
                          <div key={m.id} className="flex items-center justify-between text-sm rounded border border-border px-2 py-1">
                            <div className="flex items-center gap-2">
                              <span className="font-medium">{u?.username || t('pages:mcpGateway.teams.userLabel', { id: m.user_id })}</span>
                              {u?.is_admin && <Badge variant="info" size="sm">{t('pages:mcpGateway.teams.admin')}</Badge>}
                              {u?.email && <span className="text-xs text-muted-foreground">{u.email}</span>}
                            </div>
                            <IconButton icon={Trash2} variant="danger" aria-label={t('pages:mcpGateway.teams.tooltips.removeMember')} onClick={() => removeMember(team.id, m.user_id)} />
                          </div>
                        )
                      })}
                    </div>
                  )}
                  {addMemberTeamId === team.id && (
                    <div className="space-y-2 border border-border rounded p-2">
                      <select className="input w-full text-sm" value={selectedUserId} onChange={e => setSelectedUserId(Number(e.target.value))}>
                        <option value={0}>{t('pages:mcpGateway.teams.selectUser')}</option>
                        {allUsers
                          .filter(u => !(members[team.id] || []).some(m => m.user_id === u.id))
                          .map(u => <option key={u.id} value={u.id}>{u.username}{u.email ? ` (${u.email})` : ''}</option>)}
                      </select>
                      {memberError && <p className="text-xs text-red-400">{memberError}</p>}
                      <div className="flex justify-end gap-2">
                        <button className="btn-secondary text-xs" onClick={() => setAddMemberTeamId(null)}>{t('common:actions.cancel')}</button>
                        <button className="btn-primary text-xs" onClick={addMember} disabled={!selectedUserId}>{t('common:actions.add')}</button>
                      </div>
                    </div>
                  )}
                </div>
              )}
            </div>
          ))}
        </div>
      )}

      <Modal open={modalOpen} onClose={() => setModalOpen(false)} title={editing ? t('pages:mcpGateway.teams.editTeam') : t('pages:mcpGateway.teams.addTeam')}>
        <div className="space-y-4">
          <div>
            <label className="label">{t('pages:mcpGateway.teams.modal.name')}</label>
            <input className="input w-full" value={form.name} onChange={e => setForm({ ...form, name: e.target.value })} placeholder={t('pages:mcpGateway.teams.modal.namePlaceholder')} />
          </div>
          <div>
            <label className="label">{t('pages:mcpGateway.teams.modal.slug')}</label>
            <input className="input w-full font-mono text-sm" value={form.slug} onChange={e => setForm({ ...form, slug: e.target.value })} placeholder={t('pages:mcpGateway.teams.modal.slugPlaceholder')} />
            <p className="text-xs text-muted-foreground mt-1">{t('pages:mcpGateway.teams.slugHint')}</p>
          </div>
          <div>
            <label className="label">{t('pages:mcpGateway.teams.modal.description')}</label>
            <input className="input w-full" value={form.description} onChange={e => setForm({ ...form, description: e.target.value })} />
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
