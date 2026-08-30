import { useEffect, useState, useCallback } from 'react'
import { useTranslation } from 'react-i18next'
import { Plus, Trash2, Pencil, Shield, Code2 } from 'lucide-react'
import { mcp } from '../../services/api'
import Modal from '../Modal'
import { IconButton, Badge } from '../ui'

interface McpPolicy {
  id: number
  team_id: number
  name: string
  enabled: boolean
  priority: number
  expression: string
  expression_ast: Record<string, unknown> | null
  action: string
  log: boolean
  no_log: boolean
  created_at: string
  updated_at: string
}

interface Team { id: number; name: string; slug: string }

const EXPRESSION_FIELDS = [
  { label: 'method', insert: 'method', descKey: 'pages:mcpGateway.policies.expressionFields.method' },
  { label: 'tool', insert: 'tool', descKey: 'pages:mcpGateway.policies.expressionFields.tool' },
  { label: 'server', insert: 'server', descKey: 'pages:mcpGateway.policies.expressionFields.server' },
  { label: 'identity_name', insert: 'identity_name', descKey: 'pages:mcpGateway.policies.expressionFields.identity_name' },
  { label: 'identity_kind', insert: 'identity_kind', descKey: 'pages:mcpGateway.policies.expressionFields.identity_kind' },
  { label: 'team_slug', insert: 'team_slug', descKey: 'pages:mcpGateway.policies.expressionFields.team_slug' },
  { label: 'claims.sub', insert: 'claims["sub"]', descKey: 'pages:mcpGateway.policies.expressionFields.claimsSub' },
  { label: 'claims.iss', insert: 'claims["iss"]', descKey: 'pages:mcpGateway.policies.expressionFields.claimsIss' },
]

const EXPRESSION_OPERATORS = [
  { label: '==', insert: ' == ' },
  { label: '!=', insert: ' != ' },
  { label: 'matches', insert: ' matches ' },
  { label: '&&', insert: ' && ' },
  { label: '||', insert: ' || ' },
]

const EXPRESSION_TEMPLATES = [
  { labelKey: 'pages:mcpGateway.policies.expressionTemplates.allowSpecificTool', expr: "method == 'tools/call' && tool == 'tool_name'" },
  { labelKey: 'pages:mcpGateway.policies.expressionTemplates.allowToolPrefix', expr: "method == 'tools/call' && tool matches 'prefix__*'" },
  { labelKey: 'pages:mcpGateway.policies.expressionTemplates.denyByIdentity', expr: "identity_name == 'name' && action == 'deny'" },
  { labelKey: 'pages:mcpGateway.policies.expressionTemplates.jwtSubjectCheck', expr: 'claims["sub"] == "subject-value"' },
  { labelKey: 'pages:mcpGateway.policies.expressionTemplates.serverMethod', expr: "server == 'namespace' && method == 'tools/call'" },
]

const emptyForm = {
  team_id: 0, name: '', enabled: true, expression: '', action: 'allow', log: true, no_log: false,
}

export default function McpPoliciesTab() {
  const { t } = useTranslation(['pages', 'common'])
  const [policies, setPolicies] = useState<McpPolicy[]>([])
  const [teams, setTeams] = useState<Team[]>([])
  const [loading, setLoading] = useState(true)
  const [modalOpen, setModalOpen] = useState(false)
  const [editing, setEditing] = useState<McpPolicy | null>(null)
  const [form, setForm] = useState(emptyForm)
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState('')

  const fetch = useCallback(async () => {
    try {
      const [polResp, teamResp] = await Promise.all([mcp.policies.list(), mcp.teams.list()])
      setPolicies(polResp.data)
      setTeams(teamResp.data)
      if (teamResp.data.length > 0 && form.team_id === 0) {
        setForm(f => ({ ...f, team_id: teamResp.data[0].id }))
      }
    } catch { setPolicies([]) }
    finally { setLoading(false) }
  }, [form.team_id])

  useEffect(() => { fetch() }, [fetch])

  const openCreate = () => {
    setEditing(null)
    setForm({ ...emptyForm, team_id: teams[0]?.id || 0 })
    setError('')
    setModalOpen(true)
  }

  const openEdit = (p: McpPolicy) => {
    setEditing(p)
    setForm({
      team_id: p.team_id, name: p.name, enabled: p.enabled,
      expression: p.expression, action: p.action, log: p.log, no_log: p.no_log,
    })
    setError('')
    setModalOpen(true)
  }

  const save = async () => {
    setSaving(true)
    setError('')
    try {
      if (editing) {
        await mcp.policies.update(editing.id, form)
      } else {
        await mcp.policies.create(form)
      }
      setModalOpen(false)
      fetch()
    } catch (err: any) {
      setError(err?.response?.data?.detail || t('pages:mcpGateway.policies.saveFailed'))
    } finally { setSaving(false) }
  }

  const del = async (id: number) => {
    if (!confirm(t('pages:mcpGateway.policies.deleteConfirm'))) return
    try { await mcp.policies.delete(id); fetch() } catch { /* ignore */ }
  }

  const actionVariant = (action: string) => {
    switch (action) {
      case 'allow': return 'success'
      case 'deny': return 'error'
      case 'skip_dlp': return 'warning'
      case 'skip_ratelimit': return 'info'
      default: return 'default'
    }
  }

  if (loading) return <p className="text-sm text-muted-foreground">{t('common:actions.loading')}</p>

  return (
    <div className="space-y-4">
      <div className="flex justify-between items-center">
        <p className="text-sm text-muted-foreground">{t('pages:mcpGateway.policies.count', { count: policies.length })}</p>
        <button className="btn-primary text-sm" onClick={openCreate}>
          <Plus className="w-4 h-4 inline me-1" /> {t('pages:mcpGateway.policies.addPolicy')}
        </button>
      </div>

      {policies.length === 0 ? (
        <div className="rounded-lg border border-border bg-card p-8 text-center">
          <Shield className="h-8 w-8 mx-auto mb-2 text-muted-foreground" />
          <p className="text-sm text-muted-foreground">{t('pages:mcpGateway.policies.noPolicies')}</p>
        </div>
      ) : (
        <div className="space-y-2">
          {policies.sort((a, b) => a.priority - b.priority).map(p => (
            <div key={p.id} className="rounded-lg border border-border bg-card p-3 flex items-center justify-between">
              <div className="flex-1 min-w-0">
                <div className="font-medium flex items-center gap-2">
                  <span className="text-xs text-muted-foreground">#{p.priority}</span>
                  {p.name}
                  <Badge variant={p.enabled ? 'success' : 'default'} size="sm">{p.enabled ? t('pages:mcpGateway.policies.on') : t('pages:mcpGateway.policies.off')}</Badge>
                  <Badge variant={actionVariant(p.action)} size="sm">{p.action}</Badge>
                  {p.no_log && <Badge variant="warning" size="sm">{t('pages:mcpGateway.policies.noLog')}</Badge>}
                </div>
                <div className="text-xs text-muted-foreground font-mono truncate">{p.expression}</div>
              </div>
              <div className="flex items-center gap-1">
                <IconButton icon={Pencil} aria-label={t('pages:mcpGateway.policies.tooltips.editPolicy')} onClick={() => openEdit(p)} />
                <IconButton icon={Trash2} variant="danger" aria-label={t('pages:mcpGateway.policies.tooltips.deletePolicy')} onClick={() => del(p.id)} />
              </div>
            </div>
          ))}
        </div>
      )}

      <Modal open={modalOpen} onClose={() => setModalOpen(false)} title={editing ? t('pages:mcpGateway.policies.editPolicy') : t('pages:mcpGateway.policies.addPolicy')}>
        <div className="space-y-4">
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="label">{t('pages:mcpGateway.policies.modal.team')}</label>
              <select className="input w-full" value={form.team_id} onChange={e => setForm({ ...form, team_id: Number(e.target.value) })}>
                {teams.map(t => <option key={t.id} value={t.id}>{t.name}</option>)}
              </select>
            </div>
            <div>
              <label className="label">{t('pages:mcpGateway.policies.modal.name')}</label>
              <input className="input w-full" value={form.name} onChange={e => setForm({ ...form, name: e.target.value })} placeholder={t('pages:mcpGateway.policies.modal.namePlaceholder')} />
            </div>
          </div>
          <div>
            <label className="label flex items-center gap-1"><Code2 className="w-3.5 h-3.5" /> {t('pages:mcpGateway.policies.modal.expression')}</label>
            <textarea className="input w-full font-mono text-sm" rows={3} value={form.expression} onChange={e => setForm({ ...form, expression: e.target.value })} placeholder={t('pages:mcpGateway.policies.modal.expressionPlaceholder')} />
            <div className="mt-2 space-y-2">
              <div className="flex flex-wrap gap-1">
                {EXPRESSION_FIELDS.map(f => (
                  <button key={f.label} type="button" className="btn-secondary text-xs py-0.5 px-2" title={t(f.descKey)} onClick={() => setForm(prev => ({ ...prev, expression: prev.expression + f.insert }))}>
                    {f.label}
                  </button>
                ))}
              </div>
              <div className="flex flex-wrap gap-1">
                {EXPRESSION_OPERATORS.map(op => (
                  <button key={op.label} type="button" className="btn-secondary text-xs py-0.5 px-2 font-mono" onClick={() => setForm(prev => ({ ...prev, expression: prev.expression + op.insert }))}>
                    {op.label}
                  </button>
                ))}
              </div>
              <div className="flex flex-wrap gap-1">
                {EXPRESSION_TEMPLATES.map(tpl => (
                  <button key={tpl.labelKey} type="button" className="btn-secondary text-xs py-0.5 px-2" onClick={() => setForm(prev => ({ ...prev, expression: tpl.expr }))}>
                    {t(tpl.labelKey)}
                  </button>
                ))}
              </div>
            </div>
            <p className="text-xs text-muted-foreground mt-1">{t('pages:mcpGateway.policies.availableFields')}</p>
          </div>
          <div>
            <label className="label">{t('pages:mcpGateway.policies.modal.action')}</label>
            <select className="input w-full" value={form.action} onChange={e => setForm({ ...form, action: e.target.value })}>
              <option value="allow">{t('pages:mcpGateway.policies.actions.allow')}</option>
              <option value="deny">{t('pages:mcpGateway.policies.actions.deny')}</option>
              <option value="skip_dlp">{t('pages:mcpGateway.policies.actions.skipDlp')}</option>
              <option value="skip_ratelimit">{t('pages:mcpGateway.policies.actions.skipRatelimit')}</option>
            </select>
          </div>
          <div className="flex items-center gap-4">
            <label className="flex items-center gap-2">
              <input type="checkbox" checked={form.enabled} onChange={e => setForm({ ...form, enabled: e.target.checked })} />
              <span className="text-sm">{t('common:status.enabled')}</span>
            </label>
            <label className="flex items-center gap-2">
              <input type="checkbox" checked={form.log} onChange={e => setForm({ ...form, log: e.target.checked })} />
              <span className="text-sm">{t('pages:mcpGateway.policies.log')}</span>
            </label>
            <label className="flex items-center gap-2">
              <input type="checkbox" checked={form.no_log} onChange={e => setForm({ ...form, no_log: e.target.checked })} />
              <span className="text-sm">{t('pages:mcpGateway.policies.noLogLabel')}</span>
            </label>
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
