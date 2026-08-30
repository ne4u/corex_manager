import { useEffect, useState, useCallback } from 'react'
import { useTranslation } from 'react-i18next'
import { Plus, Trash2, Pencil, Eye } from 'lucide-react'
import { mcp } from '../../services/api'
import Modal from '../Modal'
import { IconButton, Badge } from '../ui'

interface McpDlpRule {
  id: number
  team_id: number
  name: string
  enabled: boolean
  priority: number
  direction: string
  detector: string
  find_regex: string | null
  action: string
  token_prefix: string | null
  token_ttl: number | null
  apply_to: string
  created_at: string
  updated_at: string
}

interface Team { id: number; name: string; slug: string }

const DETECTORS = ['email', 'phone', 'ssn', 'credit_card', 'ip', 'aws_key', 'private_key', 'github_token', 'slack_token', 'custom']
const ACTIONS = ['block', 'redact', 'tokenize']
const DIRECTIONS = ['both', 'request', 'response']
const APPLY_TO = ['json_strings', 'all_text']

const emptyForm = {
  team_id: 0, name: '', enabled: true, direction: 'both', detector: 'email',
  find_regex: '', action: 'block', token_prefix: '', token_ttl: '', apply_to: 'json_strings',
}

export default function McpDlpRulesTab() {
  const { t } = useTranslation(['pages', 'common'])
  const [rules, setRules] = useState<McpDlpRule[]>([])
  const [teams, setTeams] = useState<Team[]>([])
  const [loading, setLoading] = useState(true)
  const [modalOpen, setModalOpen] = useState(false)
  const [editing, setEditing] = useState<McpDlpRule | null>(null)
  const [form, setForm] = useState(emptyForm)
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState('')

  const fetch = useCallback(async () => {
    try {
      const [rResp, tResp] = await Promise.all([mcp.dlpRules.list(), mcp.teams.list()])
      setRules(rResp.data)
      setTeams(tResp.data)
      if (tResp.data.length > 0 && form.team_id === 0) {
        setForm(f => ({ ...f, team_id: tResp.data[0].id }))
      }
    } catch { setRules([]) }
    finally { setLoading(false) }
  }, [form.team_id])

  useEffect(() => { fetch() }, [fetch])

  const openCreate = () => {
    setEditing(null)
    setForm({ ...emptyForm, team_id: teams[0]?.id || 0 })
    setError('')
    setModalOpen(true)
  }

  const openEdit = (r: McpDlpRule) => {
    setEditing(r)
    setForm({
      team_id: r.team_id, name: r.name, enabled: r.enabled, direction: r.direction,
      detector: r.detector, find_regex: r.find_regex || '', action: r.action,
      token_prefix: r.token_prefix || '', token_ttl: r.token_ttl ? String(r.token_ttl) : '',
      apply_to: r.apply_to,
    })
    setError('')
    setModalOpen(true)
  }

  const save = async () => {
    setSaving(true)
    setError('')
    try {
      const data: Record<string, unknown> = { ...form }
      if (!data.find_regex) data.find_regex = null
      if (!data.token_prefix) data.token_prefix = null
      data.token_ttl = data.token_ttl ? Number(data.token_ttl) : null
      if (editing) {
        await mcp.dlpRules.update(editing.id, data)
      } else {
        await mcp.dlpRules.create(data)
      }
      setModalOpen(false)
      fetch()
    } catch (err: any) {
      setError(err?.response?.data?.detail || t('pages:mcpGateway.dlp.failedToSave'))
    } finally { setSaving(false) }
  }

  const del = async (id: number) => {
    if (!confirm(t('pages:mcpGateway.dlp.confirmDelete'))) return
    try { await mcp.dlpRules.delete(id); fetch() } catch { /* ignore */ }
  }

  const actionVariant = (action: string) => {
    switch (action) {
      case 'block': return 'error'
      case 'redact': return 'warning'
      case 'tokenize': return 'info'
      default: return 'default'
    }
  }

  if (loading) return <p className="text-sm text-muted-foreground">{t('common:actions.loading')}</p>

  return (
    <div className="space-y-4">
      <div className="flex justify-between items-center">
        <p className="text-sm text-muted-foreground">{t('pages:mcpGateway.dlp.count', { count: rules.length })}</p>
        <button className="btn-primary text-sm" onClick={openCreate}>
          <Plus className="w-4 h-4 inline me-1" /> {t('pages:mcpGateway.dlp.add')}
        </button>
      </div>

      {rules.length === 0 ? (
        <div className="rounded-lg border border-border bg-card p-8 text-center">
          <Eye className="h-8 w-8 mx-auto mb-2 text-muted-foreground" />
          <p className="text-sm text-muted-foreground">{t('pages:mcpGateway.dlp.empty')}</p>
        </div>
      ) : (
        <div className="space-y-2">
          {rules.sort((a, b) => a.priority - b.priority).map(r => (
            <div key={r.id} className="rounded-lg border border-border bg-card p-3 flex items-center justify-between">
              <div className="flex-1 min-w-0">
                <div className="font-medium flex items-center gap-2">
                  <span className="text-xs text-muted-foreground">#{r.priority}</span>
                  {r.name}
                  <Badge variant={r.enabled ? 'success' : 'default'} size="sm">{r.enabled ? t('common:status.on') : t('common:status.off')}</Badge>
                  <Badge variant="info" size="sm">{r.detector}</Badge>
                  <Badge variant={actionVariant(r.action)} size="sm">{r.action}</Badge>
                  <Badge variant="default" size="sm">{r.direction}</Badge>
                </div>
                {r.find_regex && <div className="text-xs text-muted-foreground font-mono truncate">{r.find_regex}</div>}
              </div>
              <div className="flex items-center gap-1">
                <IconButton icon={Pencil} aria-label={t('pages:mcpGateway.dlp.tooltips.edit')} onClick={() => openEdit(r)} />
                <IconButton icon={Trash2} variant="danger" aria-label={t('pages:mcpGateway.dlp.tooltips.delete')} onClick={() => del(r.id)} />
              </div>
            </div>
          ))}
        </div>
      )}

      <Modal open={modalOpen} onClose={() => setModalOpen(false)} title={editing ? t('pages:mcpGateway.dlp.modal.editTitle') : t('pages:mcpGateway.dlp.modal.addTitle')}>
        <div className="space-y-4">
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="label">{t('pages:mcpGateway.dlp.modal.team')}</label>
              <select className="input w-full" value={form.team_id} onChange={e => setForm({ ...form, team_id: Number(e.target.value) })}>
                {teams.map(t => <option key={t.id} value={t.id}>{t.name}</option>)}
              </select>
            </div>
            <div>
              <label className="label">{t('pages:mcpGateway.dlp.modal.name')}</label>
              <input className="input w-full" value={form.name} onChange={e => setForm({ ...form, name: e.target.value })} placeholder={t('pages:mcpGateway.dlp.modal.namePlaceholder')} />
            </div>
          </div>
          <div className="grid grid-cols-3 gap-4">
            <div>
              <label className="label">{t('pages:mcpGateway.dlp.modal.detector')}</label>
              <select className="input w-full" value={form.detector} onChange={e => setForm({ ...form, detector: e.target.value })}>
                {DETECTORS.map(d => <option key={d} value={d}>{d}</option>)}
              </select>
            </div>
            <div>
              <label className="label">{t('pages:mcpGateway.dlp.modal.direction')}</label>
              <select className="input w-full" value={form.direction} onChange={e => setForm({ ...form, direction: e.target.value })}>
                {DIRECTIONS.map(d => <option key={d} value={d}>{d}</option>)}
              </select>
            </div>
            <div>
              <label className="label">{t('pages:mcpGateway.dlp.modal.action')}</label>
              <select className="input w-full" value={form.action} onChange={e => setForm({ ...form, action: e.target.value })}>
                {ACTIONS.map(a => <option key={a} value={a}>{a}</option>)}
              </select>
            </div>
          </div>
          {form.detector === 'custom' && (
            <div>
              <label className="label">{t('pages:mcpGateway.dlp.modal.customRegex')}</label>
              <input className="input w-full font-mono text-sm" value={form.find_regex} onChange={e => setForm({ ...form, find_regex: e.target.value })} placeholder={t('pages:mcpGateway.dlp.modal.customRegexPlaceholder')} />
            </div>
          )}
          <div>
            <label className="label">{t('pages:mcpGateway.dlp.modal.applyTo')}</label>
            <select className="input w-full" value={form.apply_to} onChange={e => setForm({ ...form, apply_to: e.target.value })}>
              {APPLY_TO.map(a => <option key={a} value={a}>{a}</option>)}
            </select>
          </div>
          {form.action === 'tokenize' && (
            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="label">{t('pages:mcpGateway.dlp.modal.tokenPrefix')}</label>
                <input className="input w-full" value={form.token_prefix} onChange={e => setForm({ ...form, token_prefix: e.target.value })} placeholder={t('pages:mcpGateway.dlp.modal.tokenPrefixPlaceholder')} />
              </div>
              <div>
                <label className="label">{t('pages:mcpGateway.dlp.modal.tokenTtl')}</label>
                <input className="input w-full" type="number" value={form.token_ttl} onChange={e => setForm({ ...form, token_ttl: e.target.value })} placeholder={t('pages:mcpGateway.dlp.modal.tokenTtlPlaceholder')} />
              </div>
            </div>
          )}
          <label className="flex items-center gap-2">
            <input type="checkbox" checked={form.enabled} onChange={e => setForm({ ...form, enabled: e.target.checked })} />
            <span className="text-sm">{t('pages:mcpGateway.dlp.modal.enabled')}</span>
          </label>
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
