import { useEffect, useState, useCallback } from 'react'
import { useTranslation } from 'react-i18next'
import { Plus, Trash2, Pencil, AlertTriangle } from 'lucide-react'
import { mcp } from '../../services/api'
import Modal from '../Modal'
import { IconButton, Badge } from '../ui'

interface McpGuardrail {
  id: number
  team_id: number
  name: string
  enabled: boolean
  priority: number
  direction: string
  pack: string
  find_regex: string | null
  action: string
  created_at: string
  updated_at: string
}

interface Team { id: number; name: string; slug: string }

const PACKS = ['builtin:jailbreak_v1', 'builtin:instruction_override', 'builtin:obfuscation', 'custom']
const ACTIONS = ['block', 'redact', 'log']
const DIRECTIONS = ['both', 'request', 'response']

const emptyForm = {
  team_id: 0, name: '', enabled: true, direction: 'both', pack: 'builtin:jailbreak_v1',
  find_regex: '', action: 'block',
}

export default function McpGuardrailsTab() {
  const { t } = useTranslation(['pages', 'common'])
  const [guardrails, setGuardrails] = useState<McpGuardrail[]>([])
  const [teams, setTeams] = useState<Team[]>([])
  const [loading, setLoading] = useState(true)
  const [modalOpen, setModalOpen] = useState(false)
  const [editing, setEditing] = useState<McpGuardrail | null>(null)
  const [form, setForm] = useState(emptyForm)
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState('')

  const packDescription = (pack: string) => {
    switch (pack) {
      case 'builtin:jailbreak_v1': return t('pages:mcpGateway.guardrails.packDescriptions.jailbreak')
      case 'builtin:instruction_override': return t('pages:mcpGateway.guardrails.packDescriptions.instructionOverride')
      case 'builtin:obfuscation': return t('pages:mcpGateway.guardrails.packDescriptions.obfuscation')
      case 'custom': return t('pages:mcpGateway.guardrails.packDescriptions.custom')
      default: return ''
    }
  }

  const fetch = useCallback(async () => {
    try {
      const [gResp, tResp] = await Promise.all([mcp.guardrails.list(), mcp.teams.list()])
      setGuardrails(gResp.data)
      setTeams(tResp.data)
      if (tResp.data.length > 0 && form.team_id === 0) {
        setForm(f => ({ ...f, team_id: tResp.data[0].id }))
      }
    } catch { setGuardrails([]) }
    finally { setLoading(false) }
  }, [form.team_id])

  useEffect(() => { fetch() }, [fetch])

  const openCreate = () => {
    setEditing(null)
    setForm({ ...emptyForm, team_id: teams[0]?.id || 0 })
    setError('')
    setModalOpen(true)
  }

  const openEdit = (g: McpGuardrail) => {
    setEditing(g)
    setForm({
      team_id: g.team_id, name: g.name, enabled: g.enabled, direction: g.direction,
      pack: g.pack, find_regex: g.find_regex || '', action: g.action,
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
      if (editing) {
        await mcp.guardrails.update(editing.id, data)
      } else {
        await mcp.guardrails.create(data)
      }
      setModalOpen(false)
      fetch()
    } catch (err: any) {
      setError(err?.response?.data?.detail || t('pages:mcpGateway.guardrails.failedToSave'))
    } finally { setSaving(false) }
  }

  const del = async (id: number) => {
    if (!confirm(t('pages:mcpGateway.guardrails.confirmDelete'))) return
    try { await mcp.guardrails.delete(id); fetch() } catch { /* ignore */ }
  }

  const actionVariant = (action: string) => {
    switch (action) {
      case 'block': return 'error'
      case 'redact': return 'warning'
      case 'log': return 'info'
      default: return 'default'
    }
  }

  if (loading) return <p className="text-sm text-muted-foreground">{t('common:actions.loading')}</p>

  return (
    <div className="space-y-4">
      <div className="flex justify-between items-center">
        <p className="text-sm text-muted-foreground">{t('pages:mcpGateway.guardrails.count', { count: guardrails.length })}</p>
        <button className="btn-primary text-sm" onClick={openCreate}>
          <Plus className="w-4 h-4 inline me-1" /> {t('pages:mcpGateway.guardrails.add')}
        </button>
      </div>

      {guardrails.length === 0 ? (
        <div className="rounded-lg border border-border bg-card p-8 text-center">
          <AlertTriangle className="h-8 w-8 mx-auto mb-2 text-muted-foreground" />
          <p className="text-sm text-muted-foreground">{t('pages:mcpGateway.guardrails.empty')}</p>
        </div>
      ) : (
        <div className="space-y-2">
          {guardrails.sort((a, b) => a.priority - b.priority).map(g => (
            <div key={g.id} className="rounded-lg border border-border bg-card p-3 flex items-center justify-between">
              <div className="flex-1 min-w-0">
                <div className="font-medium flex items-center gap-2">
                  <span className="text-xs text-muted-foreground">#{g.priority}</span>
                  {g.name}
                  <Badge variant={g.enabled ? 'success' : 'default'} size="sm">{g.enabled ? t('common:status.on') : t('common:status.off')}</Badge>
                  <Badge variant="info" size="sm">{g.pack}</Badge>
                  <Badge variant={actionVariant(g.action)} size="sm">{g.action}</Badge>
                  <Badge variant="default" size="sm">{g.direction}</Badge>
                </div>
                {g.find_regex && <div className="text-xs text-muted-foreground font-mono truncate">{g.find_regex}</div>}
              </div>
              <div className="flex items-center gap-1">
                <IconButton icon={Pencil} aria-label={t('pages:mcpGateway.guardrails.tooltips.edit')} onClick={() => openEdit(g)} />
                <IconButton icon={Trash2} variant="danger" aria-label={t('pages:mcpGateway.guardrails.tooltips.delete')} onClick={() => del(g.id)} />
              </div>
            </div>
          ))}
        </div>
      )}

      <Modal open={modalOpen} onClose={() => setModalOpen(false)} title={editing ? t('pages:mcpGateway.guardrails.modal.editTitle') : t('pages:mcpGateway.guardrails.modal.addTitle')}>
        <div className="space-y-4">
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="label">{t('pages:mcpGateway.guardrails.modal.team')}</label>
              <select className="input w-full" value={form.team_id} onChange={e => setForm({ ...form, team_id: Number(e.target.value) })}>
                {teams.map(t => <option key={t.id} value={t.id}>{t.name}</option>)}
              </select>
            </div>
            <div>
              <label className="label">{t('pages:mcpGateway.guardrails.modal.name')}</label>
              <input className="input w-full" value={form.name} onChange={e => setForm({ ...form, name: e.target.value })} placeholder={t('pages:mcpGateway.guardrails.modal.namePlaceholder')} />
            </div>
          </div>
          <div>
            <label className="label">{t('pages:mcpGateway.guardrails.modal.pack')}</label>
            <select className="input w-full" value={form.pack} onChange={e => setForm({ ...form, pack: e.target.value, find_regex: '' })}>
              {PACKS.map(p => <option key={p} value={p}>{p}</option>)}
            </select>
            <p className="text-xs text-muted-foreground mt-1">{packDescription(form.pack)}</p>
          </div>
          {form.pack === 'custom' && (
            <div>
              <label className="label">{t('pages:mcpGateway.guardrails.modal.customRegex')}</label>
              <input className="input w-full font-mono text-sm" value={form.find_regex} onChange={e => setForm({ ...form, find_regex: e.target.value })} placeholder={t('pages:mcpGateway.guardrails.modal.customRegexPlaceholder')} />
            </div>
          )}
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="label">{t('pages:mcpGateway.guardrails.modal.direction')}</label>
              <select className="input w-full" value={form.direction} onChange={e => setForm({ ...form, direction: e.target.value })}>
                {DIRECTIONS.map(d => <option key={d} value={d}>{d}</option>)}
              </select>
            </div>
            <div>
              <label className="label">{t('pages:mcpGateway.guardrails.modal.action')}</label>
              <select className="input w-full" value={form.action} onChange={e => setForm({ ...form, action: e.target.value })}>
                {ACTIONS.map(a => <option key={a} value={a}>{a}</option>)}
              </select>
            </div>
          </div>
          <label className="flex items-center gap-2">
            <input type="checkbox" checked={form.enabled} onChange={e => setForm({ ...form, enabled: e.target.checked })} />
            <span className="text-sm">{t('pages:mcpGateway.guardrails.modal.enabled')}</span>
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
