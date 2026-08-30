import { useEffect, useState, useCallback } from 'react'
import { useTranslation } from 'react-i18next'
import { Plus, Trash2, Pencil, FileText, Upload, History, CheckCircle, Download, Paperclip, Globe, ExternalLink } from 'lucide-react'
import { mcp } from '../../services/api'
import Modal from '../Modal'
import { IconButton, Badge } from '../ui'
import { useDateTime } from '../../contexts/DateTimeContext'

interface McpSkill {
  id: number
  team_id: number
  name: string
  description: string | null
  enabled: boolean
  enable_when: string | null
  enable_when_ast: Record<string, unknown> | null
  tags: string[] | null
  published_version_id: number | null
  created_at: string
  updated_at: string
}

interface McpSkillVersion {
  id: number
  skill_id: number
  version: number
  frontmatter: Record<string, unknown> | null
  body: string
  files: unknown[] | null
  created_by: string | null
  created_at: string
}

interface Team { id: number; name: string; slug: string }

const emptyForm = {
  team_id: 0, name: '', description: '', enabled: true, enable_when: '', tags: '',
}

const emptyVersion = { body: '', frontmatter: '', files: '' }

const emptyImportForm = { url: '', team_id: 0, name: '', description: '', tags: '', auto_publish: true }

export default function McpSkillsTab() {
  const { t } = useTranslation(['pages', 'common'])
  const { formatDateTime } = useDateTime()
  const [skills, setSkills] = useState<McpSkill[]>([])
  const [teams, setTeams] = useState<Team[]>([])
  const [loading, setLoading] = useState(true)
  const [modalOpen, setModalOpen] = useState(false)
  const [editing, setEditing] = useState<McpSkill | null>(null)
  const [form, setForm] = useState(emptyForm)
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState('')

  const [importModalOpen, setImportModalOpen] = useState(false)
  const [importForm, setImportForm] = useState(emptyImportForm)
  const [importing, setImporting] = useState(false)
  const [importError, setImportError] = useState('')

  const [versionModalOpen, setVersionModalOpen] = useState(false)
  const [versionSkill, setVersionSkill] = useState<McpSkill | null>(null)
  const [versionForm, setVersionForm] = useState(emptyVersion)
  const [versions, setVersions] = useState<McpSkillVersion[]>([])
  const [versionSaving, setVersionSaving] = useState(false)
  const [versionError, setVersionError] = useState('')

  const [historyModalOpen, setHistoryModalOpen] = useState(false)
  const [historySkill, setHistorySkill] = useState<McpSkill | null>(null)

  const fetch = useCallback(async () => {
    try {
      const [sResp, tResp] = await Promise.all([mcp.skills.list(), mcp.teams.list()])
      setSkills(sResp.data)
      setTeams(tResp.data)
      if (tResp.data.length > 0 && form.team_id === 0) {
        setForm(f => ({ ...f, team_id: tResp.data[0].id }))
      }
    } catch { setSkills([]) }
    finally { setLoading(false) }
  }, [form.team_id])

  useEffect(() => { fetch() }, [fetch])

  const openCreate = () => {
    setEditing(null)
    setForm({ ...emptyForm, team_id: teams[0]?.id || 0 })
    setError('')
    setModalOpen(true)
  }

  const openImport = () => {
    setImportForm({ ...emptyImportForm, team_id: teams[0]?.id || 0 })
    setImportError('')
    setImportModalOpen(true)
  }

  const doImport = async () => {
    if (!importForm.url.trim()) {
      setImportError(t('pages:mcpGateway.skills.errors.urlRequired'))
      return
    }
    setImporting(true)
    setImportError('')
    try {
      const data: Record<string, unknown> = {
        url: importForm.url.trim(),
        team_id: importForm.team_id,
        auto_publish: importForm.auto_publish,
      }
      if (importForm.name.trim()) data.name = importForm.name.trim()
      if (importForm.description.trim()) data.description = importForm.description.trim()
      if (importForm.tags.trim()) {
        data.tags = importForm.tags.split(',').map((t: string) => t.trim()).filter(Boolean)
      }
      await mcp.skills.importFromUrl(data)
      setImportModalOpen(false)
      fetch()
    } catch (err: any) {
      setImportError(err?.response?.data?.detail || t('pages:mcpGateway.skills.errors.importFailed'))
    } finally { setImporting(false) }
  }

  const openEdit = (s: McpSkill) => {
    setEditing(s)
    setForm({
      team_id: s.team_id, name: s.name, description: s.description || '',
      enabled: s.enabled, enable_when: s.enable_when || '',
      tags: (s.tags || []).join(', '),
    })
    setError('')
    setModalOpen(true)
  }

  const save = async () => {
    setSaving(true)
    setError('')
    try {
      const data: Record<string, unknown> = {
        ...form,
        tags: form.tags ? form.tags.split(',').map((t: string) => t.trim()).filter(Boolean) : [],
      }
      if (!data.description) data.description = null
      if (!data.enable_when) data.enable_when = null
      if (editing) {
        await mcp.skills.update(editing.id, data)
      } else {
        await mcp.skills.create(data)
      }
      setModalOpen(false)
      fetch()
    } catch (err: any) {
      setError(err?.response?.data?.detail || t('pages:mcpGateway.skills.errors.saveFailed'))
    } finally { setSaving(false) }
  }

  const del = async (id: number) => {
    if (!confirm(t('pages:mcpGateway.skills.deleteConfirm'))) return
    try { await mcp.skills.delete(id); fetch() } catch { /* ignore */ }
  }

  const openNewVersion = (s: McpSkill) => {
    setVersionSkill(s)
    setVersionForm(emptyVersion)
    setVersionError('')
    setVersionModalOpen(true)
  }

  const saveVersion = async () => {
    if (!versionSkill) return
    setVersionSaving(true)
    setVersionError('')
    try {
      const data: Record<string, unknown> = { body: versionForm.body }
      if (versionForm.frontmatter) {
        try { data.frontmatter = JSON.parse(versionForm.frontmatter) }
        catch { data.frontmatter = null }
      }
      if (versionForm.files.trim()) {
        const files: Record<string, string> = {}
        for (const line of versionForm.files.split('\n')) {
          const sep = line.indexOf('=')
          if (sep > 0) {
            const filename = line.slice(0, sep).trim()
            const content = line.slice(sep + 1).trim()
            if (filename) files[filename] = content
          }
        }
        if (Object.keys(files).length > 0) data.files = files
      }
      await mcp.skills.versions.create(versionSkill.id, data)
      setVersionModalOpen(false)
      fetch()
    } catch (err: any) {
      setVersionError(err?.response?.data?.detail || t('pages:mcpGateway.skills.errors.versionSaveFailed'))
    } finally { setVersionSaving(false) }
  }

  const openHistory = async (s: McpSkill) => {
    setHistorySkill(s)
    setHistoryModalOpen(true)
    try {
      const resp = await mcp.skills.versions.list(s.id)
      setVersions(resp.data)
    } catch { setVersions([]) }
  }

  const publish = async (skillId: number) => {
    try {
      await mcp.skills.publish(skillId)
      fetch()
      if (historySkill?.id === skillId) {
        const resp = await mcp.skills.versions.list(skillId)
        setVersions(resp.data)
      }
    } catch { /* ignore */ }
  }

  const rollback = async (skillId: number, version: number) => {
    try {
      await mcp.skills.rollback(skillId, version)
      fetch()
      if (historySkill?.id === skillId) {
        const resp = await mcp.skills.versions.list(skillId)
        setVersions(resp.data)
      }
    } catch { /* ignore */ }
  }

  const exportSkill = async (skillId: number, skillName: string) => {
    try {
      const resp = await mcp.skills.export(skillId)
      const url = window.URL.createObjectURL(new Blob([resp.data]))
      const link = document.createElement('a')
      link.href = url
      link.download = `${skillName}.zip`
      document.body.appendChild(link)
      link.click()
      link.remove()
      window.URL.revokeObjectURL(url)
    } catch { /* ignore */ }
  }

  if (loading) return <p className="text-sm text-muted-foreground">{t('common:actions.loading')}</p>

  return (
    <div className="space-y-4">
      <div className="flex justify-between items-center">
        <div className="flex items-center gap-3">
          <p className="text-sm text-muted-foreground">{t('pages:mcpGateway.skills.count', { count: skills.length })}</p>
          <div className="flex items-center gap-1.5">
            <span className="text-xs text-muted-foreground">{t('pages:mcpGateway.skills.browse')}</span>
            <a href="https://mcpmarket.com/tools/skills" target="_blank" rel="noopener noreferrer" className="text-xs text-primary hover:underline inline-flex items-center gap-0.5">
              {t('pages:mcpGateway.skills.browseMcpMarket')} <ExternalLink className="w-3 h-3" />
            </a>
            <span className="text-muted-foreground">·</span>
            <a href="https://skillsmp.com/" target="_blank" rel="noopener noreferrer" className="text-xs text-primary hover:underline inline-flex items-center gap-0.5">
              {t('pages:mcpGateway.skills.browseSkillsMp')} <ExternalLink className="w-3 h-3" />
            </a>
            <span className="text-muted-foreground">·</span>
            <a href="https://skillsllm.com/" target="_blank" rel="noopener noreferrer" className="text-xs text-primary hover:underline inline-flex items-center gap-0.5">
              {t('pages:mcpGateway.skills.browseSkillsLlm')} <ExternalLink className="w-3 h-3" />
            </a>
          </div>
        </div>
        <div className="flex gap-2">
          <button className="btn-secondary text-sm" onClick={openImport}>
            <Globe className="w-4 h-4 inline me-1" /> {t('pages:mcpGateway.skills.importFromUrl')}
          </button>
          <button className="btn-primary text-sm" onClick={openCreate}>
            <Plus className="w-4 h-4 inline me-1" /> {t('pages:mcpGateway.skills.addSkill')}
          </button>
        </div>
      </div>

      {skills.length === 0 ? (
        <div className="rounded-lg border border-border bg-card p-8 text-center">
          <FileText className="h-8 w-8 mx-auto mb-2 text-muted-foreground" />
          <p className="text-sm text-muted-foreground">{t('pages:mcpGateway.skills.empty')}</p>
        </div>
      ) : (
        <div className="space-y-2">
          {skills.map(s => (
            <div key={s.id} className="rounded-lg border border-border bg-card p-3 flex items-center justify-between">
              <div className="flex-1 min-w-0">
                <div className="font-medium flex items-center gap-2">
                  {s.name}
                  <Badge variant={s.enabled ? 'success' : 'default'} size="sm">{s.enabled ? t('common:status.on') : t('common:status.off')}</Badge>
                  {s.published_version_id ? (
                    <Badge variant="success" size="sm">{t('pages:mcpGateway.skills.published')}</Badge>
                  ) : (
                    <Badge variant="warning" size="sm">{t('pages:mcpGateway.skills.draft')}</Badge>
                  )}
                  {s.tags && s.tags.length > 0 && s.tags.map(tag => (
                    <Badge key={tag} variant="default" size="sm">{tag}</Badge>
                  ))}
                </div>
                <div className="text-xs text-muted-foreground">
                  {s.description || t('pages:mcpGateway.skills.noDescription')}
                  {s.enable_when && t('pages:mcpGateway.skills.enableWhenLabel', { value: s.enable_when })}
                </div>
              </div>
              <div className="flex items-center gap-1">
                <button className="btn-secondary text-xs" onClick={() => openNewVersion(s)}>
                  <Upload className="w-3 h-3 inline me-1" /> {t('pages:mcpGateway.skills.newVersion')}
                </button>
                <button className="btn-secondary text-xs" onClick={() => openHistory(s)}>
                  <History className="w-3 h-3 inline me-1" /> {t('pages:mcpGateway.skills.versions')}
                </button>
                {s.published_version_id && (
                  <button className="btn-secondary text-xs" onClick={() => exportSkill(s.id, s.name)}>
                    <Download className="w-3 h-3 inline me-1" /> {t('common:actions.export')}
                  </button>
                )}
                <IconButton icon={Pencil} aria-label={t('pages:mcpGateway.skills.editSkillAria')} onClick={() => openEdit(s)} />
                <IconButton icon={Trash2} variant="danger" aria-label={t('pages:mcpGateway.skills.deleteSkillAria')} onClick={() => del(s.id)} />
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Edit/Create skill modal */}
      <Modal open={modalOpen} onClose={() => setModalOpen(false)} title={editing ? t('pages:mcpGateway.skills.editSkill') : t('pages:mcpGateway.skills.addSkill')}>
        <div className="space-y-4">
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="label">{t('pages:mcpGateway.skills.modal.team')}</label>
              <select className="input w-full" value={form.team_id} onChange={e => setForm({ ...form, team_id: Number(e.target.value) })}>
                {teams.map(t => <option key={t.id} value={t.id}>{t.name}</option>)}
              </select>
            </div>
            <div>
              <label className="label">{t('pages:mcpGateway.skills.modal.name')}</label>
              <input className="input w-full" value={form.name} onChange={e => setForm({ ...form, name: e.target.value })} placeholder="code-review" />
              <p className="text-xs text-muted-foreground mt-1">{t('pages:mcpGateway.skills.modal.nameHint')}</p>
            </div>
          </div>
          <div>
            <label className="label">{t('common:table.description')}</label>
            <input className="input w-full" value={form.description} onChange={e => setForm({ ...form, description: e.target.value })} />
          </div>
          <div>
            <label className="label">{t('pages:mcpGateway.skills.modal.enableWhen')}</label>
            <input className="input w-full font-mono text-sm" value={form.enable_when} onChange={e => setForm({ ...form, enable_when: e.target.value })} placeholder="true" />
            <p className="text-xs text-muted-foreground mt-1">{t('pages:mcpGateway.skills.modal.enableWhenHint')}</p>
          </div>
          <div>
            <label className="label">{t('pages:mcpGateway.skills.modal.tags')}</label>
            <input className="input w-full" value={form.tags} onChange={e => setForm({ ...form, tags: e.target.value })} placeholder="code, review" />
          </div>
          <label className="flex items-center gap-2">
            <input type="checkbox" checked={form.enabled} onChange={e => setForm({ ...form, enabled: e.target.checked })} />
            <span className="text-sm">{t('common:status.enabled')}</span>
          </label>
          {error && <p className="text-sm text-red-400">{error}</p>}
          <div className="flex justify-end gap-2">
            <button className="btn-secondary" onClick={() => setModalOpen(false)}>{t('common:actions.cancel')}</button>
            <button className="btn-primary" onClick={save} disabled={saving}>{saving ? t('common:actions.saving') : t('common:actions.save')}</button>
          </div>
        </div>
      </Modal>

      {/* Import from URL modal */}
      <Modal open={importModalOpen} onClose={() => setImportModalOpen(false)} title={t('pages:mcpGateway.skills.modal.importTitle')}>
        <div className="space-y-4">
          <div>
            <label className="label">{t('pages:mcpGateway.skills.modal.url')}</label>
            <input
              className="input w-full"
              value={importForm.url}
              onChange={e => setImportForm({ ...importForm, url: e.target.value })}
              placeholder="https://raw.githubusercontent.com/owner/repo/main/skills/my-skill/SKILL.md"
            />
            <p className="text-xs text-muted-foreground mt-1">
              {t('pages:mcpGateway.skills.modal.urlHint')}
            </p>
          </div>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="label">{t('pages:mcpGateway.skills.modal.team')}</label>
              <select className="input w-full" value={importForm.team_id} onChange={e => setImportForm({ ...importForm, team_id: Number(e.target.value) })}>
                {teams.map(t => <option key={t.id} value={t.id}>{t.name}</option>)}
              </select>
            </div>
            <div>
              <label className="label">{t('pages:mcpGateway.skills.modal.nameOptional')}</label>
              <input className="input w-full" value={importForm.name} onChange={e => setImportForm({ ...importForm, name: e.target.value })} placeholder="auto-detected from SKILL.md" />
              <p className="text-xs text-muted-foreground mt-1">{t('pages:mcpGateway.skills.modal.nameOptionalHint')}</p>
            </div>
          </div>
          <div>
            <label className="label">{t('pages:mcpGateway.skills.modal.descriptionOptional')}</label>
            <input className="input w-full" value={importForm.description} onChange={e => setImportForm({ ...importForm, description: e.target.value })} placeholder="auto-detected from frontmatter" />
          </div>
          <div>
            <label className="label">{t('pages:mcpGateway.skills.modal.tagsOptional')}</label>
            <input className="input w-full" value={importForm.tags} onChange={e => setImportForm({ ...importForm, tags: e.target.value })} placeholder="code, review" />
          </div>
          <label className="flex items-center gap-2">
            <input type="checkbox" checked={importForm.auto_publish} onChange={e => setImportForm({ ...importForm, auto_publish: e.target.checked })} />
            <span className="text-sm">{t('pages:mcpGateway.skills.modal.autoPublish')}</span>
          </label>
          {importError && <p className="text-sm text-red-400">{importError}</p>}
          <div className="flex justify-end gap-2">
            <button className="btn-secondary" onClick={() => setImportModalOpen(false)}>{t('common:actions.cancel')}</button>
            <button className="btn-primary" onClick={doImport} disabled={importing}>
              {importing ? t('common:actions.importing') : t('common:actions.import')}
            </button>
          </div>
        </div>
      </Modal>

      {/* New version modal */}
      <Modal open={versionModalOpen} onClose={() => setVersionModalOpen(false)} title={t('pages:mcpGateway.skills.modal.newVersionTitle', { name: versionSkill?.name || '' })}>
        <div className="space-y-4">
          <div>
            <label className="label">{t('pages:mcpGateway.skills.modal.skillBody')}</label>
            <textarea className="input w-full font-mono text-sm" rows={10} value={versionForm.body} onChange={e => setVersionForm({ ...versionForm, body: e.target.value })} placeholder="# Code Review Skill&#10;&#10;Review the provided code for..." />
          </div>
          <div>
            <label className="label">{t('pages:mcpGateway.skills.modal.frontmatter')}</label>
            <textarea className="input w-full font-mono text-sm" rows={4} value={versionForm.frontmatter} onChange={e => setVersionForm({ ...versionForm, frontmatter: e.target.value })} placeholder='{"category": "review", "model": "claude"}' />
          </div>
          <div>
            <label className="label flex items-center gap-1"><Paperclip className="w-3.5 h-3.5" /> {t('pages:mcpGateway.skills.modal.attachedFiles')}</label>
            <textarea className="input w-full font-mono text-sm" rows={4} value={versionForm.files} onChange={e => setVersionForm({ ...versionForm, files: e.target.value })} placeholder={'filename.txt=file content here\nanother.json={"key": "value"}'} />
            <p className="text-xs text-muted-foreground mt-1">{t('pages:mcpGateway.skills.modal.filesHintPre')} <code>filename=content</code>{t('pages:mcpGateway.skills.modal.filesHintPost')}</p>
          </div>
          {versionError && <p className="text-sm text-red-400">{versionError}</p>}
          <div className="flex justify-end gap-2">
            <button className="btn-secondary" onClick={() => setVersionModalOpen(false)}>{t('common:actions.cancel')}</button>
            <button className="btn-primary" onClick={saveVersion} disabled={versionSaving}>{versionSaving ? t('common:actions.saving') : t('pages:mcpGateway.skills.modal.createVersion')}</button>
          </div>
        </div>
      </Modal>

      {/* Version history modal */}
      <Modal open={historyModalOpen} onClose={() => setHistoryModalOpen(false)} title={t('pages:mcpGateway.skills.modal.versionsTitle', { name: historySkill?.name || '' })}>
        <div className="space-y-3">
          {versions.length === 0 ? (
            <p className="text-sm text-muted-foreground">{t('pages:mcpGateway.skills.modal.noVersions')}</p>
          ) : (
            versions.map(v => (
              <div key={v.id} className="rounded-lg border border-border bg-card p-3 flex items-center justify-between">
                <div className="flex-1 min-w-0">
                  <div className="font-medium flex items-center gap-2">
                    v{v.version}
                    {historySkill?.published_version_id === v.id && (
                      <Badge variant="success" size="sm"><CheckCircle className="w-3 h-3 inline me-1" />Published</Badge>
                    )}
                    <span className="text-xs text-muted-foreground">{t('pages:mcpGateway.skills.modal.byAuthor', { author: v.created_by || t('common:status.unknown') })}</span>
                  </div>
                  <div className="text-xs text-muted-foreground truncate">{v.body.slice(0, 100)}...</div>
                  <div className="text-xs text-muted-foreground">{formatDateTime(v.created_at)}</div>
                </div>
                <div className="flex items-center gap-1">
                  {historySkill?.published_version_id !== v.id && (
                    <>
                      <button className="btn-secondary text-xs" onClick={() => publish(historySkill!.id)}>{t('common:actions.publish')}</button>
                      <button className="btn-secondary text-xs" onClick={() => rollback(historySkill!.id, v.version)}>{t('common:actions.rollback')}</button>
                    </>
                  )}
                </div>
              </div>
            ))
          )}
        </div>
      </Modal>
    </div>
  )
}
