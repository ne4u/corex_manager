import React, { useState, useEffect, useCallback, useMemo } from 'react'
import { Link } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { ShieldCheck, GripVertical, Plus, Clock, Shield, Pencil, Trash2, Code2, SlidersHorizontal } from 'lucide-react'
import { securityRules, listeners, errorPages, securityLists, riskRulesets, getErrorDetail } from '../services/api'
import useApiList from '../hooks/useApiList'
import Modal from '../components/Modal'
import ErrorBoundary from '../components/ErrorBoundary'
import { IconButton, Tabs } from '../components/ui'
import { parseToGroups, serializeGroups } from '../lib/expression-parser'
import type { BuilderCondition, BuilderGroup } from '../lib/expression-parser'
import { useDateTime } from '../contexts/DateTimeContext'

interface SecurityRule {
  id: number
  name: string
  enabled: boolean
  priority: number
  listener_ids: number[]
  expression: string
  expression_ast: any
  action: string
  log: boolean
  no_log: boolean
  status_code: number | null
  redirect_url: string | null
  redirect_code: number | null
  error_page_id: number | null
  created_at: string
  updated_at: string
}

interface Listener {
  id: number
  name: string
  enabled: boolean
}

const ACTIONS = [
  { value: 'block', labelKey: 'securityRules.actions.block' },
  { value: 'allow', labelKey: 'securityRules.actions.allow' },
  { value: 'redirect', labelKey: 'securityRules.actions.redirect' },
  { value: 'custom_response', labelKey: 'securityRules.actions.customResponse' },
  { value: 'challenge', labelKey: 'securityRules.actions.challenge' },
  { value: 'skip_rules', labelKey: 'securityRules.actions.skipRules' },
  { value: 'skip_rules_ratelimit', labelKey: 'securityRules.actions.skipRulesRatelimit' },
  { value: 'skip_rules_waf', labelKey: 'securityRules.actions.skipRulesWaf' },
  { value: 'skip_all', labelKey: 'securityRules.actions.skipAll' },
] as const

const FIELD_GROUPS = [
  {
    labelKey: 'securityRules.fieldGroups.risk',
    fields: [
      'risk.score', 'risk.rules_hit', 'risk.rules_hit_count', 'risk.hit_density',
    ],
  },
  {
    labelKey: 'securityRules.fieldGroups.request',
    fields: [
      'http.request.method', 'http.request.uri.path', 'http.request.uri',
      'http.request.full_uri', 'http.request.uri.query', 'http.host',
      'http.request.user_agent', 'http.request.referer', 'http.request.version',
      'http.request.scheme', 'http.request.tls',
      'http.request.keep_alive', 'http.request.hour',
    ],
  },
  {
    labelKey: 'securityRules.fieldGroups.requestHeadersCookies',
    fields: [
      'http.request.headers', 'http.request.cookies',
    ],
  },
  {
    labelKey: 'securityRules.fieldGroups.ipGeoip',
    fields: [
      'ip.src', 'ip.geoip.country', 'ip.geoip.asnum', 'ip.geoip.continent',
      'ip.geoip.city', 'ip.geoip.region', 'ip.geoip.postal_code',
      'ip.geoip.timezone', 'ip.geoip.latitude', 'ip.geoip.longitude',
      'http.request.geo_lang_mismatch', 'http.request.geoip.timezone_mismatch',
    ],
  },
  {
    labelKey: 'securityRules.fieldGroups.tls',
    fields: [
      'http.request.tls.cipher', 'http.request.tls.version', 'http.request.ja4',
      'http.request.alpn',
    ],
  },
  {
    labelKey: 'securityRules.fieldGroups.requestFingerprint',
    fields: [
      'http.request.fingerprint', 'http.request.fingerprint.content_type',
      'http.request.fingerprint.param_keys', 'http.request.fingerprint.param_types',
      'http.request.fingerprint.param_lens', 'http.request.fingerprint.path_depth',
      'http.request.fingerprint.header_count', 'http.request.fingerprint.header_list',
      'http.request.fingerprint.auth_type', 'http.request.fingerprint.body_depth',
      'http.request.fingerprint.cipher_count', 'http.request.fingerprint.ext_count',
      'http.request.user_agent_length', 'http.request.uri_length',
      'http.request.param_count', 'http.request.version_numeric',
      'http.response.fingerprint.status', 'http.response.fingerprint.body_bytes',
    ],
  },
  {
    labelKey: 'securityRules.fieldGroups.graphql',
    fields: [
      'graphql.operation', 'graphql.depth', 'graphql.complexity',
      'graphql.field_count', 'graphql.alias_count', 'graphql.fragment_count',
      'graphql.query_hash', 'graphql.valid',
    ],
  },
  {
    labelKey: 'securityRules.fieldGroups.apiSchema',
    fields: [
      'api.schema_valid', 'api.schema_errors',
    ],
  },
  {
    labelKey: 'securityRules.fieldGroups.auth',
    fields: [
      'auth.valid', 'auth.type', 'auth.error',
      'auth.claim.sub', 'auth.claim.iss', 'auth.claim.aud', 'auth.claim',
    ],
  },
  {
    labelKey: 'securityRules.fieldGroups.profiling',
    fields: [
      'api.profile_anomaly',
    ],
  },
  {
    labelKey: 'securityRules.fieldGroups.response',
    fields: [
      'http.response.status_code', 'http.response.headers',
    ],
  },
] as const

const STRING_OPS = ['=', '!=', '~', '!~', 'contains', 'starts_with', 'ends_with', 'in', 'exists']
const INT_OPS = ['=', '!=', '>', '<', '>=', '<=', 'in']
const BOOL_OPS = ['=', '!=', 'exists']

const BOOL_FIELDS = new Set([
  'http.request.tls', 'http.request.scheme',
  'graphql.valid', 'api.schema_valid', 'auth.valid', 'api.profile_anomaly',
  'http.request.keep_alive', 'http.request.geo_lang_mismatch',
  'http.request.geoip.timezone_mismatch',
])

const NUMERIC_FIELDS = new Set([
  'ip.geoip.latitude', 'ip.geoip.longitude',
  'http.response.status_code',
  'http.request.fingerprint.path_depth', 'http.request.fingerprint.header_count',
  'http.request.fingerprint.body_depth',
  'http.request.fingerprint.cipher_count', 'http.request.fingerprint.ext_count',
  'http.request.user_agent_length', 'http.request.uri_length',
  'http.request.param_count', 'http.request.version_numeric',
  'http.request.hour',
  'http.response.fingerprint.status', 'http.response.fingerprint.body_bytes',
  'graphql.depth', 'graphql.complexity', 'graphql.field_count',
  'graphql.alias_count', 'graphql.fragment_count',
  'risk.score',
  'risk.rules_hit_count',
  'risk.hit_density',
])

// Fields whose `in` operator can reference a security list of the given type.
// Maps field base -> list type + API fetcher returning existing lists.
// Pattern lists are field-agnostic — any string-typed field can reference them.
interface ListRow { id: number; name: string }
const LIST_FIELD_MAP: Record<string, { type: string; fetch: () => Promise<{ data: ListRow[] }> }> = {
  'ip.src': { type: 'network', fetch: securityLists.network.list },
  'ip.geoip.asnum': { type: 'asn', fetch: securityLists.asn.list },
  'ip.geoip.country': { type: 'geo', fetch: securityLists.geo.list },
  'http.request.ja4': { type: 'ja4', fetch: securityLists.ja4.list },
  // Pattern lists — usable by any string-typed field
  'http.request.method': { type: 'pattern', fetch: securityLists.pattern.list },
  'http.request.uri.path': { type: 'pattern', fetch: securityLists.pattern.list },
  'http.request.uri': { type: 'pattern', fetch: securityLists.pattern.list },
  'http.request.full_uri': { type: 'pattern', fetch: securityLists.pattern.list },
  'http.host': { type: 'pattern', fetch: securityLists.pattern.list },
  'http.request.user_agent': { type: 'pattern', fetch: securityLists.pattern.list },
  'http.request.referer': { type: 'pattern', fetch: securityLists.pattern.list },
  'http.request.version': { type: 'pattern', fetch: securityLists.pattern.list },
  'http.request.headers': { type: 'pattern', fetch: securityLists.pattern.list },
  'http.request.cookies': { type: 'pattern', fetch: securityLists.pattern.list },
  'http.request.tls.cipher': { type: 'pattern', fetch: securityLists.pattern.list },
  'http.request.tls.version': { type: 'pattern', fetch: securityLists.pattern.list },
  'http.request.alpn': { type: 'pattern', fetch: securityLists.pattern.list },
  'http.response.status_code': { type: 'pattern', fetch: securityLists.pattern.list },
  'http.response.headers': { type: 'pattern', fetch: securityLists.pattern.list },
  // API Armor: Request Fingerprint fields (pattern lists for allowlisting)
  'http.request.fingerprint': { type: 'pattern', fetch: securityLists.pattern.list },
  'http.request.fingerprint.content_type': { type: 'pattern', fetch: securityLists.pattern.list },
  'http.request.fingerprint.param_keys': { type: 'pattern', fetch: securityLists.pattern.list },
  'http.request.fingerprint.param_types': { type: 'pattern', fetch: securityLists.pattern.list },
  'http.request.fingerprint.header_list': { type: 'pattern', fetch: securityLists.pattern.list },
  'http.request.fingerprint.auth_type': { type: 'pattern', fetch: securityLists.pattern.list },
  // API Armor: GraphQL query hash allowlisting
  'graphql.query_hash': { type: 'pattern', fetch: securityLists.pattern.list },
  'graphql.operation': { type: 'pattern', fetch: securityLists.pattern.list },
  // API Armor: Auth fields
  'auth.type': { type: 'pattern', fetch: securityLists.pattern.list },
  'auth.error': { type: 'pattern', fetch: securityLists.pattern.list },
  'auth.claim.sub': { type: 'pattern', fetch: securityLists.pattern.list },
  'auth.claim.iss': { type: 'pattern', fetch: securityLists.pattern.list },
  'auth.claim.aud': { type: 'pattern', fetch: securityLists.pattern.list },
  // API Armor: Schema errors
  'api.schema_errors': { type: 'pattern', fetch: securityLists.pattern.list },
}

const OTHER_VALUE = '__other__'

interface RiskRulesetInfo {
  id: number
  name: string
  slug: string
}

export default function SecurityRules() {
  const { t } = useTranslation(['pages', 'common'])
  const { formatDateTime } = useDateTime()
  const { items: rules, reload } = useApiList<SecurityRule>(securityRules.list)
  const { items: listenerList } = useApiList<Listener>(listeners.list)
  const { items: errorPageList } = useApiList<{ id: number; code: number; content_type: string }>(errorPages.list)
  const [modalOpen, setModalOpen] = useState(false)
  const [editing, setEditing] = useState<number | null>(null)
  const [form, setForm] = useState(initialForm())
  const [error, setError] = useState('')
  const [dragOverId, setDragOverId] = useState<number | null>(null)

  function initialForm() {
    return {
      name: '', enabled: true, listener_ids: [] as number[],
      expression: '', action: 'block', log: true, no_log: false, status_code: null as number | null,
      redirect_url: '' as string, redirect_code: null as number | null,
      error_page_id: null as number | null,
    }
  }

  const openAdd = () => {
    setEditing(null)
    setForm(initialForm())
    setError('')
    setModalOpen(true)
  }

  const openEdit = (r: SecurityRule) => {
    setEditing(r.id)
    setForm({
      name: r.name, enabled: r.enabled, listener_ids: r.listener_ids || [],
      expression: r.expression, action: r.action, log: r.log, no_log: r.no_log ?? false,
      status_code: r.status_code,
      redirect_url: r.redirect_url || '', redirect_code: r.redirect_code,
      error_page_id: r.error_page_id,
    })
    setError('')
    setModalOpen(true)
  }

  const submit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError('')
    try {
      if (editing) {
        await securityRules.update(editing, form)
      } else {
        await securityRules.create(form)
      }
      setModalOpen(false)
      reload()
    } catch (err) {
      setError(getErrorDetail(err))
    }
  }

  const remove = async (r: SecurityRule) => {
    if (!window.confirm(t('securityRules.confirmDelete', { name: r.name }))) return
    try {
      await securityRules.remove(r.id)
      reload()
    } catch (err) {
      alert(getErrorDetail(err))
    }
  }

  const toggleEnabled = async (r: SecurityRule) => {
    try {
      await securityRules.update(r.id, { ...r, enabled: !r.enabled })
      reload()
    } catch (err) {
      alert(getErrorDetail(err))
    }
  }

  const reorder = async (draggedId: number, targetId: number) => {
    if (draggedId === targetId) return
    const newList = [...rules]
    const from = newList.findIndex(r => r.id === draggedId)
    const to = newList.findIndex(r => r.id === targetId)
    if (from < 0 || to < 0) return
    const [moved] = newList.splice(from, 1)
    const insertAt = from < to ? to - 1 : to
    newList.splice(insertAt, 0, moved)
    const orderedIds = newList.map(r => r.id)
    try {
      await securityRules.reorder(orderedIds)
      reload()
    } catch (err) {
      alert(getErrorDetail(err))
    }
  }

  const actionLabel = (a: string) => {
    const found = ACTIONS.find(x => x.value === a)
    return found ? t(found.labelKey) : a
  }

  // Group rules by listener. "All" group (rules with no listener scope) is
  // always first; remaining groups are sorted by listener name and only shown
  // if they contain at least one rule.
  const groupedRules = useMemo(() => {
    const groups: { key: string; label: string; rules: SecurityRule[] }[] = []
    groups.push({
      key: 'all',
      label: t('securityRules.allListeners'),
      rules: rules.filter(r => !r.listener_ids || r.listener_ids.length === 0),
    })
    const sortedListeners = [...listenerList].sort((a, b) => a.name.localeCompare(b.name))
    for (const l of sortedListeners) {
      const groupRules = rules.filter(r => r.listener_ids?.includes(l.id))
      if (groupRules.length > 0) {
        groups.push({ key: String(l.id), label: l.name, rules: groupRules })
      }
    }
    return groups
  }, [rules, listenerList])

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h2 className="text-2xl font-bold flex items-center gap-2">
          <ShieldCheck className="h-5 w-5 text-primary" /> {t('securityRules.title')}
        </h2>
        <button onClick={openAdd} className="btn-primary flex items-center gap-1">
          <Plus className="h-4 w-4" /> {t('securityRules.addRule')}
        </button>
      </div>

      {/* Execution order banner */}
      <div className="card p-3">
        <div className="flex items-center gap-3 text-sm text-slate-400">
          <span className="text-slate-300 font-medium">{t('securityRules.executionOrder')}</span>
          <div className="flex items-center gap-2">
            <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-primary/20 text-primary font-medium">
              <span className="w-5 h-5 rounded-full bg-primary text-white text-xs flex items-center justify-center">1</span>
              {t('securityRules.securityRulesPhase')}
            </span>
            <span className="text-slate-600">→</span>
            <Link to="/rate-limits" className="inline-flex items-center gap-1 px-2 py-0.5 rounded hover:bg-slate-800">
              <span className="w-5 h-5 rounded-full bg-slate-700 text-slate-300 text-xs flex items-center justify-center">2</span>
              <Clock className="h-3 w-3" /> {t('securityRules.rateLimitingPhase')}
            </Link>
            <span className="text-slate-600">→</span>
            <Link to="/waf" className="inline-flex items-center gap-1 px-2 py-0.5 rounded hover:bg-slate-800">
              <span className="w-5 h-5 rounded-full bg-slate-700 text-slate-300 text-xs flex items-center justify-center">3</span>
              <Shield className="h-3 w-3" /> {t('securityRules.wafSignaturesPhase')}
            </Link>
          </div>
          <span className="text-xs text-slate-500 ms-2">{t('securityRules.skipActionsNote')}</span>
        </div>
      </div>

      {/* Rules grouped by listener — single table so columns align across groups */}
      {rules.length === 0 ? (
        <div className="card p-4 text-slate-500">{t('securityRules.noRulesYet')}</div>
      ) : (
        <div className="card overflow-x-auto">
          <table className="w-full text-sm text-start">
            <thead className="text-slate-400 border-b border-slate-800">
              <tr>
                <th className="p-2 w-8"></th>
                <th className="p-2 w-16">{t('securityRules.tableHeaders.order')}</th>
                <th className="p-2">{t('securityRules.tableHeaders.name')}</th>
                <th className="p-2 w-24">{t('securityRules.tableHeaders.enabled')}</th>
                <th className="p-2 w-40 whitespace-nowrap">{t('securityRules.tableHeaders.action')}</th>
                <th className="p-2">{t('securityRules.tableHeaders.expression')}</th>
                <th className="p-2 w-40">{t('securityRules.tableHeaders.updated')}</th>
                <th className="p-2 w-28"></th>
              </tr>
            </thead>
            <tbody>
              {groupedRules.map(group => (
                <React.Fragment key={group.key}>
                  <tr className="border-b border-slate-800 bg-slate-900/60">
                    <td colSpan={8} className="p-3">
                      <span className="font-semibold text-sm">{group.label}</span>
                      <span className="text-xs text-slate-500 ms-2">({group.rules.length === 1 ? t('securityRules.ruleCount', { count: group.rules.length }) : t('securityRules.rulesCount', { count: group.rules.length })})</span>
                    </td>
                  </tr>
                  {group.rules.length === 0 ? (
                    <tr className="border-b border-slate-800">
                      <td colSpan={8} className="p-4 text-sm text-slate-500">{t('securityRules.noRulesForAllListeners')}</td>
                    </tr>
                  ) : (
                    group.rules.map((r, gi) => (
                      <tr
                        key={r.id}
                        className={`border-b border-slate-800 ${dragOverId === r.id ? 'bg-slate-800' : ''}`}
                        draggable
                        onDragStart={(e) => { e.dataTransfer.setData('text/plain', String(r.id)); e.dataTransfer.effectAllowed = 'move' }}
                        onDragOver={(e) => { e.preventDefault(); setDragOverId(r.id) }}
                        onDrop={(e) => { e.preventDefault(); const dragged = Number(e.dataTransfer.getData('text/plain')); if (dragged !== r.id) { setDragOverId(null); reorder(dragged, r.id) } }}
                        onDragEnd={() => setDragOverId(null)}
                      >
                        <td className="p-2 cursor-grab"><GripVertical className="h-4 w-4 text-slate-500" /></td>
                        <td className="p-2 text-slate-500">{gi + 1}</td>
                        <td className="p-2 font-medium">{r.name}</td>
                        <td className="p-2">
                          <button
                            onClick={() => toggleEnabled(r)}
                            className={`px-2 py-0.5 rounded text-xs font-medium ${r.enabled ? 'bg-green-500/20 text-green-400' : 'bg-slate-700 text-slate-400'}`}
                          >
                            {r.enabled ? t('common:status.enabled') : t('common:status.disabled')}
                          </button>
                        </td>
                        <td className="p-2 whitespace-nowrap">
                          <span className={`px-2 py-0.5 rounded text-xs ${
                            r.action === 'block' ? 'bg-red-500/20 text-red-400' :
                            r.action === 'allow' ? 'bg-green-500/20 text-green-400' :
                            r.action === 'redirect' ? 'bg-yellow-500/20 text-yellow-400' :
                            r.action === 'custom_response' ? 'bg-purple-500/20 text-purple-400' :
                            r.action === 'challenge' ? 'bg-cyan-500/20 text-cyan-400' :
                            'bg-blue-500/20 text-blue-400'
                          }`}>{actionLabel(r.action)}</span>
                        </td>
                        <td className="p-2 text-xs text-slate-400 max-w-xs truncate" title={r.expression}>
                          <code className="text-slate-300">{r.expression}</code>
                        </td>
                        <td className="p-2 text-xs text-slate-400 whitespace-nowrap">{formatDateTime(r.updated_at)}</td>
                        <td className="p-2 whitespace-nowrap">
                          <div className="flex gap-1">
                            <IconButton icon={Pencil} aria-label={t('common:actions.edit')} onClick={() => openEdit(r)} />
                            <IconButton icon={Trash2} variant="danger" aria-label={t('common:actions.delete')} onClick={() => remove(r)} />
                          </div>
                        </td>
                      </tr>
                    ))
                  )}
                </React.Fragment>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Add/Edit modal */}
      <Modal open={modalOpen} onClose={() => setModalOpen(false)} title={editing ? t('securityRules.modal.editTitle') : t('securityRules.modal.addTitle')}>
        <form onSubmit={submit} className="space-y-4">
          {error && <div className="bg-red-500/10 border border-red-500/30 text-red-400 rounded p-3 text-sm">{error}</div>}

          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-sm text-slate-400 mb-1">{t('securityRules.modal.name')}</label>
              <input
                className="input w-full"
                value={form.name}
                onChange={e => setForm({ ...form, name: e.target.value })}
                placeholder={t('securityRules.modal.namePlaceholder')}
                required
              />
            </div>
            <div>
              <label className="block text-sm text-slate-400 mb-1">{t('securityRules.modal.action')}</label>
              <select
                className="input w-full"
                value={form.action}
                onChange={e => setForm({ ...form, action: e.target.value })}
              >
                {ACTIONS.map(a => <option key={a.value} value={a.value}>{t(a.labelKey)}</option>)}
              </select>
            </div>
          </div>

          <div className="grid grid-cols-3 gap-4">
            <div>
              <label className="block text-sm text-slate-400 mb-1">{t('securityRules.modal.enabled')}</label>
              <label className="flex items-center gap-2">
                <input
                  type="checkbox"
                  checked={form.enabled}
                  onChange={e => setForm({ ...form, enabled: e.target.checked })}
                />
                <span className="text-sm">{form.enabled ? t('common:status.enabled') : t('common:status.disabled')}</span>
              </label>
            </div>
            <div>
              <label className="block text-sm text-slate-400 mb-1">{t('securityRules.modal.logAction')}</label>
              <label className="flex items-center gap-2">
                <input
                  type="checkbox"
                  checked={form.log}
                  onChange={e => setForm({ ...form, log: e.target.checked })}
                />
                <span className="text-sm">{form.log ? t('common:actions.yes') : t('common:actions.no')}</span>
              </label>
            </div>
            <div>
              <label className="block text-sm text-slate-400 mb-1">{t('securityRules.modal.suppressRequestLog')}</label>
              <label className="flex items-center gap-2">
                <input
                  type="checkbox"
                  checked={form.no_log}
                  onChange={e => setForm({ ...form, no_log: e.target.checked })}
                />
                <span className="text-sm">{form.no_log ? t('common:actions.yes') : t('common:actions.no')}</span>
              </label>
            </div>
            {form.action === 'block' && (
              <div>
                <label className="block text-sm text-slate-400 mb-1">{t('securityRules.modal.statusCode')}</label>
                <input
                  type="number"
                  className="input w-full"
                  value={form.status_code ?? ''}
                  onChange={e => setForm({ ...form, status_code: e.target.value ? Number(e.target.value) : null })}
                  placeholder="403"
                  min={100}
                  max={599}
                />
              </div>
            )}
            {form.action === 'custom_response' && (
              <div>
                <label className="block text-sm text-slate-400 mb-1">{t('securityRules.modal.statusCode')}</label>
                <input
                  type="number"
                  className="input w-full"
                  value={form.status_code ?? ''}
                  onChange={e => setForm({ ...form, status_code: e.target.value ? Number(e.target.value) : null })}
                  placeholder="403"
                  min={100}
                  max={599}
                />
              </div>
            )}
          </div>

          {/* Redirect URL + code */}
          {form.action === 'redirect' && (
            <div className="grid grid-cols-3 gap-4">
              <div className="col-span-2">
                <label className="block text-sm text-slate-400 mb-1">{t('securityRules.modal.redirectUrl')}</label>
                <input
                  className="input w-full"
                  value={form.redirect_url}
                  onChange={e => setForm({ ...form, redirect_url: e.target.value })}
                  placeholder="https://example.com/blocked"
                />
              </div>
              <div>
                <label className="block text-sm text-slate-400 mb-1">{t('securityRules.modal.redirectCode')}</label>
                <input
                  type="number"
                  className="input w-full"
                  value={form.redirect_code ?? ''}
                  onChange={e => setForm({ ...form, redirect_code: e.target.value ? Number(e.target.value) : null })}
                  placeholder="302"
                  min={300}
                  max={399}
                />
              </div>
            </div>
          )}

          {/* Challenge action note */}
          {form.action === 'challenge' && (
            <div className="text-xs text-slate-500">
              <span dangerouslySetInnerHTML={{ __html: t('securityRules.challengeNote') }} />
              {form.redirect_url && <span className="block mt-1">{t('securityRules.challengeCustomUrl', { url: form.redirect_url })}</span>}
            </div>
          )}

          {/* Custom response page selector */}
          {form.action === 'custom_response' && (
            <div>
              <label className="block text-sm text-slate-400 mb-1">{t('securityRules.modal.customResponsePage')}</label>
              <select
                className="input w-full"
                value={form.error_page_id ?? ''}
                onChange={e => setForm({ ...form, error_page_id: e.target.value ? Number(e.target.value) : null })}
              >
                <option value="">{t('securityRules.modal.selectPage')}</option>
                {errorPageList.map(ep => (
                  <option key={ep.id} value={ep.id}>{ep.code} — {ep.content_type}</option>
                ))}
              </select>
            </div>
          )}

          {/* Listener scope */}
          <div>
            <label className="block text-sm text-slate-400 mb-1">{t('securityRules.modal.listenerScope')}</label>
            <div className="flex items-center gap-4 mb-2">
              <label className="flex items-center gap-1">
                <input
                  type="radio"
                  checked={form.listener_ids.length === 0}
                  onChange={() => setForm({ ...form, listener_ids: [] })}
                />
                <span className="text-sm">{t('securityRules.modal.allListeners')}</span>
              </label>
              <label className="flex items-center gap-1">
                <input
                  type="radio"
                  checked={form.listener_ids.length > 0}
                  onChange={() => setForm({ ...form, listener_ids: listenerList.length ? [listenerList[0].id] : [] })}
                />
                <span className="text-sm">{t('securityRules.modal.selectedListeners')}</span>
              </label>
            </div>
            {form.listener_ids.length > 0 && (
              <div className="flex flex-wrap gap-2">
                {listenerList.map(l => (
                  <label key={l.id} className="flex items-center gap-1 px-2 py-1 rounded bg-slate-800 text-sm">
                    <input
                      type="checkbox"
                      checked={form.listener_ids.includes(l.id)}
                      onChange={e => {
                        if (e.target.checked) setForm({ ...form, listener_ids: [...form.listener_ids, l.id] })
                        else setForm({ ...form, listener_ids: form.listener_ids.filter(id => id !== l.id) })
                      }}
                    />
                    {l.name}
                  </label>
                ))}
              </div>
            )}
          </div>

          {/* Expression editor */}
          <ExpressionEditor
            value={form.expression}
            onChange={expr => setForm({ ...form, expression: expr })}
          />

          <div className="flex justify-end gap-2 pt-2">
            <button type="button" onClick={() => setModalOpen(false)} className="btn-secondary">{t('securityRules.modal.cancel')}</button>
            <button type="submit" className="btn-primary">{editing ? t('securityRules.modal.update') : t('securityRules.modal.create')}</button>
          </div>
        </form>
      </Modal>
    </div>
  )
}

// ---------------------------------------------------------------------------
// Expression editor (text + builder tabs)
// ---------------------------------------------------------------------------

function ExpressionEditor({ value, onChange }: { value: string; onChange: (v: string) => void }) {
  const { t } = useTranslation(['pages', 'common'])
  const [tab, setTab] = useState<'text' | 'builder'>('builder')
  const [validation, setValidation] = useState<{ ok: boolean; error: string | null }>({ ok: true, error: null })
  const [validating, setValidating] = useState(false)

  const validate = useCallback(async (expr: string) => {
    if (!expr.trim()) { setValidation({ ok: true, error: null }); return }
    setValidating(true)
    try {
      const res = await securityRules.validate(expr)
      setValidation({ ok: res.data.ok, error: res.data.error })
    } catch {
      setValidation({ ok: false, error: t('securityRules.expression.validationFailed') })
    } finally {
      setValidating(false)
    }
  }, [t])

  useEffect(() => {
    const timer = setTimeout(() => validate(value), 300)
    return () => clearTimeout(timer)
  }, [value, validate])

  return (
    <div>
      <label className="block text-sm text-slate-400 mb-1">{t('securityRules.expression.label')}</label>
      <Tabs
        tabs={[
          { id: 'text', label: t('securityRules.expression.textTab'), icon: Code2 },
          { id: 'builder', label: t('securityRules.expression.builderTab'), icon: SlidersHorizontal },
        ]}
        active={tab}
        onChange={(id) => setTab(id as 'text' | 'builder')}
        className="mb-2"
      />

      {tab === 'text' ? (
        <div>
          <textarea
            className="input w-full font-mono text-sm"
            rows={4}
            value={value}
            onChange={e => onChange(e.target.value)}
            placeholder={t('securityRules.expression.placeholder')}
          />
          {validation.error && (
            <div className="text-red-400 text-xs mt-1">{validation.error}</div>
          )}
          {validation.ok && value && !validating && (
            <div className="text-green-400 text-xs mt-1">{t('securityRules.expression.valid')}</div>
          )}
        </div>
      ) : (
        <ErrorBoundary fallbackTitle="Builder error" fallbackHint="Switch to Text mode to edit the expression manually.">
          <ExpressionBuilder value={value} onChange={onChange} />
        </ErrorBoundary>
      )}
    </div>
  )
}

// ---------------------------------------------------------------------------
// Visual expression builder (DNF groups)
// ---------------------------------------------------------------------------

// Cache of security lists by type, fetched lazily when a list-capable field is used.
const _listCache: Record<string, ListRow[]> = {}
const _listFetchInflight: Partial<Record<string, Promise<void>>> = {}

function useListCache(listType: string | null): ListRow[] {
  const [, force] = useState(0)
  useEffect(() => {
    if (!listType) return
    if (_listCache[listType]) return
    if (_listFetchInflight[listType]) {
      _listFetchInflight[listType].then(() => force(x => x + 1))
      return
    }
    const entry = Object.values(LIST_FIELD_MAP).find(e => e.type === listType)
    if (!entry) return
    _listFetchInflight[listType] = entry.fetch().then(res => {
      _listCache[listType] = res.data
    }).catch(() => {
      _listCache[listType] = []
    }).finally(() => {
      delete _listFetchInflight[listType]
      force(x => x + 1)
    })
  }, [listType])
  return listType ? (_listCache[listType] || []) : []
}

function ExpressionBuilder({ value, onChange }: { value: string; onChange: (v: string) => void }) {
  const { t } = useTranslation(['pages', 'common'])
  // Fetch risk rulesets for dynamic field groups
  const [riskRulesetList, setRiskRulesetList] = useState<RiskRulesetInfo[]>([])
  useEffect(() => {
    riskRulesets.list().then(res => {
      setRiskRulesetList((res.data as RiskRulesetInfo[]).filter(rs => rs.slug !== 'default'))
    }).catch(() => { /* fallback to static field groups */ })
  }, [])
  // Build dynamic field groups: static FIELD_GROUPS + per-ruleset risk groups
  const dynamicFieldGroups = useMemo(() => {
    if (riskRulesetList.length === 0) return FIELD_GROUPS
    const rulesetGroups = riskRulesetList.map(rs => ({
      labelKey: `Risk: ${rs.name}`,
      fields: [
        `risk.${rs.slug}.score`,
        `risk.${rs.slug}.rules_hit`,
        `risk.${rs.slug}.rules_hit_count`,
        `risk.${rs.slug}.hit_density`,
      ],
    }))
    return [...FIELD_GROUPS, ...rulesetGroups]
  }, [riskRulesetList])
  // Parse the current text into DNF groups for the builder UI
  // For simplicity, we provide a basic builder that constructs conditions
  // and serializes them to the text expression
  const [groups, setGroups] = useState<BuilderGroup[]>(parseToGroups(value))

  useEffect(() => {
    setGroups(parseToGroups(value))
  }, [value])

  const serialize = (newGroups: BuilderGroup[]) => {
    const text = serializeGroups(newGroups)
    onChange(text)
  }

  const addCondition = (gi: number) => {
    const newGroups = [...groups]
    newGroups[gi].conditions.push({ field: 'http.request.uri.path', op: '=', value: '', negated: false })
    setGroups(newGroups)
    serialize(newGroups)
  }

  const addGroup = () => {
    const newGroups = [...groups, { conditions: [{ field: 'http.request.uri.path', op: '=', value: '', negated: false }] }]
    setGroups(newGroups)
    serialize(newGroups)
  }

  const removeCondition = (gi: number, ci: number) => {
    const newGroups = [...groups]
    newGroups[gi].conditions.splice(ci, 1)
    if (newGroups[gi].conditions.length === 0) newGroups.splice(gi, 1)
    setGroups(newGroups)
    serialize(newGroups)
  }

  const updateCondition = (gi: number, ci: number, patch: Partial<BuilderCondition>) => {
    const newGroups = [...groups]
    newGroups[gi].conditions[ci] = { ...newGroups[gi].conditions[ci], ...patch }
    setGroups(newGroups)
    serialize(newGroups)
  }

  return (
    <div className="space-y-3 border border-slate-800 rounded-lg p-3 bg-slate-900/50">
      {groups.map((group, gi) => (
        <div key={gi} className="space-y-2">
          {gi > 0 && <div className="text-xs text-slate-500 font-medium uppercase">{t('securityRules.expression.or')}</div>}
          {group.conditions.map((cond, ci) => (
            <div key={ci} className="flex items-center gap-2 flex-wrap">
              {ci > 0 && <span className="text-xs text-slate-500">{t('securityRules.expression.and')}</span>}
              <label className="flex items-center gap-1 text-xs">
                <input
                  type="checkbox"
                  checked={cond.negated}
                  onChange={e => updateCondition(gi, ci, { negated: e.target.checked })}
                />
                {t('securityRules.expression.not')}
              </label>
              <select
                className="input text-xs py-1"
                value={getFieldBase(cond.field)}
                onChange={e => {
                  const newField = e.target.value
                  const validOps = getOpsForField(newField)
                  const op = validOps.includes(cond.op) ? cond.op : validOps[0]
                  updateCondition(gi, ci, { field: newField, op })
                }}
              >
                {dynamicFieldGroups.map(fg => (
                  <optgroup key={fg.labelKey} label={fg.labelKey.startsWith('Risk: ') ? fg.labelKey : t(fg.labelKey)}>
                    {fg.fields.map(f => <option key={f} value={f}>{f}</option>)}
                  </optgroup>
                ))}
              </select>
              {isBracketField(cond.field) && (
                <input
                  className="input text-xs py-1 w-24"
                  placeholder={t('securityRules.expression.headerNamePlaceholder')}
                  value={getBracketKey(cond.field)}
                  onChange={e => updateCondition(gi, ci, { field: setBracketKey(cond.field, e.target.value) })}
                />
              )}
              <select
                className="input text-xs py-1"
                value={cond.op}
                onChange={e => updateCondition(gi, ci, { op: e.target.value as string })}
              >
                {getOpsForField(cond.field).map(op => <option key={op} value={op}>{op}</option>)}
              </select>
              {cond.op !== 'exists' && (
                <ListValueInput
                  field={cond.field}
                  op={cond.op}
                  value={cond.value}
                  onChange={v => updateCondition(gi, ci, { value: v })}
                />
              )}
              <button type="button" onClick={() => removeCondition(gi, ci)} className="text-red-400 text-xs hover:underline">{t('securityRules.expression.remove')}</button>
            </div>
          ))}
          <button type="button" onClick={() => addCondition(gi)} className="text-xs text-primary hover:underline">{t('securityRules.expression.addCondition')}</button>
        </div>
      ))}
      <button type="button" onClick={addGroup} className="text-xs text-primary hover:underline">{t('securityRules.expression.addOrGroup')}</button>
    </div>
  )
}

// Renders the value input for a builder condition. When the op is `in` and the
// field is list-capable, shows a dropdown of existing security lists of the
// matching type (with an "Other" fallback to free text). Otherwise shows the
// plain free-text input.
function ListValueInput({
  field,
  op,
  value,
  onChange,
}: {
  field: string
  op: string
  value: string
  onChange: (v: string) => void
}) {
  const { t } = useTranslation(['pages', 'common'])
  const base = getFieldBase(field)
  const listEntry = LIST_FIELD_MAP[base]
  const useDropdown = op === 'in' && !!listEntry
  const lists = useListCache(useDropdown ? listEntry!.type : null)
  const [showOther, setShowOther] = useState(false)
  const isBoolField = BOOL_FIELDS.has(base)

  // Reset "Other" mode when the field or operator changes so the dropdown
  // re-derives its selection from the current value.
  useEffect(() => { setShowOther(false) }, [field, op])

  // Boolean fields get a true/false dropdown instead of free text
  if (!useDropdown && isBoolField) {
    return (
      <select
        className="input text-xs py-1 flex-1 min-w-[120px]"
        value={value}
        onChange={e => onChange(e.target.value)}
      >
        <option value="">{t('securityRules.expression.selectPlaceholder')}</option>
        <option value="true">true</option>
        <option value="false">false</option>
      </select>
    )
  }

  if (!useDropdown) {
    return (
      <input
        className="input text-xs py-1 flex-1 min-w-[120px]"
        placeholder={t('securityRules.expression.valuePlaceholder')}
        value={value}
        onChange={e => onChange(e.target.value)}
      />
    )
  }

  const listType = listEntry!.type
  const optionValues = new Set(lists.map(l => `$${listType}:${l.name}`))
  // Show the free-text input when the user picked "Other" or when the current
  // value doesn't match any known list option (e.g. a literal list or a
  // $type:name reference to a list that isn't loaded / doesn't exist).
  const derivedOther = value !== '' && !optionValues.has(value)
  const otherActive = showOther || derivedOther
  const selectValue = otherActive ? OTHER_VALUE : value

  return (
    <div className="flex items-center gap-2 flex-1 min-w-[120px]">
      <select
        className="input text-xs py-1 flex-1"
        value={selectValue}
        onChange={e => {
          const v = e.target.value
          if (v === OTHER_VALUE) {
            setShowOther(true)
            onChange('')
          } else {
            setShowOther(false)
            onChange(v)
          }
        }}
      >
        <option value="">{t('securityRules.expression.selectList')}</option>
        {lists.map(l => (
          <option key={l.id} value={`$${listType}:${l.name}`}>{l.name}</option>
        ))}
        <option value={OTHER_VALUE}>{t('securityRules.expression.otherManual')}</option>
      </select>
      {otherActive && (
        <input
          className="input text-xs py-1 flex-1"
          placeholder="$type:name or [a, b, c]"
          value={value}
          onChange={e => onChange(e.target.value)}
        />
      )}
    </div>
  )
}

// BuilderCondition and BuilderGroup types are now imported from lib/expression-parser
// parseToGroups, serializeCondition, and serializeGroups are also imported

const BRACKET_CAPABLE_FIELDS = new Set([
  'http.request.headers',
  'http.request.cookies',
  'http.response.headers',
  'auth.claim',
])

function getFieldBase(field: string): string {
  const m = field.match(/^([\w.]+)(\[".*"\])?$/)
  return m ? m[1] : field
}

function isBracketField(field: string): boolean {
  const base = getFieldBase(field)
  return BRACKET_CAPABLE_FIELDS.has(base)
}

function getBracketKey(field: string): string {
  const m = field.match(/\["([^"]*)"\]$/)
  return m ? m[1] : ''
}

function setBracketKey(field: string, key: string): string {
  const base = getFieldBase(field)
  return key ? `${base}["${key}"]` : base
}

function getOpsForField(field: string): string[] {
  const base = getFieldBase(field)
  if (BOOL_FIELDS.has(base)) return BOOL_OPS
  if (NUMERIC_FIELDS.has(base)) return INT_OPS
  // Dynamic risk ruleset fields: risk.<slug>.score, .rules_hit_count, .hit_density are int
  if (/^risk\.[a-z_][a-z0-9_]*\.score$/.test(base)) return INT_OPS
  if (/^risk\.[a-z_][a-z0-9_]*\.rules_hit_count$/.test(base)) return INT_OPS
  if (/^risk\.[a-z_][a-z0-9_]*\.hit_density$/.test(base)) return INT_OPS
  // Dynamic risk ruleset fields: risk.<slug>.rules_hit is string
  if (/^risk\.[a-z_][a-z0-9_]*\.rules_hit$/.test(base)) return STRING_OPS
  return STRING_OPS
}
