import React, { useState, useEffect, useCallback, useMemo } from 'react'
import { useTranslation } from 'react-i18next'
import { Gauge, GripVertical, Plus, Pencil, Trash2, Code2, SlidersHorizontal, Sparkles, Settings, Play, CheckCircle } from 'lucide-react'
import { riskRules, riskRulesets, listeners, securityLists, getErrorDetail, applyConfig, getConfigStatus } from '../services/api'
import useApiList from '../hooks/useApiList'
import Modal from '../components/Modal'
import ErrorBoundary from '../components/ErrorBoundary'
import { IconButton, Tabs } from '../components/ui'
import { parseToGroups, serializeGroups } from '../lib/expression-parser'
import type { BuilderCondition, BuilderGroup } from '../lib/expression-parser'
import { useNotifications } from '../contexts/NotificationContext'
import { useDateTime } from '../contexts/DateTimeContext'

interface RiskRule {
  id: number
  name: string
  enabled: boolean
  priority: number
  listener_ids: number[]
  expression: string
  expression_ast: any
  points: number
  category: string | null
  log: boolean
  ruleset_id: number
  created_at: string
  updated_at: string
}

interface Listener {
  id: number
  name: string
  enabled: boolean
}

interface RiskRuleset {
  id: number
  name: string
  slug: string
  description: string | null
  enabled: boolean
  priority: number
  rule_count: number
  created_at: string | null
  updated_at: string | null
}

interface ValidateResponse {
  ok: boolean
  ast: any
  error: string | null
  suggested_category: string | null
}

interface SeedBaselineResponse {
  created_rules: number
  created_lists: number
  created_rulesets: number
  skipped: number
}

const CATEGORIES = [
  { value: 'protocol', labelKey: 'riskScoring.categories.protocol', color: 'blue' },
  { value: 'headers', labelKey: 'riskScoring.categories.headers', color: 'purple' },
  { value: 'geo', labelKey: 'riskScoring.categories.geo', color: 'amber' },
  { value: 'behavioral', labelKey: 'riskScoring.categories.behavioral', color: 'teal' },
  { value: 'list', labelKey: 'riskScoring.categories.list', color: 'red' },
  { value: 'trust', labelKey: 'riskScoring.categories.trust', color: 'green' },
  { value: 'custom', labelKey: 'riskScoring.categories.custom', color: 'gray' },
] as const

const CATEGORY_COLOR_MAP: Record<string, string> = {
  blue: 'bg-blue-500/20 text-blue-400',
  purple: 'bg-purple-500/20 text-purple-400',
  amber: 'bg-amber-500/20 text-amber-400',
  teal: 'bg-teal-500/20 text-teal-400',
  red: 'bg-red-500/20 text-red-400',
  green: 'bg-green-500/20 text-green-400',
  gray: 'bg-slate-500/20 text-slate-400',
}

const FIELD_GROUPS = [
  {
    labelKey: 'riskScoring.fieldGroups.risk',
    fields: [
      'risk.score', 'risk.rules_hit', 'risk.rules_hit_count',
    ],
  },
  {
    labelKey: 'riskScoring.fieldGroups.request',
    fields: [
      'http.request.method', 'http.request.uri.path', 'http.request.uri',
      'http.request.full_uri', 'http.request.uri.query', 'http.host',
      'http.request.user_agent', 'http.request.referer', 'http.request.version',
      'http.request.scheme', 'http.request.tls',
      'http.request.keep_alive', 'http.request.hour',
    ],
  },
  {
    labelKey: 'riskScoring.fieldGroups.requestHeadersCookies',
    fields: [
      'http.request.headers', 'http.request.cookies',
    ],
  },
  {
    labelKey: 'riskScoring.fieldGroups.ipGeoip',
    fields: [
      'ip.src', 'ip.geoip.country', 'ip.geoip.asnum', 'ip.geoip.continent',
      'ip.geoip.city', 'ip.geoip.region', 'ip.geoip.postal_code',
      'ip.geoip.timezone', 'ip.geoip.latitude', 'ip.geoip.longitude',
      'ip.beacon_trusted',
      'http.request.geo_lang_mismatch', 'http.request.geoip.timezone_mismatch',
    ],
  },
  {
    labelKey: 'riskScoring.fieldGroups.tls',
    fields: [
      'http.request.tls.cipher', 'http.request.tls.version', 'http.request.ja4',
      'http.request.alpn',
    ],
  },
  {
    labelKey: 'riskScoring.fieldGroups.requestFingerprint',
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
    labelKey: 'riskScoring.fieldGroups.graphql',
    fields: [
      'graphql.operation', 'graphql.depth', 'graphql.complexity',
      'graphql.field_count', 'graphql.alias_count', 'graphql.fragment_count',
      'graphql.query_hash', 'graphql.valid',
    ],
  },
  {
    labelKey: 'riskScoring.fieldGroups.apiSchema',
    fields: [
      'api.schema_valid', 'api.schema_errors',
    ],
  },
  {
    labelKey: 'riskScoring.fieldGroups.auth',
    fields: [
      'auth.valid', 'auth.type', 'auth.error',
      'auth.claim.sub', 'auth.claim.iss', 'auth.claim.aud', 'auth.claim',
    ],
  },
  {
    labelKey: 'riskScoring.fieldGroups.profiling',
    fields: [
      'api.profile_anomaly',
    ],
  },
  {
    labelKey: 'riskScoring.fieldGroups.response',
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
  'http.request.keep_alive',
  'http.request.geo_lang_mismatch', 'http.request.geoip.timezone_mismatch',
  'graphql.valid', 'api.schema_valid', 'auth.valid', 'api.profile_anomaly',
])

const NUMERIC_FIELDS = new Set([
  'risk.score',
  'ip.geoip.latitude', 'ip.geoip.longitude',
  'ip.beacon_trusted',
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

export default function RiskScoring() {
  const { t } = useTranslation(['pages', 'common'])
  const { formatDateTime } = useDateTime()
  const { addNotification, trackTask } = useNotifications()
  const { items: allRules, reload } = useApiList<RiskRule>(riskRules.list)
  const { items: listenerList } = useApiList<Listener>(listeners.list)
  const [rulesets, setRulesets] = useState<RiskRuleset[]>([])
  const [activeRulesetId, setActiveRulesetId] = useState<number | null>(null)
  const [manageModalOpen, setManageModalOpen] = useState(false)
  const [modalOpen, setModalOpen] = useState(false)
  const [editing, setEditing] = useState<number | null>(null)
  const [form, setForm] = useState(initialForm())
  const [error, setError] = useState('')
  const [dragOverId, setDragOverId] = useState<number | null>(null)
  const [categoryFilter, setCategoryFilter] = useState<string>('all')
  const [configPending, setConfigPending] = useState(false)
  const [applying, setApplying] = useState(false)
  const [seeding, setSeeding] = useState(false)

  function initialForm() {
    return {
      name: '', enabled: true, listener_ids: [] as number[],
      expression: '', points: 1, category: null as string | null,
      log: true,
    }
  }

  // ---- Fetch rulesets ----
  const refreshRulesets = useCallback(async () => {
    try {
      const res = await riskRulesets.list()
      const data = res.data as RiskRuleset[]
      setRulesets(data)
      if (activeRulesetId === null && data.length > 0) {
        setActiveRulesetId(data[0].id)
      }
    } catch { /* ignore */ }
  }, [activeRulesetId])

  useEffect(() => { refreshRulesets() }, [refreshRulesets])

  // Filter rules by active ruleset
  const rules = useMemo(
    () => activeRulesetId !== null ? allRules.filter(r => r.ruleset_id === activeRulesetId) : [],
    [allRules, activeRulesetId],
  )

  // Check for unapplied config changes (risk rules data file, etc.)
  const refreshConfigStatus = useCallback(async () => {
    try {
      const res = await getConfigStatus()
      setConfigPending(res.data === true)
    } catch { /* ignore */ }
  }, [])

  useEffect(() => { refreshConfigStatus() }, [refreshConfigStatus])
  // Re-check config status after any rule/ruleset save
  useEffect(() => { refreshConfigStatus() }, [allRules, rulesets])

  const handleApply = async () => {
    setApplying(true)
    try {
      const r = await applyConfig()
      const id = addNotification({
        type: 'info',
        title: t('riskScoring.applyConfig'),
        message: r.data.message || t('riskScoring.applying'),
      })
      trackTask(r.data.task_id, id, {
        title: t('riskScoring.applyConfig'),
        successMessage: t('riskScoring.appliedSuccess'),
      })
      setConfigPending(false)
    } catch (err: any) {
      const detail = err?.response?.data?.detail
      addNotification({
        type: 'error',
        title: t('riskScoring.applyFailed'),
        message: typeof detail === 'object' ? detail?.message : (detail || t('riskScoring.applyFailed')),
      })
    } finally {
      setApplying(false)
    }
  }

  // Active ruleset object
  const activeRuleset = useMemo(
    () => rulesets.find(r => r.id === activeRulesetId) ?? null,
    [rulesets, activeRulesetId],
  )

  // ---- Seed baseline ----
  const seedBaseline = async () => {
    if (!window.confirm(t('riskScoring.confirmSeedBaseline'))) return
    setSeeding(true)
    try {
      const res = await riskRules.seedBaseline()
      const data = res.data as SeedBaselineResponse
      addNotification({
        type: 'success',
        title: t('riskScoring.seedBaselineTitle'),
        message: t('riskScoring.seedBaselineResult', {
          rules: data.created_rules,
          lists: data.created_lists,
          rulesets: data.created_rulesets,
          skipped: data.skipped,
        }),
      })
      reload()
      refreshRulesets()
    } catch (err) {
      addNotification({
        type: 'error',
        title: t('riskScoring.seedBaselineTitle'),
        message: getErrorDetail(err),
      })
    } finally {
      setSeeding(false)
    }
  }

  // ---- CRUD ----
  const openAdd = () => {
    setEditing(null)
    setForm(initialForm())
    setError('')
    setModalOpen(true)
  }

  const openEdit = (r: RiskRule) => {
    setEditing(r.id)
    setForm({
      name: r.name, enabled: r.enabled, listener_ids: r.listener_ids || [],
      expression: r.expression, points: r.points, category: r.category,
      log: r.log ?? true,
    })
    setError('')
    setModalOpen(true)
  }

  const submit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError('')
    try {
      if (editing) {
        await riskRules.update(editing, form)
      } else {
        await riskRules.create({ ...form, ruleset_id: activeRulesetId ?? 1 })
      }
      setModalOpen(false)
      reload()
    } catch (err) {
      setError(getErrorDetail(err))
    }
  }

  const remove = async (r: RiskRule) => {
    if (!window.confirm(t('riskScoring.confirmDelete', { name: r.name }))) return
    try {
      await riskRules.remove(r.id)
      reload()
    } catch (err) {
      alert(getErrorDetail(err))
    }
  }

  const toggleEnabled = async (r: RiskRule) => {
    try {
      await riskRules.update(r.id, { ...r, enabled: !r.enabled })
      reload()
    } catch (err) {
      alert(getErrorDetail(err))
    }
  }

  // ---- Ruleset CRUD ----
  const [rsForm, setRsForm] = useState<{
    name: string
    description: string
  }>({ name: '', description: '' })
  const [editingRsId, setEditingRsId] = useState<number | null>(null)

  const saveRuleset = async () => {
    if (!rsForm.name.trim()) return
    try {
      if (editingRsId) {
        await riskRulesets.update(editingRsId, {
          name: rsForm.name,
          description: rsForm.description,
        })
        addNotification({ type: 'success', title: t('riskScoring.rulesets.updated'), message: rsForm.name })
      } else {
        await riskRulesets.create({
          name: rsForm.name,
          description: rsForm.description,
        })
        addNotification({ type: 'success', title: t('riskScoring.rulesets.created'), message: rsForm.name })
      }
      setRsForm({ name: '', description: '' })
      setEditingRsId(null)
      refreshRulesets()
    } catch (err) {
      alert(getErrorDetail(err))
    }
  }

  const editRuleset = (rs: RiskRuleset) => {
    setEditingRsId(rs.id)
    setRsForm({
      name: rs.name,
      description: rs.description ?? '',
    })
  }

  const removeRuleset = async (rs: RiskRuleset) => {
    if (!window.confirm(t('riskScoring.rulesets.deleteConfirm'))) return
    try {
      await riskRulesets.remove(rs.id, rs.slug === 'default')
      addNotification({ type: 'success', title: t('riskScoring.rulesets.deleted'), message: rs.name })
      if (activeRulesetId === rs.id) setActiveRulesetId(null)
      refreshRulesets()
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
      await riskRules.reorder(orderedIds)
      reload()
    } catch (err) {
      alert(getErrorDetail(err))
    }
  }

  // ---- Category helpers ----
  const categoryLabel = (c: string | null): string => {
    if (!c) return t('riskScoring.categories.custom')
    const found = CATEGORIES.find(x => x.value === c)
    return found ? t(found.labelKey) : c
  }

  const categoryColor = (c: string | null): string => {
    if (!c) return CATEGORY_COLOR_MAP.gray
    const found = CATEGORIES.find(x => x.value === c)
    return found ? CATEGORY_COLOR_MAP[found.color] : CATEGORY_COLOR_MAP.gray
  }

  // ---- Grouping by listener ----
  const filteredRules = useMemo(() => {
    if (categoryFilter === 'all') return rules
    return rules.filter(r => (r.category || 'custom') === categoryFilter)
  }, [rules, categoryFilter])

  const groupedRules = useMemo(() => {
    const groups: { key: string; label: string; rules: RiskRule[] }[] = []
    groups.push({
      key: 'all',
      label: t('riskScoring.allListeners'),
      rules: filteredRules.filter(r => !r.listener_ids || r.listener_ids.length === 0),
    })
    const sortedListeners = [...listenerList].sort((a, b) => a.name.localeCompare(b.name))
    for (const l of sortedListeners) {
      const groupRules = filteredRules.filter(r => r.listener_ids?.includes(l.id))
      if (groupRules.length > 0) {
        groups.push({ key: String(l.id), label: l.name, rules: groupRules })
      }
    }
    return groups
  }, [filteredRules, listenerList, t])

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h2 className="text-2xl font-bold flex items-center gap-2">
          <Gauge className="h-5 w-5 text-primary" /> {t('riskScoring.title')}
        </h2>
        <div className="flex items-center gap-2">
          {configPending ? (
            <button
              onClick={handleApply}
              disabled={applying}
              className="btn-primary flex items-center gap-1"
            >
              <Play className="h-4 w-4" /> {applying ? t('riskScoring.applying') : t('riskScoring.applyConfig')}
            </button>
          ) : (
            <span className="flex items-center gap-1 text-xs text-green-400">
              <CheckCircle className="h-4 w-4" /> {t('riskScoring.configApplied')}
            </span>
          )}
          <button
            onClick={() => setManageModalOpen(true)}
            className="btn-secondary flex items-center gap-1"
          >
            <Settings className="h-4 w-4" /> {t('riskScoring.rulesets.manage')}
          </button>
          <button
            onClick={seedBaseline}
            disabled={seeding}
            className="btn-secondary flex items-center gap-1"
          >
            <Sparkles className="h-4 w-4" /> {seeding ? t('riskScoring.seeding') : t('riskScoring.loadBaseline')}
          </button>
          <button onClick={openAdd} disabled={activeRulesetId === null} className="btn-secondary flex items-center gap-1">
            <Plus className="h-4 w-4" /> {t('riskScoring.addRule')}
          </button>
        </div>
      </div>

      {/* Ruleset Tabs */}
      {rulesets.length > 0 && (
        <div className="flex items-center gap-1 border-b border-slate-800">
          {rulesets.map(rs => (
            <button
              key={rs.id}
              onClick={() => setActiveRulesetId(rs.id)}
              className={`px-3 py-2 text-sm font-medium border-b-2 transition-colors ${
                activeRulesetId === rs.id
                  ? 'border-primary text-primary'
                  : 'border-transparent text-slate-400 hover:text-slate-200'
              }`}
            >
              {rs.name}
              <span className="ml-1.5 text-xs text-slate-500">({rs.rule_count})</span>
            </button>
          ))}
        </div>
      )}

      {/* How Risk Scoring Works */}
      {activeRuleset && (
        <div className="card p-4">
          <div className="flex items-center gap-2 mb-3">
            <Gauge className="h-4 w-4 text-primary" />
            <span className="font-semibold text-sm">{t('riskScoring.helpTitle')}</span>
          </div>
          <div className="text-xs text-slate-400 space-y-2">
            <p>{t('riskScoring.helpDescription')}</p>
            <p>{t('riskScoring.helpDensity')}</p>
            <div>
              <span className="text-slate-300 font-medium">{t('riskScoring.helpCalibrationTitle')}</span>
              <ul className="mt-1 space-y-0.5 ms-4 list-disc">
                <li><span className="text-green-400 font-mono">0–5</span> — {t('riskScoring.calibrationTrusted')}</li>
                <li><span className="text-green-400 font-mono">5–15</span> — {t('riskScoring.calibrationLow')}</li>
                <li><span className="text-amber-400 font-mono">15–35</span> — {t('riskScoring.calibrationMedium')}</li>
                <li><span className="text-orange-400 font-mono">35–60</span> — {t('riskScoring.calibrationHigh')}</li>
                <li><span className="text-red-400 font-mono">60–99</span> — {t('riskScoring.calibrationBlock')}</li>
              </ul>
            </div>
            <div>
              <span className="text-slate-300 font-medium">{t('riskScoring.helpExampleTitle')}</span>
              <pre className="mt-1 p-2 rounded bg-slate-900/60 text-slate-300 font-mono text-xs overflow-x-auto"><code>{t('riskScoring.helpExampleCode')}</code></pre>
            </div>
          </div>
        </div>
      )}

      {/* Category filter + table */}
      {rules.length === 0 ? (
        <div className="card p-4 text-slate-500">{t('riskScoring.noRulesYet')}</div>
      ) : (
        <>
          {/* Category filter */}
          <div className="flex items-center gap-2">
            <label className="text-sm text-slate-400">{t('riskScoring.categoryFilter')}</label>
            <select
              className="input text-sm py-1 w-auto"
              value={categoryFilter}
              onChange={e => setCategoryFilter(e.target.value)}
            >
              <option value="all">{t('riskScoring.allCategories')}</option>
              {CATEGORIES.map(c => (
                <option key={c.value} value={c.value}>{t(c.labelKey)}</option>
              ))}
            </select>
          </div>

          <div className="card overflow-x-auto">
            <table className="w-full text-sm text-start">
              <thead className="text-slate-400 border-b border-slate-800">
                <tr>
                  <th className="p-2 w-8"></th>
                  <th className="p-2 w-16">{t('riskScoring.tableHeaders.order')}</th>
                  <th className="p-2">{t('riskScoring.tableHeaders.name')}</th>
                  <th className="p-2 w-20">{t('riskScoring.tableHeaders.points')}</th>
                  <th className="p-2 w-24">{t('riskScoring.tableHeaders.enabled')}</th>
                  <th className="p-2">{t('riskScoring.tableHeaders.expression')}</th>
                  <th className="p-2 w-28">{t('riskScoring.tableHeaders.modified')}</th>
                  <th className="p-2 w-28"></th>
                </tr>
              </thead>
              <tbody>
                {groupedRules.map(group => (
                  <React.Fragment key={group.key}>
                    <tr className="border-b border-slate-800 bg-slate-900/60">
                      <td colSpan={8} className="p-3">
                        <span className="font-semibold text-sm">{group.label}</span>
                        <span className="text-xs text-slate-500 ms-2">({group.rules.length === 1 ? t('riskScoring.ruleCount', { count: group.rules.length }) : t('riskScoring.rulesCount', { count: group.rules.length })})</span>
                      </td>
                    </tr>
                    {group.rules.length === 0 ? (
                      <tr className="border-b border-slate-800">
                        <td colSpan={8} className="p-4 text-sm text-slate-500">{t('riskScoring.noRulesForAllListeners')}</td>
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
                          <td className="p-2 font-medium">
                            <div className="flex items-center gap-2 flex-wrap">
                              <span>{r.name}</span>
                              <span className={`px-2 py-0.5 rounded text-xs font-medium ${categoryColor(r.category)}`}>
                                {categoryLabel(r.category)}
                              </span>
                            </div>
                          </td>
                          <td className="p-2 whitespace-nowrap">
                            <span className={`font-mono font-bold ${r.points > 0 ? 'text-green-400' : r.points < 0 ? 'text-blue-400' : 'text-slate-400'}`}>
                              {r.points > 0 ? `+${r.points}` : r.points}
                            </span>
                          </td>
                          <td className="p-2">
                            <button
                              onClick={() => toggleEnabled(r)}
                              className={`px-2 py-0.5 rounded text-xs font-medium ${r.enabled ? 'bg-green-500/20 text-green-400' : 'bg-slate-700 text-slate-400'}`}
                            >
                              {r.enabled ? t('common:status.enabled') : t('common:status.disabled')}
                            </button>
                          </td>
                          <td className="p-2 text-xs text-slate-400 max-w-xs truncate" title={r.expression}>
                            <code className="text-slate-300">{r.expression}</code>
                          </td>
                          <td className="p-2 text-xs text-slate-400">{formatDateTime(r.updated_at)}</td>
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
        </>
      )}

      {/* Add/Edit modal */}
      <Modal open={modalOpen} onClose={() => setModalOpen(false)} title={editing ? t('riskScoring.modal.editTitle') : t('riskScoring.modal.addTitle')}>
        <form onSubmit={submit} className="space-y-4">
          {error && <div className="bg-red-500/10 border border-red-500/30 text-red-400 rounded p-3 text-sm">{error}</div>}

          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-sm text-slate-400 mb-1">{t('riskScoring.modal.name')}</label>
              <input
                className="input w-full"
                value={form.name}
                onChange={e => setForm({ ...form, name: e.target.value })}
                placeholder={t('riskScoring.modal.namePlaceholder')}
                required
              />
            </div>
            <div>
              <label className="block text-sm text-slate-400 mb-1">{t('riskScoring.modal.category')}</label>
              <CategorySelect
                value={form.category}
                expression={form.expression}
                editing={!!editing}
                onChange={c => setForm({ ...form, category: c })}
              />
            </div>
          </div>

          <div className="grid grid-cols-3 gap-4">
            <div>
              <label className="block text-sm text-slate-400 mb-1">{t('riskScoring.modal.points')}</label>
              <PointsStepper
                value={form.points}
                onChange={v => setForm({ ...form, points: v })}
              />
            </div>
            <div>
              <label className="block text-sm text-slate-400 mb-1">{t('riskScoring.modal.enabled')}</label>
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
              <label className="block text-sm text-slate-400 mb-1">{t('riskScoring.modal.logRuleName')}</label>
              <label className="flex items-center gap-2">
                <input
                  type="checkbox"
                  checked={form.log}
                  onChange={e => setForm({ ...form, log: e.target.checked })}
                />
                <span className="text-sm">{form.log ? t('common:actions.yes') : t('common:actions.no')}</span>
              </label>
            </div>
          </div>

          {/* Listener scope */}
          <div>
            <label className="block text-sm text-slate-400 mb-1">{t('riskScoring.modal.listenerScope')}</label>
            <div className="flex items-center gap-4 mb-2">
              <label className="flex items-center gap-1">
                <input
                  type="radio"
                  checked={form.listener_ids.length === 0}
                  onChange={() => setForm({ ...form, listener_ids: [] })}
                />
                <span className="text-sm">{t('riskScoring.modal.allListeners')}</span>
              </label>
              <label className="flex items-center gap-1">
                <input
                  type="radio"
                  checked={form.listener_ids.length > 0}
                  onChange={() => setForm({ ...form, listener_ids: listenerList.length ? [listenerList[0].id] : [] })}
                />
                <span className="text-sm">{t('riskScoring.modal.selectedListeners')}</span>
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
            <button type="button" onClick={() => setModalOpen(false)} className="btn-secondary">{t('riskScoring.modal.cancel')}</button>
            <button type="submit" className="btn-primary">{editing ? t('riskScoring.modal.update') : t('riskScoring.modal.create')}</button>
          </div>
        </form>
      </Modal>

      {/* Manage Rulesets Modal */}
      <Modal open={manageModalOpen} onClose={() => { setManageModalOpen(false); setEditingRsId(null); setRsForm({ name: '', description: '' }) }} title={t('riskScoring.rulesets.title')}>
        <div className="space-y-4">
          {/* Existing rulesets list */}
          <div className="space-y-2">
            {rulesets.map(rs => (
              <div key={rs.id} className="flex items-center justify-between p-2 rounded border border-slate-800 bg-slate-900/50">
                <div className="flex-1 min-w-0">
                  <div className="text-sm font-medium text-slate-200">{rs.name}</div>
                  <div className="text-xs text-slate-500">
                    <code className="text-slate-400">risk.{rs.slug}.score</code>
                    {' · '}
                    {t('riskScoring.rulesets.ruleCount', { count: rs.rule_count })}
                  </div>
                  {rs.description && <div className="text-xs text-slate-500 mt-0.5">{rs.description}</div>}
                </div>
                <div className="flex gap-1">
                  <IconButton icon={Pencil} onClick={() => editRuleset(rs)} title={t('common:actions.edit')} aria-label={t('common:actions.edit')} />
                  {rs.slug !== 'default' && (
                    <IconButton icon={Trash2} onClick={() => removeRuleset(rs)} title={t('common.delete')} aria-label={t('common.delete')} />
                  )}
                </div>
              </div>
            ))}
          </div>

          {/* Create / Edit form */}
          <div className="border-t border-slate-800 pt-3 space-y-2">
            <div className="text-sm font-medium text-slate-200">
              {editingRsId ? t('common:actions.edit') : t('riskScoring.rulesets.create')}
            </div>
            {editingRsId && (
              <div className="text-xs text-amber-400 bg-amber-500/10 border border-amber-500/30 rounded p-2">
                {t('riskScoring.rulesets.renameWarning')}
              </div>
            )}
            <input
              className="input"
              placeholder={t('riskScoring.rulesets.namePlaceholder')}
              value={rsForm.name}
              onChange={e => setRsForm({ ...rsForm, name: e.target.value })}
            />
            {rsForm.name && (
              <div className="text-xs text-slate-500">
                {t('riskScoring.rulesets.slug')}: <code className="text-slate-400">risk.{rsForm.name.toLowerCase().replace(/[^a-zA-Z0-9]+/g, '_').replace(/^(\d)/, 'rs_$1').replace(/^_|_$/g, '')}.score</code>
              </div>
            )}
            <input
              className="input"
              placeholder={t('riskScoring.rulesets.descriptionPlaceholder')}
              value={rsForm.description}
              onChange={e => setRsForm({ ...rsForm, description: e.target.value })}
            />

            <div className="flex justify-end gap-2">
              {editingRsId && (
                <button
                  onClick={() => { setEditingRsId(null); setRsForm({ name: '', description: '' }) }}
                  className="btn-secondary"
                >
                  {t('riskScoring.rulesets.cancel')}
                </button>
              )}
              <button onClick={saveRuleset} disabled={!rsForm.name.trim()} className="btn-primary">
                {editingRsId ? t('riskScoring.rulesets.save') : t('riskScoring.rulesets.createBtn')}
              </button>
            </div>
          </div>
        </div>
      </Modal>
    </div>
  )
}

// ---------------------------------------------------------------------------
// Points stepper (-99..99)
// ---------------------------------------------------------------------------

function PointsStepper({ value, onChange }: { value: number; onChange: (v: number) => void }) {
  const { t } = useTranslation(['pages', 'common'])
  const clamp = (v: number) => Math.max(-99, Math.min(99, v))
  return (
    <div className="space-y-2">
      {/* Slider + number input row */}
      <div className="flex items-center gap-3">
        <input
          type="range"
          min={-99}
          max={99}
          step={1}
          value={value}
          onChange={e => onChange(clamp(Number(e.target.value)))}
          className="flex-1 accent-blue-500"
        />
        <input
          type="number"
          className="input w-20 text-center font-mono font-bold"
          value={value}
          onChange={e => {
            const v = e.target.value === '' ? 0 : clamp(Number(e.target.value))
            onChange(v)
          }}
          min={-99}
          max={99}
        />
      </div>
      {/* Scale labels */}
      <div className="flex justify-between text-xs text-slate-600">
        <span className="text-blue-400">-99 ({t('riskScoring.modal.trustSignal')})</span>
        <span>0</span>
        <span className="text-red-400">99 ({t('riskScoring.modal.maxRisk')})</span>
      </div>
    </div>
  )
}

// ---------------------------------------------------------------------------
// Category select with auto-suggestion from expression validation
// ---------------------------------------------------------------------------

function CategorySelect({
  value,
  expression,
  editing,
  onChange,
}: {
  value: string | null
  expression: string
  editing: boolean
  onChange: (v: string | null) => void
}) {
  const { t } = useTranslation(['pages', 'common'])
  const [suggested, setSuggested] = useState<string | null>(null)
  const [userOverride, setUserOverride] = useState(false)

  // Validate expression and get suggested category
  useEffect(() => {
    if (!expression.trim()) { setSuggested(null); return }
    const timer = setTimeout(async () => {
      try {
        const res = await riskRules.validate(expression)
        const data = res.data as ValidateResponse
        if (data.ok && data.suggested_category) {
          setSuggested(data.suggested_category)
          // Auto-update category if user hasn't manually overridden
          if (!userOverride) {
            onChange(data.suggested_category)
          }
        }
      } catch {
        // ignore validation errors here — the expression editor handles them
      }
    }, 400)
    return () => clearTimeout(timer)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [expression])

  // Reset override flag when modal reopens (expression changes to a new rule)
  useEffect(() => {
    setUserOverride(false)
  }, [editing])

  const handleManualChange = (v: string) => {
    setUserOverride(true)
    onChange(v === '' ? null : v)
  }

  const isAuto = !userOverride && suggested !== null && value === suggested

  return (
    <div className="flex items-center gap-2">
      <select
        className="input w-full"
        value={value || ''}
        onChange={e => handleManualChange(e.target.value)}
      >
        <option value="">{t('riskScoring.categories.custom')}</option>
        {CATEGORIES.map(c => (
          <option key={c.value} value={c.value}>{t(c.labelKey)}</option>
        ))}
      </select>
      {isAuto && (
        <span className="text-xs text-primary whitespace-nowrap flex items-center gap-0.5">
          <Sparkles className="h-3 w-3" /> {t('riskScoring.auto')}
        </span>
      )}
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
      const res = await riskRules.validate(expr)
      setValidation({ ok: res.data.ok, error: res.data.error })
    } catch {
      setValidation({ ok: false, error: t('riskScoring.expression.validationFailed') })
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
      <label className="block text-sm text-slate-400 mb-1">{t('riskScoring.expression.label')}</label>
      <Tabs
        tabs={[
          { id: 'text', label: t('riskScoring.expression.textTab'), icon: Code2 },
          { id: 'builder', label: t('riskScoring.expression.builderTab'), icon: SlidersHorizontal },
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
            placeholder={t('riskScoring.expression.placeholder')}
          />
          {validation.error && (
            <div className="text-red-400 text-xs mt-1">{validation.error}</div>
          )}
          {validation.ok && value && !validating && (
            <div className="text-green-400 text-xs mt-1">{t('riskScoring.expression.valid')}</div>
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
          {gi > 0 && <div className="text-xs text-slate-500 font-medium uppercase">{t('riskScoring.expression.or')}</div>}
          {group.conditions.map((cond, ci) => (
            <div key={ci} className="flex items-center gap-2 flex-wrap">
              {ci > 0 && <span className="text-xs text-slate-500">{t('riskScoring.expression.and')}</span>}
              <label className="flex items-center gap-1 text-xs">
                <input
                  type="checkbox"
                  checked={cond.negated}
                  onChange={e => updateCondition(gi, ci, { negated: e.target.checked })}
                />
                {t('riskScoring.expression.not')}
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
                {FIELD_GROUPS.map(fg => (
                  <optgroup key={fg.labelKey} label={t(fg.labelKey)}>
                    {fg.fields.map(f => <option key={f} value={f}>{f}</option>)}
                  </optgroup>
                ))}
              </select>
              {isBracketField(cond.field) && (
                <input
                  className="input text-xs py-1 w-24"
                  placeholder={t('riskScoring.expression.headerNamePlaceholder')}
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
              <button type="button" onClick={() => removeCondition(gi, ci)} className="text-red-400 text-xs hover:underline">{t('riskScoring.expression.remove')}</button>
            </div>
          ))}
          <button type="button" onClick={() => addCondition(gi)} className="text-xs text-primary hover:underline">{t('riskScoring.expression.addCondition')}</button>
        </div>
      ))}
      <button type="button" onClick={addGroup} className="text-xs text-primary hover:underline">{t('riskScoring.expression.addOrGroup')}</button>
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
        <option value="">{t('riskScoring.expression.selectPlaceholder')}</option>
        <option value="true">true</option>
        <option value="false">false</option>
      </select>
    )
  }

  if (!useDropdown) {
    return (
      <input
        className="input text-xs py-1 flex-1 min-w-[120px]"
        placeholder={t('riskScoring.expression.valuePlaceholder')}
        value={value}
        onChange={e => onChange(e.target.value)}
      />
    )
  }

  const listType = listEntry!.type
  const optionValues = new Set(lists.map(l => `$${listType}:${l.name}`))
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
        <option value="">{t('riskScoring.expression.selectList')}</option>
        {lists.map(l => (
          <option key={l.id} value={`$${listType}:${l.name}`}>{l.name}</option>
        ))}
        <option value={OTHER_VALUE}>{t('riskScoring.expression.otherManual')}</option>
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

// ---------------------------------------------------------------------------
// Builder helpers
// ---------------------------------------------------------------------------

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
  return STRING_OPS
}
