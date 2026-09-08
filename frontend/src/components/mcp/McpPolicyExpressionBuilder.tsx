import { useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { createPortal } from 'react-dom'
import { Code2, SlidersHorizontal, X, Plus, RefreshCw } from 'lucide-react'
import { mcp } from '../../services/api'
import { Tabs } from '../ui'
import { parseToGroups, serializeGroups, type BuilderCondition, type BuilderGroup } from '../../lib/expression-parser'

export interface BuilderMetadataServer {
  id: number
  namespace: string
  name: string
  last_catalog_at?: string | null
  stale?: boolean
}

export interface BuilderMetadata {
  methods: string[]
  servers: BuilderMetadataServer[]
  stale_servers: BuilderMetadataServer[]
  tools: string[]
  resources: string[]
  prompts: string[]
  identities: string[]
  identity_kinds: string[]
  teams: { id: number; name: string; slug: string }[]
  refreshing?: boolean
}

interface McpPolicyExpressionBuilderProps {
  value: string
  onChange: (value: string) => void
  metadata?: BuilderMetadata | null
  onRefreshMetadata?: () => void
}

interface FieldDef {
  value: string
  label: string
  group: string
  bracket?: boolean
}

const DEFAULT_FIELD = 'mcp.method'

const FIELDS: FieldDef[] = [
  { value: 'mcp.method', label: 'mcpGateway.policies.expressionFields.mcpMethod', group: 'mcpGateway.policies.fieldGroup.mcp' },
  { value: 'mcp.server', label: 'mcpGateway.policies.expressionFields.mcpServer', group: 'mcpGateway.policies.fieldGroup.mcp' },
  { value: 'mcp.tool', label: 'mcpGateway.policies.expressionFields.mcpTool', group: 'mcpGateway.policies.fieldGroup.mcp' },
  { value: 'mcp.resource', label: 'mcpGateway.policies.expressionFields.mcpResource', group: 'mcpGateway.policies.fieldGroup.mcp' },
  { value: 'mcp.prompt', label: 'mcpGateway.policies.expressionFields.mcpPrompt', group: 'mcpGateway.policies.fieldGroup.mcp' },
  { value: 'mcp.identity', label: 'mcpGateway.policies.expressionFields.mcpIdentity', group: 'mcpGateway.policies.fieldGroup.mcp' },
  { value: 'mcp.identity.kind', label: 'mcpGateway.policies.expressionFields.mcpIdentityKind', group: 'mcpGateway.policies.fieldGroup.mcp' },
  { value: 'mcp.team', label: 'mcpGateway.policies.expressionFields.mcpTeam', group: 'mcpGateway.policies.fieldGroup.mcp' },
  { value: 'mcp.arg["..."]', label: 'mcpGateway.policies.expressionFields.mcpArg', group: 'mcpGateway.policies.fieldGroup.mcp', bracket: true },
  { value: 'auth.claim.sub', label: 'mcpGateway.policies.expressionFields.authClaimSub', group: 'mcpGateway.policies.fieldGroup.auth' },
  { value: 'auth.claim.iss', label: 'mcpGateway.policies.expressionFields.authClaimIss', group: 'mcpGateway.policies.fieldGroup.auth' },
  { value: 'auth.claim.aud', label: 'mcpGateway.policies.expressionFields.authClaimAud', group: 'mcpGateway.policies.fieldGroup.auth' },
  { value: 'auth.claim["..."]', label: 'mcpGateway.policies.expressionFields.authClaim', group: 'mcpGateway.policies.fieldGroup.auth', bracket: true },
  { value: 'ip.src', label: 'mcpGateway.policies.expressionFields.ipSrc', group: 'mcpGateway.policies.fieldGroup.network' },
  { value: 'true', label: 'mcpGateway.policies.expressionFields.true', group: 'mcpGateway.policies.fieldGroup.literal' },
  { value: 'false', label: 'mcpGateway.policies.expressionFields.false', group: 'mcpGateway.policies.fieldGroup.literal' },
]

const OPERATORS = [
  { value: '=', label: 'mcpGateway.policies.operator.equals' },
  { value: '!=', label: 'mcpGateway.policies.operator.notEquals' },
  { value: '~', label: 'mcpGateway.policies.operator.matchesRegex' },
  { value: '!~', label: 'mcpGateway.policies.operator.notMatchesRegex' },
  { value: 'contains', label: 'mcpGateway.policies.operator.contains' },
  { value: 'starts_with', label: 'mcpGateway.policies.operator.startsWith' },
  { value: 'ends_with', label: 'mcpGateway.policies.operator.endsWith' },
  { value: 'in', label: 'mcpGateway.policies.operator.inList' },
  { value: 'exists', label: 'mcpGateway.policies.operator.exists' },
]

const RAW_INSERT_FIELDS = [
  'mcp.method', 'mcp.server', 'mcp.tool', 'mcp.resource', 'mcp.prompt',
  'mcp.identity', 'mcp.identity.kind', 'mcp.team', 'mcp.arg["..."]',
  'auth.claim.sub', 'auth.claim.iss', 'auth.claim.aud', 'auth.claim["..."]', 'ip.src',
]

const RAW_INSERT_OPERATORS = [
  { label: '=', insert: ' = ' },
  { label: '!=', insert: ' != ' },
  { label: '~', insert: ' ~ ' },
  { label: '!~', insert: ' !~ ' },
  { label: 'and', insert: ' and ' },
  { label: 'or', insert: ' or ' },
  { label: 'in', insert: ' in ' },
  { label: 'contains', insert: ' contains ' },
  { label: 'starts_with', insert: ' starts_with ' },
  { label: 'ends_with', insert: ' ends_with ' },
]

function getFieldBase(field: string): string {
  if (field.startsWith('mcp.arg["') || field.startsWith("mcp.arg['")) return 'mcp.arg["..."]'
  if (field.startsWith('auth.claim["') || field.startsWith("auth.claim['")) return 'auth.claim["..."]'
  return field
}

function getBracketKey(field: string): string {
  const match = field.match(/\["([^"]+)"\]$/) || field.match(/\['([^']+)'\]$/)
  return match ? match[1] : ''
}

function isInOperator(op: string): boolean {
  return op === 'in'
}

function isLiteralField(field: string): boolean {
  return field.toLowerCase() === 'true' || field.toLowerCase() === 'false'
}

function valueToChips(value: string): string[] {
  const trimmed = value.trim()
  if (trimmed.startsWith('[') && trimmed.endsWith(']')) {
    const inner = trimmed.slice(1, -1).trim()
    if (!inner) return []
    const chips: string[] = []
    let current = ''
    let inQuote = false
    let quote = ''
    for (let i = 0; i < inner.length; i++) {
      const c = inner[i]
      if (inQuote) {
        if (c === '\\' && i + 1 < inner.length) {
          current += inner[i + 1]
          i++
        } else if (c === quote) {
          inQuote = false
          quote = ''
        } else {
          current += c
        }
      } else if (c === '"' || c === "'") {
        inQuote = true
        quote = c
      } else if (c === ',') {
        chips.push(current.trim())
        current = ''
      } else {
        current += c
      }
    }
    chips.push(current.trim())
    return chips.filter(Boolean)
  }
  return trimmed ? [trimmed] : []
}

function chipsToValue(chips: string[]): string {
  if (chips.length === 0) return '[]'
  const quoted = chips.map(v => {
    const escaped = v.replace(/\\/g, '\\\\').replace(/"/g, '\\"')
    return `"${escaped}"`
  })
  return `[${quoted.join(', ')}]`
}

export default function McpPolicyExpressionBuilder({ value, onChange, metadata, onRefreshMetadata }: McpPolicyExpressionBuilderProps) {
  const { t } = useTranslation(['pages', 'common'])
  const [mode, setMode] = useState<'builder' | 'raw'>('builder')
  const [rawText, setRawText] = useState(value)
  const [groups, setGroups] = useState<BuilderGroup[]>(() => parseToGroups(value, DEFAULT_FIELD))
  const [validation, setValidation] = useState<{ ok: boolean | null; error: string | null; validating: boolean }>({ ok: null, error: null, validating: false })
  const validateTimer = useRef<ReturnType<typeof setTimeout> | null>(null)
  const refreshTimer = useRef<ReturnType<typeof setTimeout> | null>(null)
  const [refreshingServer, setRefreshingServer] = useState<number | null>(null)
  const [refreshingAll, setRefreshingAll] = useState(false)

  useEffect(() => {
    if (value !== rawText) {
      setRawText(value)
      setGroups(parseToGroups(value, DEFAULT_FIELD))
    }
  }, [value, rawText])

  const validate = useCallback((expr: string) => {
    if (!expr.trim()) {
      setValidation({ ok: true, error: null, validating: false })
      return
    }
    setValidation(v => ({ ...v, validating: true }))
    mcp.policies.validate(expr)
      .then(res => {
        setValidation({ ok: res.data.ok, error: res.data.error || null, validating: false })
      })
      .catch(() => {
        setValidation({ ok: false, error: t('common:errors.requestFailed'), validating: false })
      })
  }, [t])

  useEffect(() => {
    if (validateTimer.current) clearTimeout(validateTimer.current)
    validateTimer.current = setTimeout(() => validate(rawText), 300)
    return () => { if (validateTimer.current) clearTimeout(validateTimer.current) }
  }, [rawText, validate])

  useEffect(() => {
    if (metadata?.refreshing && onRefreshMetadata) {
      if (refreshTimer.current) clearTimeout(refreshTimer.current)
      refreshTimer.current = setTimeout(() => onRefreshMetadata(), 3000)
      return () => { if (refreshTimer.current) clearTimeout(refreshTimer.current) }
    }
  }, [metadata?.refreshing, onRefreshMetadata])

  const handleRefreshServer = useCallback(async (sid: number) => {
    setRefreshingServer(sid)
    try {
      await mcp.servers.refreshCatalog(sid)
      onRefreshMetadata?.()
    } catch (e) {
      // ignore; next metadata refresh will show state
    } finally {
      setRefreshingServer(null)
    }
  }, [onRefreshMetadata])

  const handleRefreshAll = useCallback(async () => {
    if (!metadata?.servers?.length) return
    setRefreshingAll(true)
    try {
      for (const s of metadata.servers) {
        await mcp.servers.refreshCatalog(s.id)
      }
      onRefreshMetadata?.()
    } catch (e) {
      // ignore
    } finally {
      setRefreshingAll(false)
    }
  }, [metadata?.servers, onRefreshMetadata])

  const updateFromGroups = (newGroups: BuilderGroup[]) => {
    setGroups(newGroups)
    const serialized = serializeGroups(newGroups)
    setRawText(serialized)
    onChange(serialized)
  }

  const updateFromRaw = (text: string) => {
    setRawText(text)
    setGroups(parseToGroups(text, DEFAULT_FIELD))
    onChange(text)
  }

  const addGroup = () => updateFromGroups([...groups, { conditions: [{ field: DEFAULT_FIELD, op: '=', value: '', negated: false }] }])

  const removeGroup = (gi: number) => {
    const next = [...groups]
    next.splice(gi, 1)
    updateFromGroups(next)
  }

  const addCondition = (gi: number) => {
    const next = [...groups]
    next[gi].conditions.push({ field: DEFAULT_FIELD, op: '=', value: '', negated: false })
    updateFromGroups(next)
  }

  const removeCondition = (gi: number, ci: number) => {
    const next = [...groups]
    next[gi].conditions.splice(ci, 1)
    if (next[gi].conditions.length === 0) next.splice(gi, 1)
    updateFromGroups(next)
  }

  const updateCondition = (gi: number, ci: number, patch: Partial<BuilderCondition>) => {
    const next = [...groups]
    next[gi].conditions[ci] = { ...next[gi].conditions[ci], ...patch }
    updateFromGroups(next)
  }

  const insertAtCursor = (insert: string) => {
    const textarea = document.getElementById('mcp-policy-expression-raw') as HTMLTextAreaElement | null
    if (!textarea) return
    const start = textarea.selectionStart
    const end = textarea.selectionEnd
    const before = rawText.slice(0, start)
    const after = rawText.slice(end)
    const next = before + insert + after
    updateFromRaw(next)
    setTimeout(() => {
      textarea.focus()
      const pos = start + insert.length
      textarea.setSelectionRange(pos, pos)
    }, 0)
  }

  const groupedFieldOptions = useMemo(() => {
    const map: Record<string, FieldDef[]> = {}
    FIELDS.forEach(f => {
      if (!map[f.group]) map[f.group] = []
      map[f.group].push(f)
    })
    return map
  }, [])

  const renderValueInput = (cond: BuilderCondition, onChangeCond: (patch: Partial<BuilderCondition>) => void) => {
    const meta = metadata || { methods: [], servers: [], tools: [], resources: [], prompts: [], identities: [], identity_kinds: [], teams: [] }

    if (isLiteralField(cond.field)) {
      return <span className="text-xs text-muted-foreground italic">{t('pages:mcpGateway.policies.literalValue')}</span>
    }

    const base = getFieldBase(cond.field)
    const isIn = isInOperator(cond.op)

    if (base === 'mcp.method') {
      return (
        <select
          className="input text-xs py-1 min-w-[160px]"
          value={cond.value}
          onChange={e => onChangeCond({ value: e.target.value })}
        >
          <option value="">{t('pages:mcpGateway.policies.selectValue')}</option>
          {meta.methods.map(m => <option key={m} value={m}>{m}</option>)}
        </select>
      )
    }

    if (base === 'mcp.server') {
      return (
        <select
          className="input text-xs py-1 min-w-[160px]"
          value={cond.value}
          onChange={e => onChangeCond({ value: e.target.value })}
        >
          <option value="">{t('pages:mcpGateway.policies.selectValue')}</option>
          {meta.servers.map(s => <option key={s.id} value={s.namespace}>{s.name} ({s.namespace})</option>)}
        </select>
      )
    }

    if (base === 'mcp.tool' || base === 'mcp.prompt') {
      const options = base === 'mcp.tool' ? meta.tools : meta.prompts
      if (isIn) {
        return <ChipInput values={valueToChips(cond.value)} options={options} onChange={v => onChangeCond({ value: chipsToValue(v) })} placeholder={t('pages:mcpGateway.policies.addTool')} />
      }
      return (
        <Autocomplete
          value={cond.value}
          options={options}
          onChange={v => onChangeCond({ value: v })}
          placeholder={t('pages:mcpGateway.policies.selectOrTypeValue')}
        />
      )
    }

    if (base === 'mcp.identity') {
      return (
        <Autocomplete
          value={cond.value}
          options={meta.identities}
          onChange={v => onChangeCond({ value: v })}
          placeholder={t('pages:mcpGateway.policies.selectOrTypeValue')}
        />
      )
    }

    if (base === 'mcp.identity.kind') {
      return (
        <select
          className="input text-xs py-1 min-w-[120px]"
          value={cond.value}
          onChange={e => onChangeCond({ value: e.target.value })}
        >
          <option value="">{t('pages:mcpGateway.policies.selectValue')}</option>
          {meta.identity_kinds.map(k => <option key={k} value={k}>{k}</option>)}
        </select>
      )
    }

    if (base === 'mcp.team') {
      return (
        <select
          className="input text-xs py-1 min-w-[160px]"
          value={cond.value}
          onChange={e => onChangeCond({ value: e.target.value })}
        >
          <option value="">{t('pages:mcpGateway.policies.selectValue')}</option>
          {meta.teams.map(team => <option key={team.id} value={team.slug}>{team.name} ({team.slug})</option>)}
        </select>
      )
    }

    if (base === 'mcp.resource') {
      return (
        <Autocomplete
          value={cond.value}
          options={meta.resources}
          onChange={v => onChangeCond({ value: v })}
          placeholder={t('pages:mcpGateway.policies.selectOrTypeValue')}
        />
      )
    }

    if (base === 'mcp.arg["..."]' || base === 'auth.claim["..."]') {
      // For bracket fields, value is a normal string; the key is stored in the field string
      if (cond.op === 'exists' || cond.op === 'not exists') {
        return <span className="text-xs text-muted-foreground italic">{t('pages:mcpGateway.policies.noValueForExists')}</span>
      }
      return (
        <input
          className="input text-xs py-1 min-w-[160px]"
          value={cond.value}
          onChange={e => onChangeCond({ value: e.target.value })}
          placeholder={t('pages:mcpGateway.policies.valuePlaceholder')}
        />
      )
    }

    return (
      <input
        className="input text-xs py-1 min-w-[160px]"
        value={cond.value}
        onChange={e => onChangeCond({ value: e.target.value })}
        placeholder={t('pages:mcpGateway.policies.valuePlaceholder')}
      />
    )
  }

  return (
    <div className="space-y-2">
      <div className="flex items-center justify-between gap-2">
        <Tabs
          className="flex-1"
          tabs={[
            { id: 'builder', label: t('pages:mcpGateway.policies.builderTab'), icon: SlidersHorizontal },
            { id: 'raw', label: t('pages:mcpGateway.policies.rawTab'), icon: Code2 },
          ]}
          active={mode}
          onChange={id => {
            if (id === 'raw') {
              setRawText(serializeGroups(groups))
            } else {
              setGroups(parseToGroups(rawText, DEFAULT_FIELD))
            }
            setMode(id as 'builder' | 'raw')
          }}
        />
        {onRefreshMetadata && (
          <button
            type="button"
            onClick={handleRefreshAll}
            disabled={refreshingAll || metadata?.refreshing}
            title={t('pages:mcpGateway.policies.refreshAllCatalogs')}
            className="btn-ghost p-1.5 disabled:opacity-50"
          >
            <RefreshCw className={`w-4 h-4 ${(refreshingAll || metadata?.refreshing) ? 'animate-spin' : ''}`} />
          </button>
        )}
      </div>

      {metadata?.stale_servers && metadata.stale_servers.length > 0 && (
        <div className="mb-3 rounded-md border border-yellow-600/30 bg-yellow-950/20 p-2 space-y-2">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-xs font-medium text-yellow-400">
                {t('pages:mcpGateway.policies.staleCatalogsTitle', { count: metadata.stale_servers.length })}
              </p>
              <p className="text-[11px] text-muted-foreground">
                {metadata.refreshing ? t('pages:mcpGateway.policies.refreshingCatalogs') : t('pages:mcpGateway.policies.staleCatalogsHint')}
              </p>
            </div>
            <button
              type="button"
              onClick={handleRefreshAll}
              disabled={refreshingServer !== null || refreshingAll || metadata.refreshing}
              className="btn-secondary text-xs py-1 px-2 disabled:opacity-50"
            >
              {t('pages:mcpGateway.policies.refreshAllCatalogs')}
            </button>
          </div>
          <ul className="space-y-1">
            {metadata.stale_servers.map(s => (
              <li key={s.id} className="flex items-center justify-between text-xs">
                <span className="text-muted-foreground">{s.name} <span className="text-slate-500">({s.namespace})</span></span>
                <button
                  type="button"
                  onClick={() => handleRefreshServer(s.id)}
                  disabled={refreshingServer !== null || refreshingAll || metadata.refreshing}
                  className="text-yellow-400 hover:text-yellow-300 disabled:opacity-50"
                >
                  {refreshingServer === s.id ? t('common:loading') : t('pages:mcpGateway.policies.refreshServerCatalog')}
                </button>
              </li>
            ))}
          </ul>
        </div>
      )}

      {mode === 'builder' ? (
        <div className="space-y-3 max-h-[50vh] overflow-y-auto pe-1">
          {groups.map((group, gi) => (
            <div key={gi} className="rounded-md border border-border bg-card p-2 space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-xs font-medium text-muted-foreground uppercase">{t('pages:mcpGateway.policies.conditionGroup', { number: gi + 1 })}</span>
                {groups.length > 1 && (
                  <button type="button" className="text-xs text-red-400 hover:underline" onClick={() => removeGroup(gi)}>{t('common:actions.remove')}</button>
                )}
              </div>
              {group.conditions.map((cond, ci) => (
                <div key={ci} className="flex flex-wrap items-center gap-2">
                  {ci > 0 && <span className="text-xs text-muted-foreground">{t('pages:mcpGateway.policies.and')}</span>}
                  <label className="flex items-center gap-1 text-xs cursor-pointer">
                    <input
                      type="checkbox"
                      checked={cond.negated}
                      onChange={e => updateCondition(gi, ci, { negated: e.target.checked })}
                    />
                    {t('pages:mcpGateway.policies.not')}
                  </label>

                  <select
                    className="input text-xs py-1 min-w-[160px]"
                    value={getFieldBase(cond.field)}
                    onChange={e => {
                      const selected = FIELDS.find(f => f.value === e.target.value)
                      if (!selected) return
                      if (selected.bracket) {
                        updateCondition(gi, ci, { field: selected.value, value: '' })
                      } else if (selected.value === 'true' || selected.value === 'false') {
                        updateCondition(gi, ci, { field: selected.value, op: 'literal', value: '' })
                      } else {
                        updateCondition(gi, ci, { field: selected.value, value: '' })
                      }
                    }}
                  >
                    {Object.entries(groupedFieldOptions).map(([group, opts]) => (
                      <optgroup key={group} label={t(group)}>
                        {opts.map(f => <option key={f.value} value={f.value}>{t(f.label)}</option>)}
                      </optgroup>
                    ))}
                  </select>

                  {(cond.field === 'mcp.arg["..."]' || cond.field === 'auth.claim["..."]') && (
                    <input
                      className="input text-xs py-1 w-24"
                      value={getBracketKey(cond.field)}
                      onChange={e => {
                        const base = cond.field.startsWith('mcp.arg') ? 'mcp.arg' : 'auth.claim'
                        updateCondition(gi, ci, { field: `${base}["${e.target.value.replace(/"/g, '\\"')}"]` })
                      }}
                      placeholder={t('pages:mcpGateway.policies.keyPlaceholder')}
                    />
                  )}

                  {!isLiteralField(cond.field) && (
                    <select
                      className="input text-xs py-1 min-w-[120px]"
                      value={cond.op}
                      onChange={e => updateCondition(gi, ci, { op: e.target.value, value: cond.op === e.target.value ? cond.value : '' })}
                    >
                      {OPERATORS.map(op => <option key={op.value} value={op.value}>{t(op.label)}</option>)}
                    </select>
                  )}

                  {cond.op !== 'exists' && renderValueInput(cond, patch => updateCondition(gi, ci, patch))}

                  <button
                    type="button"
                    className="text-red-400 hover:text-red-300 p-1"
                    onClick={() => removeCondition(gi, ci)}
                    aria-label={t('common:actions.remove')}
                  >
                    <X className="w-3.5 h-3.5" />
                  </button>
                </div>
              ))}
              <button
                type="button"
                className="text-xs text-primary hover:underline flex items-center gap-1"
                onClick={() => addCondition(gi)}
              >
                <Plus className="w-3 h-3" /> {t('pages:mcpGateway.policies.addCondition')}
              </button>
            </div>
          ))}
          <button
            type="button"
            className="text-xs text-primary hover:underline flex items-center gap-1"
            onClick={addGroup}
          >
            <Plus className="w-3 h-3" /> {t('pages:mcpGateway.policies.addOrGroup')}
          </button>
        </div>
      ) : (
        <div className="space-y-2">
          <textarea
            id="mcp-policy-expression-raw"
            className="input w-full font-mono text-sm"
            rows={3}
            value={rawText}
            onChange={e => updateFromRaw(e.target.value)}
            placeholder={t('pages:mcpGateway.policies.modal.expressionPlaceholder')}
          />
          <div className="space-y-1">
            <p className="text-xs text-muted-foreground">{t('pages:mcpGateway.policies.insertField')}</p>
            <div className="flex flex-wrap gap-1">
              {RAW_INSERT_FIELDS.map(f => (
                <button
                  key={f}
                  type="button"
                  className="btn-secondary text-xs py-0.5 px-2"
                  onClick={() => insertAtCursor(f)}
                >
                  {f}
                </button>
              ))}
            </div>
          </div>
          <div className="space-y-1">
            <p className="text-xs text-muted-foreground">{t('pages:mcpGateway.policies.insertOperator')}</p>
            <div className="flex flex-wrap gap-1">
              {RAW_INSERT_OPERATORS.map(op => (
                <button
                  key={op.label}
                  type="button"
                  className="btn-secondary text-xs py-0.5 px-2 font-mono"
                  onClick={() => insertAtCursor(op.insert)}
                >
                  {op.label}
                </button>
              ))}
            </div>
          </div>
        </div>
      )}

      <div className="min-h-[1.25rem]">
        {validation.validating && <p className="text-xs text-muted-foreground">{t('common:actions.loading')}</p>}
        {!validation.validating && validation.error && <p className="text-xs text-red-400">{validation.error}</p>}
        {!validation.validating && validation.ok && rawText.trim() && <p className="text-xs text-green-400">{t('pages:mcpGateway.policies.valid')}</p>}
      </div>
    </div>
  )
}

function Autocomplete({ value, options, onChange, placeholder }: { value: string; options: string[]; onChange: (v: string) => void; placeholder?: string }) {
  const [open, setOpen] = useState(false)
  const [input, setInput] = useState(value)
  const containerRef = useRef<HTMLDivElement>(null)
  const dropdownRef = useRef<HTMLDivElement>(null)
  const [coords, setCoords] = useState({ top: 0, left: 0, width: 0 })

  useEffect(() => setInput(value), [value])

  useEffect(() => {
    const handler = (e: MouseEvent) => {
      if (containerRef.current?.contains(e.target as Node) || dropdownRef.current?.contains(e.target as Node)) return
      setOpen(false)
    }
    document.addEventListener('mousedown', handler)
    return () => document.removeEventListener('mousedown', handler)
  }, [])

  // Close the dropdown whenever the page or any scrollable ancestor scrolls,
  // because the menu is rendered with fixed positioning and would otherwise
  // detach from the input while scrolling.  Keep it open when the user is
  // scrolling the dropdown list itself.
  useEffect(() => {
    const closeOnResize = () => setOpen(false)
    const closeOnScroll = (e: Event) => {
      const target = e.target
      if (target instanceof Node) {
        if (dropdownRef.current && (dropdownRef.current === target || dropdownRef.current.contains(target))) return
        if (containerRef.current && (containerRef.current === target || containerRef.current.contains(target))) return
      }
      setOpen(false)
    }
    window.addEventListener('resize', closeOnResize)
    window.addEventListener('scroll', closeOnScroll, true)
    return () => {
      window.removeEventListener('resize', closeOnResize)
      window.removeEventListener('scroll', closeOnScroll, true)
    }
  }, [])

  const matches = useMemo(() => {
    if (!input.trim()) return options.slice(0, 20)
    const lower = input.toLowerCase()
    return options.filter(o => o.toLowerCase().includes(lower)).slice(0, 20)
  }, [input, options])

  useLayoutEffect(() => {
    if (!open || !containerRef.current) return
    const rect = containerRef.current.getBoundingClientRect()
    const desiredWidth = Math.max(rect.width, 240)
    const maxAllowedWidth = Math.min(480, window.innerWidth - 8)
    const dropdownWidth = Math.min(desiredWidth, maxAllowedWidth)
    const maxDropdownHeight = 192 // max-h-48
    const spaceBelow = window.innerHeight - rect.bottom - 4
    let top = rect.bottom + 4
    if (spaceBelow < maxDropdownHeight) {
      top = Math.max(4, rect.top - 4 - maxDropdownHeight)
    }
    let left = rect.left
    if (left + dropdownWidth > window.innerWidth - 4) {
      left = Math.max(4, window.innerWidth - dropdownWidth - 4)
    }
    setCoords({ top, left, width: dropdownWidth })
  }, [open, matches.length, input])

  const dropdown = open && matches.length > 0 && (
    <div
      ref={dropdownRef}
      className="fixed z-[200] max-h-48 overflow-auto rounded-md border border-border bg-card shadow-xl py-1"
      style={{ top: coords.top, left: coords.left, width: `${coords.width}px`, maxWidth: `${coords.width}px` }}
    >
      {matches.map(o => (
        <button
          key={o}
          type="button"
          className="w-full text-left px-3 py-1.5 text-sm text-foreground break-all hover:bg-muted"
          onClick={() => { setInput(o); onChange(o); setOpen(false) }}
        >
          {o}
        </button>
      ))}
    </div>
  )

  return (
    <div ref={containerRef} className="min-w-[160px] w-full">
      <input
        className="input text-xs py-1 w-full"
        value={input}
        onChange={e => { setInput(e.target.value); onChange(e.target.value) }}
        onFocus={() => setOpen(true)}
        placeholder={placeholder}
      />
      {dropdown && createPortal(dropdown, document.body)}
    </div>
  )
}

function ChipInput({ values, options, onChange, placeholder }: { values: string[]; options: string[]; onChange: (v: string[]) => void; placeholder?: string }) {
  const [input, setInput] = useState('')
  const [open, setOpen] = useState(false)
  const containerRef = useRef<HTMLDivElement>(null)
  const dropdownRef = useRef<HTMLDivElement>(null)
  const [coords, setCoords] = useState({ top: 0, left: 0, width: 0 })

  useEffect(() => {
    const handler = (e: MouseEvent) => {
      if (containerRef.current?.contains(e.target as Node) || dropdownRef.current?.contains(e.target as Node)) return
      setOpen(false)
    }
    document.addEventListener('mousedown', handler)
    return () => document.removeEventListener('mousedown', handler)
  }, [])

  useEffect(() => {
    const closeOnResize = () => setOpen(false)
    const closeOnScroll = (e: Event) => {
      const target = e.target
      if (target instanceof Node) {
        if (dropdownRef.current && (dropdownRef.current === target || dropdownRef.current.contains(target))) return
        if (containerRef.current && (containerRef.current === target || containerRef.current.contains(target))) return
      }
      setOpen(false)
    }
    window.addEventListener('resize', closeOnResize)
    window.addEventListener('scroll', closeOnScroll, true)
    return () => {
      window.removeEventListener('resize', closeOnResize)
      window.removeEventListener('scroll', closeOnScroll, true)
    }
  }, [])

  const matches = useMemo(() => {
    if (!input.trim()) return options.slice(0, 20)
    const lower = input.toLowerCase()
    return options.filter(o => o.toLowerCase().includes(lower) && !values.includes(o)).slice(0, 20)
  }, [input, options, values])

  const add = (v: string) => {
    const trimmed = v.trim()
    if (!trimmed || values.includes(trimmed)) return
    onChange([...values, trimmed])
    setInput('')
    setOpen(false)
  }

  const remove = (v: string) => onChange(values.filter(x => x !== v))

  useLayoutEffect(() => {
    if (!open || !containerRef.current) return
    const rect = containerRef.current.getBoundingClientRect()
    const desiredWidth = Math.max(rect.width, 240)
    const maxAllowedWidth = Math.min(480, window.innerWidth - 8)
    const dropdownWidth = Math.min(desiredWidth, maxAllowedWidth)
    const maxDropdownHeight = 192
    const spaceBelow = window.innerHeight - rect.bottom - 4
    let top = rect.bottom + 4
    if (spaceBelow < maxDropdownHeight) {
      top = Math.max(4, rect.top - 4 - maxDropdownHeight)
    }
    let left = rect.left
    if (left + dropdownWidth > window.innerWidth - 4) {
      left = Math.max(4, window.innerWidth - dropdownWidth - 4)
    }
    setCoords({ top, left, width: dropdownWidth })
  }, [open, matches.length, input, values.length])

  const dropdown = open && matches.length > 0 && (
    <div
      ref={dropdownRef}
      className="fixed z-[200] max-h-48 overflow-auto rounded-md border border-border bg-card shadow-xl py-1"
      style={{ top: coords.top, left: coords.left, width: `${coords.width}px`, maxWidth: `${coords.width}px` }}
    >
      {matches.map(o => (
        <button
          key={o}
          type="button"
          className="w-full text-left px-3 py-1.5 text-sm text-foreground break-all hover:bg-muted"
          onClick={() => add(o)}
        >
          {o}
        </button>
      ))}
    </div>
  )

  return (
    <div ref={containerRef} className="min-w-[160px] w-full">
      <div className="input w-full flex flex-wrap items-center gap-1 py-1 px-2 min-h-[2rem]">
        {values.map(v => (
          <span key={v} className="inline-flex items-center gap-1 rounded bg-muted px-1.5 py-0.5 text-xs">
            {v}
            <button type="button" onClick={() => remove(v)} className="hover:text-red-400"><X className="w-3 h-3" /></button>
          </span>
        ))}
        <input
          className="bg-transparent text-xs flex-1 min-w-[80px] outline-none"
          value={input}
          onChange={e => { setInput(e.target.value); setOpen(true) }}
          onKeyDown={e => { if (e.key === 'Enter') { e.preventDefault(); add(input) } }}
          onFocus={() => setOpen(true)}
          placeholder={values.length === 0 ? placeholder : ''}
        />
      </div>
      {dropdown && createPortal(dropdown, document.body)}
    </div>
  )
}
