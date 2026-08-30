import { useEffect, useState, useCallback } from 'react'
import { useTranslation } from 'react-i18next'
import { ChevronDown, ChevronRight, Search } from 'lucide-react'
import { mcp } from '../../services/api'
import { Badge } from '../ui'
import { useDateTime } from '../../contexts/DateTimeContext'

interface McpEvent {
  id: number
  captured_at: string
  request_id: string | null
  session_id: string | null
  identity_id: number | null
  team_id: number | null
  server_id: number | null
  jsonrpc_method: string | null
  tool: string | null
  resource_uri: string | null
  prompt: string | null
  action: string | null
  status: string | null
  latency_ms: number | null
  error: string | null
  bytes_in: number | null
  bytes_out: number | null
  dlp_hits: any[] | null
  guardrail_hits: any[] | null
}

const ACTION_COLORS: Record<string, 'success' | 'error' | 'warning' | 'default' | 'info'> = {
  allow: 'success',
  deny: 'error',
  dlp_block: 'error',
  dlp_redact: 'warning',
  guardrail_block: 'error',
  guardrail_redact: 'warning',
  upstream_error: 'error',
  rate_limited: 'warning',
}

const TIME_RANGES = [
  { label: '15m', minutes: 15 },
  { label: '1h', minutes: 60 },
  { label: '6h', minutes: 360 },
  { label: '1d', minutes: 1440 },
  { label: '7d', minutes: 10080 },
]

const ACTIONS = ['', 'allow', 'deny', 'dlp_block', 'dlp_redact', 'guardrail_block', 'guardrail_redact', 'upstream_error', 'rate_limited']

export default function McpEventsTab() {
  const { t } = useTranslation(['pages', 'common'])
  const { formatDateTime } = useDateTime()
  const [events, setEvents] = useState<McpEvent[]>([])
  const [loading, setLoading] = useState(true)
  const [timeRange, setTimeRange] = useState(60)
  const [actionFilter, setActionFilter] = useState('')
  const [methodFilter, setMethodFilter] = useState('')
  const [search, setSearch] = useState('')
  const [expandedId, setExpandedId] = useState<number | null>(null)
  const [offset, setOffset] = useState(0)
  const [total, setTotal] = useState(0)
  const LIMIT = 50

  const fetch = useCallback(async () => {
    setLoading(true)
    try {
      const from = new Date(Date.now() - timeRange * 60 * 1000).toISOString()
      const params: Record<string, unknown> = { from, limit: LIMIT, offset }
      if (actionFilter) params.action = actionFilter
      if (methodFilter) params.method = methodFilter
      const resp = await mcp.events.list(params as any)
      setEvents(resp.data.events || resp.data)
      setTotal(resp.data.total || resp.data.length)
    } catch { setEvents([]) }
    finally { setLoading(false) }
  }, [timeRange, actionFilter, methodFilter, offset])

  useEffect(() => { fetch() }, [fetch])

  const filtered = search
    ? events.filter(e =>
        (e.request_id?.includes(search) || e.tool?.includes(search) || e.jsonrpc_method?.includes(search))
      )
    : events

  return (
    <div className="space-y-4">
      {/* Filters */}
      <div className="flex flex-wrap items-center gap-3">
        <div className="flex items-center gap-1">
          {TIME_RANGES.map(r => (
            <button
              key={r.label}
              className={`btn-secondary text-xs ${timeRange === r.minutes ? 'ring-2 ring-primary' : ''}`}
              onClick={() => { setTimeRange(r.minutes); setOffset(0) }}
            >
              {r.label}
            </button>
          ))}
        </div>
        <select className="input w-40 text-sm" value={actionFilter} onChange={e => { setActionFilter(e.target.value); setOffset(0) }}>
          {ACTIONS.map(a => <option key={a} value={a}>{a || t('pages:mcpGateway.events.allActions')}</option>)}
        </select>
        <select className="input w-44 text-sm" value={methodFilter} onChange={e => { setMethodFilter(e.target.value); setOffset(0) }}>
          <option value="">{t('pages:mcpGateway.events.allMethods')}</option>
          <option value="initialize">initialize</option>
          <option value="tools/list">tools/list</option>
          <option value="tools/call">tools/call</option>
          <option value="resources/list">resources/list</option>
          <option value="resources/read">resources/read</option>
          <option value="prompts/list">prompts/list</option>
          <option value="prompts/get">prompts/get</option>
        </select>
        <div className="relative flex-1 min-w-48">
          <Search className="absolute left-2 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
          <input
            className="input w-full text-sm ps-8"
            placeholder={t('pages:mcpGateway.events.searchPlaceholder')}
            value={search}
            onChange={e => setSearch(e.target.value)}
          />
        </div>
      </div>

      <p className="text-sm text-muted-foreground">{t('pages:mcpGateway.events.count', { count: filtered.length })}{total > LIMIT ? ` ${t('pages:mcpGateway.events.showingRange', { from: offset + 1, to: offset + filtered.length, total })}` : ''}</p>

      {/* Events table */}
      {loading ? (
        <p className="text-sm text-muted-foreground">{t('common:actions.loading')}</p>
      ) : filtered.length === 0 ? (
        <div className="rounded-lg border border-border bg-card p-8 text-center">
          <p className="text-sm text-muted-foreground">{t('pages:mcpGateway.events.empty')}</p>
        </div>
      ) : (
        <div className="space-y-1">
          {filtered.map(e => (
            <div key={e.id} className="rounded-lg border border-border bg-card">
              <div
                className="p-2 flex items-center gap-3 cursor-pointer hover:bg-muted/50"
                onClick={() => setExpandedId(expandedId === e.id ? null : e.id)}
              >
                <span className="text-muted-foreground">
                  {expandedId === e.id ? <ChevronDown className="w-4 h-4" /> : <ChevronRight className="w-4 h-4" />}
                </span>
                <span className="text-xs text-muted-foreground w-36 shrink-0">{formatDateTime(e.captured_at)}</span>
                {e.action && <Badge variant={ACTION_COLORS[e.action] || 'default'} size="sm">{e.action}</Badge>}
                <span className="text-sm font-mono truncate flex-1">{e.jsonrpc_method || '-'}</span>
                <span className="text-sm text-muted-foreground truncate max-w-32">{e.tool || e.resource_uri || e.prompt || '-'}</span>
                {e.latency_ms != null && <span className="text-xs text-muted-foreground">{e.latency_ms}ms</span>}
                {e.status && e.status !== 'ok' && <Badge variant="warning" size="sm">{e.status}</Badge>}
              </div>
              {expandedId === e.id && (
                <div className="border-t border-border p-3 space-y-2 text-sm">
                  <div className="grid grid-cols-2 gap-x-6 gap-y-1">
                    <div><span className="text-muted-foreground">{t('pages:mcpGateway.events.fields.requestId')}</span> <code className="text-xs">{e.request_id || '-'}</code></div>
                    <div><span className="text-muted-foreground">{t('pages:mcpGateway.events.fields.session')}</span> <code className="text-xs">{e.session_id || '-'}</code></div>
                    <div><span className="text-muted-foreground">{t('pages:mcpGateway.events.fields.identity')}</span> #{e.identity_id || '-'}</div>
                    <div><span className="text-muted-foreground">{t('pages:mcpGateway.events.fields.team')}</span> #{e.team_id || '-'}</div>
                    <div><span className="text-muted-foreground">{t('pages:mcpGateway.events.fields.server')}</span> #{e.server_id || '-'}</div>
                    <div><span className="text-muted-foreground">{t('pages:mcpGateway.events.fields.status')}</span> {e.status || '-'}</div>
                    <div><span className="text-muted-foreground">{t('pages:mcpGateway.events.fields.bytesIn')}</span> {e.bytes_in ?? '-'}</div>
                    <div><span className="text-muted-foreground">{t('pages:mcpGateway.events.fields.bytesOut')}</span> {e.bytes_out ?? '-'}</div>
                    <div><span className="text-muted-foreground">{t('pages:mcpGateway.events.fields.latency')}</span> {e.latency_ms != null ? `${e.latency_ms}ms` : '-'}</div>
                    <div><span className="text-muted-foreground">{t('pages:mcpGateway.events.fields.action')}</span> {e.action || '-'}</div>
                  </div>
                  {e.error && (
                    <div className="rounded border border-red-500/30 bg-red-500/10 p-2 text-xs text-red-300">
                      <span className="font-semibold">{t('pages:mcpGateway.events.fields.error')}</span> {e.error}
                    </div>
                  )}
                  {e.dlp_hits && e.dlp_hits.length > 0 && (
                    <div>
                      <span className="text-xs font-semibold">{t('pages:mcpGateway.events.fields.dlpHits')}</span>
                      <pre className="text-xs bg-muted rounded p-2 mt-1 overflow-x-auto">{JSON.stringify(e.dlp_hits, null, 2)}</pre>
                    </div>
                  )}
                  {e.guardrail_hits && e.guardrail_hits.length > 0 && (
                    <div>
                      <span className="text-xs font-semibold">{t('pages:mcpGateway.events.fields.guardrailHits')}</span>
                      <pre className="text-xs bg-muted rounded p-2 mt-1 overflow-x-auto">{JSON.stringify(e.guardrail_hits, null, 2)}</pre>
                    </div>
                  )}
                </div>
              )}
            </div>
          ))}
        </div>
      )}

      {/* Pagination */}
      {total > LIMIT && (
        <div className="flex items-center justify-center gap-2">
          <button className="btn-secondary text-xs" disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - LIMIT))}>
            {t('common:actions.previous')}
          </button>
          <span className="text-sm text-muted-foreground">{t('pages:mcpGateway.events.pagination.range', { from: offset + 1, to: Math.min(offset + LIMIT, total), total })}</span>
          <button className="btn-secondary text-xs" disabled={offset + LIMIT >= total} onClick={() => setOffset(offset + LIMIT)}>
            {t('common:actions.next')}
          </button>
        </div>
      )}
    </div>
  )
}
