import { useCallback, useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import {
  Activity,
  Server,
  Shield,
  Database,
  RefreshCw,
  Save,
  Plus,
  Trash2,
  AlertCircle,
} from 'lucide-react'
import { ha, getErrorDetail } from '../services/api'
import { useNotifications } from '../contexts/NotificationContext'
import { Badge, Button, IconButton } from '../components/ui'

// ---------------------------------------------------------------------------
// Types (mirror backend/app/schemas/ha.py)
// ---------------------------------------------------------------------------

interface HaproxyInstance {
  name: string
  url: string
  user?: string | null
  password?: string | null
}

interface KeepalivedConfig {
  vip: string
  virtual_router_id: number
  priority: number
  interface: string
  auth_password?: string | null
  peer_addresses: string[]
  advert_int: number
  preempt: boolean
  track_script?: string | null
}

interface HaConfig {
  ha_enabled: boolean
  swarm_mode?: boolean
  ha_topology: string
  haproxy_ha_replicas: number
  valkey_ha_replicas: number
  coraza_ha_replicas: number
  haproxy_instances: HaproxyInstance[]
  haproxy_peer_port: number
  keepalived: KeepalivedConfig
  valkey_sentinel_enabled: boolean
  valkey_sentinel_hosts: string[]
  valkey_sentinel_service: string
}

interface HaproxyInstanceHealth {
  name: string
  url: string
  available: boolean
  version?: string | null
  status?: string | null
  current_connections?: number | null
  keepalived_state?: string | null
  error?: string | null
}

interface ValkeyNodeHealth {
  role: string
  host: string
  available: boolean
  error?: string | null
}

interface CorazaInstanceHealth {
  name: string
  state: string
  check_status?: string | null
  error?: string | null
}

interface HaHealthSummary {
  ha_enabled: boolean
  swarm_mode?: boolean
  haproxy_instances: HaproxyInstanceHealth[]
  valkey_nodes: ValkeyNodeHealth[]
  coraza_instances: CorazaInstanceHealth[]
  error?: string | null
}

interface HaApplyResponse {
  status: string
  results: Record<string, unknown>
  error?: string | null
}

const AUTO_REFRESH_MS = 5000

// ---------------------------------------------------------------------------
// Status badge helpers
// ---------------------------------------------------------------------------

function StatusBadge({ available }: { available: boolean; error?: string | null }) {
  const { t } = useTranslation(['pages', 'common'])
  if (available) {
    return <Badge variant="success">{t('common:ok')}</Badge>
  }
  return <Badge variant="error">{t('common:error')}</Badge>
}

function KeepalivedStateBadge({ state, swarmMode }: { state?: string | null; swarmMode?: boolean }) {
  const { t } = useTranslation(['pages', 'common'])
  if (!state) {
    if (swarmMode) {
      return <Badge variant="info">{t('pages:systemHa.swarmVip')}</Badge>
    }
    return <span className="text-muted-foreground">—</span>
  }
  const variant = state === 'MASTER' ? 'success' : state === 'BACKUP' ? 'info' : 'error'
  return <Badge variant={variant as 'success' | 'info' | 'error'}>{state}</Badge>
}

// ---------------------------------------------------------------------------
// Main component
// ---------------------------------------------------------------------------

export default function SystemHa() {
  const { t } = useTranslation(['pages', 'common'])
  const { addNotification } = useNotifications()
  const [config, setConfig] = useState<HaConfig | null>(null)
  const [health, setHealth] = useState<HaHealthSummary | null>(null)
  const [loading, setLoading] = useState(true)
  const [autoRefresh, setAutoRefresh] = useState(true)
  const [saving, setSaving] = useState(false)
  const [applying, setApplying] = useState(false)

  // Editable form state
  const [editConfig, setEditConfig] = useState<HaConfig | null>(null)

  const loadConfig = useCallback(async () => {
    try {
      const res = await ha.getConfig()
      setConfig(res.data)
      setEditConfig(res.data)
    } catch (err) {
      addNotification({ type: 'error', title: 'HA', message: getErrorDetail(err, 'Failed to load HA config') })
    }
  }, [addNotification])

  const loadHealth = useCallback(async () => {
    try {
      const res = await ha.getHealth()
      setHealth(res.data)
    } catch (err) {
      setHealth({ ha_enabled: false, haproxy_instances: [], valkey_nodes: [], coraza_instances: [], error: getErrorDetail(err) })
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    loadConfig()
    loadHealth()
  }, [loadConfig, loadHealth])

  // Auto-refresh health
  useEffect(() => {
    if (!autoRefresh) return
    const id = setInterval(loadHealth, AUTO_REFRESH_MS)
    return () => clearInterval(id)
  }, [autoRefresh, loadHealth])

  const handleSave = async () => {
    if (!editConfig) return
    setSaving(true)
    try {
      const res = await ha.updateConfig(editConfig as unknown as Record<string, unknown>)
      setConfig(res.data)
      setEditConfig(res.data)
      addNotification({ type: 'success', title: 'HA', message: t('pages:systemHa.configSaved') })
    } catch (err) {
      addNotification({ type: 'error', title: 'HA', message: getErrorDetail(err, 'Failed to save HA config') })
    } finally {
      setSaving(false)
    }
  }

  const handleApply = async () => {
    setApplying(true)
    try {
      const res = await ha.apply()
      const data: HaApplyResponse = res.data
      if (data.status === 'ok') {
        addNotification({ type: 'success', title: 'HA', message: t('pages:systemHa.applySuccess') })
      } else {
        addNotification({ type: 'error', title: 'HA', message: data.error || t('pages:systemHa.applyFailed') })
      }
    } catch (err) {
      addNotification({ type: 'error', title: 'HA', message: getErrorDetail(err, 'Failed to apply config') })
    } finally {
      setApplying(false)
    }
  }

  // Instance editor helpers
  const addInstance = () => {
    if (!editConfig) return
    setEditConfig({
      ...editConfig,
      haproxy_instances: [...editConfig.haproxy_instances, { name: '', url: '' }],
    })
  }

  const removeInstance = (idx: number) => {
    if (!editConfig) return
    setEditConfig({
      ...editConfig,
      haproxy_instances: editConfig.haproxy_instances.filter((_, i) => i !== idx),
    })
  }

  const updateInstance = (idx: number, field: keyof HaproxyInstance, value: string) => {
    if (!editConfig) return
    const instances = [...editConfig.haproxy_instances]
    instances[idx] = { ...instances[idx], [field]: value }
    setEditConfig({ ...editConfig, haproxy_instances: instances })
  }

  if (loading && !config) {
    return <div className="text-muted-foreground">{t('common:loading')}</div>
  }

  if (config && !config.ha_enabled) {
    return (
      <div className="space-y-4">
        <div className="rounded-lg border border-border p-6 text-center">
          <AlertCircle className="h-8 w-8 mx-auto text-muted-foreground mb-2" />
          <p className="text-muted-foreground">{t('pages:systemHa.disabled')}</p>
          <p className="text-sm text-muted-foreground mt-1">{t('pages:systemHa.disabledHint')}</p>
        </div>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      {/* Header with refresh + apply */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Activity className="h-5 w-5 text-primary" />
          <h2 className="text-lg font-semibold">{t('pages:systemHa.title')}</h2>
        </div>
        <div className="flex items-center gap-2">
          <IconButton
            icon={RefreshCw}
            aria-label={t('common:refresh')}
            onClick={() => { loadConfig(); loadHealth() }}
          />
          <label className="flex items-center gap-1 text-sm text-muted-foreground">
            <input
              type="checkbox"
              checked={autoRefresh}
              onChange={(e) => setAutoRefresh(e.target.checked)}
              className="rounded"
            />
            {t('pages:systemHa.autoRefresh')}
          </label>
          <Button
            variant="primary"
            size="sm"
            onClick={handleApply}
            disabled={applying}
          >
            {applying ? t('common:applying') : t('pages:systemHa.apply')}
          </Button>
        </div>
      </div>

      {/* Health dashboard */}
      {health && (
        <div className="space-y-4">
          {/* HAProxy instances */}
          <div className="rounded-lg border border-border p-4">
            <div className="flex items-center gap-2 mb-3">
              <Server className="h-4 w-4 text-primary" />
              <h3 className="font-semibold">{t('pages:systemHa.haproxyInstances')}</h3>
            </div>
            <div className="space-y-2">
              {health.haproxy_instances.map((inst) => (
                <div key={inst.name} className="flex items-center justify-between rounded border border-border p-3">
                  <div className="space-y-1">
                    <div className="flex items-center gap-2">
                      <span className="font-medium">{inst.name}</span>
                      <StatusBadge available={inst.available} error={inst.error} />
                      <KeepalivedStateBadge state={inst.keepalived_state} swarmMode={health?.swarm_mode} />
                    </div>
                    <div className="text-sm text-muted-foreground">{inst.url}</div>
                    {inst.version && (
                      <div className="text-xs text-muted-foreground">v{inst.version}</div>
                    )}
                    {inst.error && (
                      <div className="text-xs text-danger">{inst.error}</div>
                    )}
                  </div>
                  <div className="text-right text-sm">
                    {inst.current_connections != null && (
                      <div className="text-muted-foreground">
                        {t('pages:systemHa.connections')}: {inst.current_connections}
                      </div>
                    )}
                    {inst.status && (
                      <div className="text-muted-foreground">{inst.status}</div>
                    )}
                  </div>
                </div>
              ))}
              {health.haproxy_instances.length === 0 && (
                <div className="text-sm text-muted-foreground">{t('pages:systemHa.noInstances')}</div>
              )}
            </div>
          </div>

          {/* Valkey nodes */}
          <div className="rounded-lg border border-border p-4">
            <div className="flex items-center gap-2 mb-3">
              <Database className="h-4 w-4 text-primary" />
              <h3 className="font-semibold">{t('pages:systemHa.valkeyNodes')}</h3>
            </div>
            <div className="space-y-2">
              {health.valkey_nodes.map((node, i) => (
                <div key={i} className="flex items-center justify-between rounded border border-border p-3">
                  <div className="flex items-center gap-2">
                    <span className="font-medium">{node.host}</span>
                    <Badge variant={node.role === 'master' ? 'success' : 'info'}>{node.role}</Badge>
                    <StatusBadge available={node.available} error={node.error} />
                  </div>
                  {node.error && <div className="text-xs text-danger">{node.error}</div>}
                </div>
              ))}
              {health.valkey_nodes.length === 0 && (
                <div className="text-sm text-muted-foreground">{t('pages:systemHa.noValkeyNodes')}</div>
              )}
            </div>
          </div>

          {/* Coraza instances */}
          <div className="rounded-lg border border-border p-4">
            <div className="flex items-center gap-2 mb-3">
              <Shield className="h-4 w-4 text-primary" />
              <h3 className="font-semibold">{t('pages:systemHa.corazaInstances')}</h3>
            </div>
            <div className="space-y-2">
              {health.coraza_instances.map((inst, i) => (
                <div key={i} className="flex items-center justify-between rounded border border-border p-3">
                  <div className="flex items-center gap-2">
                    <span className="font-medium">{inst.name}</span>
                    <Badge variant={inst.state === 'UP' ? 'success' : 'error'}>{inst.state}</Badge>
                  </div>
                  {inst.error && <div className="text-xs text-danger">{inst.error}</div>}
                </div>
              ))}
              {health.coraza_instances.length === 0 && (
                <div className="text-sm text-muted-foreground">{t('pages:systemHa.noCorazaInstances')}</div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Configuration editor */}
      {editConfig && (
        <div className="rounded-lg border border-border p-4 space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="font-semibold">{t('pages:systemHa.configEditor')}</h3>
            <Button variant="primary" size="sm" onClick={handleSave} disabled={saving}>
              <Save className="h-4 w-4 mr-1" />
              {saving ? t('common:saving') : t('common:save')}
            </Button>
          </div>

          {/* Topology settings */}
          <div className="grid grid-cols-2 gap-4">
            <label className="space-y-1">
              <span className="text-sm font-medium">{t('pages:systemHa.topology')}</span>
              <select
                className="w-full rounded border border-border bg-background px-2 py-1 text-sm"
                value={editConfig.ha_topology}
                onChange={(e) => setEditConfig({ ...editConfig, ha_topology: e.target.value })}
              >
                <option value="single">single</option>
                <option value="multi-host">multi-host</option>
                <option value="single-host">single-host</option>
              </select>
            </label>
            <label className="space-y-1">
              <span className="text-sm font-medium">{t('pages:systemHa.peerPort')}</span>
              <input
                type="number"
                className="w-full rounded border border-border bg-background px-2 py-1 text-sm"
                value={editConfig.haproxy_peer_port}
                onChange={(e) => setEditConfig({ ...editConfig, haproxy_peer_port: parseInt(e.target.value) || 10000 })}
              />
            </label>
            <label className="space-y-1">
              <span className="text-sm font-medium">{t('pages:systemHa.haproxyReplicas')}</span>
              <input
                type="number"
                className="w-full rounded border border-border bg-background px-2 py-1 text-sm"
                value={editConfig.haproxy_ha_replicas}
                onChange={(e) => setEditConfig({ ...editConfig, haproxy_ha_replicas: parseInt(e.target.value) || 1 })}
              />
            </label>
            <label className="space-y-1">
              <span className="text-sm font-medium">{t('pages:systemHa.valkeyReplicas')}</span>
              <input
                type="number"
                className="w-full rounded border border-border bg-background px-2 py-1 text-sm"
                value={editConfig.valkey_ha_replicas}
                onChange={(e) => setEditConfig({ ...editConfig, valkey_ha_replicas: parseInt(e.target.value) || 1 })}
              />
            </label>
            <label className="space-y-1">
              <span className="text-sm font-medium">{t('pages:systemHa.corazaReplicas')}</span>
              <input
                type="number"
                className="w-full rounded border border-border bg-background px-2 py-1 text-sm"
                value={editConfig.coraza_ha_replicas}
                onChange={(e) => setEditConfig({ ...editConfig, coraza_ha_replicas: parseInt(e.target.value) || 1 })}
              />
            </label>
          </div>

          {/* Sentinel settings */}
          <div className="space-y-2">
            <label className="flex items-center gap-2 text-sm font-medium">
              <input
                type="checkbox"
                checked={editConfig.valkey_sentinel_enabled}
                onChange={(e) => setEditConfig({ ...editConfig, valkey_sentinel_enabled: e.target.checked })}
              />
              {t('pages:systemHa.sentinelEnabled')}
            </label>
            {editConfig.valkey_sentinel_enabled && (
              <div className="grid grid-cols-2 gap-4 pl-6">
                <label className="space-y-1">
                  <span className="text-sm">{t('pages:systemHa.sentinelService')}</span>
                  <input
                    type="text"
                    className="w-full rounded border border-border bg-background px-2 py-1 text-sm"
                    value={editConfig.valkey_sentinel_service}
                    onChange={(e) => setEditConfig({ ...editConfig, valkey_sentinel_service: e.target.value })}
                  />
                </label>
                <label className="space-y-1">
                  <span className="text-sm">{t('pages:systemHa.sentinelHosts')}</span>
                  <input
                    type="text"
                    className="w-full rounded border border-border bg-background px-2 py-1 text-sm"
                    placeholder="sentinel1:26379,sentinel2:26379"
                    value={editConfig.valkey_sentinel_hosts.join(',')}
                    onChange={(e) => setEditConfig({ ...editConfig, valkey_sentinel_hosts: e.target.value.split(',').map(s => s.trim()).filter(Boolean) })}
                  />
                </label>
              </div>
            )}
          </div>

          {/* HAProxy instances editor */}
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-sm font-medium">{t('pages:systemHa.instanceEditor')}</span>
              <IconButton icon={Plus} aria-label={t('common:add')} onClick={addInstance} />
            </div>
            {editConfig.haproxy_instances.map((inst, idx) => (
              <div key={idx} className="flex items-center gap-2">
                <input
                  type="text"
                  className="w-32 rounded border border-border bg-background px-2 py-1 text-sm"
                  placeholder="name"
                  value={inst.name}
                  onChange={(e) => updateInstance(idx, 'name', e.target.value)}
                />
                <input
                  type="text"
                  className="flex-1 rounded border border-border bg-background px-2 py-1 text-sm"
                  placeholder="https://haproxy:5555/v3"
                  value={inst.url}
                  onChange={(e) => updateInstance(idx, 'url', e.target.value)}
                />
                <input
                  type="text"
                  className="w-24 rounded border border-border bg-background px-2 py-1 text-sm"
                  placeholder="user"
                  value={inst.user || ''}
                  onChange={(e) => updateInstance(idx, 'user', e.target.value)}
                />
                <input
                  type="password"
                  className="w-32 rounded border border-border bg-background px-2 py-1 text-sm"
                  placeholder="password"
                  value={inst.password || ''}
                  onChange={(e) => updateInstance(idx, 'password', e.target.value)}
                />
                <IconButton icon={Trash2} aria-label={t('common:delete')} onClick={() => removeInstance(idx)} />
              </div>
            ))}
          </div>

          {/* Keepalived editor */}
          <div className="space-y-3 border-t border-border pt-4">
            <h4 className="font-medium">{t('pages:systemHa.keepalived')}</h4>
            {editConfig.swarm_mode && (
              <div className="rounded border border-border bg-muted/20 p-3 text-sm text-muted-foreground">
                {t('pages:systemHa.swarmModeHint')}
              </div>
            )}
            <div className="grid grid-cols-2 gap-4">
              <label className="space-y-1">
                <span className="text-sm">{t('pages:systemHa.vip')}</span>
                <input
                  type="text"
                  className="w-full rounded border border-border bg-background px-2 py-1 text-sm"
                  placeholder="10.0.0.100"
                  value={editConfig.keepalived.vip}
                  onChange={(e) => setEditConfig({
                    ...editConfig,
                    keepalived: { ...editConfig.keepalived, vip: e.target.value },
                  })}
                />
              </label>
              <label className="space-y-1">
                <span className="text-sm">{t('pages:systemHa.interface')}</span>
                <input
                  type="text"
                  className="w-full rounded border border-border bg-background px-2 py-1 text-sm"
                  placeholder="eth0"
                  value={editConfig.keepalived.interface}
                  onChange={(e) => setEditConfig({
                    ...editConfig,
                    keepalived: { ...editConfig.keepalived, interface: e.target.value },
                  })}
                />
              </label>
              <label className="space-y-1">
                <span className="text-sm">{t('pages:systemHa.vrid')}</span>
                <input
                  type="number"
                  className="w-full rounded border border-border bg-background px-2 py-1 text-sm"
                  value={editConfig.keepalived.virtual_router_id}
                  onChange={(e) => setEditConfig({
                    ...editConfig,
                    keepalived: { ...editConfig.keepalived, virtual_router_id: parseInt(e.target.value) || 51 },
                  })}
                />
              </label>
              <label className="space-y-1">
                <span className="text-sm">{t('pages:systemHa.priority')}</span>
                <input
                  type="number"
                  className="w-full rounded border border-border bg-background px-2 py-1 text-sm"
                  value={editConfig.keepalived.priority}
                  onChange={(e) => setEditConfig({
                    ...editConfig,
                    keepalived: { ...editConfig.keepalived, priority: parseInt(e.target.value) || 100 },
                  })}
                />
              </label>
              <label className="space-y-1">
                <span className="text-sm">{t('pages:systemHa.advertInt')}</span>
                <input
                  type="number"
                  className="w-full rounded border border-border bg-background px-2 py-1 text-sm"
                  value={editConfig.keepalived.advert_int}
                  onChange={(e) => setEditConfig({
                    ...editConfig,
                    keepalived: { ...editConfig.keepalived, advert_int: parseInt(e.target.value) || 1 },
                  })}
                />
              </label>
              <label className="space-y-1">
                <span className="text-sm">{t('pages:systemHa.authPassword')}</span>
                <input
                  type="password"
                  className="w-full rounded border border-border bg-background px-2 py-1 text-sm"
                  value={editConfig.keepalived.auth_password || ''}
                  onChange={(e) => setEditConfig({
                    ...editConfig,
                    keepalived: { ...editConfig.keepalived, auth_password: e.target.value },
                  })}
                />
              </label>
              <label className="space-y-1">
                <span className="text-sm">{t('pages:systemHa.peerAddresses')}</span>
                <input
                  type="text"
                  className="w-full rounded border border-border bg-background px-2 py-1 text-sm"
                  placeholder="10.0.0.2,10.0.0.3"
                  value={editConfig.keepalived.peer_addresses.join(',')}
                  onChange={(e) => setEditConfig({
                    ...editConfig,
                    keepalived: { ...editConfig.keepalived, peer_addresses: e.target.value.split(',').map(s => s.trim()).filter(Boolean) },
                  })}
                />
              </label>
              <label className="space-y-1">
                <span className="text-sm">{t('pages:systemHa.trackScript')}</span>
                <input
                  type="text"
                  className="w-full rounded border border-border bg-background px-2 py-1 text-sm"
                  placeholder="/usr/local/bin/check_haproxy.sh"
                  value={editConfig.keepalived.track_script || ''}
                  onChange={(e) => setEditConfig({
                    ...editConfig,
                    keepalived: { ...editConfig.keepalived, track_script: e.target.value },
                  })}
                />
              </label>
              <label className="flex items-center gap-2 text-sm">
                <input
                  type="checkbox"
                  checked={editConfig.keepalived.preempt}
                  onChange={(e) => setEditConfig({
                    ...editConfig,
                    keepalived: { ...editConfig.keepalived, preempt: e.target.checked },
                  })}
                />
                {t('pages:systemHa.preempt')}
              </label>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
