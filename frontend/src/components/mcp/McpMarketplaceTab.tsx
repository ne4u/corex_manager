import { useEffect, useState, useCallback } from 'react'
import { useTranslation } from 'react-i18next'
import { Search, Download, Package, Trash2, ExternalLink, Loader2, Plus } from 'lucide-react'
import { mcp } from '../../services/api'
import Modal from '../Modal'
import { Button, Badge, IconButton } from '../ui'

interface MarketplaceResult {
  name: string
  description: string | null
  version: string | null
  homepage: string | null
  repository_url: string | null
  author: string | null
  license: string | null
  keywords: string[] | null
  downloads: number | null
  score: number | null
}

interface PackageDetails {
  name: string
  version: string | null
  description: string | null
  homepage: string | null
  repository_url: string | null
  author: string | null
  license: string | null
  keywords: string[] | null
  dependencies: Record<string, string> | null
  readme: string | null
  required_env_vars: string[] | null
}

interface Team {
  id: number
  name: string
  slug: string
}

interface McpServer {
  id: number
  name: string
  display_name: string | null
  transport_type: string
  command: string | null
  package_manager: string | null
  source_package_name: string | null
  installed_version: string | null
  health_status: string | null
}

export default function McpMarketplaceTab() {
  const { t } = useTranslation(['pages', 'common'])
  const [query, setQuery] = useState('')
  const [manager, setManager] = useState('npm')
  const [results, setResults] = useState<MarketplaceResult[]>([])
  const [searching, setSearching] = useState(false)
  const [teams, setTeams] = useState<Team[]>([])
  const [servers, setServers] = useState<McpServer[]>([])
  const [details, setDetails] = useState<PackageDetails | null>(null)
  const [detailsLoading, setDetailsLoading] = useState(false)
  const [detailsPkg, setDetailsPkg] = useState<{ manager: string; name: string } | null>(null)
  const [installOpen, setInstallOpen] = useState(false)
  const [installPkg, setInstallPkg] = useState<MarketplaceResult | null>(null)
  const [installForm, setInstallForm] = useState({
    team_id: 0,
    name: '',
    namespace: '',
    display_name: '',
    version: '',
  })
  const [envVars, setEnvVars] = useState<Record<string, string>>({})
  const [newEnvName, setNewEnvName] = useState('')
  const [installing, setInstalling] = useState(false)
  const [error, setError] = useState('')

  const loadTeams = useCallback(async () => {
    try {
      const res = await mcp.teams.list()
      setTeams(res.data)
      if (res.data.length > 0 && installForm.team_id === 0) {
        setInstallForm(f => ({ ...f, team_id: res.data[0].id }))
      }
    } catch {
      // ignore
    }
  }, [installForm.team_id])

  const loadServers = useCallback(async () => {
    try {
      const res = await mcp.servers.list()
      setServers(res.data.filter((s: McpServer) => s.package_manager && s.package_manager !== 'none'))
    } catch {
      // ignore
    }
  }, [])

  useEffect(() => {
    loadTeams()
    loadServers()
  }, [loadTeams, loadServers])

  const handleSearch = async () => {
    if (!query.trim()) return
    setSearching(true)
    setError('')
    try {
      const res = await mcp.marketplace.search(query, manager, 20)
      setResults(res.data)
    } catch (e: any) {
      setError(e?.response?.data?.detail || t('pages:mcpGateway.marketplace.errors.searchFailed'))
      setResults([])
    } finally {
      setSearching(false)
    }
  }

  const handleShowDetails = async (mgr: string, name: string) => {
    setDetailsPkg({ manager: mgr, name })
    setDetailsLoading(true)
    setDetails(null)
    try {
      const res = await mcp.marketplace.packageDetails(mgr, name)
      setDetails(res.data)
    } catch (e: any) {
      setError(e?.response?.data?.detail || t('pages:mcpGateway.marketplace.errors.loadDetailsFailed'))
    } finally {
      setDetailsLoading(false)
    }
  }

  const handleInstallClick = async (pkg: MarketplaceResult) => {
    setInstallPkg(pkg)
    setInstallForm({
      team_id: teams.length > 0 ? teams[0].id : 0,
      name: '',
      namespace: '',
      display_name: pkg.description || pkg.name,
      version: pkg.version || '',
    })
    setEnvVars({})
    setNewEnvName('')
    setInstallOpen(true)

    // Discover env vars and auto-populate
    try {
      const res = await mcp.marketplace.discoverEnvVars(manager, pkg.name)
      const initialEnv: Record<string, string> = {}
      ;(res.data.env_vars || []).forEach((v: string) => { initialEnv[v] = '' })
      setEnvVars(initialEnv)
    } catch {
      // ignore
    }
  }

  const handleInstall = async () => {
    if (!installPkg) return
    setInstalling(true)
    setError('')
    try {
      await mcp.marketplace.install({
        package_manager: manager,
        package_name: installPkg.name,
        version: installForm.version || null,
        team_id: installForm.team_id,
        name: installForm.name || null,
        namespace: installForm.namespace || null,
        display_name: installForm.display_name || null,
        env_vars: Object.entries(envVars).filter(([, v]) => v).length > 0
          ? Object.fromEntries(Object.entries(envVars).filter(([, v]) => v))
          : null,
      })
      setInstallOpen(false)
      await loadServers()
    } catch (e: any) {
      setError(e?.response?.data?.detail || t('pages:mcpGateway.marketplace.errors.installFailed'))
    } finally {
      setInstalling(false)
    }
  }

  const handleUninstall = async (serverId: number) => {
    if (!confirm(t('pages:mcpGateway.marketplace.uninstallConfirm'))) return
    try {
      await mcp.marketplace.uninstall(serverId)
      await loadServers()
    } catch (e: any) {
      setError(e?.response?.data?.detail || t('pages:mcpGateway.marketplace.errors.uninstallFailed'))
    }
  }

  const installedPackageNames = new Set(servers.map(s => s.source_package_name))

  return (
    <div className="space-y-4">
      {error && (
        <div className="rounded-md bg-red-500/10 border border-red-500/30 px-4 py-2 text-sm text-red-400">
          {error}
        </div>
      )}

      {/* Search bar */}
      <div className="flex gap-2 items-center">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-slate-500" />
          <input
            type="text"
            value={query}
            onChange={e => setQuery(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && handleSearch()}
            placeholder={t('pages:mcpGateway.marketplace.searchPlaceholder')}
            className="w-full pl-10 pr-4 py-2 rounded-md bg-slate-800 border border-slate-700 text-sm text-slate-100 placeholder:text-slate-500 focus:outline-none focus:ring-1 focus:ring-primary"
          />
        </div>
        <select
          value={manager}
          onChange={e => setManager(e.target.value)}
          className="px-3 py-2 rounded-md bg-slate-800 border border-slate-700 text-sm text-slate-100"
        >
          <option value="npm">npm</option>
          <option value="pypi">PyPI</option>
          <option value="all">{t('pages:mcpGateway.marketplace.allManagers')}</option>
        </select>
        <Button onClick={handleSearch} disabled={searching || !query.trim()}>
          {searching ? <Loader2 className="h-4 w-4 animate-spin" /> : <Search className="h-4 w-4" />}
          {t('common:actions.search')}
        </Button>
      </div>

      {/* Installed servers */}
      {servers.length > 0 && (
        <div className="rounded-lg border border-slate-700 overflow-hidden">
          <div className="bg-slate-800/50 px-4 py-2 text-sm font-medium text-slate-300">
            {t('pages:mcpGateway.marketplace.installedPackages', { count: servers.length })}
          </div>
          <div className="divide-y divide-slate-700/50">
            {servers.map(s => (
              <div key={s.id} className="flex items-center justify-between px-4 py-3 hover:bg-slate-800/30">
                <div className="flex items-center gap-3">
                  <Package className="h-4 w-4 text-primary" />
                  <div>
                    <div className="text-sm font-medium text-slate-200">{s.display_name || s.name}</div>
                    <div className="text-xs text-slate-500">
                      {s.package_manager} · {s.source_package_name}
                      {s.installed_version && ` · v${s.installed_version}`}
                    </div>
                  </div>
                  <Badge variant={s.health_status === 'healthy' ? 'success' : s.health_status === 'unhealthy' ? 'error' : 'default'}>
                    {s.health_status || t('common:status.unknown')}
                  </Badge>
                </div>
                <IconButton
                  icon={Trash2}
                  onClick={() => handleUninstall(s.id)}
                  variant="danger"
                  aria-label={t('pages:mcpGateway.marketplace.uninstallAria')}
                />
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Search results */}
      {results.length > 0 && (
        <div className="rounded-lg border border-slate-700 overflow-hidden">
          <div className="bg-slate-800/50 px-4 py-2 text-sm font-medium text-slate-300">
            {t('pages:mcpGateway.marketplace.searchResults', { count: results.length })}
          </div>
          <div className="divide-y divide-slate-700/50">
            {results.map(pkg => (
              <div key={`${manager}-${pkg.name}`} className="px-4 py-3 hover:bg-slate-800/30">
                <div className="flex items-start justify-between">
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2">
                      <span className="text-sm font-medium text-slate-200">{pkg.name}</span>
                      {pkg.version && (
                        <span className="text-xs text-slate-500">v{pkg.version}</span>
                      )}
                      {installedPackageNames.has(pkg.name) && (
                        <Badge variant="success">{t('pages:mcpGateway.marketplace.installed')}</Badge>
                      )}
                    </div>
                    {pkg.description && (
                      <p className="text-xs text-slate-400 mt-1 line-clamp-2">{pkg.description}</p>
                    )}
                    <div className="flex items-center gap-3 mt-1 text-xs text-slate-500">
                      {pkg.author && <span>{t('pages:mcpGateway.marketplace.byAuthor', { author: pkg.author })}</span>}
                      {pkg.license && <span>{pkg.license}</span>}
                      {pkg.homepage && (
                        <a href={pkg.homepage} target="_blank" rel="noopener noreferrer" className="flex items-center gap-1 hover:text-primary">
                          <ExternalLink className="h-3 w-3" /> {t('pages:mcpGateway.marketplace.homepage')}
                        </a>
                      )}
                    </div>
                  </div>
                  <div className="flex items-center gap-2 ml-4">
                    <Button
                      size="sm"
                      variant="secondary"
                      onClick={() => handleShowDetails(manager, pkg.name)}
                    >
                      {t('common:actions.details')}
                    </Button>
                    {!installedPackageNames.has(pkg.name) && (
                      <Button
                        size="sm"
                        onClick={() => handleInstallClick(pkg)}
                      >
                        <Download className="h-3.5 w-3.5" /> {t('common:actions.install')}
                      </Button>
                    )}
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Details modal */}
      <Modal
        open={!!detailsPkg}
        onClose={() => { setDetailsPkg(null); setDetails(null) }}
        title={detailsPkg ? t('pages:mcpGateway.marketplace.modal.packageTitle', { name: detailsPkg.name }) : ''}
      >
        {detailsLoading ? (
          <div className="flex items-center justify-center py-8">
            <Loader2 className="h-6 w-6 animate-spin text-primary" />
          </div>
        ) : details ? (
          <div className="space-y-4 max-h-[60vh] overflow-y-auto">
            <div className="grid grid-cols-2 gap-3 text-sm">
              {details.version && <div><span className="text-slate-500">{t('pages:mcpGateway.marketplace.modal.version')}</span> <span className="text-slate-200">{details.version}</span></div>}
              {details.author && <div><span className="text-slate-500">{t('pages:mcpGateway.marketplace.modal.author')}</span> <span className="text-slate-200">{details.author}</span></div>}
              {details.license && <div><span className="text-slate-500">{t('pages:mcpGateway.marketplace.modal.license')}</span> <span className="text-slate-200">{details.license}</span></div>}
              {details.homepage && (
                <div>
                  <span className="text-slate-500">{t('pages:mcpGateway.marketplace.modal.homepage')}</span>{' '}
                  <a href={details.homepage} target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">
                    {details.homepage}
                  </a>
                </div>
              )}
            </div>
            {details.description && (
              <p className="text-sm text-slate-300">{details.description}</p>
            )}
            {details.keywords && details.keywords.length > 0 && (
              <div className="flex flex-wrap gap-1">
                {details.keywords.map(k => (
                  <Badge key={k} variant="default">{k}</Badge>
                ))}
              </div>
            )}
            {details.required_env_vars && details.required_env_vars.length > 0 && (
              <div>
                <div className="text-sm font-medium text-slate-300 mb-1">{t('pages:mcpGateway.marketplace.modal.requiredEnvVars')}</div>
                <div className="flex flex-wrap gap-1">
                  {details.required_env_vars.map(v => (
                    <Badge key={v} variant="warning">{v}</Badge>
                  ))}
                </div>
              </div>
            )}
            {details.readme && (
              <div>
                <div className="text-sm font-medium text-slate-300 mb-1">{t('pages:mcpGateway.marketplace.modal.readme')}</div>
                <pre className="text-xs text-slate-400 bg-slate-800/50 rounded-md p-3 max-h-64 overflow-y-auto whitespace-pre-wrap">{details.readme}</pre>
              </div>
            )}
          </div>
        ) : (
          <div className="text-sm text-slate-500 py-4">{t('pages:mcpGateway.marketplace.modal.noDetails')}</div>
        )}
      </Modal>

      {/* Install modal */}
      <Modal
        open={installOpen}
        onClose={() => setInstallOpen(false)}
        title={installPkg ? t('pages:mcpGateway.marketplace.modal.installTitle', { name: installPkg.name }) : ''}
      >
        <div className="space-y-4">
          {error && (
            <div className="rounded-md bg-red-500/10 border border-red-500/30 px-4 py-2 text-sm text-red-400">
              {error}
            </div>
          )}
          <div>
            <label className="block text-sm text-slate-400 mb-1">{t('pages:mcpGateway.marketplace.modal.team')}</label>
            <select
              value={installForm.team_id}
              onChange={e => setInstallForm(f => ({ ...f, team_id: Number(e.target.value) }))}
              className="w-full px-3 py-2 rounded-md bg-slate-800 border border-slate-700 text-sm text-slate-100"
            >
              {teams.map(t => (
                <option key={t.id} value={t.id}>{t.name}</option>
              ))}
            </select>
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-sm text-slate-400 mb-1">{t('pages:mcpGateway.marketplace.modal.serverNameOptional')}</label>
              <input
                type="text"
                value={installForm.name}
                onChange={e => setInstallForm(f => ({ ...f, name: e.target.value }))}
                placeholder="auto-generated"
                className="w-full px-3 py-2 rounded-md bg-slate-800 border border-slate-700 text-sm text-slate-100"
              />
            </div>
            <div>
              <label className="block text-sm text-slate-400 mb-1">{t('pages:mcpGateway.marketplace.modal.namespaceOptional')}</label>
              <input
                type="text"
                value={installForm.namespace}
                onChange={e => setInstallForm(f => ({ ...f, namespace: e.target.value }))}
                placeholder="auto-generated"
                className="w-full px-3 py-2 rounded-md bg-slate-800 border border-slate-700 text-sm text-slate-100"
              />
            </div>
          </div>
          <div>
            <label className="block text-sm text-slate-400 mb-1">{t('pages:mcpGateway.marketplace.modal.versionOptional')}</label>
            <input
              type="text"
              value={installForm.version}
              onChange={e => setInstallForm(f => ({ ...f, version: e.target.value }))}
              placeholder="latest"
              className="w-full px-3 py-2 rounded-md bg-slate-800 border border-slate-700 text-sm text-slate-100"
            />
          </div>
          <div>
            <label className="block text-sm text-slate-400 mb-1">{t('pages:mcpGateway.marketplace.modal.envVars')}</label>
            <div className="space-y-2">
              {Object.entries(envVars).map(([name, value]) => (
                <div key={name} className="flex items-center gap-2">
                  <span className="text-xs text-slate-500 w-40 truncate" title={name}>{name}</span>
                  <input
                    type="text"
                    value={value}
                    onChange={e => setEnvVars(prev => ({ ...prev, [name]: e.target.value }))}
                    placeholder={t('pages:mcpGateway.marketplace.modal.valuePlaceholder')}
                    className="flex-1 px-2 py-1 rounded bg-slate-800 border border-slate-700 text-xs text-slate-100"
                  />
                  <IconButton
                    icon={Trash2}
                    onClick={() => setEnvVars(prev => { const next = { ...prev }; delete next[name]; return next })}
                    variant="danger"
                    aria-label={t('pages:mcpGateway.marketplace.modal.removeEnvVarAria')}
                  />
                </div>
              ))}
              <div className="flex items-center gap-2">
                <input
                  type="text"
                  value={newEnvName}
                  onChange={e => setNewEnvName(e.target.value)}
                  placeholder="NEW_VAR_NAME"
                  className="w-40 px-2 py-1 rounded bg-slate-800 border border-slate-700 text-xs text-slate-100"
                />
                <Button
                  size="sm"
                  variant="secondary"
                  disabled={!newEnvName.trim() || newEnvName in envVars}
                  onClick={() => {
                    const key = newEnvName.trim().toUpperCase()
                    if (key && !(key in envVars)) {
                      setEnvVars(prev => ({ ...prev, [key]: '' }))
                      setNewEnvName('')
                    }
                  }}
                >
                  <Plus className="h-3 w-3" /> {t('common:actions.add')}
                </Button>
              </div>
            </div>
          </div>
          <div className="flex justify-end gap-2">
            <Button variant="secondary" onClick={() => setInstallOpen(false)}>{t('common:actions.cancel')}</Button>
            <Button onClick={handleInstall} disabled={installing || installForm.team_id === 0}>
              {installing ? <Loader2 className="h-4 w-4 animate-spin" /> : <Download className="h-4 w-4" />}
              {t('common:actions.install')}
            </Button>
          </div>
        </div>
      </Modal>
    </div>
  )
}
