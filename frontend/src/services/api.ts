import axios from 'axios'

const api = axios.create({
  baseURL: '/api/v1',
  headers: {
    'Content-Type': 'application/json',
  },
})

api.interceptors.request.use((config) => {
  const token = localStorage.getItem('token')
  if (token) {
    config.headers.Authorization = `Bearer ${token}`
  }
  return config
})

api.interceptors.response.use(
  (res) => res,
  (err) => {
    // Password expired — backend blocks all non-auth endpoints with 403.
    // Notify the app to show the forced password-change modal instead of
    // redirecting to login.
    if (
      err.response?.status === 403 &&
      err.response?.data?.detail === 'password_change_required'
    ) {
      window.dispatchEvent(new CustomEvent('password-change-required'))
      return Promise.reject(err)
    }
    if (err.response?.status === 401 && !err.config?.url?.startsWith('/auth/')) {
      localStorage.removeItem('token')
      window.location.href = '/login'
    }
    return Promise.reject(err)
  },
)

export default api

export const login = (username: string, password: string, totpCode?: string) =>
  api.post(
    '/auth/token',
    `username=${encodeURIComponent(username)}&password=${encodeURIComponent(password)}` +
      (totpCode ? `&totp_code=${encodeURIComponent(totpCode)}` : ''),
    { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } },
  )

export const logout = () => api.post('/auth/logout')

export const auth = {
  refresh: () => api.post('/auth/refresh'),
  session: () => api.get('/auth/session'),
  me: () => api.get('/auth/me'),
  getPreferences: () => api.get('/auth/preferences'),
  updatePreferences: (data: Record<string, unknown>) => api.put('/auth/preferences', data),
  changePassword: (currentPassword: string, newPassword: string) =>
    api.post('/auth/change-password', { current_password: currentPassword, new_password: newPassword }),
}

export const totp = {
  setup: (alias?: string) => api.post('/auth/totp/setup', { alias }),
  verify: (code: string) => api.post('/auth/totp/verify', { code }),
  disable: (password: string) => api.post('/auth/totp/disable', { password }),
}

export const applyConfig = (comment?: string) => api.post('/config/apply', { comment })
export const revertConfig = () => api.post('/config/revert', { confirm: true })
export const getTask = (id: number) => api.get(`/tasks/${id}`)
export const previewConfig = () => api.get('/config/preview')
export const previewAllConfigs = () => api.get('/config/preview-all')
export const getConfigStatus = () => api.get('/config/status')
export const getConfigDiff = () => api.get('/config/diff')
export const getSystemHealth = () => api.get('/system/health')

export const snapshots = {
  list: () => api.get('/config/snapshots'),
  rollback: (id: number) => api.post(`/config/snapshots/${id}/rollback`),
}
export const getStats = () => api.get('/stats')

export const metrics = {
  get: (from?: string, to?: string, step?: number) =>
    api.get('/haproxy-stats', { params: { from, to, step } }),
}

export const wafMetrics = {
  get: (from?: string, to?: string, step?: number, breakdown?: string) =>
    api.get('/waf/haproxy-stats', { params: { from, to, step, breakdown } }),
}

export const getErrorDetail = (err: unknown, fallback = 'Request failed'): string => {
  if (axios.isAxiosError<{ detail?: string }>(err) && err.response?.data?.detail) {
    return err.response.data.detail
  }
  if (err instanceof Error) return err.message
  return fallback
}

export const certificates = {
  list: (kind?: string) => api.get('/certificates', { params: kind ? { kind } : undefined }),
  create: (data: Record<string, unknown>) => api.post('/certificates', data),
  update: (id: number, data: Record<string, unknown>) => api.put(`/certificates/${id}`, data),
  issue: (id: number) => api.post(`/certificates/${id}/issue`),
  upload: (id: number, data: Record<string, unknown>) => api.post(`/certificates/${id}/upload`, data),
  renew: () => api.post('/certificates/renew'),
  remove: (id: number) => api.delete(`/certificates/${id}`),
  dnsProviders: () => api.get('/certificates/dns-providers'),
  acmeCas: () => api.get('/certificates/acme-cas'),
  issueStatus: () => api.get('/certificates/issue-status'),
  cancelIssue: (taskId: number) => api.post(`/tasks/${taskId}/cancel`),
}

export const ssllabs = {
  hosts: (certId: number) => api.get(`/certificates/${certId}/ssllabs/hosts`),
  listScans: (certId: number) => api.get(`/certificates/${certId}/ssllabs/scans`),
  getScan: (certId: number, scanId: number) => api.get(`/certificates/${certId}/ssllabs/scans/${scanId}`),
  startScan: (certId: number, host: string) => api.post(`/certificates/${certId}/ssllabs/scans`, { host }),
  pollScan: (certId: number, scanId: number) => api.post(`/certificates/${certId}/ssllabs/scans/${scanId}/poll`),
  deleteScan: (certId: number, scanId: number) => api.delete(`/certificates/${certId}/ssllabs/scans/${scanId}`),
}

export const haproxy = {
  globalOptions: () => api.get('/haproxy/global-options'),
  updateGlobalOptions: (data: Record<string, unknown>[]) => api.put('/haproxy/global-options', data),
}

export const settings = {
  list: () => api.get('/settings'),
  get: (key: string) => api.get(`/settings/${key}`),
  update: (key: string, data: Record<string, unknown>) => api.put(`/settings/${key}`, data),
  getMaxmindLicenseKey: () => api.get('/settings/maxmind/license-key'),
  updateMaxmindLicenseKey: (data: Record<string, unknown>) => api.put('/settings/maxmind/license-key', data),
  downloadGeoip: () => api.post('/settings/geoip/download'),
  getGeoipStatus: () => api.get('/settings/geoip/status'),
}

export const geoip = {
  lookupAsn: (ip: string) => api.get(`/geoip/asn?ip=${encodeURIComponent(ip)}`),
}

export const ciphers = {
  list: () => api.get('/ciphers'),
  create: (data: Record<string, unknown>) => api.post('/ciphers', data),
  update: (id: number, data: Record<string, unknown>) => api.put(`/ciphers/${id}`, data),
  remove: (id: number) => api.delete(`/ciphers/${id}`),
}

export const backends = {
  list: () => api.get('/backends'),
  create: (data: Record<string, unknown>) => api.post('/backends', data),
  get: (id: number) => api.get(`/backends/${id}`),
  update: (id: number, data: Record<string, unknown>) => api.put(`/backends/${id}`, data),
  remove: (id: number) => api.delete(`/backends/${id}`),
  addServer: (id: number, data: Record<string, unknown>) => api.post(`/backends/${id}/servers`, data),
  updateServer: (id: number, data: Record<string, unknown>) => api.put(`/servers/${id}`, data),
  removeServer: (id: number) => api.delete(`/servers/${id}`),
}

export const fcgiApps = {
  list: () => api.get('/fcgi-apps'),
  create: (data: Record<string, unknown>) => api.post('/fcgi-apps', data),
  get: (id: number) => api.get(`/fcgi-apps/${id}`),
  update: (id: number, data: Record<string, unknown>) => api.put(`/fcgi-apps/${id}`, data),
  remove: (id: number) => api.delete(`/fcgi-apps/${id}`),
}

export const listeners = {
  list: () => api.get('/listeners'),
  create: (data: Record<string, unknown>) => api.post('/listeners', data),
  get: (id: number) => api.get(`/listeners/${id}`),
  update: (id: number, data: Record<string, unknown>) => api.put(`/listeners/${id}`, data),
  remove: (id: number) => api.delete(`/listeners/${id}`),
}

export const backendRules = {
  list: (listener_id?: number) => api.get('/backend-rules', { params: { listener_id } }),
  create: (data: Record<string, unknown>) => api.post('/backend-rules', data),
  get: (id: number) => api.get(`/backend-rules/${id}`),
  update: (id: number, data: Record<string, unknown>) => api.put(`/backend-rules/${id}`, data),
  remove: (id: number) => api.delete(`/backend-rules/${id}`),
}

export const securityLists = {
  network: {
    list: () => api.get('/security-lists/network'),
    create: (data: Record<string, unknown>) => api.post('/security-lists/network', data),
    update: (id: number, data: Record<string, unknown>) => api.put(`/security-lists/network/${id}`, data),
    remove: (id: number, force = false) => api.delete(`/security-lists/network/${id}`, { params: { force } }),
    entries: {
      list: (lid: number) => api.get(`/security-lists/network/${lid}/entries`),
      create: (lid: number, data: Record<string, unknown>) => api.post(`/security-lists/network/${lid}/entries`, data),
      update: (lid: number, eid: number, data: Record<string, unknown>) => api.put(`/security-lists/network/${lid}/entries/${eid}`, data),
      remove: (lid: number, eid: number) => api.delete(`/security-lists/network/${lid}/entries/${eid}`),
    },
  },
  asn: {
    list: () => api.get('/security-lists/asn'),
    create: (data: Record<string, unknown>) => api.post('/security-lists/asn', data),
    update: (id: number, data: Record<string, unknown>) => api.put(`/security-lists/asn/${id}`, data),
    remove: (id: number, force = false) => api.delete(`/security-lists/asn/${id}`, { params: { force } }),
    entries: {
      list: (lid: number) => api.get(`/security-lists/asn/${lid}/entries`),
      create: (lid: number, data: Record<string, unknown>) => api.post(`/security-lists/asn/${lid}/entries`, data),
      update: (lid: number, eid: number, data: Record<string, unknown>) => api.put(`/security-lists/asn/${lid}/entries/${eid}`, data),
      remove: (lid: number, eid: number) => api.delete(`/security-lists/asn/${lid}/entries/${eid}`),
    },
  },
  geo: {
    list: () => api.get('/security-lists/geo'),
    countries: () => api.get('/security-lists/geo/countries'),
    create: (data: Record<string, unknown>) => api.post('/security-lists/geo', data),
    update: (id: number, data: Record<string, unknown>) => api.put(`/security-lists/geo/${id}`, data),
    remove: (id: number) => api.delete(`/security-lists/geo/${id}`),
    entries: {
      list: (lid: number) => api.get(`/security-lists/geo/${lid}/entries`),
      create: (lid: number, data: Record<string, unknown>) => api.post(`/security-lists/geo/${lid}/entries`, data),
      update: (lid: number, eid: number, data: Record<string, unknown>) => api.put(`/security-lists/geo/${lid}/entries/${eid}`, data),
      remove: (lid: number, eid: number) => api.delete(`/security-lists/geo/${lid}/entries/${eid}`),
    },
  },
  ja4: {
    list: () => api.get('/security-lists/ja4'),
    create: (data: Record<string, unknown>) => api.post('/security-lists/ja4', data),
    update: (id: number, data: Record<string, unknown>) => api.put(`/security-lists/ja4/${id}`, data),
    remove: (id: number, force = false) => api.delete(`/security-lists/ja4/${id}`, { params: { force } }),
    entries: {
      list: (lid: number) => api.get(`/security-lists/ja4/${lid}/entries`),
      create: (lid: number, data: Record<string, unknown>) => api.post(`/security-lists/ja4/${lid}/entries`, data),
      update: (lid: number, eid: number, data: Record<string, unknown>) => api.put(`/security-lists/ja4/${lid}/entries/${eid}`, data),
      remove: (lid: number, eid: number) => api.delete(`/security-lists/ja4/${lid}/entries/${eid}`),
    },
  },
  pattern: {
    list: () => api.get('/security-lists/pattern'),
    create: (data: Record<string, unknown>) => api.post('/security-lists/pattern', data),
    update: (id: number, data: Record<string, unknown>) => api.put(`/security-lists/pattern/${id}`, data),
    remove: (id: number) => api.delete(`/security-lists/pattern/${id}`),
    entries: {
      list: (lid: number) => api.get(`/security-lists/pattern/${lid}/entries`),
      create: (lid: number, data: Record<string, unknown>) => api.post(`/security-lists/pattern/${lid}/entries`, data),
      update: (lid: number, eid: number, data: Record<string, unknown>) => api.put(`/security-lists/pattern/${lid}/entries/${eid}`, data),
      remove: (lid: number, eid: number) => api.delete(`/security-lists/pattern/${lid}/entries/${eid}`),
    },
  },
  feeds: {
    list: () => api.get('/security-lists/feeds'),
    create: (data: Record<string, unknown>) => api.post('/security-lists/feeds', data),
    update: (id: number, data: Record<string, unknown>) => api.put(`/security-lists/feeds/${id}`, data),
    remove: (id: number, deleteList = false) => api.delete(`/security-lists/feeds/${id}`, { params: { delete_list: deleteList } }),
    refresh: (id: number) => api.post(`/security-lists/feeds/${id}/refresh`),
  },
}

export const securityRules = {
  list: () => api.get('/security-rules'),
  create: (data: Record<string, unknown>) => api.post('/security-rules', data),
  update: (id: number, data: Record<string, unknown>) => api.put(`/security-rules/${id}`, data),
  remove: (id: number) => api.delete(`/security-rules/${id}`),
  reorder: (orderedIds: number[]) => api.put('/security-rules/reorder', { ordered_ids: orderedIds }),
  validate: (expression: string) => api.post('/security-rules/validate', { expression }),
}

export const riskRules = {
  list: (rulesetId?: number) => api.get('/risk-rules', { params: rulesetId ? { ruleset_id: rulesetId } : {} }),
  create: (data: Record<string, unknown>) => api.post('/risk-rules', data),
  update: (id: number, data: Record<string, unknown>) => api.put(`/risk-rules/${id}`, data),
  remove: (id: number) => api.delete(`/risk-rules/${id}`),
  reorder: (orderedIds: number[]) => api.put('/risk-rules/reorder', { ordered_ids: orderedIds }),
  validate: (expression: string) => api.post('/risk-rules/validate', { expression }),
  seedBaseline: () => api.post('/risk-rules/seed-baseline'),
}

export const riskRulesets = {
  list: () => api.get('/risk-rulesets'),
  create: (data: Record<string, unknown>) => api.post('/risk-rulesets', data),
  update: (id: number, data: Record<string, unknown>) => api.put(`/risk-rulesets/${id}`, data),
  remove: (id: number, force?: boolean) => api.delete(`/risk-rulesets/${id}`, { params: force ? { force: true } : {} }),
}

export const wafRules = {
  list: () => api.get('/waf-rules'),
  create: (data: Record<string, unknown>) => api.post('/waf-rules', data),
  update: (id: number, data: Record<string, unknown>) => api.put(`/waf-rules/${id}`, data),
  remove: (id: number) => api.delete(`/waf-rules/${id}`),
  export: () => api.get('/waf/rules/export'),
  import: (data: Record<string, unknown>) => api.post('/waf/rules/import', data),
  refreshRuleSet: (id: number) => api.post(`/waf/rules/${id}/refresh-rule-set`),
}

export const wafExceptions = {
  list: () => api.get('/waf-exceptions'),
  create: (data: Record<string, unknown>) => api.post('/waf-exceptions', data),
  update: (id: number, data: Record<string, unknown>) => api.put(`/waf-exceptions/${id}`, data),
  remove: (id: number) => api.delete(`/waf-exceptions/${id}`),
}

export const waf = {
  logs: (limit = 100) => api.get(`/waf/logs?limit=${limit}`),
  health: () => api.get('/waf/health'),
  siem: {
    list: () => api.get('/waf/siem-integrations'),
    create: (data: Record<string, unknown>) => api.post('/waf/siem-integrations', data),
    update: (id: number, data: Record<string, unknown>) => api.put(`/waf/siem-integrations/${id}`, data),
    remove: (id: number) => api.delete(`/waf/siem-integrations/${id}`),
  },
  ruleVersions: {
    list: (waf_rule_id?: number) => api.get('/waf/rule-versions', { params: { waf_rule_id } }),
    snapshot: (id: number, version: string) => api.post(`/waf/rules/${id}/snapshot?version=${encodeURIComponent(version)}`),
    restore: (id: number, versionId: number) => api.post(`/waf/rules/${id}/restore/${versionId}`),
    remove: (versionId: number) => api.delete(`/waf/rule-versions/${versionId}`),
    getMax: () => api.get('/waf/rule-versions/max'),
    setMax: (value: number) => api.put('/waf/rule-versions/max', { value: String(value) }),
  },
  crs: {
    status: () => api.get('/waf/crs/status'),
    download: () => api.post('/waf/crs/download'),
    snapshots: () => api.get('/waf/crs/snapshots'),
    rollback: (snapshotId: number) => api.post(`/waf/crs/rollback/${snapshotId}`),
    deleteSnapshot: (snapshotId: number) => api.delete(`/waf/crs/snapshots/${snapshotId}`),
    setPinnedVersion: (version: string) => api.put('/waf/crs/pinned-version', { value: version }),
  },
}

export const rateLimits = {
  list: () => api.get('/rate-limits'),
  create: (data: Record<string, unknown>) => api.post('/rate-limits', data),
  update: (id: number, data: Record<string, unknown>) => api.put(`/rate-limits/${id}`, data),
  remove: (id: number) => api.delete(`/rate-limits/${id}`),
}

export const redirects = {
  list: () => api.get('/redirects'),
  create: (data: Record<string, unknown>) => api.post('/redirects', data),
  update: (id: number, data: Record<string, unknown>) => api.put(`/redirects/${id}`, data),
  remove: (id: number) => api.delete(`/redirects/${id}`),
}

export const rewrites = {
  list: () => api.get('/rewrites'),
  create: (data: Record<string, unknown>) => api.post('/rewrites', data),
  update: (id: number, data: Record<string, unknown>) => api.put(`/rewrites/${id}`, data),
  remove: (id: number) => api.delete(`/rewrites/${id}`),
}

export const responseTransforms = {
  list: () => api.get('/resp-transforms'),
  create: (data: Record<string, unknown>) => api.post('/resp-transforms', data),
  update: (id: number, data: Record<string, unknown>) => api.put(`/resp-transforms/${id}`, data),
  remove: (id: number) => api.delete(`/resp-transforms/${id}`),
  reorder: (orderedIds: number[]) => api.put('/resp-transforms/reorder', { ordered_ids: orderedIds }),
  validate: (data: Record<string, unknown>) => api.post('/resp-transforms/validate', data),
}

export const responseHeaders = {
  list: () => api.get('/response-headers'),
  create: (data: Record<string, unknown>) => api.post('/response-headers', data),
  update: (id: number, data: Record<string, unknown>) => api.put(`/response-headers/${id}`, data),
  remove: (id: number) => api.delete(`/response-headers/${id}`),
}

export const requestHeaders = {
  list: () => api.get('/request-headers'),
  create: (data: Record<string, unknown>) => api.post('/request-headers', data),
  update: (id: number, data: Record<string, unknown>) => api.put(`/request-headers/${id}`, data),
  remove: (id: number) => api.delete(`/request-headers/${id}`),
}

export const logDestinations = {
  list: () => api.get('/log-destinations'),
  create: (data: Record<string, unknown>) => api.post('/log-destinations', data),
  update: (id: number, data: Record<string, unknown>) => api.put(`/log-destinations/${id}`, data),
  remove: (id: number) => api.delete(`/log-destinations/${id}`),
}

export const loggedFields = {
  list: () => api.get('/logged-fields'),
  create: (data: Record<string, unknown>) => api.post('/logged-fields', data),
  update: (id: number, data: Record<string, unknown>) => api.put(`/logged-fields/${id}`, data),
  remove: (id: number) => api.delete(`/logged-fields/${id}`),
}

export const logs = {
  recent: (limit = 100) => api.get(`/logs/recent?limit=${limit}`),
  health: () => api.get('/logs/health'),
}

export const errorPages = {
  list: () => api.get('/error-pages'),
  create: (data: Record<string, unknown>) => api.post('/error-pages', data),
  update: (id: number, data: Record<string, unknown>) => api.put(`/error-pages/${id}`, data),
  remove: (id: number) => api.delete(`/error-pages/${id}`),
  preview: (id: number) => api.get(`/error-pages/${id}/preview`),
}

export const users = {
  list: () => api.get('/users'),
  create: (data: Record<string, unknown>) => api.post('/users', data),
  update: (id: number, data: Record<string, unknown>) => api.put(`/users/${id}`, data),
  remove: (id: number) => api.delete(`/users/${id}`),
}

export interface AuditEventFilters {
  username?: string
  action?: string
  resource?: string
  ip?: string
  hasSnapshot?: boolean
}

export interface AuditEventFilterOptions {
  usernames: string[]
  actions: string[]
  resource_types: string[]
  ip_addresses: string[]
}

export interface AuditEvent {
  id: number
  created_at: string
  user_id: number | null
  username: string | null
  action: string
  method: string
  path: string
  resource_type: string | null
  resource_id: string | null
  status_code: number | null
  ip_address: string | null
  payload: Record<string, unknown> | null
  snapshot_id: number | null
  config_change: boolean
  snapshot_comment: string | null
  snapshot_created_at: string | null
}

export const auditEvents = {
  list: (limit = 100, filters?: AuditEventFilters, fromDate?: string, toDate?: string) =>
    api.get('/audit-events', {
      params: {
        limit,
        username: filters?.username,
        action: filters?.action,
        resource: filters?.resource,
        ip_address: filters?.ip,
        has_snapshot: filters?.hasSnapshot,
        from: fromDate,
        to: toDate,
      },
    }),
  filterOptions: () => api.get('/audit-events/filters'),
  export: (fromDate?: string, toDate?: string, filters?: AuditEventFilters) =>
    api.get('/audit-events/export', {
      params: {
        from: fromDate,
        to: toDate,
        username: filters?.username,
        action: filters?.action,
        resource: filters?.resource,
        ip_address: filters?.ip,
        has_snapshot: filters?.hasSnapshot,
      },
      responseType: 'blob',
    }),
}

export const systemBackup = {
  export: (includeSecrets: boolean, includeMetrics: boolean, password?: string) =>
    api.get('/system/export', {
      params: {
        include_secrets: includeSecrets,
        include_metrics: includeMetrics,
        password: password || undefined,
      },
      responseType: 'blob',
    }),
  restore: (file: File, password?: string) => {
    const formData = new FormData()
    formData.append('file', file)
    if (password) formData.append('password', password)
    return api.post('/system/restore', formData, {
      headers: { 'Content-Type': 'multipart/form-data' },
    })
  },
}

export const pageProtect = {
  settings: {
    get: () => api.get('/page-protect/settings'),
    update: (data: Record<string, unknown>) => api.put('/page-protect/settings', data),
  },
  policies: {
    list: () => api.get('/page-protect/policies'),
    create: (data: Record<string, unknown>) => api.post('/page-protect/policies', data),
    update: (id: number, data: Record<string, unknown>) => api.put(`/page-protect/policies/${id}`, data),
    remove: (id: number) => api.delete(`/page-protect/policies/${id}`),
  },
  reports: {
    list: (params?: Record<string, unknown>) => api.get('/page-protect/reports', { params }),
    export: () => api.get('/page-protect/reports/export', { responseType: 'blob' }),
    clear: (params?: Record<string, unknown>) => api.delete('/page-protect/reports', { params }),
  },
  scripts: {
    list: (params?: Record<string, unknown>) => api.get('/page-protect/scripts', { params }),
    create: (data: Record<string, unknown>) => api.post('/page-protect/scripts', data),
    update: (id: number, data: Record<string, unknown>) => api.put(`/page-protect/scripts/${id}`, data),
    remove: (id: number) => api.delete(`/page-protect/scripts/${id}`),
    check: (id: number) => api.post(`/page-protect/scripts/${id}/check`),
    resetHash: (id: number, recheck: boolean = true) => api.post(`/page-protect/scripts/${id}/reset-hash`, null, { params: { recheck } }),
    checkAll: () => api.post('/page-protect/scripts/check-all'),
  },
  stats: () => api.get('/page-protect/stats'),
  sample: () => api.post('/page-protect/sample'),
  baseline: {
    get: () => api.get('/page-protect/baseline'),
    start: (note: string) => api.post('/page-protect/baseline/start', { note }),
    stop: () => api.post('/page-protect/baseline/stop'),
    clear: () => api.delete('/page-protect/baseline'),
  },
  recommend: (backendIds?: number[]) =>
    api.get('/page-protect/recommend', { params: backendIds?.length ? { backend_ids: backendIds.join(',') } : {} }),
}

export const cache = {
  status: () => api.get('/cache/status'),
  listConfigs: () => api.get('/cache/configs'),
  createConfig: (data: Record<string, unknown>) => api.post('/cache/configs', data),
  getConfig: (backendId: number) => api.get(`/cache/configs/${backendId}`),
  updateConfig: (backendId: number, data: Record<string, unknown>) => api.put(`/cache/configs/${backendId}`, data),
  removeConfig: (backendId: number) => api.delete(`/cache/configs/${backendId}`),
  clearBackend: (backendId: number) => api.post(`/cache/${backendId}/clear`),
  clearAll: () => api.post('/cache/clear-all'),
  metrics: (params?: Record<string, unknown>) => api.get('/cache/metrics', { params }),
  listRules: (backendId: number) => api.get(`/cache/configs/${backendId}/rules`),
  createRule: (backendId: number, data: Record<string, unknown>) => api.post(`/cache/configs/${backendId}/rules`, data),
  updateRule: (backendId: number, ruleId: number, data: Record<string, unknown>) => api.put(`/cache/configs/${backendId}/rules/${ruleId}`, data),
  removeRule: (backendId: number, ruleId: number) => api.delete(`/cache/configs/${backendId}/rules/${ruleId}`),
  reorderRules: (backendId: number, ruleIds: number[]) => api.post(`/cache/configs/${backendId}/rules/reorder`, { rule_ids: ruleIds }),
}

export const captcha = {
  settings: {
    get: () => api.get('/captcha/settings'),
    update: (data: Record<string, unknown>) => api.put('/captcha/settings', data),
  },
  stats: {
    list: (params?: Record<string, unknown>) => api.get('/captcha/stats', { params }),
    timeseries: (ruleType: string, ruleId: number, hours?: number) =>
      api.get(`/captcha/stats/${ruleType}/${ruleId}`, { params: hours ? { hours } : {} }),
    events: (params?: Record<string, unknown>) => api.get('/captcha/events', { params }),
  },
  keys: {
    list: () => api.get('/captcha/keys'),
    create: (data: Record<string, unknown>) => api.post('/captcha/keys', data),
    get: (siteKey: string, chartDuration?: string) =>
      api.get(`/captcha/keys/${siteKey}`, { params: chartDuration ? { chart_duration: chartDuration } : {} }),
    updateConfig: (siteKey: string, data: Record<string, unknown>) => api.put(`/captcha/keys/${siteKey}/config`, data),
    rotateSecret: (siteKey: string) => api.post(`/captcha/keys/${siteKey}/rotate-secret`),
    delete: (siteKey: string) => api.delete(`/captcha/keys/${siteKey}`),
  },
}

export const apiArmor = {
  settings: {
    get: () => api.get('/api-armor/settings'),
    update: (data: Record<string, unknown>) => api.put('/api-armor/settings', data),
  },
  presets: {
    list: () => api.get('/api-armor/presets'),
    apply: (data?: Record<string, unknown>) => api.post('/api-armor/presets/apply', data || {}),
  },
  specs: {
    list: () => api.get('/api-armor/specs'),
    create: (data: Record<string, unknown>) => api.post('/api-armor/specs', data),
    delete: (id: number) => api.delete(`/api-armor/specs/${id}`),
    schemas: (id: number) => api.get(`/api-armor/specs/${id}/schemas`),
  },
  schemas: {
    list: (params?: Record<string, unknown>) => api.get('/api-armor/schemas', { params }),
    update: (id: number, data: Record<string, unknown>) => api.put(`/api-armor/schemas/${id}`, data),
  },
  authPolicies: {
    list: () => api.get('/api-armor/auth-policies'),
    create: (data: Record<string, unknown>) => api.post('/api-armor/auth-policies', data),
    update: (id: number, data: Record<string, unknown>) => api.put(`/api-armor/auth-policies/${id}`, data),
    delete: (id: number) => api.delete(`/api-armor/auth-policies/${id}`),
  },
  apiKeyLists: {
    list: () => api.get('/api-armor/api-key-lists'),
    create: (data: Record<string, unknown>) => api.post('/api-armor/api-key-lists', data),
    delete: (id: number) => api.delete(`/api-armor/api-key-lists/${id}`),
  },
  profiles: {
    list: (params?: Record<string, unknown>) => api.get('/api-armor/profiles', { params }),
    finalize: (id: number, minSamples?: number) =>
      api.post(`/api-armor/profiles/${id}/finalize`, {}, { params: minSamples ? { min_samples: minSamples } : {} }),
    delete: (id: number) => api.delete(`/api-armor/profiles/${id}`),
  },
  anomalies: {
    list: (params?: Record<string, unknown>) => api.get('/api-armor/anomalies', { params }),
    clear: (params?: Record<string, unknown>) => api.delete('/api-armor/anomalies', { params }),
  },
}

export const mcp = {
  teams: {
    list: () => api.get('/mcp/teams'),
    create: (data: Record<string, unknown>) => api.post('/mcp/teams', data),
    update: (id: number, data: Record<string, unknown>) => api.put(`/mcp/teams/${id}`, data),
    delete: (id: number) => api.delete(`/mcp/teams/${id}`),
    listMembers: (teamId: number) =>
      api.get(`/mcp/teams/${teamId}/members`),
    addMember: (teamId: number, userId: number) =>
      api.post(`/mcp/teams/${teamId}/members`, { user_id: userId, team_id: teamId }),
    removeMember: (teamId: number, userId: number) =>
      api.delete(`/mcp/teams/${teamId}/members/${userId}`),
  },
  servers: {
    list: () => api.get('/mcp/servers'),
    create: (data: Record<string, unknown>) => api.post('/mcp/servers', data),
    update: (id: number, data: Record<string, unknown>) => api.put(`/mcp/servers/${id}`, data),
    delete: (id: number) => api.delete(`/mcp/servers/${id}`),
    replicas: {
      list: (serverId: number) => api.get(`/mcp/servers/${serverId}/replicas`),
      create: (serverId: number, data: Record<string, unknown>) =>
        api.post(`/mcp/servers/${serverId}/replicas`, data),
      update: (serverId: number, replicaId: number, data: Record<string, unknown>) =>
        api.put(`/mcp/servers/${serverId}/replicas/${replicaId}`, data),
      delete: (serverId: number, replicaId: number) =>
        api.delete(`/mcp/servers/${serverId}/replicas/${replicaId}`),
    },
  },
  identities: {
    list: () => api.get('/mcp/identities'),
    create: (data: Record<string, unknown>) => api.post('/mcp/identities', data),
    update: (id: number, data: Record<string, unknown>) => api.put(`/mcp/identities/${id}`, data),
    delete: (id: number) => api.delete(`/mcp/identities/${id}`),
    issuePat: (id: number) => api.post(`/mcp/identities/${id}/tokens`),
  },
  policies: {
    list: () => api.get('/mcp/policies'),
    create: (data: Record<string, unknown>) => api.post('/mcp/policies', data),
    update: (id: number, data: Record<string, unknown>) => api.put(`/mcp/policies/${id}`, data),
    delete: (id: number) => api.delete(`/mcp/policies/${id}`),
  },
  dlpRules: {
    list: () => api.get('/mcp/dlp-rules'),
    create: (data: Record<string, unknown>) => api.post('/mcp/dlp-rules', data),
    update: (id: number, data: Record<string, unknown>) => api.put(`/mcp/dlp-rules/${id}`, data),
    delete: (id: number) => api.delete(`/mcp/dlp-rules/${id}`),
  },
  guardrails: {
    list: () => api.get('/mcp/guardrails'),
    create: (data: Record<string, unknown>) => api.post('/mcp/guardrails', data),
    update: (id: number, data: Record<string, unknown>) => api.put(`/mcp/guardrails/${id}`, data),
    delete: (id: number) => api.delete(`/mcp/guardrails/${id}`),
  },
  skills: {
    list: () => api.get('/mcp/skills'),
    create: (data: Record<string, unknown>) => api.post('/mcp/skills', data),
    update: (id: number, data: Record<string, unknown>) => api.put(`/mcp/skills/${id}`, data),
    delete: (id: number) => api.delete(`/mcp/skills/${id}`),
    importFromUrl: (data: Record<string, unknown>) => api.post('/mcp/skills/import', data),
    versions: {
      list: (skillId: number) => api.get(`/mcp/skills/${skillId}/versions`),
      create: (skillId: number, data: Record<string, unknown>) =>
        api.post(`/mcp/skills/${skillId}/versions`, data),
    },
    publish: (id: number) => api.post(`/mcp/skills/${id}/publish`),
    rollback: (id: number, version: number) =>
      api.post(`/mcp/skills/${id}/rollback`, null, { params: { version } }),
    export: (id: number) => api.post(`/mcp/skills/${id}/export`, null, { responseType: 'blob' }),
  },
  metrics: {
    get: (params: { from?: string; to?: string; step?: number; breakdown?: string }) =>
      api.get('/mcp/metrics', { params }),
  },
  marketplace: {
    search: (q: string, manager: string = 'npm', limit: number = 20) =>
      api.get('/mcp/marketplace/search', { params: { q, manager, limit } }),
    packageDetails: (manager: string, name: string) =>
      api.get('/mcp/marketplace/packages', { params: { manager, name } }),
    install: (data: Record<string, unknown>) => api.post('/mcp/marketplace/install', data),
    uninstall: (serverId: number) => api.post('/mcp/marketplace/uninstall', { server_id: serverId }),
    discoverEnvVars: (packageManager: string, packageName: string) =>
      api.post('/mcp/marketplace/discover-env-vars', { package_manager: packageManager, package_name: packageName }),
  },
  installations: {
    list: (serverId: number) => api.get(`/mcp/installations/${serverId}`),
  },
  oauth: {
    discover: (serverId: number, url: string, transportType: string = 'streamable_http') =>
      api.post(`/mcp/servers/${serverId}/oauth/discover`, { url, transport_type: transportType }),
    configure: (serverId: number, data: Record<string, unknown>) =>
      api.post(`/mcp/servers/${serverId}/oauth/configure`, data),
    status: (serverId: number) => api.get(`/mcp/servers/${serverId}/oauth/status`),
    authorize: (serverId: number) => api.post(`/mcp/servers/${serverId}/oauth/authorize`),
    disable: (serverId: number) => api.post(`/mcp/servers/${serverId}/oauth/disable`),
  },
  events: {
    list: (params: { from?: string; to?: string; action?: string; method?: string; identity_id?: number; server_id?: number; limit?: number; offset?: number }) =>
      api.get('/mcp/events', { params }),
  },
  sessions: {
    list: (params?: { identity_id?: number }) =>
      api.get('/mcp/sessions', { params }),
    revoke: (sessionId: string) =>
      api.delete(`/mcp/sessions/${sessionId}`),
    revokeIdentity: (identityId: number) =>
      api.post(`/mcp/identities/${identityId}/revoke`),
  },
  config: {
    status: () => api.get('/mcp/config/status'),
    regenerate: () => api.post('/mcp/config/regenerate'),
  },
  alerts: {
    getConfig: () => api.get('/mcp/alerts/config'),
    updateConfig: (data: Record<string, unknown>) => api.put('/mcp/alerts/config', data),
    history: (params?: { limit?: number }) => api.get('/mcp/alerts/history', { params }),
  },
  catalog: {
    get: (serverId: number) => api.get(`/mcp/servers/${serverId}/catalog`),
  },
}

export const stickTables = {
  list: () => api.get('/haproxy/tables'),
  get: (name: string, params?: { limit?: number; offset?: number; search?: string }) =>
    api.get(`/haproxy/tables/${encodeURIComponent(name)}`, { params }),
  clearAll: (name: string) => api.delete(`/haproxy/tables/${encodeURIComponent(name)}`),
  clearEntry: (name: string, key: string) =>
    api.delete(`/haproxy/tables/${encodeURIComponent(name)}/entries/${encodeURIComponent(key)}`),
}

export const valkey = {
  info: () => api.get('/valkey/info'),
  namespaces: () => api.get('/valkey/namespaces'),
  namespace: (prefix: string, params?: { limit?: number; offset?: number; search?: string }) =>
    api.get(`/valkey/namespaces/${encodeURIComponent(prefix)}`, { params }),
  // `{key:path}` route — encode `/` so it survives the path segment.
  deleteKey: (key: string) => api.delete(`/valkey/keys/${encodeURIComponent(key)}`),
}
