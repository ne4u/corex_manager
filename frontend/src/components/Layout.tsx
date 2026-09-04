import React, { useEffect, useState } from 'react'
import { NavLink, useNavigate } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import {
  LayoutDashboard, Shield, ShieldCheck, Lock,
  Activity, ArrowLeftRight, Clock, AlignJustify, LogOut,
  Menu, X, ClipboardList, Settings as SettingsIcon, AlertTriangle,
  SlidersHorizontal, ListChecks, ScanEye, Database, Wand2,
  Bot, Search, BrickWallShield, Logs, Network, Gauge
} from 'lucide-react'
import { logout as logoutApi, getConfigStatus, getConfigDiff, applyConfig, revertConfig, getTask, settings as settingsApi, auth } from '../services/api'
import { useNotifications } from '../contexts/NotificationContext'
import Toaster from './Toaster'
import Modal from './Modal'
import ProfileDrawer from './ProfileDrawer'
import { Logo } from './Logo'

interface NavItem {
  to: string
  icon: any
  labelKey: string
  featureFlag?: string
  adminOnly?: boolean
}

const navItems: NavItem[] = [
  // Overview
  { to: '/', icon: LayoutDashboard, labelKey: 'nav:items.dashboard' },
  // System Setup
  { to: '/system', icon: SettingsIcon, labelKey: 'nav:items.system', adminOnly: true },
  // Global Configuration
  { to: '/global-options', icon: SlidersHorizontal, labelKey: 'nav:items.globalOptions' },
  // Core Proxy
  { to: '/load-balancing', icon: Network, labelKey: 'nav:items.loadBalancing' },
  { to: '/certificates', icon: Lock, labelKey: 'nav:items.certificates' },
  // Traffic Management
  { to: '/caching', icon: Database, labelKey: 'nav:items.caching' },
  { to: '/redirects', icon: ArrowLeftRight, labelKey: 'nav:items.redirects' },
  { to: '/headers', icon: AlignJustify, labelKey: 'nav:items.headers' },
  { to: '/response-transforms', icon: Wand2, labelKey: 'nav:items.responseTransforms', featureFlag: 'resp_transform_enabled' },
  { to: '/risk-scoring', icon: Gauge, labelKey: 'nav:items.riskScoring' },
  // Security
  { to: '/security-lists', icon: ListChecks, labelKey: 'nav:items.securityLists' },
  { to: '/security-rules', icon: BrickWallShield, labelKey: 'nav:items.securityRules' },
  { to: '/rate-limits', icon: Clock, labelKey: 'nav:items.rateLimits' },
  { to: '/waf', icon: Shield, labelKey: 'nav:items.wafSignatures' },
  { to: '/captcha', icon: Bot, labelKey: 'nav:items.captcha' },
  { to: '/page-armor', icon: ScanEye, labelKey: 'nav:items.pageArmor' },
  { to: '/api-armor', icon: ShieldCheck, labelKey: 'nav:items.apiArmor', featureFlag: 'api_armor_enabled' },
  // AI Gateway
  { to: '/mcp-gateway', icon: Network, labelKey: 'nav:items.mcpGateway', featureFlag: 'mcp_gateway_enabled' },
  // Observability
  { to: '/logs', icon: Logs, labelKey: 'nav:items.logging' },
  { to: '/metrics', icon: Activity, labelKey: 'nav:items.metrics' },
  { to: '/audit-logs', icon: ClipboardList, labelKey: 'nav:items.auditLogs', adminOnly: true },
]

export default function Layout({ children }: { children: React.ReactNode }) {
  const { t } = useTranslation(['nav', 'common', 'pages'])
  const [open, setOpen] = useState(false)
  const [unapplied, setUnapplied] = useState(false)
  // Tracks which action is currently in flight so each button can show its
  // own progress label. `null` = idle, 'apply' = applying, 'revert' = reverting.
  const [activeAction, setActiveAction] = useState<'apply' | 'revert' | null>(null)
  const applying = activeAction !== null
  const [applyTaskId, setApplyTaskId] = useState<number | null>(null)
  const [applyComment, setApplyComment] = useState('')
  const [showDiff, setShowDiff] = useState(false)
  const [diff, setDiff] = useState('')
  const [diffLoading, setDiffLoading] = useState(false)
  const [featureFlags, setFeatureFlags] = useState<Record<string, boolean>>({})
  const [navSearch, setNavSearch] = useState('')
  const [isAdmin, setIsAdmin] = useState(false)
  const navigate = useNavigate()
  const { addNotification, trackTask } = useNotifications()

  useEffect(() => {
    auth.me()
      .then((r) => setIsAdmin(r.data.role === 'admin' || r.data.is_admin === true))
      .catch(() => setIsAdmin(false))
  }, [])

  useEffect(() => {
    const check = async () => {
      try {
        const r = await getConfigStatus()
        setUnapplied(r.data.unapplied)
      } catch {
        // If the status check fails (e.g. config generation error), assume
        // there are unapplied changes so the revert button stays visible.
        // Otherwise the user gets stuck: bad config → status check fails →
        // revert button disappears → can't fix the problem.
        setUnapplied(true)
      }
    }
    check()
    const iv = setInterval(check, 10000)
    return () => clearInterval(iv)
  }, [])

  useEffect(() => {
    const refreshStatus = async () => {
      try {
        const r = await getConfigStatus()
        setUnapplied(r.data.unapplied)
      } catch {
        setUnapplied(true)
      }
    }
    const listener: EventListener = (evt) => {
      // If the event includes a pre-fetched status result, use it directly
      // instead of making another API call (avoids race with polling).
      const detail = (evt as CustomEvent<{ unapplied?: boolean }>).detail
      if (detail && typeof detail.unapplied === 'boolean') {
        setUnapplied(detail.unapplied)
      } else {
        void refreshStatus()
      }
    }
    window.addEventListener('config-status-changed', listener)
    return () => window.removeEventListener('config-status-changed', listener)
  }, [])

  useEffect(() => {
    // Fetch feature flags that gate nav entry visibility.
    const fetchFlags = () => {
      const flags = ['resp_transform_enabled', 'api_armor_enabled', 'mcp_gateway_enabled']
      Promise.all(
        flags.map((key) =>
          settingsApi.get(key)
            .then((r) => [key, (r.data.value || 'false').toLowerCase() === 'true'] as [string, boolean])
            .catch(() => [key, false] as [string, boolean])
        )
      ).then((entries) => {
        setFeatureFlags(Object.fromEntries(entries))
      })
    }
    fetchFlags()
    // Re-fetch when a feature flag is toggled in Global Options (or elsewhere).
    window.addEventListener('feature-flags-changed', fetchFlags)
    return () => window.removeEventListener('feature-flags-changed', fetchFlags)
  }, [])

  useEffect(() => {
    if (!applyTaskId) return
    const iv = setInterval(async () => {
      try {
        const t = await getTask(applyTaskId)
        if (t.data.status !== 'pending' && t.data.status !== 'running') {
          clearInterval(iv)
          setApplyTaskId(null)
          setActiveAction(null)
          try {
            const s = await getConfigStatus()
            setUnapplied(s.data.unapplied)
          } catch {
            setUnapplied(true)
          }
        }
      } catch {
        clearInterval(iv)
        setApplyTaskId(null)
        setActiveAction(null)
      }
    }, 1500)
    return () => clearInterval(iv)
  }, [applyTaskId])

  const handleReview = async () => {
    setDiffLoading(true)
    try {
      const r = await getConfigDiff()
      setDiff(r.data.diff || t('nav:diff.noChanges'))
      setShowDiff(true)
    } catch (err: any) {
      addNotification({
        type: 'error',
        title: t('pages:dashboard.diffFailed'),
        message: err?.response?.data?.detail || t('pages:dashboard.diffFailedMsg'),
      })
    } finally {
      setDiffLoading(false)
    }
  }

  const handleRevert = async () => {
    if (!window.confirm(t('pages:dashboard.revertConfirm'))) {
      return
    }
    setActiveAction('revert')
    try {
      const r = await revertConfig()
      const id = addNotification({
        type: 'info',
        title: t('pages:dashboard.configRevert'),
        message: r.data.message || t('pages:dashboard.configRevertStarted'),
      })
      trackTask(r.data.task_id, id, {
        title: t('pages:dashboard.configRevert'),
        successMessage: r.data.message || t('pages:dashboard.configRevertedSuccessfully'),
      })
      setApplyTaskId(r.data.task_id)
    } catch (err: any) {
      const detail = err?.response?.data?.detail
      addNotification({
        type: 'error',
        title: t('pages:dashboard.configRevertFailed'),
        message: typeof detail === 'object' ? detail?.message : (detail || t('pages:dashboard.revertFailed')),
        detail: typeof detail === 'object' ? (detail?.error || JSON.stringify(detail, null, 2)) : (err.message),
      })
      setActiveAction(null)
    }
  }


  const handleApply = async () => {
    setActiveAction('apply')
    try {
      const r = await applyConfig(applyComment)
      const id = addNotification({
        type: 'info',
        title: t('pages:dashboard.configApply'),
        message: r.data.message || t('pages:dashboard.configApplyStarted'),
      })
      trackTask(r.data.task_id, id, {
        title: t('pages:dashboard.configApply'),
        successMessage: r.data.message || t('pages:dashboard.configAppliedSuccessfully'),
      })
      setApplyTaskId(r.data.task_id)
    } catch (err: any) {
      const detail = err?.response?.data?.detail
      addNotification({
        type: 'error',
        title: t('pages:dashboard.configApplyFailed'),
        message: typeof detail === 'object' ? detail?.message : (detail || t('pages:dashboard.applyFailed')),
        detail: typeof detail === 'object' ? (detail?.error || JSON.stringify(detail, null, 2)) : (err.message),
      })
      setActiveAction(null)
    }
  }

  const logout = async () => {
    try {
      await logoutApi()
    } catch {
      // ignore network errors and clear session locally
    }
    localStorage.removeItem('token')
    navigate('/login')
    window.location.reload()
  }

  return (
    <div className="flex h-screen bg-slate-950 text-slate-100">
      <aside className={`${open ? 'translate-x-0' : '-translate-x-full rtl:translate-x-full'} fixed inset-y-0 start-0 rtl:end-0 rtl:left-auto z-50 w-64 transform bg-slate-900 border-r rtl:border-r-0 rtl:border-l border-slate-800 transition-transform lg:translate-x-0 rtl:lg:translate-x-0 lg:static flex flex-col`}>
        <div className="relative flex items-center justify-center px-6 py-4 border-b border-slate-800 shrink-0">
          <Logo className="h-[150px] w-auto" />
          <button onClick={() => setOpen(false)} className="absolute end-6 rtl:right-auto rtl:start-6 lg:hidden"><X /></button>
        </div>
        <nav className="p-4 space-y-1 overflow-y-auto flex-1">
          {/* Search input */}
          <div className="relative mb-3">
            <Search className="absolute start-2 rtl:left-auto rtl:end-2 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
            <input
              type="search"
              className="input !ps-8 rtl:!ps-3 rtl:!pe-8 py-1.5 text-sm w-full"
              placeholder={t('nav:searchPlaceholder')}
              value={navSearch}
              onChange={e => setNavSearch(e.target.value)}
            />
          </div>
          {navItems
            .filter(item => !item.adminOnly || isAdmin)
            .filter(item => !item.featureFlag || featureFlags[item.featureFlag])
            .filter(item => !navSearch.trim() || t(item.labelKey).toLowerCase().includes(navSearch.toLowerCase()))
            .map(item => (
              <NavLink
                key={item.to}
                to={item.to}
                end={item.to !== '/' && !item.to.endsWith('/*')}
                onClick={() => setOpen(false)}
                className={({ isActive }) =>
                  `flex items-center gap-3 px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
                    isActive ? 'bg-primary/10 text-primary' : 'text-slate-300 hover:bg-slate-800'
                  }`
                }
              >
                <item.icon className="w-4 h-4" />
                {t(item.labelKey)}
              </NavLink>
            ))}
        </nav>
        <div className="p-4 border-t border-slate-800 shrink-0">
          <button onClick={logout} className="btn-secondary w-full">
            <LogOut className="w-4 h-4 me-2 rtl:me-0 rtl:ms-2" /> {t('nav:logout')}
          </button>
        </div>
      </aside>
      <Toaster />
      <ProfileDrawer />
      <main className="flex-1 overflow-y-auto p-6 pe-12 lg:ms-0">
        <div className="lg:hidden flex items-center gap-3 mb-4">
          <button onClick={() => setOpen(true)} className="p-2 rounded-lg bg-slate-900 border border-slate-800">
            <Menu className="w-5 h-5" />
          </button>
          <span className="font-semibold">{t('nav:brand')}</span>
        </div>
        {unapplied && (
          <div className="mb-4 p-3 rounded-lg bg-amber-500/10 border border-amber-500/20 text-amber-300 flex flex-col sm:flex-row gap-3 sm:items-center sm:justify-between">
            <div className="flex flex-col gap-1 flex-1 min-w-0">
              <div className="flex items-center gap-2">
                <AlertTriangle className="w-4 h-4" />
                <span className="font-medium">{t('nav:unapplied.title')}</span>
              </div>
              <input
                type="text"
                placeholder={t('nav:unapplied.commentPlaceholder')}
                className="input text-xs w-full sm:w-96"
                value={applyComment}
                onChange={(e) => setApplyComment(e.target.value)}
                disabled={applying}
                onKeyDown={(e) => {
                  if (e.key === 'Enter' && !applying) {
                    e.preventDefault()
                    handleApply()
                  }
                }}
              />
            </div>
            <div className="flex items-center gap-3">
              <button onClick={handleReview} disabled={diffLoading} className="text-sm hover:underline">{diffLoading ? t('nav:unapplied.loading') : t('nav:unapplied.review')}</button>
              <button onClick={handleRevert} disabled={applying} className="text-sm text-amber-400 hover:underline">{activeAction === 'revert' ? t('nav:unapplied.reverting') : t('common:actions.revert')}</button>
              <button onClick={handleApply} disabled={applying} className="text-sm btn-primary">{activeAction === 'apply' ? t('nav:unapplied.applying') : t('common:actions.apply')}</button>
            </div>
          </div>
        )}
        {children}
        <Modal open={showDiff} onClose={() => setShowDiff(false)} title={t('nav:diff.title')}>
          <pre className="bg-slate-950 p-4 rounded-lg overflow-auto text-xs text-slate-300 max-h-96 whitespace-pre font-mono">{maskConfig(diff) || t('nav:diff.noChanges')}</pre>
        </Modal>
      </main>
    </div>
  )
}

const SENSITIVE_RE = /\b(auth|user|username|password|passwd|secret|token|credential)\b/i

function maskConfig(config: string): string {
  return config
    .split('\n')
    .map((line) => {
      if (!SENSITIVE_RE.test(line)) return line
      const match = line.match(/^(\s*\S+\s+\S+\s+)/)
      if (!match) return line
      return match[1] + '***'
    })
    .join('\n')
}
