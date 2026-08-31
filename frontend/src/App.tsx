import { useState, useEffect } from 'react'
import { Routes, Route, Navigate } from 'react-router-dom'
import { NotificationProvider } from './contexts/NotificationContext'
import Layout from './components/Layout'
import SessionManager from './components/SessionManager'
import Login from './pages/Login'
import Dashboard from './pages/Dashboard'
import GlobalOptions from './pages/GlobalOptions'
import LoadBalancing from './pages/LoadBalancing'
import Caching from './pages/Caching'
import Certificates from './pages/Certificates'
import CertificateSslLabs from './pages/CertificateSslLabs'
import SecurityLists from './pages/SecurityLists'
import SecurityRules from './pages/SecurityRules'
import RiskScoring from './pages/RiskScoring'
import Waf from './pages/Waf'
import Captcha from './pages/Captcha'
import RateLimits from './pages/RateLimits'
import Redirects from './pages/Redirects'
import ResponseTransforms from './pages/ResponseTransforms'
import Headers from './pages/Headers'
import PageProtect from './pages/PageProtect'
import ApiArmor from './pages/ApiArmor'
import Logs from './pages/Logs'
import AuditLogs from './pages/AuditLogs'
import Metrics from './pages/Metrics'
import System from './pages/System'
import McpGateway from './pages/McpGateway'
import { settings as settingsApi, auth } from './services/api'
import { useTheme } from './themes/useTheme'

function FeatureGate({ settingKey, children }: { settingKey: string; children: React.ReactNode }) {
  const [enabled, setEnabled] = useState<boolean | null>(null)
  useEffect(() => {
    settingsApi.get(settingKey)
      .then((r) => setEnabled((r.data.value || 'false').toLowerCase() === 'true'))
      .catch(() => setEnabled(false))
  }, [settingKey])
  if (enabled === null) return null
  if (!enabled) return <Navigate to="/" replace />
  return <>{children}</>
}

function RoleGate({ children }: { children: React.ReactNode }) {
  const [isAdmin, setIsAdmin] = useState<boolean | null>(null)
  useEffect(() => {
    auth.me()
      .then((r) => setIsAdmin(r.data.role === 'admin' || r.data.is_admin === true))
      .catch(() => setIsAdmin(false))
  }, [])
  if (isAdmin === null) return null
  if (!isAdmin) return <Navigate to="/" replace />
  return <>{children}</>
}

function App() {
  const [token, setToken] = useState<string | null>(localStorage.getItem('token'))
  const { refreshPreferences } = useTheme()

  useEffect(() => {
    const handleStorage = () => setToken(localStorage.getItem('token'))
    window.addEventListener('storage', handleStorage)
    return () => window.removeEventListener('storage', handleStorage)
  }, [])

  const setAuth = (t: string) => {
    localStorage.setItem('token', t)
    setToken(t)
    // The ThemeProvider's initial preferences load may have run before a token
    // existed (e.g. Safari/ITP evicted localStorage and the user just logged
    // in fresh), in which case it 401'd silently. Re-fetch now so the active
    // theme + custom themes sync from the backend after login.
    refreshPreferences()
  }

  const handleLogout = () => {
    localStorage.removeItem('token')
    setToken(null)
  }

  if (!token) {
    return <Login onLogin={setAuth} />
  }

  return (
    <NotificationProvider>
      <SessionManager onLogout={handleLogout} />
      <Layout>
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/global-options" element={<GlobalOptions />} />
          <Route path="/load-balancing" element={<LoadBalancing />} />
        <Route path="/listeners" element={<Navigate to="/load-balancing" replace />} />
        <Route path="/backends" element={<Navigate to="/load-balancing" replace />} />
        <Route path="/caching" element={<Caching />} />
        <Route path="/fastcgi" element={<Navigate to="/load-balancing" replace />} />
        <Route path="/certificates" element={<Certificates />} />
        <Route path="/certificates/:id/ssllabs" element={<CertificateSslLabs />} />
        <Route path="/security-lists" element={<SecurityLists />} />
        <Route path="/security-rules" element={<SecurityRules />} />
        <Route path="/risk-scoring" element={<RiskScoring />} />
        <Route path="/waf" element={<Waf />} />
        <Route path="/captcha" element={<Captcha />} />
        <Route path="/rate-limits" element={<RateLimits />} />
        <Route path="/redirects" element={<Redirects />} />
        <Route path="/response-transforms" element={<FeatureGate settingKey="resp_transform_enabled"><ResponseTransforms /></FeatureGate>} />
        <Route path="/headers" element={<Headers />} />
        <Route path="/page-armor" element={<PageProtect />} />
        <Route path="/api-armor" element={<FeatureGate settingKey="api_armor_enabled"><ApiArmor /></FeatureGate>} />
        <Route path="/logs" element={<Logs />} />
        <Route path="/audit-logs" element={<RoleGate><AuditLogs /></RoleGate>} />
        <Route path="/metrics" element={<Metrics />} />
        <Route path="/system" element={<RoleGate><System /></RoleGate>} />
        <Route path="/settings" element={<Navigate to="/system" replace />} />
        <Route path="/users" element={<Navigate to="/system" replace />} />
        <Route path="/snapshots" element={<Navigate to="/system" replace />} />
        <Route path="/custom-response-pages" element={<Navigate to="/global-options" replace />} />
        <Route path="/mcp-gateway" element={<FeatureGate settingKey="mcp_gateway_enabled"><McpGateway /></FeatureGate>} />
        <Route path="*" element={<Navigate to="/" />} />
      </Routes>
      </Layout>
    </NotificationProvider>
  )
}

export default App
