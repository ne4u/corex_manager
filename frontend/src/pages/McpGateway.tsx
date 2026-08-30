import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Network, Server, KeyRound, Shield, Eye, AlertTriangle, FileText, Activity, Store, Users, Settings, ScrollText } from 'lucide-react'
import { Tabs } from '../components/ui'
import McpTrafficTab from '../components/McpTrafficTab'
import McpServersTab from '../components/mcp/McpServersTab'
import McpIdentitiesTab from '../components/mcp/McpIdentitiesTab'
import McpPoliciesTab from '../components/mcp/McpPoliciesTab'
import McpDlpRulesTab from '../components/mcp/McpDlpRulesTab'
import McpGuardrailsTab from '../components/mcp/McpGuardrailsTab'
import McpSkillsTab from '../components/mcp/McpSkillsTab'
import McpMarketplaceTab from '../components/mcp/McpMarketplaceTab'
import McpTeamsTab from '../components/mcp/McpTeamsTab'
import McpSettingsTab from '../components/mcp/McpSettingsTab'
import McpEventsTab from '../components/mcp/McpEventsTab'

type Tab = 'teams' | 'servers' | 'marketplace' | 'identities' | 'policies' | 'dlp' | 'guardrails' | 'skills' | 'traffic' | 'events' | 'settings'

const TABS: { key: Tab; labelKey: string; icon: typeof Server }[] = [
  { key: 'teams', labelKey: 'pages:mcpGateway.tabs.teams', icon: Users },
  { key: 'servers', labelKey: 'pages:mcpGateway.tabs.servers', icon: Server },
  { key: 'marketplace', labelKey: 'pages:mcpGateway.tabs.marketplace', icon: Store },
  { key: 'identities', labelKey: 'pages:mcpGateway.tabs.identities', icon: KeyRound },
  { key: 'policies', labelKey: 'pages:mcpGateway.tabs.policies', icon: Shield },
  { key: 'dlp', labelKey: 'pages:mcpGateway.tabs.dlp', icon: Eye },
  { key: 'guardrails', labelKey: 'pages:mcpGateway.tabs.guardrails', icon: AlertTriangle },
  { key: 'skills', labelKey: 'pages:mcpGateway.tabs.skills', icon: FileText },
  { key: 'traffic', labelKey: 'pages:mcpGateway.tabs.traffic', icon: Activity },
  { key: 'events', labelKey: 'pages:mcpGateway.tabs.events', icon: ScrollText },
  { key: 'settings', labelKey: 'pages:mcpGateway.tabs.settings', icon: Settings },
]

export default function McpGateway() {
  const { t } = useTranslation(['pages', 'common'])
  const [tab, setTab] = useState<Tab>('servers')

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold flex items-center gap-2">
        <Network className="h-5 w-5 text-primary" /> {t('pages:mcpGateway.title')}
      </h1>
      <p className="text-sm text-slate-400 max-w-3xl">
        {t('pages:mcpGateway.description')}
      </p>

      <Tabs
        tabs={TABS.map(tab => ({ id: tab.key, label: t(tab.labelKey), icon: tab.icon }))}
        active={tab}
        onChange={(id) => setTab(id as Tab)}
      />

      {tab === 'teams' && <McpTeamsTab />}
      {tab === 'servers' && <McpServersTab />}
      {tab === 'marketplace' && <McpMarketplaceTab />}
      {tab === 'identities' && <McpIdentitiesTab />}
      {tab === 'policies' && <McpPoliciesTab />}
      {tab === 'dlp' && <McpDlpRulesTab />}
      {tab === 'guardrails' && <McpGuardrailsTab />}
      {tab === 'skills' && <McpSkillsTab />}
      {tab === 'traffic' && <McpTrafficTab />}
      {tab === 'events' && <McpEventsTab />}
      {tab === 'settings' && <McpSettingsTab />}
    </div>
  )
}
