import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Settings as SettingsIcon, Users as UsersIcon, Flag, History, Table as TableIcon, Database, Activity } from 'lucide-react'
import { Tabs } from '../components/ui'
import SystemSettings from './SystemSettings'
import Users from './Users'
import FeatureFlags from './FeatureFlags'
import SystemSnapshots from './SystemSnapshots'
import SystemTables from './SystemTables'
import SystemValkey from './SystemValkey'
import SystemHa from './SystemHa'

type SystemTab = 'settings' | 'users' | 'features' | 'snapshots' | 'tables' | 'valkey' | 'ha'

export default function System() {
  const { t } = useTranslation(['pages', 'common'])
  const [tab, setTab] = useState<SystemTab>('settings')
  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold flex items-center gap-2"><SettingsIcon className="h-5 w-5 text-primary" /> {t('pages:system.title')}</h1>

      <Tabs
        tabs={[
          { id: 'settings', label: t('pages:system.tabs.settings'), icon: SettingsIcon },
          { id: 'users', label: t('pages:system.tabs.users'), icon: UsersIcon },
          { id: 'features', label: t('pages:system.tabs.features'), icon: Flag },
          { id: 'snapshots', label: t('pages:system.tabs.snapshots'), icon: History },
          { id: 'tables', label: t('pages:system.tabs.tables'), icon: TableIcon },
          { id: 'valkey', label: t('pages:system.tabs.valkey'), icon: Database },
          { id: 'ha', label: t('pages:system.tabs.ha'), icon: Activity },
        ]}
        active={tab}
        onChange={(id) => setTab(id as SystemTab)}
      />

      {tab === 'settings' && <SystemSettings />}
      {tab === 'users' && <Users />}
      {tab === 'features' && <FeatureFlags />}
      {tab === 'snapshots' && <SystemSnapshots />}
      {tab === 'tables' && <SystemTables />}
      {tab === 'valkey' && <SystemValkey />}
      {tab === 'ha' && <SystemHa />}
    </div>
  )
}
