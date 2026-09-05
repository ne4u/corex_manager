import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Settings as SettingsIcon, Users as UsersIcon, Flag, History, Table as TableIcon } from 'lucide-react'
import { Tabs } from '../components/ui'
import SystemSettings from './SystemSettings'
import Users from './Users'
import FeatureFlags from './FeatureFlags'
import SystemSnapshots from './SystemSnapshots'
import SystemTables from './SystemTables'

type SystemTab = 'settings' | 'users' | 'features' | 'snapshots' | 'tables'

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
        ]}
        active={tab}
        onChange={(id) => setTab(id as SystemTab)}
      />

      {tab === 'settings' && <SystemSettings />}
      {tab === 'users' && <Users />}
      {tab === 'features' && <FeatureFlags />}
      {tab === 'snapshots' && <SystemSnapshots />}
      {tab === 'tables' && <SystemTables />}
    </div>
  )
}
