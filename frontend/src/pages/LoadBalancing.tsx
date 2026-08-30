import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Network, Globe, Server, Zap } from 'lucide-react'
import { Tabs } from '../components/ui'
import Listeners from './Listeners'
import Backends from './Backends'
import FastCGI from './FastCGI'

type LoadBalancingTab = 'frontends' | 'backends' | 'fastcgi'

export default function LoadBalancing() {
  const { t } = useTranslation(['pages', 'common'])
  const [tab, setTab] = useState<LoadBalancingTab>('frontends')

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold flex items-center gap-2"><Network className="h-5 w-5 text-primary" /> {t('pages:loadBalancing.title')}</h1>

      <Tabs
        tabs={[
          { id: 'frontends', label: t('pages:loadBalancing.tabs.frontends'), icon: Globe },
          { id: 'backends', label: t('pages:loadBalancing.tabs.backends'), icon: Server },
          { id: 'fastcgi', label: t('pages:loadBalancing.tabs.fastcgi'), icon: Zap },
        ]}
        active={tab}
        onChange={(id) => setTab(id as LoadBalancingTab)}
      />

      {tab === 'frontends' && <Listeners />}
      {tab === 'backends' && <Backends />}
      {tab === 'fastcgi' && <FastCGI />}
    </div>
  )
}
