import { LucideIcon } from 'lucide-react'
import { cn } from '../../lib/utils'

export interface Tab {
  id: string
  label: string
  icon?: LucideIcon
  badge?: string | number
}

export interface TabsProps {
  tabs: Tab[]
  active: string
  onChange: (id: string) => void
  className?: string
}

export function Tabs({ tabs, active, onChange, className }: TabsProps) {
  return (
    <div className={cn('flex flex-wrap gap-1 border-b border-slate-800', className)}>
      {tabs.map((tab) => (
        <button
          type="button"
          key={tab.id}
          onClick={() => onChange(tab.id)}
          className={cn(
            'px-3 py-2 text-sm font-medium border-b-2 transition-colors flex items-center gap-1.5 whitespace-nowrap',
            active === tab.id
              ? 'border-primary text-primary'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          )}
        >
          {tab.icon && <tab.icon className="w-4 h-4 shrink-0" />}
          {tab.label}
          {tab.badge !== undefined && (
            <span className="px-1.5 py-0.5 rounded-full bg-slate-800 text-xs">
              {tab.badge}
            </span>
          )}
        </button>
      ))}
    </div>
  )
}
