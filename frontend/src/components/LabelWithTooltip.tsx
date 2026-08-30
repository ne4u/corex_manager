import React from 'react'
import InfoTooltip from './InfoTooltip'

interface LabelWithTooltipProps {
  children: React.ReactNode
  tooltip: string
  className?: string
  textClassName?: string
}

export default function LabelWithTooltip({ children, tooltip, className, textClassName }: LabelWithTooltipProps) {
  return (
    <div className={className ?? 'flex items-center gap-1.5 mb-1'}>
      <span className={textClassName ?? 'text-xs font-semibold text-slate-400'}>{children}</span>
      <InfoTooltip content={tooltip} />
    </div>
  )
}
