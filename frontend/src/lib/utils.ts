import { CSSProperties } from 'react'

/**
 * Utility function to merge class names
 */
export function cn(...classes: (string | undefined | null | false)[]): string {
  return classes.filter(Boolean).join(' ')
}

/**
 * Shared Recharts tooltip styling, themed via the runtime CSS variables.
 * The background uses the card color at 95% opacity so grid lines stay
 * faintly visible beneath the popup.
 */
export const chartTooltipContentStyle: CSSProperties = {
  backgroundColor: 'rgb(var(--color-bg-secondary) / 0.95)',
  border: '1px solid rgb(var(--color-border-default))',
  borderRadius: '8px',
  color: 'rgb(var(--color-text-primary))',
}

export const chartTooltipLabelStyle: CSSProperties = {
  color: 'rgb(var(--color-text-secondary))',
}
