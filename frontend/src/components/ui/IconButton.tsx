import { ButtonHTMLAttributes, forwardRef } from 'react'
import { LucideIcon } from 'lucide-react'
import { cn } from '../../lib/utils'

export interface IconButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  icon: LucideIcon
  variant?: 'default' | 'danger' | 'primary'
  size?: 'sm' | 'md'
  'aria-label': string
}

export const IconButton = forwardRef<HTMLButtonElement, IconButtonProps>(
  (
    {
      icon: Icon,
      variant = 'default',
      size = 'sm',
      className,
      'aria-label': ariaLabel,
      ...props
    },
    ref
  ) => {
    const baseClasses = 'inline-flex items-center justify-center rounded transition-colors focus:outline-none focus:ring-2 focus:ring-offset-1 disabled:opacity-50 disabled:cursor-not-allowed'

    const variantClasses = {
      default: 'text-slate-400 hover:text-slate-200 hover:bg-slate-800 focus:ring-slate-700',
      danger: 'text-red-400 hover:text-red-300 hover:bg-red-500/10 focus:ring-red-500',
      primary: 'text-primary hover:text-primary-hover hover:bg-primary/10 focus:ring-primary',
    }

    const sizeClasses = {
      sm: 'p-1',
      md: 'p-1.5',
    }

    const iconSize = {
      sm: 'w-3.5 h-3.5',
      md: 'w-4 h-4',
    }

    return (
      <button
        type="button"
        ref={ref}
        className={cn(baseClasses, variantClasses[variant], sizeClasses[size], className)}
        aria-label={ariaLabel}
        title={ariaLabel}
        {...props}
      >
        <Icon className={iconSize[size]} />
      </button>
    )
  }
)

IconButton.displayName = 'IconButton'
