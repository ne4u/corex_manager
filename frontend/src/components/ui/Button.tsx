import { ButtonHTMLAttributes, forwardRef } from 'react'
import { LucideIcon } from 'lucide-react'
import { cn } from '../../lib/utils'

export interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: 'primary' | 'secondary' | 'danger' | 'ghost'
  size?: 'sm' | 'md' | 'lg'
  icon?: LucideIcon
  iconPosition?: 'left' | 'right'
  iconOnly?: boolean
}

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(
  (
    {
      variant = 'primary',
      size = 'md',
      icon: Icon,
      iconPosition = 'left',
      iconOnly = false,
      className,
      children,
      ...props
    },
    ref
  ) => {
    const baseClasses = 'inline-flex items-center justify-center rounded-lg font-medium transition-colors focus:outline-none focus:ring-2 focus:ring-offset-2 disabled:opacity-50 disabled:cursor-not-allowed'

    const variantClasses = {
      primary: 'bg-primary text-white hover:opacity-90 focus:ring-primary',
      secondary: 'bg-slate-800 text-slate-100 hover:bg-slate-700 border border-slate-700 focus:ring-slate-700',
      danger: 'bg-red-600 text-white hover:opacity-90 focus:ring-red-600',
      ghost: 'text-slate-100 hover:bg-slate-800 focus:ring-slate-700',
    }

    const sizeClasses = iconOnly
      ? {
          sm: 'p-1.5',
          md: 'p-2',
          lg: 'p-3',
        }
      : {
          sm: 'px-3 py-1.5 text-sm gap-1.5',
          md: 'px-4 py-2 text-sm gap-2',
          lg: 'px-6 py-3 text-base gap-2',
        }

    const iconSize = {
      sm: 'w-3.5 h-3.5',
      md: 'w-4 h-4',
      lg: 'w-5 h-5',
    }

    return (
      <button
        type="button"
        ref={ref}
        className={cn(baseClasses, variantClasses[variant], sizeClasses[size], className)}
        {...props}
      >
        {Icon && iconPosition === 'left' && <Icon className={iconSize[size]} />}
        {!iconOnly && children}
        {Icon && iconPosition === 'right' && <Icon className={iconSize[size]} />}
      </button>
    )
  }
)

Button.displayName = 'Button'
