import React from 'react'
import { Button } from '@/components/ui/button'
import { cn } from '@/lib/utils'

interface AccessibleButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  children: React.ReactNode
  variant?: 'default' | 'destructive' | 'outline' | 'secondary' | 'ghost' | 'link'
  size?: 'default' | 'sm' | 'lg' | 'icon'
  loading?: boolean
  loadingText?: string
  description?: string
  className?: string
}

export function AccessibleButton({
  children,
  variant = 'default',
  size = 'default',
  loading = false,
  loadingText = 'Загрузка...',
  description,
  className,
  disabled,
  ...props
}: AccessibleButtonProps) {
  const isDisabled = disabled || loading
  
  return (
    <Button
      variant={variant}
      size={size}
      disabled={isDisabled}
      className={cn(
        'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-500 focus-visible:ring-offset-2',
        className
      )}
      aria-describedby={description ? `${props.id || 'button'}-description` : undefined}
      {...props}
    >
      {loading ? (
        <>
          <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white mr-2" />
          <span className="sr-only">{loadingText}</span>
          <span aria-hidden="true">{loadingText}</span>
        </>
      ) : (
        children
      )}
      
      {description && (
        <span id={`${props.id || 'button'}-description`} className="sr-only">
          {description}
        </span>
      )}
    </Button>
  )
}

interface IconButtonProps extends Omit<AccessibleButtonProps, 'children'> {
  icon: React.ReactNode
  label: string
  description?: string
}

export function IconButton({
  icon,
  label,
  description,
  className,
  ...props
}: IconButtonProps) {
  return (
    <AccessibleButton
      size="icon"
      className={cn('h-10 w-10', className)}
      aria-label={label}
      description={description}
      {...props}
    >
      {icon}
      <span className="sr-only">{label}</span>
    </AccessibleButton>
  )
}

interface ToggleButtonProps extends AccessibleButtonProps {
  pressed: boolean
  pressedText?: string
  unpressedText?: string
}

export function ToggleButton({
  pressed,
  pressedText = 'Нажато',
  unpressedText = 'Не нажато',
  children,
  ...props
}: ToggleButtonProps) {
  return (
    <AccessibleButton
      aria-pressed={pressed}
      aria-label={`${children} - ${pressed ? pressedText : unpressedText}`}
      {...props}
    >
      {children}
    </AccessibleButton>
  )
}