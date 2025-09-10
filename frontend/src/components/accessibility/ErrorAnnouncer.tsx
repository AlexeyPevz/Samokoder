import React from 'react'

interface ErrorAnnouncerProps {
  error: string | null
  className?: string
}

export function ErrorAnnouncer({ error, className = '' }: ErrorAnnouncerProps) {
  return (
    <div
      role="alert"
      aria-live="polite"
      aria-atomic="true"
      className={`sr-only ${className}`}
    >
      {error && `Ошибка: ${error}`}
    </div>
  )
}

interface LoadingAnnouncerProps {
  loading: boolean
  message?: string
  className?: string
}

export function LoadingAnnouncer({ 
  loading, 
  message = "Загрузка...", 
  className = '' 
}: LoadingAnnouncerProps) {
  return (
    <div
      role="status"
      aria-live="polite"
      aria-atomic="true"
      className={`sr-only ${className}`}
    >
      {loading && message}
    </div>
  )
}

interface LiveRegionProps {
  message: string | null
  className?: string
}

export function LiveRegion({ message, className = '' }: LiveRegionProps) {
  return (
    <div
      aria-live="polite"
      aria-atomic="true"
      className={`sr-only ${className}`}
    >
      {message}
    </div>
  )
}