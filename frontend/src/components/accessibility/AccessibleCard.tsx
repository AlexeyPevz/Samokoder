import React from 'react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { cn } from '@/lib/utils'

interface AccessibleCardProps {
  children: React.ReactNode
  title?: string
  description?: string
  role?: string
  tabIndex?: number
  onClick?: () => void
  className?: string
  ariaLabel?: string
  ariaDescribedBy?: string
}

export function AccessibleCard({
  children,
  title,
  description,
  role = 'article',
  tabIndex,
  onClick,
  className,
  ariaLabel,
  ariaDescribedBy
}: AccessibleCardProps) {
  const isInteractive = !!onClick || tabIndex !== undefined
  
  return (
    <Card
      role={role}
      tabIndex={tabIndex}
      onClick={onClick}
      className={cn(
        'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary focus-visible:ring-offset-2',
        isInteractive && 'cursor-pointer hover:shadow-lg transition-shadow',
        className
      )}
      aria-label={ariaLabel}
      aria-describedby={ariaDescribedBy}
    >
      {title && (
        <CardHeader>
          <CardTitle className="text-lg font-semibold">
            {title}
          </CardTitle>
          {description && (
            <p className="text-sm text-gray-600 mt-1">
              {description}
            </p>
          )}
        </CardHeader>
      )}
      <CardContent className={title ? '' : 'pt-6'}>
        {children}
      </CardContent>
    </Card>
  )
}

interface ProjectCardProps {
  project: {
    id: string
    name: string
    description: string
    status: string
    lastModified: string
    progress?: number
  }
  onOpen: () => void
  onDelete: () => void
  className?: string
}

export function AccessibleProjectCard({
  project,
  onOpen,
  onDelete,
  className
}: ProjectCardProps) {
  const getStatusText = (status: string) => {
    switch (status) {
      case 'creating':
        return 'Создается'
      case 'ready':
        return 'Готов'
      case 'error':
        return 'Ошибка'
      default:
        return 'Неизвестно'
    }
  }
  
  const formatDate = (dateString: string) => {
    try {
      return new Date(dateString).toLocaleDateString('ru-RU', {
        year: 'numeric',
        month: 'long',
        day: 'numeric'
      })
    } catch {
      return 'недавно'
    }
  }
  
  return (
    <AccessibleCard
      title={project.name}
      description={project.description}
      role="article"
      tabIndex={0}
      onClick={onOpen}
      className={cn('hover:shadow-lg transition-all duration-200', className)}
      ariaLabel={`Проект ${project.name}, статус: ${getStatusText(project.status)}, изменен: ${formatDate(project.lastModified)}`}
    >
      <div className="space-y-3">
        <div className="flex items-center justify-between">
          <span 
            className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium"
            aria-label={`Статус: ${getStatusText(project.status)}`}
          >
            {getStatusText(project.status)}
          </span>
          <time 
            className="text-xs text-gray-500"
            dateTime={project.lastModified}
          >
            {formatDate(project.lastModified)}
          </time>
        </div>
        
        {project.status === 'creating' && project.progress !== undefined && (
          <div className="space-y-1">
            <div className="flex justify-between text-xs">
              <span>Прогресс</span>
              <span aria-live="polite">{project.progress}%</span>
            </div>
            <div 
              className="w-full bg-gray-200 rounded-full h-2"
              role="progressbar"
              aria-valuenow={project.progress}
              aria-valuemin={0}
              aria-valuemax={100}
              aria-label={`Прогресс создания: ${project.progress}%`}
            >
              <div 
                className="bg-primary h-2 rounded-full transition-all duration-300"
                style={{ width: `${project.progress}%` }}
              />
            </div>
          </div>
        )}
        
        <div className="flex gap-2">
          <button
            onClick={(e) => {
              e.stopPropagation()
              onOpen()
            }}
            className="flex-1 bg-primary text-white px-4 py-2 rounded-md hover:bg-primary/90 focus:outline-none focus:ring-2 focus:ring-primary focus:ring-offset-2"
            aria-label={`Открыть проект ${project.name}`}
          >
            Открыть
          </button>
          <button
            onClick={(e) => {
              e.stopPropagation()
              onDelete()
            }}
            className="px-4 py-2 text-red-600 border border-red-600 rounded-md hover:bg-red-50 focus:outline-none focus:ring-2 focus:ring-red-500 focus:ring-offset-2"
            aria-label={`Удалить проект ${project.name}`}
          >
            Удалить
          </button>
        </div>
      </div>
    </AccessibleCard>
  )
}