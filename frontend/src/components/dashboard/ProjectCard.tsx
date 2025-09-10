import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Progress } from "@/components/ui/progress"
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from "@/components/ui/dropdown-menu"
import { Play, Download, Trash2, MoreVertical, Clock, CheckCircle, AlertCircle, RefreshCw } from "lucide-react"
import { Project } from "@/api/projects"
import { formatDistanceToNow } from "date-fns"
import { ru } from "date-fns/locale"
import { AccessibleButton } from "@/components/accessibility/AccessibleButton"

interface ProjectCardProps {
  project: Project
  onOpen: () => void
  onDelete: () => void
}

export function ProjectCard({ project, onOpen, onDelete }: ProjectCardProps) {
  const getStatusIcon = () => {
    switch (project.status) {
      case 'creating':
        return <RefreshCw className="h-4 w-4 animate-spin" />
      case 'ready':
        return <CheckCircle className="h-4 w-4" />
      case 'error':
        return <AlertCircle className="h-4 w-4" />
      default:
        return <Clock className="h-4 w-4" />
    }
  }

  const getStatusColor = () => {
    switch (project.status) {
      case 'creating':
        return 'bg-yellow-100 text-yellow-700'
      case 'ready':
        return 'bg-green-100 text-green-700'
      case 'error':
        return 'bg-red-100 text-red-700'
      default:
        return 'bg-gray-100 text-gray-700'
    }
  }

  const getStatusText = () => {
    switch (project.status) {
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
      return formatDistanceToNow(new Date(dateString), { 
        addSuffix: true, 
        locale: ru 
      })
    } catch {
      return 'недавно'
    }
  }

  return (
    <Card 
      className="hover:shadow-lg transition-all duration-200 hover:-translate-y-1 bg-white/80 backdrop-blur-sm border-0 shadow-md focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-500 focus-visible:ring-offset-2"
      role="article"
      aria-labelledby={`project-title-${project._id}`}
      aria-describedby={`project-description-${project._id}`}
      tabIndex={0}
      onClick={onOpen}
      onKeyDown={(e) => {
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault()
          onOpen()
        }
      }}
    >
      <CardHeader className="pb-3">
        <div className="flex items-start justify-between">
          <div className="flex-1">
            <CardTitle 
              id={`project-title-${project._id}`}
              className="text-lg mb-1 line-clamp-1"
            >
              {project.name}
            </CardTitle>
            <p 
              id={`project-description-${project._id}`}
              className="text-sm text-muted-foreground line-clamp-2"
            >
              {project.description}
            </p>
          </div>
          
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <AccessibleButton
                variant="ghost"
                size="icon"
                className="h-8 w-8"
                aria-label={`Открыть меню проекта ${project.name}`}
                aria-haspopup="menu"
                onClick={(e) => e.stopPropagation()}
              >
                <MoreVertical className="h-4 w-4" aria-hidden="true" />
              </AccessibleButton>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end" role="menu">
              <DropdownMenuItem 
                role="menuitem" 
                onClick={(e) => {
                  e.stopPropagation()
                  onOpen()
                }}
              >
                <Play className="mr-2 h-4 w-4" aria-hidden="true" />
                Открыть
              </DropdownMenuItem>
              {project.status === 'ready' && (
                <DropdownMenuItem 
                  role="menuitem"
                  onClick={(e) => e.stopPropagation()}
                >
                  <Download className="mr-2 h-4 w-4" aria-hidden="true" />
                  Экспорт
                </DropdownMenuItem>
              )}
              <DropdownMenuItem 
                role="menuitem"
                onClick={(e) => {
                  e.stopPropagation()
                  onDelete()
                }} 
                className="text-red-600"
              >
                <Trash2 className="mr-2 h-4 w-4" aria-hidden="true" />
                Удалить
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
        </div>
      </CardHeader>

      <CardContent className="pt-0">
        {/* Preview Thumbnail */}
        <div className="mb-4">
          {project.thumbnailUrl ? (
            <div 
              className="h-32 bg-gradient-to-br from-blue-100 to-purple-100 rounded-lg flex items-center justify-center"
              role="img"
              aria-label={`Превью проекта ${project.name}`}
            >
              <div className="text-4xl font-bold text-blue-300 opacity-50">
                {project.name.charAt(0)}
              </div>
            </div>
          ) : (
            <div 
              className="h-32 bg-gradient-to-br from-gray-100 to-gray-200 rounded-lg flex items-center justify-center"
              role="img"
              aria-label={`Превью проекта ${project.name}`}
            >
              <div className="text-4xl font-bold text-gray-300">
                {project.name.charAt(0)}
              </div>
            </div>
          )}
        </div>

        {/* Status and Progress */}
        <div className="space-y-3">
          <div className="flex items-center justify-between">
            <Badge 
              className={`${getStatusColor()} flex items-center gap-1`}
              aria-label={`Статус проекта: ${getStatusText()}`}
            >
              {getStatusIcon()}
              {getStatusText()}
            </Badge>
            <time 
              className="text-xs text-muted-foreground"
              dateTime={project.lastModified}
              aria-label={`Изменен: ${formatDate(project.lastModified)}`}
            >
              {formatDate(project.lastModified)}
            </time>
          </div>

          {project.status === 'creating' && (
            <div className="space-y-1">
              <div className="flex justify-between text-xs">
                <span>Прогресс</span>
                <span aria-live="polite">{project.progress}%</span>
              </div>
              <Progress 
                value={project.progress} 
                className="h-2"
                role="progressbar"
                aria-valuenow={project.progress}
                aria-valuemin={0}
                aria-valuemax={100}
                aria-label={`Прогресс создания: ${project.progress}%`}
              />
            </div>
          )}

          <AccessibleButton
            onClick={(e) => {
              e.stopPropagation()
              onOpen()
            }}
            className="w-full focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-500 focus-visible:ring-offset-2"
            variant={project.status === 'ready' ? 'default' : 'outline'}
            disabled={project.status === 'error'}
            description={`Открыть проект ${project.name}`}
          >
            {project.status === 'creating' && (
              <>
                <RefreshCw className="mr-2 h-4 w-4 animate-spin" aria-hidden="true" />
                <span className="sr-only">Создается проект</span>
                <span aria-hidden="true">Создается...</span>
              </>
            )}
            {project.status === 'ready' && (
              <>
                <Play className="mr-2 h-4 w-4" aria-hidden="true" />
                Открыть
              </>
            )}
            {project.status === 'error' && (
              <>
                <AlertCircle className="mr-2 h-4 w-4" aria-hidden="true" />
                Попробовать снова
              </>
            )}
          </AccessibleButton>
        </div>
      </CardContent>
    </Card>
  )
}