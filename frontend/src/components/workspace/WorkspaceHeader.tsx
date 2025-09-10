import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import { ArrowLeft, ExternalLink, Download, Settings, Share } from "lucide-react"
import { useNavigate } from "react-router-dom"
import { Project } from "@/api/projects"

interface WorkspaceHeaderProps {
  project: Project
}

export function WorkspaceHeader({ project }: WorkspaceHeaderProps) {
  const navigate = useNavigate()

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

  return (
    <header className="fixed top-0 z-50 w-full border-b bg-white/80 backdrop-blur-sm">
      <div className="flex h-16 items-center justify-between px-6">
        <div className="flex items-center gap-4">
          <Button
            variant="ghost"
            size="icon"
            onClick={() => navigate("/dashboard")}
          >
            <ArrowLeft className="h-4 w-4" />
          </Button>
          
          <div>
            <h1 className="font-semibold">{project.name}</h1>
            <div className="flex items-center gap-2">
              <Badge className={`${getStatusColor()} text-xs`}>
                {getStatusText()}
              </Badge>
              {project.status === 'creating' && (
                <span className="text-xs text-muted-foreground">
                  {project.progress}%
                </span>
              )}
            </div>
          </div>
        </div>

        <div className="flex items-center gap-2">
          {project.previewUrl && (
            <Button variant="outline" size="sm">
              <ExternalLink className="mr-2 h-4 w-4" />
              Открыть в новом окне
            </Button>
          )}
          
          <Button variant="outline" size="sm">
            <Share className="mr-2 h-4 w-4" />
            Поделиться
          </Button>
          
          {project.status === 'ready' && (
            <Button variant="outline" size="sm">
              <Download className="mr-2 h-4 w-4" />
              Экспорт
            </Button>
          )}
          
          <Button variant="outline" size="sm">
            <Settings className="h-4 w-4" />
          </Button>
        </div>
      </div>
    </header>
  )
}