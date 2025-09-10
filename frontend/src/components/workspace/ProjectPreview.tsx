import { useState } from "react"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import { Monitor, Smartphone, RefreshCw, ExternalLink, Camera } from "lucide-react"
import { Project } from "@/api/projects"

interface ProjectPreviewProps {
  project: Project
}

export function ProjectPreview({ project }: ProjectPreviewProps) {
  const [viewMode, setViewMode] = useState<'desktop' | 'mobile'>('desktop')
  const [isRefreshing, setIsRefreshing] = useState(false)

  const handleRefresh = () => {
    console.log('Refreshing preview...')
    setIsRefreshing(true)
    setTimeout(() => setIsRefreshing(false), 1000)
  }

  const handleScreenshot = () => {
    console.log('Taking screenshot...')
    // Implementation for screenshot functionality
  }

  return (
    <div className="flex flex-col h-full bg-white/50 backdrop-blur-sm">
      {/* Header */}
      <div className="p-4 border-b bg-white/80">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <h3 className="font-semibold">Превью</h3>
            <Badge variant="outline" className="text-xs">
              Обновлено {new Date().toLocaleTimeString('ru-RU', {
                hour: '2-digit',
                minute: '2-digit'
              })}
            </Badge>
          </div>

          <div className="flex items-center gap-2">
            {/* Device Toggle */}
            <div className="flex items-center bg-gray-100 rounded-lg p-1">
              <Button
                variant={viewMode === 'desktop' ? 'default' : 'ghost'}
                size="sm"
                onClick={() => setViewMode('desktop')}
                className="h-8 px-3"
              >
                <Monitor className="h-4 w-4" />
              </Button>
              <Button
                variant={viewMode === 'mobile' ? 'default' : 'ghost'}
                size="sm"
                onClick={() => setViewMode('mobile')}
                className="h-8 px-3"
              >
                <Smartphone className="h-4 w-4" />
              </Button>
            </div>

            <Button
              variant="outline"
              size="sm"
              onClick={handleRefresh}
              disabled={isRefreshing}
            >
              <RefreshCw className={`h-4 w-4 ${isRefreshing ? 'animate-spin' : ''}`} />
            </Button>

            <Button variant="outline" size="sm" onClick={handleScreenshot}>
              <Camera className="h-4 w-4" />
            </Button>

            {project.previewUrl && (
              <Button variant="outline" size="sm">
                <ExternalLink className="h-4 w-4" />
              </Button>
            )}
          </div>
        </div>

        {project.previewUrl && (
          <div className="mt-2 text-xs text-muted-foreground">
            {project.previewUrl}
          </div>
        )}
      </div>

      {/* Preview Area */}
      <div className="flex-1 p-4">
        <div className="h-full flex items-center justify-center">
          {project.status === 'creating' ? (
            <div className="text-center">
              <div className="w-16 h-16 border-4 border-blue-600 border-t-transparent rounded-full animate-spin mx-auto mb-4"></div>
              <h3 className="font-semibold mb-2">Создание приложения</h3>
              <p className="text-muted-foreground mb-4">
                Прогресс: {project.progress}%
              </p>
              <div className="w-64 bg-gray-200 rounded-full h-2 mx-auto">
                <div
                  className="bg-blue-600 h-2 rounded-full transition-all duration-300"
                  style={{ width: `${project.progress}%` }}
                ></div>
              </div>
            </div>
          ) : project.status === 'error' ? (
            <div className="text-center">
              <div className="w-16 h-16 bg-red-100 rounded-full flex items-center justify-center mx-auto mb-4">
                <ExternalLink className="h-8 w-8 text-red-600" />
              </div>
              <h3 className="font-semibold mb-2">Ошибка создания</h3>
              <p className="text-muted-foreground mb-4">
                Произошла ошибка при создании приложения
              </p>
              <Button variant="outline">
                Попробовать снова
              </Button>
            </div>
          ) : (
            <div
              className={`bg-white rounded-lg shadow-lg overflow-hidden transition-all duration-300 ${
                viewMode === 'mobile'
                  ? 'w-80 h-[600px]'
                  : 'w-full h-full max-w-6xl'
              }`}
            >
              {project.previewUrl ? (
                <iframe
                  src={project.previewUrl}
                  className="w-full h-full border-0"
                  title="App Preview"
                />
              ) : (
                <div className="w-full h-full flex items-center justify-center bg-gradient-to-br from-blue-100 to-purple-100">
                  <div className="text-center">
                    <div className="text-6xl font-bold text-blue-300 mb-4">
                      {project.name.charAt(0)}
                    </div>
                    <h3 className="text-xl font-semibold text-gray-700 mb-2">
                      {project.name}
                    </h3>
                    <p className="text-gray-500">
                      Превью будет доступно после завершения создания
                    </p>
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      </div>

      {/* Footer */}
      <div className="p-4 border-t bg-white/80">
        <div className="flex items-center justify-between text-xs text-muted-foreground">
          <span>
            Статус: {project.status === 'ready' ? 'Готов' : project.status === 'creating' ? 'Создается' : 'Ошибка'}
          </span>
          <span>
            Последнее обновление: {new Date(project.lastModified).toLocaleString('ru-RU')}
          </span>
        </div>
      </div>
    </div>
  )
}