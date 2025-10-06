import { useState, useEffect } from "react"
import { useNavigate } from "react-router-dom"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Card, CardContent, CardHeader } from "@/components/ui/card"
import { Plus, Search, RefreshCw } from "lucide-react"
import { motion } from "framer-motion"
import { getProjects, deleteProject, type Project } from "@/api/projects"
import { useToast } from "@/hooks/useToast"
import { ProjectCard } from "@/components/dashboard/ProjectCard"
import { CreateProjectDialog } from "@/components/dashboard/CreateProjectDialog"
import { EmptyState } from "@/components/dashboard/EmptyState"
import { PageTitle } from "@/components/accessibility/ScreenReaderSupport"
import { LoadingAnnouncer, LiveRegion } from "@/components/accessibility/ErrorAnnouncer"
import { AccessibleButton } from "@/components/accessibility/AccessibleButton"

export default function Dashboard() {
  const navigate = useNavigate()
  const { toast } = useToast()
  const [projects, setProjects] = useState<Project[]>([])
  const [loading, setLoading] = useState(true)
  const [searchQuery, setSearchQuery] = useState("")
  const [showCreateDialog, setShowCreateDialog] = useState(false)
  const [announcement, setAnnouncement] = useState<string | null>(null)

  useEffect(() => {
    loadProjects()
  }, []) // eslint-disable-line react-hooks/exhaustive-deps

  const loadProjects = async () => {
    try {
      setLoading(true)
      setAnnouncement("Загрузка проектов...")
      const projects = await getProjects()
      setProjects(projects)
      setAnnouncement(`Загружено ${projects.length} проектов`)
    } catch (error) {
      setAnnouncement("Ошибка загрузки проектов")
      toast({
        title: "Ошибка",
        description: "Не удалось загрузить проекты",
        variant: "destructive"
      })
    } finally {
      setLoading(false)
    }
  }

  const handleDeleteProject = async (projectId: string) => {
    try {
      setAnnouncement("Удаление проекта...")
      await deleteProject(projectId)
      setProjects(projects.filter(p => p.id !== projectId))
      setAnnouncement("Проект успешно удален")
      toast({
        title: "Успешно",
        description: "Проект удален"
      })
    } catch (error) {
      setAnnouncement("Ошибка удаления проекта")
      toast({
        title: "Ошибка",
        description: "Не удалось удалить проект",
        variant: "destructive"
      })
    }
  }

  const filteredProjects = projects.filter(project =>
    project?.name?.toLowerCase().includes(searchQuery.toLowerCase())
  )

  if (loading) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-primary-50 via-white to-secondary-50 p-6">
        <div className="mx-auto max-w-6xl">
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            {[...Array(6)].map((_, i) => (
              <Card key={i} className="animate-pulse">
                <CardHeader>
                  <div className="h-4 bg-gray-200 rounded w-3/4"></div>
                  <div className="h-3 bg-gray-200 rounded w-1/2"></div>
                </CardHeader>
                <CardContent>
                  <div className="h-32 bg-gray-200 rounded"></div>
                </CardContent>
              </Card>
            ))}
          </div>
        </div>
      </div>
    )
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-primary-50 via-white to-secondary-50 p-6">
      <PageTitle 
        title="Панель управления" 
        description="Управляйте своими проектами и создавайте новые"
      />
      <LoadingAnnouncer loading={loading} message="Загрузка проектов..." />
      <LiveRegion message={announcement} />
      
      <div className="mx-auto max-w-6xl">
        {/* Header */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6 }}
          className="flex flex-col md:flex-row md:items-center justify-between gap-4 mb-8"
        >
          <div>
            <h1 className="text-3xl font-bold mb-2">Мои проекты</h1>
            <p className="text-muted-foreground">
              Управляйте своими приложениями и создавайте новые
            </p>
          </div>
          
          <AccessibleButton
            onClick={() => setShowCreateDialog(true)}
            className="bg-gradient-to-r from-primary to-secondary hover:from-blue-700 hover:to-purple-700 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-500 focus-visible:ring-offset-2"
            data-action="create-project"
            description="Создать новый проект"
          >
            <Plus className="mr-2 h-4 w-4" aria-hidden="true" />
            Новый проект
          </AccessibleButton>
        </motion.div>

        {/* Search and Filters */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6, delay: 0.1 }}
          className="flex flex-col md:flex-row gap-4 mb-8"
        >
          <div className="relative flex-1">
            <label htmlFor="search" className="sr-only">
              Поиск проектов
            </label>
            <Search 
              className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-muted-foreground" 
              aria-hidden="true"
            />
            <Input
              id="search"
              data-action="search"
              placeholder="Поиск проектов..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="pl-10 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-500 focus-visible:ring-offset-2"
              aria-label="Поиск проектов по названию и описанию"
            />
          </div>
          
          <AccessibleButton 
            variant="outline" 
            onClick={loadProjects}
            description="Обновить список проектов"
          >
            <RefreshCw className="mr-2 h-4 w-4" aria-hidden="true" />
            Обновить
          </AccessibleButton>
        </motion.div>

        {/* Projects Grid */}
        {filteredProjects.length === 0 ? (
          <EmptyState onCreateProject={() => setShowCreateDialog(true)} />
        ) : (
          <div 
            className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6"
            role="grid"
            aria-label="Список проектов"
          >
            {filteredProjects.map((project, index) => (
              <motion.div
                key={project.id}
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.6, delay: index * 0.1 }}
                role="gridcell"
              >
                <ProjectCard
                  project={project}
                  onOpen={() => navigate(`/workspace/${project.id}`)}
                  onDelete={() => handleDeleteProject(project.id)}
                />
              </motion.div>
            ))}
          </div>
        )}

        <CreateProjectDialog
          open={showCreateDialog}
          onOpenChange={setShowCreateDialog}
          onProjectCreated={(project) => {
            setProjects([project, ...projects])
            navigate(`/workspace/${project.id}`)
          }}
        />
      </div>
    </div>
  )
}