/**
 * ОПТИМИЗАЦИЯ 2: Debouncing + Memoization
 * Цель: Улучшить INP (Interaction to Next Paint) с 280мс до 150мс
 * 
 * Проблемы:
 * - Поиск без debouncing блокирует UI
 * - Тяжелые вычисления без мемоизации
 * - Неоптимизированные обработчики событий
 * - Избыточные ререндеры компонентов
 */

import { useState, useEffect, useMemo, useCallback, memo } from 'react'
import { useDebouncedCallback } from 'use-debounce'
import { Input } from '@/components/ui/input'
import { Search } from 'lucide-react'

// Debounced search hook
export function useDebouncedSearch<T>(
  items: T[],
  searchFn: (items: T[], query: string) => T[],
  delay: number = 300
) {
  const [query, setQuery] = useState('')
  const [debouncedQuery, setDebouncedQuery] = useState('')

  // Debounced update of search query
  const debouncedSetQuery = useDebouncedCallback(
    (value: string) => {
      setDebouncedQuery(value)
    },
    delay
  )

  // Update debounced query when query changes
  useEffect(() => {
    debouncedSetQuery(query)
  }, [query, debouncedSetQuery])

  // Memoized filtered results
  const filteredItems = useMemo(() => {
    if (!debouncedQuery.trim()) return items
    return searchFn(items, debouncedQuery)
  }, [items, debouncedQuery, searchFn])

  return {
    query,
    setQuery,
    filteredItems,
    isSearching: query !== debouncedQuery
  }
}

// Optimized search function with memoization
const searchProjects = (projects: Project[], query: string): Project[] => {
  const lowercaseQuery = query.toLowerCase()
  return projects.filter(project =>
    project?.name?.toLowerCase().includes(lowercaseQuery) ||
    project?.description?.toLowerCase().includes(lowercaseQuery) ||
    project?.techStack?.some(tech => 
      tech.toLowerCase().includes(lowercaseQuery)
    )
  )
}

// Memoized ProjectCard component
export const OptimizedProjectCard = memo(function ProjectCard({ 
  project, 
  onOpen, 
  onDelete 
}: ProjectCardProps) {
  // Memoized status calculations
  const statusConfig = useMemo(() => {
    const configs = {
      creating: {
        icon: <RefreshCw className="h-4 w-4 animate-spin" />,
        color: 'bg-yellow-100 text-yellow-700',
        text: 'Создается'
      },
      ready: {
        icon: <CheckCircle className="h-4 w-4" />,
        color: 'bg-green-100 text-green-700',
        text: 'Готов'
      },
      error: {
        icon: <AlertCircle className="h-4 w-4" />,
        color: 'bg-red-100 text-red-700',
        text: 'Ошибка'
      },
      default: {
        icon: <Clock className="h-4 w-4" />,
        color: 'bg-gray-100 text-gray-700',
        text: 'Неизвестно'
      }
    }
    return configs[project.status] || configs.default
  }, [project.status])

  // Memoized formatted date
  const formattedDate = useMemo(() => {
    try {
      return formatDistanceToNow(new Date(project.lastModified), { 
        addSuffix: true, 
        locale: ru 
      })
    } catch {
      return 'недавно'
    }
  }, [project.lastModified])

  // Memoized thumbnail
  const thumbnail = useMemo(() => {
    if (project.thumbnailUrl) {
      return (
        <div className="h-32 bg-gradient-to-br from-blue-100 to-purple-100 rounded-lg flex items-center justify-center">
          <div className="text-4xl font-bold text-blue-300 opacity-50">
            {project.name.charAt(0)}
          </div>
        </div>
      )
    }
    return (
      <div className="h-32 bg-gradient-to-br from-gray-100 to-gray-200 rounded-lg flex items-center justify-center">
        <div className="text-4xl font-bold text-gray-300">
          {project.name.charAt(0)}
        </div>
      </div>
    )
  }, [project.thumbnailUrl, project.name])

  // Memoized button content
  const buttonContent = useMemo(() => {
    switch (project.status) {
      case 'creating':
        return (
          <>
            <RefreshCw className="mr-2 h-4 w-4 animate-spin" />
            Создается...
          </>
        )
      case 'ready':
        return (
          <>
            <Play className="mr-2 h-4 w-4" />
            Открыть
          </>
        )
      case 'error':
        return (
          <>
            <AlertCircle className="mr-2 h-4 w-4" />
            Попробовать снова
          </>
        )
      default:
        return 'Открыть'
    }
  }, [project.status])

  return (
    <Card className="hover:shadow-lg transition-all duration-200 hover:-translate-y-1 bg-white/80 backdrop-blur-sm border-0 shadow-md">
      <CardHeader className="pb-3">
        <div className="flex items-start justify-between">
          <div className="flex-1">
            <CardTitle className="text-lg mb-1 line-clamp-1">{project.name}</CardTitle>
            <p className="text-sm text-muted-foreground line-clamp-2">
              {project.description}
            </p>
          </div>
          
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button variant="ghost" size="icon" className="h-8 w-8">
                <MoreVertical className="h-4 w-4" />
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end">
              <DropdownMenuItem onClick={onOpen}>
                <Play className="mr-2 h-4 w-4" />
                Открыть
              </DropdownMenuItem>
              {project.status === 'ready' && (
                <DropdownMenuItem>
                  <Download className="mr-2 h-4 w-4" />
                  Экспорт
                </DropdownMenuItem>
              )}
              <DropdownMenuItem onClick={onDelete} className="text-red-600">
                <Trash2 className="mr-2 h-4 w-4" />
                Удалить
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
        </div>
      </CardHeader>

      <CardContent className="pt-0">
        {/* Memoized Thumbnail */}
        {thumbnail}

        {/* Status and Progress */}
        <div className="space-y-3">
          <div className="flex items-center justify-between">
            <Badge className={`${statusConfig.color} flex items-center gap-1`}>
              {statusConfig.icon}
              {statusConfig.text}
            </Badge>
            <span className="text-xs text-muted-foreground">
              {formattedDate}
            </span>
          </div>

          {project.status === 'creating' && (
            <div className="space-y-1">
              <div className="flex justify-between text-xs">
                <span>Прогресс</span>
                <span>{project.progress}%</span>
              </div>
              <Progress value={project.progress} className="h-2" />
            </div>
          )}

          <Button
            onClick={onOpen}
            className="w-full"
            variant={project.status === 'ready' ? 'default' : 'outline'}
            disabled={project.status === 'error'}
          >
            {buttonContent}
          </Button>
        </div>
      </CardContent>
    </Card>
  )
})

// Optimized Dashboard with debounced search
export function OptimizedDashboard() {
  const navigate = useNavigate()
  const { toast } = useToast()
  const [projects, setProjects] = useState<Project[]>([])
  const [loading, setLoading] = useState(true)
  const [showCreateDialog, setShowCreateDialog] = useState(false)

  // Debounced search with memoization
  const {
    query: searchQuery,
    setQuery: setSearchQuery,
    filteredItems: filteredProjects,
    isSearching
  } = useDebouncedSearch(projects, searchProjects, 300)

  // Memoized load projects function
  const loadProjects = useCallback(async () => {
    try {
      console.log('Loading projects...')
      setLoading(true)
      const response = await getProjects()
      setProjects(response.projects)
      console.log('Projects loaded:', response.projects.length)
    } catch (error) {
      console.error('Error loading projects:', error)
      toast({
        title: "Ошибка",
        description: "Не удалось загрузить проекты",
        variant: "destructive"
      })
    } finally {
      setLoading(false)
    }
  }, [toast])

  // Memoized delete handler
  const handleDeleteProject = useCallback(async (projectId: string) => {
    try {
      console.log('Deleting project:', projectId)
      await deleteProject(projectId)
      setProjects(prev => prev.filter(p => p._id !== projectId))
      toast({
        title: "Успешно",
        description: "Проект удален"
      })
    } catch (error) {
      console.error('Error deleting project:', error)
      toast({
        title: "Ошибка",
        description: "Не удалось удалить проект",
        variant: "destructive"
      })
    }
  }, [toast])

  // Memoized open handler
  const handleOpenProject = useCallback((projectId: string) => {
    navigate(`/workspace/${projectId}`)
  }, [navigate])

  // Memoized project creation handler
  const handleProjectCreated = useCallback((project: Project) => {
    setProjects(prev => [project, ...prev])
    navigate(`/workspace/${project._id}`)
  }, [navigate])

  // Load projects on mount
  useEffect(() => {
    loadProjects()
  }, [loadProjects])

  // Memoized search input
  const searchInput = useMemo(() => (
    <div className="relative flex-1">
      <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-muted-foreground" />
      <Input
        placeholder="Поиск проектов..."
        value={searchQuery}
        onChange={(e) => setSearchQuery(e.target.value)}
        className="pl-10"
      />
      {isSearching && (
        <div className="absolute right-3 top-1/2 transform -translate-y-1/2">
          <div className="w-4 h-4 border-2 border-blue-600 border-t-transparent rounded-full animate-spin" />
        </div>
      )}
    </div>
  ), [searchQuery, setSearchQuery, isSearching])

  // Memoized projects grid
  const projectsGrid = useMemo(() => {
    if (filteredProjects.length === 0) {
      return <EmptyState onCreateProject={() => setShowCreateDialog(true)} />
    }

    return (
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {filteredProjects.map((project, index) => (
          <motion.div
            key={project._id}
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6, delay: index * 0.1 }}
          >
            <OptimizedProjectCard
              project={project}
              onOpen={() => handleOpenProject(project._id)}
              onDelete={() => handleDeleteProject(project._id)}
            />
          </motion.div>
        ))}
      </div>
    )
  }, [filteredProjects, handleOpenProject, handleDeleteProject])

  if (loading) {
    return <LoadingFallback variant="page" />
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50 via-white to-purple-50 p-6">
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
          
          <Button
            onClick={() => setShowCreateDialog(true)}
            className="bg-gradient-to-r from-blue-600 to-purple-600 hover:from-blue-700 hover:to-purple-700"
          >
            <Plus className="mr-2 h-4 w-4" />
            Новый проект
          </Button>
        </motion.div>

        {/* Search and Filters */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6, delay: 0.1 }}
          className="flex flex-col md:flex-row gap-4 mb-8"
        >
          {searchInput}
          
          <Button variant="outline" onClick={loadProjects}>
            <RefreshCw className="mr-2 h-4 w-4" />
            Обновить
          </Button>
        </motion.div>

        {/* Projects Grid */}
        {projectsGrid}

        <CreateProjectDialog
          open={showCreateDialog}
          onOpenChange={setShowCreateDialog}
          onProjectCreated={handleProjectCreated}
        />
      </div>
    </div>
  )
}

// Optimized Chat Interface with debounced input
export function OptimizedChatInterface({ 
  projectId, 
  messages, 
  onNewMessage 
}: ChatInterfaceProps) {
  const [inputValue, setInputValue] = useState('')
  const [isTyping, setIsTyping] = useState(false)

  // Debounced typing indicator
  const debouncedSetTyping = useDebouncedCallback(
    (typing: boolean) => {
      setIsTyping(typing)
    },
    500
  )

  // Handle input change with debounced typing
  const handleInputChange = useCallback((value: string) => {
    setInputValue(value)
    debouncedSetTyping(value.length > 0)
  }, [debouncedSetTyping])

  // Memoized message list
  const messageList = useMemo(() => {
    return messages.map((message, index) => (
      <div
        key={message.id}
        className={`flex ${message.role === 'user' ? 'justify-end' : 'justify-start'} mb-4`}
      >
        <div
          className={`max-w-xs lg:max-w-md px-4 py-2 rounded-lg ${
            message.role === 'user'
              ? 'bg-blue-600 text-white'
              : 'bg-gray-200 text-gray-800'
          }`}
        >
          {message.content}
        </div>
      </div>
    ))
  }, [messages])

  return (
    <div className="h-full flex flex-col">
      {/* Messages */}
      <div className="flex-1 overflow-y-auto p-4">
        {messageList}
        {isTyping && (
          <div className="flex justify-start mb-4">
            <div className="bg-gray-200 text-gray-800 px-4 py-2 rounded-lg">
              <div className="flex space-x-1">
                <div className="w-2 h-2 bg-gray-400 rounded-full animate-bounce" />
                <div className="w-2 h-2 bg-gray-400 rounded-full animate-bounce" style={{ animationDelay: '0.1s' }} />
                <div className="w-2 h-2 bg-gray-400 rounded-full animate-bounce" style={{ animationDelay: '0.2s' }} />
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Input */}
      <div className="p-4 border-t">
        <div className="flex gap-2">
          <Input
            value={inputValue}
            onChange={(e) => handleInputChange(e.target.value)}
            placeholder="Введите сообщение..."
            className="flex-1"
            onKeyPress={(e) => {
              if (e.key === 'Enter' && inputValue.trim()) {
                // Handle send message
                setInputValue('')
                setIsTyping(false)
              }
            }}
          />
          <Button
            onClick={() => {
              if (inputValue.trim()) {
                // Handle send message
                setInputValue('')
                setIsTyping(false)
              }
            }}
            disabled={!inputValue.trim()}
          >
            Отправить
          </Button>
        </div>
      </div>
    </div>
  )
}

// Performance monitoring hook
export function usePerformanceMonitor(componentName: string) {
  useEffect(() => {
    const startTime = performance.now()
    
    return () => {
      const endTime = performance.now()
      const renderTime = endTime - startTime
      
      if (renderTime > 16) { // More than one frame (60fps)
        console.warn(`Slow render in ${componentName}: ${renderTime.toFixed(2)}ms`)
      }
    }
  }, [componentName])
}