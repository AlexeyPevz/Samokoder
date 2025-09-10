/**
 * ОПТИМИЗАЦИЯ 3: Layout Stability + GPU Acceleration
 * Цель: Улучшить CLS (Cumulative Layout Shift) с 0.15 до 0.08
 * 
 * Проблемы:
 * - Отсутствие фиксированных размеров для изображений
 * - Динамическая загрузка контента без резервирования места
 * - Анимации без GPU ускорения
 * - Отсутствие skeleton loading
 */

import { useState, useEffect, useMemo, useRef } from 'react'
import { motion, useMotionValue, useTransform } from 'framer-motion'

// Skeleton loading components with fixed dimensions
export function ProjectCardSkeleton() {
  return (
    <div className="bg-white/80 backdrop-blur-sm border-0 shadow-md rounded-lg p-6">
      {/* Fixed height for header */}
      <div className="pb-3 mb-4">
        <div className="flex items-start justify-between">
          <div className="flex-1">
            {/* Fixed height for title */}
            <div className="h-6 bg-gray-200 rounded w-3/4 mb-2 animate-pulse" />
            {/* Fixed height for description */}
            <div className="h-4 bg-gray-200 rounded w-1/2 animate-pulse" />
          </div>
          {/* Fixed size for menu button */}
          <div className="h-8 w-8 bg-gray-200 rounded animate-pulse" />
        </div>
      </div>

      {/* Fixed height for thumbnail */}
      <div className="h-32 bg-gray-200 rounded-lg mb-4 animate-pulse" />

      {/* Fixed height for status section */}
      <div className="space-y-3">
        <div className="flex items-center justify-between">
          {/* Fixed height for badge */}
          <div className="h-6 bg-gray-200 rounded w-20 animate-pulse" />
          {/* Fixed height for date */}
          <div className="h-4 bg-gray-200 rounded w-16 animate-pulse" />
        </div>
        
        {/* Fixed height for button */}
        <div className="h-10 bg-gray-200 rounded animate-pulse" />
      </div>
    </div>
  )
}

// Optimized image component with fixed dimensions
interface OptimizedImageProps {
  src?: string
  alt: string
  width: number
  height: number
  className?: string
  fallback?: React.ReactNode
}

export function OptimizedImage({ 
  src, 
  alt, 
  width, 
  height, 
  className = '', 
  fallback 
}: OptimizedImageProps) {
  const [loaded, setLoaded] = useState(false)
  const [error, setError] = useState(false)

  // Reserve space with fixed dimensions
  const imageStyle = {
    width: `${width}px`,
    height: `${height}px`,
    aspectRatio: `${width}/${height}`
  }

  if (error || !src) {
    return (
      <div 
        style={imageStyle}
        className={`bg-gradient-to-br from-gray-100 to-gray-200 rounded-lg flex items-center justify-center ${className}`}
      >
        {fallback || (
          <div className="text-4xl font-bold text-gray-300">
            {alt.charAt(0)}
          </div>
        )}
      </div>
    )
  }

  return (
    <div style={imageStyle} className={`relative overflow-hidden rounded-lg ${className}`}>
      {!loaded && (
        <div className="absolute inset-0 bg-gray-200 animate-pulse" />
      )}
      <img
        src={src}
        alt={alt}
        width={width}
        height={height}
        className={`w-full h-full object-cover transition-opacity duration-300 ${
          loaded ? 'opacity-100' : 'opacity-0'
        }`}
        onLoad={() => setLoaded(true)}
        onError={() => setError(true)}
        loading="lazy"
        decoding="async"
      />
    </div>
  )
}

// GPU-accelerated animations
export function GPUAcceleratedCard({ children, className = '' }: { 
  children: React.ReactNode
  className?: string 
}) {
  const cardRef = useRef<HTMLDivElement>(null)
  
  // Use transform3d for GPU acceleration
  const hoverStyle = {
    transform: 'translate3d(0, -4px, 0)',
    boxShadow: '0 20px 25px -5px rgba(0, 0, 0, 0.1), 0 10px 10px -5px rgba(0, 0, 0, 0.04)'
  }

  return (
    <motion.div
      ref={cardRef}
      className={`transition-all duration-200 bg-white/80 backdrop-blur-sm border-0 shadow-md rounded-lg ${className}`}
      whileHover={hoverStyle}
      style={{
        willChange: 'transform, box-shadow',
        backfaceVisibility: 'hidden',
        perspective: '1000px'
      }}
    >
      {children}
    </motion.div>
  )
}

// Optimized ProjectCard with layout stability
export function LayoutStableProjectCard({ 
  project, 
  onOpen, 
  onDelete 
}: ProjectCardProps) {
  // Memoized status configuration
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

  return (
    <GPUAcceleratedCard>
      <div className="p-6">
        {/* Header with fixed heights */}
        <div className="pb-3 mb-4">
          <div className="flex items-start justify-between">
            <div className="flex-1 min-w-0">
              {/* Fixed height for title */}
              <h3 className="text-lg font-semibold mb-1 line-clamp-1 h-6">
                {project.name}
              </h3>
              {/* Fixed height for description */}
              <p className="text-sm text-muted-foreground line-clamp-2 h-8">
                {project.description}
              </p>
            </div>
            
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button variant="ghost" size="icon" className="h-8 w-8 flex-shrink-0">
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
        </div>

        {/* Fixed size thumbnail */}
        <div className="mb-4">
          <OptimizedImage
            src={project.thumbnailUrl}
            alt={project.name}
            width={300}
            height={128}
            fallback={
              <div className="text-4xl font-bold text-gray-300">
                {project.name.charAt(0)}
              </div>
            }
          />
        </div>

        {/* Status section with fixed heights */}
        <div className="space-y-3">
          <div className="flex items-center justify-between h-6">
            <Badge className={`${statusConfig.color} flex items-center gap-1 h-6`}>
              {statusConfig.icon}
              {statusConfig.text}
            </Badge>
            <span className="text-xs text-muted-foreground h-4">
              {formattedDate}
            </span>
          </div>

          {project.status === 'creating' && (
            <div className="space-y-1">
              <div className="flex justify-between text-xs h-4">
                <span>Прогресс</span>
                <span>{project.progress}%</span>
              </div>
              <Progress value={project.progress} className="h-2" />
            </div>
          )}

          {/* Fixed height button */}
          <Button
            onClick={onOpen}
            className="w-full h-10"
            variant={project.status === 'ready' ? 'default' : 'outline'}
            disabled={project.status === 'error'}
          >
            {project.status === 'creating' && (
              <>
                <RefreshCw className="mr-2 h-4 w-4 animate-spin" />
                Создается...
              </>
            )}
            {project.status === 'ready' && (
              <>
                <Play className="mr-2 h-4 w-4" />
                Открыть
              </>
            )}
            {project.status === 'error' && (
              <>
                <AlertCircle className="mr-2 h-4 w-4" />
                Попробовать снова
              </>
            )}
          </Button>
        </div>
      </div>
    </GPUAcceleratedCard>
  )
}

// Optimized Dashboard with layout stability
export function LayoutStableDashboard() {
  const [projects, setProjects] = useState<Project[]>([])
  const [loading, setLoading] = useState(true)
  const [searchQuery, setSearchQuery] = useState("")

  // Memoized filtered projects
  const filteredProjects = useMemo(() => {
    if (!searchQuery.trim()) return projects
    const lowercaseQuery = searchQuery.toLowerCase()
    return projects.filter(project =>
      project?.name?.toLowerCase().includes(lowercaseQuery) ||
      project?.description?.toLowerCase().includes(lowercaseQuery)
    )
  }, [projects, searchQuery])

  // Load projects
  useEffect(() => {
    const loadProjects = async () => {
      try {
        setLoading(true)
        const response = await getProjects()
        setProjects(response.projects)
      } catch (error) {
        console.error('Error loading projects:', error)
      } finally {
        setLoading(false)
      }
    }
    loadProjects()
  }, [])

  if (loading) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-blue-50 via-white to-purple-50 p-6">
        <div className="mx-auto max-w-6xl">
          {/* Header skeleton with fixed heights */}
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 mb-8">
            <div className="space-y-2">
              <div className="h-8 bg-gray-200 rounded w-64 animate-pulse" />
              <div className="h-4 bg-gray-200 rounded w-96 animate-pulse" />
            </div>
            <div className="h-10 bg-gray-200 rounded w-32 animate-pulse" />
          </div>
          
          {/* Search skeleton with fixed height */}
          <div className="flex gap-4 mb-8">
            <div className="h-10 bg-gray-200 rounded flex-1 animate-pulse" />
            <div className="h-10 bg-gray-200 rounded w-24 animate-pulse" />
          </div>
          
          {/* Grid skeleton with fixed card dimensions */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            {[...Array(6)].map((_, i) => (
              <ProjectCardSkeleton key={i} />
            ))}
          </div>
        </div>
      </div>
    )
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50 via-white to-purple-50 p-6">
      <div className="mx-auto max-w-6xl">
        {/* Header with fixed heights */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6 }}
          className="flex flex-col md:flex-row md:items-center justify-between gap-4 mb-8"
        >
          <div>
            <h1 className="text-3xl font-bold mb-2 h-8">Мои проекты</h1>
            <p className="text-muted-foreground h-4">
              Управляйте своими приложениями и создавайте новые
            </p>
          </div>
          
          <Button
            onClick={() => setShowCreateDialog(true)}
            className="bg-gradient-to-r from-blue-600 to-purple-600 hover:from-blue-700 hover:to-purple-700 h-10"
          >
            <Plus className="mr-2 h-4 w-4" />
            Новый проект
          </Button>
        </motion.div>

        {/* Search with fixed height */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6, delay: 0.1 }}
          className="flex flex-col md:flex-row gap-4 mb-8"
        >
          <div className="relative flex-1">
            <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-muted-foreground" />
            <Input
              placeholder="Поиск проектов..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="pl-10 h-10"
            />
          </div>
          
          <Button variant="outline" className="h-10">
            <RefreshCw className="mr-2 h-4 w-4" />
            Обновить
          </Button>
        </motion.div>

        {/* Projects Grid with stable layout */}
        {filteredProjects.length === 0 ? (
          <EmptyState onCreateProject={() => setShowCreateDialog(true)} />
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            {filteredProjects.map((project, index) => (
              <motion.div
                key={project._id}
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ 
                  duration: 0.6, 
                  delay: index * 0.1,
                  ease: "easeOut"
                }}
                style={{
                  willChange: 'transform, opacity'
                }}
              >
                <LayoutStableProjectCard
                  project={project}
                  onOpen={() => navigate(`/workspace/${project._id}`)}
                  onDelete={() => handleDeleteProject(project._id)}
                />
              </motion.div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}

// Optimized ResizablePanel with layout stability
export function LayoutStableResizablePanel({ 
  children, 
  defaultSize, 
  minSize, 
  maxSize 
}: ResizablePanelProps) {
  const panelRef = useRef<HTMLDivElement>(null)
  
  return (
    <ResizablePanel
      ref={panelRef}
      defaultSize={defaultSize}
      minSize={minSize}
      maxSize={maxSize}
      style={{
        minHeight: '400px', // Prevent layout shift
        willChange: 'width'
      }}
    >
      <div className="h-full overflow-hidden">
        {children}
      </div>
    </ResizablePanel>
  )
}

// CSS for GPU acceleration
export const gpuAccelerationStyles = `
  .gpu-accelerated {
    transform: translateZ(0);
    backface-visibility: hidden;
    perspective: 1000px;
    will-change: transform;
  }
  
  .stable-layout {
    contain: layout style paint;
  }
  
  .smooth-animation {
    transition: transform 0.2s cubic-bezier(0.4, 0, 0.2, 1);
  }
  
  .prevent-layout-shift {
    min-height: 200px;
    contain: size;
  }
`