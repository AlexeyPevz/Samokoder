/**
 * ОПТИМИЗАЦИЯ 1: Lazy Loading + Code Splitting
 * Цель: Улучшить LCP (Largest Contentful Paint) с 3.2с до 2.1с
 * 
 * Проблемы:
 * - Все компоненты загружаются сразу
 * - Большие bundle размеры
 * - Блокирующая загрузка страниц
 */

import { lazy, Suspense, ComponentType } from 'react'
import { Skeleton } from '@/components/ui/skeleton'

// Lazy loading для страниц
export const LazyHome = lazy(() => import('@/pages/Home'))
export const LazyDashboard = lazy(() => import('@/pages/Dashboard'))
export const LazyWorkspace = lazy(() => import('@/pages/Workspace'))
export const LazySettings = lazy(() => import('@/pages/Settings'))
export const LazyLogin = lazy(() => import('@/pages/Login'))
export const LazyRegister = lazy(() => import('@/pages/Register'))

// Lazy loading для тяжелых компонентов
export const LazyProjectCard = lazy(() => import('@/components/dashboard/ProjectCard'))
export const LazyCreateProjectDialog = lazy(() => import('@/components/dashboard/CreateProjectDialog'))
export const LazyChatInterface = lazy(() => import('@/components/workspace/ChatInterface'))
export const LazyProjectPreview = lazy(() => import('@/components/workspace/ProjectPreview'))

// Универсальный компонент загрузки с skeleton
interface LoadingFallbackProps {
  variant?: 'page' | 'card' | 'component'
  className?: string
}

export function LoadingFallback({ variant = 'component', className = '' }: LoadingFallbackProps) {
  switch (variant) {
    case 'page':
      return (
        <div className={`min-h-screen bg-gradient-to-br from-blue-50 via-white to-purple-50 p-6 ${className}`}>
          <div className="mx-auto max-w-6xl">
            <div className="space-y-6">
              {/* Header skeleton */}
              <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
                <div className="space-y-2">
                  <Skeleton className="h-8 w-64" />
                  <Skeleton className="h-4 w-96" />
                </div>
                <Skeleton className="h-10 w-32" />
              </div>
              
              {/* Search skeleton */}
              <div className="flex gap-4">
                <Skeleton className="h-10 flex-1" />
                <Skeleton className="h-10 w-24" />
              </div>
              
              {/* Grid skeleton */}
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                {[...Array(6)].map((_, i) => (
                  <div key={i} className="space-y-3">
                    <Skeleton className="h-48 w-full rounded-lg" />
                    <div className="space-y-2">
                      <Skeleton className="h-4 w-3/4" />
                      <Skeleton className="h-3 w-1/2" />
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      )
      
    case 'card':
      return (
        <div className={`space-y-3 ${className}`}>
          <Skeleton className="h-48 w-full rounded-lg" />
          <div className="space-y-2">
            <Skeleton className="h-4 w-3/4" />
            <Skeleton className="h-3 w-1/2" />
            <Skeleton className="h-8 w-full" />
          </div>
        </div>
      )
      
    default:
      return (
        <div className={`flex items-center justify-center p-4 ${className}`}>
          <div className="w-6 h-6 border-2 border-blue-600 border-t-transparent rounded-full animate-spin" />
        </div>
      )
  }
}

// HOC для lazy loading с fallback
export function withLazyLoading<T extends object>(
  Component: ComponentType<T>,
  fallbackVariant: LoadingFallbackProps['variant'] = 'component'
) {
  return function LazyComponent(props: T) {
    return (
      <Suspense fallback={<LoadingFallback variant={fallbackVariant} />}>
        <Component {...props} />
      </Suspense>
    )
  }
}

// Оптимизированный роутер с lazy loading
export function OptimizedAppRoutes() {
  return (
    <Routes>
      <Route 
        path="/login" 
        element={
          <Suspense fallback={<LoadingFallback variant="page" />}>
            <LazyLogin />
          </Suspense>
        } 
      />
      <Route 
        path="/register" 
        element={
          <Suspense fallback={<LoadingFallback variant="page" />}>
            <LazyRegister />
          </Suspense>
        } 
      />
      <Route path="/" element={<ProtectedRoute><Layout /></ProtectedRoute>}>
        <Route 
          index 
          element={
            <Suspense fallback={<LoadingFallback variant="page" />}>
              <LazyHome />
            </Suspense>
          } 
        />
        <Route 
          path="dashboard" 
          element={
            <Suspense fallback={<LoadingFallback variant="page" />}>
              <LazyDashboard />
            </Suspense>
          } 
        />
        <Route 
          path="workspace/:projectId" 
          element={
            <Suspense fallback={<LoadingFallback variant="page" />}>
              <LazyWorkspace />
            </Suspense>
          } 
        />
        <Route 
          path="settings" 
          element={
            <Suspense fallback={<LoadingFallback variant="page" />}>
              <LazySettings />
            </Suspense>
          } 
        />
      </Route>
      <Route path="*" element={<BlankPage />} />
    </Routes>
  )
}

// Оптимизированный Dashboard с lazy loading компонентов
export function OptimizedDashboard() {
  const [projects, setProjects] = useState<Project[]>([])
  const [loading, setLoading] = useState(true)
  const [searchQuery, setSearchQuery] = useState("")
  const [showCreateDialog, setShowCreateDialog] = useState(false)

  // Lazy loading для диалога создания проекта
  const CreateProjectDialogLazy = useMemo(() => 
    withLazyLoading(LazyCreateProjectDialog, 'component'), 
    []
  )

  // ... остальная логика Dashboard

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
          <div className="relative flex-1">
            <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-muted-foreground" />
            <Input
              placeholder="Поиск проектов..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="pl-10"
            />
          </div>
          
          <Button variant="outline" onClick={loadProjects}>
            <RefreshCw className="mr-2 h-4 w-4" />
            Обновить
          </Button>
        </motion.div>

        {/* Projects Grid with Lazy Loading */}
        {filteredProjects.length === 0 ? (
          <EmptyState onCreateProject={() => setShowCreateDialog(true)} />
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            {filteredProjects.map((project, index) => (
              <motion.div
                key={project._id}
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.6, delay: index * 0.1 }}
              >
                <Suspense fallback={<LoadingFallback variant="card" />}>
                  <LazyProjectCard
                    project={project}
                    onOpen={() => navigate(`/workspace/${project._id}`)}
                    onDelete={() => handleDeleteProject(project._id)}
                  />
                </Suspense>
              </motion.div>
            ))}
          </div>
        )}

        {/* Lazy Create Project Dialog */}
        {showCreateDialog && (
          <CreateProjectDialogLazy
            open={showCreateDialog}
            onOpenChange={setShowCreateDialog}
            onProjectCreated={(project) => {
              setProjects([project, ...projects])
              navigate(`/workspace/${project._id}`)
            }}
          />
        )}
      </div>
    </div>
  )
}

// Оптимизированный Workspace с lazy loading
export function OptimizedWorkspace() {
  const { projectId } = useParams<{ projectId: string }>()
  const [project, setProject] = useState<Project | null>(null)
  const [messages, setMessages] = useState<ChatMessage[]>([])
  const [loading, setLoading] = useState(true)

  // Lazy loading для тяжелых компонентов
  const ChatInterfaceLazy = useMemo(() => 
    withLazyLoading(LazyChatInterface, 'component'), 
    []
  )
  
  const ProjectPreviewLazy = useMemo(() => 
    withLazyLoading(LazyProjectPreview, 'component'), 
    []
  )

  // ... остальная логика Workspace

  return (
    <div className="h-screen bg-gradient-to-br from-blue-50 via-white to-purple-50">
      <WorkspaceHeader project={project} />
      
      <div className="h-[calc(100vh-4rem)] pt-16">
        <ResizablePanelGroup direction="horizontal">
          <ResizablePanel defaultSize={35} minSize={25} maxSize={50}>
            <Suspense fallback={<LoadingFallback variant="component" />}>
              <ChatInterfaceLazy
                projectId={project._id}
                messages={messages}
                onNewMessage={handleNewMessage}
              />
            </Suspense>
          </ResizablePanel>
          
          <ResizableHandle withHandle />
          
          <ResizablePanel defaultSize={65} minSize={50}>
            <Suspense fallback={<LoadingFallback variant="component" />}>
              <ProjectPreviewLazy project={project} />
            </Suspense>
          </ResizablePanel>
        </ResizablePanelGroup>
      </div>
    </div>
  )
}