import { useState, useEffect } from "react"
import { useParams } from "react-router-dom"
import { ResizablePanelGroup, ResizablePanel, ResizableHandle } from "@/components/ui/resizable"
import { ChatInterface } from "@/components/workspace/ChatInterface"
import { ProjectPreview } from "@/components/workspace/ProjectPreview"
import { WorkspaceHeader } from "@/components/workspace/WorkspaceHeader"
import { MobileWorkspace } from "@/components/workspace/MobileWorkspace"
import { getProject, type Project } from "@/api/projects"
// import { getChatMessages, type ChatMessage } from "@/api/chat"

// Временный тип для чата
interface ChatMessage {
  id: string
  content: string
  role: 'user' | 'assistant'
  timestamp: string
}
import { useToast } from "@/hooks/useToast"
import { useMobile } from "@/hooks/useMobile"

export function Workspace() {
  const { projectId } = useParams<{ projectId: string }>()
  const { toast } = useToast()
  const isMobile = useMobile()
  
  const [project, setProject] = useState<Project | null>(null)
  const [messages, setMessages] = useState<ChatMessage[]>([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    if (projectId) {
      loadWorkspaceData()
    }
  }, [projectId]) // eslint-disable-line react-hooks/exhaustive-deps

  const loadWorkspaceData = async () => {
    if (!projectId) return

    try {
      setLoading(true)
      
      const projectResponse = await getProject(projectId)
      
      setProject(projectResponse.project)
      // Временно пустой массив сообщений
      setMessages([])
      
        project: projectResponse.project.name,
        messagesCount: 0
      })
    } catch (error) {
      console.error('Error loading workspace data:', error)
      toast({
        title: "Ошибка",
        description: "Не удалось загрузить данные проекта",
        variant: "destructive"
      })
    } finally {
      setLoading(false)
    }
  }

  const handleNewMessage = (userMessage: ChatMessage, assistantMessage: ChatMessage) => {
    setMessages(prev => [...prev, userMessage, assistantMessage])
  }

  if (loading) {
    return (
      <div className="h-screen bg-gradient-to-br from-blue-50 via-white to-purple-50 flex items-center justify-center">
        <div className="text-center">
          <div className="w-8 h-8 border-4 border-blue-600 border-t-transparent rounded-full animate-spin mx-auto mb-4"></div>
          <p className="text-muted-foreground">Загрузка проекта...</p>
        </div>
      </div>
    )
  }

  if (!project) {
    return (
      <div className="h-screen bg-gradient-to-br from-blue-50 via-white to-purple-50 flex items-center justify-center">
        <div className="text-center">
          <p className="text-muted-foreground">Проект не найден</p>
        </div>
      </div>
    )
  }

  if (isMobile) {
    return (
      <MobileWorkspace
        project={project}
        messages={messages}
        onNewMessage={handleNewMessage}
      />
    )
  }

  return (
    <div className="h-screen bg-gradient-to-br from-blue-50 via-white to-purple-50">
      <WorkspaceHeader project={project} />
      
      <div className="h-[calc(100vh-4rem)] pt-16">
        <ResizablePanelGroup direction="horizontal">
          <ResizablePanel defaultSize={35} minSize={25} maxSize={50}>
            <ChatInterface
              projectId={project._id}
              messages={messages}
              onNewMessage={handleNewMessage}
            />
          </ResizablePanel>
          
          <ResizableHandle withHandle />
          
          <ResizablePanel defaultSize={65} minSize={50}>
            <ProjectPreview project={project} />
          </ResizablePanel>
        </ResizablePanelGroup>
      </div>
    </div>
  )
}