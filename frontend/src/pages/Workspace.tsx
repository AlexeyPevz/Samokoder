import { useState, useEffect } from "react"
import { useParams } from "react-router-dom"
import { ResizablePanelGroup, ResizablePanel, ResizableHandle } from "@/components/ui/resizable"
import ChatInterface from "@/components/workspace/ChatInterface"
import ProjectPreview from "@/components/workspace/ProjectPreview"
import { WorkspaceHeader } from "@/components/workspace/WorkspaceHeader"
import { MobileWorkspace } from "@/components/workspace/MobileWorkspace"
import { ProviderSelector } from "@/components/workspace/ProviderSelector"
import { getProject, type Project } from "@/api/projects"
import { type ChatMessage } from "@/api/chat"
import { useToast } from "@/hooks/useToast"
import { useMobile } from "@/hooks/useMobile"
import { workspaceSocket } from "@/api/workspace"

export default function Workspace() {
  const { projectId } = useParams<{ projectId: string }>()
  const { toast } = useToast()
  const isMobile = useMobile()
  
  const [project, setProject] = useState<Project | null>(null)
  const [messages, setMessages] = useState<ChatMessage[]>([])
  const [loading, setLoading] = useState(true)
  const [showProviderSelector, setShowProviderSelector] = useState(false)
  const [buildLogs, setBuildLogs] = useState<string>("")
  const [buildStatus, setBuildStatus] = useState<"success" | "error" | "building" | "unknown">("unknown")
  const [isFixing, setIsFixing] = useState(false)

  useEffect(() => {
    if (projectId) {
      loadWorkspaceData()

      // Establish WebSocket connection
      workspaceSocket.connect(projectId, (message: any) => {
        // Handle different types of messages from WebSocket
        if (message.type === "message") {
          // Add message to chat
          const chatMessage: ChatMessage = {
            id: Date.now().toString(),
            content: message.content,
            role: message.source === "system" ? "system" : "assistant",
            timestamp: new Date().toISOString(),
          }
          setMessages(prev => [...prev, chatMessage])
        } else if (message.type === "project_stage") {
          // Handle project stage updates
          // Project stage updated
        } else if (message.type === "question") {
          // Handle questions from Samokoder
          // Question received from Samokoder
        } else if (message.type === "process_output") {
          setBuildLogs(prev => prev + message.data)
          setBuildStatus("building")
        } else if (message.type === "process_status") {
          setBuildStatus(message.status_code === 0 ? "success" : "error")
          setIsFixing(false)
        }
      })

      // Cleanup WebSocket on component unmount
      return () => {
        workspaceSocket.disconnect()
      }
    }
  }, [projectId]) // eslint-disable-line react-hooks/exhaustive-deps

  const loadWorkspaceData = async () => {
    if (!projectId) return

    try {
      setLoading(true)
      
      const projectData = await getProject(projectId)
      
      setProject(projectData)
      // Временно пустой массив сообщений
      setMessages([])
    } catch (error) {
      // Error loading workspace data
      toast({
        title: "Ошибка",
        description: "Не удалось загрузить данные проекта",
        variant: "destructive"
      })
    } finally {
      setLoading(false)
    }
  }

  const handleNewMessage = (userMessage: ChatMessage) => {
    setMessages(prev => [...prev, userMessage])
    const payload = JSON.stringify({
      type: "chat",
      content: userMessage.content
    })
    workspaceSocket.sendMessage(payload)
  }

  const handleSendCommand = (command: string, commandPayload?: any) => {
    const payload = JSON.stringify({
      type: "command",
      name: command,
      payload: commandPayload
    })
    workspaceSocket.sendMessage(payload)
  }

  const clearBuildLogs = () => {
    setBuildLogs("");
  }

  if (loading) {
    return (
      <div className="h-screen bg-gradient-to-br from-primary-50 via-white to-secondary-50 flex items-center justify-center">
        <div className="text-center">
          <div className="w-8 h-8 border-4 border-primary border-t-transparent rounded-full animate-spin mx-auto mb-4"></div>
          <p className="text-muted-foreground">Загрузка проекта...</p>
        </div>
      </div>
    )
  }

  if (!project) {
    return (
      <div className="h-screen bg-gradient-to-br from-primary-50 via-white to-secondary-50 flex items-center justify-center">
        <div className="text-center">
          <p className="text-muted-foreground">Проект не найден</p>
        </div>
      </div>
    )
  }

  if (showProviderSelector) {
    return (
      <div className="h-screen bg-gradient-to-br from-primary-50 via-white to-secondary-50">
        <div className="h-full flex flex-col">
          {/* Header with back button */}
          <div className="p-4 border-b bg-white/80 backdrop-blur-sm">
            <div className="flex items-center justify-between">
              <h1 className="font-semibold text-lg">{project.name}</h1>
              <button 
                onClick={() => setShowProviderSelector(false)}
                className="text-primary hover:text-primary/80"
              >
                Назад к проекту
              </button>
            </div>
          </div>
          
          {/* Provider selector content */}
          <div className="flex-1 overflow-auto p-4">
            <ProviderSelector />
          </div>
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
        onSendCommand={handleSendCommand}
        buildLogs={buildLogs}
        buildStatus={buildStatus}
        isFixing={isFixing}
        onClearLogs={clearBuildLogs}
      />
    )
  }

  return (
    <div className="h-screen bg-gradient-to-br from-primary-50 via-white to-secondary-50">
      <WorkspaceHeader project={project} onShowProviderSelector={() => setShowProviderSelector(true)} />
      
      <div className="h-[calc(100vh-4rem)] pt-16">
        <ResizablePanelGroup direction="horizontal">
          <ResizablePanel defaultSize={35} minSize={25} maxSize={50}>
            <ChatInterface
              projectId={project.id}
              messages={messages}
              onNewMessage={handleNewMessage}
              onSendCommand={handleSendCommand}
            />
          </ResizablePanel>
          
          <ResizableHandle withHandle />
          
          <ResizablePanel defaultSize={65} minSize={50}>
            <ProjectPreview 
              project={project} 
              onSendCommand={handleSendCommand} 
              buildLogs={buildLogs} 
              buildStatus={buildStatus}
              isFixing={isFixing}
              onClearLogs={clearBuildLogs}
            />
          </ResizablePanel>
        </ResizablePanelGroup>
      </div>
    </div>
  )
}