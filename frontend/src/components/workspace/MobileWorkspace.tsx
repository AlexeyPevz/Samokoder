import { useState } from "react"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Button } from "@/components/ui/button"
import { MessageCircle, Eye, ArrowLeft } from "lucide-react"
import { useNavigate } from "react-router-dom"
import { ChatInterface } from "./ChatInterface"
import { ProjectPreview } from "./ProjectPreview"
import { Project } from "@/api/projects"
import { ChatMessage } from "@/api/chat"

interface MobileWorkspaceProps {
  project: Project
  messages: ChatMessage[]
  onNewMessage: (userMessage: ChatMessage, assistantMessage: ChatMessage) => void
}

export function MobileWorkspace({ project, messages, onNewMessage }: MobileWorkspaceProps) {
  const navigate = useNavigate()
  const [activeTab, setActiveTab] = useState("chat")

  return (
    <div className="h-screen bg-gradient-to-br from-blue-50 via-white to-purple-50">
      {/* Mobile Header */}
      <div className="fixed top-0 z-50 w-full bg-white/90 backdrop-blur-sm border-b">
        <div className="flex items-center justify-between p-4">
          <Button
            variant="ghost"
            size="icon"
            onClick={() => navigate("/dashboard")}
          >
            <ArrowLeft className="h-5 w-5" />
          </Button>

          <div className="text-center">
            <h1 className="font-semibold text-sm">{project.name}</h1>
            <p className="text-xs text-muted-foreground">
              {project.status === 'ready' ? 'Готов' : project.status === 'creating' ? 'Создается' : 'Ошибка'}
            </p>
          </div>

          <div className="w-10" /> {/* Spacer */}
        </div>
      </div>

      {/* Content */}
      <div className="pt-20 pb-20 h-full">
        <Tabs value={activeTab} onValueChange={setActiveTab} className="h-full">
          <TabsContent value="chat" className="h-full m-0">
            <ChatInterface
              projectId={project._id}
              messages={messages}
              onNewMessage={onNewMessage}
            />
          </TabsContent>

          <TabsContent value="preview" className="h-full m-0">
            <ProjectPreview project={project} />
          </TabsContent>
        </Tabs>
      </div>

      {/* Bottom Navigation */}
      <div className="fixed bottom-0 w-full bg-white/90 backdrop-blur-sm border-t">
        <TabsList className="grid w-full grid-cols-2 bg-transparent">
          <TabsTrigger
            value="chat"
            className="flex items-center gap-2 data-[state=active]:bg-blue-100 data-[state=active]:text-blue-700"
          >
            <MessageCircle className="h-4 w-4" />
            Чат
          </TabsTrigger>
          <TabsTrigger
            value="preview"
            className="flex items-center gap-2 data-[state=active]:bg-blue-100 data-[state=active]:text-blue-700"
          >
            <Eye className="h-4 w-4" />
            Превью
          </TabsTrigger>
        </TabsList>
      </div>
    </div>
  )
}