import { useState } from "react"
import { Button } from "@/components/ui/button"
import { Card, CardContent } from "@/components/ui/card"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { MessageCircle, Monitor, Wrench } from "lucide-react"
import ChatInterface from "@/components/workspace/ChatInterface"
import ProjectPreview from "@/components/workspace/ProjectPreview"
import { type Project } from "@/api/projects"
import { type ChatMessage } from "@/api/chat"

interface MobileWorkspaceProps {
  project: Project;
  messages: ChatMessage[];
  onNewMessage: (userMessage: ChatMessage) => void;
  onSendCommand: (command: string, payload?: any) => void;
  buildLogs: string;
  buildStatus: "success" | "error" | "building" | "unknown";
  isFixing: boolean;
  onClearLogs: () => void;
}

export function MobileWorkspace({ 
  project, 
  messages, 
  onNewMessage, 
  onSendCommand, 
  buildLogs, 
  buildStatus, 
  isFixing, 
  onClearLogs 
}: MobileWorkspaceProps) {
  const [activeTab, setActiveTab] = useState<"chat" | "preview">("chat")

  return (
    <div className="h-screen flex flex-col bg-gradient-to-br from-primary-50 via-white to-secondary-50">
      {/* Header */}
      <div className="p-4 border-b bg-white/80 backdrop-blur-sm">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="font-semibold text-lg truncate max-w-[200px]">{project.name}</h1>
            <p className="text-xs text-muted-foreground">Мобильная версия</p>
          </div>
          <div className="flex gap-2">
            <Button
              variant={activeTab === "chat" ? "default" : "outline"}
              size="sm"
              onClick={() => setActiveTab("chat")}
            >
              <MessageCircle className="h-4 w-4" />
            </Button>
            <Button
              variant={activeTab === "preview" ? "default" : "outline"}
              size="sm"
              onClick={() => setActiveTab("preview")}
            >
              <Monitor className="h-4 w-4" />
            </Button>
          </div>
        </div>
      </div>

      {/* Content */}
      <div className="flex-1 overflow-hidden">
        {activeTab === "chat" ? (
          <div className="h-full flex flex-col">
            <div className="flex-1 overflow-hidden">
              <ChatInterface
                projectId={project.id}
                messages={messages}
                onNewMessage={onNewMessage}
                onSendCommand={onSendCommand}
              />
            </div>
          </div>
        ) : (
          <div className="h-full">
            <ProjectPreview 
              project={project} 
              onSendCommand={onSendCommand} 
              buildLogs={buildLogs} 
              buildStatus={buildStatus}
              isFixing={isFixing}
              onClearLogs={onClearLogs}
            />
          </div>
        )}
      </div>

      {/* Quick Actions */}
      <div className="p-4 border-t bg-white/80 backdrop-blur-sm">
        <div className="flex gap-2">
          <Button variant="outline" className="flex-1">
            <Wrench className="h-4 w-4 mr-2" />
            Исправить
          </Button>
          <Button className="flex-1">Новый чат</Button>
        </div>
      </div>
    </div>
  )
}