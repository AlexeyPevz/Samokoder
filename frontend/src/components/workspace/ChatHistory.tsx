import { useState, useEffect } from "react"
import { Button } from "@/components/ui/button"
import { ScrollArea } from "@/components/ui/scroll-area"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog"
import { formatDistanceToNow } from "date-fns"
import { ru } from "date-fns/locale"
import { MessageCircle, Plus, Trash2 } from "lucide-react"
import { ChatSession, chatHistoryService } from "@/services/chatHistory"
import { ChatMessage } from "@/api/chat"

interface ChatHistoryProps {
  projectId: string
  currentSessionId?: string
  onSessionSelect: (session: ChatSession) => void
  onNewSession: () => void
}

export function ChatHistory({ projectId, currentSessionId, onSessionSelect, onNewSession }: ChatHistoryProps) {
  const [sessions, setSessions] = useState<ChatSession[]>([])
  const [isOpen, setIsOpen] = useState(false)

  useEffect(() => {
    loadSessions()
  }, [projectId])

  const loadSessions = () => {
    const projectSessions = chatHistoryService.getSessions(projectId)
    setSessions(projectSessions)
  }

  const handleNewSession = () => {
    onNewSession()
    setIsOpen(false)
  }

  const handleSessionSelect = (session: ChatSession) => {
    onSessionSelect(session)
    setIsOpen(false)
  }

  const handleDeleteSession = (sessionId: string, e: React.MouseEvent) => {
    e.stopPropagation()
    chatHistoryService.deleteSession(sessionId)
    loadSessions()
    
    // If we deleted the current session, create a new one
    if (sessionId === currentSessionId) {
      onNewSession()
    }
  }

  const formatTime = (timestamp: string) => {
    try {
      return formatDistanceToNow(new Date(timestamp), { 
        addSuffix: true, 
        locale: ru 
      })
    } catch {
      return 'недавно'
    }
  }

  return (
    <Dialog open={isOpen} onOpenChange={setIsOpen}>
      <DialogTrigger asChild>
        <Button variant="outline" size="sm">
          <MessageCircle className="h-4 w-4 mr-2" />
          История чатов
        </Button>
      </DialogTrigger>
      <DialogContent className="max-w-md">
        <DialogHeader>
          <DialogTitle>История чатов</DialogTitle>
        </DialogHeader>
        
        <div className="space-y-4">
          <Button onClick={handleNewSession} className="w-full">
            <Plus className="h-4 w-4 mr-2" />
            Новая сессия
          </Button>
          
          <ScrollArea className="h-[300px]">
            {sessions.length === 0 ? (
              <div className="text-center py-8 text-muted-foreground">
                <MessageCircle className="h-12 w-12 mx-auto mb-2 opacity-50" />
                <p>Нет сохраненных сессий</p>
              </div>
            ) : (
              <div className="space-y-2">
                {sessions.map((session) => (
                  <Card 
                    key={session.id}
                    className={`cursor-pointer transition-colors ${
                      session.id === currentSessionId 
                        ? "border-blue-500 bg-blue-50" 
                        : "hover:bg-gray-50"
                    }`}
                    onClick={() => handleSessionSelect(session)}
                  >
                    <CardHeader className="p-4">
                      <div className="flex items-start justify-between">
                        <CardTitle className="text-sm font-medium line-clamp-2">
                          {session.title}
                        </CardTitle>
                        {session.id === currentSessionId && (
                          <Badge variant="default" className="text-xs">
                            Текущая
                          </Badge>
                        )}
                      </div>
                      <div className="flex items-center justify-between mt-2">
                        <p className="text-xs text-muted-foreground">
                          {session.messages.length} сообщений
                        </p>
                        <div className="flex items-center gap-2">
                          <span className="text-xs text-muted-foreground">
                            {formatTime(session.updatedAt)}
                          </span>
                          <Button
                            variant="ghost"
                            size="icon"
                            className="h-6 w-6"
                            onClick={(e) => handleDeleteSession(session.id, e)}
                          >
                            <Trash2 className="h-3 w-3" />
                          </Button>
                        </div>
                      </div>
                    </CardHeader>
                  </Card>
                ))}
              </div>
            )}
          </ScrollArea>
        </div>
      </DialogContent>
    </Dialog>
  )
}