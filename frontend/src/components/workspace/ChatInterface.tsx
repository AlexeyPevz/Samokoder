import { useState, useRef, useEffect } from "react"
import { Button } from "@/components/ui/button"
import { Textarea } from "@/components/ui/textarea"
import { Avatar, AvatarFallback } from "@/components/ui/avatar"
import { Badge } from "@/components/ui/badge"
import { 
  Send, 
  Mic, 
  Copy, 
  ThumbsUp, 
  ThumbsDown, 
  Loader2, 
  Wand2, 
  Code, 
  Database, 
  Palette, 
  User,
  Cpu,
  Sparkles
} from "lucide-react"
import { ChatMessage } from "@/api/chat"
import { useToast } from "@/hooks/useToast"
import { formatDistanceToNow } from "date-fns"
import { ru } from "date-fns/locale"
import { ChatHistory } from "@/components/workspace/ChatHistory"
import { ChatSession, chatHistoryService } from "@/services/chatHistory"
import { workspaceSocket } from "@/api/workspace"

interface ChatInterfaceProps {
  projectId: string
  messages: ChatMessage[]
  onNewMessage: (userMessage: ChatMessage) => void
  onSendCommand: (command: string) => void
  sessionId?: string
  onSessionChange?: (session: ChatSession) => void
}

export default function ChatInterface({ 
  projectId, 
  messages, 
  onNewMessage,
  onSendCommand,
  sessionId,
  onSessionChange
}: ChatInterfaceProps) {
  const { toast } = useToast()
  const [input, setInput] = useState("")
  const [isTyping, setIsTyping] = useState(false)
  const messagesEndRef = useRef<HTMLDivElement>(null)
  const textareaRef = useRef<HTMLTextAreaElement>(null)

  useEffect(() => {
    scrollToBottom()
  }, [messages, isTyping])

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" })
  }

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    
    if (!input.trim() || isTyping) return

    const messageContent = input.trim()
    
    const userMessage: ChatMessage = {
      id: Date.now().toString(),
      content: messageContent,
      role: 'user',
      timestamp: new Date().toISOString(),
    }

    // Immediately update the UI with the user's message
    onNewMessage(userMessage)
    setInput("")
    setIsTyping(true)
    
    // In a real implementation, we would wait for the response from WebSocket
    // For now, we just stop typing indicator
    setTimeout(() => {
      setIsTyping(false)
    }, 1000)
  }

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault()
      handleSubmit(e)
    }
  }

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text)
    toast({
      title: "Скопировано",
      description: "Текст скопирован в буфер обмена"
    })
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

  // Шаблоны промптов
  const promptTemplates = [
    {
      id: "add-feature",
      title: "Добавить функцию",
      icon: <Wand2 className="h-4 w-4" />,
      prompt: "Добавь новую функцию в приложение",
      category: "development"
    },
    {
      id: "fix-bug",
      title: "Исправить баг",
      icon: <Code className="h-4 w-4" />,
      prompt: "Найди и исправь ошибку в коде",
      category: "development"
    },
    {
      id: "database",
      title: "База данных",
      icon: <Database className="h-4 w-4" />,
      prompt: "Настрой подключение к базе данных",
      category: "backend"
    },
    {
      id: "design",
      title: "Дизайн",
      icon: <Palette className="h-4 w-4" />,
      prompt: "Улучши дизайн интерфейса",
      category: "frontend"
    },
    {
      id: "auth",
      title: "Авторизация",
      icon: <User className="h-4 w-4" />,
      prompt: "Добавь систему авторизации",
      category: "backend"
    },
    {
      id: "optimize",
      title: "Оптимизация",
      icon: <Cpu className="h-4 w-4" />,
      prompt: "Оптимизируй производительность приложения",
      category: "performance"
    },
    {
      id: "ai-integration",
      title: "ИИ интеграция",
      icon: <Sparkles className="h-4 w-4" />,
      prompt: "Интегрируй AI-возможности в приложение",
      category: "ai"
    }
  ]

  const handleTemplateClick = (template: { prompt: string }) => {
    setInput(template.prompt)
    textareaRef.current?.focus()
  }

  const handleNewSession = () => {
    // Create a new session
    const newSession = chatHistoryService.createSession(projectId, "Новая сессия")
    if (onSessionChange) {
      onSessionChange(newSession)
    }
  }

  const handleSessionSelect = (session: ChatSession) => {
    if (onSessionChange) {
      onSessionChange(session)
    }
  }

  return (
    <div className="flex flex-col h-full bg-white/50 backdrop-blur-sm">
      {/* Header */}
      <div className="p-4 border-b bg-white/80">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <Avatar className="h-8 w-8">
              <AvatarFallback className="bg-gradient-to-br from-primary to-accent text-white text-sm">
                ИИ
              </AvatarFallback>
            </Avatar>
            <div>
              <h3 className="font-semibold">ИИ Ассистент</h3>
              <p className="text-xs text-muted-foreground">
                {isTyping ? "Печатает..." : "В сети"}
              </p>
            </div>
          </div>
          
          <ChatHistory 
            projectId={projectId}
            currentSessionId={sessionId}
            onSessionSelect={handleSessionSelect}
            onNewSession={handleNewSession}
          />
        </div>
      </div>

      {/* Messages */}
      <div className="flex-1 overflow-y-auto p-4 space-y-4">
        {messages.map((message) => (
          <div
            key={message.id}
            className={`flex gap-3 ${
              message.role === 'user' ? 'justify-end' : 'justify-start'
            }`}
          >
            {message.role !== 'user' && (
              <Avatar className="h-8 w-8 flex-shrink-0">
                <AvatarFallback className="bg-gradient-to-br from-primary to-accent text-white text-xs">
                  ИИ
                </AvatarFallback>
              </Avatar>
            )}
            
            <div className={`max-w-[80%] ${message.role === 'user' ? 'order-1' : ''}`}>
              <div
                className={`rounded-2xl px-4 py-3 ${
                  message.role === 'user'
                    ? 'bg-primary text-white ml-auto'
                    : message.role === 'system'
                    ? 'bg-gray-100 text-gray-700 text-center'
                    : 'bg-gray-100 text-gray-900'
                }`}
              >
                <p className="text-sm whitespace-pre-wrap">{message.content}</p>
              </div>
              
              <div className={`flex items-center gap-2 mt-1 ${
                message.role === 'user' ? 'justify-end' : 'justify-start'
              }`}>
                <span className="text-xs text-muted-foreground">
                  {formatTime(message.timestamp)}
                </span>
                
                {message.role === 'assistant' && (
                  <div className="flex items-center gap-1">
                    <Button
                      variant="ghost"
                      size="icon"
                      className="h-6 w-6"
                      onClick={() => copyToClipboard(message.content)}
                    >
                      <Copy className="h-3 w-3" />
                    </Button>
                    <Button variant="ghost" size="icon" className="h-6 w-6">
                      <ThumbsUp className="h-3 w-3" />
                    </Button>
                    <Button variant="ghost" size="icon" className="h-6 w-6">
                      <ThumbsDown className="h-3 w-3" />
                    </Button>
                  </div>
                )}
              </div>
            </div>
            
            {message.role === 'user' && (
              <Avatar className="h-8 w-8 flex-shrink-0">
                <AvatarFallback className="bg-gray-300 text-gray-700 text-xs">
                  Вы
                </AvatarFallback>
              </Avatar>
            )}
          </div>
        ))}
        
        {isTyping && (
          <div className="flex gap-3 justify-start">
            <Avatar className="h-8 w-8 flex-shrink-0">
              <AvatarFallback className="bg-gradient-to-br from-primary to-accent text-white text-xs">
                ИИ
              </AvatarFallback>
            </Avatar>
            <div className="bg-gray-100 rounded-2xl px-4 py-3">
              <div className="flex items-center gap-1">
                <div className="w-2 h-2 bg-gray-400 rounded-full animate-bounce"></div>
                <div className="w-2 h-2 bg-gray-400 rounded-full animate-bounce" style={{ animationDelay: '0.1s' }}></div>
                <div className="w-2 h-2 bg-gray-400 rounded-full animate-bounce" style={{ animationDelay: '0.2s' }}></div>
              </div>
            </div>
          </div>
        )}
        
        <div ref={messagesEndRef} />
      </div>

      {/* Quick Actions */}
      <div className="p-4 border-t bg-white/80">
        <div className="flex flex-wrap gap-2 mb-3">
          <div className="w-full text-xs text-muted-foreground mb-2">Шаблоны промптов:</div>
          {promptTemplates.map((template) => (
            <Badge
              key={template.id}
              variant="outline"
              className="cursor-pointer hover:bg-primary/5 flex items-center gap-1"
              onClick={() => handleTemplateClick(template)}
            >
              {template.icon}
              {template.title}
            </Badge>
          ))}
        </div>
        <div className="flex flex-wrap gap-2 mb-3">
          <div className="w-full text-xs text-muted-foreground mb-2">Команды:</div>
          <Badge
            variant="outline"
            className="cursor-pointer hover:bg-primary/5 flex items-center gap-1"
            onClick={() => onSendCommand('skip-task')}
          >
            Пропустить задачу
          </Badge>
          <Badge
            variant="outline"
            className="cursor-pointer hover:bg-primary/5 flex items-center gap-1"
            onClick={() => onSendCommand('im-stuck')}
          >
            Я застрял
          </Badge>
        </div>
      </div>

      {/* Input */}
      <div className="p-4 border-t bg-white">
        <form onSubmit={handleSubmit} className="flex gap-2">
          <div className="flex-1 relative">
            <Textarea
              ref={textareaRef}
              placeholder="Опишите что нужно изменить..."
              value={input}
              onChange={(e) => setInput(e.target.value)}
              onKeyDown={handleKeyDown}
              disabled={isTyping}
              className="min-h-[44px] max-h-32 resize-none pr-12"
            />
            <Button
              type="button"
              variant="ghost"
              size="icon"
              className="absolute right-2 top-2 h-8 w-8"
              disabled={isTyping}
            >
              <Mic className="h-4 w-4" />
            </Button>
          </div>
          
          <Button
            type="submit"
            disabled={!input.trim() || isTyping}
            className="h-11 px-4 bg-primary hover:bg-primary/90"
          >
            {isTyping ? (
              <Loader2 className="h-4 w-4 animate-spin" />
            ) : (
              <Send className="h-4 w-4" />
            )}
          </Button>
        </form>
      </div>
    </div>
  )
}
