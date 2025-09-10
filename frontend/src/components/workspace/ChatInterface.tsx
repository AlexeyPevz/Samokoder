import { useState, useRef, useEffect } from "react"
import { Button } from "@/components/ui/button"
import { Textarea } from "@/components/ui/textarea"
import { Avatar, AvatarFallback } from "@/components/ui/avatar"
import { Badge } from "@/components/ui/badge"
import { Send, Mic, Copy, ThumbsUp, ThumbsDown, Loader2 } from "lucide-react"
// import { ChatMessage, sendChatMessage } from "@/api/chat"

// Временные типы и функции для чата
interface ChatMessage {
  id: string
  content: string
  role: 'user' | 'assistant'
  timestamp: string
}

const sendChatMessage = async (projectId: string, message: string): Promise<ChatMessage> => {
  // Временная заглушка
  return {
    id: Date.now().toString(),
    content: `Ответ на: ${message}`,
    role: 'assistant',
    timestamp: new Date().toISOString()
  }
}
import { useToast } from "@/hooks/useToast"
import { formatDistanceToNow } from "date-fns"
import { ru } from "date-fns/locale"

interface ChatInterfaceProps {
  projectId: string
  messages: ChatMessage[]
  onNewMessage: (userMessage: ChatMessage, assistantMessage: ChatMessage) => void
}

export function ChatInterface({ projectId, messages, onNewMessage }: ChatInterfaceProps) {
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
    setInput("")
    setIsTyping(true)

    try {
      console.log('Sending message:', messageContent)
      const response = await sendChatMessage(projectId, messageContent)
      onNewMessage(response.message, response.assistantMessage)
      console.log('Message sent successfully')
    } catch (error) {
      console.error('Error sending message:', error)
      toast({
        title: "Ошибка",
        description: "Не удалось отправить сообщение",
        variant: "destructive"
      })
    } finally {
      setIsTyping(false)
    }
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

  return (
    <div className="flex flex-col h-full bg-white/50 backdrop-blur-sm">
      {/* Header */}
      <div className="p-4 border-b bg-white/80">
        <div className="flex items-center gap-3">
          <Avatar className="h-8 w-8">
            <AvatarFallback className="bg-gradient-to-br from-blue-500 to-purple-600 text-white text-sm">
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
      </div>

      {/* Messages */}
      <div className="flex-1 overflow-y-auto p-4 space-y-4">
        {messages.map((message) => (
          <div
            key={message._id}
            className={`flex gap-3 ${
              message.role === 'user' ? 'justify-end' : 'justify-start'
            }`}
          >
            {message.role !== 'user' && (
              <Avatar className="h-8 w-8 flex-shrink-0">
                <AvatarFallback className="bg-gradient-to-br from-blue-500 to-purple-600 text-white text-xs">
                  ИИ
                </AvatarFallback>
              </Avatar>
            )}
            
            <div className={`max-w-[80%] ${message.role === 'user' ? 'order-1' : ''}`}>
              <div
                className={`rounded-2xl px-4 py-3 ${
                  message.role === 'user'
                    ? 'bg-blue-600 text-white ml-auto'
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
              <AvatarFallback className="bg-gradient-to-br from-blue-500 to-purple-600 text-white text-xs">
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
          <Badge
            variant="outline"
            className="cursor-pointer hover:bg-blue-50"
            onClick={() => setInput("Добавь корзину для покупок")}
          >
            Добавить корзину
          </Badge>
          <Badge
            variant="outline"
            className="cursor-pointer hover:bg-blue-50"
            onClick={() => setInput("Настрой дизайн в современном стиле")}
          >
            Настроить дизайн
          </Badge>
          <Badge
            variant="outline"
            className="cursor-pointer hover:bg-blue-50"
            onClick={() => setInput("Подключи базу данных")}
          >
            Подключить БД
          </Badge>
          <Badge
            variant="outline"
            className="cursor-pointer hover:bg-blue-50"
            onClick={() => setInput("Добавь авторизацию пользователей")}
          >
            Добавить авторизацию
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
            className="h-11 px-4 bg-blue-600 hover:bg-blue-700"
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