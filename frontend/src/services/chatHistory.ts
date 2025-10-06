import { ChatMessage } from "@/api/chat"

export interface ChatSession {
  id: string
  projectId: string
  title: string
  messages: ChatMessage[]
  createdAt: string
  updatedAt: string
}

class ChatHistoryService {
  private storageKey = "gpt_pilot_chat_sessions"
  
  // Get all chat sessions for a project
  getSessions(projectId: string): ChatSession[] {
    try {
      const sessions = localStorage.getItem(this.storageKey)
      if (sessions) {
        const allSessions: ChatSession[] = JSON.parse(sessions)
        return allSessions.filter(session => session.projectId === projectId)
      }
      return []
    } catch (error) {
      console.error("Error loading chat sessions:", error)
      return []
    }
  }
  
  // Get a specific chat session
  getSession(sessionId: string): ChatSession | null {
    try {
      const sessions = localStorage.getItem(this.storageKey)
      if (sessions) {
        const allSessions: ChatSession[] = JSON.parse(sessions)
        return allSessions.find(session => session.id === sessionId) || null
      }
      return null
    } catch (error) {
      console.error("Error loading chat session:", error)
      return null
    }
  }
  
  // Save a chat session
  saveSession(session: ChatSession): void {
    try {
      const sessions = localStorage.getItem(this.storageKey)
      let allSessions: ChatSession[] = []
      
      if (sessions) {
        allSessions = JSON.parse(sessions)
        // Remove existing session with same ID
        allSessions = allSessions.filter(s => s.id !== session.id)
      }
      
      // Add new session
      allSessions.push(session)
      
      // Save to localStorage
      localStorage.setItem(this.storageKey, JSON.stringify(allSessions))
    } catch (error) {
      console.error("Error saving chat session:", error)
    }
  }
  
  // Create a new chat session
  createSession(projectId: string, title: string, messages: ChatMessage[] = []): ChatSession {
    const session: ChatSession = {
      id: `session_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
      projectId,
      title,
      messages,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString()
    }
    
    this.saveSession(session)
    return session
  }
  
  // Update an existing chat session
  updateSession(sessionId: string, updates: Partial<ChatSession>): void {
    const session = this.getSession(sessionId)
    if (session) {
      const updatedSession = {
        ...session,
        ...updates,
        updatedAt: new Date().toISOString()
      }
      this.saveSession(updatedSession)
    }
  }
  
  // Delete a chat session
  deleteSession(sessionId: string): void {
    try {
      const sessions = localStorage.getItem(this.storageKey)
      if (sessions) {
        let allSessions: ChatSession[] = JSON.parse(sessions)
        allSessions = allSessions.filter(session => session.id !== sessionId)
        localStorage.setItem(this.storageKey, JSON.stringify(allSessions))
      }
    } catch (error) {
      console.error("Error deleting chat session:", error)
    }
  }
  
  // Add a message to a session
  addMessageToSession(sessionId: string, message: ChatMessage): void {
    const session = this.getSession(sessionId)
    if (session) {
      session.messages.push(message)
      session.updatedAt = new Date().toISOString()
      this.saveSession(session)
    }
  }
  
  // Generate a title for a session based on first message
  generateSessionTitle(firstMessage: string): string {
    // Truncate and clean up the first message to create a title
    let title = firstMessage.trim()
    
    // Remove extra whitespace and limit length
    title = title.replace(/\s+/g, ' ')
    if (title.length > 50) {
      title = title.substring(0, 47) + '...'
    }
    
    // If title is empty, use default
    if (!title) {
      title = "Новая сессия"
    }
    
    return title
  }
}

// Global instance
export const chatHistoryService = new ChatHistoryService()