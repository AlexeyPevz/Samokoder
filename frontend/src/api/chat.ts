// API functions for chat
import { workspaceSocket } from './workspace';

export interface ChatMessage {
  id: string;
  role: 'user' | 'assistant' | 'system';
  content: string;
  timestamp: string;
}

// Store chat history in memory
const chatHistory: Map<string, ChatMessage[]> = new Map();

export async function getChatMessages(projectId: string): Promise<{ messages: ChatMessage[] }> {
  // Return messages from history
  const messages = chatHistory.get(projectId) || [];
  return Promise.resolve({ messages });
}

export async function sendChatMessage(projectId: string, message: string): Promise<ChatMessage> {
  // Create user message
  const userMessage: ChatMessage = {
    id: `user-${Date.now()}`,
    role: 'user',
    content: message,
    timestamp: new Date().toISOString(),
  };
  
  // Add to history
  if (!chatHistory.has(projectId)) {
    chatHistory.set(projectId, []);
  }
  chatHistory.get(projectId)!.push(userMessage);
  
  // Send via WebSocket
  workspaceSocket.sendMessage(JSON.stringify({
    type: 'chat_message',
    message: message,
    timestamp: userMessage.timestamp
  }));
  
  // Return user message immediately
  // Assistant response will come via WebSocket and should be handled by the component
  return Promise.resolve(userMessage);
}

// Helper function to add assistant messages from WebSocket
export function addAssistantMessage(projectId: string, content: string): ChatMessage {
  const assistantMessage: ChatMessage = {
    id: `assistant-${Date.now()}`,
    role: 'assistant',
    content: content,
    timestamp: new Date().toISOString(),
  };
  
  if (!chatHistory.has(projectId)) {
    chatHistory.set(projectId, []);
  }
  chatHistory.get(projectId)!.push(assistantMessage);
  
  return assistantMessage;
}
