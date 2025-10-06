// API functions for chat

export interface ChatMessage {
  id: string;
  role: 'user' | 'assistant' | 'system';
  content: string;
  timestamp: string;
}

// We'll use the workspaceSocket for actual implementation
// These functions are kept for compatibility with existing components

export async function getChatMessages(projectId: string): Promise<{ messages: ChatMessage[] }> {
  console.log(`Fetching messages for project ${projectId}`);
  // In a real implementation, we would fetch messages from the backend
  // For now, we return an empty array
  return Promise.resolve({ messages: [] });
}

export async function sendChatMessage(projectId: string, message: string): Promise<ChatMessage> {
  console.log(`Sending message for project ${projectId}: ${message}`);
  // In a real implementation, we would send the message via WebSocket
  // For now, we return a mock response
  const mockResponse: ChatMessage = {
    id: new Date().toISOString(),
    role: 'assistant',
    content: "This is a mock response from the assistant.",
    timestamp: new Date().toISOString(),
  };
  return Promise.resolve(mockResponse);
}
