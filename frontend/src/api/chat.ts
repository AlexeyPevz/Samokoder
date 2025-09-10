import api from './api';

export interface ChatMessage {
  _id: string;
  role: 'user' | 'assistant' | 'system';
  content: string;
  timestamp: string;
  projectId: string;
}

// Description: Get chat messages for a project
// Endpoint: GET /api/projects/:projectId/chat
// Request: {}
// Response: { messages: ChatMessage[] }
export const getChatMessages = (projectId: string): Promise<{ messages: ChatMessage[] }> => {
  // Mocking the response
  return new Promise((resolve) => {
    setTimeout(() => {
      resolve({
        messages: [
          {
            _id: '1',
            role: 'system',
            content: 'Добро пожаловать! Я помогу вам создать приложение. Опишите, что вы хотите изменить или добавить.',
            timestamp: new Date(Date.now() - 3600000).toISOString(),
            projectId
          },
          {
            _id: '2',
            role: 'user',
            content: 'Создай интернет-магазин цветов с корзиной и оплатой',
            timestamp: new Date(Date.now() - 3000000).toISOString(),
            projectId
          },
          {
            _id: '3',
            role: 'assistant',
            content: 'Отлично! Я создал для вас интернет-магазин цветов. В приложении есть:\n\n• Каталог товаров с фильтрами\n• Корзина для покупок\n• Система оплаты\n• Личный кабинет пользователя\n\nЧто бы вы хотели изменить или добавить?',
            timestamp: new Date(Date.now() - 2900000).toISOString(),
            projectId
          }
        ]
      });
    }, 500);
  });
  // Uncomment the below lines to make an actual API call
  // try {
  //   return await api.get(`/api/projects/${projectId}/chat`);
  // } catch (error) {
  //   throw new Error(error?.response?.data?.message || error.message);
  // }
};

// Description: Send a chat message
// Endpoint: POST /api/projects/:projectId/chat
// Request: { content: string }
// Response: { message: ChatMessage, assistantMessage: ChatMessage }
export const sendChatMessage = (projectId: string, content: string): Promise<{ message: ChatMessage, assistantMessage: ChatMessage }> => {
  // Mocking the response
  return new Promise((resolve) => {
    setTimeout(() => {
      const userMessage: ChatMessage = {
        _id: Date.now().toString(),
        role: 'user',
        content,
        timestamp: new Date().toISOString(),
        projectId
      };

      const assistantMessage: ChatMessage = {
        _id: (Date.now() + 1).toString(),
        role: 'assistant',
        content: 'Понял! Я обновлю приложение согласно вашему запросу. Изменения будут видны в превью через несколько секунд.',
        timestamp: new Date(Date.now() + 1000).toISOString(),
        projectId
      };

      resolve({ message: userMessage, assistantMessage });
    }, 1000);
  });
  // Uncomment the below lines to make an actual API call
  // try {
  //   return await api.post(`/api/projects/${projectId}/chat`, { content });
  // } catch (error) {
  //   throw new Error(error?.response?.data?.message || error.message);
  // }
};