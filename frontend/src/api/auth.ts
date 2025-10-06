import api from './api';

// Description: Login user
// Endpoint: POST /auth/login
// Request: { email: string, password: string }
// Response: { access_token: string, token_type: string }
export const login = async (data: { email: string; password: string }) => {
  // FastAPI's OAuth2PasswordRequestForm expects form data, not JSON
  const formData = new URLSearchParams();
  formData.append('username', data.email);
  formData.append('password', data.password);

  try {
    const response = await api.post('/auth/login', formData, {
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
    });
    // Оборачиваем для совместимости с Login.tsx
    return {
      success: true,
      data: {
        accessToken: response.data.access_token,
        refreshToken: response.data.refresh_token,
        user: {
          id: response.data.user_id,
          email: response.data.email
        }
      }
    };
  } catch (error: unknown) {
    const errorMessage = (error as any)?.response?.data?.detail || (error as Error).message;
    throw new Error(errorMessage);
  }
};

// Description: Register user
// Endpoint: POST /auth/register
// Request: { email: string, password: string }
// Response: { access_token: string, refresh_token: string, token_type: string, expires_in: number, user_id: number, email: string }
export const register = async (data: { email: string; password: string }) => {
  try {
    const response = await api.post('/auth/register', data);
    // API возвращает прямой объект, оборачиваем для совместимости с Register.tsx
    return {
      success: true,
      data: {
        accessToken: response.data.access_token,
        refreshToken: response.data.refresh_token,
        user: {
          id: response.data.user_id,
          email: response.data.email
        }
      }
    };
  } catch (error: unknown) {
    const errorMessage = (error as any)?.response?.data?.detail || (error as Error).message;
    throw new Error(errorMessage);
  }
};
