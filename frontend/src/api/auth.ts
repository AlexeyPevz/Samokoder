import api from './api';

// Description: Login user
// Endpoint: POST /api/auth/login
// Request: { email: string, password: string }
// Response: { success: boolean, data: { user: object, accessToken: string, refreshToken: string }, message: string }
export const login = async (data: { email: string; password: string }) => {
  try {
    const response = await api.post('/api/auth/login', data);
    return response.data;
  } catch (error: unknown) {
    const errorMessage = (error as any)?.response?.data?.message || (error as Error).message;
    throw new Error(errorMessage);
  }
};

// Description: Register user
// Endpoint: POST /api/auth/register
// Request: { email: string, password: string }
// Response: { success: boolean, data: { user: object, accessToken: string, refreshToken: string }, message: string }
export const register = async (data: { email: string; password: string }) => {
  try {
    const response = await api.post('/api/auth/register', data);
    return response.data;
  } catch (error: unknown) {
    const errorMessage = (error as any)?.response?.data?.message || (error as Error).message;
    throw new Error(errorMessage);
  }
};

// Description: Logout user
// Endpoint: POST /api/auth/logout
// Request: {}
// Response: { success: boolean, message: string }
export const logout = async () => {
  try {
    const response = await api.post('/api/auth/logout');
    return response.data;
  } catch (error: unknown) {
    const errorMessage = (error as any)?.response?.data?.message || (error as Error).message;
    throw new Error(errorMessage);
  }
};