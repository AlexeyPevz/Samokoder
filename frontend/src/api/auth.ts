import api from './api';

// Description: Login user
// Endpoint: POST /api/auth/login
// Request: { email: string, password: string }
// Response: { success: boolean, data: { user: object, accessToken: string, refreshToken: string }, message: string }
export const login = async (data: { email: string; password: string }) => {
  console.log('API: Attempting login for email:', data.email)
  
  try {
    const response = await api.post('/api/auth/login', data);
    console.log('API: Login response received:', response.data)
    return response.data;
  } catch (error: unknown) {
    console.error('API: Login error:', error)
    throw new Error((error as any)?.response?.data?.message || (error as Error).message);
  }
};

// Description: Register user
// Endpoint: POST /api/auth/register
// Request: { email: string, password: string }
// Response: { success: boolean, data: { user: object, accessToken: string, refreshToken: string }, message: string }
export const register = async (data: { email: string; password: string }) => {
  console.log('API: Attempting registration for email:', data.email)
  
  try {
    const response = await api.post('/api/auth/register', data);
    console.log('API: Registration response received:', response.data)
    return response.data;
  } catch (error: unknown) {
    console.error('API: Registration error:', error)
    throw new Error((error as any)?.response?.data?.message || (error as Error).message);
  }
};

// Description: Logout user
// Endpoint: POST /api/auth/logout
// Request: {}
// Response: { success: boolean, message: string }
export const logout = async () => {
  console.log('API: Attempting logout')
  
  try {
    const response = await api.post('/api/auth/logout');
    console.log('API: Logout response received:', response.data)
    return response.data;
  } catch (error: unknown) {
    console.error('API: Logout error:', error)
    throw new Error((error as any)?.response?.data?.message || (error as Error).message);
  }
};