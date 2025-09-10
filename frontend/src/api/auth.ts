import api from './api';

// Description: Login user
// Endpoint: POST /api/auth/login
// Request: { email: string, password: string }
// Response: { success: boolean, user: object, message: string }
export const login = async (data: { email: string; password: string }) => {
  console.log('API: Attempting login for email:', data.email)
  
  try {
    const response = await api.post('/api/auth/login', data);
    console.log('API: Login response received:', response.data)
    return response.data;
  } catch (error: any) {
    console.error('API: Login error:', error)
    throw new Error(error?.response?.data?.message || error.message);
  }
};

// Description: Register user
// Endpoint: POST /api/auth/register
// Request: { email: string, password: string }
// Response: { success: boolean, user: object, message: string }
export const register = async (data: { email: string; password: string }) => {
  console.log('API: Attempting registration for email:', data.email)
  
  try {
    const response = await api.post('/api/auth/register', data);
    console.log('API: Registration response received:', response.data)
    return response.data;
  } catch (error: any) {
    console.error('API: Registration error:', error)
    throw new Error(error?.response?.data?.message || error.message);
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
  } catch (error: any) {
    console.error('API: Logout error:', error)
    throw new Error(error?.response?.data?.message || error.message);
  }
};