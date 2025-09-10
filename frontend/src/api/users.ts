import api from './api';

// Description: Get current user profile with API configuration preferences
// Endpoint: GET /api/users/me
// Request: {}
// Response: { success: boolean, data: { _id: string, email: string, name: string, apiProvider: string, apiKey: string, preferences: { theme: string, language: string, emailNotifications: boolean, browserNotifications: boolean }, createdAt: string, lastLoginAt: string, isActive: boolean } }
export const getUserProfile = async () => {
  try {
    const response = await api.get('/api/users/me');
    return response.data;
  } catch (error) {
    throw new Error(error?.response?.data?.message || error.message);
  }
};

// Description: Update current user profile with API configuration preferences
// Endpoint: PUT /api/users/me
// Request: { name?: string, apiProvider?: string, apiKey?: string, preferences?: { theme?: string, language?: string, emailNotifications?: boolean, browserNotifications?: boolean } }
// Response: { success: boolean, data: { _id: string, email: string, name: string, apiProvider: string, apiKey: string, preferences: { theme: string, language: string, emailNotifications: boolean, browserNotifications: boolean }, createdAt: string, lastLoginAt: string, isActive: boolean } }
export const updateUserProfile = async (profileData: {
  name?: string;
  apiProvider?: string;
  apiKey?: string;
  preferences?: {
    theme?: string;
    language?: string;
    emailNotifications?: boolean;
    browserNotifications?: boolean;
  };
}) => {
  try {
    const response = await api.put('/api/users/me', profileData);
    return response.data;
  } catch (error) {
    throw new Error(error?.response?.data?.message || error.message);
  }
};

// Description: Create new user with API configuration preferences
// Endpoint: POST /api/users
// Request: { email: string, password: string, name?: string, apiProvider?: string, apiKey?: string, preferences?: { theme?: string, language?: string, emailNotifications?: boolean, browserNotifications?: boolean } }
// Response: { success: boolean, data: { _id: string, email: string, name: string, apiProvider: string, apiKey: string, preferences: { theme: string, language: string, emailNotifications: boolean, browserNotifications: boolean }, createdAt: string, lastLoginAt: string, isActive: boolean } }
export const createUser = async (userData: {
  email: string;
  password: string;
  name?: string;
  apiProvider?: string;
  apiKey?: string;
  preferences?: {
    theme?: string;
    language?: string;
    emailNotifications?: boolean;
    browserNotifications?: boolean;
  };
}) => {
  try {
    const response = await api.post('/api/users', userData);
    return response.data;
  } catch (error) {
    throw new Error(error?.response?.data?.message || error.message);
  }
};