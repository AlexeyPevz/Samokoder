import api from './api';
import axios from 'axios';

// Description: Get current user profile
// Endpoint: GET /user/profile
// Response: User profile data
export const getUserProfile = async () => {
  try {
    const response = await api.get('/user/profile');
    return response.data;
  } catch (error) {
    if (axios.isAxiosError(error) && error.response) {
      throw new Error(error.response.data?.message || 'An unknown API error occurred');
    } 
    throw new Error('An unexpected error occurred');
  }
};
