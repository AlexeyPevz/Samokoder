import api from './api';

// Description: Set user's GitHub token
// Endpoint: POST /user/github-token
// Request: { token: string }
export const setGitHubToken = async (token: string): Promise<void> => {
  try {
    await api.post('/user/github-token', { token });
  } catch (error: unknown) {
    const errorMessage = (error as any)?.response?.data?.detail || (error as Error).message;
    throw new Error(errorMessage);
  }
};
