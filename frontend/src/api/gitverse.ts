import api from './api';

// Description: Set user's GitVerse token
// Endpoint: POST /user/gitverse-token
// Request: { token: string }
export const setGitVerseToken = async (token: string): Promise<void> => {
  try {
    await api.post('/user/gitverse-token', { token });
  } catch (error: unknown) {
    const errorMessage = (error as any)?.response?.data?.detail || (error as Error).message;
    throw new Error(errorMessage);
  }
};
