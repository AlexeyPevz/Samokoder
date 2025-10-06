import api from './api';

export interface TokenUsageSummary {
  totals: {
    providers: number;
    tokens: number;
    requests: number;
  };
  providers: Record<string, {
    tokens: number;
    requests: number;
    models: number;
  }>;
}

// Description: Get token usage summary
// Endpoint: GET /usage/token/summary
// Response: TokenUsageSummary
export const getTokenUsageSummary = async (): Promise<TokenUsageSummary> => {
  try {
    const response = await api.get('/usage/token/summary');
    return response.data;
  } catch (error: unknown) {
    const errorMessage = (error as any)?.response?.data?.detail || (error as Error).message;
    throw new Error(errorMessage);
  }
};
