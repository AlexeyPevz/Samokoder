import api from './api';

export interface ApiKey {
  provider: string;
  display_key: string;
  model?: string;
  settings?: Record<string, any>;
}

export interface TokenUsage {
  provider: string;
  model: string;
  total_tokens: number;
  requests: number;
  updated_at?: string;
}

export interface ProviderModels {
  [provider: string]: {
    models: Array<{
      id: string;
      name: string;
      context: number;
    }>;
    default: string;
  };
}

export const addApiKey = async (provider: string, apiKey: string, model?: string): Promise<ApiKey> => {
  try {
    const response = await api.post('/keys', { 
      provider, 
      api_key: apiKey,
      model,
      settings: model ? { model } : undefined
    });
    return response.data;
  } catch (error: unknown) {
    const errorMessage = (error as any)?.response?.data?.detail || (error as Error).message;
    throw new Error(errorMessage);
  }
};

export const getApiKeys = async (): Promise<ApiKey[]> => {
  try {
    const response = await api.get('/keys');
    return response.data;
  } catch (error: unknown) {
    const errorMessage = (error as any)?.response?.data?.detail || (error as Error).message;
    throw new Error(errorMessage);
  }
};

export const deleteApiKey = async (provider: string): Promise<void> => {
  try {
    await api.delete(`/keys/${provider}`);
  } catch (error: unknown) {
    const errorMessage = (error as any)?.response?.data?.detail || (error as Error).message;
    throw new Error(errorMessage);
  }
};

export const updateApiKeySettings = async (provider: string, model?: string): Promise<ApiKey> => {
  try {
    const response = await api.put(`/keys/${provider}/settings`, { 
      model,
      settings: model ? { model } : {}
    });
    return response.data;
  } catch (error: unknown) {
    const errorMessage = (error as any)?.response?.data?.detail || (error as Error).message;
    throw new Error(errorMessage);
  }
};

export const getAllTokenUsage = async (): Promise<Record<string, Record<string, TokenUsage>>> => {
  try {
    const response = await api.get('/keys/usage');
    return response.data;
  } catch (error: unknown) {
    const errorMessage = (error as any)?.response?.data?.detail || (error as Error).message;
    throw new Error(errorMessage);
  }
};

export const getProviderTokenUsage = async (provider: string): Promise<TokenUsage[]> => {
  try {
    const response = await api.get(`/keys/${provider}/usage`);
    return response.data;
  } catch (error: unknown) {
    const errorMessage = (error as any)?.response?.data?.detail || (error as Error).message;
    throw new Error(errorMessage);
  }
};

export const resetTokenUsage = async (provider?: string, model?: string): Promise<{ success: boolean; message: string }> => {
  try {
    const params = new URLSearchParams();
    if (provider) params.append('provider', provider);
    if (model) params.append('model', model);
    
    const response = await api.post(`/usage/token/reset?${params.toString()}`);
    return response.data;
  } catch (error: unknown) {
    const errorMessage = (error as any)?.response?.data?.detail || (error as Error).message;
    throw new Error(errorMessage);
  }
};

export const getAvailableModels = async (): Promise<ProviderModels> => {
  try {
    const response = await api.get('/models');
    return response.data;
  } catch (error: unknown) {
    console.error('Error fetching models:', error);
    // Возвращаем пустой объект если не удалось загрузить
    return {};
  }
};
