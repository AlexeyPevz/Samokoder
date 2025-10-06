import api from './api';

export interface Model {
  id: string;
  name: string;
  context: number;
}

export interface ProviderModels {
  models: Model[];
  default: string;
}

export const getAvailableModels = async (): Promise<Record<string, ProviderModels>> => {
  try {
    const response = await api.get('/models');
    return response.data;
  } catch (error: unknown) {
    const errorMessage = (error as any)?.response?.data?.detail || (error as Error).message;
    throw new Error(errorMessage);
  }
};

export const getProviderModels = async (provider: string): Promise<ProviderModels> => {
  try {
    const response = await api.get(`/models/${provider}`);
    return response.data;
  } catch (error: unknown) {
    const errorMessage = (error as any)?.response?.data?.detail || (error as Error).message;
    throw new Error(errorMessage);
  }
};
