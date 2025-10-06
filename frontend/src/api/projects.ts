import api from './api';

export interface Project {
  id: string;
  name: string;
  status: 'creating' | 'ready' | 'error';
  progress: number;
  lastModified: string;
  previewUrl?: string;
  thumbnailUrl?: string;
}

export const getProjects = async (): Promise<Project[]> => {
  try {
    const response = await api.get('/projects/');
    // API может вернуть { data: [...] } или просто [...]
    const data = response.data?.data || response.data;
    // Убедимся что это массив
    return Array.isArray(data) ? data : [];
  } catch (error: unknown) {
    const errorMessage = (error as any)?.response?.data?.detail || (error as Error).message;
    throw new Error(errorMessage);
  }
};

export const createProject = async (data: { name: string }): Promise<Project> => {
  try {
    const response = await api.post('/test-endpoint', data);
    return response.data;
  } catch (error: unknown) {
    const errorMessage = (error as any)?.response?.data?.detail || (error as Error).message;
    throw new Error(errorMessage);
  }
};

export const deleteProject = async (projectId: string): Promise<void> => {
  try {
    await api.delete(`/projects/${projectId}`);
  } catch (error: unknown) {
    const errorMessage = (error as any)?.response?.data?.detail || (error as Error).message;
    throw new Error(errorMessage);
  }
};

export const getProject = async (projectId: string): Promise<Project> => {
  try {
    const response = await api.get(`/projects/${projectId}`);
    return response.data;
  } catch (error: unknown) {
    const errorMessage = (error as any)?.response?.data?.detail || (error as Error).message;
    throw new Error(errorMessage);
  }
};
