import api from './api';

export interface Project {
  _id: string;
  name: string;
  description: string;
  status: 'creating' | 'ready' | 'error';
  progress: number;
  lastModified: string;
  previewUrl?: string;
  thumbnailUrl?: string;
}

// Description: Get user's projects
// Endpoint: GET /api/projects
// Request: {}
// Response: { success: boolean, projects: Project[] }
export const getProjects = async (): Promise<{ projects: Project[] }> => {
  try {
    const response = await api.get('/api/projects');
    return { projects: response.data.projects };
  } catch (error: unknown) {
    const errorMessage = (error as any)?.response?.data?.message || (error as Error).message;
    throw new Error(errorMessage);
  }
};

// Description: Create a new project
// Endpoint: POST /api/projects
// Request: { name: string, description: string }
// Response: { success: boolean, project: Project }
export const createProject = async (data: { name: string; description: string }): Promise<{ project: Project }> => {
  try {
    const response = await api.post('/api/projects', data);
    return { project: response.data.project };
  } catch (error: unknown) {
    const errorMessage = (error as any)?.response?.data?.message || (error as Error).message;
    throw new Error(errorMessage);
  }
};

// Description: Delete a project
// Endpoint: DELETE /api/projects/:id
// Request: {}
// Response: { success: boolean, message: string }
export const deleteProject = async (projectId: string): Promise<{ success: boolean }> => {
  try {
    const response = await api.delete(`/api/projects/${projectId}`);
    return { success: response.data.success };
  } catch (error: unknown) {
    const errorMessage = (error as any)?.response?.data?.message || (error as Error).message;
    throw new Error(errorMessage);
  }
};

// Description: Get project details
// Endpoint: GET /api/projects/:id
// Request: {}
// Response: { success: boolean, project: Project }
export const getProject = async (projectId: string): Promise<{ project: Project }> => {
  try {
    const response = await api.get(`/api/projects/${projectId}`);
    return { project: response.data.project };
  } catch (error: unknown) {
    const errorMessage = (error as any)?.response?.data?.message || (error as Error).message;
    throw new Error(errorMessage);
  }
};