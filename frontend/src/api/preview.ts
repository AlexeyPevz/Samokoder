import api from "./api";

export interface PreviewInfo {
  url: string;
  status: 'running' | 'stopped' | 'error';
  port?: string;
  type?: string;
}

export async function startPreview(projectId: string): Promise<PreviewInfo> {
  const response = await api.post(`/projects/${projectId}/preview/start`);
  return response.data;
}

export async function stopPreview(projectId: string): Promise<{ success: boolean; message: string }> {
  const response = await api.post(`/projects/${projectId}/preview/stop`);
  return response.data;
}

export async function getPreviewStatus(projectId: string): Promise<{ status: PreviewInfo }> {
  const response = await api.get(`/projects/${projectId}/preview/status`);
  return response.data;
}