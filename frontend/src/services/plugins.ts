// Frontend service for managing plugins

export interface Plugin {
  name: string;
  version: string;
  description: string;
  enabled: boolean;
}

export interface PluginSettings {
  [key: string]: any;
}

class PluginService {
  private baseUrl = "/api/v1/plugins";
  
  // Get all available plugins
  async getPlugins(): Promise<{ plugins: Plugin[] }> {
    const response = await fetch(`${this.baseUrl}`, {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${localStorage.getItem('accessToken')}`,
        'Content-Type': 'application/json'
      }
    });
    
    if (!response.ok) {
      throw new Error(`Failed to get plugins: ${response.statusText}`);
    }
    
    return response.json();
  }
  
  // Get information about a specific plugin
  async getPluginInfo(pluginName: string): Promise<Plugin> {
    const response = await fetch(`${this.baseUrl}/${pluginName}`, {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${localStorage.getItem('accessToken')}`,
        'Content-Type': 'application/json'
      }
    });
    
    if (!response.ok) {
      throw new Error(`Failed to get plugin info: ${response.statusText}`);
    }
    
    return response.json();
  }
  
  // Enable a plugin
  async enablePlugin(pluginName: string): Promise<{ success: boolean; message: string }> {
    const response = await fetch(`${this.baseUrl}/${pluginName}/enable`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${localStorage.getItem('accessToken')}`,
        'Content-Type': 'application/json'
      }
    });
    
    if (!response.ok) {
      throw new Error(`Failed to enable plugin: ${response.statusText}`);
    }
    
    return response.json();
  }
  
  // Disable a plugin
  async disablePlugin(pluginName: string): Promise<{ success: boolean; message: string }> {
    const response = await fetch(`${this.baseUrl}/${pluginName}/disable`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${localStorage.getItem('accessToken')}`,
        'Content-Type': 'application/json'
      }
    });
    
    if (!response.ok) {
      throw new Error(`Failed to disable plugin: ${response.statusText}`);
    }
    
    return response.json();
  }
  
  // Get user settings for a plugin
  async getPluginSettings(pluginName: string): Promise<{ plugin: string; settings: PluginSettings }> {
    const response = await fetch(`${this.baseUrl}/${pluginName}/settings`, {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${localStorage.getItem('accessToken')}`,
        'Content-Type': 'application/json'
      }
    });
    
    if (!response.ok) {
      throw new Error(`Failed to get plugin settings: ${response.statusText}`);
    }
    
    return response.json();
  }
  
  // Update user settings for a plugin
  async updatePluginSettings(
    pluginName: string,
    settings: PluginSettings
  ): Promise<{ success: boolean; message: string }> {
    const response = await fetch(`${this.baseUrl}/${pluginName}/settings`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${localStorage.getItem('accessToken')}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(settings)
    });
    
    if (!response.ok) {
      throw new Error(`Failed to update plugin settings: ${response.statusText}`);
    }
    
    return response.json();
  }
  
  // Create a GitHub repository for a project
  async createGitHubRepository(
    projectId: string
  ): Promise<{ success: boolean; message: string }> {
    const response = await fetch(`${this.baseUrl}/github/create-repo`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${localStorage.getItem('accessToken')}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ project_id: projectId })
    });
    
    if (!response.ok) {
      throw new Error(`Failed to create GitHub repository: ${response.statusText}`);
    }
    
    return response.json();
  }
}

// Global instance
export const pluginService = new PluginService();