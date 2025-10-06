// Frontend service for analytics

export interface UserMetrics {
  total_actions: number;
  actions_by_type: Record<string, number>;
  projects_created: number;
  projects_used_count: number;
  last_active: number | null;
}

export interface SystemMetrics {
  total_users: number;
  total_actions: number;
  total_projects_created: number;
  most_common_actions: [string, number][];
  active_users_24h: number;
  active_users_7d: number;
}

export interface ActionLog {
  user_id: number;
  action: string;
  details: Record<string, any>;
  project_id: string | null;
  timestamp: number;
}

class AnalyticsService {
  private baseUrl = "/api/v1/analytics";
  
  // Get user analytics metrics
  async getUserMetrics(): Promise<{ user_id: number; metrics: UserMetrics }> {
    const response = await fetch(`${this.baseUrl}/user`, {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${localStorage.getItem('accessToken')}`,
        'Content-Type': 'application/json'
      }
    });
    
    if (!response.ok) {
      throw new Error(`Failed to get user metrics: ${response.statusText}`);
    }
    
    return response.json();
  }
  
  // Get system analytics metrics
  async getSystemMetrics(): Promise<{ metrics: SystemMetrics }> {
    const response = await fetch(`${this.baseUrl}/system`, {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${localStorage.getItem('accessToken')}`,
        'Content-Type': 'application/json'
      }
    });
    
    if (!response.ok) {
      throw new Error(`Failed to get system metrics: ${response.statusText}`);
    }
    
    return response.json();
  }
  
  // Get user action logs
  async getUserActionLogs(limit: number = 100): Promise<{ user_id: number; logs: ActionLog[] }> {
    const response = await fetch(`${this.baseUrl}/user/actions?limit=${limit}`, {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${localStorage.getItem('accessToken')}`,
        'Content-Type': 'application/json'
      }
    });
    
    if (!response.ok) {
      throw new Error(`Failed to get user action logs: ${response.statusText}`);
    }
    
    return response.json();
  }
  
  // Record a user action
  async recordUserAction(
    action: string,
    details?: Record<string, any>,
    projectId?: string
  ): Promise<{ success: boolean; message: string }> {
    const response = await fetch(`${this.baseUrl}/record`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${localStorage.getItem('accessToken')}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        action,
        details,
        project_id: projectId
      })
    });
    
    if (!response.ok) {
      throw new Error(`Failed to record user action: ${response.statusText}`);
    }
    
    return response.json();
  }
  
  // Export all analytics data
  async exportAnalytics(): Promise<any> {
    const response = await fetch(`${this.baseUrl}/export`, {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${localStorage.getItem('accessToken')}`,
        'Content-Type': 'application/json'
      }
    });
    
    if (!response.ok) {
      throw new Error(`Failed to export analytics: ${response.statusText}`);
    }
    
    return response.json();
  }
}

// Global instance
export const analyticsService = new AnalyticsService();