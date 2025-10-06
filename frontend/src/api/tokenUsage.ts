// Frontend API functions for token usage

export interface TokenUsage {
  provider: string;
  model: string;
  total_tokens: number;
  requests: number;
  updated_at?: string;
}

export interface ProviderUsage {
  [model: string]: TokenUsage;
}

export interface UserTokenUsage {
  [provider: string]: ProviderUsage;
}

export interface TokenUsageSummary {
  totals: {
    providers: number;
    tokens: number;
    requests: number;
  };
  providers: {
    [provider: string]: {
      tokens: number;
      requests: number;
      models: number;
    };
  };
}

class TokenUsageService {
  private baseUrl = "/api/v1/usage/token";
  
  // Get user's token usage statistics
  async getTokenUsage(): Promise<{ usage: UserTokenUsage }> {
    const response = await fetch(`${this.baseUrl}`, {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${localStorage.getItem('accessToken')}`,
        'Content-Type': 'application/json'
      }
    });
    
    if (!response.ok) {
      throw new Error(`Failed to get token usage: ${response.statusText}`);
    }
    
    return response.json();
  }
  
  // Get token usage statistics for a specific provider
  async getProviderTokenUsage(provider: string): Promise<{
    provider: string;
    usage: ProviderUsage;
    totals: {
      total_tokens: number;
      total_requests: number;
      models_count: number;
    };
  }> {
    const response = await fetch(`${this.baseUrl}/provider/${provider}`, {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${localStorage.getItem('accessToken')}`,
        'Content-Type': 'application/json'
      }
    });
    
    if (!response.ok) {
      throw new Error(`Failed to get provider token usage: ${response.statusText}`);
    }
    
    return response.json();
  }
  
  // Get token usage statistics for a specific provider and model
  async getModelTokenUsage(provider: string, model: string): Promise<{
    provider: string;
    model: string;
    usage: TokenUsage;
  }> {
    const response = await fetch(`${this.baseUrl}/provider/${provider}/model/${model}`, {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${localStorage.getItem('accessToken')}`,
        'Content-Type': 'application/json'
      }
    });
    
    if (!response.ok) {
      throw new Error(`Failed to get model token usage: ${response.statusText}`);
    }
    
    return response.json();
  }
  
  // Reset token usage statistics
  async resetTokenUsage(provider?: string, model?: string): Promise<{
    success: boolean;
    message: string;
  }> {
    const params = new URLSearchParams();
    if (provider) params.append('provider', provider);
    if (model) params.append('model', model);
    
    const response = await fetch(`${this.baseUrl}/reset?${params.toString()}`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${localStorage.getItem('accessToken')}`,
        'Content-Type': 'application/json'
      }
    });
    
    if (!response.ok) {
      throw new Error(`Failed to reset token usage: ${response.statusText}`);
    }
    
    return response.json();
  }
  
  // Get a summary of token usage statistics
  async getTokenUsageSummary(): Promise<TokenUsageSummary> {
    const response = await fetch(`${this.baseUrl}/summary`, {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${localStorage.getItem('accessToken')}`,
        'Content-Type': 'application/json'
      }
    });
    
    if (!response.ok) {
      throw new Error(`Failed to get token usage summary: ${response.statusText}`);
    }
    
    return response.json();
  }
}

// Global instance
export const tokenUsageService = new TokenUsageService();