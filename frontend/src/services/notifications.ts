// Frontend service for managing notifications

export interface Notification {
  id: string;
  title: string;
  message: string;
  type: string;
  read: boolean;
  createdAt: string;
  data?: Record<string, any>;
}

class NotificationService {
  private baseUrl = "/api/v1/notifications";
  
  // Subscribe to notification types
  async subscribeToNotifications(notificationTypes: string[]): Promise<{ success: boolean; message: string }> {
    const response = await fetch(`${this.baseUrl}/subscribe`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${localStorage.getItem('accessToken')}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ notification_types: notificationTypes })
    });
    
    if (!response.ok) {
      throw new Error(`Failed to subscribe to notifications: ${response.statusText}`);
    }
    
    return response.json();
  }
  
  // Unsubscribe from notification types
  async unsubscribeFromNotifications(notificationTypes: string[]): Promise<{ success: boolean; message: string }> {
    const response = await fetch(`${this.baseUrl}/unsubscribe`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${localStorage.getItem('accessToken')}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ notification_types: notificationTypes })
    });
    
    if (!response.ok) {
      throw new Error(`Failed to unsubscribe from notifications: ${response.statusText}`);
    }
    
    return response.json();
  }
  
  // Get user's notifications
  async getUserNotifications(): Promise<{ notifications: Notification[] }> {
    const response = await fetch(`${this.baseUrl}`, {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${localStorage.getItem('accessToken')}`,
        'Content-Type': 'application/json'
      }
    });
    
    if (!response.ok) {
      throw new Error(`Failed to get notifications: ${response.statusText}`);
    }
    
    return response.json();
  }
  
  // Mark notification as read
  async markNotificationAsRead(notificationId: string): Promise<{ success: boolean; message: string }> {
    const response = await fetch(`${this.baseUrl}/${notificationId}/read`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${localStorage.getItem('accessToken')}`,
        'Content-Type': 'application/json'
      }
    });
    
    if (!response.ok) {
      throw new Error(`Failed to mark notification as read: ${response.statusText}`);
    }
    
    return response.json();
  }
  
  // Send test notification
  async sendTestNotification(
    notificationType: string,
    title: string,
    message: string,
    data?: Record<string, any>
  ): Promise<{ success: boolean; message: string }> {
    const response = await fetch(`${this.baseUrl}/test`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${localStorage.getItem('accessToken')}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        notification_type: notificationType,
        title,
        message,
        data
      })
    });
    
    if (!response.ok) {
      throw new Error(`Failed to send test notification: ${response.statusText}`);
    }
    
    return response.json();
  }
  
  // Request notification permissions (for browser notifications)
  async requestNotificationPermission(): Promise<boolean> {
    if (!('Notification' in window)) {
      // Browser doesn't support desktop notifications
      return false;
    }
    
    if (Notification.permission === 'granted') {
      return true;
    }
    
    if (Notification.permission !== 'denied') {
      const permission = await Notification.requestPermission();
      return permission === 'granted';
    }
    
    return false;
  }
  
  // Show browser notification
  async showBrowserNotification(title: string, message: string, icon?: string): Promise<void> {
    const hasPermission = await this.requestNotificationPermission();
    if (hasPermission) {
      new Notification(title, {
        body: message,
        icon: icon || '/favicon.ico'
      });
    }
  }
}

// Global instance
export const notificationService = new NotificationService();