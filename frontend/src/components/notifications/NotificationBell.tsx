import { useState, useEffect } from "react"
import { Button } from "@/components/ui/button"
import { ScrollArea } from "@/components/ui/scroll-area"
import { Badge } from "@/components/ui/badge"
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover"
import { Bell, BellOff, Check, X } from "lucide-react"
import { Notification, notificationService } from "@/services/notifications"
import { formatDistanceToNow } from "date-fns"
import { ru } from "date-fns/locale"

export function NotificationBell() {
  const [notifications, setNotifications] = useState<Notification[]>([])
  const [unreadCount, setUnreadCount] = useState(0)
  const [isOpen, setIsOpen] = useState(false)

  useEffect(() => {
    loadNotifications()
    
    // Set up periodic checking for new notifications
    const interval = setInterval(() => {
      loadNotifications()
    }, 30000) // Check every 30 seconds
    
    return () => clearInterval(interval)
  }, [])

  const loadNotifications = async () => {
    try {
      const data = await notificationService.getUserNotifications()
      setNotifications(data.notifications)
      setUnreadCount(data.notifications.filter(n => !n.read).length)
    } catch (error) {
      // Error loading notifications - handled by UI
    }
  }

  const markAsRead = async (notificationId: string) => {
    try {
      await notificationService.markNotificationAsRead(notificationId)
      setNotifications(prev => 
        prev.map(n => 
          n.id === notificationId ? { ...n, read: true } : n
        )
      )
      setUnreadCount(prev => prev - 1)
    } catch (error) {
      // Error marking notification as read - handled by UI
    }
  }

  const markAllAsRead = async () => {
    try {
      for (const notification of notifications.filter(n => !n.read)) {
        await notificationService.markNotificationAsRead(notification.id)
      }
      setNotifications(prev => prev.map(n => ({ ...n, read: true })))
      setUnreadCount(0)
    } catch (error) {
      // Error marking all notifications as read - handled by UI
    }
  }

  const formatTime = (timestamp: string) => {
    try {
      return formatDistanceToNow(new Date(timestamp), { 
        addSuffix: true, 
        locale: ru 
      })
    } catch {
      return 'недавно'
    }
  }

  const getNotificationIcon = (type: string) => {
    switch (type) {
      case 'success':
        return <Check className="h-4 w-4 text-green-500" />
      case 'error':
        return <X className="h-4 w-4 text-red-500" />
      case 'warning':
        return <BellOff className="h-4 w-4 text-yellow-500" />
      default:
        return <Bell className="h-4 w-4 text-primary" />
    }
  }

  return (
    <Popover open={isOpen} onOpenChange={setIsOpen}>
      <PopoverTrigger asChild>
        <Button variant="ghost" size="icon" className="relative">
          <Bell className="h-5 w-5" />
          {unreadCount > 0 && (
            <Badge 
              variant="destructive" 
              className="absolute -top-1 -right-1 h-5 w-5 p-0 flex items-center justify-center text-xs"
            >
              {unreadCount}
            </Badge>
          )}
        </Button>
      </PopoverTrigger>
      <PopoverContent className="w-80 p-0" align="end">
        <div className="p-4 border-b">
          <div className="flex items-center justify-between">
            <h3 className="font-semibold">Уведомления</h3>
            {unreadCount > 0 && (
              <Button 
                variant="ghost" 
                size="sm" 
                onClick={markAllAsRead}
                className="h-8 px-2 text-xs"
              >
                Отметить все как прочитанное
              </Button>
            )}
          </div>
        </div>
        
        <ScrollArea className="h-[300px]">
          {notifications.length === 0 ? (
            <div className="p-4 text-center text-muted-foreground">
              <Bell className="h-12 w-12 mx-auto mb-2 opacity-50" />
              <p>Нет уведомлений</p>
            </div>
          ) : (
            <div className="divide-y">
              {notifications.map((notification) => (
                <div 
                  key={notification.id}
                  className={`p-4 hover:bg-gray-50 ${!notification.read ? 'bg-primary/5' : ''}`}
                >
                  <div className="flex items-start gap-3">
                    {getNotificationIcon(notification.type)}
                    <div className="flex-1 min-w-0">
                      <div className="flex items-start justify-between">
                        <h4 className="text-sm font-medium leading-tight">
                          {notification.title}
                        </h4>
                        {!notification.read && (
                          <Button
                            variant="ghost"
                            size="icon"
                            className="h-5 w-5"
                            onClick={() => markAsRead(notification.id)}
                          >
                            <Check className="h-3 w-3" />
                          </Button>
                        )}
                      </div>
                      <p className="text-sm text-muted-foreground mt-1">
                        {notification.message}
                      </p>
                      <p className="text-xs text-muted-foreground mt-2">
                        {formatTime(notification.createdAt)}
                      </p>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </ScrollArea>
      </PopoverContent>
    </Popover>
  )
}