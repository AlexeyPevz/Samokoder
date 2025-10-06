import { useState } from "react"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Separator } from "@/components/ui/separator"
import { Badge } from "@/components/ui/badge"
import { Switch } from "@/components/ui/switch"
import { 
  Users, 
  Settings, 
  BarChart3, 
  Bell, 
  Shield, 
  Database,
  Download,
  RefreshCw,
  Cpu
} from "lucide-react"
import { useToast } from "@/hooks/useToast"
import { AnalyticsDashboard } from "@/components/analytics/AnalyticsDashboard"
import { TokenUsageStats } from "@/components/analytics/TokenUsageStats"

export default function AdminPanel() {
  const { toast } = useToast()
  const [activeTab, setActiveTab] = useState("overview")
  const [systemStatus, setSystemStatus] = useState({
    api: "operational",
    database: "operational",
    websocket: "operational",
    storage: "operational"
  })

  const handleSystemCheck = () => {
    // Simulate system check
    toast({
      title: "Проверка системы",
      description: "Выполняется проверка состояния системы..."
    })
    
    setTimeout(() => {
      toast({
        title: "Система проверена",
        description: "Все компоненты работают нормально"
      })
    }, 2000)
  }

  const handleBackup = () => {
    toast({
      title: "Резервное копирование",
      description: "Начато создание резервной копии данных"
    })
  }

  const handleMaintenance = () => {
    toast({
      title: "Режим обслуживания",
      description: "Система переведена в режим обслуживания"
    })
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-primary-50 via-white to-secondary-50 p-6">
      <div className="mx-auto max-w-6xl space-y-8">
        {/* Header */}
        <div>
          <h1 className="text-3xl font-bold mb-2">Панель администратора</h1>
          <p className="text-muted-foreground">
            Управление системой, пользователями и мониторинг
          </p>
        </div>

        {/* System Status */}
        <Card className="bg-white/80 backdrop-blur-sm border-0 shadow-lg">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Shield className="h-5 w-5" />
              Состояние системы
            </CardTitle>
            <CardDescription>
              Текущее состояние компонентов платформы
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
              <div className="flex items-center justify-between p-3 bg-green-50 rounded-lg">
                <span className="font-medium">API</span>
                <Badge variant="secondary" className="bg-green-100 text-green-800">
                  {systemStatus.api}
                </Badge>
              </div>
              <div className="flex items-center justify-between p-3 bg-green-50 rounded-lg">
                <span className="font-medium">База данных</span>
                <Badge variant="secondary" className="bg-green-100 text-green-800">
                  {systemStatus.database}
                </Badge>
              </div>
              <div className="flex items-center justify-between p-3 bg-green-50 rounded-lg">
                <span className="font-medium">WebSocket</span>
                <Badge variant="secondary" className="bg-green-100 text-green-800">
                  {systemStatus.websocket}
                </Badge>
              </div>
              <div className="flex items-center justify-between p-3 bg-green-50 rounded-lg">
                <span className="font-medium">Хранилище</span>
                <Badge variant="secondary" className="bg-green-100 text-green-800">
                  {systemStatus.storage}
                </Badge>
              </div>
            </div>
            
            <div className="flex gap-3 mt-4">
              <Button onClick={handleSystemCheck} variant="outline" className="flex items-center gap-2">
                <RefreshCw className="h-4 w-4" />
                Проверить систему
              </Button>
              <Button onClick={handleBackup} variant="outline" className="flex items-center gap-2">
                <Download className="h-4 w-4" />
                Создать бэкап
              </Button>
              <Button onClick={handleMaintenance} variant="outline" className="flex items-center gap-2">
                <Settings className="h-4 w-4" />
                Обслуживание
              </Button>
            </div>
          </CardContent>
        </Card>

        {/* Tabs */}
        <Tabs value={activeTab} onValueChange={setActiveTab} className="w-full">
          <TabsList className="grid w-full grid-cols-5">
            <TabsTrigger value="overview" className="flex items-center gap-2">
              <BarChart3 className="h-4 w-4" />
              <span>Аналитика</span>
            </TabsTrigger>
            <TabsTrigger value="usage" className="flex items-center gap-2">
              <Cpu className="h-4 w-4" />
              <span>Использование</span>
            </TabsTrigger>
            <TabsTrigger value="users" className="flex items-center gap-2">
              <Users className="h-4 w-4" />
              <span>Пользователи</span>
            </TabsTrigger>
            <TabsTrigger value="notifications" className="flex items-center gap-2">
              <Bell className="h-4 w-4" />
              <span>Уведомления</span>
            </TabsTrigger>
            <TabsTrigger value="settings" className="flex items-center gap-2">
              <Settings className="h-4 w-4" />
              <span>Настройки</span>
            </TabsTrigger>
          </TabsList>

          <TabsContent value="overview">
            <AnalyticsDashboard />
          </TabsContent>

          <TabsContent value="usage">
            <TokenUsageStats />
          </TabsContent>

          <TabsContent value="users">
            <Card className="bg-white/80 backdrop-blur-sm border-0 shadow-lg">
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Users className="h-5 w-5" />
                  Управление пользователями
                </CardTitle>
                <CardDescription>
                  Просмотр и управление аккаунтами пользователей
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  <div className="flex gap-2">
                    <Input placeholder="Поиск пользователей..." className="flex-1" />
                    <Button>Поиск</Button>
                  </div>
                  
                  <div className="border rounded-lg">
                    <div className="grid grid-cols-4 gap-4 p-4 border-b bg-gray-50 font-medium">
                      <div>Пользователь</div>
                      <div>Email</div>
                      <div>Статус</div>
                      <div>Действия</div>
                    </div>
                    <div className="grid grid-cols-4 gap-4 p-4 border-b">
                      <div>
                        <div className="font-medium">Иван Иванов</div>
                        <div className="text-sm text-muted-foreground">ivan@example.com</div>
                      </div>
                      <div>ivan@example.com</div>
                      <div>
                        <Badge variant="secondary">Активен</Badge>
                      </div>
                      <div className="flex gap-2">
                        <Button variant="outline" size="sm">Редактировать</Button>
                        <Button variant="outline" size="sm">Блокировать</Button>
                      </div>
                    </div>
                    <div className="grid grid-cols-4 gap-4 p-4">
                      <div>
                        <div className="font-medium">Мария Петрова</div>
                        <div className="text-sm text-muted-foreground">maria@example.com</div>
                      </div>
                      <div>maria@example.com</div>
                      <div>
                        <Badge variant="secondary">Активен</Badge>
                      </div>
                      <div className="flex gap-2">
                        <Button variant="outline" size="sm">Редактировать</Button>
                        <Button variant="outline" size="sm">Блокировать</Button>
                      </div>
                    </div>
                  </div>
                </div>
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="notifications">
            <Card className="bg-white/80 backdrop-blur-sm border-0 shadow-lg">
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Bell className="h-5 w-5" />
                  Системные уведомления
                </CardTitle>
                <CardDescription>
                  Управление уведомлениями для пользователей
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  <div className="flex items-center justify-between p-4 bg-blue-50 rounded-lg">
                    <div>
                      <h4 className="font-medium">Плановое обслуживание</h4>
                      <p className="text-sm text-muted-foreground">
                        Платформа будет недоступна 15 сентября с 02:00 до 04:00 по МСК
                      </p>
                    </div>
                    <Button variant="outline">Отправить</Button>
                  </div>
                  
                  <div className="flex items-center justify-between p-4 bg-yellow-50 rounded-lg">
                    <div>
                      <h4 className="font-medium">Обновление функционала</h4>
                      <p className="text-sm text-muted-foreground">
                        Добавлены новые шаблоны для генерации кода
                      </p>
                    </div>
                    <Button variant="outline">Отправить</Button>
                  </div>
                  
                  <div className="space-y-2">
                    <Label>Создать новое уведомление</Label>
                    <Input placeholder="Заголовок уведомления" />
                    <Input placeholder="Текст уведомления" />
                    <Button className="flex items-center gap-2">
                      <Bell className="h-4 w-4" />
                      Отправить всем пользователям
                    </Button>
                  </div>
                </div>
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="settings">
            <Card className="bg-white/80 backdrop-blur-sm border-0 shadow-lg">
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Settings className="h-5 w-5" />
                  Системные настройки
                </CardTitle>
                <CardDescription>
                  Конфигурация платформы и ограничения
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-6">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                  <div className="space-y-2">
                    <Label>Максимум проектов на пользователя</Label>
                    <Input type="number" defaultValue="10" />
                  </div>
                  
                  <div className="space-y-2">
                    <Label>Лимит API вызовов в день</Label>
                    <Input type="number" defaultValue="1000" />
                  </div>
                </div>
                
                <Separator />
                
                <div className="space-y-4">
                  <h4 className="font-medium">Безопасность</h4>
                  
                  <div className="flex items-center justify-between">
                    <div>
                      <Label>Двухфакторная аутентификация</Label>
                      <p className="text-sm text-muted-foreground">
                        Требовать 2FA для всех администраторов
                      </p>
                    </div>
                    <Switch defaultChecked />
                  </div>
                  
                  <div className="flex items-center justify-between">
                    <div>
                      <Label>Регулярные бэкапы</Label>
                      <p className="text-sm text-muted-foreground">
                        Автоматическое резервное копирование данных
                      </p>
                    </div>
                    <Switch defaultChecked />
                  </div>
                </div>
                
                <Button>Сохранить настройки</Button>
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>
      </div>
    </div>
  )
}