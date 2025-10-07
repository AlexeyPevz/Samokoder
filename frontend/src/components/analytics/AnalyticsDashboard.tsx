import { useState, useEffect } from "react"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Separator } from "@/components/ui/separator"
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer, PieChart, Pie, Cell } from "recharts"
import { analyticsService, type UserMetrics, type SystemMetrics, type ActionLog } from "@/services/analytics"
import { useToast } from "@/hooks/useToast"
import { 
  Users, 
  Activity, 
  FileText, 
  MessageSquare, 
  Eye, 
  Wrench,
  Calendar,
  Clock
} from "lucide-react"

export function AnalyticsDashboard() {
  const { toast } = useToast()
  const [userMetrics, setUserMetrics] = useState<UserMetrics | null>(null)
  const [systemMetrics, setSystemMetrics] = useState<SystemMetrics | null>(null)
  const [actionLogs, setActionLogs] = useState<ActionLog[]>([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    loadAnalytics()
  }, [])

  const loadAnalytics = async () => {
    try {
      setLoading(true)
      
      // Load user metrics
      const userMetricsData = await analyticsService.getUserMetrics()
      setUserMetrics(userMetricsData.metrics)
      
      // Load system metrics
      const systemMetricsData = await analyticsService.getSystemMetrics()
      setSystemMetrics(systemMetricsData.metrics)
      
      // Load action logs
      const actionLogsData = await analyticsService.getUserActionLogs(50)
      setActionLogs(actionLogsData.logs)
    } catch (error) {
      // Error loading analytics - handled by UI
      toast({
        title: "Ошибка",
        description: "Не удалось загрузить аналитику",
        variant: "destructive"
      })
    } finally {
      setLoading(false)
    }
  }

  // Format data for charts
  const getActionChartData = () => {
    if (!userMetrics) return []
    
    return Object.entries(userMetrics.actions_by_type).map(([action, count]) => ({
      name: action,
      count
    }))
  }

  const getSystemActionChartData = () => {
    if (!systemMetrics) return []
    
    return systemMetrics.most_common_actions.map(([action, count]) => ({
      name: action,
      count
    }))
  }

  const getActionTypeData = () => {
    if (!userMetrics) return []
    
    const actionTypes = [
      { name: "Создание проектов", value: userMetrics.projects_created, icon: FileText },
      { name: "Сообщения в чате", value: userMetrics.actions_by_type.chat_message || 0, icon: MessageSquare },
      { name: "Просмотры превью", value: userMetrics.actions_by_type.preview_view || 0, icon: Eye },
      { name: "Исправления ошибок", value: userMetrics.actions_by_type.error_fix || 0, icon: Wrench }
    ]
    
    return actionTypes.filter(item => item.value > 0)
  }

  const COLORS = ['#0088FE', '#00C49F', '#FFBB28', '#FF8042', '#8884D8']

  const formatTime = (timestamp: number) => {
    return new Date(timestamp * 1000).toLocaleString('ru-RU')
  }

  const getActionIcon = (action: string) => {
    switch (action) {
      case 'project_create': return <FileText className="h-4 w-4" />
      case 'chat_message': return <MessageSquare className="h-4 w-4" />
      case 'preview_view': return <Eye className="h-4 w-4" />
      case 'error_fix': return <Wrench className="h-4 w-4" />
      default: return <Activity className="h-4 w-4" />
    }
  }

  if (loading) {
    return <div>Загрузка аналитики...</div>
  }

  return (
    <div className="space-y-6">
      <div>
        <h3 className="text-lg font-medium">Аналитика</h3>
        <p className="text-sm text-muted-foreground">
          Статистика использования платформы
        </p>
      </div>

      <Separator />

      {/* User Metrics Summary */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Всего действий</CardTitle>
            <Activity className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {userMetrics?.total_actions || 0}
            </div>
            <p className="text-xs text-muted-foreground">
              Общее количество действий
            </p>
          </CardContent>
        </Card>
        
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Проектов создано</CardTitle>
            <FileText className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {userMetrics?.projects_created || 0}
            </div>
            <p className="text-xs text-muted-foreground">
              Создано проектов
            </p>
          </CardContent>
        </Card>
        
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Проектов использовано</CardTitle>
            <Eye className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {userMetrics?.projects_used_count || 0}
            </div>
            <p className="text-xs text-muted-foreground">
              Уникальных проектов
            </p>
          </CardContent>
        </Card>
        
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Последняя активность</CardTitle>
            <Clock className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {userMetrics?.last_active 
                ? new Date(userMetrics.last_active * 1000).toLocaleDateString('ru-RU')
                : 'Нет данных'}
            </div>
            <p className="text-xs text-muted-foreground">
              Последнее действие
            </p>
          </CardContent>
        </Card>
      </div>

      {/* Action Distribution */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <Card>
          <CardHeader>
            <CardTitle>Распределение действий</CardTitle>
            <CardDescription>
              Ваши действия по типам
            </CardDescription>
          </CardHeader>
          <CardContent>
            {getActionChartData().length > 0 ? (
              <ResponsiveContainer width="100%" height={300}>
                <BarChart data={getActionChartData()}>
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis dataKey="name" />
                  <YAxis />
                  <Tooltip />
                  <Legend />
                  <Bar dataKey="count" fill="#8884d8" name="Количество действий" />
                </BarChart>
              </ResponsiveContainer>
            ) : (
              <div className="flex items-center justify-center h-64 text-muted-foreground">
                Нет данных для отображения
              </div>
            )}
          </CardContent>
        </Card>
        
        <Card>
          <CardHeader>
            <CardTitle>Типы действий</CardTitle>
            <CardDescription>
              Детализация по категориям
            </CardDescription>
          </CardHeader>
          <CardContent>
            {getActionTypeData().length > 0 ? (
              <ResponsiveContainer width="100%" height={300}>
                <PieChart>
                  <Pie
                    data={getActionTypeData()}
                    cx="50%"
                    cy="50%"
                    labelLine={false}
                    outerRadius={80}
                    fill="#8884d8"
                    dataKey="value"
                    label={({ name, percent }) => `${name}: ${((percent as number) * 100).toFixed(0)}%`}
                  >
                    {getActionTypeData().map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                    ))}
                  </Pie>
                  <Tooltip />
                </PieChart>
              </ResponsiveContainer>
            ) : (
              <div className="flex items-center justify-center h-64 text-muted-foreground">
                Нет данных для отображения
              </div>
            )}
          </CardContent>
        </Card>
      </div>

      {/* System Metrics */}
      {systemMetrics && (
        <>
          <Separator />
          
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <Card>
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-sm font-medium">Всего пользователей</CardTitle>
                <Users className="h-4 w-4 text-muted-foreground" />
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold">
                  {systemMetrics.total_users}
                </div>
                <p className="text-xs text-muted-foreground">
                  Зарегистрировано пользователей
                </p>
              </CardContent>
            </Card>
            
            <Card>
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-sm font-medium">Активные (24ч)</CardTitle>
                <Activity className="h-4 w-4 text-muted-foreground" />
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold">
                  {systemMetrics.active_users_24h}
                </div>
                <p className="text-xs text-muted-foreground">
                  Активных за последние 24 часа
                </p>
              </CardContent>
            </Card>
            
            <Card>
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-sm font-medium">Активные (7д)</CardTitle>
                <Calendar className="h-4 w-4 text-muted-foreground" />
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold">
                  {systemMetrics.active_users_7d}
                </div>
                <p className="text-xs text-muted-foreground">
                  Активных за последние 7 дней
                </p>
              </CardContent>
            </Card>
          </div>
          
          <Card>
            <CardHeader>
              <CardTitle>Популярные действия в системе</CardTitle>
              <CardDescription>
                Наиболее частые действия всех пользователей
              </CardDescription>
            </CardHeader>
            <CardContent>
              {systemMetrics.most_common_actions.length > 0 ? (
                <ResponsiveContainer width="100%" height={300}>
                  <BarChart data={getSystemActionChartData()}>
                    <CartesianGrid strokeDasharray="3 3" />
                    <XAxis dataKey="name" />
                    <YAxis />
                    <Tooltip />
                    <Legend />
                    <Bar dataKey="count" fill="#82ca9d" name="Количество действий" />
                  </BarChart>
                </ResponsiveContainer>
              ) : (
                <div className="flex items-center justify-center h-64 text-muted-foreground">
                  Нет данных для отображения
                </div>
              )}
            </CardContent>
          </Card>
        </>
      )}

      {/* Recent Actions */}
      <Separator />
      
      <Card>
        <CardHeader>
          <CardTitle>Последние действия</CardTitle>
          <CardDescription>
            Ваши последние действия в системе
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="space-y-4">
            {actionLogs.length > 0 ? (
              actionLogs.map((log, index) => (
                <div key={index} className="flex items-center justify-between p-3 bg-gray-50 rounded-lg">
                  <div className="flex items-center gap-3">
                    {getActionIcon(log.action)}
                    <div>
                      <p className="font-medium text-sm">
                        {log.action === 'project_create' && 'Создание проекта'}
                        {log.action === 'chat_message' && 'Сообщение в чате'}
                        {log.action === 'preview_view' && 'Просмотр превью'}
                        {log.action === 'error_fix' && 'Исправление ошибки'}
                        {!['project_create', 'chat_message', 'preview_view', 'error_fix'].includes(log.action) && log.action}
                      </p>
                      <p className="text-xs text-muted-foreground">
                        {formatTime(log.timestamp)}
                      </p>
                    </div>
                  </div>
                  <Badge variant="secondary">
                    {log.project_id ? `Проект: ${log.project_id.substring(0, 8)}...` : 'Без проекта'}
                  </Badge>
                </div>
              ))
            ) : (
              <div className="text-center py-8 text-muted-foreground">
                Нет записей о действиях
              </div>
            )}
          </div>
        </CardContent>
      </Card>
    </div>
  )
}