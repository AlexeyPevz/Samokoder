import { useState, useEffect } from "react"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { 
  TrendingUp, 
  TrendingDown, 
  Minus,
  BarChart3,
  Activity,
  Users
} from "lucide-react"
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer } from "recharts"
import { tokenUsageService, type UserTokenUsage } from "@/api/tokenUsage"
import { formatDistanceToNow } from "date-fns"
import { ru } from "date-fns/locale"
import { useToast } from "@/hooks/useToast"
import { Button } from "@/components/ui/button"
import { RefreshCw } from "lucide-react"

interface TokenUsageData {
  provider: string;
  model: string;
  totalTokens: number;
  requests: number;
  lastUsed: number;
  avgTokensPerRequest: number;
}

export function TokenUsageStats() {
  const { toast } = useToast()
  const [usageData, setUsageData] = useState<TokenUsageData[]>([])
  const [timeRange, setTimeRange] = useState<'day' | 'week' | 'month' | 'all'>('week')
  const [sortBy, setSortBy] = useState<'tokens' | 'requests' | 'recent'>('tokens')
  const [loading, setLoading] = useState(true)
  const [summary, setSummary] = useState({
    totals: {
      providers: 0,
      tokens: 0,
      requests: 0
    },
    providers: {} as Record<string, any>
  })

  useEffect(() => {
    loadUsageData()
    
    // Update data every 30 seconds
    const interval = setInterval(() => {
      loadUsageData()
    }, 30000)
    
    return () => clearInterval(interval)
  }, [timeRange, sortBy])

  const loadUsageData = async () => {
    try {
      setLoading(true)
      
      // Get usage data
      const usageResponse = await tokenUsageService.getTokenUsage()
      const usage = usageResponse.usage
      
      // Get summary
      const summaryResponse = await tokenUsageService.getTokenUsageSummary()
      setSummary(summaryResponse)
      
      // Convert to array and add calculated fields
      const dataArray: TokenUsageData[] = []
      
      Object.entries(usage).forEach(([provider, providerData]) => {
        Object.entries(providerData).forEach(([model, modelData]) => {
          dataArray.push({
            provider,
            model,
            totalTokens: modelData.total_tokens,
            requests: modelData.requests,
            lastUsed: modelData.updated_at ? new Date(modelData.updated_at).getTime() : Date.now(),
            avgTokensPerRequest: modelData.requests > 0 ? Math.round(modelData.total_tokens / modelData.requests) : 0
          })
        })
      })
      
      // Sort data
      const sortedData = sortData(dataArray, sortBy)
      
      setUsageData(sortedData)
    } catch (error) {
      console.error("Error loading token usage data:", error)
      toast({
        title: "Ошибка",
        description: "Не удалось загрузить данные об использовании токенов",
        variant: "destructive"
      })
    } finally {
      setLoading(false)
    }
  }

  const sortData = (data: TokenUsageData[], sortBy: string) => {
    switch (sortBy) {
      case 'tokens':
        return [...data].sort((a, b) => b.totalTokens - a.totalTokens)
      case 'requests':
        return [...data].sort((a, b) => b.requests - a.requests)
      case 'recent':
        return [...data].sort((a, b) => b.lastUsed - a.lastUsed)
      default:
        return data
    }
  }

  // Format time
  const formatTime = (timestamp: number) => {
    try {
      return formatDistanceToNow(new Date(timestamp), { 
        addSuffix: true, 
        locale: ru 
      })
    } catch {
      return 'недавно'
    }
  }

  // Get trend indicator
  const getTrendIndicator = (avgTokens: number, prevAvg?: number) => {
    if (!prevAvg) return <Minus className="h-4 w-4 text-gray-400" />
    
    if (avgTokens > prevAvg * 1.1) {
      return <TrendingUp className="h-4 w-4 text-green-500" />
    } else if (avgTokens < prevAvg * 0.9) {
      return <TrendingDown className="h-4 w-4 text-red-500" />
    } else {
      return <Minus className="h-4 w-4 text-gray-400" />
    }
  }

  const handleRefresh = () => {
    loadUsageData()
  }

  if (loading) {
    return (
      <div className="space-y-6">
        <div className="animate-pulse space-y-4">
          <div className="h-4 bg-gray-200 rounded w-1/4"></div>
          <div className="h-64 bg-gray-200 rounded"></div>
          <div className="h-64 bg-gray-200 rounded"></div>
        </div>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      {/* Header with refresh button */}
      <div className="flex items-center justify-between">
        <h3 className="text-lg font-medium">Статистика использования токенов</h3>
        <Button variant="outline" size="sm" onClick={handleRefresh}>
          <RefreshCw className="h-4 w-4 mr-2" />
          Обновить
        </Button>
      </div>

      {/* Summary Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Всего токенов</CardTitle>
            <TrendingUp className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {summary.totals.tokens.toLocaleString()}
            </div>
            <p className="text-xs text-muted-foreground">
              Использовано за выбранный период
            </p>
          </CardContent>
        </Card>
        
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Всего запросов</CardTitle>
            <TrendingUp className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {summary.totals.requests.toLocaleString()}
            </div>
            <p className="text-xs text-muted-foreground">
              Выполнено за выбранный период
            </p>
          </CardContent>
        </Card>
        
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Провайдеров</CardTitle>
            <TrendingUp className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {summary.totals.providers}
            </div>
            <p className="text-xs text-muted-foreground">
              Активных провайдеров
            </p>
          </CardContent>
        </Card>
      </div>

      {/* Provider Breakdown */}
      <Card>
        <CardHeader>
          <CardTitle>По провайдерам</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-4">
            {Object.entries(summary.providers).map(([provider, data]) => (
              <div key={provider} className="flex items-center justify-between p-3 bg-gray-50 rounded-lg">
                <div className="flex items-center gap-3">
                  <div className="w-10 h-10 bg-gradient-to-br from-primary to-accent rounded-lg flex items-center justify-center">
                    <span className="text-white font-bold text-sm uppercase">
                      {provider.charAt(0)}
                    </span>
                  </div>
                  <div>
                    <h4 className="font-medium capitalize">{provider}</h4>
                    <p className="text-sm text-muted-foreground">
                      {data.models} моделей
                    </p>
                  </div>
                </div>
                
                <div className="text-right">
                  <div className="font-medium">
                    {data.tokens.toLocaleString()} токенов
                  </div>
                  <div className="text-sm text-muted-foreground">
                    {data.requests.toLocaleString()} запросов
                  </div>
                </div>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>

      {/* Detailed Usage Table */}
      <Card>
        <CardHeader>
          <CardTitle>Детализация использования</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b">
                  <th className="text-left py-2 px-2">Провайдер</th>
                  <th className="text-left py-2 px-2">Модель</th>
                  <th className="text-right py-2 px-2">Токены</th>
                  <th className="text-right py-2 px-2">Запросы</th>
                  <th className="text-right py-2 px-2">Среднее</th>
                  <th className="text-right py-2 px-2">Последнее</th>
                </tr>
              </thead>
              <tbody>
                {usageData.map((item, index) => (
                  <tr key={`${item.provider}-${item.model}`} className="border-b hover:bg-gray-50">
                    <td className="py-2 px-2">
                      <Badge variant="outline" className="capitalize">
                        {item.provider}
                      </Badge>
                    </td>
                    <td className="py-2 px-2 text-sm">
                      {item.model}
                    </td>
                    <td className="py-2 px-2 text-right font-medium">
                      {item.totalTokens.toLocaleString()}
                    </td>
                    <td className="py-2 px-2 text-right">
                      {item.requests.toLocaleString()}
                    </td>
                    <td className="py-2 px-2 text-right text-sm text-muted-foreground">
                      {item.avgTokensPerRequest.toLocaleString()}
                    </td>
                    <td className="py-2 px-2 text-right text-sm text-muted-foreground">
                      {formatTime(item.lastUsed)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </CardContent>
      </Card>

      {/* Chart Visualization */}
      <Card>
        <CardHeader>
          <CardTitle>График использования</CardTitle>
        </CardHeader>
        <CardContent className="h-80">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart
              data={usageData.slice(0, 10)} // Top 10 models
              margin={{ top: 20, right: 30, left: 20, bottom: 50 }}
            >
              <CartesianGrid strokeDasharray="3 3" />
              <XAxis 
                dataKey="model" 
                angle={-45} 
                textAnchor="end" 
                height={60}
                tick={{ fontSize: 12 }}
              />
              <YAxis />
              <Tooltip 
                formatter={(value) => [value.toLocaleString(), 'Значение']}
                labelFormatter={(label) => `Модель: ${label}`}
              />
              <Legend />
              <Bar 
                dataKey="totalTokens" 
                name="Токены" 
                fill="#8884d8" 
                radius={[4, 4, 0, 0]}
              />
              <Bar 
                dataKey="requests" 
                name="Запросы" 
                fill="#82ca9d" 
                radius={[4, 4, 0, 0]}
              />
            </BarChart>
          </ResponsiveContainer>
        </CardContent>
      </Card>
    </div>
  )
}