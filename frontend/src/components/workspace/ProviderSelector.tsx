import { useState, useEffect } from "react"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Label } from "@/components/ui/label"
import { Badge } from "@/components/ui/badge"
import { Separator } from "@/components/ui/separator"
import { 
  Play, 
  Square, 
  Settings, 
  Cpu, 
  Database,
  BarChart3
} from "lucide-react"
import { useToast } from "@/hooks/useToast"
import { getApiKeys, updateApiKeySettings, getAllTokenUsage, type ApiKey, type TokenUsage } from "@/api/keys"

interface ProviderModel {
  [provider: string]: string[];
}

const PROVIDER_MODELS: ProviderModel = {
  "openai": [
    "gpt-4-turbo",
    "gpt-4",
    "gpt-3.5-turbo",
    "gpt-4o",
    "gpt-4o-mini"
  ],
  "anthropic": [
    "claude-3-5-sonnet-20240620",
    "claude-3-opus-20240229",
    "claude-3-sonnet-20240229",
    "claude-3-haiku-20240307"
  ],
  "openrouter": [
    "openai/gpt-4-turbo",
    "openai/gpt-4",
    "openai/gpt-3.5-turbo",
    "anthropic/claude-3-5-sonnet",
    "anthropic/claude-3-opus",
    "google/gemini-pro",
    "meta-llama/llama-3-70b-instruct"
  ]
}

export function ProviderSelector() {
  const { toast } = useToast()
  const [loading, setLoading] = useState(true)
  const [keys, setKeys] = useState<ApiKey[]>([])
  const [tokenUsage, setTokenUsage] = useState<Record<string, Record<string, TokenUsage>>>({})
  const [selectedProviders, setSelectedProviders] = useState<Record<string, string>>({})

  useEffect(() => {
    loadKeys()
    loadTokenUsage()
  }, [])

  const loadKeys = async () => {
    try {
      setLoading(true)
      const apiKeys = await getApiKeys()
      setKeys(apiKeys)
      
      // Initialize selected providers with default models
      const initialSelected: Record<string, string> = {}
      apiKeys.forEach(key => {
        if (key.model) {
          initialSelected[key.provider] = key.model
        } else if (PROVIDER_MODELS[key.provider] && PROVIDER_MODELS[key.provider].length > 0) {
          // Set first available model as default
          initialSelected[key.provider] = PROVIDER_MODELS[key.provider][0]
        }
      })
      setSelectedProviders(initialSelected)
    } catch (error) {
      // Error loading API keys
      toast({
        title: "Ошибка",
        description: "Не удалось загрузить API ключи",
        variant: "destructive"
      })
    } finally {
      setLoading(false)
    }
  }

  const loadTokenUsage = async () => {
    try {
      const usage = await getAllTokenUsage()
      setTokenUsage(usage)
    } catch (error) {
      // Error loading token usage
    }
  }

  const handleModelChange = async (provider: string, model: string) => {
    try {
      // Update selected model in state
      setSelectedProviders(prev => ({
        ...prev,
        [provider]: model
      }))
      
      // Update settings on backend
      await updateApiKeySettings(provider, model)
      
      toast({
        title: "Успешно",
        description: `Модель для ${provider} обновлена.`
      })
    } catch (error) {
      // Error updating model
      toast({
        title: "Ошибка",
        description: "Не удалось обновить модель",
        variant: "destructive"
      })
    }
  }

  if (loading) {
    return (
      <div className="space-y-4">
        <div className="animate-pulse space-y-4">
          <div className="h-4 bg-gray-200 rounded w-1/4"></div>
          <div className="h-10 bg-gray-200 rounded"></div>
          <div className="h-20 bg-gray-200 rounded"></div>
        </div>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Cpu className="h-5 w-5" />
            Выбор провайдера и модели
          </CardTitle>
          <CardDescription>
            Выберите провайдера AI и модель для генерации кода
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-6">
          {keys.length === 0 ? (
            <div className="text-center py-8 text-muted-foreground">
              <Cpu className="h-12 w-12 mx-auto mb-2 opacity-50" />
              <p>Нет доступных API ключей</p>
              <p className="text-sm mt-2">Добавьте API ключ в разделе "API Ключи"</p>
            </div>
          ) : (
            <div className="space-y-4">
              {keys.map((key) => {
                const providerUsage = tokenUsage[key.provider] || {}
                const totalTokens = Object.values(providerUsage).reduce((sum, model) => sum + model.total_tokens, 0)
                const totalRequests = Object.values(providerUsage).reduce((sum, model) => sum + model.requests, 0)
                
                return (
                  <Card key={key.provider} className="bg-gray-50">
                    <CardContent className="p-4">
                      <div className="flex items-center justify-between mb-3">
                        <div className="flex items-center gap-2">
                          <span className="font-medium capitalize">{key.provider}</span>
                          <Badge variant="secondary" className="font-mono text-xs">
                            {key.display_key}
                          </Badge>
                        </div>
                        
                        <div className="flex items-center gap-4 text-sm text-muted-foreground">
                          <span>Токены: {totalTokens.toLocaleString()}</span>
                          <span>Запросы: {totalRequests.toLocaleString()}</span>
                        </div>
                      </div>
                      
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                        <div className="space-y-2">
                          <Label>Модель</Label>
                          <Select 
                            value={selectedProviders[key.provider] || ""} 
                            onValueChange={(value) => handleModelChange(key.provider, value)}
                          >
                            <SelectTrigger>
                              <SelectValue placeholder="Выберите модель" />
                            </SelectTrigger>
                            <SelectContent>
                              {PROVIDER_MODELS[key.provider] ? (
                                PROVIDER_MODELS[key.provider].map((model) => (
                                  <SelectItem key={model} value={model}>
                                    {model}
                                  </SelectItem>
                                ))
                              ) : (
                                <SelectItem value="">Нет доступных моделей</SelectItem>
                              )}
                            </SelectContent>
                          </Select>
                        </div>
                        
                        <div className="space-y-2">
                          <Label>Статистика использования</Label>
                          <div className="flex items-center gap-2 text-sm">
                            <BarChart3 className="h-4 w-4" />
                            <span>
                              {Object.keys(providerUsage).length > 0 
                                ? `${Object.keys(providerUsage).length} моделей использовано` 
                                : "Нет данных"}
                            </span>
                          </div>
                        </div>
                      </div>
                      
                      {/* Token usage breakdown */}
                      {Object.keys(providerUsage).length > 0 && (
                        <div className="mt-3 pt-3 border-t">
                          <h4 className="text-sm font-medium mb-2">Использование по моделям</h4>
                          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-2">
                            {Object.entries(providerUsage).map(([model, usage]) => (
                              <div key={model} className="p-2 bg-white rounded text-xs">
                                <div className="font-medium truncate">{model}</div>
                                <div className="text-muted-foreground">
                                  {usage.total_tokens.toLocaleString()} токенов
                                </div>
                                <div className="text-muted-foreground">
                                  {usage.requests} запросов
                                </div>
                              </div>
                            ))}
                          </div>
                        </div>
                      )}
                    </CardContent>
                  </Card>
                )
              })}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  )
}