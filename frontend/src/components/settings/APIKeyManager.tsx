import { useState, useEffect } from "react"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Separator } from "@/components/ui/separator"
import { Eye, EyeOff, Save, Trash2, BarChart3 } from "lucide-react"
import { useToast } from "@/hooks/useToast"
import { 
  getApiKeys, 
  addApiKey, 
  deleteApiKey, 
  updateApiKeySettings,
  getAllTokenUsage,
  type ApiKey,
  type TokenUsage
} from "@/api/keys"

const PROVIDER_MODELS: Record<string, Array<{id: string, name: string}>> = {
  "openai": [
    { id: "gpt-4o", name: "GPT-4o" },
    { id: "gpt-4o-mini", name: "GPT-4o Mini" },
    { id: "gpt-4-turbo", name: "GPT-4 Turbo" },
    { id: "gpt-4", name: "GPT-4" },
    { id: "gpt-3.5-turbo", name: "GPT-3.5 Turbo" }
  ],
  "anthropic": [
    { id: "claude-3-5-sonnet-20241022", name: "Claude 3.5 Sonnet (New)" },
    { id: "claude-3-5-sonnet-20240620", name: "Claude 3.5 Sonnet" },
    { id: "claude-3-opus-20240229", name: "Claude 3 Opus" },
    { id: "claude-3-sonnet-20240229", name: "Claude 3 Sonnet" },
    { id: "claude-3-haiku-20240307", name: "Claude 3 Haiku" }
  ],
  "groq": [
    { id: "llama-3.3-70b-versatile", name: "Llama 3.3 70B" },
    { id: "llama-3.1-70b-versatile", name: "Llama 3.1 70B" },
    { id: "llama-3.1-8b-instant", name: "Llama 3.1 8B" },
    { id: "mixtral-8x7b-32768", name: "Mixtral 8x7B" }
  ],
  "openrouter": [
    { id: "openai/gpt-4-turbo", name: "OpenAI: GPT-4 Turbo" },
    { id: "openai/gpt-3.5-turbo", name: "OpenAI: GPT-3.5 Turbo" },
    { id: "anthropic/claude-3-5-sonnet", name: "Anthropic: Claude 3.5 Sonnet" },
    { id: "anthropic/claude-3-opus", name: "Anthropic: Claude 3 Opus" },
    { id: "google/gemini-pro-1.5", name: "Google: Gemini Pro 1.5" },
    { id: "meta-llama/llama-3-70b-instruct", name: "Meta: Llama 3 70B" }
  ]
}

export function APIKeyManager() {
  const { toast } = useToast()
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)
  const [keys, setKeys] = useState<ApiKey[]>([])
  const [tokenUsage, setTokenUsage] = useState<Record<string, Record<string, TokenUsage>>>({})
  const [newApiProvider, setNewApiProvider] = useState("")
  const [newApiKey, setNewApiKey] = useState("")
  const [newApiModel, setNewApiModel] = useState("")
  const [showNewApiKey, setShowNewApiKey] = useState(false)

  useEffect(() => {
    loadKeys()
    loadTokenUsage()
  }, [])

  const loadKeys = async () => {
    try {
      setLoading(true)
      const apiKeys = await getApiKeys()
      setKeys(apiKeys)
    } catch (error) {
      console.error('Error loading API keys:', error)
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
      console.error('Error loading token usage:', error)
    }
  }

  const handleAddApiKey = async () => {
    if (!newApiProvider || !newApiKey.trim()) {
      toast({
        title: "Ошибка",
        description: "Выберите провайдера и введите ключ",
        variant: "destructive"
      })
      return
    }

    try {
      setSaving(true)
      await addApiKey(newApiProvider, newApiKey, newApiModel || undefined)
      await loadKeys()
      setNewApiProvider("")
      setNewApiKey("")
      setNewApiModel("")
      toast({
        title: "Успешно",
        description: `API ключ для ${newApiProvider} добавлен.`
      })
    } catch (error) {
      console.error('Error adding API key:', error)
      toast({
        title: "Ошибка",
        description: error instanceof Error ? error.message : "Не удалось добавить ключ",
        variant: "destructive"
      })
    } finally {
      setSaving(false)
    }
  }

  const handleUpdateSettings = async (provider: string, model: string) => {
    try {
      await updateApiKeySettings(provider, model)
      await loadKeys()
      toast({
        title: "Успешно",
        description: `Настройки для ${provider} обновлены.`
      })
    } catch (error) {
      console.error('Error updating API key settings:', error)
      toast({
        title: "Ошибка",
        description: "Не удалось обновить настройки",
        variant: "destructive"
      })
    }
  }

  const handleDeleteApiKey = async (provider: string) => {
    try {
      await deleteApiKey(provider)
      setKeys(keys.filter(key => key.provider !== provider))
      toast({
        title: "Успешно",
        description: `Ключ для ${provider} удален.`
      })
    } catch (error) {
      console.error('Error deleting API key:', error)
      toast({
        title: "Ошибка",
        description: "Не удалось удалить ключ",
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
          <CardTitle>Управление API ключами</CardTitle>
          <CardDescription>
            Добавьте и управляйте вашими API ключами от AI провайдеров
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-6">
          {keys.length > 0 && (
            <div className="space-y-4">
              <Label>Сохранённые ключи</Label>
              {keys.map((key) => {
                const providerUsage = tokenUsage[key.provider] || {}
                const totalTokens = Object.values(providerUsage).reduce((sum, model) => sum + model.total_tokens, 0)
                const totalRequests = Object.values(providerUsage).reduce((sum, model) => sum + model.requests, 0)

                return (
                  <Card key={key.provider} className="border-2">
                    <CardContent className="pt-6 space-y-4">
                      <div className="flex items-start justify-between">
                        <div className="space-y-2 flex-1">
                          <div className="flex items-center gap-2">
                            <Badge variant="outline">{key.provider}</Badge>
                            <span className="text-sm text-muted-foreground font-mono">
                              {key.display_key}
                            </span>
                          </div>
                          <div className="space-y-2">
                            <Label className="text-sm">Модель по умолчанию</Label>
                            <Select
                              value={key.model || ""}
                              onValueChange={(value) => handleUpdateSettings(key.provider, value)}
                            >
                              <SelectTrigger className="w-64">
                                <SelectValue placeholder="Выберите модель" />
                              </SelectTrigger>
                              <SelectContent>
                                {PROVIDER_MODELS[key.provider] ? (
                                  PROVIDER_MODELS[key.provider].map((model) => (
                                    <SelectItem key={model.id} value={model.id}>
                                      {model.name}
                                    </SelectItem>
                                  ))
                                ) : (
                                  <SelectItem value="placeholder" disabled>Нет доступных моделей</SelectItem>
                                )}
                              </SelectContent>
                            </Select>
                          </div>
                        </div>
                        <Button
                          variant="destructive"
                          size="icon"
                          onClick={() => handleDeleteApiKey(key.provider)}
                        >
                          <Trash2 className="h-4 w-4" />
                        </Button>
                      </div>

                      {Object.keys(providerUsage).length > 0 && (
                        <div className="mt-3 pt-3 border-t">
                          <div className="flex items-center gap-2 mb-2">
                            <BarChart3 className="h-4 w-4 text-muted-foreground" />
                            <Label className="text-sm">Использование токенов</Label>
                          </div>
                          <div className="space-y-1">
                            <div className="flex justify-between text-sm">
                              <span className="text-muted-foreground">Всего токенов:</span>
                              <span className="font-mono">{totalTokens.toLocaleString()}</span>
                            </div>
                            <div className="flex justify-between text-sm">
                              <span className="text-muted-foreground">Запросов:</span>
                              <span className="font-mono">{totalRequests}</span>
                            </div>
                          </div>
                        </div>
                      )}
                    </CardContent>
                  </Card>
                )
              })}
            </div>
          )}

          <Separator />

          <div className="space-y-4">
            <Label>Добавить новый ключ</Label>
            <div className="grid gap-4">
              <div className="space-y-2">
                <Label htmlFor="provider">Провайдер AI</Label>
                <Select value={newApiProvider} onValueChange={setNewApiProvider}>
                  <SelectTrigger id="provider">
                    <SelectValue placeholder="Выберите провайдера" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="openai">OpenAI</SelectItem>
                    <SelectItem value="anthropic">Anthropic</SelectItem>
                    <SelectItem value="groq">Groq</SelectItem>
                    <SelectItem value="openrouter">OpenRouter</SelectItem>
                  </SelectContent>
                </Select>
              </div>

              {newApiProvider && (
                <>
                  <div className="space-y-2">
                    <Label htmlFor="model">Модель (опционально)</Label>
                    <Select value={newApiModel} onValueChange={setNewApiModel}>
                      <SelectTrigger id="model">
                        <SelectValue placeholder="Выберите модель" />
                      </SelectTrigger>
                      <SelectContent>
                        {PROVIDER_MODELS[newApiProvider] ? (
                          PROVIDER_MODELS[newApiProvider].map((model) => (
                            <SelectItem key={model.id} value={model.id}>
                              {model.name}
                            </SelectItem>
                          ))
                        ) : (
                          <SelectItem value="placeholder" disabled>Выберите провайдера</SelectItem>
                        )}
                      </SelectContent>
                    </Select>
                  </div>

                  <div className="space-y-2">
                    <Label htmlFor="apiKey">API Ключ</Label>
                    <div className="relative">
                      <Input
                        id="apiKey"
                        type={showNewApiKey ? "text" : "password"}
                        value={newApiKey}
                        onChange={(e) => setNewApiKey(e.target.value)}
                        placeholder="sk-..."
                        className="pr-10"
                      />
                      <Button
                        type="button"
                        variant="ghost"
                        size="icon"
                        className="absolute right-0 top-0 h-full"
                        onClick={() => setShowNewApiKey(!showNewApiKey)}
                      >
                        {showNewApiKey ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                      </Button>
                    </div>
                  </div>
                </>
              )}

              <Button
                onClick={handleAddApiKey}
                disabled={!newApiKey.trim() || !newApiProvider || saving}
                className="flex items-center gap-2"
              >
                <Save className="h-4 w-4" />
                {saving ? "Добавляем..." : "Добавить ключ"}
              </Button>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}
