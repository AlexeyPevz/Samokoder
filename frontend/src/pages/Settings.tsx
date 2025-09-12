import { useState, useEffect } from "react"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Switch } from "@/components/ui/switch"
import { Separator } from "@/components/ui/separator"
import { Badge } from "@/components/ui/badge"
import { Eye, EyeOff, TestTube, Save, Trash2, CreditCard } from "lucide-react"
import { useToast } from "@/hooks/useToast"
import { motion } from "framer-motion"
import { getUserProfile, updateUserProfile } from "@/api/users"

export function Settings() {
  const { toast } = useToast()
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)
  const [showApiKey, setShowApiKey] = useState(false)
  const [apiProvider, setApiProvider] = useState("openrouter")
  const [apiKey, setApiKey] = useState("")
  const [isTestingConnection, setIsTestingConnection] = useState(false)
  const [theme, setTheme] = useState("light")
  const [language, setLanguage] = useState("ru")
  const [emailNotifications, setEmailNotifications] = useState(true)
  const [browserNotifications, setBrowserNotifications] = useState(true)

  // Load user profile on component mount
  useEffect(() => {
    const loadUserProfile = async () => {
      try {
        setLoading(true)
        const response = await getUserProfile()
        
        if (response.success && response.data) {
          const user = response.data
          setApiProvider(user.apiProvider || "openrouter")
          setApiKey(user.apiKey || "")
          setTheme(user.preferences?.theme || "light")
          setLanguage(user.preferences?.language || "ru")
          setEmailNotifications(user.preferences?.emailNotifications ?? true)
          setBrowserNotifications(user.preferences?.browserNotifications ?? true)
        }
      } catch (error) {
        console.error('Error loading user profile:', error)
        toast({
          title: "Ошибка",
          description: error.message,
          variant: "destructive"
        })
      } finally {
        setLoading(false)
      }
    }

    loadUserProfile()
  }, [toast])

  const handleSaveApiSettings = async () => {
    try {
      setSaving(true)
      
      await updateUserProfile({
        apiProvider,
        apiKey
      })

      toast({
        title: "Настройки сохранены",
        description: "API настройки успешно обновлены"
      })
    } catch (error) {
      console.error('Error saving API settings:', error)
      toast({
        title: "Ошибка",
        description: error.message,
        variant: "destructive"
      })
    } finally {
      setSaving(false)
    }
  }

  const handleTestConnection = async () => {
    if (!apiKey.trim()) {
      toast({
        title: "Ошибка",
        description: "Введите API ключ",
        variant: "destructive"
      })
      return
    }

    setIsTestingConnection(true)

    // Simulate API test
    setTimeout(() => {
      setIsTestingConnection(false)
      toast({
        title: "Подключение успешно",
        description: "API ключ работает корректно"
      })
    }, 2000)
  }

  const handleSavePreferences = async () => {
    try {
      setSaving(true)
      
      await updateUserProfile({
        preferences: {
          theme,
          language,
          emailNotifications,
          browserNotifications
        }
      })

      toast({
        title: "Настройки сохранены",
        description: "Предпочтения успешно обновлены"
      })
    } catch (error) {
      console.error('Error saving preferences:', error)
      toast({
        title: "Ошибка",
        description: error.message,
        variant: "destructive"
      })
    } finally {
      setSaving(false)
    }
  }

  if (loading) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-blue-50 via-white to-purple-50 p-6">
        <div className="mx-auto max-w-4xl">
          <div className="animate-pulse space-y-8">
            <div className="h-8 bg-gray-200 rounded w-1/4"></div>
            <div className="h-64 bg-gray-200 rounded"></div>
            <div className="h-64 bg-gray-200 rounded"></div>
          </div>
        </div>
      </div>
    )
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50 via-white to-purple-50 p-6">
      <div className="mx-auto max-w-4xl space-y-8">
        {/* Header */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6 }}
        >
          <h1 className="text-3xl font-bold mb-2">Настройки</h1>
          <p className="text-muted-foreground">
            Управляйте настройками API, предпочтениями и аккаунтом
          </p>
        </motion.div>

        {/* API Configuration */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6, delay: 0.1 }}
        >
          <Card className="bg-white/80 backdrop-blur-sm border-0 shadow-lg">
            <CardHeader>
              <CardTitle>Настройки API</CardTitle>
              <CardDescription>
                Настройте подключение к AI провайдерам для генерации приложений
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              <div className="space-y-2">
                <Label htmlFor="provider">Провайдер AI</Label>
                <Select value={apiProvider} onValueChange={setApiProvider}>
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="openrouter">OpenRouter</SelectItem>
                    <SelectItem value="openai">OpenAI</SelectItem>
                    <SelectItem value="anthropic">Anthropic Claude</SelectItem>
                    <SelectItem value="custom">Пользовательский endpoint</SelectItem>
                  </SelectContent>
                </Select>
              </div>

              <div className="space-y-2">
                <Label htmlFor="apikey">API Ключ</Label>
                <div className="relative">
                  <Input
                    id="apikey"
                    type={showApiKey ? "text" : "password"}
                    placeholder="Введите ваш API ключ..."
                    value={apiKey}
                    onChange={(e) => setApiKey(e.target.value)}
                    className="pr-20"
                  />
                  <div className="absolute right-2 top-1/2 -translate-y-1/2 flex items-center gap-1">
                    <Button
                      type="button"
                      variant="ghost"
                      size="icon"
                      className="h-8 w-8"
                      onClick={() => setShowApiKey(!showApiKey)}
                    >
                      {showApiKey ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                    </Button>
                  </div>
                </div>
                {apiKey && (
                  <p className="text-xs text-muted-foreground">
                    Ключ: ***{apiKey.slice(-4)}
                  </p>
                )}
              </div>

              <div className="flex gap-3">
                <Button
                  onClick={handleTestConnection}
                  disabled={!apiKey.trim() || isTestingConnection}
                  variant="outline"
                  className="flex items-center gap-2"
                >
                  <TestTube className="h-4 w-4" />
                  {isTestingConnection ? "Тестируем..." : "Тест подключения"}
                </Button>

                <Button
                  onClick={handleSaveApiSettings}
                  disabled={!apiKey.trim() || saving}
                  className="flex items-center gap-2"
                >
                  <Save className="h-4 w-4" />
                  {saving ? "Сохраняем..." : "Сохранить"}
                </Button>
              </div>
            </CardContent>
          </Card>
        </motion.div>

        {/* Preferences */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6, delay: 0.2 }}
        >
          <Card className="bg-white/80 backdrop-blur-sm border-0 shadow-lg">
            <CardHeader>
              <CardTitle>Предпочтения</CardTitle>
              <CardDescription>
                Настройте интерфейс и уведомления под ваши потребности
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div className="space-y-2">
                  <Label>Тема оформления</Label>
                  <Select value={theme} onValueChange={setTheme}>
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="light">Светлая</SelectItem>
                      <SelectItem value="dark">Темная</SelectItem>
                      <SelectItem value="auto">Автоматически</SelectItem>
                    </SelectContent>
                  </Select>
                </div>

                <div className="space-y-2">
                  <Label>Язык интерфейса</Label>
                  <Select value={language} onValueChange={setLanguage}>
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="ru">Русский</SelectItem>
                      <SelectItem value="en">English</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
              </div>

              <Separator />

              <div className="space-y-4">
                <h4 className="font-medium">Уведомления</h4>

                <div className="flex items-center justify-between">
                  <div>
                    <Label>Email уведомления</Label>
                    <p className="text-sm text-muted-foreground">
                      Получать уведомления о завершении проектов на email
                    </p>
                  </div>
                  <Switch
                    checked={emailNotifications}
                    onCheckedChange={setEmailNotifications}
                  />
                </div>

                <div className="flex items-center justify-between">
                  <div>
                    <Label>Браузерные уведомления</Label>
                    <p className="text-sm text-muted-foreground">
                      Показывать push-уведомления в браузере
                    </p>
                  </div>
                  <Switch
                    checked={browserNotifications}
                    onCheckedChange={setBrowserNotifications}
                  />
                </div>
              </div>

              <Button 
                onClick={handleSavePreferences} 
                disabled={saving}
                className="w-full md:w-auto"
              >
                <Save className="mr-2 h-4 w-4" />
                {saving ? "Сохраняем..." : "Сохранить предпочтения"}
              </Button>
            </CardContent>
          </Card>
        </motion.div>

        {/* Account */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6, delay: 0.3 }}
        >
          <Card className="bg-white/80 backdrop-blur-sm border-0 shadow-lg">
            <CardHeader>
              <CardTitle>Аккаунт</CardTitle>
              <CardDescription>
                Управление подпиской и настройками аккаунта
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              <div className="flex items-center justify-between p-4 bg-blue-50 rounded-lg">
                <div>
                  <h4 className="font-medium">Текущий план</h4>
                  <p className="text-sm text-muted-foreground">Базовый план</p>
                </div>
                <Badge className="bg-blue-100 text-blue-700">
                  Активен
                </Badge>
              </div>

              <div className="space-y-3">
                <div className="flex justify-between text-sm">
                  <span>Использовано проектов</span>
                  <span>3 из 10</span>
                </div>
                <div className="w-full bg-gray-200 rounded-full h-2">
                  <div className="bg-blue-600 h-2 rounded-full" style={{ width: '30%' }}></div>
                </div>
              </div>

              <div className="flex gap-3">
                <Button variant="outline" className="flex items-center gap-2">
                  <CreditCard className="h-4 w-4" />
                  Обновить план
                </Button>

                <Button variant="outline">
                  История платежей
                </Button>
              </div>

              <Separator />

              <div className="space-y-4">
                <h4 className="font-medium text-red-600">Опасная зона</h4>
                <p className="text-sm text-muted-foreground">
                  Удаление аккаунта необратимо и приведет к потере всех данных
                </p>
                <Button variant="destructive" className="flex items-center gap-2">
                  <Trash2 className="h-4 w-4" />
                  Удалить аккаунт
                </Button>
              </div>
            </CardContent>
          </Card>
        </motion.div>
      </div>
    </div>
  )
}