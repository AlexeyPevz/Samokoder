import { useState } from "react"
import { Link, useNavigate } from "react-router-dom"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Loader2 } from "lucide-react"
import { login } from "@/api/auth"
import { useAuth } from "@/contexts/AuthContext"
import { useToast } from "@/hooks/useToast"
import { FormField } from "@/components/accessibility/FormField"
import { ErrorAnnouncer, LoadingAnnouncer } from "@/components/accessibility/ErrorAnnouncer"
import { PageTitle } from "@/components/accessibility/ScreenReaderSupport"
import { useFocusManagement } from "@/hooks/useFocusManagement"

export function Login() {
  const navigate = useNavigate()
  const { setUser } = useAuth()
  const { toast } = useToast()
  const { focusRef, setFocus } = useFocusManagement()
  const [email, setEmail] = useState("")
  const [password, setPassword] = useState("")
  const [isLoading, setIsLoading] = useState(false)
  const [errors, setErrors] = useState<{ email?: string; password?: string }>({})

  console.log('Login component rendering')

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setErrors({})
    
    // Валидация email
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    const newErrors: { email?: string; password?: string } = {}
    
    if (!email || !email.trim()) {
      newErrors.email = "Введите email"
    } else if (!emailRegex.test(email)) {
      newErrors.email = "Введите корректный email"
    }
    
    if (!password || !password.trim()) {
      newErrors.password = "Введите пароль"
    } else if (password.length < 6) {
      newErrors.password = "Пароль должен содержать минимум 6 символов"
    }
    
    if (Object.keys(newErrors).length > 0) {
      setErrors(newErrors)
      // Focus на первое поле с ошибкой
      const firstErrorField = document.querySelector('[aria-invalid="true"]') as HTMLElement
      if (firstErrorField) {
        setFocus(firstErrorField)
      }
      return
    }

    try {
      console.log('Attempting login with email:', email)
      setIsLoading(true)
      
      const response = await login({ email, password })
      console.log('Login response received:', response)
      
      if (response.success && response.data) {
        console.log('Login successful, setting user and navigating')
        
        // Сохраняем токены с валидацией
        if (response.data.accessToken && typeof response.data.accessToken === 'string') {
          localStorage.setItem('accessToken', response.data.accessToken)
        }
        if (response.data.refreshToken && typeof response.data.refreshToken === 'string') {
          localStorage.setItem('refreshToken', response.data.refreshToken)
        }
        
        // Устанавливаем пользователя
        if (response.data.user) {
          setUser(response.data.user)
        }
        
        toast({
          title: "Успешно",
          description: "Вход выполнен успешно"
        })
        
        console.log('About to navigate to dashboard')
        navigate("/dashboard")
        console.log('Navigation to dashboard completed')
      } else {
        console.error('Login failed - invalid response structure:', response)
        toast({
          title: "Ошибка",
          description: "Неверные данные для входа",
          variant: "destructive"
        })
      }
    } catch (error) {
      console.error('Login error:', error)
      toast({
        title: "Ошибка",
        description: error instanceof Error ? error.message : "Ошибка входа",
        variant: "destructive"
      })
    } finally {
      setIsLoading(false)
    }
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-blue-50 via-white to-purple-50 p-4">
      <PageTitle 
        title="Вход в Самокодер" 
        description="Введите ваши данные для входа в систему"
      />
      <ErrorAnnouncer error={Object.values(errors)[0] || null} />
      <LoadingAnnouncer loading={isLoading} message="Выполняется вход в систему..." />
      
      <Card className="w-full max-w-md" role="main" aria-labelledby="login-title">
        <CardHeader className="space-y-1">
          <div className="flex items-center justify-center mb-4">
            <div 
              className="w-12 h-12 bg-gradient-to-br from-blue-500 to-purple-600 rounded-xl flex items-center justify-center text-white text-xl font-bold"
              role="img"
              aria-label="Логотип Самокодер"
            >
              С
            </div>
          </div>
          <CardTitle id="login-title" className="text-2xl text-center">
            Вход в Самокодер
          </CardTitle>
          <CardDescription className="text-center">
            Введите ваши данные для входа в систему
          </CardDescription>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleSubmit} className="space-y-4" noValidate>
            <FormField
              id="email"
              label="Email"
              type="email"
              value={email}
              onChange={setEmail}
              error={errors.email}
              required
              disabled={isLoading}
              placeholder="your@email.com"
              description="Введите ваш email адрес"
            />
            
            <FormField
              id="password"
              label="Пароль"
              type="password"
              value={password}
              onChange={setPassword}
              error={errors.password}
              required
              disabled={isLoading}
              placeholder="••••••••"
              description="Введите ваш пароль"
            />
            
            <Button 
              type="submit" 
              className="w-full bg-gradient-to-r from-blue-600 to-purple-600 hover:from-blue-700 hover:to-purple-700 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-500 focus-visible:ring-offset-2"
              disabled={isLoading}
              aria-describedby="login-help"
            >
              {isLoading ? (
                <>
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" aria-hidden="true" />
                  <span className="sr-only">Выполняется вход в систему</span>
                  <span aria-hidden="true">Вход...</span>
                </>
              ) : (
                "Войти"
              )}
            </Button>
            
            <div id="login-help" className="sr-only">
              Нажмите Enter для входа в систему или Tab для перехода к следующему полю
            </div>
          </form>
          
          <div className="mt-4 text-center text-sm">
            <span>Нет аккаунта? </span>
            <Link 
              to="/register" 
              className="text-blue-600 hover:underline focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 rounded"
              aria-label="Перейти к странице регистрации"
            >
              Зарегистрироваться
            </Link>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}