import { useState } from "react"
import { Link, useNavigate } from "react-router-dom"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card"
import { useToast } from "@/hooks/useToast"
import { Loader2 } from "lucide-react"
import { register } from "@/api/auth"
import { useAuth } from "@/contexts/AuthContext"
import { FormField } from "@/components/accessibility/FormField"
import { ErrorAnnouncer, LoadingAnnouncer } from "@/components/accessibility/ErrorAnnouncer"
import { PageTitle } from "@/components/accessibility/ScreenReaderSupport"
import { useFocusManagement } from "@/hooks/useFocusManagement"

export default function Register() {
  const navigate = useNavigate()
  const { setUser } = useAuth()
  const { toast } = useToast()
  const { focusRef, setFocus } = useFocusManagement()
  const [email, setEmail] = useState("")
  const [password, setPassword] = useState("")
  const [isLoading, setIsLoading] = useState(false)
  const [errors, setErrors] = useState<{ email?: string; password?: string }>({})

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
      setIsLoading(true)
      
      const response = await register({ email, password });
      
      if (response.success && response.data) {
        // P0-2: Tokens are now in httpOnly cookies, no localStorage needed
        // Just set the user in context
        if (response.data.user) {
          setUser(response.data.user)
        }
        
        toast({
          title: "Успешно",
          description: "Аккаунт создан успешно",
        })
        navigate("/dashboard")
      } else {
        throw new Error("Ошибка регистрации")
      }
    } catch (error) {
      toast({
        variant: "destructive",
        title: "Ошибка",
        description: error instanceof Error ? error.message : "Ошибка регистрации",
      })
    } finally {
      setIsLoading(false)
    }
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-primary-50 via-white to-secondary-50 p-4">
      <PageTitle 
        title="Регистрация в Самокодер" 
        description="Создайте аккаунт для начала работы"
      />
      <ErrorAnnouncer error={Object.values(errors)[0] || null} />
      <LoadingAnnouncer loading={isLoading} message="Создание аккаунта..." />
      
      <Card className="w-full max-w-md" role="main" aria-labelledby="register-title">
        <CardHeader className="space-y-1">
          <div className="flex items-center justify-center mb-4">
            <div 
              className="w-12 h-12 bg-gradient-to-br from-primary to-accent rounded-xl flex items-center justify-center text-white text-xl font-bold"
              role="img"
              aria-label="Логотип Самокодер"
            >
              С
            </div>
          </div>
          <CardTitle id="register-title" className="text-2xl text-center">
            Регистрация
          </CardTitle>
          <CardDescription className="text-center">
            Создайте аккаунт для начала работы
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
              description="Минимум 6 символов"
            />
            
            <Button 
              type="submit" 
              className="w-full bg-primary hover:bg-primary/90 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary focus-visible:ring-offset-2"
              disabled={isLoading}
              aria-describedby="register-help"
            >
              {isLoading ? (
                <>
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" aria-hidden="true" />
                  <span className="sr-only">Создание аккаунта</span>
                  <span aria-hidden="true">Создание...</span>
                </>
              ) : (
                "Зарегистрироваться"
              )}
            </Button>
            
            <div id="register-help" className="sr-only">
              Нажмите Enter для регистрации или Tab для перехода к следующему полю
            </div>
          </form>
          
          <div className="mt-4 text-center text-sm">
            <span>Уже есть аккаунт? </span>
            <Link 
              to="/login" 
              className="text-primary hover:underline focus:outline-none focus:ring-2 focus:ring-primary focus:ring-offset-2 rounded"
              aria-label="Перейти к странице входа"
            >
              Войти
            </Link>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}
