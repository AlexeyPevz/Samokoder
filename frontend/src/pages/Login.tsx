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

export function Login() {
  const navigate = useNavigate()
  const { setUser } = useAuth()
  const { toast } = useToast()
  const [email, setEmail] = useState("")
  const [password, setPassword] = useState("")
  const [isLoading, setIsLoading] = useState(false)

  console.log('Login component rendering')

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    
    if (!email || !password) {
      toast({
        title: "Ошибка",
        description: "Заполните все поля",
        variant: "destructive"
      })
      return
    }

    try {
      console.log('Attempting login with email:', email)
      setIsLoading(true)
      
      const response = await login({ email, password })
      console.log('Login response received:', response)
      
      if (response.success && response.user) {
        console.log('Login successful, setting user and navigating')
        setUser(response.user)
        
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
      <Card className="w-full max-w-md">
        <CardHeader className="space-y-1">
          <div className="flex items-center justify-center mb-4">
            <div className="w-12 h-12 bg-gradient-to-br from-blue-500 to-purple-600 rounded-xl flex items-center justify-center text-white text-xl font-bold">
              С
            </div>
          </div>
          <CardTitle className="text-2xl text-center">Вход в Самокодер</CardTitle>
          <CardDescription className="text-center">
            Введите ваши данные для входа в систему
          </CardDescription>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleSubmit} className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="email">Email</Label>
              <Input
                id="email"
                type="email"
                placeholder="your@email.com"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                disabled={isLoading}
                required
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="password">Пароль</Label>
              <Input
                id="password"
                type="password"
                placeholder="••••••••"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                disabled={isLoading}
                required
              />
            </div>
            <Button 
              type="submit" 
              className="w-full bg-gradient-to-r from-blue-600 to-purple-600 hover:from-blue-700 hover:to-purple-700"
              disabled={isLoading}
            >
              {isLoading ? (
                <>
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                  Вход...
                </>
              ) : (
                "Войти"
              )}
            </Button>
          </form>
          <div className="mt-4 text-center text-sm">
            Нет аккаунта?{" "}
            <Link to="/register" className="text-blue-600 hover:underline">
              Зарегистрироваться
            </Link>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}