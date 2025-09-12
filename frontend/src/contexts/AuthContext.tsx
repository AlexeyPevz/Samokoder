import { createContext, useContext, useState, useEffect, ReactNode } from "react"
import { getUserProfile } from "@/api/users"

interface User {
  _id: string
  email: string
  name?: string
  preferences?: {
    language?: string
    theme?: string
    emailNotifications?: boolean
    browserNotifications?: boolean
  }
  apiProvider?: string
  apiKey?: string
  createdAt?: string
  lastLoginAt?: string
  isActive?: boolean
}

interface AuthContextType {
  user: User | null
  setUser: (user: User | null) => void
  loading: boolean
  logout: () => void
}

const AuthContext = createContext<AuthContextType | undefined>(undefined)

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null)
  const [loading, setLoading] = useState(true)


  useEffect(() => {
    checkAuth()
  }, [])

  const checkAuth = async () => {
    const token = localStorage.getItem('accessToken')
    
    if (!token) {
      setLoading(false)
      return
    }

    try {
      const response = await getUserProfile()
      
      if (response.data) {
        setUser(response.data)
      } else {
        localStorage.removeItem('accessToken')
        localStorage.removeItem('refreshToken')
      }
    } catch (error) {
      console.error('Auth check failed:', error)
      localStorage.removeItem('accessToken')
      localStorage.removeItem('refreshToken')
      setUser(null) // Очищаем состояние пользователя
    } finally {
      setLoading(false)
    }
  }

  const logout = () => {
    localStorage.removeItem('accessToken')
    localStorage.removeItem('refreshToken')
    setUser(null)
  }

  return (
    <AuthContext.Provider value={{ user, setUser, loading, logout }}>
      {children}
    </AuthContext.Provider>
  )
}

export function useAuth() {
  const context = useContext(AuthContext)
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider')
  }
  return context
}