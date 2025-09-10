import { Bell, LogOut, Home, Settings, FolderOpen } from "lucide-react"
import { Button } from "./ui/button"
import { ThemeToggle } from "./ui/theme-toggle"
import { useAuth } from "@/contexts/AuthContext"
import { useNavigate, useLocation } from "react-router-dom"

export function Header() {
  const { logout } = useAuth()
  const navigate = useNavigate()
  const location = useLocation()

  console.log('Header component rendering, current location:', location.pathname)

  const handleLogout = () => {
    console.log('User logging out')
    logout()
    navigate("/login")
  }

  const isActive = (path: string) => location.pathname === path

  return (
    <header className="fixed top-0 z-50 w-full border-b bg-background/80 backdrop-blur-sm">
      <div className="flex h-16 items-center justify-between px-6">
        <div
          className="text-xl font-bold cursor-pointer flex items-center gap-2 text-blue-600"
          onClick={() => navigate("/")}
        >
          <div className="w-8 h-8 bg-gradient-to-br from-blue-500 to-purple-600 rounded-lg flex items-center justify-center text-white text-sm font-bold">
            С
          </div>
          Самокодер
        </div>

        <nav className="hidden md:flex items-center gap-4">
          <Button
            variant={isActive("/") ? "default" : "ghost"}
            size="sm"
            onClick={() => navigate("/")}
            className="flex items-center gap-2"
          >
            <Home className="h-4 w-4" />
            Главная
          </Button>
          <Button
            variant={isActive("/dashboard") ? "default" : "ghost"}
            size="sm"
            onClick={() => navigate("/dashboard")}
            className="flex items-center gap-2"
          >
            <FolderOpen className="h-4 w-4" />
            Проекты
          </Button>
          <Button
            variant={isActive("/settings") ? "default" : "ghost"}
            size="sm"
            onClick={() => navigate("/settings")}
            className="flex items-center gap-2"
          >
            <Settings className="h-4 w-4" />
            Настройки
          </Button>
        </nav>

        <div className="flex items-center gap-4">
          <ThemeToggle />
          <Button variant="ghost" size="icon">
            <Bell className="h-5 w-5" />
          </Button>
          <Button variant="ghost" size="icon" onClick={handleLogout}>
            <LogOut className="h-5 w-5" />
          </Button>
        </div>
      </div>
    </header>
  )
}