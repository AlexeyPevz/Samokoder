import { useState } from "react"
import { Bell, LogOut, Home, Settings, FolderOpen, Menu } from "lucide-react"
import { Button } from "./ui/button"
import { ThemeToggle } from "./ui/theme-toggle"
import { useAuth } from "@/contexts/AuthContext"
import { useNavigate, useLocation } from "react-router-dom"
import SamokoderLogo from "./ui/SamokoderLogo"
import { SamokoderIcon } from "./ui/SamokoderIcons"

export function Header() {
  const { logout } = useAuth()
  const navigate = useNavigate()
  const location = useLocation()
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false)

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
          className="cursor-pointer"
          onClick={() => navigate("/")}
        >
          <SamokoderLogo 
            variant="default" 
            size="md" 
            showText={true}
            className="hover:opacity-80 transition-opacity"
          />
        </div>

        <nav 
          id="navigation"
          className="hidden md:flex items-center gap-4"
          role="navigation"
          aria-label="Основная навигация"
        >
          <Button
            variant={isActive("/") ? "default" : "ghost"}
            size="sm"
            onClick={() => navigate("/")}
            className="flex items-center gap-2 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-samokoder-blue focus-visible:ring-offset-2"
            aria-current={isActive("/") ? "page" : undefined}
          >
            <Home className="h-4 w-4" aria-hidden="true" />
            Главная
          </Button>
          <Button
            variant={isActive("/dashboard") ? "default" : "ghost"}
            size="sm"
            onClick={() => navigate("/dashboard")}
            className="flex items-center gap-2 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-samokoder-blue focus-visible:ring-offset-2"
            aria-current={isActive("/dashboard") ? "page" : undefined}
          >
            <FolderOpen className="h-4 w-4" aria-hidden="true" />
            Проекты
          </Button>
          <Button
            variant={isActive("/settings") ? "default" : "ghost"}
            size="sm"
            onClick={() => navigate("/settings")}
            className="flex items-center gap-2 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-samokoder-blue focus-visible:ring-offset-2"
            aria-current={isActive("/settings") ? "page" : undefined}
          >
            <Settings className="h-4 w-4" aria-hidden="true" />
            Настройки
          </Button>
          <Button
            variant={isActive("/brand") ? "default" : "ghost"}
            size="sm"
            onClick={() => navigate("/brand")}
            className="flex items-center gap-2 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-samokoder-blue focus-visible:ring-offset-2"
            aria-current={isActive("/brand") ? "page" : undefined}
          >
            <SamokoderIcon className="h-4 w-4" />
            Бренд
          </Button>
        </nav>

        <div className="flex items-center gap-4">
          <ThemeToggle />
          <Button 
            variant="ghost" 
            size="icon"
            aria-label="Уведомления"
            className="focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-samokoder-blue focus-visible:ring-offset-2"
          >
            <Bell className="h-5 w-5" aria-hidden="true" />
          </Button>
          <Button 
            variant="ghost" 
            size="icon" 
            onClick={handleLogout}
            aria-label="Выйти из системы"
            className="focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-samokoder-blue focus-visible:ring-offset-2"
          >
            <LogOut className="h-5 w-5" aria-hidden="true" />
          </Button>
          
          {/* Мобильное меню */}
          <Button
            variant="ghost"
            size="icon"
            className="md:hidden focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-500 focus-visible:ring-offset-2"
            onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
            aria-label="Открыть меню навигации"
            aria-expanded={mobileMenuOpen}
            aria-controls="mobile-navigation"
          >
            <Menu className="h-5 w-5" aria-hidden="true" />
          </Button>
        </div>
      </div>
      
      {/* Мобильная навигация */}
      {mobileMenuOpen && (
        <nav 
          id="mobile-navigation"
          className="md:hidden bg-background border-t"
          role="navigation"
          aria-label="Мобильная навигация"
        >
          <div className="px-6 py-4 space-y-2">
            <Button
              variant={isActive("/") ? "default" : "ghost"}
              size="sm"
              onClick={() => {
                navigate("/")
                setMobileMenuOpen(false)
              }}
              className="w-full justify-start focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-samokoder-blue focus-visible:ring-offset-2"
              aria-current={isActive("/") ? "page" : undefined}
            >
              <Home className="h-4 w-4 mr-2" aria-hidden="true" />
              Главная
            </Button>
            <Button
              variant={isActive("/dashboard") ? "default" : "ghost"}
              size="sm"
              onClick={() => {
                navigate("/dashboard")
                setMobileMenuOpen(false)
              }}
              className="w-full justify-start focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-samokoder-blue focus-visible:ring-offset-2"
              aria-current={isActive("/dashboard") ? "page" : undefined}
            >
              <FolderOpen className="h-4 w-4 mr-2" aria-hidden="true" />
              Проекты
            </Button>
            <Button
              variant={isActive("/settings") ? "default" : "ghost"}
              size="sm"
              onClick={() => {
                navigate("/settings")
                setMobileMenuOpen(false)
              }}
              className="w-full justify-start focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-samokoder-blue focus-visible:ring-offset-2"
              aria-current={isActive("/settings") ? "page" : undefined}
            >
              <Settings className="h-4 w-4 mr-2" aria-hidden="true" />
              Настройки
            </Button>
            <Button
              variant={isActive("/brand") ? "default" : "ghost"}
              size="sm"
              onClick={() => {
                navigate("/brand")
                setMobileMenuOpen(false)
              }}
              className="w-full justify-start focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-samokoder-blue focus-visible:ring-offset-2"
              aria-current={isActive("/brand") ? "page" : undefined}
            >
              <SamokoderIcon className="h-4 w-4 mr-2" />
              Бренд
            </Button>
          </div>
        </nav>
      )}
    </header>
  )
}