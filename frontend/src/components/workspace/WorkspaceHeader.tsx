import { Button } from "@/components/ui/button"
import { Avatar, AvatarFallback, AvatarImage } from "@/components/ui/avatar"
import { Badge } from "@/components/ui/badge"
import { 
  Home, 
  Settings, 
  LogOut, 
  User, 
  Bell,
  Play,
  Square,
  Cpu
} from "lucide-react"
import { Link, useNavigate } from "react-router-dom"
import { useAuth } from "@/contexts/AuthContext"
import { Project } from "@/api/projects"
import { NotificationBell } from "@/components/notifications/NotificationBell"

interface WorkspaceHeaderProps {
  project: Project
  onShowProviderSelector?: () => void
}

import { Download } from "lucide-react";

export function WorkspaceHeader({ project, onShowProviderSelector }: WorkspaceHeaderProps) {
  return (
    <header className="fixed top-0 z-40 w-full border-b bg-background/80 backdrop-blur-sm">
      <div className="flex h-16 items-center justify-between px-6">
        <h1 className="font-semibold text-lg">{project.name}</h1>
        <div className="flex items-center gap-4">
          <Button variant="outline" onClick={onShowProviderSelector}>Настройки провайдера</Button>
          <a href={`/api/v1/projects/${project.id}/archive`} download={`${project.name}.zip`}>
            <Button variant="outline" size="icon">
              <Download className="h-4 w-4" />
            </Button>
          </a>
        </div>
      </div>
    </header>
  );
}