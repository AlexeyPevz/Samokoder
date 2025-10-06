import { useState, useEffect } from "react"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Switch } from "@/components/ui/switch"
import { Label } from "@/components/ui/label"
import { Input } from "@/components/ui/input"
import { Separator } from "@/components/ui/separator"
import { Plugin, pluginService } from "@/services/plugins"
import { useToast } from "@/hooks/useToast"
import { Github, GitBranch, Zap } from "lucide-react"

export function PluginSettings() {
  const { toast } = useToast()
  const [plugins, setPlugins] = useState<Plugin[]>([])
  const [githubSettings, setGithubSettings] = useState({
    enabled: false,
    autoCommit: false,
    createRelease: false,
    accessToken: ""
  })
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    loadPlugins()
    loadGithubSettings()
  }, [])

  const loadPlugins = async () => {
    try {
      const data = await pluginService.getPlugins()
      setPlugins(data.plugins)
    } catch (error) {
      console.error("Error loading plugins:", error)
      toast({
        title: "Ошибка",
        description: "Не удалось загрузить плагины",
        variant: "destructive"
      })
    } finally {
      setLoading(false)
    }
  }

  const loadGithubSettings = async () => {
    try {
      const data = await pluginService.getPluginSettings("github")
      setGithubSettings({
        enabled: data.settings.enabled || false,
        autoCommit: data.settings.autoCommit || false,
        createRelease: data.settings.createRelease || false,
        accessToken: data.settings.accessToken || ""
      })
    } catch (error) {
      console.error("Error loading GitHub settings:", error)
    }
  }

  const togglePlugin = async (pluginName: string, enabled: boolean) => {
    try {
      if (enabled) {
        await pluginService.enablePlugin(pluginName)
      } else {
        await pluginService.disablePlugin(pluginName)
      }
      
      // Update local state
      setPlugins(prev => 
        prev.map(plugin => 
          plugin.name === pluginName ? { ...plugin, enabled } : plugin
        )
      )
      
      toast({
        title: "Успех",
        description: `Плагин ${enabled ? "включен" : "выключен"}`
      })
    } catch (error) {
      console.error("Error toggling plugin:", error)
      toast({
        title: "Ошибка",
        description: "Не удалось изменить состояние плагина",
        variant: "destructive"
      })
    }
  }

  const updateGithubSettings = async () => {
    try {
      await pluginService.updatePluginSettings("github", githubSettings)
      toast({
        title: "Успех",
        description: "Настройки GitHub сохранены"
      })
    } catch (error) {
      console.error("Error updating GitHub settings:", error)
      toast({
        title: "Ошибка",
        description: "Не удалось сохранить настройки GitHub",
        variant: "destructive"
      })
    }
  }

  const createGithubRepo = async (projectId: string) => {
    try {
      await pluginService.createGitHubRepository(projectId)
      toast({
        title: "Успех",
        description: "Репозиторий GitHub создан"
      })
    } catch (error) {
      console.error("Error creating GitHub repository:", error)
      toast({
        title: "Ошибка",
        description: "Не удалось создать репозиторий GitHub",
        variant: "destructive"
      })
    }
  }

  if (loading) {
    return <div>Загрузка плагинов...</div>
  }

  return (
    <div className="space-y-6">
      <div>
        <h3 className="text-lg font-medium">Плагины и интеграции</h3>
        <p className="text-sm text-muted-foreground">
          Управление плагинами и интеграциями с внешними сервисами
        </p>
      </div>

      <Separator />

      <div className="grid gap-6">
        {plugins.map((plugin) => (
          <Card key={plugin.name}>
            <CardHeader>
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-3">
                  {plugin.name === "github" && <Github className="h-5 w-5" />}
                  {plugin.name === "gitlab" && <GitBranch className="h-5 w-5" />}
                  {plugin.name === "bitbucket" && <Zap className="h-5 w-5" />}
                  <div>
                    <CardTitle className="text-base">{plugin.name}</CardTitle>
                    <CardDescription>{plugin.description}</CardDescription>
                  </div>
                </div>
                <Switch
                  checked={plugin.enabled}
                  onCheckedChange={(checked) => togglePlugin(plugin.name, checked)}
                />
              </div>
            </CardHeader>
            <CardContent>
              <div className="text-sm text-muted-foreground">
                Версия: {plugin.version}
              </div>
            </CardContent>
          </Card>
        ))}
      </div>

      {plugins.some(p => p.name === "github" && p.enabled) && (
        <>
          <Separator />
          
          <Card>
            <CardHeader>
              <CardTitle>Настройки GitHub</CardTitle>
              <CardDescription>
                Настройте интеграцию с GitHub
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="flex items-center justify-between">
                <div>
                  <Label>Автоматический коммит</Label>
                  <p className="text-sm text-muted-foreground">
                    Автоматически коммитить изменения в репозиторий
                  </p>
                </div>
                <Switch
                  checked={githubSettings.autoCommit}
                  onCheckedChange={(checked) => 
                    setGithubSettings(prev => ({ ...prev, autoCommit: checked }))
                  }
                />
              </div>
              
              <div className="flex items-center justify-between">
                <div>
                  <Label>Создавать релизы</Label>
                  <p className="text-sm text-muted-foreground">
                    Создавать GitHub релизы при деплое
                  </p>
                </div>
                <Switch
                  checked={githubSettings.createRelease}
                  onCheckedChange={(checked) => 
                    setGithubSettings(prev => ({ ...prev, createRelease: checked }))
                  }
                />
              </div>
              
              <div className="space-y-2">
                <Label>Токен доступа GitHub</Label>
                <Input
                  type="password"
                  value={githubSettings.accessToken}
                  onChange={(e) => 
                    setGithubSettings(prev => ({ ...prev, accessToken: e.target.value }))
                  }
                  placeholder="Введите токен доступа GitHub"
                />
                <p className="text-sm text-muted-foreground">
                  Токен необходим для доступа к GitHub API
                </p>
              </div>
              
              <Button onClick={updateGithubSettings}>
                Сохранить настройки
              </Button>
            </CardContent>
          </Card>
        </>
      )}
    </div>
  )
}