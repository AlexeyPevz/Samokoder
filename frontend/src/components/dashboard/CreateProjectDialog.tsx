import { useState } from "react"
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Textarea } from "@/components/ui/textarea"
import { Label } from "@/components/ui/label"
import { Loader2, Sparkles } from "lucide-react"
import { createProject, type Project } from "@/api/projects"
import { useToast } from "@/hooks/useToast"

interface CreateProjectDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  onProjectCreated: (project: Project) => void
}

export function CreateProjectDialog({ open, onOpenChange, onProjectCreated }: CreateProjectDialogProps) {
  const { toast } = useToast()
  const [name, setName] = useState("")
  const [description, setDescription] = useState("")
  const [isCreating, setIsCreating] = useState(false)

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    
    if (!name.trim() || !description.trim()) {
      toast({
        title: "Ошибка",
        description: "Заполните все поля",
        variant: "destructive"
      })
      return
    }

    try {
      console.log('Creating project:', { name, description })
      setIsCreating(true)
      
      const response = await createProject({ name, description })
      
      console.log('Project created:', response.project)
      onProjectCreated(response.project)
      
      toast({
        title: "Успешно",
        description: "Проект создан и начинается генерация"
      })
      
      // Reset form
      setName("")
      setDescription("")
      onOpenChange(false)
      
    } catch (error) {
      console.error('Error creating project:', error)
      toast({
        title: "Ошибка",
        description: "Не удалось создать проект",
        variant: "destructive"
      })
    } finally {
      setIsCreating(false)
    }
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent 
        className="sm:max-w-md bg-white"
        role="dialog"
        aria-labelledby="create-project-title"
        aria-describedby="create-project-description"
      >
        <DialogHeader>
          <DialogTitle 
            id="create-project-title"
            className="flex items-center gap-2"
          >
            <Sparkles className="h-5 w-5 text-blue-600" aria-hidden="true" />
            Создать новый проект
          </DialogTitle>
          <p id="create-project-description" className="text-sm text-muted-foreground">
            Заполните форму для создания нового проекта
          </p>
        </DialogHeader>
        
        <form onSubmit={handleSubmit} className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="name">Название проекта</Label>
            <Input
              id="name"
              placeholder="Например: Интернет-магазин цветов"
              value={name}
              onChange={(e) => setName(e.target.value)}
              disabled={isCreating}
            />
          </div>
          
          <div className="space-y-2">
            <Label htmlFor="description">Описание приложения</Label>
            <Textarea
              id="description"
              placeholder="Опишите что должно делать ваше приложение..."
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              disabled={isCreating}
              className="min-h-[100px] resize-none"
            />
          </div>
          
          <div className="flex gap-3 pt-4">
            <Button
              type="button"
              variant="outline"
              onClick={() => onOpenChange(false)}
              disabled={isCreating}
              className="flex-1"
            >
              Отмена
            </Button>
            <Button
              type="submit"
              disabled={isCreating || !name.trim() || !description.trim()}
              className="flex-1 bg-gradient-to-r from-blue-600 to-purple-600 hover:from-blue-700 hover:to-purple-700"
            >
              {isCreating ? (
                <>
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                  Создаем...
                </>
              ) : (
                <>
                  <Sparkles className="mr-2 h-4 w-4" />
                  Создать
                </>
              )}
            </Button>
          </div>
        </form>
      </DialogContent>
    </Dialog>
  )
}