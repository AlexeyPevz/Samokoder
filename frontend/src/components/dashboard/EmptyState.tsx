import { Button } from "@/components/ui/button"
import { Card, CardContent } from "@/components/ui/card"
import { Plus, Sparkles } from "lucide-react"
import { motion } from "framer-motion"

interface EmptyStateProps {
  onCreateProject: () => void
}

export function EmptyState({ onCreateProject }: EmptyStateProps) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.6 }}
      className="flex items-center justify-center min-h-[400px]"
    >
      <Card className="max-w-md text-center bg-white/80 backdrop-blur-sm border-0 shadow-lg">
        <CardContent className="p-8">
          <div className="w-16 h-16 bg-gradient-to-br from-primary to-secondary rounded-2xl flex items-center justify-center mx-auto mb-6">
            <Sparkles className="h-8 w-8 text-white" />
          </div>
          
          <h3 className="text-xl font-semibold mb-2">Создайте ваше первое приложение</h3>
          <p className="text-muted-foreground mb-6">
            Опишите идею вашего приложения, и наш ИИ создаст его за несколько минут
          </p>
          
          <Button
            onClick={onCreateProject}
            className="bg-gradient-to-r from-primary to-secondary hover:from-blue-700 hover:to-purple-700"
          >
            <Plus className="mr-2 h-4 w-4" />
            Начать
          </Button>
        </CardContent>
      </Card>
    </motion.div>
  )
}