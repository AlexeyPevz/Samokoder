import { Button } from "@/components/ui/button"
import { Textarea } from "@/components/ui/textarea"
import { Sparkles, Mic, Loader2 } from "lucide-react"
import { motion } from "framer-motion"

interface HeroSectionProps {
  appDescription: string
  setAppDescription: (value: string) => void
  onCreateApp: () => void
  isCreating: boolean
}

export default function HeroSection({ appDescription, setAppDescription, onCreateApp, isCreating }: HeroSectionProps) {
  return (
    <section className="relative overflow-hidden py-20 px-6">
      <div className="absolute inset-0 bg-gradient-to-r from-primary/10 to-secondary/10" />
      
      <div className="relative mx-auto max-w-4xl text-center">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6 }}
        >
          <h1 className="text-4xl md:text-6xl font-bold bg-gradient-to-r from-primary to-secondary bg-clip-text text-transparent mb-6">
            От идеи до приложения за 10 минут
          </h1>
          
          <p className="text-xl text-muted-foreground mb-8 max-w-2xl mx-auto">
            Опишите ваше приложение простыми словами, и наш ИИ создаст его за считанные минуты. 
            Никаких навыков программирования не требуется.
          </p>
        </motion.div>

        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6, delay: 0.2 }}
          className="max-w-2xl mx-auto"
        >
          <div className="relative">
            <Textarea
              placeholder="Опишите ваше приложение... (например: интернет-магазин цветов с корзиной и оплатой)"
              value={appDescription}
              onChange={(e) => setAppDescription(e.target.value)}
              className="min-h-[120px] text-lg p-6 rounded-2xl border-2 border-blue-200 focus:border-blue-500 bg-white/80 backdrop-blur-sm resize-none"
            />
            
            <Button
              variant="ghost"
              size="icon"
              className="absolute top-4 right-4 text-blue-500 hover:text-blue-600"
            >
              <Mic className="h-5 w-5" />
            </Button>
          </div>

          <Button
            onClick={onCreateApp}
            disabled={!appDescription.trim() || isCreating}
            className="mt-6 h-14 px-8 text-lg bg-gradient-to-r from-primary to-secondary hover:from-blue-700 hover:to-purple-700 rounded-2xl shadow-lg hover:shadow-xl transition-all duration-200"
          >
            {isCreating ? (
              <>
                <Loader2 className="mr-2 h-5 w-5 animate-spin" />
                Создаем приложение...
              </>
            ) : (
              <>
                <Sparkles className="mr-2 h-5 w-5" />
                Создать приложение
              </>
            )}
          </Button>
        </motion.div>
      </div>
    </section>
  )
}