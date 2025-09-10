import { Card, CardContent } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { ShoppingCart, Calendar, Target, Calculator, Coffee, Camera, Music, BookOpen } from "lucide-react"
import { motion } from "framer-motion"

interface ExamplePromptsProps {
  onExampleClick: (example: string) => void
}

const examples = [
  {
    title: "Сервис записи к врачу",
    description: "Приложение для записи на прием с календарем и уведомлениями",
    icon: Calendar,
    color: "bg-green-100 text-green-700",
    prompt: "Создай приложение для записи к врачу с выбором специалиста, времени приема и отправкой уведомлений"
  },
  {
    title: "Интернет-магазин цветов",
    description: "Магазин с каталогом, корзиной и оплатой",
    icon: ShoppingCart,
    color: "bg-pink-100 text-pink-700",
    prompt: "Интернет-магазин цветов с каталогом, фильтрами, корзиной и онлайн оплатой"
  },
  {
    title: "Трекер привычек",
    description: "Отслеживание ежедневных привычек и прогресса",
    icon: Target,
    color: "bg-blue-100 text-blue-700",
    prompt: "Приложение для отслеживания привычек с ежедневными чек-листами и статистикой прогресса"
  },
  {
    title: "Калькулятор калорий",
    description: "Подсчет калорий и планирование питания",
    icon: Calculator,
    color: "bg-orange-100 text-orange-700",
    prompt: "Калькулятор калорий с базой продуктов, дневником питания и целями по весу"
  },
  {
    title: "Кафе-заказы",
    description: "Система заказов для кафе с меню",
    icon: Coffee,
    color: "bg-amber-100 text-amber-700",
    prompt: "Приложение для заказов в кафе с меню, корзиной и уведомлениями о готовности"
  },
  {
    title: "Фото-галерея",
    description: "Галерея с сортировкой и фильтрами",
    icon: Camera,
    color: "bg-purple-100 text-purple-700",
    prompt: "Фото-галерея с загрузкой изображений, альбомами и поиском по тегам"
  },
  {
    title: "Музыкальный плеер",
    description: "Плеер с плейлистами и рекомендациями",
    icon: Music,
    color: "bg-red-100 text-red-700",
    prompt: "Музыкальный плеер с плейлистами, поиском и рекомендациями на основе предпочтений"
  },
  {
    title: "Библиотека книг",
    description: "Каталог книг с отзывами и рейтингами",
    icon: BookOpen,
    color: "bg-indigo-100 text-indigo-700",
    prompt: "Библиотека книг с каталогом, отзывами, рейтингами и списком для чтения"
  }
]

export function ExamplePrompts({ onExampleClick }: ExamplePromptsProps) {
  return (
    <section className="py-16 px-6">
      <div className="mx-auto max-w-6xl">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6 }}
          viewport={{ once: true }}
          className="text-center mb-12"
        >
          <h2 className="text-3xl font-bold mb-4">Примеры приложений</h2>
          <p className="text-muted-foreground text-lg">
            Выберите готовый пример или создайте что-то уникальное
          </p>
        </motion.div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
          {examples.map((example, index) => {
            const Icon = example.icon
            return (
              <motion.div
                key={example.title}
                initial={{ opacity: 0, y: 20 }}
                whileInView={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.6, delay: index * 0.1 }}
                viewport={{ once: true }}
              >
                <Card 
                  className="cursor-pointer hover:shadow-lg transition-all duration-200 hover:-translate-y-1 bg-white/80 backdrop-blur-sm border-0 shadow-md"
                  onClick={() => onExampleClick(example.prompt)}
                >
                  <CardContent className="p-6">
                    <div className={`w-12 h-12 rounded-xl ${example.color} flex items-center justify-center mb-4`}>
                      <Icon className="h-6 w-6" />
                    </div>
                    <h3 className="font-semibold mb-2">{example.title}</h3>
                    <p className="text-sm text-muted-foreground">{example.description}</p>
                  </CardContent>
                </Card>
              </motion.div>
            )
          })}
        </div>
      </div>
    </section>
  )
}