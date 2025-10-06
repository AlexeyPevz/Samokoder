import { Card, CardContent } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import { ArrowRight, Star } from "lucide-react"
import { motion } from "framer-motion"

const templates = [
  {
    id: 1,
    title: "E-commerce Starter",
    category: "E-commerce",
    description: "Готовый интернет-магазин с корзиной, оплатой и админ-панелью",
    image: "https://picsum.photos/seed/ecommerce/300/200",
    rating: 4.8,
    downloads: 1200,
    color: "bg-primary"
  },
  {
    id: 2,
    title: "Healthcare App",
    category: "Healthcare",
    description: "Медицинское приложение с записью к врачам и историей болезни",
    image: "https://picsum.photos/seed/healthcare/300/200",
    rating: 4.9,
    downloads: 850,
    color: "bg-green-500"
  },
  {
    id: 3,
    title: "Task Manager",
    category: "Productivity",
    description: "Менеджер задач с командной работой и отчетами",
    image: "https://picsum.photos/seed/tasks/300/200",
    rating: 4.7,
    downloads: 2100,
    color: "bg-accent"
  },
  {
    id: 4,
    title: "Food Delivery",
    category: "Food & Drink",
    description: "Приложение доставки еды с трекингом заказов",
    image: "https://picsum.photos/seed/food/300/200",
    rating: 4.6,
    downloads: 950,
    color: "bg-orange-500"
  }
]

export default function TemplateGallery() {
  return (
    <section className="py-16 px-6 bg-white/50">
      <div className="mx-auto max-w-6xl">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6 }}
          viewport={{ once: true }}
          className="text-center mb-12"
        >
          <h2 className="text-3xl font-bold mb-4">Готовые шаблоны</h2>
          <p className="text-muted-foreground text-lg">
            Начните с готового шаблона и настройте под свои нужды
          </p>
        </motion.div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
          {templates.map((template, index) => (
            <motion.div
              key={template.id}
              initial={{ opacity: 0, y: 20 }}
              whileInView={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.6, delay: index * 0.1 }}
              viewport={{ once: true }}
            >
              <Card className="overflow-hidden hover:shadow-lg transition-all duration-200 hover:-translate-y-1 bg-white border-0 shadow-md">
                <div className="relative">
                  <img src={template.image} alt={template.title} className="h-32 w-full object-cover" />
                  <Badge className="absolute top-2 right-2 bg-white text-gray-700">
                    {template.category}
                  </Badge>
                </div>
                
                <CardContent className="p-4">
                  <h3 className="font-semibold mb-2">{template.title}</h3>
                  <p className="text-sm text-muted-foreground mb-4 line-clamp-2">
                    {template.description}
                  </p>
                  
                  <div className="flex items-center justify-between mb-4">
                    <div className="flex items-center gap-1">
                      <Star className="h-4 w-4 fill-yellow-400 text-yellow-400" />
                      <span className="text-sm font-medium">{template.rating}</span>
                    </div>
                    <span className="text-sm text-muted-foreground">
                      {template.downloads} загрузок
                    </span>
                  </div>
                  
                  <Button className="w-full" size="sm">
                    Использовать
                    <ArrowRight className="ml-2 h-4 w-4" />
                  </Button>
                </CardContent>
              </Card>
            </motion.div>
          ))}
        </div>
      </div>
    </section>
  )
}