import { Card, CardContent } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Check, X, Zap, Smartphone, Clock, DollarSign } from "lucide-react"
import { motion } from "framer-motion"

const benefits = [
  {
    icon: Clock,
    title: "Быстрое создание",
    description: "От идеи до готового приложения за 10 минут",
    color: "bg-primary/10 text-primary"
  },
  {
    icon: DollarSign,
    title: "Доступная цена",
    description: "В 10 раз дешевле разработки с нуля",
    color: "bg-green-100 text-green-700"
  },
  {
    icon: Smartphone,
    title: "Mobile-first",
    description: "Все приложения адаптированы под мобильные устройства",
    color: "bg-accent/10 text-accent"
  },
  {
    icon: Zap,
    title: "Простота использования",
    description: "Никаких навыков программирования не требуется",
    color: "bg-orange-100 text-orange-700"
  }
]

const comparison = [
  { feature: "Время создания", us: "10 минут", competitors: "2-6 месяцев" },
  { feature: "Стоимость", us: "от $29/мес", competitors: "от $5000" },
  { feature: "Навыки программирования", us: "Не требуются", competitors: "Обязательны" },
  { feature: "Мобильная адаптация", us: "Автоматически", competitors: "Дополнительно" },
  { feature: "Поддержка", us: "24/7", competitors: "Ограниченная" }
]

const testimonials = [
  {
    name: "Анна Петрова",
    role: "Владелец цветочного магазина",
    avatar: "AP",
    text: "Создала интернет-магазин за 15 минут! Клиенты в восторге от удобства заказов."
  },
  {
    name: "Михаил Сидоров",
    role: "Врач-терапевт",
    avatar: "МС",
    text: "Приложение для записи пациентов сэкономило мне часы работы каждый день."
  },
  {
    name: "Елена Козлова",
    role: "Фитнес-тренер",
    avatar: "ЕК",
    text: "Трекер тренировок для клиентов получился именно таким, как я хотела!"
  }
]

export default function BenefitsSection() {
  return (
    <section className="py-16 px-6">
      <div className="mx-auto max-w-6xl">
        {/* Benefits Grid */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6 }}
          viewport={{ once: true }}
          className="text-center mb-12"
        >
          <h2 className="text-3xl font-bold mb-4">Почему выбирают нас</h2>
          <p className="text-muted-foreground text-lg">
            Создавайте приложения быстро, просто и доступно
          </p>
        </motion.div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-16">
          {benefits.map((benefit, index) => {
            const Icon = benefit.icon
            return (
              <motion.div
                key={benefit.title}
                initial={{ opacity: 0, y: 20 }}
                whileInView={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.6, delay: index * 0.1 }}
                viewport={{ once: true }}
              >
                <Card className="text-center bg-white/80 backdrop-blur-sm border-0 shadow-md">
                  <CardContent className="p-6">
                    <div className={`w-16 h-16 rounded-2xl ${benefit.color} flex items-center justify-center mx-auto mb-4`}>
                      <Icon className="h-8 w-8" />
                    </div>
                    <h3 className="font-semibold mb-2">{benefit.title}</h3>
                    <p className="text-sm text-muted-foreground">{benefit.description}</p>
                  </CardContent>
                </Card>
              </motion.div>
            )
          })}
        </div>

        {/* Comparison Table */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6 }}
          viewport={{ once: true }}
          className="mb-16"
        >
          <h3 className="text-2xl font-bold text-center mb-8">Сравнение с конкурентами</h3>
          <Card className="bg-white/80 backdrop-blur-sm border-0 shadow-lg">
            <CardContent className="p-0">
              <div className="overflow-x-auto">
                <table className="w-full">
                  <thead>
                    <tr className="border-b">
                      <th className="text-left p-4 font-semibold">Критерий</th>
                      <th className="text-center p-4 font-semibold text-primary">Самокодер</th>
                      <th className="text-center p-4 font-semibold text-muted-foreground">Конкуренты</th>
                    </tr>
                  </thead>
                  <tbody>
                    {comparison.map((item, index) => (
                      <tr key={item.feature} className={index % 2 === 0 ? "bg-gray-50/50" : ""}>
                        <td className="p-4 font-medium">{item.feature}</td>
                        <td className="p-4 text-center">
                          <Badge variant="secondary" className="bg-green-100 text-green-700">
                            <Check className="h-3 w-3 mr-1" />
                            {item.us}
                          </Badge>
                        </td>
                        <td className="p-4 text-center">
                          <Badge variant="outline" className="text-muted-foreground">
                            <X className="h-3 w-3 mr-1" />
                            {item.competitors}
                          </Badge>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </CardContent>
          </Card>
        </motion.div>

        {/* Testimonials */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6 }}
          viewport={{ once: true }}
        >
          <h3 className="text-2xl font-bold text-center mb-8">Отзывы клиентов</h3>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            {testimonials.map((testimonial, index) => (
              <motion.div
                key={testimonial.name}
                initial={{ opacity: 0, y: 20 }}
                whileInView={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.6, delay: index * 0.1 }}
                viewport={{ once: true }}
              >
                <Card className="bg-white/80 backdrop-blur-sm border-0 shadow-md">
                  <CardContent className="p-6">
                    <div className="flex items-center gap-3 mb-4">
                      <div className="w-10 h-10 bg-gradient-to-br from-primary to-accent rounded-full flex items-center justify-center text-white text-sm font-bold">
                        {testimonial.avatar}
                      </div>
                      <div>
                        <div className="font-semibold">{testimonial.name}</div>
                        <div className="text-sm text-muted-foreground">{testimonial.role}</div>
                      </div>
                    </div>
                    <p className="text-sm text-muted-foreground italic">"{testimonial.text}"</p>
                  </CardContent>
                </Card>
              </motion.div>
            ))}
          </div>
        </motion.div>
      </div>
    </section>
  )
}