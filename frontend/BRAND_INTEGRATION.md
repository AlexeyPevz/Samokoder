# SAMOKODER Brand Integration

Этот документ описывает интеграцию фирменного стиля САМОКОДЕР в фронтенд приложение.

## 🎨 Цветовая палитра

### Основные цвета
- **SAMOKODER Blue**: `#00A2E5` (hsl(199, 100%, 45%))
- **SAMOKODER Green**: `#00A868` (hsl(150, 100%, 33%))

### Темные варианты
- **SAMOKODER Blue Dark**: для hover состояний
- **SAMOKODER Green Dark**: для hover состояний

### Использование в Tailwind
```css
/* Основные цвета */
bg-samokoder-blue
text-samokoder-blue
border-samokoder-blue

bg-samokoder-green
text-samokoder-green
border-samokoder-green

/* Темные варианты */
bg-samokoder-blue-dark
bg-samokoder-green-dark
```

## 🏷️ Логотип

### Компонент SamokoderLogo

```tsx
import SamokoderLogo from './components/ui/SamokoderLogo'

// Основной логотип с текстом
<SamokoderLogo 
  variant="default" 
  size="md" 
  showText={true} 
/>

// Только иконка
<SamokoderLogo 
  variant="mono" 
  size="lg" 
  showText={false} 
/>
```

### Варианты логотипа
- `default` - основной логотип
- `mono` - монохромный
- `inverted` - инвертированный
- `outline` - контурный
- `negative-s` - с негативным пространством S
- `frost-ice` - ледяная тема

### Размеры
- `sm` - маленький (24px)
- `md` - средний (32px)
- `lg` - большой (48px)
- `xl` - очень большой (64px)

## 🔘 Кнопки

### Компонент SamokoderButton

```tsx
import SamokoderButton from './components/ui/SamokoderButton'

// Основная кнопка
<SamokoderButton variant="primary">
  Основная кнопка
</SamokoderButton>

// Вторичная кнопка
<SamokoderButton variant="secondary">
  Вторичная кнопка
</SamokoderButton>
```

### Варианты кнопок
- `primary` - основная (синяя)
- `secondary` - вторичная (зеленая)
- `accent` - акцентная
- `outline` - контурная
- `ghost` - призрачная

### Размеры
- `sm` - маленькая
- `md` - средняя (по умолчанию)
- `lg` - большая

## 📋 Карточки

### Компонент SamokoderCard

```tsx
import { 
  SamokoderCard, 
  SamokoderCardHeader, 
  SamokoderCardTitle, 
  SamokoderCardDescription, 
  SamokoderCardContent, 
  SamokoderCardFooter 
} from './components/ui/SamokoderCard'

<SamokoderCard variant="bordered">
  <SamokoderCardHeader>
    <SamokoderCardTitle>Заголовок</SamokoderCardTitle>
    <SamokoderCardDescription>Описание</SamokoderCardDescription>
  </SamokoderCardHeader>
  <SamokoderCardContent>
    Содержимое карточки
  </SamokoderCardContent>
  <SamokoderCardFooter>
    Футер карточки
  </SamokoderCardFooter>
</SamokoderCard>
```

### Варианты карточек
- `default` - обычная карточка
- `bordered` - с выделенной рамкой
- `gradient` - с градиентным фоном
- `elevated` - с тенью

## 🏷️ Значки

### Компонент SamokoderBadge

```tsx
import SamokoderBadge from './components/ui/SamokoderBadge'

<SamokoderBadge variant="default">Основной</SamokoderBadge>
<SamokoderBadge variant="success">Успех</SamokoderBadge>
<SamokoderBadge variant="warning">Предупреждение</SamokoderBadge>
```

### Варианты значков
- `default` - основной (синий)
- `secondary` - вторичный (зеленый)
- `accent` - акцентный
- `outline` - контурный
- `success` - успех
- `warning` - предупреждение
- `error` - ошибка

## 🎯 Иконки

### Доступные иконки

```tsx
import { 
  SamokoderIcon, 
  LightningIcon, 
  CodeBracketsIcon, 
  AIBrainIcon, 
  DevelopmentIcon, 
  PlatformIcon 
} from './components/ui/SamokoderIcons'

<SamokoderIcon size={24} />
<LightningIcon size={32} />
<AIBrainIcon size={48} />
```

### Иконки
- `SamokoderIcon` - основной логотип
- `LightningIcon` - молния
- `CodeBracketsIcon` - скобки кода
- `AIBrainIcon` - AI мозг
- `DevelopmentIcon` - разработка
- `PlatformIcon` - платформа

## 🚀 Демонстрация

Для просмотра всех компонентов перейдите на страницу `/brand` в приложении.

## 📱 Адаптивность

Все компоненты адаптивны и корректно отображаются на:
- Десктопе (1024px+)
- Планшетах (768px - 1023px)
- Мобильных устройствах (до 767px)

## 🌙 Темная тема

Все компоненты поддерживают темную тему и автоматически адаптируются к текущей теме приложения.

## 🎨 Кастомизация

### CSS переменные

```css
:root {
  --samokoder-blue: 199 100% 45%;
  --samokoder-green: 150 100% 33%;
  --samokoder-blue-dark: 199 100% 35%;
  --samokoder-green-dark: 150 100% 25%;
}
```

### Tailwind классы

```css
/* Цвета фона */
.bg-samokoder-blue
.bg-samokoder-green

/* Цвета текста */
.text-samokoder-blue
.text-samokoder-green

/* Цвета границ */
.border-samokoder-blue
.border-samokoder-green
```

## 📋 Чек-лист интеграции

- [x] Обновлена цветовая схема
- [x] Создан компонент логотипа
- [x] Созданы брендовые кнопки
- [x] Созданы брендовые карточки
- [x] Созданы брендовые значки
- [x] Созданы SVG иконки
- [x] Обновлен Header
- [x] Добавлена демонстрационная страница
- [x] Настроена адаптивность
- [x] Поддержка темной темы

## 🔧 Технические детали

- **React 18** с TypeScript
- **Tailwind CSS** для стилизации
- **Radix UI** для базовых компонентов
- **Framer Motion** для анимаций
- **Lucide React** для дополнительных иконок

## 📞 Поддержка

При возникновении вопросов или проблем с интеграцией брендовых компонентов, обратитесь к команде разработки.