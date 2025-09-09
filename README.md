# 🚀 Самокодер - AI-платформа для создания full-stack приложений

> **Революционная ценовая модель**: $5-10/месяц вместо $49 у конкурентов  
> **BYOK (Bring Your Own Key)**: полная прозрачность API-расходов  
> **15 минут от идеи до working app**: production-ready код с интеграциями

## 🎯 Концепция продукта

### Проблема на рынке
- **Pythagora (YC-backed)**: отличная технология, но **$49/месяц** — недоступно для indie-разработчиков
- **Существующие решения**: либо дорогие enterprise-инструменты, либо простые no-code builders без AI-мощи
- **Разрыв в рынке**: нет доступного full-stack AI app builder'а для массового рынка

### Наше решение
**AI-платформа для создания полноценных веб-приложений с использованием форка GPT-Pilot + собственные улучшения + революционная ценовая модель**

### Уникальная ценность
- **Тот же функционал что у Pythagora за $5-10/месяц вместо $49**
- **BYOK модель** — полная прозрачность API-расходов  
- **15 минут от идеи до working app** вместо часов ручной разработки
- **Production-ready код** с интеграциями, не просто прототипы

## 🏗️ Архитектура системы

### Технический стек
- **Backend**: Python FastAPI + Supabase
- **AI Engine**: Модифицированный GPT-Pilot
- **Database**: PostgreSQL (Supabase) с RLS
- **Storage**: Supabase Storage для проектов
- **Auth**: Supabase Auth
- **AI Providers**: OpenRouter, OpenAI, Anthropic, Groq

### Компоненты системы

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Frontend      │    │   FastAPI        │    │   GPT-Pilot     │
│   (React/Vue)   │◄──►│   Backend        │◄──►│   AI Engine     │
│                 │    │                  │    │                 │
└─────────────────┘    └──────────────────┘    └─────────────────┘
                                │
                                ▼
                       ┌──────────────────┐
                       │   Supabase       │
                       │   - Auth         │
                       │   - Database     │
                       │   - Storage      │
                       │   - RLS          │
                       └──────────────────┘
```

## 📋 План разработки MVP (3 недели)

### Неделя 1: Базовая инфраструктура
- [x] **День 1-2**: Fork GPT-Pilot + минимальные модификации
- [ ] **День 3-4**: Supabase setup: auth + базовые таблицы
- [ ] **День 5-7**: OpenRouter API integration (3-5 бесплатных моделей)

### Неделя 2: Core Backend
- [ ] **День 8-10**: SamokoderGPTPilot wrapper класс
- [ ] **День 11-12**: FastAPI с основными эндпоинтами
- [ ] **День 13-14**: BYOK функция для пользовательских ключей

### Неделя 3: Первый workflow
- [ ] **День 15-17**: Регистрация → создание проекта → генерация → экспорт
- [ ] **День 18-19**: WebSocket/SSE для live обновлений
- [ ] **День 20-21**: Базовая система биллинга и тестирование

## 🔧 Установка и запуск

### Требования
- Python 3.9+
- Node.js 18+ (для фронтенда)
- Supabase аккаунт
- API ключи для AI провайдеров

### Быстрый старт

1. **Клонирование репозитория**
```bash
git clone https://github.com/your-username/samokoder.git
cd samokoder
```

2. **Установка зависимостей**
```bash
# Backend
pip install -r requirements.txt

# Frontend (когда будет готов)
cd frontend && npm install
```

3. **Настройка переменных окружения**
```bash
cp .env.example .env
# Заполните переменные в .env файле
```

4. **Инициализация базы данных**
```bash
# Запустите SQL скрипты в Supabase Dashboard
# Или используйте Supabase CLI
supabase db reset
```

5. **Запуск сервера**
```bash
# Backend
uvicorn backend.main:app --reload --host 0.0.0.0 --port 8000

# Frontend (когда будет готов)
cd frontend && npm run dev
```

## 📊 База данных (Supabase)

### Основные таблицы

#### Пользователи и аутентификация
- `profiles` - профили пользователей (расширение auth.users)
- `user_settings` - настройки пользователей
- `user_api_keys` - зашифрованные API ключи пользователей

#### AI провайдеры и модели
- `ai_providers` - справочник AI провайдеров
- `ai_models` - модели для каждого провайдера
- `subscription_limits` - лимиты тарифных планов

#### Проекты и использование
- `projects` - проекты пользователей
- `api_usage_log` - детальная статистика использования
- `generation_history` - история генераций

### RLS (Row Level Security)
Все таблицы защищены политиками RLS - пользователи видят только свои данные.

## 🔐 Система безопасности

### Шифрование API ключей
- **Алгоритм**: PBKDF2 + Fernet
- **Соль**: уникальная для каждого ключа
- **Итерации**: 100,000 для защиты от брутфорса
- **Отображение**: только последние 4 символа

### Аутентификация
- **Supabase Auth** с JWT токенами
- **Автоматическое обновление** токенов
- **Защита от CSRF** через SameSite cookies

## 🎛️ API Endpoints

### Аутентификация
```
POST /api/auth/login          # Вход через Supabase
POST /api/auth/logout         # Выход
GET  /api/auth/user           # Текущий пользователь
```

### Управление API ключами
```
POST /api/user/api-keys       # Добавить API ключ
GET  /api/user/api-keys       # Список ключей пользователя
PUT  /api/user/api-keys/{id}  # Обновить ключ
DELETE /api/user/api-keys/{id} # Удалить ключ
```

### Проекты
```
GET    /api/projects                    # Список проектов
POST   /api/projects                    # Создать проект
GET    /api/projects/{id}               # Детали проекта
DELETE /api/projects/{id}               # Удалить проект
POST   /api/projects/{id}/export        # Экспорт в ZIP
```

### Чат и генерация
```
POST /api/projects/{id}/chat            # Отправить сообщение агентам
GET  /api/projects/{id}/chat/history    # История чата
POST /api/projects/{id}/generate        # Запуск генерации кода
GET  /api/projects/{id}/generation      # Статус генерации
```

### Файлы проекта
```
GET /api/projects/{id}/files                    # Дерево файлов
GET /api/projects/{id}/files/{path}             # Содержимое файла
PUT /api/projects/{id}/files/{path}             # Обновить файл
```

### WebSocket
```
WS /api/projects/{id}/stream                    # Live обновления генерации
```

## 💰 Бизнес-модель

### Тарифные планы

#### Starter ($5/месяц)
- **BYOK обязательно** — пользователь предоставляет свои API-ключи
- **5 проектов/месяц**
- **Базовые шаблоны и интеграции**
- **Community поддержка**

#### Professional ($10/месяц)  
- **BYOK + Managed Credits** ($5 включено, доплата по факту)
- **Unlimited проекты**
- **Расширенные интеграции** (Stripe, email-сервисы)
- **Priority поддержка**

#### Business ($25/месяц)
- **Managed Credits ($15 включено)**
- **Team collaboration** (до 5 разработчиков)
- **Advanced templates**
- **White-label options**

### Дополнительные revenue streams
- **API Credits markup**: 20-30% наценка на managed credits
- **Template marketplace**: $10-50 за готовые шаблоны
- **Consulting services**: $1000+ за custom development

## 🚀 Roadmap

### Phase 1: MVP (месяц 1)
- ✅ Базовая интеграция с GPT-Pilot
- ✅ Простой веб-интерфейс
- ✅ BYOK система
- ✅ Экспорт проектов

### Phase 2: Enhanced AI (месяц 2-3)
- 🔄 Schema-Guided Reasoning
- 🔄 Специализированные агенты
- 🔄 Улучшенная архитектура

### Phase 3: Production (месяц 4-6)
- 🔄 Comprehensive testing
- 🔄 Microservices architecture
- 🔄 Advanced integrations

### Phase 4: Scale (год 2)
- 🔄 Vector databases
- 🔄 Custom knowledge bases
- 🔄 Enterprise features

## 📈 Финансовая модель

### Консервативный прогноз
```
Месяц 3: 50 пользователей × $8 = $400 MRR
Месяц 6: 200 пользователей × $8 = $1,600 MRR  
Год 1: 1,000 пользователей × $8 = $8,000 MRR = $96K ARR
Год 2: 5,000 пользователей × $8 = $40,000 MRR = $480K ARR
```

### Break-even point
```
При 100 пользователях ($800 MRR) уже profitable
При 1000 пользователях ($8K MRR) = $90K+ прибыли в год
```

## 🎯 Success Metrics

### MVP validation (первые 3 месяца)
- **50+ регистраций** в первую неделю
- **30%+ conversion** от регистрации к первому проекту
- **20%+ retention** после первого проекта
- **<10 минут** average time to first success

### Growth metrics (месяцы 4-12)
- **10%+ месячный рост** пользовательской базы
- **<5% monthly churn** rate
- **$50+ LTV/CAC** ratio
- **4.5+ NPS score** от пользователей

## 🤝 Контрибьюция

Мы приветствуем контрибьюции! Пожалуйста:

1. Fork репозиторий
2. Создайте feature branch (`git checkout -b feature/amazing-feature`)
3. Commit изменения (`git commit -m 'Add amazing feature'`)
4. Push в branch (`git push origin feature/amazing-feature`)
5. Откройте Pull Request

## 📄 Лицензия

Этот проект лицензирован под MIT License - см. файл [LICENSE](LICENSE) для деталей.

## 📞 Контакты

- **Email**: hello@samokoder.com
- **Discord**: [Сервер сообщества](https://discord.gg/samokoder)
- **Twitter**: [@samokoder](https://twitter.com/samokoder)

---

**🚀 Время запуска: СЕЙЧАС**

**Пока конкуренты фокусируются на enterprise рынке, мы захватываем mass market с революционной ценовой моделью и становимся "Pythagora для людей".**