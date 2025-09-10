# 🚀 Самокодер - AI-генератор кода

Полнофункциональная платформа для генерации кода с помощью ИИ, включающая фронтенд на React и бэкенд на Python.

## 📁 Структура проекта

```
/workspace/
├── frontend/                 # React фронтенд
│   ├── src/
│   │   ├── components/      # UI компоненты
│   │   ├── pages/          # Страницы приложения
│   │   ├── api/            # API клиенты
│   │   ├── contexts/       # React контексты
│   │   └── lib/            # Утилиты
│   ├── package.json
│   └── vite.config.ts
├── backend/                 # Python бэкенд
│   ├── api/                # API эндпоинты
│   ├── models/             # Модели данных
│   ├── services/           # Бизнес-логика
│   └── utils/              # Утилиты
├── database/               # SQL схемы
├── config/                 # Конфигурация
├── .env                    # Переменные окружения
└── README.md              # Этот файл
```

## 🚀 Быстрый старт

### 1. Настройка Supabase

1. **Перейдите в Supabase Dashboard:**
   ```
   https://supabase.com/dashboard/project/auhzhdndqyflfdfszapm/sql
   ```

2. **Выполните SQL скрипт:**
   ```bash
   cat supabase_setup_fixed.sql
   ```
   Скопируйте содержимое и выполните в SQL Editor.

3. **Проверьте настройку:**
   ```bash
   python3 execute_sql_supabase.py
   ```

### 2. Запуск проекта

**Вариант 1: Автоматический запуск (рекомендуется)**
```bash
chmod +x start_dev.sh
./start_dev.sh
```

**Вариант 2: Ручной запуск**
```bash
# Терминал 1 - Бэкенд
python3 run_server.py

# Терминал 2 - Фронтенд
cd frontend
npm install
npm run dev
```

### 3. Доступ к приложению

- **Фронтенд:** http://localhost:5173
- **Бэкенд API:** http://localhost:3000
- **Supabase:** https://auhzhdndqyflfdfszapm.supabase.co

## 🔧 Настройка

### Переменные окружения (.env)

```env
# Supabase
SUPABASE_URL=https://auhzhdndqyflfdfszapm.supabase.co
SUPABASE_ANON_KEY=ваш_anon_key
SUPABASE_SERVICE_ROLE_KEY=ваш_service_role_key

# API
API_ENCRYPTION_KEY=your-32-character-secret-key-here
JWT_SECRET=your-jwt-secret-key-here

# Environment
NODE_ENV=development
PORT=3000
```

### Ключи Supabase

- **Anon Key:** `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImF1aHpoZG5kcXlmbGZkZnN6YXBtIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NTc0NDg3MTcsImV4cCI6MjA3MzAyNDcxN30.q-YUEKQqhd-k1YJMUqyStleW96SXh9bINhtsF5Av4oU`
- **Service Role Key:** `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImF1aHpoZG5kcXlmbGZkZnN6YXBtIiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTc1NzQ0ODcxNywiZXhwIjoyMDczMDI0NzE3fQ.xIJO7zl1hD4IN08oUV5vUWIAP71PEdn2yu_qfF7seQk`

## 🛠 Технологии

### Фронтенд
- **React 18** - UI библиотека
- **TypeScript** - Типизация
- **Vite** - Сборщик
- **Tailwind CSS** - Стилизация
- **Radix UI** - UI компоненты
- **React Router** - Маршрутизация
- **React Query** - Управление состоянием
- **Axios** - HTTP клиент

### Бэкенд
- **Python 3.9+** - Основной язык
- **FastAPI** - Web фреймворк
- **Supabase** - База данных
- **JWT** - Аутентификация
- **Pydantic** - Валидация данных

### База данных
- **PostgreSQL** (через Supabase)
- **Row Level Security (RLS)**
- **Real-time subscriptions**

## 📋 Основные функции

### ✅ Реализовано
- 🔐 **Аутентификация** - Регистрация, вход, JWT токены
- 👤 **Профили пользователей** - Управление настройками
- 📁 **Управление проектами** - Создание, редактирование, удаление
- 🤖 **AI интеграция** - Поддержка множества провайдеров
- 💬 **Чат интерфейс** - Общение с AI
- 🎨 **Современный UI** - Адаптивный дизайн
- 🔒 **Безопасность** - RLS, валидация, шифрование

### 🚧 В разработке
- 📊 **Аналитика** - Статистика использования
- 💳 **Подписки** - Платные тарифы
- 🔄 **Экспорт проектов** - Скачивание кода
- 🧪 **Тестирование** - Автоматические тесты

## 🐛 Устранение неполадок

### Проблемы с Supabase
```bash
# Проверка подключения
python3 setup_supabase_simple.py

# Проверка таблиц
python3 execute_sql_supabase.py
```

### Проблемы с фронтендом
```bash
cd frontend
npm install
npm run build
```

### Проблемы с бэкендом
```bash
pip install -r requirements.txt
python3 run_server.py
```

## 📚 Документация

- [Установка](INSTALL.md) - Подробная инструкция по установке
- [Развертывание](DEPLOY.md) - Настройка для продакшена
- [Безопасность](SECURITY_FIXES.md) - Исправления безопасности
- [Тестирование](TESTING_REPORT.md) - Результаты тестов

## 🤝 Вклад в проект

1. Форкните репозиторий
2. Создайте ветку для функции
3. Внесите изменения
4. Создайте Pull Request

## 📄 Лицензия

MIT License - см. [LICENSE](LICENSE)

## 🆘 Поддержка

Если у вас есть вопросы или проблемы:
1. Проверьте [раздел устранения неполадок](#-устранение-неполадок)
2. Создайте Issue в репозитории
3. Обратитесь к документации

---

**Статус проекта:** ✅ Готов к использованию  
**Версия:** 1.0.0  
**Последнее обновление:** $(date)