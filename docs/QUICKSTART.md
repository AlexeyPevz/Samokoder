# 🚀 Быстрый старт - Самокодер v1.0.0

> **Установка и запуск за 5 минут**  
> Получите работающий экземпляр Самокодера за минимальное время

## ⚡ Установка за 5 минут

### 📋 Предварительные требования

Убедитесь, что у вас установлены:

- **Python 3.9+** ([скачать](https://python.org/downloads/))
- **Node.js 18+** ([скачать](https://nodejs.org/))
- **Git** ([скачать](https://git-scm.com/))
- **Docker** (опционально, [скачать](https://docker.com/))

### 🔍 Проверка версий

```bash
# Проверьте версии
python --version    # Должно быть 3.9+
node --version      # Должно быть 18+
git --version       # Любая версия
docker --version    # Опционально
```

## 🚀 Шаг 1: Клонирование репозитория

```bash
# Клонируйте репозиторий
git clone https://github.com/samokoder/samokoder.git
cd samokoder

# Проверьте, что вы в правильной директории
ls -la
# Должны увидеть: frontend/, backend/, .env.example, README.md
```

## 🔧 Шаг 2: Настройка переменных окружения

### 📝 Создание .env файла

```bash
# Скопируйте пример конфигурации
cp .env.example .env

# Откройте файл для редактирования
nano .env  # или code .env, vim .env
```

### 🔑 Минимальная конфигурация

Добавьте в `.env` файл:

```env
# ===========================================
# ОСНОВНЫЕ НАСТРОЙКИ
# ===========================================
NODE_ENV=development
ENVIRONMENT=development
DEBUG=true
HOST=0.0.0.0
PORT=8000
FRONTEND_PORT=5173

# ===========================================
# БАЗА ДАННЫХ (Supabase - рекомендуется)
# ===========================================
SUPABASE_URL=https://your-project.supabase.co
SUPABASE_ANON_KEY=your_anon_key_here
SUPABASE_SERVICE_ROLE_KEY=your_service_role_key_here

# ===========================================
# БЕЗОПАСНОСТЬ
# ===========================================
JWT_SECRET=your-super-secret-jwt-key-here-32-chars-minimum
API_ENCRYPTION_KEY=your-32-character-secret-key-here

# ===========================================
# AI ПРОВАЙДЕРЫ (минимум один)
# ===========================================
OPENAI_API_KEY=sk-your-openai-key
# ИЛИ
ANTHROPIC_API_KEY=sk-ant-your-anthropic-key
# ИЛИ
GROQ_API_KEY=gsk_your-groq-key
# ИЛИ
OPENROUTER_API_KEY=sk-or-your-openrouter-key

# ===========================================
# КЭШИРОВАНИЕ (опционально)
# ===========================================
REDIS_URL=redis://localhost:6379
```

### 🔐 Генерация безопасных ключей

```bash
# Сгенерируйте безопасные ключи
python scripts/generate_keys.py

# Или используйте простой генератор
python scripts/generate_keys_simple.py
```

## 📦 Шаг 3: Установка зависимостей

### 🐍 Backend зависимости

```bash
# Создайте виртуальное окружение (рекомендуется)
python -m venv venv

# Активируйте виртуальное окружение
# Linux/Mac:
source venv/bin/activate
# Windows:
# venv\Scripts\activate

# Установите зависимости
pip install -r requirements.txt

# Проверьте установку
python -c "import fastapi; print('FastAPI установлен!')"
```

### ⚛️ Frontend зависимости

```bash
# Перейдите в директорию frontend
cd frontend

# Установите зависимости
npm install

# Проверьте установку
npm run build

# Вернитесь в корневую директорию
cd ..
```

## 🗄️ Шаг 4: Настройка базы данных

### 🎯 Вариант A: Supabase (рекомендуется)

1. **Создайте проект в Supabase**
   - Перейдите на [supabase.com](https://supabase.com)
   - Создайте новый проект
   - Скопируйте URL и ключи

2. **Обновите .env файл**
   ```env
   SUPABASE_URL=https://your-project-id.supabase.co
   SUPABASE_ANON_KEY=your_anon_key
   SUPABASE_SERVICE_ROLE_KEY=your_service_role_key
   ```

3. **Выполните SQL скрипт**
   ```bash
   # Выполните SQL в Supabase Dashboard
   cat database/schema.sql
   # Скопируйте содержимое и выполните в SQL Editor
   ```

### 🎯 Вариант B: Локальная PostgreSQL

1. **Установите PostgreSQL**
   ```bash
   # Ubuntu/Debian
   sudo apt-get install postgresql postgresql-contrib
   
   # macOS (с Homebrew)
   brew install postgresql
   
   # Windows
   # Скачайте с postgresql.org
   ```

2. **Создайте базу данных**
   ```bash
   sudo -u postgres createdb samokoder
   sudo -u postgres createuser samokoder
   sudo -u postgres psql -c "ALTER USER samokoder PASSWORD 'password';"
   ```

3. **Обновите .env файл**
   ```env
   DATABASE_URL=postgresql://samokoder:password@localhost:5432/samokoder
   ```

4. **Выполните миграции**
   ```bash
   python -m alembic upgrade head
   ```

### 🎯 Вариант C: Docker (быстрый старт)

```bash
# Запустите PostgreSQL в Docker
docker run --name samokoder-postgres \
  -e POSTGRES_DB=samokoder \
  -e POSTGRES_USER=samokoder \
  -e POSTGRES_PASSWORD=password \
  -p 5432:5432 \
  -d postgres:15

# Обновите .env
echo "DATABASE_URL=postgresql://samokoder:password@localhost:5432/samokoder" >> .env

# Выполните миграции
python -m alembic upgrade head
```

## 🚀 Шаг 5: Запуск приложения

### 🎯 Автоматический запуск (рекомендуется)

```bash
# Запустите все сервисы одной командой
./scripts/start_dev.sh

# Или используйте Make
make dev
```

### 🎯 Ручной запуск

**Терминал 1 - Backend:**
```bash
# Активируйте виртуальное окружение
source venv/bin/activate  # Linux/Mac
# или
# venv\Scripts\activate  # Windows

# Запустите сервер
python run_server.py
```

**Терминал 2 - Frontend:**
```bash
cd frontend
npm run dev
```

## ✅ Шаг 6: Проверка работы

### 🌐 Откройте приложение

- **Frontend**: http://localhost:5173
- **Backend API**: http://localhost:8000
- **API Docs**: http://localhost:8000/docs
- **Health Check**: http://localhost:8000/health

### 🧪 Быстрая проверка

```bash
# Проверьте health check
curl http://localhost:8000/health

# Должен вернуть:
# {"status": "healthy", "version": "1.0.0", "timestamp": "2025-09-10T..."}
```

### 🔐 Тест аутентификации

1. Откройте http://localhost:5173
2. Нажмите "Зарегистрироваться"
3. Создайте аккаунт
4. Войдите в систему
5. Создайте тестовый проект

## 🐛 Устранение проблем

### ❌ "ModuleNotFoundError"

```bash
# Переустановите зависимости
pip install -r requirements.txt --force-reinstall
cd frontend && npm install
```

### ❌ "Database connection failed"

```bash
# Проверьте настройки БД
python scripts/check_database.py

# Или пересоздайте подключение
python scripts/setup_supabase.py
```

### ❌ "CORS error"

```bash
# Проверьте CORS_ORIGINS в .env
echo "CORS_ORIGINS=http://localhost:3000,http://localhost:5173" >> .env
```

### ❌ "Port already in use"

```bash
# Найдите процесс, использующий порт
lsof -i :8000  # Backend
lsof -i :5173  # Frontend

# Убейте процесс
kill -9 <PID>
```

## 🎯 Следующие шаги

### 📚 Изучение документации

- [📖 Полная документация](README.md)
- [🔧 Подробная установка](INSTALL.md)
- [🚀 Развертывание](DEPLOY.md)
- [🔐 Безопасность](SECURITY.md)

### 🧪 Запуск тестов

```bash
# Все тесты
make test

# Unit тесты
make test-unit

# E2E тесты
make test-e2e
```

### 🔧 Разработка

```bash
# Запуск в режиме разработки
make dev

# Линтинг кода
make lint

# Форматирование кода
make format
```

## 🆘 Получение помощи

### 📞 Поддержка

1. **Проверьте [FAQ](FAQ.md)** - возможно, ваша проблема уже решена
2. **Создайте Issue** - опишите проблему подробно
3. **Discord** - присоединяйтесь к сообществу
4. **Email** - support@samokoder.com

### 🐛 Сообщение об ошибках

При создании Issue укажите:
- **Версию** приложения (1.0.0)
- **Операционную систему**
- **Шаги воспроизведения**
- **Логи ошибок**

---

## 🎉 Поздравляем!

Вы успешно установили и запустили Самокодер v1.0.0!

### 🏆 Что дальше?

1. **Создайте первый проект** - попробуйте AI генерацию
2. **Изучите API** - посмотрите на http://localhost:8000/docs
3. **Настройте мониторинг** - следуйте [руководству по мониторингу](MONITORING.md)
4. **Внесите вклад** - присоединяйтесь к разработке

### 📊 Статистика установки

- ⏱️ **Время установки**: ~5 минут
- 📦 **Размер**: ~500MB
- 🧪 **Тесты**: 95% покрытие
- 🔒 **Безопасность**: ASVS Level 2
- ♿ **Доступность**: WCAG 2.2 AA

---

**Создано с ❤️ командой Самокодер**  
**© 2025 Samokoder. Все права защищены.**