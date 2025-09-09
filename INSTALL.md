# 🚀 Установка и настройка Самокодер

## 📋 Предварительные требования

- **Python 3.9+**
- **Node.js 18+** (для фронтенда, когда будет готов)
- **Supabase аккаунт** (бесплатный)
- **API ключи** для AI провайдеров (OpenRouter, OpenAI, Anthropic, Groq)

## 🔧 Пошаговая установка

### 1. Клонирование репозитория

```bash
git clone https://github.com/your-username/samokoder.git
cd samokoder
```

### 2. Создание виртуального окружения

```bash
# Создаем виртуальное окружение
python -m venv venv

# Активируем его
# На Linux/Mac:
source venv/bin/activate
# На Windows:
# venv\Scripts\activate
```

### 3. Установка зависимостей

```bash
pip install -r requirements.txt
```

### 4. Настройка Supabase

#### 4.1 Создание проекта в Supabase

1. Перейдите на [supabase.com](https://supabase.com)
2. Создайте новый проект
3. Запомните **Project URL** и **anon public key**

#### 4.2 Настройка базы данных

1. Откройте **SQL Editor** в Supabase Dashboard
2. Выполните скрипт `database/schema.sql`
3. Выполните скрипт `database/init_data.sql`

#### 4.3 Настройка аутентификации

1. Перейдите в **Authentication > Settings**
2. Включите **Email** провайдер
3. Настройте **Site URL**: `http://localhost:8000`
4. Добавьте **Redirect URLs**: `http://localhost:8000/auth/callback`

### 5. Настройка переменных окружения

```bash
# Копируем пример конфигурации
cp .env.example .env

# Редактируем файл .env
nano .env
```

Заполните следующие переменные в `.env`:

```env
# Supabase Configuration
SUPABASE_URL=https://your-project.supabase.co
SUPABASE_ANON_KEY=your_anon_key_here
SUPABASE_SERVICE_ROLE_KEY=your_service_role_key_here

# API Encryption (сгенерируйте случайные строки)
API_ENCRYPTION_KEY=your_32_character_encryption_key_here
API_ENCRYPTION_SALT=your_16_character_salt_here

# System API Keys (опционально, для fallback)
SYSTEM_OPENROUTER_KEY=your_openrouter_api_key_here
SYSTEM_OPENAI_KEY=your_openai_api_key_here
SYSTEM_ANTHROPIC_KEY=your_anthropic_api_key_here
SYSTEM_GROQ_KEY=your_groq_api_key_here
```

### 6. Генерация ключей шифрования

```bash
# Генерируем случайные ключи
python -c "
import secrets
import string

# Генерируем 32-символьный ключ шифрования
encryption_key = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(32))

# Генерируем 16-символьную соль
salt = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(16))

print(f'API_ENCRYPTION_KEY={encryption_key}')
print(f'API_ENCRYPTION_SALT={salt}')
"
```

### 7. Запуск сервера

```bash
# Запуск через скрипт
python run_server.py

# Или напрямую через uvicorn
uvicorn backend.main:app --reload --host 0.0.0.0 --port 8000
```

### 8. Проверка работы

Откройте в браузере:
- **API документация**: http://localhost:8000/docs
- **Health check**: http://localhost:8000/health
- **Корневой эндпоинт**: http://localhost:8000/

## 🧪 Тестирование установки

### 1. Проверка API

```bash
# Проверяем health endpoint
curl http://localhost:8000/health

# Ожидаемый ответ:
# {
#   "status": "healthy",
#   "timestamp": "2025-01-XX...",
#   "active_projects": 0
# }
```

### 2. Проверка Supabase

```bash
# Проверяем подключение к базе данных
curl -X GET "http://localhost:8000/api/ai/providers" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"
```

### 3. Проверка GPT-Pilot интеграции

```bash
# Создаем тестовый проект
curl -X POST "http://localhost:8000/api/projects" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -d '{
    "name": "Test Project",
    "description": "Тестовое приложение для проверки интеграции"
  }'
```

## 🔧 Устранение неполадок

### Ошибка подключения к Supabase

```
❌ Ошибка: Invalid API key
```

**Решение:**
1. Проверьте правильность `SUPABASE_URL` и `SUPABASE_ANON_KEY`
2. Убедитесь, что проект Supabase активен
3. Проверьте настройки RLS в Supabase

### Ошибка импорта GPT-Pilot

```
❌ ModuleNotFoundError: No module named 'core'
```

**Решение:**
1. Убедитесь, что GPT-Pilot клонирован в `samokoder-core/`
2. Проверьте структуру директорий
3. Переустановите зависимости: `pip install -r requirements.txt`

### Ошибка шифрования

```
❌ ValueError: Ошибка шифрования API ключа
```

**Решение:**
1. Проверьте правильность `API_ENCRYPTION_KEY` (32 символа)
2. Проверьте правильность `API_ENCRYPTION_SALT` (16 символов)
3. Перегенерируйте ключи шифрования

### Ошибка портов

```
❌ Address already in use: Port 8000
```

**Решение:**
1. Измените порт в `.env`: `PORT=8001`
2. Или остановите процесс на порту 8000:
   ```bash
   # Найти процесс
   lsof -i :8000
   # Убить процесс
   kill -9 PID
   ```

## 📚 Дополнительные настройки

### Настройка логирования

```env
# В .env файле
LOG_LEVEL=DEBUG  # DEBUG, INFO, WARNING, ERROR
```

### Настройка CORS

```env
# В .env файле
CORS_ORIGINS=http://localhost:3000,http://localhost:5173,https://yourdomain.com
```

### Настройка лимитов

```env
# В .env файле
RATE_LIMIT_PER_MINUTE=60
RATE_LIMIT_PER_HOUR=1000
MAX_FILE_SIZE_MB=50
```

## 🚀 Готово!

Если все настроено правильно, вы увидите:

```
🚀 Запуск Samokoder Backend API...
📍 Host: 0.0.0.0
🔌 Port: 8000
🌍 Environment: development
🐛 Debug: True
📚 Docs: http://0.0.0.0:8000/docs
--------------------------------------------------
INFO:     Started server process [XXXX]
INFO:     Waiting for application startup.
INFO:     Application startup complete.
INFO:     Uvicorn running on http://0.0.0.0:8000 (Press CTRL+C to quit)
```

Теперь можете:
1. 📖 Изучить API документацию на `/docs`
2. 🧪 Протестировать эндпоинты
3. 🔗 Интегрировать с фронтендом
4. 🚀 Начать разработку!

## 📞 Поддержка

Если возникли проблемы:
- 📧 Email: hello@samokoder.com
- 💬 Discord: [Сервер сообщества](https://discord.gg/samokoder)
- 🐛 Issues: [GitHub Issues](https://github.com/your-username/samokoder/issues)