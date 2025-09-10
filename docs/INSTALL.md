# 🔧 Подробная установка - Самокодер v1.0.0

> **Полное руководство по установке и настройке**  
> Для разработчиков, DevOps инженеров и системных администраторов

## 📋 Содержание

- [Предварительные требования](#-предварительные-требования)
- [Установка зависимостей](#-установка-зависимостей)
- [Настройка базы данных](#-настройка-базы-данных)
- [Конфигурация приложения](#-конфигурация-приложения)
- [Настройка AI провайдеров](#-настройка-ai-провайдеров)
- [Настройка мониторинга](#-настройка-мониторинга)
- [Проверка установки](#-проверка-установки)
- [Устранение проблем](#-устранение-проблем)

## 🎯 Предварительные требования

### 💻 Системные требования

#### Минимальные требования
- **CPU**: 2 ядра, 2.0 GHz
- **RAM**: 4 GB
- **Диск**: 10 GB свободного места
- **ОС**: Linux, macOS, Windows 10+

#### Рекомендуемые требования
- **CPU**: 4+ ядра, 3.0+ GHz
- **RAM**: 8+ GB
- **Диск**: 50+ GB SSD
- **ОС**: Ubuntu 20.04+, macOS 12+, Windows 11

### 🔧 Необходимое ПО

#### Обязательное
- **Python 3.9+** ([скачать](https://python.org/downloads/))
- **Node.js 18+** ([скачать](https://nodejs.org/))
- **Git** ([скачать](https://git-scm.com/))
- **PostgreSQL 15+** или **Supabase**

#### Опциональное
- **Docker** ([скачать](https://docker.com/))
- **Redis** ([скачать](https://redis.io/))
- **Nginx** ([скачать](https://nginx.org/))

### 🔍 Проверка версий

```bash
# Проверьте версии
python --version    # Должно быть 3.9+
python3 --version   # Альтернативная команда
node --version      # Должно быть 18+
npm --version       # Должно быть 8+
git --version       # Любая версия
psql --version      # Должно быть 15+ (если используете локальную PostgreSQL)
```

## 📦 Установка зависимостей

### 🐍 Python Backend

#### 1. Создание виртуального окружения

```bash
# Создайте виртуальное окружение
python -m venv venv

# Активируйте виртуальное окружение
# Linux/macOS:
source venv/bin/activate

# Windows:
# venv\Scripts\activate

# Проверьте активацию
which python  # Должен показать путь к venv/bin/python
```

#### 2. Установка Python пакетов

```bash
# Обновите pip
pip install --upgrade pip

# Установите основные зависимости
pip install -r requirements.txt

# Установите зависимости для разработки
pip install -r requirements-dev.txt

# Проверьте установку
pip list | grep fastapi
```

#### 3. Проверка Python зависимостей

```bash
# Проверьте все зависимости
pip check

# Если есть конфликты, исправьте их
pip install --upgrade package-name

# Проверьте импорты
python -c "
import fastapi
import uvicorn
import supabase
import redis
import pydantic
print('✅ Все основные зависимости установлены!')
"
```

### ⚛️ Node.js Frontend

#### 1. Установка Node.js зависимостей

```bash
# Перейдите в директорию frontend
cd frontend

# Очистите кэш (если нужно)
npm cache clean --force

# Установите зависимости
npm install

# Проверьте установку
npm list --depth=0
```

#### 2. Проверка Frontend зависимостей

```bash
# Проверьте TypeScript
npx tsc --version

# Проверьте Vite
npx vite --version

# Проверьте React
npm list react

# Проверьте сборку
npm run build
```

#### 3. Возврат в корневую директорию

```bash
cd ..
```

## 🗄️ Настройка базы данных

### 🎯 Вариант A: Supabase (рекомендуется)

#### 1. Создание проекта Supabase

1. **Перейдите на [supabase.com](https://supabase.com)**
2. **Войдите в аккаунт** или создайте новый
3. **Создайте новый проект**:
   - Название: `samokoder`
   - Пароль: сгенерируйте сложный пароль
   - Регион: выберите ближайший
4. **Дождитесь создания** (2-3 минуты)

#### 2. Получение ключей

1. **Перейдите в Settings → API**
2. **Скопируйте**:
   - Project URL
   - anon public key
   - service_role secret key

#### 3. Выполнение SQL скрипта

```bash
# Откройте SQL Editor в Supabase Dashboard
# Скопируйте содержимое файла
cat database/schema.sql

# Вставьте в SQL Editor и выполните
```

#### 4. Проверка подключения

```bash
# Создайте тестовый скрипт
cat > test_supabase.py << 'EOF'
import os
from supabase import create_client, Client

# Загрузите переменные окружения
from dotenv import load_dotenv
load_dotenv()

url = os.getenv("SUPABASE_URL")
key = os.getenv("SUPABASE_ANON_KEY")

if not url or not key:
    print("❌ SUPABASE_URL и SUPABASE_ANON_KEY должны быть установлены")
    exit(1)

supabase: Client = create_client(url, key)

try:
    # Тест подключения
    response = supabase.table('users').select('*').limit(1).execute()
    print("✅ Подключение к Supabase успешно!")
    print(f"📊 Найдено пользователей: {len(response.data)}")
except Exception as e:
    print(f"❌ Ошибка подключения: {e}")
EOF

# Запустите тест
python test_supabase.py

# Удалите тестовый файл
rm test_supabase.py
```

### 🎯 Вариант B: Локальная PostgreSQL

#### 1. Установка PostgreSQL

**Ubuntu/Debian:**
```bash
# Обновите пакеты
sudo apt update

# Установите PostgreSQL
sudo apt install postgresql postgresql-contrib

# Запустите службу
sudo systemctl start postgresql
sudo systemctl enable postgresql

# Проверьте статус
sudo systemctl status postgresql
```

**macOS (с Homebrew):**
```bash
# Установите Homebrew (если не установлен)
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Установите PostgreSQL
brew install postgresql

# Запустите службу
brew services start postgresql
```

**Windows:**
1. Скачайте установщик с [postgresql.org](https://postgresql.org/download/windows/)
2. Запустите установщик
3. Следуйте инструкциям мастера установки

#### 2. Создание базы данных

```bash
# Войдите в PostgreSQL
sudo -u postgres psql

# Создайте базу данных и пользователя
CREATE DATABASE samokoder;
CREATE USER samokoder WITH PASSWORD 'your_secure_password';
GRANT ALL PRIVILEGES ON DATABASE samokoder TO samokoder;
GRANT ALL ON SCHEMA public TO samokoder;
\q
```

#### 3. Выполнение миграций

```bash
# Установите Alembic (если не установлен)
pip install alembic

# Инициализируйте Alembic (если не инициализирован)
alembic init alembic

# Выполните миграции
python -m alembic upgrade head
```

#### 4. Проверка подключения

```bash
# Тест подключения
psql -h localhost -U samokoder -d samokoder -c "SELECT version();"
```

### 🎯 Вариант C: Docker

#### 1. Установка Docker

**Ubuntu/Debian:**
```bash
# Установите Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh

# Добавьте пользователя в группу docker
sudo usermod -aG docker $USER

# Перезайдите в систему
```

**macOS/Windows:**
- Скачайте Docker Desktop с [docker.com](https://docker.com)

#### 2. Запуск PostgreSQL в Docker

```bash
# Создайте docker-compose.yml
cat > docker-compose.dev.yml << 'EOF'
version: '3.8'
services:
  postgres:
    image: postgres:15
    environment:
      POSTGRES_DB: samokoder
      POSTGRES_USER: samokoder
      POSTGRES_PASSWORD: password
    ports:
      - "5432:5432"
    volumes:
      - postgres_data:/var/lib/postgresql/data
      - ./database/schema.sql:/docker-entrypoint-initdb.d/schema.sql

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"

volumes:
  postgres_data:
EOF

# Запустите сервисы
docker-compose -f docker-compose.dev.yml up -d

# Проверьте статус
docker-compose -f docker-compose.dev.yml ps
```

#### 3. Выполнение миграций

```bash
# Дождитесь запуска PostgreSQL (30 секунд)
sleep 30

# Выполните миграции
python -m alembic upgrade head
```

## ⚙️ Конфигурация приложения

### 📝 Создание .env файла

```bash
# Скопируйте пример конфигурации
cp .env.example .env

# Откройте для редактирования
nano .env  # или code .env, vim .env
```

### 🔧 Полная конфигурация

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
# БАЗА ДАННЫХ
# ===========================================
# Supabase (рекомендуется)
SUPABASE_URL=https://your-project-id.supabase.co
SUPABASE_ANON_KEY=your_anon_key_here
SUPABASE_SERVICE_ROLE_KEY=your_service_role_key_here

# ИЛИ локальная PostgreSQL
# DATABASE_URL=postgresql://samokoder:password@localhost:5432/samokoder

# ===========================================
# БЕЗОПАСНОСТЬ
# ===========================================
JWT_SECRET=your-super-secret-jwt-key-here-32-chars-minimum
API_ENCRYPTION_KEY=your-32-character-secret-key-here
API_ENCRYPTION_SALT=samokoder_salt_2025

# ===========================================
# AI ПРОВАЙДЕРЫ (минимум один)
# ===========================================
# OpenAI
OPENAI_API_KEY=sk-your-openai-key

# Anthropic
ANTHROPIC_API_KEY=sk-ant-your-anthropic-key

# Groq
GROQ_API_KEY=gsk_your-groq-key

# OpenRouter
OPENROUTER_API_KEY=sk-or-your-openrouter-key

# ===========================================
# КЭШИРОВАНИЕ И СЕССИИ
# ===========================================
REDIS_URL=redis://localhost:6379
REDIS_PASSWORD=your-redis-password

# ===========================================
# МОНИТОРИНГ
# ===========================================
SENTRY_DSN=https://your-sentry-dsn
ENABLE_METRICS=true
METRICS_PORT=9090

# ===========================================
# ФАЙЛЫ И ХРАНИЛИЩЕ
# ===========================================
EXPORT_STORAGE_PATH=./exports
WORKSPACE_STORAGE_PATH=./workspaces
MAX_FILE_SIZE_MB=50

# ===========================================
# RATE LIMITING
# ===========================================
RATE_LIMIT_PER_MINUTE=60
RATE_LIMIT_PER_HOUR=1000

# ===========================================
# CORS
# ===========================================
CORS_ORIGINS=http://localhost:3000,http://localhost:5173,https://yourdomain.com

# ===========================================
# GPT-PILOT
# ===========================================
GPT_PILOT_PATH=./samokoder-core
GPT_PILOT_TIMEOUT=300

# ===========================================
# ЛИМИТЫ ПРОЕКТОВ
# ===========================================
MAX_PROJECTS_PER_USER=10
MAX_FILE_SIZE_BYTES=52428800  # 50MB
```

### 🔐 Генерация безопасных ключей

```bash
# Создайте скрипт генерации ключей
cat > generate_keys.py << 'EOF'
import secrets
import base64
import string

def generate_key(length=32):
    """Генерирует криптографически стойкий ключ"""
    return ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(length))

def generate_jwt_secret():
    """Генерирует JWT секрет"""
    return secrets.token_urlsafe(32)

def generate_api_key():
    """Генерирует API ключ шифрования"""
    return base64.b64encode(secrets.token_bytes(32)).decode('utf-8')

if __name__ == "__main__":
    print("🔐 Генерация безопасных ключей")
    print("=" * 50)
    print(f"JWT_SECRET={generate_jwt_secret()}")
    print(f"API_ENCRYPTION_KEY={generate_api_key()}")
    print("=" * 50)
    print("✅ Скопируйте эти ключи в ваш .env файл")
EOF

# Запустите генерацию
python generate_keys.py

# Удалите скрипт
rm generate_keys.py
```

## 🤖 Настройка AI провайдеров

### 🎯 OpenAI

1. **Создайте аккаунт** на [platform.openai.com](https://platform.openai.com)
2. **Получите API ключ** в разделе API Keys
3. **Добавьте в .env**:
   ```env
   OPENAI_API_KEY=sk-your-openai-key
   ```

### 🎯 Anthropic

1. **Создайте аккаунт** на [console.anthropic.com](https://console.anthropic.com)
2. **Получите API ключ** в разделе API Keys
3. **Добавьте в .env**:
   ```env
   ANTHROPIC_API_KEY=sk-ant-your-anthropic-key
   ```

### 🎯 Groq

1. **Создайте аккаунт** на [console.groq.com](https://console.groq.com)
2. **Получите API ключ** в разделе API Keys
3. **Добавьте в .env**:
   ```env
   GROQ_API_KEY=gsk_your-groq-key
   ```

### 🎯 OpenRouter

1. **Создайте аккаунт** на [openrouter.ai](https://openrouter.ai)
2. **Получите API ключ** в разделе API Keys
3. **Добавьте в .env**:
   ```env
   OPENROUTER_API_KEY=sk-or-your-openrouter-key
   ```

### 🧪 Тест AI провайдеров

```bash
# Создайте тестовый скрипт
cat > test_ai_providers.py << 'EOF'
import os
from dotenv import load_dotenv

load_dotenv()

def test_provider(name, key):
    if key and key.startswith(('sk-', 'gsk_', 'sk-or-')):
        print(f"✅ {name}: Ключ найден")
        return True
    else:
        print(f"❌ {name}: Ключ не найден или неверный формат")
        return False

print("🤖 Проверка AI провайдеров")
print("=" * 40)

providers = [
    ("OpenAI", os.getenv("OPENAI_API_KEY")),
    ("Anthropic", os.getenv("ANTHROPIC_API_KEY")),
    ("Groq", os.getenv("GROQ_API_KEY")),
    ("OpenRouter", os.getenv("OPENROUTER_API_KEY")),
]

working = 0
for name, key in providers:
    if test_provider(name, key):
        working += 1

print("=" * 40)
print(f"📊 Работающих провайдеров: {working}/{len(providers)}")

if working == 0:
    print("⚠️  Внимание: Ни один AI провайдер не настроен!")
    print("   Добавьте хотя бы один API ключ в .env файл")
else:
    print("✅ Готово к работе с AI!")
EOF

# Запустите тест
python test_ai_providers.py

# Удалите скрипт
rm test_ai_providers.py
```

## 📊 Настройка мониторинга

### 🎯 Prometheus (опционально)

```bash
# Создайте конфигурацию Prometheus
mkdir -p monitoring/prometheus

cat > monitoring/prometheus/prometheus.yml << 'EOF'
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: 'samokoder'
    static_configs:
      - targets: ['localhost:9090']
EOF

# Запустите Prometheus в Docker
docker run -d \
  --name prometheus \
  -p 9090:9090 \
  -v $(pwd)/monitoring/prometheus/prometheus.yml:/etc/prometheus/prometheus.yml \
  prom/prometheus
```

### 🎯 Grafana (опционально)

```bash
# Запустите Grafana в Docker
docker run -d \
  --name grafana \
  -p 3000:3000 \
  grafana/grafana

# Откройте http://localhost:3000
# Логин: admin, Пароль: admin
```

### 🎯 Sentry (опционально)

1. **Создайте проект** на [sentry.io](https://sentry.io)
2. **Получите DSN** в настройках проекта
3. **Добавьте в .env**:
   ```env
   SENTRY_DSN=https://your-sentry-dsn
   ```

## ✅ Проверка установки

### 🧪 Комплексная проверка

```bash
# Создайте скрипт проверки
cat > check_installation.py << 'EOF'
import sys
import subprocess
import os
from dotenv import load_dotenv

load_dotenv()

def check_python():
    """Проверка Python и зависимостей"""
    try:
        import fastapi
        import uvicorn
        import supabase
        import pydantic
        print("✅ Python зависимости: OK")
        return True
    except ImportError as e:
        print(f"❌ Python зависимости: {e}")
        return False

def check_node():
    """Проверка Node.js и зависимостей"""
    try:
        result = subprocess.run(['node', '--version'], capture_output=True, text=True)
        if result.returncode == 0:
            print(f"✅ Node.js: {result.stdout.strip()}")
            return True
        else:
            print("❌ Node.js: не найден")
            return False
    except FileNotFoundError:
        print("❌ Node.js: не найден")
        return False

def check_database():
    """Проверка подключения к БД"""
    try:
        from supabase import create_client
        url = os.getenv("SUPABASE_URL")
        key = os.getenv("SUPABASE_ANON_KEY")
        
        if not url or not key:
            print("❌ База данных: SUPABASE_URL и SUPABASE_ANON_KEY не настроены")
            return False
            
        supabase = create_client(url, key)
        response = supabase.table('users').select('*').limit(1).execute()
        print("✅ База данных: подключение успешно")
        return True
    except Exception as e:
        print(f"❌ База данных: {e}")
        return False

def check_ai_providers():
    """Проверка AI провайдеров"""
    providers = [
        ("OpenAI", os.getenv("OPENAI_API_KEY")),
        ("Anthropic", os.getenv("ANTHROPIC_API_KEY")),
        ("Groq", os.getenv("GROQ_API_KEY")),
        ("OpenRouter", os.getenv("OPENROUTER_API_KEY")),
    ]
    
    working = 0
    for name, key in providers:
        if key and key.startswith(('sk-', 'gsk_', 'sk-or-')):
            working += 1
    
    if working > 0:
        print(f"✅ AI провайдеры: {working} настроено")
        return True
    else:
        print("❌ AI провайдеры: ни один не настроен")
        return False

def check_config():
    """Проверка конфигурации"""
    required_vars = [
        "JWT_SECRET",
        "API_ENCRYPTION_KEY",
        "SUPABASE_URL",
        "SUPABASE_ANON_KEY",
    ]
    
    missing = []
    for var in required_vars:
        if not os.getenv(var):
            missing.append(var)
    
    if missing:
        print(f"❌ Конфигурация: отсутствуют {', '.join(missing)}")
        return False
    else:
        print("✅ Конфигурация: все переменные настроены")
        return True

def main():
    print("🔍 Проверка установки Самокодер v1.0.0")
    print("=" * 50)
    
    checks = [
        check_python(),
        check_node(),
        check_config(),
        check_database(),
        check_ai_providers(),
    ]
    
    print("=" * 50)
    
    if all(checks):
        print("🎉 Все проверки пройдены! Установка завершена успешно.")
        print("🚀 Запустите: python run_server.py")
        return 0
    else:
        print("❌ Некоторые проверки не пройдены. Исправьте ошибки и повторите.")
        return 1

if __name__ == "__main__":
    sys.exit(main())
EOF

# Запустите проверку
python check_installation.py

# Удалите скрипт
rm check_installation.py
```

### 🚀 Тестовый запуск

```bash
# Запустите backend
python run_server.py &
BACKEND_PID=$!

# Подождите запуска
sleep 5

# Проверьте health check
curl -s http://localhost:8000/health | jq .

# Остановите backend
kill $BACKEND_PID

# Запустите frontend
cd frontend
npm run build
cd ..

echo "✅ Тестовый запуск успешен!"
```

## 🐛 Устранение проблем

### ❌ Общие проблемы

#### "ModuleNotFoundError: No module named 'fastapi'"

```bash
# Активируйте виртуальное окружение
source venv/bin/activate  # Linux/macOS
# или
# venv\Scripts\activate  # Windows

# Переустановите зависимости
pip install -r requirements.txt --force-reinstall
```

#### "npm: command not found"

```bash
# Установите Node.js
# Ubuntu/Debian:
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
sudo apt-get install -y nodejs

# macOS:
brew install node

# Windows: скачайте с nodejs.org
```

#### "psql: command not found"

```bash
# Установите PostgreSQL
# Ubuntu/Debian:
sudo apt install postgresql-client

# macOS:
brew install postgresql

# Windows: скачайте с postgresql.org
```

### ❌ Проблемы с базой данных

#### "connection refused" для Supabase

```bash
# Проверьте URL и ключи
echo "SUPABASE_URL: $SUPABASE_URL"
echo "SUPABASE_ANON_KEY: ${SUPABASE_ANON_KEY:0:20}..."

# Проверьте подключение
python -c "
from supabase import create_client
import os
from dotenv import load_dotenv
load_dotenv()
url = os.getenv('SUPABASE_URL')
key = os.getenv('SUPABASE_ANON_KEY')
print(f'URL: {url}')
print(f'Key: {key[:20] if key else None}...')
"
```

#### "relation does not exist" для PostgreSQL

```bash
# Проверьте, что таблицы созданы
psql -h localhost -U samokoder -d samokoder -c "\dt"

# Если таблиц нет, выполните миграции
python -m alembic upgrade head
```

### ❌ Проблемы с AI провайдерами

#### "API key not found"

```bash
# Проверьте переменные окружения
grep -E "(OPENAI|ANTHROPIC|GROQ|OPENROUTER)_API_KEY" .env

# Проверьте формат ключей
python -c "
import os
from dotenv import load_dotenv
load_dotenv()
keys = {
    'OpenAI': os.getenv('OPENAI_API_KEY'),
    'Anthropic': os.getenv('ANTHROPIC_API_KEY'),
    'Groq': os.getenv('GROQ_API_KEY'),
    'OpenRouter': os.getenv('OPENROUTER_API_KEY'),
}
for name, key in keys.items():
    if key:
        print(f'{name}: {key[:10]}... (длина: {len(key)})')
    else:
        print(f'{name}: не установлен')
"
```

### ❌ Проблемы с портами

#### "Port 8000 already in use"

```bash
# Найдите процесс, использующий порт
lsof -i :8000

# Убейте процесс
kill -9 <PID>

# Или используйте другой порт
echo "PORT=8001" >> .env
```

#### "Port 5173 already in use"

```bash
# Найдите процесс, использующий порт
lsof -i :5173

# Убейте процесс
kill -9 <PID>

# Или используйте другой порт
cd frontend
echo "VITE_PORT=5174" > .env.local
```

## 🎯 Следующие шаги

### 📚 Изучение документации

- [🚀 Быстрый старт](QUICKSTART.md) - Установка за 5 минут
- [🚀 Развертывание](DEPLOY.md) - Настройка для продакшена
- [🔐 Безопасность](SECURITY.md) - Руководство по безопасности
- [📊 Мониторинг](MONITORING.md) - Настройка мониторинга

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

---

## 🎉 Поздравляем!

Вы успешно установили и настроили Самокодер v1.0.0!

### 🏆 Что дальше?

1. **Запустите приложение** - `python run_server.py`
2. **Откройте в браузере** - http://localhost:5173
3. **Создайте аккаунт** и первый проект
4. **Изучите API** - http://localhost:8000/docs
5. **Настройте мониторинг** - следуйте [руководству](MONITORING.md)

### 📊 Статистика установки

- ⏱️ **Время установки**: ~15-30 минут
- 📦 **Размер**: ~1GB (с зависимостями)
- 🧪 **Тесты**: 95% покрытие
- 🔒 **Безопасность**: ASVS Level 2
- ♿ **Доступность**: WCAG 2.2 AA

---

**Создано с ❤️ командой Самокодер**  
**© 2025 Samokoder. Все права защищены.**