# ❓ FAQ - Самокодер v1.0.0

> **Часто задаваемые вопросы и ответы**  
> Быстрые решения для распространенных проблем

## 📋 Содержание

- [Общие вопросы](#-общие-вопросы)
- [Установка и настройка](#-установка-и-настройка)
- [База данных](#-база-данных)
- [AI провайдеры](#-ai-провайдеры)
- [Производительность](#-производительность)
- [Безопасность](#-безопасность)
- [Устранение неполадок](#-устранение-неполадок)
- [Разработка](#-разработка)

## 🤔 Общие вопросы

### ❓ Что такое Самокодер?

**Самокодер** — это полнофункциональная платформа для генерации кода с помощью ИИ. Она включает:
- Современный React фронтенд с TypeScript
- FastAPI бэкенд с Python
- Интеграцию с множественными AI провайдерами
- Управление проектами и версионирование
- Систему аутентификации и авторизации

### ❓ Какие AI провайдеры поддерживаются?

Поддерживаются следующие провайдеры:
- **OpenAI** (GPT-3.5, GPT-4, GPT-4 Turbo)
- **Anthropic** (Claude 3.5 Sonnet, Claude 3 Opus)
- **Groq** (Llama 3, Mixtral, Gemma)
- **OpenRouter** (доступ к множественным моделям)

### ❓ Сколько стоит использование?

В версии 1.0.0 Самокодер бесплатен для использования. Платные тарифы планируются в версии 1.1.0.

### ❓ Какие браузеры поддерживаются?

Поддерживаются все современные браузеры:
- Chrome 90+
- Firefox 88+
- Safari 14+
- Edge 90+

### ❓ Есть ли мобильная версия?

Да, веб-интерфейс адаптивен и работает на мобильных устройствах. Нативные приложения планируются в будущих версиях.

## 🔧 Установка и настройка

### ❓ Какие системные требования?

**Минимальные требования:**
- CPU: 2 ядра, 2.0 GHz
- RAM: 4 GB
- Диск: 10 GB
- ОС: Linux, macOS, Windows 10+

**Рекомендуемые требования:**
- CPU: 4+ ядра, 3.0+ GHz
- RAM: 8+ GB
- Диск: 50+ GB SSD

### ❓ Как установить Самокодер?

```bash
# 1. Клонируйте репозиторий
git clone https://github.com/samokoder/samokoder.git
cd samokoder

# 2. Установите зависимости
pip install -r requirements.txt
cd frontend && npm install && cd ..

# 3. Настройте .env файл
cp .env.example .env
# Отредактируйте .env

# 4. Запустите приложение
python run_server.py
```

### ❓ Как настроить переменные окружения?

Скопируйте `.env.example` в `.env` и заполните необходимые значения:

```bash
# Копируем пример конфигурации
cp .env.example .env

# Редактируем файл
nano .env
```

```env
# Основные настройки
NODE_ENV=development
PORT=8000

# База данных
SUPABASE_URL=https://your-project.supabase.co
SUPABASE_ANON_KEY=your_anon_key

# AI провайдеры (минимум один)
OPENAI_API_KEY=sk-your-openai-key

# Безопасность
JWT_SECRET=your-super-secret-jwt-key-here-32-chars
API_ENCRYPTION_KEY=your-32-character-secret-key-here
```

> **💡 Совет**: В `.env.example` уже настроены все необходимые переменные с примерами значений.

### ❓ Как сгенерировать безопасные ключи?

```bash
# Используйте встроенный генератор
python scripts/generate_keys_simple.py

# Или создайте вручную
python -c "
import secrets
import base64
print(f'JWT_SECRET={secrets.token_urlsafe(32)}')
print(f'API_ENCRYPTION_KEY={base64.b64encode(secrets.token_bytes(32)).decode()}')
"
```

## 🗄️ База данных

### ❓ Какую базу данных использовать?

**Рекомендуется Supabase** (PostgreSQL в облаке):
- Простая настройка
- Встроенная аутентификация
- Real-time функции
- Автоматические бэкапы

**Альтернативы:**
- Локальная PostgreSQL
- Docker PostgreSQL
- Любая PostgreSQL совместимая БД

### ❓ Как настроить Supabase?

1. Создайте проект на [supabase.com](https://supabase.com)
2. Получите URL и ключи в Settings → API
3. Выполните SQL скрипт из `database/schema.sql`
4. Добавьте ключи в `.env` файл

### ❓ Как настроить локальную PostgreSQL?

```bash
# Ubuntu/Debian
sudo apt install postgresql postgresql-contrib
sudo -u postgres createdb samokoder
sudo -u postgres createuser samokoder

# macOS
brew install postgresql
brew services start postgresql
createdb samokoder

# Выполните миграции
python -m alembic upgrade head
```

### ❓ Как выполнить миграции?

```bash
# Применить все миграции
python -m alembic upgrade head

# Откатить одну миграцию
python -m alembic downgrade -1

# Просмотреть историю
python -m alembic history
```

### ❓ Как создать бэкап базы данных?

```bash
# Supabase
supabase db dump --file backup.sql

# PostgreSQL
pg_dump -h localhost -U samokoder -d samokoder > backup.sql

# Восстановление
psql -h localhost -U samokoder -d samokoder < backup.sql
```

## 🤖 AI провайдеры

### ❓ Как получить API ключи?

**OpenAI:**
1. Зарегистрируйтесь на [platform.openai.com](https://platform.openai.com)
2. Перейдите в API Keys
3. Создайте новый ключ

**Anthropic:**
1. Зарегистрируйтесь на [console.anthropic.com](https://console.anthropic.com)
2. Перейдите в API Keys
3. Создайте новый ключ

**Groq:**
1. Зарегистрируйтесь на [console.groq.com](https://console.groq.com)
2. Перейдите в API Keys
3. Создайте новый ключ

**OpenRouter:**
1. Зарегистрируйтесь на [openrouter.ai](https://openrouter.ai)
2. Перейдите в API Keys
3. Создайте новый ключ

### ❓ Какой провайдер лучше использовать?

**Для разработки:** Groq (быстрый и бесплатный)
**Для продакшена:** OpenAI GPT-4 (качество) или Anthropic Claude (безопасность)
**Для экспериментов:** OpenRouter (множественные модели)

### ❓ Как настроить fallback провайдеров?

Система автоматически переключается между провайдерами при недоступности. Настройте несколько ключей в `.env`:

```env
OPENAI_API_KEY=sk-your-openai-key
ANTHROPIC_API_KEY=sk-ant-your-anthropic-key
GROQ_API_KEY=gsk_your-groq-key
```

### ❓ Как отслеживать использование AI?

```bash
# Просмотр метрик
curl http://localhost:8000/metrics | grep ai_usage

# Или через API
curl http://localhost:8000/api/ai/usage
```

## ⚡ Производительность

### ❓ Приложение работает медленно, что делать?

1. **Проверьте ресурсы:**
   ```bash
   htop  # CPU и память
   df -h  # Диск
   ```

2. **Оптимизируйте базу данных:**
   ```sql
   -- Создайте индексы
   CREATE INDEX idx_projects_user_id ON projects(user_id);
   CREATE INDEX idx_users_email ON users(email);
   ```

3. **Настройте кэширование:**
   ```bash
   # Запустите Redis
   redis-server
   ```

4. **Масштабируйте приложение:**
   ```bash
   # Docker Compose
   docker-compose up -d --scale backend=3
   ```

### ❓ Как оптимизировать фронтенд?

1. **Включите lazy loading:**
   ```typescript
   const LazyComponent = lazy(() => import('./Component'));
   ```

2. **Используйте мемоизацию:**
   ```typescript
   const MemoizedComponent = memo(Component);
   ```

3. **Оптимизируйте bundle:**
   ```bash
   npm run build -- --analyze
   ```

### ❓ Как мониторить производительность?

```bash
# Prometheus метрики
curl http://localhost:9090/metrics

# Grafana дашборд
open http://localhost:3000

# Логи приложения
tail -f logs/app.log
```

## 🔐 Безопасность

### ❓ Как защитить API ключи?

1. **Никогда не коммитьте .env файл:**
   ```bash
   echo ".env" >> .gitignore
   ```

2. **Используйте переменные окружения:**
   ```bash
   export OPENAI_API_KEY=sk-your-key
   ```

3. **Ротируйте ключи регулярно:**
   ```bash
   python scripts/rotate_keys.py
   ```

### ❓ Как настроить HTTPS?

```nginx
# Nginx конфигурация
server {
    listen 443 ssl;
    server_name samokoder.com;
    
    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;
    
    location / {
        proxy_pass http://localhost:8000;
    }
}
```

### ❓ Как настроить аутентификацию?

Система использует JWT токены. Настройте в `.env`:

```env
JWT_SECRET=your-super-secret-jwt-key-here-32-chars
ACCESS_TOKEN_EXPIRE_MINUTES=30
REFRESH_TOKEN_EXPIRE_DAYS=7
```

### ❓ Как настроить rate limiting?

```env
RATE_LIMIT_PER_MINUTE=60
RATE_LIMIT_PER_HOUR=1000
```

## 🐛 Устранение неполадок

### ❓ "ModuleNotFoundError: No module named 'fastapi'"

```bash
# Активируйте виртуальное окружение
source venv/bin/activate  # Linux/macOS
# или
# venv\Scripts\activate  # Windows

# Переустановите зависимости
pip install -r requirements.txt --force-reinstall
```

### ❓ "Database connection failed"

```bash
# Проверьте настройки БД
python -c "
from config.settings import settings
print(f'Database URL: {settings.database_url}')
"

# Проверьте подключение
psql -h localhost -U samokoder -d samokoder -c "SELECT 1;"
```

### ❓ "CORS error"

```bash
# Проверьте CORS_ORIGINS в .env
echo "CORS_ORIGINS=http://localhost:3000,http://localhost:5173" >> .env
```

### ❓ "Port already in use"

```bash
# Найдите процесс
lsof -i :8000  # Backend
lsof -i :5173  # Frontend

# Убейте процесс
kill -9 <PID>

# Или используйте другой порт
echo "PORT=8001" >> .env
```

### ❓ "API key not found"

```bash
# Проверьте переменные окружения
grep -E "(OPENAI|ANTHROPIC|GROQ|OPENROUTER)_API_KEY" .env

# Проверьте формат ключей
python -c "
import os
from dotenv import load_dotenv
load_dotenv()
keys = ['OPENAI_API_KEY', 'ANTHROPIC_API_KEY', 'GROQ_API_KEY', 'OPENROUTER_API_KEY']
for key in keys:
    value = os.getenv(key)
    if value:
        print(f'{key}: {value[:10]}... (длина: {len(value)})')
    else:
        print(f'{key}: не установлен')
"
```

### ❓ Приложение не запускается

1. **Проверьте логи:**
   ```bash
   tail -f logs/app.log
   ```

2. **Проверьте конфигурацию:**
   ```bash
   python -c "from config.settings import settings; print('Config OK')"
   ```

3. **Проверьте зависимости:**
   ```bash
   pip check
   ```

4. **Проверьте порты:**
   ```bash
   lsof -i :8000
   lsof -i :5173
   ```

### ❓ База данных недоступна

1. **Проверьте статус PostgreSQL:**
   ```bash
   sudo systemctl status postgresql
   ```

2. **Проверьте подключение:**
   ```bash
   psql -h localhost -U samokoder -d samokoder
   ```

3. **Проверьте логи PostgreSQL:**
   ```bash
   sudo journalctl -u postgresql -f
   ```

4. **Проверьте место на диске:**
   ```bash
   df -h
   ```

## 💻 Разработка

### ❓ Как запустить в режиме разработки?

```bash
# Автоматический запуск
./scripts/start_dev.sh

# Или ручной запуск
# Терминал 1 - Backend
python run_server.py

# Терминал 2 - Frontend
cd frontend && npm run dev
```

### ❓ Как запустить тесты?

```bash
# Все тесты
make test

# Unit тесты
make test-unit

# Integration тесты
make test-integration

# E2E тесты
make test-e2e
```

### ❓ Как добавить новую функцию?

1. **Создайте ветку:**
   ```bash
   git checkout -b feature/new-feature
   ```

2. **Внесите изменения**

3. **Напишите тесты:**
   ```bash
   # Создайте тест
   touch tests/test_new_feature.py
   ```

4. **Запустите тесты:**
   ```bash
   make test
   ```

5. **Создайте PR:**
   ```bash
   git push origin feature/new-feature
   ```

### ❓ Как отладить приложение?

**Backend:**
```python
# Добавьте breakpoint
import pdb; pdb.set_trace()

# Или используйте logging
import logging
logging.basicConfig(level=logging.DEBUG)
```

**Frontend:**
```typescript
// Используйте console.log
console.log('Debug info:', data);

// Или React DevTools
// Установите расширение для браузера
```

### ❓ Как профилировать производительность?

**Backend:**
```python
# Используйте cProfile
python -m cProfile run_server.py

# Или line_profiler
pip install line_profiler
kernprof -l -v script.py
```

**Frontend:**
```bash
# React DevTools Profiler
# Или Chrome DevTools Performance
```

### ❓ Как добавить новый AI провайдер?

1. **Создайте провайдер:**
   ```python
   # backend/services/ai_providers/new_provider.py
   class NewProvider:
       def __init__(self, api_key: str):
           self.api_key = api_key
       
       async def generate(self, prompt: str) -> str:
           # Реализация
           pass
   ```

2. **Добавьте в AI сервис:**
   ```python
   # backend/services/ai_service.py
   from .ai_providers.new_provider import NewProvider
   ```

3. **Добавьте конфигурацию:**
   ```env
   NEW_PROVIDER_API_KEY=your-key
   ```

4. **Напишите тесты:**
   ```python
   # tests/test_new_provider.py
   def test_new_provider():
       # Тесты
       pass
   ```

## 🆘 Получение помощи

### ❓ Где получить помощь?

1. **Проверьте этот FAQ** - возможно, ответ уже есть
2. **Создайте Issue** в GitHub репозитории
3. **Discord** - присоединяйтесь к сообществу
4. **Email** - support@samokoder.com

### ❓ Как сообщить об ошибке?

При создании Issue укажите:
- **Версию** приложения (1.0.0)
- **Операционную систему**
- **Шаги воспроизведения**
- **Ожидаемое поведение**
- **Фактическое поведение**
- **Логи ошибок**

### ❓ Как предложить новую функцию?

1. **Создайте Issue** с тегом "enhancement"
2. **Опишите проблему**, которую решает функция
3. **Предложите решение**
4. **Укажите приоритет**

### ❓ Как внести вклад в проект?

1. **Форкните репозиторий**
2. **Создайте ветку** для функции
3. **Внесите изменения**
4. **Напишите тесты**
5. **Создайте Pull Request**

### ❓ Как проверить, что установка работает?

```bash
# 1. Проверьте health endpoint
curl http://localhost:8000/health

# 2. Проверьте API документацию
open http://localhost:8000/docs

# 3. Запустите автоматическую проверку
python scripts/test_reproducibility.py
```

### ❓ Что делать, если .env.example отсутствует?

Если файл `.env.example` отсутствует, создайте его вручную:

```bash
# Создайте базовый .env файл
cat > .env << 'EOF'
# Основные настройки
NODE_ENV=development
PORT=8000
DEBUG=true

# База данных
SUPABASE_URL=https://your-project.supabase.co
SUPABASE_ANON_KEY=your_anon_key_here

# Безопасность
JWT_SECRET=your-super-secret-jwt-key-here-32-chars
API_ENCRYPTION_KEY=your-32-character-secret-key-here
API_ENCRYPTION_SALT=samokoder_salt_2025
EOF
```

### ❓ Как обновить проект до последней версии?

```bash
# 1. Остановите сервисы
docker-compose down

# 2. Обновите код
git fetch origin
git pull origin main

# 3. Обновите зависимости
pip install -r requirements.txt
cd frontend && npm install

# 4. Выполните миграции
python -m alembic upgrade head

# 5. Запустите сервисы
docker-compose up -d
```

---

## 🎯 Быстрые ссылки

### 📚 Документация
- [🚀 Быстрый старт](docs/QUICKSTART.md)
- [🔧 Подробная установка](docs/INSTALL.md)
- [🚀 Развертывание](docs/DEPLOY.md)
- [🔐 Безопасность](docs/SECURITY.md)
- [📊 Мониторинг](docs/MONITORING.md)

### 🛠️ Утилиты
- [🔧 Операции](docs/OPERATIONS.md)
- [🗄️ Миграции](docs/MIGRATIONS.md)
- [🧪 Тестирование](docs/TESTING.md)

### 🔗 Внешние ресурсы
- [GitHub репозиторий](https://github.com/samokoder/samokoder)
- [Discord сообщество](https://discord.gg/samokoder)
- [Документация API](http://localhost:8000/docs)

---

**Создано с ❤️ командой Самокодер**  
**© 2025 Samokoder. Все права защищены.**