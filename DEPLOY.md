# 🚀 Деплой Самокодер в Production

## 🎯 Готовность к деплою

### ✅ Что готово
- **Backend API** - FastAPI с полным функционалом
- **База данных** - Supabase схема с RLS
- **Аутентификация** - JWT токены
- **BYOK система** - шифрование API ключей
- **Документация** - полная и подробная

### 🔄 Что требует настройки
- **Environment variables** - production конфигурация
- **SSL сертификаты** - HTTPS
- **Domain настройки** - CORS и redirects
- **Мониторинг** - логи и метрики

## 🌐 Варианты деплоя

### 1. Railway (Рекомендуется)

**Преимущества:**
- Автоматический деплой из Git
- Встроенная поддержка PostgreSQL
- SSL сертификаты из коробки
- Простая настройка переменных окружения

**Шаги:**

1. **Подключаем репозиторий**
```bash
# Устанавливаем Railway CLI
npm install -g @railway/cli

# Логинимся
railway login

# Создаем проект
railway init
```

2. **Настраиваем переменные**
```bash
# Добавляем переменные окружения
railway variables set SUPABASE_URL=https://your-project.supabase.co
railway variables set SUPABASE_ANON_KEY=your_anon_key
railway variables set API_ENCRYPTION_KEY=your_encryption_key
railway variables set API_ENCRYPTION_SALT=your_salt
railway variables set ENVIRONMENT=production
railway variables set DEBUG=false
```

3. **Деплоим**
```bash
# Деплой автоматически при push в main
git push origin main
```

### 2. DigitalOcean App Platform

**Преимущества:**
- Автоматическое масштабирование
- Встроенный мониторинг
- Простая интеграция с GitHub

**Шаги:**

1. **Создаем App Spec**
```yaml
# .do/app.yaml
name: samokoder-backend
services:
- name: api
  source_dir: /
  github:
    repo: your-username/samokoder
    branch: main
  run_command: python run_server.py
  environment_slug: python
  instance_count: 1
  instance_size_slug: basic-xxs
  envs:
  - key: SUPABASE_URL
    value: https://your-project.supabase.co
  - key: SUPABASE_ANON_KEY
    value: your_anon_key
  - key: API_ENCRYPTION_KEY
    value: your_encryption_key
  - key: ENVIRONMENT
    value: production
```

2. **Деплоим через CLI**
```bash
# Устанавливаем doctl
doctl apps create --spec .do/app.yaml
```

### 3. AWS EC2 + Docker

**Преимущества:**
- Полный контроль над инфраструктурой
- Возможность кастомизации
- Интеграция с AWS сервисами

**Шаги:**

1. **Создаем Dockerfile**
```dockerfile
FROM python:3.9-slim

WORKDIR /app

# Устанавливаем зависимости
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Копируем код
COPY . .

# Создаем пользователя
RUN useradd --create-home --shell /bin/bash app
RUN chown -R app:app /app
USER app

# Экспонируем порт
EXPOSE 8000

# Запускаем приложение
CMD ["python", "run_server.py"]
```

2. **Создаем docker-compose.yml**
```yaml
version: '3.8'

services:
  api:
    build: .
    ports:
      - "8000:8000"
    environment:
      - SUPABASE_URL=${SUPABASE_URL}
      - SUPABASE_ANON_KEY=${SUPABASE_ANON_KEY}
      - API_ENCRYPTION_KEY=${API_ENCRYPTION_KEY}
      - ENVIRONMENT=production
    restart: unless-stopped
```

3. **Деплоим на EC2**
```bash
# Подключаемся к серверу
ssh -i your-key.pem ubuntu@your-ec2-ip

# Клонируем репозиторий
git clone https://github.com/your-username/samokoder.git
cd samokoder

# Запускаем через Docker
docker-compose up -d
```

## 🔧 Production настройки

### Environment Variables

```env
# Supabase
SUPABASE_URL=https://your-project.supabase.co
SUPABASE_ANON_KEY=your_anon_key_here
SUPABASE_SERVICE_ROLE_KEY=your_service_role_key_here

# Security
API_ENCRYPTION_KEY=your_32_character_production_key
API_ENCRYPTION_SALT=your_16_character_production_salt

# Server
HOST=0.0.0.0
PORT=8000
ENVIRONMENT=production
DEBUG=false

# CORS (замените на ваш домен)
CORS_ORIGINS=https://yourdomain.com,https://www.yourdomain.com

# Logging
LOG_LEVEL=INFO
SENTRY_DSN=your_sentry_dsn_here

# Rate Limiting
RATE_LIMIT_PER_MINUTE=100
RATE_LIMIT_PER_HOUR=1000
```

### Supabase Production настройки

1. **Настраиваем домен**
```
Authentication → Settings → Site URL: https://yourdomain.com
Authentication → Settings → Redirect URLs: https://yourdomain.com/auth/callback
```

2. **Настраиваем RLS**
```sql
-- Проверяем, что все политики активны
SELECT schemaname, tablename, policyname, permissive, roles, cmd, qual
FROM pg_policies
WHERE schemaname = 'public';
```

3. **Настраиваем мониторинг**
```sql
-- Создаем представление для мониторинга
CREATE VIEW production_metrics AS
SELECT 
    COUNT(DISTINCT user_id) as active_users,
    COUNT(*) as total_projects,
    SUM(file_count) as total_files,
    AVG(generation_time_seconds) as avg_generation_time
FROM projects
WHERE created_at >= NOW() - INTERVAL '24 hours';
```

## 📊 Мониторинг и логирование

### Sentry интеграция

```python
# Добавляем в backend/main.py
import sentry_sdk
from sentry_sdk.integrations.fastapi import FastApiIntegration

sentry_sdk.init(
    dsn=settings.sentry_dsn,
    integrations=[FastApiIntegration()],
    traces_sample_rate=0.1,
    environment=settings.environment
)
```

### Логирование

```python
# Добавляем структурированное логирование
import structlog
import logging

structlog.configure(
    processors=[
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.UnicodeDecoder(),
        structlog.processors.JSONRenderer()
    ],
    context_class=dict,
    logger_factory=structlog.stdlib.LoggerFactory(),
    wrapper_class=structlog.stdlib.BoundLogger,
    cache_logger_on_first_use=True,
)
```

### Health Checks

```python
# Добавляем детальные health checks
@app.get("/health/detailed")
async def detailed_health_check():
    checks = {
        "database": await check_database_connection(),
        "supabase": await check_supabase_connection(),
        "gpt_pilot": await check_gpt_pilot_availability(),
        "storage": await check_storage_access()
    }
    
    overall_status = "healthy" if all(checks.values()) else "unhealthy"
    
    return {
        "status": overall_status,
        "timestamp": datetime.now().isoformat(),
        "checks": checks,
        "version": "1.0.0"
    }
```

## 🔐 Безопасность

### SSL сертификаты

```bash
# Используем Let's Encrypt
sudo apt install certbot
sudo certbot --nginx -d yourdomain.com
```

### Firewall настройки

```bash
# Настраиваем UFW
sudo ufw allow 22
sudo ufw allow 80
sudo ufw allow 443
sudo ufw enable
```

### Rate Limiting

```python
# Добавляем в backend/main.py
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

@app.post("/api/projects")
@limiter.limit("10/minute")
async def create_project(request: Request, ...):
    # Ваш код
```

## 📈 Масштабирование

### Горизонтальное масштабирование

```yaml
# docker-compose.prod.yml
version: '3.8'

services:
  api:
    build: .
    ports:
      - "8000:8000"
    environment:
      - SUPABASE_URL=${SUPABASE_URL}
      - SUPABASE_ANON_KEY=${SUPABASE_ANON_KEY}
    deploy:
      replicas: 3
      resources:
        limits:
          memory: 512M
        reservations:
          memory: 256M

  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf
      - ./ssl:/etc/ssl
    depends_on:
      - api
```

### Nginx конфигурация

```nginx
# nginx.conf
upstream api {
    server api:8000;
}

server {
    listen 80;
    server_name yourdomain.com;
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl;
    server_name yourdomain.com;

    ssl_certificate /etc/ssl/cert.pem;
    ssl_certificate_key /etc/ssl/key.pem;

    location / {
        proxy_pass http://api;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

## 🚀 Автоматический деплой

### GitHub Actions

```yaml
# .github/workflows/deploy.yml
name: Deploy to Production

on:
  push:
    branches: [main]

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Deploy to Railway
        uses: railway-app/railway-deploy@v1
        with:
          railway-token: ${{ secrets.RAILWAY_TOKEN }}
          service: samokoder-backend
```

### CI/CD Pipeline

```bash
# Скрипт для автоматического деплоя
#!/bin/bash

echo "🚀 Starting deployment..."

# Тестируем код
echo "🧪 Running tests..."
python -m pytest tests/

# Проверяем линтеры
echo "🔍 Running linters..."
black --check .
flake8 .

# Деплоим
echo "📦 Deploying to production..."
railway up

echo "✅ Deployment complete!"
```

## 🎉 Готово!

После настройки production окружения:

1. **Проверяем работу**: https://yourdomain.com/health
2. **Тестируем API**: https://yourdomain.com/docs
3. **Мониторим логи**: через Sentry и структурированные логи
4. **Настраиваем алерты**: на критические ошибки

**🎯 Ваш Самокодер готов к production!**

Теперь можете:
- 🚀 **Принимать пользователей**
- 📊 **Мониторить метрики**
- 🔧 **Масштабировать по потребности**
- 💰 **Монетизировать платформу**