# Справочник переменных окружения

> Полное описание всех переменных окружения Samokoder с примерами и ссылками на код

## 📋 Содержание

- [Обязательные переменные](#обязательные-переменные)
- [База данных](#база-данных)
- [Безопасность](#безопасность)
- [LLM Providers](#llm-providers)
- [Мониторинг](#мониторинг)
- [SMTP / Email](#smtp--email)
- [OAuth / GitHub](#oauth--github)
- [Прочие настройки](#прочие-настройки)
- [Валидация](#валидация)

---

## Обязательные переменные

### SECRET_KEY

**Описание:** Секретный ключ для подписи JWT токенов  
**Требования:** Минимум 64 символа, случайная строка  
**Источник:** [`.env.example:25`](.env.example#L25)  
**Использование:** [`core/config/config.py:163`](core/config/config.py#L163)  
**Валидация:** [`core/config/validator.py`](core/config/validator.py)

**Генерация:**
```bash
python3 -c "import secrets; print(secrets.token_urlsafe(64))"
```

**Пример:**
```bash
SECRET_KEY=xQW9mZ3kL8nV2pR7tY4uI1oP6aS5dF0gH3jK9lM8bN7cV6xZ2qW5eR4tY3u
```

**⚠️ Критично:** Приложение не запустится с дефолтным значением из `.env.example`

---

### APP_SECRET_KEY

**Описание:** Секретный ключ для шифрования данных (GitHub tokens и т.д.)  
**Требования:** Минимум 64 символа, случайная строка  
**Источник:** [`.env.example:26`](.env.example#L26)  
**Использование:** [`core/config/config.py:164`](core/config/config.py#L164)  
**Валидация:** [`core/config/validator.py`](core/config/validator.py)

**Генерация:**
```bash
python3 -c "import secrets; print(secrets.token_urlsafe(64))"
```

**Пример:**
```bash
APP_SECRET_KEY=aB1cD2eF3gH4iJ5kL6mN7oP8qR9sT0uV1wX2yZ3aB4cD5eF6gH7iJ8kL9mN0
```

**⚠️ Критично:** Используется для шифрования чувствительных данных в БД

---

## База данных

### DATABASE_URL

**Описание:** URL подключения к PostgreSQL базе данных  
**Требования:** Формат `postgresql+asyncpg://user:password@host:port/db`  
**Источник:** [`.env.example:13`](.env.example#L13)  
**Использование:** [`core/config/config.py:167`](core/config/config.py#L167)

**Примеры:**
```bash
# Development (локальный PostgreSQL)
DATABASE_URL=postgresql+asyncpg://samokoder:password@localhost:5432/samokoder

# Production (Yandex Cloud)
DATABASE_URL=postgresql+asyncpg://user:password@c-abc123.rw.mdb.yandexcloud.net:6432/samokoder

# Docker Compose (используется имя сервиса)
DATABASE_URL=postgresql+asyncpg://user:password@db:5432/samokoder
```

**По умолчанию:** `sqlite+aiosqlite:///data/database/samokoder.db` (для разработки)

---

### SAMOKODER_DATABASE_URL

**Описание:** URL для Alembic миграций (обычно совпадает с DATABASE_URL)  
**Требования:** Формат `postgresql+asyncpg://...`  
**Источник:** [`alembic/env.py:59`](alembic/env.py#L59), [`alembic/env.py:82`](alembic/env.py#L82)  
**Использование:** Alembic читает эту переменную с приоритетом над `alembic.ini`

**Пример:**
```bash
SAMOKODER_DATABASE_URL=postgresql+asyncpg://user:password@localhost:5432/samokoder
```

**Примечание:** Должна совпадать с `DATABASE_URL` в большинстве случаев

---

### REDIS_HOST

**Описание:** Hostname Redis сервера  
**Источник:** [`.env.example:14`](.env.example#L14)  
**Использование:** [`core/config/config.py:165`](core/config/config.py#L165)

**Примеры:**
```bash
# Development
REDIS_HOST=localhost

# Docker Compose
REDIS_HOST=redis

# Production
REDIS_HOST=c-abc123.rw.mdb.yandexcloud.net
```

**По умолчанию:** `localhost`

---

### REDIS_PORT

**Описание:** Порт Redis сервера  
**Источник:** [`.env.example:15`](.env.example#L15)

**По умолчанию:** `6379`

---

## Безопасность

### ALGORITHM

**Описание:** Алгоритм подписи JWT токенов  
**Источник:** [`.env.example:31`](.env.example#L31)

**Значения:** `HS256` (рекомендуется), `HS384`, `HS512`

**По умолчанию:** `HS256`

---

### ACCESS_TOKEN_EXPIRE_MINUTES

**Описание:** Время жизни JWT access токена (в минутах)  
**Источник:** [`.env.example:32`](.env.example#L32)

**По умолчанию:** `30` минут

**Примеры:**
```bash
ACCESS_TOKEN_EXPIRE_MINUTES=30   # 30 минут (production)
ACCESS_TOKEN_EXPIRE_MINUTES=1440 # 24 часа (development)
```

---

## LLM Providers

### OPENROUTER_API_KEY

**Описание:** API ключ для OpenRouter (доступ к различным LLM моделям)  
**Требования:** Необязателен, можно настроить через UI  
**Источник:** [`.env.example:54`](.env.example#L54)  
**Использование:** [`core/config/config.py:181`](core/config/config.py#L181)

**Пример:**
```bash
OPENROUTER_API_KEY=sk-or-v1-abc123xyz789...
```

---

### OPENROUTER_ENDPOINT

**Описание:** Endpoint для OpenRouter API  
**Источник:** [`.env.example:55`](.env.example#L55)  
**Использование:** [`core/config/config.py:182`](core/config/config.py#L182)

**По умолчанию:** `https://openrouter.ai/api/v1/chat/completions`

---

## Мониторинг

### GRAFANA_ADMIN_USER

**Описание:** Имя администратора Grafana  
**Источник:** [`.env.example:59`](.env.example#L59)  
**Использование:** [`docker-compose.yml:143`](docker-compose.yml#L143)

**По умолчанию:** `admin`

---

### GRAFANA_ADMIN_PASSWORD

**Описание:** Пароль администратора Grafana  
**Источник:** [`.env.example:60`](.env.example#L60)  
**Использование:** [`docker-compose.yml:143`](docker-compose.yml#L143)

**⚠️ Важно:** Изменить в production!

**По умолчанию:** `admin`

**Пример:**
```bash
GRAFANA_ADMIN_PASSWORD=MySecurePassword123!
```

---

### TELEGRAM_BOT_TOKEN

**Описание:** Токен Telegram бота для отправки алертов  
**Требования:** Получить от [@BotFather](https://t.me/BotFather)  
**Источник:** [`.env.example:63`](.env.example#L63)  
**Использование:** [`docker-compose.yml:163`](docker-compose.yml#L163), [`monitoring/alertmanager/`](monitoring/alertmanager/)

**Получение токена:**
1. Напишите [@BotFather](https://t.me/BotFather) в Telegram
2. Отправьте `/newbot`
3. Следуйте инструкциям
4. Скопируйте токен

**Пример:**
```bash
TELEGRAM_BOT_TOKEN=1234567890:ABCdefGHIjklMNOpqrsTUVwxyz
```

---

### TELEGRAM_CHAT_ID

**Описание:** ID чата/группы для отправки алертов  
**Требования:** ID чата, куда бот будет отправлять сообщения  
**Источник:** [`.env.example:64`](.env.example#L64)  
**Использование:** [`docker-compose.yml:164`](docker-compose.yml#L164)

**Получение chat ID:**
```bash
# 1. Добавьте бота в чат
# 2. Отправьте сообщение в чат
# 3. Получите chat_id:
curl https://api.telegram.org/bot<YOUR_BOT_TOKEN>/getUpdates
```

**Примеры:**
```bash
TELEGRAM_CHAT_ID=-1001234567890  # Группа
TELEGRAM_CHAT_ID=123456789       # Личный чат
```

---

### ALERT_EMAIL

**Описание:** Email для отправки алертов (опционально)  
**Источник:** [`.env.example:67`](.env.example#L67)  
**Использование:** [`docker-compose.yml:165`](docker-compose.yml#L165)

**Пример:**
```bash
ALERT_EMAIL=ops@samokoder.com
```

---

## SMTP / Email

### SMTP_HOST

**Описание:** SMTP сервер для отправки email  
**Источник:** [`.env.example:68`](.env.example#L68)  
**Использование:** [`core/config/config.py:171`](core/config/config.py#L171)

**Примеры:**
```bash
SMTP_HOST=smtp.gmail.com
SMTP_HOST=smtp.yandex.ru
SMTP_HOST=smtp.mailgun.org
```

---

### SMTP_PORT

**Описание:** Порт SMTP сервера  
**Источник:** [`.env.example:69`](.env.example#L69)  
**Использование:** [`core/config/config.py:172`](core/config/config.py#L172)

**Стандартные порты:**
- `587` - STARTTLS (рекомендуется)
- `465` - SSL/TLS
- `25` - Plain (не рекомендуется)

**По умолчанию:** `587`

---

### SMTP_USER

**Описание:** Username для SMTP авторизации  
**Источник:** [`.env.example:70`](.env.example#L70)  
**Использование:** [`core/config/config.py:173`](core/config/config.py#L173)

**Пример:**
```bash
SMTP_USER=noreply@samokoder.com
```

---

### SMTP_PASS

**Описание:** Пароль для SMTP авторизации  
**Источник:** [`.env.example:71`](.env.example#L71)  
**Использование:** [`core/config/config.py:174`](core/config/config.py#L174)

**⚠️ Важно:** Для Gmail используйте App Password, не основной пароль

---

## OAuth / GitHub

### GITHUB_CLIENT_ID

**Описание:** Client ID для GitHub OAuth приложения  
**Использование:** [`core/config/config.py:178`](core/config/config.py#L178)

**Получение:**
1. GitHub → Settings → Developer settings → OAuth Apps
2. New OAuth App
3. Скопировать Client ID

---

### GITHUB_CLIENT_SECRET

**Описание:** Client Secret для GitHub OAuth  
**Использование:** [`core/config/config.py:179`](core/config/config.py#L179)

**⚠️ Важно:** Храните в секрете!

---

## Прочие настройки

### ENVIRONMENT

**Описание:** Режим работы приложения  
**Источник:** [`.env.example:43`](.env.example#L43)  
**Использование:** [`core/config/config.py:168`](core/config/config.py#L168)

**Значения:**
- `development` - режим разработки (подробные логи, hot reload)
- `staging` - промежуточная среда (тестирование перед продакшеном)
- `production` - production (минимальные логи, оптимизации)

**По умолчанию:** `development`

---

### FRONTEND_URL

**Описание:** URL frontend приложения для CORS  
**Источник:** [`.env.example:37`](.env.example#L37)

**Примеры:**
```bash
# Development
FRONTEND_URL=http://localhost:3000

# Production
FRONTEND_URL=https://samokoder.com
```

---

### COMPOSE_PROJECT_NAME

**Описание:** Префикс для Docker Compose контейнеров и volumes  
**Источник:** [`.env.example:48`](.env.example#L48)

**По умолчанию:** `samokoder`

**Влияние:**
- Контейнеры: `samokoder-api`, `samokoder-db`, и т.д.
- Volumes: `samokoder_postgres_data`, и т.д.

---

### VERCEL_TOKEN

**Описание:** Токен для Vercel API (деплой frontend)  
**Использование:** [`core/config/config.py:166`](core/config/config.py#L166)

**Опционально:** Используется только для автоматического деплоя

---

## Валидация

### Автоматическая валидация при запуске

Приложение автоматически проверяет критичные переменные при старте:

**Источник:** [`core/config/validator.py`](core/config/validator.py)

**Проверки:**
- ✅ `SECRET_KEY` и `APP_SECRET_KEY` не являются дефолтными значениями
- ✅ Ключи имеют достаточную длину (64+ символов)
- ✅ `DATABASE_URL` корректного формата
- ✅ `REDIS_HOST` доступен

**При ошибке валидации:**
```
❌ Configuration validation failed:
  - SECRET_KEY is using default/weak value. Generate secure key!
  - APP_SECRET_KEY is using default/weak value. Generate secure key!

Generate secure keys:
  python3 -c "import secrets; print('SECRET_KEY=' + secrets.token_urlsafe(64))"
  python3 -c "import secrets; print('APP_SECRET_KEY=' + secrets.token_urlsafe(64))"
```

---

## Примеры конфигураций

### Development (локальный)

```bash
# .env (development)
SECRET_KEY=<generated>
APP_SECRET_KEY=<generated>
DATABASE_URL=postgresql+asyncpg://samokoder:password@localhost:5432/samokoder
SAMOKODER_DATABASE_URL=postgresql+asyncpg://samokoder:password@localhost:5432/samokoder
REDIS_HOST=localhost
REDIS_PORT=6379
ENVIRONMENT=development
FRONTEND_URL=http://localhost:5173
```

### Docker Compose (локальный)

```bash
# .env (docker-compose)
SECRET_KEY=<generated>
APP_SECRET_KEY=<generated>
POSTGRES_USER=user
POSTGRES_PASSWORD=password
POSTGRES_DB=samokoder
REDIS_HOST=redis
REDIS_PORT=6379
ENVIRONMENT=development
GRAFANA_ADMIN_PASSWORD=admin
```

### Production (Yandex Cloud)

```bash
# .env (production)
SECRET_KEY=<generated-strong>
APP_SECRET_KEY=<generated-strong>
DATABASE_URL=postgresql+asyncpg://user:password@c-abc.rw.mdb.yandexcloud.net:6432/samokoder
SAMOKODER_DATABASE_URL=postgresql+asyncpg://user:password@c-abc.rw.mdb.yandexcloud.net:6432/samokoder
REDIS_HOST=c-redis.rw.mdb.yandexcloud.net
REDIS_PORT=6379
ENVIRONMENT=production
FRONTEND_URL=https://samokoder.com
GRAFANA_ADMIN_PASSWORD=<strong-password>
TELEGRAM_BOT_TOKEN=<bot-token>
TELEGRAM_CHAT_ID=<chat-id>
```

---

## Дополнительные ресурсы

- **Пример:** [`.env.example`](.env.example)
- **Конфигурация:** [`core/config/config.py`](core/config/config.py)
- **Валидация:** [`core/config/validator.py`](core/config/validator.py)
- **Docker Compose:** [`docker-compose.yml`](docker-compose.yml)
- **Alembic:** [`alembic/env.py`](alembic/env.py)
- **Quick Start:** [`QUICK_START.md`](QUICK_START.md)
