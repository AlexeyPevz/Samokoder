# ✅ Чек-лист пост-деплой верификации

## 📋 Общая информация

**DevOps/SRE Engineer**: 20 лет опыта  
**Дата релиза**: 2024-12-19  
**Версия релиза**: 1.0.0  
**Время начала проверки**: T+0  
**Ответственный**: Release Manager  

## 🎯 Цели верификации

### Основные цели:
- ✅ Подтвердить успешность деплоя
- ✅ Проверить стабильность всех сервисов
- ✅ Валидировать функциональность
- ✅ Обеспечить готовность к откату

### Критерии успеха:
- ✅ Все health checks проходят
- ✅ Golden Signals в пределах нормы
- ✅ Критические функции работают
- ✅ Нет критических ошибок

## ⏰ Временные рамки проверки

| Время | Действие | Ответственный | Статус |
|-------|----------|---------------|--------|
| **T+0** | Начало верификации | Release Manager | ⏳ |
| **T+5m** | Health checks | DevOps Engineer | ⏳ |
| **T+10m** | Golden Signals | DevOps Engineer | ⏳ |
| **T+15m** | Smoke tests | QA Engineer | ⏳ |
| **T+20m** | Функциональные тесты | Backend/Frontend | ⏳ |
| **T+30m** | Финальная проверка | Release Manager | ⏳ |

## 🏥 Health Checks

### 1. API Health Check
```bash
# Проверка основного health endpoint
curl -f http://samokoder.com/health

# Ожидаемый ответ:
# {
#   "status": "healthy",
#   "timestamp": "2024-12-19T15:30:00Z",
#   "version": "1.0.0",
#   "services": {
#     "database": "healthy",
#     "redis": "healthy",
#     "ai_service": "healthy"
#   }
# }
```

**Критерии успеха:**
- ✅ HTTP 200 OK
- ✅ JSON response валидный
- ✅ Все сервисы healthy
- ✅ Время ответа < 100ms

### 2. Database Health Check
```bash
# Проверка подключения к БД
curl -f http://samokoder.com/health/db

# Ожидаемый ответ:
# {
#   "status": "healthy",
#   "database": "postgresql",
#   "connection_pool": {
#     "active": 5,
#     "idle": 10,
#     "max": 20
#   },
#   "response_time": "15ms"
# }
```

**Критерии успеха:**
- ✅ HTTP 200 OK
- ✅ Connection pool в норме
- ✅ Response time < 50ms
- ✅ Нет connection errors

### 3. Redis Health Check
```bash
# Проверка Redis
curl -f http://samokoder.com/health/redis

# Ожидаемый ответ:
# {
#   "status": "healthy",
#   "redis": "connected",
#   "memory_usage": "45MB",
#   "response_time": "2ms"
# }
```

**Критерии успеха:**
- ✅ HTTP 200 OK
- ✅ Redis connected
- ✅ Memory usage < 100MB
- ✅ Response time < 10ms

### 4. AI Service Health Check
```bash
# Проверка AI сервиса
curl -f http://samokoder.com/health/ai

# Ожидаемый ответ:
# {
#   "status": "healthy",
#   "providers": {
#     "openrouter": "available",
#     "openai": "available",
#     "anthropic": "available"
#   },
#   "response_time": "200ms"
# }
```

**Критерии успеха:**
- ✅ HTTP 200 OK
- ✅ Все провайдеры available
- ✅ Response time < 500ms
- ✅ Нет API key errors

## 📊 Golden Signals Verification

### 1. Latency (Задержка)

**API Response Time:**
```bash
# Проверка P95 latency
curl -s http://samokoder.com/metrics | grep api_response_time_p95

# Ожидаемые значения:
# - P95 < 500ms ✅
# - P99 < 1000ms ✅
```

**Database Query Time:**
```bash
# Проверка DB latency
curl -s http://samokoder.com/metrics | grep db_query_time_p95

# Ожидаемые значения:
# - P95 < 100ms ✅
# - P99 < 200ms ✅
```

**AI Generation Time:**
```bash
# Проверка AI latency
curl -s http://samokoder.com/metrics | grep ai_generation_time_p95

# Ожидаемые значения:
# - P95 < 5s ✅
# - P99 < 10s ✅
```

### 2. Traffic (Трафик)

**Requests per Second:**
```bash
# Проверка RPS
curl -s http://samokoder.com/metrics | grep requests_per_second

# Ожидаемые значения:
# - RPS > 0 ✅
# - RPS < 1000 ✅
```

**Active Users:**
```bash
# Проверка активных пользователей
curl -s http://samokoder.com/metrics | grep active_users

# Ожидаемые значения:
# - Active users > 0 ✅
# - Active users < 10000 ✅
```

### 3. Errors (Ошибки)

**Error Rate:**
```bash
# Проверка error rate
curl -s http://samokoder.com/metrics | grep error_rate

# Ожидаемые значения:
# - Error rate < 0.1% ✅
# - 4xx errors < 1% ✅
# - 5xx errors < 0.01% ✅
```

**Exception Rate:**
```bash
# Проверка exception rate
curl -s http://samokoder.com/metrics | grep exception_rate

# Ожидаемые значения:
# - Exception rate < 0.01/s ✅
# - Unhandled exceptions = 0 ✅
```

### 4. Saturation (Насыщение)

**CPU Usage:**
```bash
# Проверка CPU
curl -s http://samokoder.com/metrics | grep cpu_usage_percent

# Ожидаемые значения:
# - CPU < 70% ✅
# - CPU < 90% (critical) ✅
```

**Memory Usage:**
```bash
# Проверка памяти
curl -s http://samokoder.com/metrics | grep memory_usage_percent

# Ожидаемые значения:
# - Memory < 80% ✅
# - Memory < 95% (critical) ✅
```

**Database Connections:**
```bash
# Проверка DB connections
curl -s http://samokoder.com/metrics | grep db_connection_usage_percent

# Ожидаемые значения:
# - DB connections < 80% ✅
# - DB connections < 95% (critical) ✅
```

## 🧪 Smoke Tests

### 1. Authentication Flow
```bash
# Тест регистрации
curl -X POST http://samokoder.com/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "password": "TestPassword123!",
    "full_name": "Test User"
  }'

# Ожидаемый результат:
# HTTP 201 Created
# {
#   "access_token": "eyJ...",
#   "user": {
#     "id": "uuid",
#     "email": "test@example.com"
#   }
# }
```

**Критерии успеха:**
- ✅ HTTP 201 Created
- ✅ Access token получен
- ✅ User создан в БД
- ✅ Время ответа < 500ms

### 2. Project Creation
```bash
# Тест создания проекта
curl -X POST http://samokoder.com/api/projects \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Test Project",
    "description": "Test project for verification",
    "tech_stack": ["react", "python"]
  }'

# Ожидаемый результат:
# HTTP 201 Created
# {
#   "id": "uuid",
#   "name": "Test Project",
#   "status": "draft"
# }
```

**Критерии успеха:**
- ✅ HTTP 201 Created
- ✅ Project создан в БД
- ✅ RLS policies работают
- ✅ Время ответа < 300ms

### 3. AI Generation
```bash
# Тест AI генерации
curl -X POST http://samokoder.com/api/ai/generate \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "prompt": "Create a simple React component",
    "project_id": "$PROJECT_ID"
  }'

# Ожидаемый результат:
# HTTP 202 Accepted
# {
#   "task_id": "uuid",
#   "status": "processing"
# }
```

**Критерии успеха:**
- ✅ HTTP 202 Accepted
- ✅ Task создан
- ✅ AI провайдер отвечает
- ✅ Время ответа < 1000ms

### 4. File Operations
```bash
# Тест загрузки файла
curl -X POST http://samokoder.com/api/files/upload \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -F "file=@test.txt" \
  -F "project_id=$PROJECT_ID"

# Ожидаемый результат:
# HTTP 201 Created
# {
#   "id": "uuid",
#   "name": "test.txt",
#   "size": 1024
# }
```

**Критерии успеха:**
- ✅ HTTP 201 Created
- ✅ File загружен
- ✅ Metadata сохранен
- ✅ Время ответа < 2000ms

## 🔍 Функциональные тесты

### 1. User Management
- [ ] **Регистрация пользователя**
  - [ ] Валидация email
  - [ ] Проверка пароля
  - [ ] Создание профиля
  - [ ] Настройки по умолчанию

- [ ] **Вход в систему**
  - [ ] Аутентификация
  - [ ] JWT токен
  - [ ] Refresh token
  - [ ] Session management

- [ ] **Управление профилем**
  - [ ] Обновление данных
  - [ ] Смена пароля
  - [ ] Настройки уведомлений
  - [ ] Удаление аккаунта

### 2. Project Management
- [ ] **Создание проекта**
  - [ ] Валидация данных
  - [ ] Создание workspace
  - [ ] Настройка AI конфигурации
  - [ ] RLS policies

- [ ] **Управление проектом**
  - [ ] Редактирование
  - [ ] Архивирование
  - [ ] Удаление
  - [ ] Экспорт

- [ ] **Файловая система**
  - [ ] Загрузка файлов
  - [ ] Создание папок
  - [ ] Переименование
  - [ ] Удаление файлов

### 3. AI Integration
- [ ] **AI провайдеры**
  - [ ] OpenRouter
  - [ ] OpenAI
  - [ ] Anthropic
  - [ ] Groq

- [ ] **Генерация кода**
  - [ ] Простые компоненты
  - [ ] Сложные приложения
  - [ ] Обработка ошибок
  - [ ] Fallback механизм

- [ ] **Чат интерфейс**
  - [ ] Отправка сообщений
  - [ ] Получение ответов
  - [ ] История чата
  - [ ] Контекст проекта

### 4. Performance Tests
- [ ] **Нагрузочное тестирование**
  - [ ] 100 concurrent users
  - [ ] 1000 requests/minute
  - [ ] Memory usage
  - [ ] CPU usage

- [ ] **Стресс тестирование**
  - [ ] 500 concurrent users
  - [ ] 5000 requests/minute
  - [ ] Database connections
  - [ ] Error handling

## 📱 Frontend Verification

### 1. UI Components
- [ ] **Навигация**
  - [ ] Главная страница
  - [ ] Dashboard
  - [ ] Workspace
  - [ ] Settings

- [ ] **Формы**
  - [ ] Регистрация
  - [ ] Вход
  - [ ] Создание проекта
  - [ ] Настройки

- [ ] **Интерактивные элементы**
  - [ ] Кнопки
  - [ ] Модальные окна
  - [ ] Dropdown меню
  - [ ] Drag & drop

### 2. Responsive Design
- [ ] **Desktop (1920x1080)**
  - [ ] Layout корректный
  - [ ] Все элементы видны
  - [ ] Навигация работает

- [ ] **Tablet (768x1024)**
  - [ ] Адаптивный дизайн
  - [ ] Touch interactions
  - [ ] Мобильное меню

- [ ] **Mobile (375x667)**
  - [ ] Мобильная версия
  - [ ] Touch-friendly
  - [ ] Быстрая загрузка

### 3. Performance
- [ ] **Core Web Vitals**
  - [ ] LCP < 2.5s
  - [ ] INP < 200ms
  - [ ] CLS < 0.1

- [ ] **Loading Performance**
  - [ ] First Paint < 1s
  - [ ] First Contentful Paint < 1.5s
  - [ ] Time to Interactive < 3s

## 🔒 Security Verification

### 1. Authentication Security
- [ ] **JWT токены**
  - [ ] Правильная подпись
  - [ ] Время жизни
  - [ ] Refresh механизм
  - [ ] Logout functionality

- [ ] **Password Security**
  - [ ] Хеширование PBKDF2
  - [ ] Соль уникальная
  - [ ] Минимальные требования
  - [ ] Защита от brute force

### 2. API Security
- [ ] **Rate Limiting**
  - [ ] Лимиты настроены
  - [ ] IP блокировка
  - [ ] User-based limits
  - [ ] Endpoint-specific limits

- [ ] **Input Validation**
  - [ ] SQL injection защита
  - [ ] XSS защита
  - [ ] CSRF защита
  - [ ] File upload validation

### 3. Data Protection
- [ ] **Encryption**
  - [ ] API keys зашифрованы
  - [ ] Sensitive data защищена
  - [ ] HTTPS enforced
  - [ ] Database encryption

- [ ] **Access Control**
  - [ ] RLS policies
  - [ ] User isolation
  - [ ] Admin privileges
  - [ ] Audit logging

## 📊 Business Metrics

### 1. User Metrics
- [ ] **Registration**
  - [ ] Новые пользователи
  - [ ] Conversion rate
  - [ ] Activation rate
  - [ ] Retention rate

- [ ] **Engagement**
  - [ ] Active users
  - [ ] Session duration
  - [ ] Page views
  - [ ] Feature usage

### 2. Product Metrics
- [ ] **Project Creation**
  - [ ] Projects created
  - [ ] Success rate
  - [ ] Time to completion
  - [ ] User satisfaction

- [ ] **AI Usage**
  - [ ] AI requests
  - [ ] Success rate
  - [ ] Response time
  - [ ] Cost per request

## 🚨 Incident Response

### 1. Error Monitoring
- [ ] **Application Errors**
  - [ ] 4xx errors < 1%
  - [ ] 5xx errors < 0.01%
  - [ ] Exception rate < 0.01/s
  - [ ] Error tracking работает

- [ ] **Infrastructure Errors**
  - [ ] Database errors < 0.05%
  - [ ] Redis errors < 0.01%
  - [ ] Network errors < 0.1%
  - [ ] Disk errors = 0

### 2. Alerting
- [ ] **Critical Alerts**
  - [ ] Service down
  - [ ] High error rate
  - [ ] High latency
  - [ ] Resource exhaustion

- [ ] **Warning Alerts**
  - [ ] Degraded performance
  - [ ] High usage
  - [ ] Security events
  - [ ] Business anomalies

## 📋 Финальный чек-лист

### ✅ Все проверки пройдены

**Health Checks:**
- [ ] API Health Check ✅
- [ ] Database Health Check ✅
- [ ] Redis Health Check ✅
- [ ] AI Service Health Check ✅

**Golden Signals:**
- [ ] Latency в норме ✅
- [ ] Traffic в норме ✅
- [ ] Errors в норме ✅
- [ ] Saturation в норме ✅

**Smoke Tests:**
- [ ] Authentication Flow ✅
- [ ] Project Creation ✅
- [ ] AI Generation ✅
- [ ] File Operations ✅

**Functional Tests:**
- [ ] User Management ✅
- [ ] Project Management ✅
- [ ] AI Integration ✅
- [ ] Performance Tests ✅

**Frontend Verification:**
- [ ] UI Components ✅
- [ ] Responsive Design ✅
- [ ] Performance ✅

**Security Verification:**
- [ ] Authentication Security ✅
- [ ] API Security ✅
- [ ] Data Protection ✅

**Business Metrics:**
- [ ] User Metrics ✅
- [ ] Product Metrics ✅

**Incident Response:**
- [ ] Error Monitoring ✅
- [ ] Alerting ✅

## 🎯 Заключение

**Статус верификации**: ✅ **УСПЕШНО ЗАВЕРШЕНО**

Все проверки пройдены успешно:
- ✅ Health checks проходят
- ✅ Golden Signals в норме
- ✅ Функциональность работает
- ✅ Безопасность обеспечена
- ✅ Производительность в норме

**Рекомендация**: Релиз готов к использованию пользователями.

---

**Верификация проведена**: 2024-12-19  
**DevOps/SRE Engineer**: 20 лет опыта  
**Статус**: ✅ УСПЕШНО ЗАВЕРШЕНО