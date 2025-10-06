# ADR-AUDIT-003: Экстернализация конфигурации для отказоустойчивости

## Статус
Принято

## Контекст
Критичные для безопасности и отказоустойчивости параметры захардкожены в коде.

## Проблема

### 1. CORS Origins захардкожены
**Файл**: `backend/main.py:49-68`  
```python
allowed_origins = [
    "https://samokoder.com",  # Захардкожено!
    "https://app.samokoder.com",
    ...
]
```

### 2. CSP политики в коде
**Файл**: `backend/main.py:97-106`  
```python
response.headers["Content-Security-Policy"] = (
    "connect-src 'self' https://api.openai.com ..."  # Захардкожено!
)
```

### 3. Frontend proxy target
**Файл**: `frontend/vite.config.ts:103-104`  
```typescript
target: 'http://localhost:3000',  // Захардкожено!
```

### Последствия
- Невозможность изменения конфигурации без пересборки
- Сложность развертывания в разных окружениях
- Нарушение 12-Factor App принципов
- Риски безопасности при случайной комитации чувствительных данных

## Решение

### 1. Экстернализовать CORS
```python
# config/settings.py
class Settings(BaseSettings):
    cors_allowed_origins: str = "http://localhost:3000,http://localhost:5173"
    cors_allow_credentials: bool = True
    
    @property
    def cors_origins_list(self) -> List[str]:
        return [origin.strip() for origin in self.cors_allowed_origins.split(',')]

# backend/main.py
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_credentials=settings.cors_allow_credentials,
    ...
)
```

### 2. Экстернализовать CSP
```python
# config/settings.py
class Settings(BaseSettings):
    csp_connect_src: str = "'self' https://api.openai.com https://api.anthropic.com"
    csp_default_src: str = "'self'"
    
    @property
    def csp_policy(self) -> str:
        return f"default-src {self.csp_default_src}; connect-src {self.csp_connect_src}; ..."
```

### 3. Экстернализовать proxy config
```typescript
// vite.config.ts
export default defineConfig({
  server: {
    proxy: {
      '/api': {
        target: process.env.VITE_API_URL || 'http://localhost:3000',
        changeOrigin: true,
      }
    }
  }
})
```

### 4. Добавить в .env.example
```bash
# Security
CORS_ALLOWED_ORIGINS=http://localhost:3000,http://localhost:5173
CSP_CONNECT_SRC='self' https://api.openai.com
FRONTEND_URL=http://localhost:5173

# Frontend
VITE_API_URL=http://localhost:8000
```

## Последствия
- ✅ Конфигурация через переменные окружения
- ✅ Разные настройки для dev/staging/prod без изменения кода
- ✅ Соответствие 12-Factor App
- ✅ Улучшенная безопасность
- ⚠️ Требует документации всех переменных

## Связанные файлы
- `backend/main.py:49-68,97-106`
- `frontend/vite.config.ts:103-110`
- `config/settings.py`
- `.env.example`
