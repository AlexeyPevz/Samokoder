# ADR-002: Улучшение отказоустойчивости конфигураций

## Статус
**ПРИНЯТО** - 2025-01-11

## Контекст
Аудит конфигураций выявил проблемы с отказоустойчивостью:

### Обнаруженные проблемы:
- **config/settings.py** - отсутствуют значения по умолчанию для критических полей
- **.env** - демо ключи в продакшене (system_openai_key, system_anthropic_key, system_groq_key, system_openrouter_key)
- **requirements.txt** - нет точных версий (57 пакетов с диапазонами)
- **docker-compose.yml** - отсутствует PostgreSQL

### Риски:
1. **Невоспроизводимые развертывания** - разные версии зависимостей
2. **Отказы в продакшене** - демо ключи не работают
3. **Нарушение принципа "fail-fast"** - ошибки обнаруживаются только в runtime

## Решение
Внедрить **Configuration Resilience Pattern**:

### 1. Улучшить config/settings.py
```python
# config/settings.py (ДОБАВИТЬ)
class Settings(BaseSettings):
    # Критические поля с fallback
    database_url: str = Field(default="", description="Database URL")
    redis_url: str = Field(default="redis://localhost:6379", description="Redis URL")
    
    # Валидация конфигурации
    def __post_init__(self):
        if not self.database_url and not self.debug:
            raise ConfigurationError("Database URL required in production")
        
        if any(key.startswith('sk-demo') for key in [
            self.system_openai_key, self.system_anthropic_key
        ]) and not self.debug:
            raise ConfigurationError("Demo keys not allowed in production")
```

### 2. Создать requirements-lock.txt
```bash
# Создать файл с точными версиями
pip freeze > requirements-lock.txt
```

### 3. Добавить PostgreSQL в docker-compose.yml
```yaml
# docker-compose.yml (ДОБАВИТЬ)
services:
  postgres:
    image: postgres:15-alpine
    environment:
      POSTGRES_DB: samokoder
      POSTGRES_USER: samokoder
      POSTGRES_PASSWORD: password
    ports:
      - "5432:5432"
```

## Последствия
### Положительные:
- ✅ Воспроизводимые развертывания
- ✅ Fail-fast конфигурация
- ✅ Защита от демо ключей в продакшене
- ✅ Полная инфраструктура в docker-compose

### Отрицательные:
- ⚠️ Необходимость обновления CI/CD
- ⚠️ Дополнительная валидация

## Миграция
1. **Фаза 1**: Добавить валидацию в settings.py
2. **Фаза 2**: Создать requirements-lock.txt
3. **Фаза 3**: Обновить docker-compose.yml

**Время реализации**: 1 день
**Обратная совместимость**: 100% сохранена