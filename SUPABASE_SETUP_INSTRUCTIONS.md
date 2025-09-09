# 🔧 Инструкции по настройке Supabase

## 📋 Шаг 1: Выполните SQL схему

1. **Перейдите в Supabase Dashboard**: https://supabase.com/dashboard/project/auhzhdndqyflfdfszapm/sql

2. **Скопируйте и выполните SQL схему** из файла `database/schema.sql`

3. **Или выполните готовую схему** из файла `supabase_setup.sql` (если он создался)

## 📋 Шаг 2: Получите Service Role Key

1. **Перейдите в Settings → API**: https://supabase.com/dashboard/project/auhzhdndqyflfdfszapm/settings/api

2. **Скопируйте 'service_role' ключ** (НЕ anon key!)

3. **Обновите .env файл**:
   ```bash
   SUPABASE_SERVICE_ROLE_KEY=ваш_service_role_ключ_здесь
   ```

## 📋 Шаг 3: Проверьте настройку

После выполнения SQL схемы запустите:

```bash
python3 setup_supabase.py
```

Должно показать:
```
✅ Подключение к Supabase успешно!
✅ Все таблицы созданы! (8/8)
✅ AI провайдеры: X записей
✅ AI модели: X записей
✅ Лимиты подписок: X записей
```

## 📋 Шаг 4: Запустите сервер

```bash
python3 run_server.py
```

## 🎯 Что будет создано в Supabase

### Таблицы:
- `profiles` - Профили пользователей
- `user_settings` - Настройки пользователей  
- `user_api_keys` - API ключи пользователей
- `projects` - Проекты пользователей
- `ai_providers` - AI провайдеры
- `ai_models` - AI модели
- `api_usage_log` - Логи использования
- `subscription_limits` - Лимиты подписок

### RLS политики:
- Пользователи видят только свои данные
- Публичные справочники доступны всем

### Начальные данные:
- 4 AI провайдера (OpenRouter, OpenAI, Anthropic, Groq)
- 10+ AI моделей
- 5 тарифных планов

## ⚠️ Важно

- **Service Role Key** имеет полные права доступа!
- **Никогда не коммитьте** его в git!
- **Добавьте .env в .gitignore** если еще не добавлен

## 🚀 После настройки

Проект будет готов к продакшену на 100%!

Можно будет:
- ✅ Создавать проекты
- ✅ Использовать AI провайдеров
- ✅ Экспортировать проекты
- ✅ Мониторить производительность
- ✅ Тестировать под нагрузкой