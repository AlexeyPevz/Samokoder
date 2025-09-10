# 🚀 Быстрая настройка Supabase для Самокодер

## 📋 Что нужно сделать

### 1. Выполните SQL схему в Supabase

1. **Откройте Supabase Dashboard**: https://supabase.com/dashboard/project/auhzhdndqyflfdfszapm/sql

2. **Скопируйте весь SQL код** из файла `supabase_quick_setup.sql`

3. **Вставьте в SQL Editor** и нажмите "Run"

### 2. Получите Service Role Key

1. **Перейдите в Settings → API**: https://supabase.com/dashboard/project/auhzhdndqyflfdfszapm/settings/api

2. **Скопируйте 'service_role' ключ** (НЕ anon key!)

3. **Обновите .env файл**:
   ```bash
   SUPABASE_SERVICE_ROLE_KEY=ваш_service_role_ключ_здесь
   ```

### 3. Проверьте настройку

```bash
python3 setup_supabase.py
```

### 4. Запустите сервер

```bash
python3 run_server.py
```

## 🎯 Что будет создано

- ✅ 8 таблиц для SaaS платформы
- ✅ RLS политики безопасности
- ✅ 4 AI провайдера
- ✅ 10+ AI моделей
- ✅ 5 тарифных планов

## ⚠️ Важно

- **Service Role Key** имеет полные права доступа!
- **Никогда не коммитьте** его в git!

---

**После выполнения этих шагов проект будет готов к продакшену на 100%!** 🚀