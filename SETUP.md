# 🚀 Быстрая настройка проекта

## 📋 Что нужно сделать

### 1. Выполнить SQL в Supabase

1. **Откройте Supabase Dashboard:**
   ```
   https://supabase.com/dashboard/project/auhzhdndqyflfdfszapm/sql
   ```

2. **Скопируйте SQL скрипт:**
   ```bash
   cat supabase_setup_fixed.sql
   ```

3. **Вставьте в SQL Editor и нажмите "Run"**

4. **Проверьте результат:**
   ```bash
   python3 check_supabase.py
   ```

### 2. Запустить проект

```bash
# Автоматический запуск (рекомендуется)
chmod +x start_dev.sh
./start_dev.sh

# Или вручную:
# Терминал 1: python3 run_server.py
# Терминал 2: cd frontend && npm run dev
```

### 3. Открыть приложение

- **Фронтенд:** http://localhost:5173
- **API:** http://localhost:3000

## ✅ Готово!

После выполнения этих шагов проект будет полностью готов к использованию.

## 🐛 Если что-то не работает

1. **Проверьте Supabase:**
   ```bash
   python3 check_supabase.py
   ```

2. **Проверьте логи сервера:**
   ```bash
   python3 run_server.py
   ```

3. **Проверьте фронтенд:**
   ```bash
   cd frontend
   npm run dev
   ```

## 📞 Поддержка

Если возникли проблемы, проверьте:
- [README.md](README.md) - полная документация
- [INSTALL.md](INSTALL.md) - подробная установка
- [SECURITY_FIXES.md](SECURITY_FIXES.md) - исправления безопасности