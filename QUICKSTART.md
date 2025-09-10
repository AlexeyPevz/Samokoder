# ⚡ Быстрый старт Самокодер

> **5 минут до первого AI-приложения!**

## 🚀 Супер-быстрый старт

### 1. Клонируем и настраиваем

```bash
# Клонируем репозиторий
git clone https://github.com/your-username/samokoder.git
cd samokoder

# Создаем виртуальное окружение
python -m venv venv
source venv/bin/activate  # Linux/Mac
# venv\Scripts\activate   # Windows

# Устанавливаем зависимости
pip install -r requirements.txt
```

### 2. Настраиваем Supabase (2 минуты)

1. **Создаем проект**: [supabase.com](https://supabase.com) → New Project
2. **Копируем ключи**: Settings → API → Project URL + anon key
3. **Настраиваем БД**: SQL Editor → выполнить `database/schema.sql` + `database/init_data.sql`

### 3. Настраиваем переменные

```bash
# Копируем конфиг
cp .env.example .env

# Генерируем ключи шифрования
python -c "
import secrets, string
key = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(32))
salt = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(16))
print(f'API_ENCRYPTION_KEY={key}')
print(f'API_ENCRYPTION_SALT={salt}')
"
```

> **💡 Совет**: В `.env.example` уже настроены все необходимые переменные. Просто замените `your-*` значения на реальные.

Добавляем в `.env`:
```env
SUPABASE_URL=https://your-project.supabase.co
SUPABASE_ANON_KEY=your_anon_key_here
API_ENCRYPTION_KEY=your_generated_key_here
API_ENCRYPTION_SALT=your_generated_salt_here
```

### 4. Запускаем сервер

```bash
python run_server.py
```

🎉 **Готово!** Открываем http://localhost:8000/docs

## 🧪 Тестируем API

### Создаем тестовый проект

```bash
curl -X POST "http://localhost:8000/api/projects" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Мое первое AI-приложение",
    "description": "Простое веб-приложение для управления задачами"
  }'
```

### Запускаем генерацию

```bash
curl -X POST "http://localhost:8000/api/projects/{PROJECT_ID}/generate"
```

### Смотрим файлы

```bash
curl "http://localhost:8000/api/projects/{PROJECT_ID}/files"
```

### Экспортируем проект

```bash
curl -X POST "http://localhost:8000/api/projects/{PROJECT_ID}/export" \
  --output my_app.zip
```

## 🔑 Добавляем свои API ключи

### Через API (рекомендуется)

```bash
# Добавляем OpenRouter ключ
curl -X POST "http://localhost:8000/api/user/api-keys" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -d '{
    "provider_id": "openrouter-uuid",
    "key_name": "Мой OpenRouter ключ",
    "api_key": "sk-or-your-key-here"
  }'
```

### Через Supabase Dashboard

1. Открываем **Table Editor** → `user_api_keys`
2. Добавляем запись с зашифрованным ключом
3. Используем функцию шифрования из кода

## 🎯 Что дальше?

### Интеграция с фронтендом

```javascript
// Пример использования API
const response = await fetch('/api/projects', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'Authorization': `Bearer ${userToken}`
  },
  body: JSON.stringify({
    name: 'Мое приложение',
    description: 'Описание приложения'
  })
});

const project = await response.json();
console.log('Создан проект:', project.project_id);
```

### WebSocket для live обновлений

```javascript
// Подключение к live обновлениям генерации
const ws = new WebSocket(`ws://localhost:8000/api/projects/${projectId}/stream`);

ws.onmessage = (event) => {
  const data = JSON.parse(event.data);
  console.log('Обновление:', data);
  
  if (data.type === 'generation_complete') {
    console.log('🎉 Генерация завершена!');
  }
};
```

### Настройка CI/CD

```yaml
# .github/workflows/deploy.yml
name: Deploy Samokoder
on:
  push:
    branches: [main]

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Setup Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.9'
      - name: Install dependencies
        run: pip install -r requirements.txt
      - name: Deploy
        run: python run_server.py
```

## 🐛 Устранение неполадок

### Сервер не запускается

```bash
# Проверяем порт
lsof -i :8000

# Меняем порт в .env
echo "PORT=8001" >> .env
```

### Ошибка Supabase

```bash
# Проверяем подключение
curl -H "apikey: YOUR_ANON_KEY" \
     -H "Authorization: Bearer YOUR_ANON_KEY" \
     "YOUR_SUPABASE_URL/rest/v1/"
```

### GPT-Pilot не работает

```bash
# Проверяем структуру
ls -la samokoder-core/core/

# Переустанавливаем зависимости
pip install -r samokoder-core/requirements.txt
```

## 📚 Полезные ссылки

- 📖 **Полная документация**: [README.md](README.md)
- 🔧 **Подробная установка**: [INSTALL.md](INSTALL.md)
- 🎯 **API документация**: http://localhost:8000/docs
- 💬 **Поддержка**: [Discord](https://discord.gg/samokoder)

## ✅ Проверка воспроизводимости

### 🧪 Тест "с нуля до запуска"

Для проверки, что установка работает корректно:

```bash
# 1. Проверяем, что сервер запустился
curl http://localhost:8000/health

# Ожидаемый ответ:
# {
#   "status": "healthy",
#   "timestamp": "2025-01-XX...",
#   "version": "1.0.0"
# }

# 2. Проверяем API документацию
open http://localhost:8000/docs

# 3. Проверяем метрики
curl http://localhost:8000/metrics
```

### 🔧 Автоматическая проверка

```bash
# Запустите скрипт проверки
python scripts/test_reproducibility.py

# Или используйте Makefile
make health
```

## 🎉 Поздравляем!

Вы успешно запустили Самокодер! Теперь можете:

1. 🚀 **Создавать AI-приложения** за 15 минут
2. 🔑 **Использовать свои API ключи** (BYOK)
3. 📦 **Экспортировать проекты** в ZIP
4. 🔄 **Интегрировать с фронтендом**
5. 📈 **Масштабировать на тысячи пользователей**

**Удачи в создании AI-приложений! 🚀**