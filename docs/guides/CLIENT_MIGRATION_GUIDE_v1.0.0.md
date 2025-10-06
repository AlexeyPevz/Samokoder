# 📘 Client Migration Guide: v0.1.0 → v1.0.0

**Дата:** 2025-10-06  
**Целевая аудитория:** Разработчики клиентских приложений (Web, Mobile, Third-party)  
**Время на миграцию:** ~2-4 часа

---

## 🎯 Обзор изменений

Версия 1.0.0 вносит **критические изменения** в аутентификацию и безопасность API, которые требуют обновления всех клиентских приложений.

### ⚠️ КРИТИЧЕСКИЕ BREAKING CHANGES

1. **httpOnly Cookies для JWT токенов** (вместо Authorization header)
2. **Новая структура JWT токена** (добавлено поле `jti`)
3. **Усиленные требования к паролям**
4. **Rate limiting на критических endpoints**

---

## 🔐 1. Authentication Flow Changes

### ❌ СТАРЫЙ способ (v0.1.0)

```typescript
// Login
const response = await axios.post('/auth/login', {
  username: 'user@example.com',
  password: 'password123'
});

// Сохранить токен
const token = response.data.access_token;
localStorage.setItem('token', token);

// Использовать в последующих запросах
axios.defaults.headers.common['Authorization'] = `Bearer ${token}`;

// Refresh токена
const refreshResponse = await axios.post('/auth/refresh', {
  refresh_token: localStorage.getItem('refresh_token')
});
```

### ✅ НОВЫЙ способ (v1.0.0)

```typescript
// Login - токены автоматически сохраняются в httpOnly cookies
const response = await axios.post('/auth/login', {
  username: 'user@example.com',
  password: 'password123'
}, {
  withCredentials: true  // ⚠️ ОБЯЗАТЕЛЬНО для cookies
});

// НЕ нужно сохранять токен - он в httpOnly cookie
// НЕ нужно устанавливать Authorization header

// Использовать в последующих запросах
const protectedResponse = await axios.get('/v1/projects', {
  withCredentials: true  // ⚠️ ОБЯЗАТЕЛЬНО для каждого запроса
});

// Refresh токена - автоматически использует cookie
const refreshResponse = await axios.post('/auth/refresh', {}, {
  withCredentials: true
});
```

---

## 🌐 2. CORS Configuration

### Web Applications

Для работы с httpOnly cookies необходимо правильно настроить CORS:

**Frontend (Web App):**

```typescript
// axios instance configuration
import axios from 'axios';

const api = axios.create({
  baseURL: 'https://api.samokoder.com',
  withCredentials: true,  // ⚠️ ОБЯЗАТЕЛЬНО
  headers: {
    'Content-Type': 'application/json',
  }
});

export default api;
```

**Backend CORS (для reference):**

```python
# Server должен разрешить credentials
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://app.samokoder.com"],  # Конкретный origin
    allow_credentials=True,  # ⚠️ ОБЯЗАТЕЛЬНО
    allow_methods=["*"],
    allow_headers=["*"],
)
```

⚠️ **ВАЖНО:** `allow_credentials=True` НЕ совместим с `allow_origins=["*"]`

---

## 📱 3. Mobile Applications (iOS/Android)

### React Native

```typescript
import axios from 'axios';

// Настройка axios для работы с cookies
const api = axios.create({
  baseURL: 'https://api.samokoder.com',
  withCredentials: true,
});

// Login
const login = async (username: string, password: string) => {
  try {
    const response = await api.post('/auth/login', {
      username,
      password
    });
    // Cookies автоматически сохранены
    return response.data;
  } catch (error) {
    console.error('Login failed', error);
    throw error;
  }
};

// Использование защищённых endpoints
const getProjects = async () => {
  return await api.get('/v1/projects');
  // Cookie автоматически отправлен
};
```

### Flutter

```dart
import 'package:dio/dio.dart';
import 'package:cookie_jar/cookie_jar.dart';
import 'package:dio_cookie_manager/dio_cookie_manager.dart';

class ApiClient {
  late Dio _dio;
  late CookieJar _cookieJar;

  ApiClient() {
    _cookieJar = CookieJar();
    _dio = Dio(BaseOptions(
      baseUrl: 'https://api.samokoder.com',
    ));
    _dio.interceptors.add(CookieManager(_cookieJar));
  }

  Future<Response> login(String username, String password) async {
    return await _dio.post('/auth/login', data: {
      'username': username,
      'password': password,
    });
    // Cookies автоматически сохранены в CookieJar
  }

  Future<Response> getProjects() async {
    return await _dio.get('/v1/projects');
    // Cookies автоматически отправлены
  }
}
```

### iOS (Swift)

```swift
import Foundation

class APIClient {
    let baseURL = URL(string: "https://api.samokoder.com")!
    let session: URLSession
    
    init() {
        let config = URLSessionConfiguration.default
        config.httpCookieAcceptPolicy = .always
        config.httpShouldSetCookies = true
        self.session = URLSession(configuration: config)
    }
    
    func login(username: String, password: String) async throws -> LoginResponse {
        let url = baseURL.appendingPathComponent("/auth/login")
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        
        let body = ["username": username, "password": password]
        request.httpBody = try JSONEncoder().encode(body)
        
        let (data, response) = try await session.data(for: request)
        // Cookies автоматически сохранены
        
        return try JSONDecoder().decode(LoginResponse.self, from: data)
    }
    
    func getProjects() async throws -> [Project] {
        let url = baseURL.appendingPathComponent("/v1/projects")
        var request = URLRequest(url: url)
        // Cookies автоматически отправлены
        
        let (data, _) = try await session.data(for: request)
        return try JSONDecoder().decode([Project].self, from: data)
    }
}
```

### Android (Kotlin)

```kotlin
import okhttp3.OkHttpClient
import okhttp3.JavaNetCookieJar
import java.net.CookieManager
import java.net.CookiePolicy

class ApiClient {
    private val cookieManager = CookieManager().apply {
        setCookiePolicy(CookiePolicy.ACCEPT_ALL)
    }
    
    private val client = OkHttpClient.Builder()
        .cookieJar(JavaNetCookieJar(cookieManager))
        .build()
    
    suspend fun login(username: String, password: String): LoginResponse {
        val request = Request.Builder()
            .url("https://api.samokoder.com/auth/login")
            .post(
                JSONObject().apply {
                    put("username", username)
                    put("password", password)
                }.toString().toRequestBody("application/json".toMediaType())
            )
            .build()
        
        return client.newCall(request).execute().use { response ->
            // Cookies автоматически сохранены
            Json.decodeFromString(response.body!!.string())
        }
    }
    
    suspend fun getProjects(): List<Project> {
        val request = Request.Builder()
            .url("https://api.samokoder.com/v1/projects")
            .get()
            .build()
        
        return client.newCall(request).execute().use { response ->
            // Cookies автоматически отправлены
            Json.decodeFromString(response.body!!.string())
        }
    }
}
```

---

## 🔑 4. Password Policy Changes

### Новые требования к паролям (с v1.0.0)

- ✅ Минимум **8 символов**
- ✅ Хотя бы **1 заглавная буква** (A-Z)
- ✅ Хотя бы **1 цифра** (0-9)
- ✅ Хотя бы **1 специальный символ** (!@#$%^&*()_+-=[]{}|;:,.<>?)

### Client-side валидация

```typescript
function validatePassword(password: string): {valid: boolean, errors: string[]} {
  const errors: string[] = [];
  
  if (password.length < 8) {
    errors.push('Password must be at least 8 characters long');
  }
  
  if (!/[A-Z]/.test(password)) {
    errors.push('Password must contain at least one uppercase letter');
  }
  
  if (!/[0-9]/.test(password)) {
    errors.push('Password must contain at least one digit');
  }
  
  if (!/[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]/.test(password)) {
    errors.push('Password must contain at least one special character');
  }
  
  return {
    valid: errors.length === 0,
    errors
  };
}

// Использование
const {valid, errors} = validatePassword('mypassword');
if (!valid) {
  console.error('Invalid password:', errors);
}
```

### React Hook Form пример

```typescript
import { useForm } from 'react-hook-form';

interface RegistrationForm {
  username: string;
  password: string;
}

export function RegistrationForm() {
  const { register, handleSubmit, formState: { errors } } = useForm<RegistrationForm>();
  
  const onSubmit = async (data: RegistrationForm) => {
    // Submit to API
  };
  
  return (
    <form onSubmit={handleSubmit(onSubmit)}>
      <input
        {...register('password', {
          required: 'Password is required',
          minLength: {
            value: 8,
            message: 'Password must be at least 8 characters'
          },
          validate: {
            hasUppercase: (value) => 
              /[A-Z]/.test(value) || 'Must contain uppercase letter',
            hasDigit: (value) => 
              /[0-9]/.test(value) || 'Must contain digit',
            hasSpecial: (value) => 
              /[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]/.test(value) || 'Must contain special character'
          }
        })}
        type="password"
      />
      {errors.password && <span>{errors.password.message}</span>}
    </form>
  );
}
```

---

## 🚦 5. Rate Limiting

Следующие endpoints теперь имеют rate limiting:

| Endpoint | Limit | Window |
|----------|-------|--------|
| `POST /auth/login` | 5 requests | per minute |
| `POST /auth/register` | 3 requests | per hour |
| `POST /auth/refresh` | 10 requests | per minute |
| `POST /auth/password-reset` | 3 requests | per hour |

### Обработка 429 Too Many Requests

```typescript
import axios, { AxiosError } from 'axios';

const api = axios.create({
  baseURL: 'https://api.samokoder.com',
  withCredentials: true,
});

// Response interceptor для обработки rate limiting
api.interceptors.response.use(
  response => response,
  async (error: AxiosError) => {
    if (error.response?.status === 429) {
      const retryAfter = error.response.headers['retry-after'] || 60;
      
      console.warn(`Rate limited. Retry after ${retryAfter} seconds`);
      
      // Показать уведомление пользователю
      showNotification({
        type: 'warning',
        message: `Too many requests. Please try again in ${retryAfter} seconds.`
      });
      
      // Опционально: автоматический retry с exponential backoff
      // await new Promise(resolve => setTimeout(resolve, retryAfter * 1000));
      // return api.request(error.config!);
    }
    
    throw error;
  }
);
```

---

## 🧪 6. Testing Your Migration

### Checklist

- [ ] **Login flow работает** с `withCredentials: true`
- [ ] **Protected endpoints доступны** после login
- [ ] **Logout корректно очищает** cookies
- [ ] **Refresh token работает** автоматически
- [ ] **Password validation** работает на клиенте
- [ ] **Rate limiting обрабатывается** корректно (показать 429 ошибку)
- [ ] **CORS errors отсутствуют** в production

### Тестовый сценарий

```typescript
describe('Authentication v1.0.0', () => {
  it('should login with httpOnly cookies', async () => {
    const response = await api.post('/auth/login', {
      username: 'test@example.com',
      password: 'TestPass123!'
    });
    
    expect(response.status).toBe(200);
    expect(response.data.user).toBeDefined();
    // Cookie установлен автоматически
  });
  
  it('should access protected endpoint after login', async () => {
    // Login first
    await api.post('/auth/login', {
      username: 'test@example.com',
      password: 'TestPass123!'
    });
    
    // Access protected endpoint
    const response = await api.get('/v1/projects');
    expect(response.status).toBe(200);
    expect(response.data).toBeInstanceOf(Array);
  });
  
  it('should handle rate limiting', async () => {
    // Trigger rate limit
    const promises = Array(10).fill(null).map(() => 
      api.post('/auth/login', {
        username: 'wrong@example.com',
        password: 'wrong'
      }).catch(e => e)
    );
    
    const results = await Promise.all(promises);
    const rateLimited = results.some(r => r.response?.status === 429);
    
    expect(rateLimited).toBe(true);
  });
  
  it('should validate password requirements', () => {
    const { valid, errors } = validatePassword('weak');
    expect(valid).toBe(false);
    expect(errors.length).toBeGreaterThan(0);
    
    const { valid: valid2 } = validatePassword('StrongPass123!');
    expect(valid2).toBe(true);
  });
});
```

---

## 🚨 7. Common Issues & Solutions

### Issue 1: "401 Unauthorized" после миграции

**Причина:** Cookies не отправляются с запросами

**Решение:**
```typescript
// Убедитесь, что withCredentials: true установлен
const api = axios.create({
  baseURL: 'https://api.samokoder.com',
  withCredentials: true,  // ⚠️ Это обязательно!
});
```

---

### Issue 2: CORS error "credentials mode is 'include'"

**Причина:** Backend не разрешает credentials или использует wildcard origin

**Решение (Backend side):**
```python
# НЕПРАВИЛЬНО:
allow_origins=["*"]  # Не работает с credentials

# ПРАВИЛЬНО:
allow_origins=["https://app.samokoder.com"]  # Конкретный origin
allow_credentials=True
```

---

### Issue 3: Cookies не сохраняются в mobile app

**Причина:** Не настроен cookie manager

**Решение (React Native):**
```bash
# Установить cookie manager
npm install @react-native-cookies/cookies

# Использовать
import CookieManager from '@react-native-cookies/cookies';

// Cookies теперь будут работать автоматически
```

---

### Issue 4: Старые пользователи не могут войти

**Причина:** Пароль не соответствует новым требованиям

**Решение:**
- Старые пользователи НЕ требуют сброса пароля
- Новые требования применяются только при смене пароля
- Если пользователь не может войти, предложите password reset

---

### Issue 5: "Too Many Requests" при тестировании

**Причина:** Достигнут rate limit

**Решение:**
```typescript
// Используйте exponential backoff
async function loginWithRetry(credentials: Credentials, maxRetries = 3) {
  for (let i = 0; i < maxRetries; i++) {
    try {
      return await api.post('/auth/login', credentials);
    } catch (error) {
      if (error.response?.status === 429 && i < maxRetries - 1) {
        const delay = Math.pow(2, i) * 1000; // 1s, 2s, 4s
        await new Promise(resolve => setTimeout(resolve, delay));
        continue;
      }
      throw error;
    }
  }
}
```

---

## 📅 8. Migration Timeline

### Рекомендуемый план миграции

**Week 1:**
- [ ] Прочитать этот migration guide
- [ ] Обновить development environment
- [ ] Протестировать authentication flow локально
- [ ] Обновить unit tests

**Week 2:**
- [ ] Deploy на staging
- [ ] Провести integration testing
- [ ] Исправить найденные issues
- [ ] Code review

**Week 3:**
- [ ] Deploy на production (координировать с backend v1.0.0 release)
- [ ] Мониторинг ошибок
- [ ] Hotfix если необходимо

**Week 4:**
- [ ] Собрать feedback от пользователей
- [ ] Оптимизация
- [ ] Документация lessons learned

---

## 📞 Support

Если у вас возникли вопросы или проблемы при миграции:

- 📧 **Email**: alex83ey@gmail.com
- 🐙 **GitHub Issues**: https://github.com/AlexeyPevz/Samokoder/issues
- 📚 **Documentation**: https://github.com/AlexeyPevz/Samokoder/blob/main/README.md

---

## 📚 Additional Resources

- **Release Notes**: `RELEASE_v1.0.0.md`
- **API Specification**: `openapi.yaml`
- **Security Audit Report**: `SECURITY_AUDIT_REPORT.md`
- **Backend README**: `README.md`

---

**Migration Guide Version:** 1.0  
**Last Updated:** 2025-10-06  
**Applies to:** Client applications migrating from v0.1.0 to v1.0.0
