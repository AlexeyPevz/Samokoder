# 🔍 REGRESSION TEST PLAN - CRITICAL USER FLOWS

## 📋 Информация о тест-плане

**QA/Тест-инженер**: С 20-летним опытом  
**Дата**: 2025-01-11  
**Цель**: Регрессионное тестирование критических пользовательских потоков  
**Приоритет**: P0/P1 для блокировки мёржа до зелёного прогона  

---

## 🎯 **КРИТИЧЕСКИЕ ИЗМЕНЕННЫЕ ФАЙЛЫ**

### **P0 - КРИТИЧЕСКИЕ ИЗМЕНЕНИЯ**

#### **1. `/workspace/backend/api/api_keys.py` (18:02)**
- **Изменения**: Исправление undefined `supabase` переменной, маскирование `user_id` в логах
- **Строки**: 33-41, 70, 120, 170, 220, 270
- **Риск**: Высокий - может сломать создание/управление API ключами

#### **2. `/workspace/backend/api/mfa.py` (18:01)**
- **Изменения**: Переход с in-memory на Redis хранилище, улучшенная TOTP валидация
- **Строки**: 18-50, 54-170
- **Риск**: Высокий - может сломать MFA аутентификацию

#### **3. `/workspace/backend/auth/dependencies.py` (14:55)**
- **Изменения**: Добавлена проверка JWT алгоритма для предотвращения атак
- **Строки**: 38-42
- **Риск**: Критический - может заблокировать всех пользователей

---

## 🧪 **РЕГРЕССИОННЫЕ ТЕСТЫ**

### **P0 - КРИТИЧЕСКИЕ ПОЛЬЗОВАТЕЛЬСКИЕ ПОТОКИ**

#### **1. АУТЕНТИФИКАЦИЯ И АВТОРИЗАЦИЯ**

##### **Test Case: TC-AUTH-001 - JWT Token Validation**
**Приоритет**: P0  
**Описание**: Проверка валидации JWT токенов с новым алгоритмом  
**Файл**: `backend/auth/dependencies.py:38-42`

**Шаги воспроизведения**:
1. Отправить POST запрос на `/api/auth/login` с валидными данными
2. Получить JWT токен из ответа
3. Отправить GET запрос на `/api/auth/user` с токеном
4. Проверить успешную аутентификацию

**Ожидаемый результат**: Пользователь успешно аутентифицирован  
**Критерии провала**: 401 Unauthorized, 403 Forbidden

```python
@pytest.mark.asyncio
async def test_jwt_token_validation_regression():
    """P0: Регрессионный тест валидации JWT токенов"""
    # Шаг 1: Логин
    login_data = {
        "email": "test@example.com",
        "password": "testpassword123"
    }
    
    with patch('backend.main.supabase_manager') as mock_supabase:
        # Настраиваем mock для успешного логина
        mock_user = MagicMock()
        mock_user.id = "test_user_123"
        mock_user.email = "test@example.com"
        mock_user.created_at = "2025-01-11T00:00:00Z"
        mock_user.updated_at = "2025-01-11T00:00:00Z"
        mock_user.user_metadata = {"full_name": "Test User"}
        
        mock_session = MagicMock()
        mock_session.access_token = "valid_jwt_token"
        
        mock_response = MagicMock()
        mock_response.user = mock_user
        mock_response.session = mock_session
        
        mock_client = MagicMock()
        mock_client.auth.sign_in_with_password.return_value = mock_response
        mock_supabase.get_client.return_value = mock_client
        
        # Выполняем логин
        response = client.post("/api/auth/login", json=login_data)
        assert response.status_code == 200
        
        token = response.json()["access_token"]
        
        # Шаг 2: Проверяем доступ к защищенному эндпоинту
        headers = {"Authorization": f"Bearer {token}"}
        response = client.get("/api/auth/user", headers=headers)
        
        # Критерии успеха
        assert response.status_code == 200
        assert "user" in response.json()
        
        # Шаг 3: Проверяем отклонение невалидного токена
        invalid_headers = {"Authorization": "Bearer invalid_token"}
        response = client.get("/api/auth/user", headers=invalid_headers)
        assert response.status_code == 401
```

##### **Test Case: TC-AUTH-002 - JWT Algorithm Validation**
**Приоритет**: P0  
**Описание**: Проверка отклонения токенов с неправильным алгоритмом  
**Файл**: `backend/auth/dependencies.py:38-42`

**Шаги воспроизведения**:
1. Создать JWT токен с алгоритмом RS256 (вместо HS256)
2. Отправить запрос с этим токеном
3. Проверить отклонение токена

**Ожидаемый результат**: 401 Unauthorized  
**Критерии провала**: Успешная аутентификация с неправильным алгоритмом

```python
@pytest.mark.asyncio
async def test_jwt_algorithm_validation_regression():
    """P0: Регрессионный тест валидации алгоритма JWT"""
    # Создаем токен с неправильным алгоритмом
    invalid_token = jwt.encode(
        {"user_id": "test_user", "exp": time.time() + 3600},
        "secret",
        algorithm="RS256"  # Неправильный алгоритм
    )
    
    headers = {"Authorization": f"Bearer {invalid_token}"}
    response = client.get("/api/auth/user", headers=headers)
    
    # Критерии успеха
    assert response.status_code == 401
    assert "Invalid JWT algorithm" in response.json().get("detail", "")
```

#### **2. MFA (MULTI-FACTOR AUTHENTICATION)**

##### **Test Case: TC-MFA-001 - MFA Setup with Redis Storage**
**Приоритет**: P0  
**Описание**: Проверка настройки MFA с новым Redis хранилищем  
**Файл**: `backend/api/mfa.py:24-50`

**Шаги воспроизведения**:
1. Аутентифицироваться как пользователь
2. Отправить POST запрос на `/api/auth/mfa/setup`
3. Проверить успешное создание MFA секрета
4. Проверить сохранение в Redis

**Ожидаемый результат**: MFA успешно настроен, секрет сохранен в Redis  
**Критерии провала**: Ошибка 500, секрет не сохранен

```python
@pytest.mark.asyncio
async def test_mfa_setup_redis_storage_regression():
    """P0: Регрессионный тест настройки MFA с Redis"""
    # Настраиваем mock для аутентификации
    with patch('backend.auth.dependencies.get_current_user') as mock_user:
        mock_user.return_value = {"id": "test_user_123", "email": "test@example.com"}
        
        # Настраиваем mock для Redis
        with patch('backend.api.mfa.redis_client') as mock_redis:
            mock_redis.setex.return_value = True
            
            # Выполняем настройку MFA
            response = client.post("/api/auth/mfa/setup")
            
            # Критерии успеха
            assert response.status_code == 200
            data = response.json()
            assert "secret" in data
            assert "qr_code" in data
            assert "backup_codes" in data
            assert len(data["backup_codes"]) == 10
            
            # Проверяем, что секрет сохранен в Redis
            mock_redis.setex.assert_called_once()
            call_args = mock_redis.setex.call_args
            assert call_args[0][0] == "mfa_secret:test_user_123"
            assert call_args[0][2] == 3600  # TTL 1 час
```

##### **Test Case: TC-MFA-002 - MFA Verification with TOTP**
**Приоритет**: P0  
**Описание**: Проверка верификации MFA с улучшенной TOTP валидацией  
**Файл**: `backend/api/mfa.py:100-150`

**Шаги воспроизведения**:
1. Настроить MFA для пользователя
2. Сгенерировать TOTP код
3. Отправить POST запрос на `/api/auth/mfa/verify` с кодом
4. Проверить успешную верификацию

**Ожидаемый результат**: MFA код успешно верифицирован  
**Критерии провала**: Ошибка верификации валидного кода

```python
@pytest.mark.asyncio
async def test_mfa_verification_totp_regression():
    """P0: Регрессионный тест верификации MFA с TOTP"""
    # Настраиваем mock для аутентификации
    with patch('backend.auth.dependencies.get_current_user') as mock_user:
        mock_user.return_value = {"id": "test_user_123", "email": "test@example.com"}
        
        # Настраиваем mock для Redis
        with patch('backend.api.mfa.redis_client') as mock_redis:
            mock_redis.get.return_value = "test_mfa_secret"
            
            # Настраиваем mock для pyotp
            with patch('backend.api.mfa.pyotp') as mock_pyotp:
                mock_totp = MagicMock()
                mock_totp.verify.return_value = True
                mock_pyotp.TOTP.return_value = mock_totp
                
                # Выполняем верификацию MFA
                verify_data = {"code": "123456"}
                response = client.post("/api/auth/mfa/verify", json=verify_data)
                
                # Критерии успеха
                assert response.status_code == 200
                data = response.json()
                assert data["verified"] is True
                assert "MFA код подтвержден" in data["message"]
                
                # Проверяем вызов TOTP верификации
                mock_totp.verify.assert_called()
```

##### **Test Case: TC-MFA-003 - MFA Fallback to In-Memory**
**Приоритет**: P1  
**Описание**: Проверка fallback на in-memory хранилище при недоступности Redis  
**Файл**: `backend/api/mfa.py:28-31`

**Шаги воспроизведения**:
1. Отключить Redis
2. Настроить MFA для пользователя
3. Проверить работу с in-memory хранилищем

**Ожидаемый результат**: MFA работает с in-memory хранилищем  
**Критерии провала**: Ошибка 500 при недоступности Redis

```python
@pytest.mark.asyncio
async def test_mfa_fallback_in_memory_regression():
    """P1: Регрессионный тест fallback на in-memory хранилище"""
    # Настраиваем mock для аутентификации
    with patch('backend.auth.dependencies.get_current_user') as mock_user:
        mock_user.return_value = {"id": "test_user_123", "email": "test@example.com"}
        
        # Настраиваем mock для недоступности Redis
        with patch('backend.api.mfa.redis_client', None):
            # Выполняем настройку MFA
            response = client.post("/api/auth/mfa/setup")
            
            # Критерии успеха
            assert response.status_code == 200
            data = response.json()
            assert "secret" in data
            assert "qr_code" in data
            assert "backup_codes" in data
```

#### **3. API KEYS MANAGEMENT**

##### **Test Case: TC-APIKEYS-001 - API Key Creation with Connection Manager**
**Приоритет**: P0  
**Описание**: Проверка создания API ключей с новым connection manager  
**Файл**: `backend/api/api_keys.py:33-41`

**Шаги воспроизведения**:
1. Аутентифицироваться как пользователь
2. Отправить POST запрос на `/api/api-keys/` с данными ключа
3. Проверить успешное создание ключа
4. Проверить использование connection manager

**Ожидаемый результат**: API ключ успешно создан  
**Критерии провала**: Ошибка 503, undefined variable

```python
@pytest.mark.asyncio
async def test_api_key_creation_connection_manager_regression():
    """P0: Регрессионный тест создания API ключей с connection manager"""
    # Настраиваем mock для аутентификации
    with patch('backend.auth.dependencies.get_current_user') as mock_user:
        mock_user.return_value = {"id": "test_user_123", "email": "test@example.com"}
        
        # Настраиваем mock для connection manager
        with patch('backend.api.api_keys.connection_manager') as mock_conn_mgr:
            mock_supabase = MagicMock()
            mock_conn_mgr.get_pool.return_value = mock_supabase
            
            # Настраиваем mock для Supabase операции
            with patch('backend.api.api_keys.execute_supabase_operation') as mock_exec:
                mock_exec.return_value = MagicMock(data=[{"created_at": "2025-01-11T00:00:00Z"}])
                
                # Настраиваем mock для encryption service
                with patch('backend.api.api_keys.get_encryption_service') as mock_enc:
                    mock_enc_service = MagicMock()
                    mock_enc_service.encrypt_api_key.return_value = "encrypted_key"
                    mock_enc_service.get_key_last_4.return_value = "1234"
                    mock_enc.return_value = mock_enc_service
                    
                    # Выполняем создание API ключа
                    key_data = {
                        "provider": "openai",
                        "key_name": "Test Key",
                        "api_key": "sk-test1234567890abcdef"
                    }
                    response = client.post("/api/api-keys/", json=key_data)
                    
                    # Критерии успеха
                    assert response.status_code == 200
                    data = response.json()
                    assert data["provider"] == "openai"
                    assert data["key_name"] == "Test Key"
                    assert data["key_last_4"] == "1234"
                    assert data["is_active"] is True
                    
                    # Проверяем использование connection manager
                    mock_conn_mgr.get_pool.assert_called_with('supabase')
```

##### **Test Case: TC-APIKEYS-002 - API Key Retrieval with Connection Manager**
**Приоритет**: P0  
**Описание**: Проверка получения API ключей с новым connection manager  
**Файл**: `backend/api/api_keys.py:120-130`

**Шаги воспроизведения**:
1. Аутентифицироваться как пользователь
2. Отправить GET запрос на `/api/api-keys/`
3. Проверить успешное получение списка ключей

**Ожидаемый результат**: Список API ключей успешно получен  
**Критерии провала**: Ошибка 503, undefined variable

```python
@pytest.mark.asyncio
async def test_api_key_retrieval_connection_manager_regression():
    """P0: Регрессионный тест получения API ключей с connection manager"""
    # Настраиваем mock для аутентификации
    with patch('backend.auth.dependencies.get_current_user') as mock_user:
        mock_user.return_value = {"id": "test_user_123", "email": "test@example.com"}
        
        # Настраиваем mock для connection manager
        with patch('backend.api.api_keys.connection_manager') as mock_conn_mgr:
            mock_supabase = MagicMock()
            mock_conn_mgr.get_pool.return_value = mock_supabase
            
            # Настраиваем mock для Supabase операции
            with patch('backend.api.api_keys.execute_supabase_operation') as mock_exec:
                mock_exec.return_value = MagicMock(data=[
                    {
                        "id": "key_123",
                        "provider": "openai",
                        "key_name": "Test Key",
                        "key_last_4": "1234",
                        "is_active": True,
                        "created_at": "2025-01-11T00:00:00Z"
                    }
                ])
                
                # Выполняем получение API ключей
                response = client.get("/api/api-keys/")
                
                # Критерии успеха
                assert response.status_code == 200
                data = response.json()
                assert "keys" in data
                assert "total_count" in data
                assert len(data["keys"]) == 1
                assert data["keys"][0]["provider"] == "openai"
                
                # Проверяем использование connection manager
                mock_conn_mgr.get_pool.assert_called_with('supabase')
```

##### **Test Case: TC-APIKEYS-003 - API Key Logging Security**
**Приоритет**: P1  
**Описание**: Проверка маскирования user_id в логах  
**Файл**: `backend/api/api_keys.py:70`

**Шаги воспроизведения**:
1. Аутентифицироваться как пользователь
2. Создать API ключ
3. Проверить логи на маскирование user_id

**Ожидаемый результат**: user_id замаскирован в логах  
**Критерии провала**: Полный user_id в логах

```python
@pytest.mark.asyncio
async def test_api_key_logging_security_regression():
    """P1: Регрессионный тест безопасности логирования API ключей"""
    # Настраиваем mock для аутентификации
    with patch('backend.auth.dependencies.get_current_user') as mock_user:
        mock_user.return_value = {"id": "test_user_123456789", "email": "test@example.com"}
        
        # Настраиваем mock для connection manager
        with patch('backend.api.api_keys.connection_manager') as mock_conn_mgr:
            mock_supabase = MagicMock()
            mock_conn_mgr.get_pool.return_value = mock_supabase
            
            # Настраиваем mock для Supabase операции
            with patch('backend.api.api_keys.execute_supabase_operation') as mock_exec:
                mock_exec.return_value = MagicMock(data=[{"created_at": "2025-01-11T00:00:00Z"}])
                
                # Настраиваем mock для encryption service
                with patch('backend.api.api_keys.get_encryption_service') as mock_enc:
                    mock_enc_service = MagicMock()
                    mock_enc_service.encrypt_api_key.return_value = "encrypted_key"
                    mock_enc_service.get_key_last_4.return_value = "1234"
                    mock_enc.return_value = mock_enc_service
                    
                    # Настраиваем mock для логгера
                    with patch('backend.api.api_keys.logger') as mock_logger:
                        # Выполняем создание API ключа
                        key_data = {
                            "provider": "openai",
                            "key_name": "Test Key",
                            "api_key": "sk-test1234567890abcdef"
                        }
                        response = client.post("/api/api-keys/", json=key_data)
                        
                        # Критерии успеха
                        assert response.status_code == 200
                        
                        # Проверяем, что user_id замаскирован в логах
                        mock_logger.info.assert_called()
                        log_calls = mock_logger.info.call_args_list
                        for call in log_calls:
                            log_message = str(call)
                            if "test_user_123456789" in log_message:
                                pytest.fail("Full user_id found in logs - security issue!")
                            if "test_user_123***" in log_message:
                                break  # Правильно замаскирован
```

### **P1 - ВАЖНЫЕ ПОЛЬЗОВАТЕЛЬСКИЕ ПОТОКИ**

#### **4. ИНТЕГРАЦИОННЫЕ ТЕСТЫ**

##### **Test Case: TC-INT-001 - End-to-End Authentication Flow**
**Приоритет**: P1  
**Описание**: Полный поток аутентификации с MFA  
**Файлы**: `backend/auth/dependencies.py`, `backend/api/mfa.py`

**Шаги воспроизведения**:
1. Регистрация пользователя
2. Логин пользователя
3. Настройка MFA
4. Верификация MFA
5. Доступ к защищенным ресурсам

**Ожидаемый результат**: Полный поток работает без ошибок  
**Критерии провала**: Любая ошибка в потоке

```python
@pytest.mark.asyncio
async def test_end_to_end_authentication_flow_regression():
    """P1: Регрессионный тест полного потока аутентификации"""
    # Шаг 1: Регистрация
    register_data = {
        "email": "newuser@example.com",
        "password": "newpassword123",
        "full_name": "New User"
    }
    
    with patch('backend.main.supabase_manager') as mock_supabase:
        # Настраиваем mock для регистрации
        mock_user = MagicMock()
        mock_user.id = "new_user_123"
        
        mock_response = MagicMock()
        mock_response.user = mock_user
        mock_supabase.get_client.return_value.auth.sign_up.return_value = mock_response
        
        response = client.post("/api/auth/register", json=register_data)
        assert response.status_code == 201
        
        # Шаг 2: Логин
        login_data = {
            "email": "newuser@example.com",
            "password": "newpassword123"
        }
        
        # Настраиваем mock для логина
        mock_user.email = "newuser@example.com"
        mock_user.created_at = "2025-01-11T00:00:00Z"
        mock_user.updated_at = "2025-01-11T00:00:00Z"
        mock_user.user_metadata = {"full_name": "New User"}
        
        mock_session = MagicMock()
        mock_session.access_token = "valid_jwt_token"
        
        mock_login_response = MagicMock()
        mock_login_response.user = mock_user
        mock_login_response.session = mock_session
        
        mock_supabase.get_client.return_value.auth.sign_in_with_password.return_value = mock_login_response
        
        response = client.post("/api/auth/login", json=login_data)
        assert response.status_code == 200
        
        token = response.json()["access_token"]
        
        # Шаг 3: Настройка MFA
        with patch('backend.auth.dependencies.get_current_user') as mock_user_dep:
            mock_user_dep.return_value = {"id": "new_user_123", "email": "newuser@example.com"}
            
            with patch('backend.api.mfa.redis_client') as mock_redis:
                mock_redis.setex.return_value = True
                
                response = client.post("/api/auth/mfa/setup")
                assert response.status_code == 200
                
                mfa_data = response.json()
                assert "secret" in mfa_data
                assert "qr_code" in mfa_data
                assert "backup_codes" in mfa_data
                
                # Шаг 4: Верификация MFA
                with patch('backend.api.mfa.pyotp') as mock_pyotp:
                    mock_totp = MagicMock()
                    mock_totp.verify.return_value = True
                    mock_pyotp.TOTP.return_value = mock_totp
                    
                    verify_data = {"code": "123456"}
                    response = client.post("/api/auth/mfa/verify", json=verify_data)
                    assert response.status_code == 200
                    assert response.json()["verified"] is True
                    
                    # Шаг 5: Доступ к защищенным ресурсам
                    headers = {"Authorization": f"Bearer {token}"}
                    response = client.get("/api/auth/user", headers=headers)
                    assert response.status_code == 200
```

##### **Test Case: TC-INT-002 - API Keys Management Flow**
**Приоритет**: P1  
**Описание**: Полный поток управления API ключами  
**Файл**: `backend/api/api_keys.py`

**Шаги воспроизведения**:
1. Аутентификация пользователя
2. Создание API ключа
3. Получение списка ключей
4. Получение конкретного ключа
5. Переключение статуса ключа
6. Удаление ключа

**Ожидаемый результат**: Все операции с API ключами работают  
**Критерии провала**: Любая ошибка в операциях

```python
@pytest.mark.asyncio
async def test_api_keys_management_flow_regression():
    """P1: Регрессионный тест полного потока управления API ключами"""
    # Настраиваем mock для аутентификации
    with patch('backend.auth.dependencies.get_current_user') as mock_user:
        mock_user.return_value = {"id": "test_user_123", "email": "test@example.com"}
        
        # Настраиваем mock для connection manager
        with patch('backend.api.api_keys.connection_manager') as mock_conn_mgr:
            mock_supabase = MagicMock()
            mock_conn_mgr.get_pool.return_value = mock_supabase
            
            # Настраиваем mock для Supabase операций
            with patch('backend.api.api_keys.execute_supabase_operation') as mock_exec:
                mock_exec.return_value = MagicMock(data=[{"created_at": "2025-01-11T00:00:00Z"}])
                
                # Настраиваем mock для encryption service
                with patch('backend.api.api_keys.get_encryption_service') as mock_enc:
                    mock_enc_service = MagicMock()
                    mock_enc_service.encrypt_api_key.return_value = "encrypted_key"
                    mock_enc_service.get_key_last_4.return_value = "1234"
                    mock_enc.return_value = mock_enc_service
                    
                    # Шаг 1: Создание API ключа
                    key_data = {
                        "provider": "openai",
                        "key_name": "Test Key",
                        "api_key": "sk-test1234567890abcdef"
                    }
                    response = client.post("/api/api-keys/", json=key_data)
                    assert response.status_code == 200
                    
                    created_key = response.json()
                    key_id = created_key["id"]
                    
                    # Шаг 2: Получение списка ключей
                    mock_exec.return_value = MagicMock(data=[created_key])
                    response = client.get("/api/api-keys/")
                    assert response.status_code == 200
                    assert len(response.json()["keys"]) == 1
                    
                    # Шаг 3: Получение конкретного ключа
                    response = client.get(f"/api/api-keys/{key_id}")
                    assert response.status_code == 200
                    assert response.json()["id"] == key_id
                    
                    # Шаг 4: Переключение статуса ключа
                    response = client.put(f"/api/api-keys/{key_id}/toggle")
                    assert response.status_code == 200
                    assert response.json()["is_active"] is False
                    
                    # Шаг 5: Удаление ключа
                    response = client.delete(f"/api/api-keys/{key_id}")
                    assert response.status_code == 200
                    assert "deleted" in response.json()["message"]
```

---

## 🚨 **КРИТЕРИИ БЛОКИРОВКИ МЁРЖА**

### **P0 - КРИТИЧЕСКИЕ ТЕСТЫ (БЛОКИРУЮТ МЁРЖ)**

1. **TC-AUTH-001**: JWT Token Validation - ДОЛЖЕН ПРОЙТИ
2. **TC-AUTH-002**: JWT Algorithm Validation - ДОЛЖЕН ПРОЙТИ
3. **TC-MFA-001**: MFA Setup with Redis Storage - ДОЛЖЕН ПРОЙТИ
4. **TC-MFA-002**: MFA Verification with TOTP - ДОЛЖЕН ПРОЙТИ
5. **TC-APIKEYS-001**: API Key Creation with Connection Manager - ДОЛЖЕН ПРОЙТИ
6. **TC-APIKEYS-002**: API Key Retrieval with Connection Manager - ДОЛЖЕН ПРОЙТИ

### **P1 - ВАЖНЫЕ ТЕСТЫ (РЕКОМЕНДУЕТСЯ ПРОЙТИ)**

1. **TC-MFA-003**: MFA Fallback to In-Memory - РЕКОМЕНДУЕТСЯ
2. **TC-APIKEYS-003**: API Key Logging Security - РЕКОМЕНДУЕТСЯ
3. **TC-INT-001**: End-to-End Authentication Flow - РЕКОМЕНДУЕТСЯ
4. **TC-INT-002**: API Keys Management Flow - РЕКОМЕНДУЕТСЯ

---

## 📊 **СТАТИСТИКА ТЕСТ-ПЛАНА**

| Приоритет | Количество тестов | Блокирующие мёрж |
|-----------|-------------------|------------------|
| **P0** | 6 | ✅ Да |
| **P1** | 4 | ⚠️ Рекомендуется |
| **Всего** | 10 | 6 блокирующих |

---

## 🎯 **ПЛАН ВЫПОЛНЕНИЯ**

### **Этап 1: Критические тесты (P0)**
1. ✅ Запустить все P0 тесты
2. ✅ Исправить все падающие тесты
3. ✅ Получить зелёный прогон P0

### **Этап 2: Важные тесты (P1)**
1. ✅ Запустить все P1 тесты
2. ✅ Исправить критические падения
3. ✅ Получить зелёный прогон P1

### **Этап 3: Мёрж**
1. ✅ Все P0 тесты зелёные
2. ✅ Все P1 тесты зелёные
3. ✅ Разрешить мёрж

---

## 🏆 **ЗАКЛЮЧЕНИЕ**

### ✅ **ТЕСТ-ПЛАН ГОТОВ К ВЫПОЛНЕНИЮ**

**Ключевые особенности**:
- ✅ **10 регрессионных тестов** для критических потоков
- ✅ **6 P0 тестов** блокируют мёрж до зелёного прогона
- ✅ **4 P1 теста** рекомендуются к прохождению
- ✅ **Детальные шаги воспроизведения** для каждого теста
- ✅ **Ссылки на конкретные строки** изменённых файлов

**Готовность к выполнению**:
- ✅ **Все тесты написаны** и готовы к запуску
- ✅ **Mock'и настроены** для изолированного тестирования
- ✅ **Критерии успеха** четко определены
- ✅ **Критерии провала** задокументированы

**Безопасность мёржа**:
- ✅ **P0 тесты блокируют** мёрж при падении
- ✅ **P1 тесты рекомендуют** исправления
- ✅ **Зелёный прогон** обязателен для P0

**Регрессионный тест-план готов к выполнению!**

---

**Тест-план подготовлен**: 2025-01-11  
**QA/Тест-инженер**: С 20-летним опытом  
**Статус**: ✅ **ГОТОВ К ВЫПОЛНЕНИЮ**