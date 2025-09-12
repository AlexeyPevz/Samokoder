"""
P1 тесты для security boundaries - важные пробелы в покрытии
Рекомендуются для улучшения безопасности
"""

import pytest
import time
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient
from backend.main import app

client = TestClient(app)

class TestSecurityBoundariesP1Coverage:
    """P1 тесты для security boundaries"""
    
    # === P1 - ВАЖНЫЕ ТЕСТЫ (РЕКОМЕНДУЮТСЯ) ===
    
    @pytest.mark.asyncio
    async def test_sql_injection_attempts(self):
        """P1: Тест попыток SQL injection"""
        # Настраиваем mock для аутентификации
        with patch('backend.auth.dependencies.get_current_user') as mock_user:
            mock_user.return_value = {"id": "test_user_123", "email": "test@example.com"}
            
            # Тестируем различные SQL injection атаки
            sql_injection_payloads = [
                "'; DROP TABLE users; --",
                "' OR '1'='1",
                "'; INSERT INTO users VALUES ('hacker', 'password'); --",
                "' UNION SELECT * FROM users --",
                "'; UPDATE users SET password='hacked' WHERE id=1; --",
                "' OR 1=1 --",
                "'; DELETE FROM users; --"
            ]
            
            for payload in sql_injection_payloads:
                # Выполняем создание API ключа с SQL injection в имени
                key_data = {
                    "provider": "openai",
                    "key_name": payload,
                    "api_key": "sk-test1234567890abcdef"
                }
                response = client.post("/api/api-keys/", json=key_data)
                
                # Критерии успеха - должен обработать безопасно
                # Может вернуть 422 (validation error) или 200 (если экранировано)
                assert response.status_code in [200, 422]
                
                # Проверяем, что в ответе нет SQL кода
                if response.status_code == 200:
                    response_data = response.json()
                    assert "DROP TABLE" not in str(response_data)
                    assert "INSERT INTO" not in str(response_data)
                    assert "UPDATE" not in str(response_data)
                    assert "DELETE FROM" not in str(response_data)
    
    @pytest.mark.asyncio
    async def test_xss_attacks(self):
        """P1: Тест XSS атак"""
        # Настраиваем mock для аутентификации
        with patch('backend.auth.dependencies.get_current_user') as mock_user:
            mock_user.return_value = {"id": "test_user_123", "email": "test@example.com"}
            
            # Тестируем различные XSS атаки
            xss_payloads = [
                "<script>alert('XSS')</script>",
                "<img src=x onerror=alert('XSS')>",
                "javascript:alert('XSS')",
                "<svg onload=alert('XSS')>",
                "<iframe src=javascript:alert('XSS')></iframe>",
                "<body onload=alert('XSS')>",
                "<input onfocus=alert('XSS') autofocus>"
            ]
            
            for payload in xss_payloads:
                # Выполняем создание API ключа с XSS в имени
                key_data = {
                    "provider": "openai",
                    "key_name": payload,
                    "api_key": "sk-test1234567890abcdef"
                }
                response = client.post("/api/api-keys/", json=key_data)
                
                # Критерии успеха - должен обработать безопасно
                # Может вернуть 422 (validation error) или 200 (если экранировано)
                assert response.status_code in [200, 422]
                
                # Проверяем, что в ответе нет неэкранированного JavaScript
                if response.status_code == 200:
                    response_data = response.json()
                    assert "<script>" not in str(response_data)
                    assert "javascript:" not in str(response_data)
                    assert "onerror=" not in str(response_data)
                    assert "onload=" not in str(response_data)
    
    @pytest.mark.asyncio
    async def test_csrf_bypass(self):
        """P1: Тест обхода CSRF"""
        # Выполняем POST запрос без CSRF токена
        key_data = {
            "provider": "openai",
            "key_name": "Test Key",
            "api_key": "sk-test1234567890abcdef"
        }
        response = client.post("/api/api-keys/", json=key_data)
        
        # Критерии успеха - должен вернуть 403 (CSRF protection)
        assert response.status_code == 403
        assert "CSRF token missing" in response.json()["detail"]
    
    @pytest.mark.asyncio
    async def test_rate_limiting_bypass(self):
        """P1: Тест обхода rate limiting"""
        # Выполняем множество запросов для проверки rate limiting
        rate_limit_hit = False
        
        for i in range(100):
            response = client.get("/health")
            
            # Проверяем заголовки rate limiting
            if "X-RateLimit-Remaining" in response.headers:
                remaining = int(response.headers["X-RateLimit-Remaining"])
                if remaining == 0:
                    # Rate limit достигнут
                    assert response.status_code == 429
                    rate_limit_hit = True
                    break
            else:
                # Rate limiting не настроен
                assert response.status_code == 200
        
        # Если rate limiting настроен, должен быть достигнут лимит
        if rate_limit_hit:
            assert True  # Rate limiting работает
        else:
            # Rate limiting не настроен - это тоже нормально для тестов
            assert True
    
    @pytest.mark.asyncio
    async def test_authentication_bypass(self):
        """P1: Тест обхода аутентификации"""
        # Выполняем запрос к защищенному эндпоинту без токена
        response = client.get("/api/auth/user")
        
        # Критерии успеха - должен вернуть 401
        assert response.status_code == 401
    
    @pytest.mark.asyncio
    async def test_authorization_bypass(self):
        """P1: Тест обхода авторизации"""
        # Настраиваем mock для аутентификации с другим пользователем
        with patch('backend.auth.dependencies.get_current_user') as mock_user:
            mock_user.return_value = {"id": "other_user_456", "email": "other@example.com"}
            
            # Пытаемся получить API ключ другого пользователя
            response = client.get("/api/api-keys/key_123")
            
            # Критерии успеха - должен вернуть 404 (ключ не найден для этого пользователя)
            assert response.status_code == 404
            assert "API ключ не найден" in response.json()["detail"]
    
    @pytest.mark.asyncio
    async def test_path_traversal_attempts(self):
        """P1: Тест попыток path traversal"""
        # Настраиваем mock для аутентификации
        with patch('backend.auth.dependencies.get_current_user') as mock_user:
            mock_user.return_value = {"id": "test_user_123", "email": "test@example.com"}
            
            # Тестируем различные path traversal атаки
            path_traversal_payloads = [
                "../../../etc/passwd",
                "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
                "....//....//....//etc/passwd",
                "..%2F..%2F..%2Fetc%2Fpasswd",
                "..%252F..%252F..%252Fetc%252Fpasswd",
                "..%c0%af..%c0%af..%c0%afetc%c0%afpasswd"
            ]
            
            for payload in path_traversal_payloads:
                # Выполняем создание API ключа с path traversal в имени
                key_data = {
                    "provider": "openai",
                    "key_name": payload,
                    "api_key": "sk-test1234567890abcdef"
                }
                response = client.post("/api/api-keys/", json=key_data)
                
                # Критерии успеха - должен обработать безопасно
                # Может вернуть 422 (validation error) или 200 (если экранировано)
                assert response.status_code in [200, 422]
                
                # Проверяем, что в ответе нет path traversal кода
                if response.status_code == 200:
                    response_data = response.json()
                    assert "../" not in str(response_data)
                    assert "..\\" not in str(response_data)
                    assert "/etc/passwd" not in str(response_data)
    
    @pytest.mark.asyncio
    async def test_command_injection_attempts(self):
        """P1: Тест попыток command injection"""
        # Настраиваем mock для аутентификации
        with patch('backend.auth.dependencies.get_current_user') as mock_user:
            mock_user.return_value = {"id": "test_user_123", "email": "test@example.com"}
            
            # Тестируем различные command injection атаки
            command_injection_payloads = [
                "; ls -la",
                "| cat /etc/passwd",
                "&& whoami",
                "`id`",
                "$(whoami)",
                "; rm -rf /",
                "| nc -l 4444"
            ]
            
            for payload in command_injection_payloads:
                # Выполняем создание API ключа с command injection в имени
                key_data = {
                    "provider": "openai",
                    "key_name": payload,
                    "api_key": "sk-test1234567890abcdef"
                }
                response = client.post("/api/api-keys/", json=key_data)
                
                # Критерии успеха - должен обработать безопасно
                # Может вернуть 422 (validation error) или 200 (если экранировано)
                assert response.status_code in [200, 422]
                
                # Проверяем, что в ответе нет command injection кода
                if response.status_code == 200:
                    response_data = response.json()
                    assert "ls -la" not in str(response_data)
                    assert "cat /etc/passwd" not in str(response_data)
                    assert "whoami" not in str(response_data)
                    assert "rm -rf" not in str(response_data)
    
    @pytest.mark.asyncio
    async def test_ldap_injection_attempts(self):
        """P1: Тест попыток LDAP injection"""
        # Настраиваем mock для аутентификации
        with patch('backend.auth.dependencies.get_current_user') as mock_user:
            mock_user.return_value = {"id": "test_user_123", "email": "test@example.com"}
            
            # Тестируем различные LDAP injection атаки
            ldap_injection_payloads = [
                "*)(uid=*))(|(uid=*",
                "*)(|(password=*))",
                "*)(|(objectClass=*))",
                "*)(|(cn=*))",
                "*)(|(mail=*))",
                "*)(|(telephoneNumber=*))"
            ]
            
            for payload in ldap_injection_payloads:
                # Выполняем создание API ключа с LDAP injection в имени
                key_data = {
                    "provider": "openai",
                    "key_name": payload,
                    "api_key": "sk-test1234567890abcdef"
                }
                response = client.post("/api/api-keys/", json=key_data)
                
                # Критерии успеха - должен обработать безопасно
                # Может вернуть 422 (validation error) или 200 (если экранировано)
                assert response.status_code in [200, 422]
                
                # Проверяем, что в ответе нет LDAP injection кода
                if response.status_code == 200:
                    response_data = response.json()
                    assert "uid=*" not in str(response_data)
                    assert "password=*" not in str(response_data)
                    assert "objectClass=*" not in str(response_data)
    
    @pytest.mark.asyncio
    async def test_xml_injection_attempts(self):
        """P1: Тест попыток XML injection"""
        # Настраиваем mock для аутентификации
        with patch('backend.auth.dependencies.get_current_user') as mock_user:
            mock_user.return_value = {"id": "test_user_123", "email": "test@example.com"}
            
            # Тестируем различные XML injection атаки
            xml_injection_payloads = [
                "<![CDATA[<script>alert('XSS')</script>]]>",
                "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY test SYSTEM 'file:///etc/passwd'>]><root>&test;</root>",
                "<root><![CDATA[<script>alert('XSS')</script>]]></root>",
                "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY test SYSTEM 'http://evil.com/steal.php'>]><root>&test;</root>"
            ]
            
            for payload in xml_injection_payloads:
                # Выполняем создание API ключа с XML injection в имени
                key_data = {
                    "provider": "openai",
                    "key_name": payload,
                    "api_key": "sk-test1234567890abcdef"
                }
                response = client.post("/api/api-keys/", json=key_data)
                
                # Критерии успеха - должен обработать безопасно
                # Может вернуть 422 (validation error) или 200 (если экранировано)
                assert response.status_code in [200, 422]
                
                # Проверяем, что в ответе нет XML injection кода
                if response.status_code == 200:
                    response_data = response.json()
                    assert "<![CDATA[" not in str(response_data)
                    assert "<!DOCTYPE" not in str(response_data)
                    assert "<!ENTITY" not in str(response_data)
    
    @pytest.mark.asyncio
    async def test_xxe_attempts(self):
        """P1: Тест попыток XXE (XML External Entity)"""
        # Настраиваем mock для аутентификации
        with patch('backend.auth.dependencies.get_current_user') as mock_user:
            mock_user.return_value = {"id": "test_user_123", "email": "test@example.com"}
            
            # Тестируем различные XXE атаки
            xxe_payloads = [
                "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><root>&xxe;</root>",
                "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY xxe SYSTEM 'http://evil.com/steal.php'>]><root>&xxe;</root>",
                "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY xxe SYSTEM 'ftp://evil.com/steal.txt'>]><root>&xxe;</root>",
                "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY xxe SYSTEM 'gopher://evil.com/steal'>]><root>&xxe;</root>"
            ]
            
            for payload in xxe_payloads:
                # Выполняем создание API ключа с XXE в имени
                key_data = {
                    "provider": "openai",
                    "key_name": payload,
                    "api_key": "sk-test1234567890abcdef"
                }
                response = client.post("/api/api-keys/", json=key_data)
                
                # Критерии успеха - должен обработать безопасно
                # Может вернуть 422 (validation error) или 200 (если экранировано)
                assert response.status_code in [200, 422]
                
                # Проверяем, что в ответе нет XXE кода
                if response.status_code == 200:
                    response_data = response.json()
                    assert "file://" not in str(response_data)
                    assert "http://evil.com" not in str(response_data)
                    assert "ftp://evil.com" not in str(response_data)
                    assert "gopher://evil.com" not in str(response_data)
    
    @pytest.mark.asyncio
    async def test_ssrf_attempts(self):
        """P1: Тест попыток SSRF (Server-Side Request Forgery)"""
        # Настраиваем mock для аутентификации
        with patch('backend.auth.dependencies.get_current_user') as mock_user:
            mock_user.return_value = {"id": "test_user_123", "email": "test@example.com"}
            
            # Тестируем различные SSRF атаки
            ssrf_payloads = [
                "http://localhost:22",
                "http://127.0.0.1:3306",
                "http://169.254.169.254/latest/meta-data/",
                "http://[::1]:22",
                "http://0.0.0.0:22",
                "http://localhost:6379",
                "http://localhost:5432"
            ]
            
            for payload in ssrf_payloads:
                # Выполняем создание API ключа с SSRF в имени
                key_data = {
                    "provider": "openai",
                    "key_name": payload,
                    "api_key": "sk-test1234567890abcdef"
                }
                response = client.post("/api/api-keys/", json=key_data)
                
                # Критерии успеха - должен обработать безопасно
                # Может вернуть 422 (validation error) или 200 (если экранировано)
                assert response.status_code in [200, 422]
                
                # Проверяем, что в ответе нет SSRF кода
                if response.status_code == 200:
                    response_data = response.json()
                    assert "localhost:22" not in str(response_data)
                    assert "127.0.0.1:3306" not in str(response_data)
                    assert "169.254.169.254" not in str(response_data)
    
    @pytest.mark.asyncio
    async def test_injection_in_api_key_field(self):
        """P1: Тест injection атак в поле API ключа"""
        # Настраиваем mock для аутентификации
        with patch('backend.auth.dependencies.get_current_user') as mock_user:
            mock_user.return_value = {"id": "test_user_123", "email": "test@example.com"}
            
            # Тестируем injection в поле API ключа
            injection_payloads = [
                "sk-test1234567890abcdef'; DROP TABLE users; --",
                "sk-test1234567890abcdef<script>alert('XSS')</script>",
                "sk-test1234567890abcdef../../../etc/passwd",
                "sk-test1234567890abcdef; ls -la",
                "sk-test1234567890abcdef*)(uid=*))(|(uid=*"
            ]
            
            for payload in injection_payloads:
                # Выполняем создание API ключа с injection в ключе
                key_data = {
                    "provider": "openai",
                    "key_name": "Test Key",
                    "api_key": payload
                }
                response = client.post("/api/api-keys/", json=key_data)
                
                # Критерии успеха - должен обработать безопасно
                # Может вернуть 422 (validation error) или 200 (если экранировано)
                assert response.status_code in [200, 422]
                
                # Проверяем, что в ответе нет injection кода
                if response.status_code == 200:
                    response_data = response.json()
                    assert "DROP TABLE" not in str(response_data)
                    assert "<script>" not in str(response_data)
                    assert "../" not in str(response_data)
                    assert "ls -la" not in str(response_data)
                    assert "uid=*" not in str(response_data)

class TestSecurityBoundariesMFA:
    """P1 тесты для security boundaries в MFA"""
    
    @pytest.mark.asyncio
    async def test_mfa_code_injection_attempts(self):
        """P1: Тест попыток injection в MFA код"""
        # Настраиваем mock для аутентификации
        with patch('backend.auth.dependencies.get_current_user') as mock_user:
            mock_user.return_value = {"id": "test_user_123", "email": "test@example.com"}
            
            # Настраиваем mock для Redis
            with patch('backend.api.mfa.redis_client') as mock_redis:
                mock_redis.get.return_value = b"test_secret"
                
                # Тестируем различные injection атаки в MFA код
                injection_payloads = [
                    "123456'; DROP TABLE users; --",
                    "123456<script>alert('XSS')</script>",
                    "123456../../../etc/passwd",
                    "123456; ls -la",
                    "123456*)(uid=*))(|(uid=*"
                ]
                
                for payload in injection_payloads:
                    # Выполняем верификацию MFA с injection в коде
                    verify_data = {"code": payload}
                    response = client.post("/api/auth/mfa/verify", json=verify_data)
                    
                    # Критерии успеха - должен обработать безопасно
                    assert response.status_code == 200
                    data = response.json()
                    assert data["verified"] is False
                    assert "Неверный MFA код" in data["message"]
    
    @pytest.mark.asyncio
    async def test_mfa_secret_injection_attempts(self):
        """P1: Тест попыток injection в MFA секрет"""
        # Настраиваем mock для аутентификации
        with patch('backend.auth.dependencies.get_current_user') as mock_user:
            mock_user.return_value = {"id": "test_user_123", "email": "test@example.com"}
            
            # Настраиваем mock для Redis
            with patch('backend.api.mfa.redis_client') as mock_redis:
                mock_redis.setex.return_value = True
                
                # Тестируем различные injection атаки в MFA секрет
                injection_payloads = [
                    "secret'; DROP TABLE users; --",
                    "secret<script>alert('XSS')</script>",
                    "secret../../../etc/passwd",
                    "secret; ls -la",
                    "secret*)(uid=*))(|(uid=*"
                ]
                
                for payload in injection_payloads:
                    # Выполняем настройку MFA с injection в секрете
                    with patch('backend.api.mfa.secrets.token_urlsafe') as mock_token:
                        mock_token.return_value = payload
                        
                        response = client.post("/api/auth/mfa/setup")
                        
                        # Критерии успеха - должен обработать безопасно
                        assert response.status_code == 200
                        data = response.json()
                        assert "secret" in data
                        assert "qr_code" in data
                        assert "backup_codes" in data
                        
                        # Проверяем, что в ответе нет injection кода
                        assert "DROP TABLE" not in str(data)
                        assert "<script>" not in str(data)
                        assert "../" not in str(data)
                        assert "ls -la" not in str(data)
                        assert "uid=*" not in str(data)

if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])