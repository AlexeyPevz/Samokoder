"""
P1: Регрессионные тесты AI сервиса
Важные тесты, требующие внимания перед релизом
"""

import pytest
import json
import uuid
from datetime import datetime, timedelta
from fastapi.testclient import TestClient
from unittest.mock import patch, MagicMock, AsyncMock
from backend.main import app
from backend.auth.dependencies import get_current_user

client = TestClient(app)

# Тестовые данные
TEST_USER = {
    "id": "test_user_123",
    "email": "test@example.com",
    "full_name": "Test User"
}

class TestAIChatFlow:
    """P1: Тесты чата с AI"""
    
    def test_ai_chat_success(self):
        """P1: Успешный чат с AI"""
        chat_data = {
            "message": "Создай простое React приложение",
            "model": "deepseek/deepseek-v3",
            "provider": "openrouter"
        }
        
        with patch('backend.main.get_current_user') as mock_auth, \
             patch('backend.main.get_ai_service') as mock_ai_service, \
             patch('backend.main.supabase_manager') as mock_manager:
            
            mock_auth.return_value = TEST_USER
            
            # Мокаем AI сервис
            mock_ai_instance = MagicMock()
            mock_ai_instance.route_request = AsyncMock(return_value=MagicMock(
                content="Вот простое React приложение:\n\n```jsx\nimport React from 'react';\n\nfunction App() {\n  return (\n    <div>\n      <h1>Hello World!</h1>\n    </div>\n  );\n}\n\nexport default App;\n```",
                provider="openrouter",
                model="deepseek/deepseek-v3",
                tokens_used=150,
                cost_usd=0.001,
                success=True,
                response_time=1.5
            ))
            mock_ai_service.return_value = mock_ai_instance
            
            # Мокаем Supabase
            mock_manager.execute_supabase_operation = AsyncMock(return_value=MagicMock(
                data=[]
            ))
            
            response = client.post("/api/ai/chat", json=chat_data)
            
            # Проверяем успешный ответ
            assert response.status_code == 200
            data = response.json()
            assert "content" in data
            assert "provider" in data
            assert "model" in data
            assert "tokens_used" in data
            assert "cost_usd" in data
            assert "response_time" in data
            assert data["provider"] == "openrouter"
            assert data["model"] == "deepseek/deepseek-v3"
    
    def test_ai_chat_validation(self):
        """P1: Валидация данных чата с AI"""
        # Тест с пустым сообщением
        response = client.post("/api/ai/chat", json={"message": ""})
        assert response.status_code == 400
        
        # Тест без сообщения
        response = client.post("/api/ai/chat", json={})
        assert response.status_code == 400
        
        # Тест с невалидными данными
        invalid_data = {
            "message": None,
            "model": 123,  # Должно быть строкой
            "provider": []  # Должно быть строкой
        }
        response = client.post("/api/ai/chat", json=invalid_data)
        assert response.status_code == 400
    
    def test_ai_chat_different_models(self):
        """P1: Чат с разными AI моделями"""
        models = [
            "deepseek/deepseek-v3",
            "gpt-4o-mini",
            "claude-3-haiku",
            "llama-3-8b-8192"
        ]
        
        for model in models:
            chat_data = {
                "message": f"Тест с моделью {model}",
                "model": model,
                "provider": "openrouter"
            }
            
            with patch('backend.main.get_current_user') as mock_auth, \
                 patch('backend.main.get_ai_service') as mock_ai_service, \
                 patch('backend.main.supabase_manager') as mock_manager:
                
                mock_auth.return_value = TEST_USER
                
                mock_ai_instance = MagicMock()
                mock_ai_instance.route_request = AsyncMock(return_value=MagicMock(
                    content=f"Ответ от модели {model}",
                    provider="openrouter",
                    model=model,
                    tokens_used=100,
                    cost_usd=0.001,
                    success=True,
                    response_time=1.0
                ))
                mock_ai_service.return_value = mock_ai_instance
                
                mock_manager.execute_supabase_operation = AsyncMock(return_value=MagicMock(
                    data=[]
                ))
                
                response = client.post("/api/ai/chat", json=chat_data)
                
                # Проверяем успешный ответ
                assert response.status_code == 200
                data = response.json()
                assert data["model"] == model
    
    def test_ai_chat_error_handling(self):
        """P1: Обработка ошибок AI сервиса"""
        chat_data = {
            "message": "Тест ошибки",
            "model": "deepseek/deepseek-v3",
            "provider": "openrouter"
        }
        
        with patch('backend.main.get_current_user') as mock_auth, \
             patch('backend.main.get_ai_service') as mock_ai_service, \
             patch('backend.main.supabase_manager') as mock_manager:
            
            mock_auth.return_value = TEST_USER
            
            # Мокаем ошибку AI сервиса
            mock_ai_instance = MagicMock()
            mock_ai_instance.route_request = AsyncMock(return_value=MagicMock(
                content="",
                provider="openrouter",
                model="deepseek/deepseek-v3",
                tokens_used=0,
                cost_usd=0.0,
                success=False,
                error="AI service unavailable",
                response_time=0.0
            ))
            mock_ai_service.return_value = mock_ai_instance
            
            mock_manager.execute_supabase_operation = AsyncMock(return_value=MagicMock(
                data=[]
            ))
            
            response = client.post("/api/ai/chat", json=chat_data)
            
            # Проверяем обработку ошибки
            assert response.status_code == 500
            data = response.json()
            assert "detail" in data

class TestAIStreamingFlow:
    """P1: Тесты потокового чата с AI"""
    
    def test_ai_stream_chat_success(self):
        """P1: Успешный потоковый чат с AI"""
        chat_data = {
            "message": "Создай компонент React",
            "model": "deepseek/deepseek-v3",
            "provider": "openrouter"
        }
        
        with patch('backend.main.get_current_user') as mock_auth, \
             patch('backend.main.get_ai_service') as mock_ai_service, \
             patch('backend.main.supabase_manager') as mock_manager:
            
            mock_auth.return_value = TEST_USER
            
            # Мокаем потоковый AI сервис
            mock_ai_instance = MagicMock()
            
            async def mock_stream():
                chunks = [
                    {"type": "content", "content": "Вот компонент React:\n\n"},
                    {"type": "content", "content": "```jsx\n"},
                    {"type": "content", "content": "import React from 'react';\n"},
                    {"type": "content", "content": "```\n"},
                    {"type": "done", "content": ""}
                ]
                for chunk in chunks:
                    yield chunk
            
            mock_ai_instance.chat_completion_stream = AsyncMock(return_value=mock_stream())
            mock_ai_service.return_value = mock_ai_instance
            
            mock_manager.execute_supabase_operation = AsyncMock(return_value=MagicMock(
                data=[]
            ))
            
            response = client.post("/api/ai/chat/stream", json=chat_data)
            
            # Проверяем потоковый ответ
            assert response.status_code == 200
            assert response.headers["content-type"] == "text/plain; charset=utf-8"
            assert response.headers["cache-control"] == "no-cache"
            assert response.headers["connection"] == "keep-alive"
    
    def test_ai_stream_chat_error(self):
        """P1: Обработка ошибок в потоковом чате"""
        chat_data = {
            "message": "Тест ошибки",
            "model": "deepseek/deepseek-v3",
            "provider": "openrouter"
        }
        
        with patch('backend.main.get_current_user') as mock_auth, \
             patch('backend.main.get_ai_service') as mock_ai_service, \
             patch('backend.main.supabase_manager') as mock_manager:
            
            mock_auth.return_value = TEST_USER
            
            # Мокаем ошибку в потоковом сервисе
            mock_ai_instance = MagicMock()
            
            async def mock_error_stream():
                yield {"type": "error", "content": "AI service error"}
            
            mock_ai_instance.chat_completion_stream = AsyncMock(return_value=mock_error_stream())
            mock_ai_service.return_value = mock_ai_instance
            
            mock_manager.execute_supabase_operation = AsyncMock(return_value=MagicMock(
                data=[]
            ))
            
            response = client.post("/api/ai/chat/stream", json=chat_data)
            
            # Проверяем обработку ошибки
            assert response.status_code == 200  # Потоковый ответ всегда 200
            content = response.text
            assert "error" in content

class TestAIUsageTracking:
    """P1: Тесты отслеживания использования AI"""
    
    def test_ai_usage_stats(self):
        """P1: Получение статистики использования AI"""
        with patch('backend.main.get_current_user') as mock_auth, \
             patch('backend.main.supabase_manager') as mock_manager:
            
            mock_auth.return_value = TEST_USER
            
            # Мокаем данные использования
            usage_data = [
                {
                    "provider": "openrouter",
                    "tokens_used": 1000,
                    "cost": 0.01,
                    "created_at": datetime.now().isoformat()
                },
                {
                    "provider": "openai",
                    "tokens_used": 500,
                    "cost": 0.005,
                    "created_at": datetime.now().isoformat()
                }
            ]
            
            mock_manager.execute_supabase_operation = AsyncMock(return_value=MagicMock(
                data=usage_data
            ))
            
            response = client.get("/api/ai/usage")
            
            # Проверяем получение статистики
            assert response.status_code == 200
            data = response.json()
            assert "total_tokens" in data
            assert "total_cost" in data
            assert "total_requests" in data
            assert "period_days" in data
            assert "provider_stats" in data
            
            assert data["total_tokens"] == 1500
            assert data["total_cost"] == 0.015
            assert data["total_requests"] == 2
    
    def test_ai_usage_stats_period(self):
        """P1: Статистика использования за определённый период"""
        with patch('backend.main.get_current_user') as mock_auth, \
             patch('backend.main.supabase_manager') as mock_manager:
            
            mock_auth.return_value = TEST_USER
            
            # Мокаем пустые данные
            mock_manager.execute_supabase_operation = AsyncMock(return_value=MagicMock(
                data=[]
            ))
            
            response = client.get("/api/ai/usage?days=7")
            
            # Проверяем статистику за 7 дней
            assert response.status_code == 200
            data = response.json()
            assert data["period_days"] == 7
            assert data["total_tokens"] == 0
            assert data["total_cost"] == 0.0
    
    def test_ai_usage_stats_provider_breakdown(self):
        """P1: Разбивка статистики по провайдерам"""
        with patch('backend.main.get_current_user') as mock_auth, \
             patch('backend.main.supabase_manager') as mock_manager:
            
            mock_auth.return_value = TEST_USER
            
            # Мокаем данные с разными провайдерами
            usage_data = [
                {
                    "provider": "openrouter",
                    "tokens_used": 1000,
                    "cost": 0.01,
                    "created_at": datetime.now().isoformat()
                },
                {
                    "provider": "openrouter",
                    "tokens_used": 500,
                    "cost": 0.005,
                    "created_at": datetime.now().isoformat()
                },
                {
                    "provider": "openai",
                    "tokens_used": 2000,
                    "cost": 0.02,
                    "created_at": datetime.now().isoformat()
                }
            ]
            
            mock_manager.execute_supabase_operation = AsyncMock(return_value=MagicMock(
                data=usage_data
            ))
            
            response = client.get("/api/ai/usage")
            
            # Проверяем разбивку по провайдерам
            assert response.status_code == 200
            data = response.json()
            provider_stats = data["provider_stats"]
            
            assert "openrouter" in provider_stats
            assert "openai" in provider_stats
            
            assert provider_stats["openrouter"]["tokens"] == 1500
            assert provider_stats["openrouter"]["cost"] == 0.015
            assert provider_stats["openrouter"]["requests"] == 2
            
            assert provider_stats["openai"]["tokens"] == 2000
            assert provider_stats["openai"]["cost"] == 0.02
            assert provider_stats["openai"]["requests"] == 1

class TestAIProviders:
    """P1: Тесты AI провайдеров"""
    
    def test_ai_providers_list(self):
        """P1: Получение списка AI провайдеров"""
        with patch('backend.main.get_current_user') as mock_auth, \
             patch('backend.main.supabase_manager') as mock_manager:
            
            mock_auth.return_value = TEST_USER
            
            # Мокаем список провайдеров
            providers_data = [
                {
                    "id": "openrouter",
                    "name": "OpenRouter",
                    "display_name": "OpenRouter",
                    "website_url": "https://openrouter.ai",
                    "documentation_url": "https://openrouter.ai/docs",
                    "requires_api_key": True,
                    "pricing_info": {"per_token": 0.0001}
                },
                {
                    "id": "openai",
                    "name": "OpenAI",
                    "display_name": "OpenAI",
                    "website_url": "https://openai.com",
                    "documentation_url": "https://platform.openai.com/docs",
                    "requires_api_key": True,
                    "pricing_info": {"per_token": 0.0002}
                }
            ]
            
            mock_manager.execute_supabase_operation = AsyncMock(return_value=MagicMock(
                data=providers_data
            ))
            
            response = client.get("/api/ai/providers")
            
            # Проверяем получение списка провайдеров
            assert response.status_code == 200
            data = response.json()
            assert "providers" in data
            assert len(data["providers"]) == 2
            
            openrouter = next(p for p in data["providers"] if p["id"] == "openrouter")
            assert openrouter["name"] == "OpenRouter"
            assert openrouter["requires_api_key"] == True
    
    def test_ai_providers_active_only(self):
        """P1: Получение только активных провайдеров"""
        with patch('backend.main.get_current_user') as mock_auth, \
             patch('backend.main.supabase_manager') as mock_manager:
            
            mock_auth.return_value = TEST_USER
            
            # Мокаем провайдеров с разным статусом
            providers_data = [
                {
                    "id": "openrouter",
                    "name": "OpenRouter",
                    "is_active": True
                },
                {
                    "id": "inactive_provider",
                    "name": "Inactive Provider",
                    "is_active": False
                }
            ]
            
            mock_manager.execute_supabase_operation = AsyncMock(return_value=MagicMock(
                data=[p for p in providers_data if p["is_active"]]
            ))
            
            response = client.get("/api/ai/providers")
            
            # Проверяем, что возвращаются только активные провайдеры
            assert response.status_code == 200
            data = response.json()
            assert len(data["providers"]) == 1
            assert data["providers"][0]["id"] == "openrouter"

class TestAIKeyValidation:
    """P1: Тесты валидации AI ключей"""
    
    def test_ai_keys_validation_success(self):
        """P1: Успешная валидация AI ключей"""
        keys_data = {
            "openrouter": "sk-or-v1-valid-key",
            "openai": "sk-valid-key"
        }
        
        with patch('backend.main.get_current_user') as mock_auth, \
             patch('backend.main.get_ai_service') as mock_ai_service:
            
            mock_auth.return_value = TEST_USER
            
            # Мокаем AI сервис
            mock_ai_instance = MagicMock()
            mock_ai_instance.validate_all_keys = AsyncMock(return_value={
                "openrouter": True,
                "openai": True
            })
            mock_ai_service.return_value = mock_ai_instance
            
            response = client.post("/api/ai/validate-keys", json=keys_data)
            
            # Проверяем успешную валидацию
            assert response.status_code == 200
            data = response.json()
            assert "validation_results" in data
            assert "valid_keys" in data
            assert "invalid_keys" in data
            
            assert data["validation_results"]["openrouter"] == True
            assert data["validation_results"]["openai"] == True
            assert len(data["valid_keys"]) == 2
            assert len(data["invalid_keys"]) == 0
    
    def test_ai_keys_validation_failure(self):
        """P1: Валидация невалидных AI ключей"""
        keys_data = {
            "openrouter": "invalid-key",
            "openai": "sk-invalid-key"
        }
        
        with patch('backend.main.get_current_user') as mock_auth, \
             patch('backend.main.get_ai_service') as mock_ai_service:
            
            mock_auth.return_value = TEST_USER
            
            # Мокаем AI сервис
            mock_ai_instance = MagicMock()
            mock_ai_instance.validate_all_keys = AsyncMock(return_value={
                "openrouter": False,
                "openai": False
            })
            mock_ai_service.return_value = mock_ai_instance
            
            response = client.post("/api/ai/validate-keys", json=keys_data)
            
            # Проверяем валидацию невалидных ключей
            assert response.status_code == 200
            data = response.json()
            
            assert data["validation_results"]["openrouter"] == False
            assert data["validation_results"]["openai"] == False
            assert len(data["valid_keys"]) == 0
            assert len(data["invalid_keys"]) == 2
    
    def test_ai_keys_validation_mixed(self):
        """P1: Валидация смешанных AI ключей"""
        keys_data = {
            "openrouter": "sk-or-v1-valid-key",
            "openai": "invalid-key",
            "anthropic": "sk-ant-valid-key"
        }
        
        with patch('backend.main.get_current_user') as mock_auth, \
             patch('backend.main.get_ai_service') as mock_ai_service:
            
            mock_auth.return_value = TEST_USER
            
            # Мокаем AI сервис
            mock_ai_instance = MagicMock()
            mock_ai_instance.validate_all_keys = AsyncMock(return_value={
                "openrouter": True,
                "openai": False,
                "anthropic": True
            })
            mock_ai_service.return_value = mock_ai_instance
            
            response = client.post("/api/ai/validate-keys", json=keys_data)
            
            # Проверяем смешанную валидацию
            assert response.status_code == 200
            data = response.json()
            
            assert data["validation_results"]["openrouter"] == True
            assert data["validation_results"]["openai"] == False
            assert data["validation_results"]["anthropic"] == True
            
            assert len(data["valid_keys"]) == 2
            assert len(data["invalid_keys"]) == 1
            assert "openai" in data["invalid_keys"]

class TestAIPerformance:
    """P1: Тесты производительности AI сервиса"""
    
    def test_ai_chat_response_time(self):
        """P1: Время ответа AI чата"""
        import time
        
        chat_data = {
            "message": "Быстрый тест",
            "model": "deepseek/deepseek-v3",
            "provider": "openrouter"
        }
        
        with patch('backend.main.get_current_user') as mock_auth, \
             patch('backend.main.get_ai_service') as mock_ai_service, \
             patch('backend.main.supabase_manager') as mock_manager:
            
            mock_auth.return_value = TEST_USER
            
            mock_ai_instance = MagicMock()
            mock_ai_instance.route_request = AsyncMock(return_value=MagicMock(
                content="Быстрый ответ",
                provider="openrouter",
                model="deepseek/deepseek-v3",
                tokens_used=50,
                cost_usd=0.0001,
                success=True,
                response_time=0.5
            ))
            mock_ai_service.return_value = mock_ai_instance
            
            mock_manager.execute_supabase_operation = AsyncMock(return_value=MagicMock(
                data=[]
            ))
            
            # Измеряем время ответа
            start_time = time.time()
            response = client.post("/api/ai/chat", json=chat_data)
            end_time = time.time()
            
            response_time = end_time - start_time
            
            # Проверяем, что ответ получен быстро (менее 3 секунд)
            assert response_time < 3.0
            assert response.status_code == 200
    
    def test_ai_chat_concurrent_requests(self):
        """P1: Обработка одновременных AI запросов"""
        import asyncio
        import concurrent.futures
        
        chat_data = {
            "message": "Тест одновременных запросов",
            "model": "deepseek/deepseek-v3",
            "provider": "openrouter"
        }
        
        def make_request():
            with patch('backend.main.get_current_user') as mock_auth, \
                 patch('backend.main.get_ai_service') as mock_ai_service, \
                 patch('backend.main.supabase_manager') as mock_manager:
                
                mock_auth.return_value = TEST_USER
                
                mock_ai_instance = MagicMock()
                mock_ai_instance.route_request = AsyncMock(return_value=MagicMock(
                    content="Ответ на одновременный запрос",
                    provider="openrouter",
                    model="deepseek/deepseek-v3",
                    tokens_used=100,
                    cost_usd=0.001,
                    success=True,
                    response_time=1.0
                ))
                mock_ai_service.return_value = mock_ai_instance
                
                mock_manager.execute_supabase_operation = AsyncMock(return_value=MagicMock(
                    data=[]
                ))
                
                response = client.post("/api/ai/chat", json=chat_data)
                return response.status_code
        
        # Делаем 5 одновременных запросов
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(make_request) for _ in range(5)]
            results = [future.result() for future in concurrent.futures.as_completed(futures)]
        
        # Проверяем, что все запросы успешны
        assert all(status == 200 for status in results)
        assert len(results) == 5

if __name__ == "__main__":
    # Запуск тестов
    pytest.main([__file__, "-v", "--tb=short", "-x"])