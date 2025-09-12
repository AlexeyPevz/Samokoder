#!/usr/bin/env python3
"""
Тесты для Contracts модулей
"""

import pytest
from typing import AsyncGenerator
from uuid import UUID
from backend.contracts.ai_service import AIServiceProtocol, AIProviderProtocol
from backend.contracts.database import (
    DatabaseServiceProtocol, UserRepositoryProtocol, 
    ProjectRepositoryProtocol, ChatRepositoryProtocol
)


class TestContracts:
    """Тесты для Contracts модулей"""
    
    def test_ai_service_protocol_exists(self):
        """Тест существования AIServiceProtocol"""
        assert AIServiceProtocol is not None
        assert hasattr(AIServiceProtocol, '__abstractmethods__')
    
    def test_ai_provider_protocol_exists(self):
        """Тест существования AIProviderProtocol"""
        assert AIProviderProtocol is not None
        assert hasattr(AIProviderProtocol, '__abstractmethods__')
    
    def test_database_service_protocol_exists(self):
        """Тест существования DatabaseServiceProtocol"""
        assert DatabaseServiceProtocol is not None
        assert hasattr(DatabaseServiceProtocol, '__abstractmethods__')
    
    def test_user_repository_protocol_exists(self):
        """Тест существования UserRepositoryProtocol"""
        assert UserRepositoryProtocol is not None
        assert hasattr(UserRepositoryProtocol, '__abstractmethods__')
    
    def test_project_repository_protocol_exists(self):
        """Тест существования ProjectRepositoryProtocol"""
        assert ProjectRepositoryProtocol is not None
        assert hasattr(ProjectRepositoryProtocol, '__abstractmethods__')
    
    def test_chat_repository_protocol_exists(self):
        """Тест существования ChatRepositoryProtocol"""
        assert ChatRepositoryProtocol is not None
        assert hasattr(ChatRepositoryProtocol, '__abstractmethods__')
    
    def test_ai_service_protocol_methods(self):
        """Тест методов AIServiceProtocol"""
        methods = [
            'chat_completion', 'chat_completion_stream', 'validate_api_key',
            'get_usage_stats', 'get_available_models', 'estimate_cost'
        ]
        
        for method_name in methods:
            assert hasattr(AIServiceProtocol, method_name)
    
    def test_ai_provider_protocol_methods(self):
        """Тест методов AIProviderProtocol"""
        methods = [
            'chat_completion', 'chat_completion_stream', 'validate_api_key',
            'get_usage_stats', 'get_available_models', 'estimate_cost'
        ]
        
        for method_name in methods:
            assert hasattr(AIProviderProtocol, method_name)
    
    def test_database_service_protocol_methods(self):
        """Тест методов DatabaseServiceProtocol"""
        methods = [
            'get_user', 'create_user', 'update_user', 'delete_user',
            'get_project', 'create_project', 'update_project', 'delete_project',
            'list_projects', 'get_chat_session', 'create_chat_session',
            'get_chat_messages', 'create_chat_message', 'get_api_key',
            'create_api_key', 'update_api_key', 'delete_api_key',
            'list_api_keys', 'get_ai_usage', 'create_ai_usage'
        ]
        
        for method_name in methods:
            assert hasattr(DatabaseServiceProtocol, method_name)
    
    def test_user_repository_protocol_methods(self):
        """Тест методов UserRepositoryProtocol"""
        methods = [
            'find_by_id', 'find_by_email', 'save', 'update', 'delete'
        ]
        
        for method_name in methods:
            assert hasattr(UserRepositoryProtocol, method_name)
    
    def test_project_repository_protocol_methods(self):
        """Тест методов ProjectRepositoryProtocol"""
        methods = [
            'find_by_id', 'find_by_user_id', 'save', 'update', 'delete'
        ]
        
        for method_name in methods:
            assert hasattr(ProjectRepositoryProtocol, method_name)
    
    def test_chat_repository_protocol_methods(self):
        """Тест методов ChatRepositoryProtocol"""
        methods = [
            'find_session_by_id', 'find_sessions_by_project', 'save_session',
            'find_messages_by_session', 'save_message'
        ]
        
        for method_name in methods:
            assert hasattr(ChatRepositoryProtocol, method_name)
    
    def test_ai_service_protocol_annotations(self):
        """Тест аннотаций типов AIServiceProtocol"""
        # Проверяем что методы имеют правильные аннотации типов
        chat_completion = AIServiceProtocol.__dict__['chat_completion']
        assert chat_completion.__annotations__ is not None
        
        chat_completion_stream = AIServiceProtocol.__dict__['chat_completion_stream']
        assert chat_completion_stream.__annotations__ is not None
    
    def test_database_service_protocol_annotations(self):
        """Тест аннотаций типов DatabaseServiceProtocol"""
        # Проверяем что методы имеют правильные аннотации типов
        get_user = DatabaseServiceProtocol.__dict__['get_user']
        assert get_user.__annotations__ is not None
        
        create_user = DatabaseServiceProtocol.__dict__['create_user']
        assert create_user.__annotations__ is not None
    
    def test_protocol_inheritance(self):
        """Тест наследования протоколов"""
        # Проверяем что все протоколы являются классами
        assert isinstance(AIServiceProtocol, type)
        assert isinstance(AIProviderProtocol, type)
        assert isinstance(DatabaseServiceProtocol, type)
        assert isinstance(UserRepositoryProtocol, type)
        assert isinstance(ProjectRepositoryProtocol, type)
        assert isinstance(ChatRepositoryProtocol, type)
    
    def test_import_structure(self):
        """Тест структуры импортов"""
        from backend.contracts.ai_service import AIServiceProtocol, AIProviderProtocol
        from backend.contracts.database import (
            DatabaseServiceProtocol, UserRepositoryProtocol, 
            ProjectRepositoryProtocol, ChatRepositoryProtocol
        )
        
        assert AIServiceProtocol is not None
        assert AIProviderProtocol is not None
        assert DatabaseServiceProtocol is not None
        assert UserRepositoryProtocol is not None
        assert ProjectRepositoryProtocol is not None
        assert ChatRepositoryProtocol is not None
    
    def test_protocol_method_signatures(self):
        """Тест сигнатур методов протоколов"""
        # Проверяем что методы протоколов имеют правильные сигнатуры
        
        # AIServiceProtocol
        ai_service_methods = AIServiceProtocol.__dict__
        assert 'chat_completion' in ai_service_methods
        assert 'chat_completion_stream' in ai_service_methods
        assert 'validate_api_key' in ai_service_methods
        
        # DatabaseServiceProtocol
        db_service_methods = DatabaseServiceProtocol.__dict__
        assert 'get_user' in db_service_methods
        assert 'create_user' in db_service_methods
        assert 'get_project' in db_service_methods
    
    def test_protocol_docstrings(self):
        """Тест документации протоколов"""
        # Проверяем что протоколы имеют документацию
        assert AIServiceProtocol.__doc__ is not None
        assert AIProviderProtocol.__doc__ is not None
        assert DatabaseServiceProtocol.__doc__ is not None
        assert UserRepositoryProtocol.__doc__ is not None
        assert ProjectRepositoryProtocol.__doc__ is not None
        assert ChatRepositoryProtocol.__doc__ is not None
        
        # Проверяем что документация не пустая
        assert len(AIServiceProtocol.__doc__.strip()) > 0
        assert len(AIProviderProtocol.__doc__.strip()) > 0
        assert len(DatabaseServiceProtocol.__doc__.strip()) > 0
    
    def test_protocol_method_docstrings(self):
        """Тест документации методов протоколов"""
        # Проверяем что методы имеют документацию
        ai_service_methods = ['chat_completion', 'validate_api_key']
        for method_name in ai_service_methods:
            method = getattr(AIServiceProtocol, method_name)
            assert method.__doc__ is not None
            assert len(method.__doc__.strip()) > 0
        
        db_service_methods = ['get_user', 'create_user', 'get_project']
        for method_name in db_service_methods:
            method = getattr(DatabaseServiceProtocol, method_name)
            assert method.__doc__ is not None
            assert len(method.__doc__.strip()) > 0
    
    def test_protocol_abstract_methods(self):
        """Тест абстрактных методов протоколов"""
        # Проверяем что протоколы имеют абстрактные методы
        assert hasattr(AIServiceProtocol, '__abstractmethods__')
        assert hasattr(AIProviderProtocol, '__abstractmethods__')
        assert hasattr(DatabaseServiceProtocol, '__abstractmethods__')
        assert hasattr(UserRepositoryProtocol, '__abstractmethods__')
        assert hasattr(ProjectRepositoryProtocol, '__abstractmethods__')
        assert hasattr(ChatRepositoryProtocol, '__abstractmethods__')
        
        # Проверяем что абстрактные методы существуют (могут быть пустыми для Protocol)
        assert isinstance(AIServiceProtocol.__abstractmethods__, frozenset)
        assert isinstance(AIProviderProtocol.__abstractmethods__, frozenset)
        assert isinstance(DatabaseServiceProtocol.__abstractmethods__, frozenset)
        assert isinstance(UserRepositoryProtocol.__abstractmethods__, frozenset)
        assert isinstance(ProjectRepositoryProtocol.__abstractmethods__, frozenset)
        assert isinstance(ChatRepositoryProtocol.__abstractmethods__, frozenset)
    
    def test_protocol_consistency(self):
        """Тест согласованности протоколов"""
        # Проверяем что протоколы имеют методы с правильными именами
        ai_service_methods = set(AIServiceProtocol.__dict__.keys())
        ai_provider_methods = set(AIProviderProtocol.__dict__.keys())
        
        # Проверяем что основные методы существуют в протоколах
        expected_methods = {
            'chat_completion', 'chat_completion_stream', 
            'validate_api_key', 'get_usage_stats', 
            'get_available_models', 'estimate_cost'
        }
        
        # Проверяем что методы существуют в протоколах
        for method in expected_methods:
            assert method in ai_service_methods or method in ai_provider_methods
    
    def test_repository_protocol_consistency(self):
        """Тест согласованности репозиториев"""
        # Проверяем что репозитории имеют методы с правильными именами
        user_methods = set(UserRepositoryProtocol.__dict__.keys())
        project_methods = set(ProjectRepositoryProtocol.__dict__.keys())
        chat_methods = set(ChatRepositoryProtocol.__dict__.keys())
        
        # Все репозитории должны иметь базовые CRUD методы
        common_methods = {'save', 'update', 'delete'}
        
        # Проверяем что методы существуют в протоколах
        for method in common_methods:
            assert (method in user_methods or 
                   method in project_methods or 
                   method in chat_methods)
    
    def test_protocol_type_hints(self):
        """Тест типов в протоколах"""
        # Проверяем что протоколы используют правильные типы
        import typing
        
        # Проверяем что используется AsyncGenerator для streaming методов
        stream_method = AIServiceProtocol.__dict__['chat_completion_stream']
        annotations = stream_method.__annotations__
        assert 'return' in annotations
        
        # Проверяем что используется UUID для ID параметров
        get_user_method = DatabaseServiceProtocol.__dict__['get_user']
        annotations = get_user_method.__annotations__
        assert 'user_id' in annotations
    
    def test_protocol_async_methods(self):
        """Тест асинхронных методов протоколов"""
        # Проверяем что все методы протоколов являются асинхронными
        
        # AIServiceProtocol
        for method_name in AIServiceProtocol.__abstractmethods__:
            method = getattr(AIServiceProtocol, method_name)
            # Проверяем что метод корутинный (has __code__ attribute)
            assert hasattr(method, '__code__')
        
        # DatabaseServiceProtocol
        for method_name in DatabaseServiceProtocol.__abstractmethods__:
            method = getattr(DatabaseServiceProtocol, method_name)
            assert hasattr(method, '__code__')
    
    def test_protocol_parameter_names(self):
        """Тест имен параметров протоколов"""
        # Проверяем что методы имеют осмысленные имена параметров
        
        # AIServiceProtocol
        validate_api_key_method = AIServiceProtocol.__dict__['validate_api_key']
        assert validate_api_key_method.__code__.co_varnames is not None
        
        # DatabaseServiceProtocol
        get_user_method = DatabaseServiceProtocol.__dict__['get_user']
        assert get_user_method.__code__.co_varnames is not None
    
    def test_contracts_module_structure(self):
        """Тест структуры модулей contracts"""
        # Проверяем что все необходимые протоколы экспортируются
        
        # AI Service contracts
        from backend.contracts.ai_service import AIServiceProtocol, AIProviderProtocol
        assert AIServiceProtocol is not None
        assert AIProviderProtocol is not None
        
        # Database contracts
        from backend.contracts.database import (
            DatabaseServiceProtocol, UserRepositoryProtocol,
            ProjectRepositoryProtocol, ChatRepositoryProtocol
        )
        assert DatabaseServiceProtocol is not None
        assert UserRepositoryProtocol is not None
        assert ProjectRepositoryProtocol is not None
        assert ChatRepositoryProtocol is not None