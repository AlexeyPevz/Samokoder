#!/usr/bin/env python3
"""
Тесты для Database Config
"""

import pytest
from backend.core.database_config import DatabaseConfig, db_config


class TestDatabaseConfig:
    """Тесты для DatabaseConfig"""
    
    def test_init(self):
        """Тест инициализации DatabaseConfig"""
        config = DatabaseConfig()
        
        # Проверяем что все атрибуты существуют
        assert hasattr(config, 'TABLES')
        assert hasattr(config, 'COLUMNS')
        assert hasattr(config, 'QUERIES')
        assert hasattr(config, 'PAGINATION')
        assert hasattr(config, 'STATUS')
        assert hasattr(config, 'SUBSCRIPTION_TIERS')
        assert hasattr(config, 'SUBSCRIPTION_STATUSES')
        assert hasattr(config, 'CHAT_ROLES')
        assert hasattr(config, 'AI_PROVIDERS')
        assert hasattr(config, 'THEMES')
    
    def test_tables_structure(self):
        """Тест структуры таблиц"""
        tables = DatabaseConfig.TABLES
        
        assert isinstance(tables, dict)
        assert len(tables) > 0
        
        # Проверяем основные таблицы
        expected_tables = [
            "profiles", "user_settings", "ai_providers", "projects",
            "chat_sessions", "chat_messages", "api_keys", "files", "ai_usage"
        ]
        
        for table in expected_tables:
            assert table in tables
            assert isinstance(tables[table], str)
            assert tables[table] == table  # Имена таблиц совпадают с ключами
    
    def test_columns_structure(self):
        """Тест структуры колонок"""
        columns = DatabaseConfig.COLUMNS
        
        assert isinstance(columns, dict)
        assert len(columns) > 0
        
        # Проверяем основные колонки
        expected_columns = [
            "id", "user_id", "project_id", "session_id",
            "email", "created_at", "updated_at", "is_active"
        ]
        
        for column in expected_columns:
            assert column in columns
            assert isinstance(columns[column], str)
            assert columns[column] == column  # Имена колонок совпадают с ключами
    
    def test_queries_structure(self):
        """Тест структуры запросов"""
        queries = DatabaseConfig.QUERIES
        
        assert isinstance(queries, dict)
        assert len(queries) > 0
        
        # Проверяем основные запросы
        expected_queries = [
            "select_all", "count_exact", "order_created_desc", "order_updated_desc"
        ]
        
        for query in expected_queries:
            assert query in queries
            assert isinstance(queries[query], str)
        
        # Проверяем конкретные значения
        assert queries["select_all"] == "*"
        assert queries["count_exact"] == "id"
        assert queries["order_created_desc"] == "created_at"
        assert queries["order_updated_desc"] == "updated_at"
    
    def test_pagination_structure(self):
        """Тест структуры пагинации"""
        pagination = DatabaseConfig.PAGINATION
        
        assert isinstance(pagination, dict)
        assert len(pagination) > 0
        
        # Проверяем основные параметры пагинации
        expected_params = ["default_limit", "max_limit", "default_offset"]
        
        for param in expected_params:
            assert param in pagination
            assert isinstance(pagination[param], int)
        
        # Проверяем конкретные значения
        assert pagination["default_limit"] == 10
        assert pagination["max_limit"] == 100
        assert pagination["default_offset"] == 0
    
    def test_status_structure(self):
        """Тест структуры статусов"""
        status = DatabaseConfig.STATUS
        
        assert isinstance(status, dict)
        assert len(status) > 0
        
        # Проверяем основные статусы
        expected_statuses = ["active", "inactive", "deleted"]
        
        for status_value in expected_statuses:
            assert status_value in status
            assert isinstance(status[status_value], str)
            assert status[status_value] == status_value
    
    def test_subscription_tiers_structure(self):
        """Тест структуры уровней подписки"""
        tiers = DatabaseConfig.SUBSCRIPTION_TIERS
        
        assert isinstance(tiers, dict)
        assert len(tiers) > 0
        
        # Проверяем основные уровни
        expected_tiers = ["free", "starter", "professional", "business", "enterprise"]
        
        for tier in expected_tiers:
            assert tier in tiers
            assert isinstance(tiers[tier], str)
            assert tiers[tier] == tier
    
    def test_subscription_statuses_structure(self):
        """Тест структуры статусов подписки"""
        statuses = DatabaseConfig.SUBSCRIPTION_STATUSES
        
        assert isinstance(statuses, dict)
        assert len(statuses) > 0
        
        # Проверяем основные статусы подписки
        expected_statuses = ["active", "canceled", "past_due", "trialing"]
        
        for status in expected_statuses:
            assert status in statuses
            assert isinstance(statuses[status], str)
            assert statuses[status] == status
    
    def test_chat_roles_structure(self):
        """Тест структуры ролей чата"""
        roles = DatabaseConfig.CHAT_ROLES
        
        assert isinstance(roles, dict)
        assert len(roles) > 0
        
        # Проверяем основные роли
        expected_roles = ["user", "assistant", "system"]
        
        for role in expected_roles:
            assert role in roles
            assert isinstance(roles[role], str)
            assert roles[role] == role
    
    def test_ai_providers_structure(self):
        """Тест структуры AI провайдеров"""
        providers = DatabaseConfig.AI_PROVIDERS
        
        assert isinstance(providers, dict)
        assert len(providers) > 0
        
        # Проверяем основные провайдеры
        expected_providers = ["openrouter", "openai", "anthropic", "groq"]
        
        for provider in expected_providers:
            assert provider in providers
            assert isinstance(providers[provider], str)
            assert providers[provider] == provider
    
    def test_themes_structure(self):
        """Тест структуры тем"""
        themes = DatabaseConfig.THEMES
        
        assert isinstance(themes, dict)
        assert len(themes) > 0
        
        # Проверяем основные темы
        expected_themes = ["light", "dark", "auto"]
        
        for theme in expected_themes:
            assert theme in themes
            assert isinstance(themes[theme], str)
            assert themes[theme] == theme
    
    def test_immutability(self):
        """Тест неизменяемости конфигурации"""
        # Проверяем что конфигурация не может быть изменена случайно
        original_tables = DatabaseConfig.TABLES.copy()
        original_columns = DatabaseConfig.COLUMNS.copy()
        
        # Попытка изменить не должна влиять на оригинальную конфигурацию
        config = DatabaseConfig()
        
        assert config.TABLES == original_tables
        assert config.COLUMNS == original_columns
    
    def test_consistency(self):
        """Тест согласованности конфигурации"""
        # Проверяем что все значения строковые и не пустые
        config = DatabaseConfig()
        
        for attr_name in ['TABLES', 'COLUMNS', 'QUERIES', 'STATUS', 
                         'SUBSCRIPTION_TIERS', 'SUBSCRIPTION_STATUSES', 
                         'CHAT_ROLES', 'AI_PROVIDERS', 'THEMES']:
            attr_value = getattr(config, attr_name)
            assert isinstance(attr_value, dict)
            
            for key, value in attr_value.items():
                assert isinstance(key, str)
                assert isinstance(value, str)
                assert len(key) > 0
                assert len(value) > 0
        
        # Проверяем что PAGINATION содержит числа
        pagination = config.PAGINATION
        for key, value in pagination.items():
            assert isinstance(key, str)
            assert isinstance(value, int)
            assert value >= 0


class TestGlobalDatabaseConfig:
    """Тесты для глобального экземпляра db_config"""
    
    def test_global_instance_exists(self):
        """Тест существования глобального экземпляра"""
        assert db_config is not None
        assert isinstance(db_config, DatabaseConfig)
    
    def test_global_instance_consistency(self):
        """Тест согласованности глобального экземпляра"""
        # Проверяем что глобальный экземпляр имеет те же данные
        config = DatabaseConfig()
        
        assert db_config.TABLES == config.TABLES
        assert db_config.COLUMNS == config.COLUMNS
        assert db_config.QUERIES == config.QUERIES
        assert db_config.PAGINATION == config.PAGINATION
        assert db_config.STATUS == config.STATUS
        assert db_config.SUBSCRIPTION_TIERS == config.SUBSCRIPTION_TIERS
        assert db_config.SUBSCRIPTION_STATUSES == config.SUBSCRIPTION_STATUSES
        assert db_config.CHAT_ROLES == config.CHAT_ROLES
        assert db_config.AI_PROVIDERS == config.AI_PROVIDERS
        assert db_config.THEMES == config.THEMES
    
    def test_global_instance_singleton_behavior(self):
        """Тест поведения синглтона глобального экземпляра"""
        from backend.core.database_config import db_config as db_config_2
        
        # Проверяем что это один и тот же объект
        assert db_config is db_config_2