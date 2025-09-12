#!/usr/bin/env python3
"""
Тесты для Database Models
"""

import pytest
from backend.models.database import (
    Base, Profile, UserSetting, AIProvider, Project, 
    ChatSession, ChatMessage, APIKey, File, AIUsage
)


class TestDatabaseModels:
    """Тесты для SQLAlchemy моделей базы данных"""
    
    def test_base_exists(self):
        """Тест существования Base класса"""
        assert Base is not None
        assert hasattr(Base, 'metadata')
    
    def test_profile_model(self):
        """Тест модели Profile"""
        assert Profile is not None
        assert hasattr(Profile, '__tablename__')
        assert Profile.__tablename__ == 'profiles'
        assert hasattr(Profile, 'id')
        assert hasattr(Profile, 'email')
        assert hasattr(Profile, 'full_name')
    
    def test_user_setting_model(self):
        """Тест модели UserSetting"""
        assert UserSetting is not None
        assert hasattr(UserSetting, '__tablename__')
        assert UserSetting.__tablename__ == 'user_settings'
        assert hasattr(UserSetting, 'id')
        assert hasattr(UserSetting, 'user_id')
    
    def test_ai_provider_model(self):
        """Тест модели AIProvider"""
        assert AIProvider is not None
        assert hasattr(AIProvider, '__tablename__')
        assert AIProvider.__tablename__ == 'ai_providers'
        assert hasattr(AIProvider, 'id')
        assert hasattr(AIProvider, 'name')
    
    def test_project_model(self):
        """Тест модели Project"""
        assert Project is not None
        assert hasattr(Project, '__tablename__')
        assert Project.__tablename__ == 'projects'
        assert hasattr(Project, 'id')
        assert hasattr(Project, 'user_id')
    
    def test_chat_session_model(self):
        """Тест модели ChatSession"""
        assert ChatSession is not None
        assert hasattr(ChatSession, '__tablename__')
        assert ChatSession.__tablename__ == 'chat_sessions'
        assert hasattr(ChatSession, 'id')
        assert hasattr(ChatSession, 'project_id')
    
    def test_chat_message_model(self):
        """Тест модели ChatMessage"""
        assert ChatMessage is not None
        assert hasattr(ChatMessage, '__tablename__')
        assert ChatMessage.__tablename__ == 'chat_messages'
        assert hasattr(ChatMessage, 'id')
        assert hasattr(ChatMessage, 'session_id')
    
    def test_api_key_model(self):
        """Тест модели APIKey"""
        assert APIKey is not None
        assert hasattr(APIKey, '__tablename__')
        assert APIKey.__tablename__ == 'api_keys'
        assert hasattr(APIKey, 'id')
        assert hasattr(APIKey, 'user_id')
    
    def test_file_model(self):
        """Тест модели File"""
        assert File is not None
        assert hasattr(File, '__tablename__')
        assert File.__tablename__ == 'files'
        assert hasattr(File, 'id')
        assert hasattr(File, 'project_id')
    
    def test_ai_usage_model(self):
        """Тест модели AIUsage"""
        assert AIUsage is not None
        assert hasattr(AIUsage, '__tablename__')
        assert AIUsage.__tablename__ == 'ai_usage'
        assert hasattr(AIUsage, 'id')
        assert hasattr(AIUsage, 'user_id')
    
    def test_model_inheritance(self):
        """Тест наследования от Base"""
        models = [Profile, UserSetting, AIProvider, Project, ChatSession, ChatMessage, APIKey, File, AIUsage]
        for model in models:
            assert issubclass(model, Base)
    
    def test_model_metadata(self):
        """Тест метаданных моделей"""
        assert 'profiles' in Base.metadata.tables
        assert 'user_settings' in Base.metadata.tables
        assert 'ai_providers' in Base.metadata.tables
        assert 'projects' in Base.metadata.tables
        assert 'chat_sessions' in Base.metadata.tables
        assert 'chat_messages' in Base.metadata.tables
        assert 'api_keys' in Base.metadata.tables
        assert 'files' in Base.metadata.tables
        assert 'ai_usage' in Base.metadata.tables
    
    def test_column_types(self):
        """Тест типов колонок"""
        profile_table = Base.metadata.tables['profiles']
        assert profile_table.columns['email'].type.python_type == str
    
    def test_foreign_keys(self):
        """Тест внешних ключей"""
        user_setting_table = Base.metadata.tables['user_settings']
        user_id_fk = user_setting_table.foreign_keys
        fk_columns = [fk.column for fk in user_id_fk]
        assert len(fk_columns) >= 1
    
    def test_unique_constraints(self):
        """Тест уникальных ограничений"""
        profile_table = Base.metadata.tables['profiles']
        email_column = profile_table.columns['email']
        assert email_column.unique is True
    
    def test_check_constraints(self):
        """Тест ограничений проверки"""
        assert hasattr(Profile, '__table_args__')
        assert hasattr(UserSetting, '__table_args__')
        assert hasattr(ChatMessage, '__table_args__')
        assert hasattr(APIKey, '__table_args__')
        assert hasattr(AIUsage, '__table_args__')
    
    def test_default_values(self):
        """Тест значений по умолчанию"""
        profile_table = Base.metadata.tables['profiles']
        subscription_tier_col = profile_table.columns['subscription_tier']
        assert subscription_tier_col.default.arg == 'free'
    
    def test_nullable_constraints(self):
        """Тест ограничений nullable"""
        profile_table = Base.metadata.tables['profiles']
        email_col = profile_table.columns['email']
        assert email_col.nullable is False
        full_name_col = profile_table.columns['full_name']
        assert full_name_col.nullable is True
    
    def test_table_names_consistency(self):
        """Тест согласованности имен таблиц"""
        expected_tables = [
            'profiles', 'user_settings', 'ai_providers', 'projects',
            'chat_sessions', 'chat_messages', 'api_keys', 'files', 'ai_usage'
        ]
        actual_tables = list(Base.metadata.tables.keys())
        for table_name in expected_tables:
            assert table_name in actual_tables
    
    def test_model_relationships(self):
        """Тест связей между моделями"""
        profile_table = Base.metadata.tables['profiles']
        user_setting_table = Base.metadata.tables['user_settings']
        user_settings_fks = user_setting_table.foreign_keys
        profile_fk_exists = any(
            fk.column.table.name == 'profiles' and fk.column.name == 'id'
            for fk in user_settings_fks
        )
        assert profile_fk_exists
    
    def test_import_structure(self):
        """Тест структуры импортов"""
        from sqlalchemy import Column, String, Integer, Boolean, DateTime, Text, JSON, DECIMAL, ForeignKey, UniqueConstraint, CheckConstraint
        from sqlalchemy.dialects.postgresql import UUID
        from sqlalchemy.ext.declarative import declarative_base
        from sqlalchemy.sql import func
        import uuid
        
        assert Column is not None
        assert String is not None
        assert Integer is not None
        assert Boolean is not None
        assert DateTime is not None
        assert Text is not None
        assert JSON is not None
        assert DECIMAL is not None
        assert ForeignKey is not None
        assert UniqueConstraint is not None
        assert CheckConstraint is not None
        assert UUID is not None
        assert declarative_base is not None
        assert func is not None
        assert uuid is not None
