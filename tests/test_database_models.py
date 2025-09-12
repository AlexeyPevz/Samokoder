"""
Тесты для backend/models/database.py - SQLAlchemy модели
"""
import pytest
import uuid
from datetime import datetime, timezone
from decimal import Decimal
from sqlalchemy import create_engine, Column, String, Integer, Boolean, DateTime, Text, JSON, DECIMAL, ForeignKey, UniqueConstraint, CheckConstraint
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy.sql import func

from backend.models.database import (
    Base,
    Profile,
    UserSetting,
    AIProvider,
    Project,
    ChatSession,
    ChatMessage,
    APIKey,
    File,
    AIUsage
)


class TestDatabaseModels:
    """Тесты для SQLAlchemy моделей"""

    def setup_method(self):
        """Настройка перед каждым тестом"""
        # Создаем in-memory SQLite базу для тестов
        self.engine = create_engine('sqlite:///:memory:', echo=False)
        Base.metadata.create_all(self.engine)
        Session = sessionmaker(bind=self.engine)
        self.session = Session()

    def teardown_method(self):
        """Очистка после каждого теста"""
        self.session.close()

    def test_profile_model_creation(self):
        """Тест создания модели Profile"""
        # Arrange
        user_id = uuid.uuid4()
        email = "test@example.com"
        full_name = "Test User"
        
        # Act
        profile = Profile(
            id=user_id,
            email=email,
            full_name=full_name,
            subscription_tier="free",
            subscription_status="active"
        )
        self.session.add(profile)
        self.session.commit()
        
        # Assert
        saved_profile = self.session.query(Profile).filter_by(id=user_id).first()
        assert saved_profile is not None
        assert saved_profile.email == email
        assert saved_profile.full_name == full_name
        assert saved_profile.subscription_tier == "free"
        assert saved_profile.subscription_status == "active"
        assert saved_profile.api_credits_balance == Decimal('0.00')

    def test_profile_model_constraints(self):
        """Тест ограничений модели Profile"""
        # Test valid subscription_tier
        profile = Profile(
            email="test@example.com",
            subscription_tier="professional",
            subscription_status="active"
        )
        self.session.add(profile)
        self.session.commit()
        
        # Test valid subscription_status
        profile2 = Profile(
            email="test2@example.com",
            subscription_tier="free",
            subscription_status="trialing"
        )
        self.session.add(profile2)
        self.session.commit()
        
        # Test invalid subscription_tier should fail
        profile3 = Profile(
            email="test3@example.com",
            subscription_tier="invalid",
            subscription_status="active"
        )
        self.session.add(profile3)
        with pytest.raises(Exception):  # SQLAlchemy constraint violation
            self.session.commit()

    def test_user_setting_model_creation(self):
        """Тест создания модели UserSetting"""
        # Arrange
        user_id = uuid.uuid4()
        profile = Profile(id=user_id, email="test@example.com")
        self.session.add(profile)
        self.session.commit()
        
        # Act
        setting = UserSetting(
            user_id=user_id,
            default_model="gpt-4",
            default_provider="openai",
            theme="dark"
        )
        self.session.add(setting)
        self.session.commit()
        
        # Assert
        saved_setting = self.session.query(UserSetting).filter_by(user_id=user_id).first()
        assert saved_setting is not None
        assert saved_setting.default_model == "gpt-4"
        assert saved_setting.default_provider == "openai"
        assert saved_setting.theme == "dark"
        assert saved_setting.auto_export is False
        assert saved_setting.notifications_email is True

    def test_user_setting_unique_constraint(self):
        """Тест уникальности user_id в UserSetting"""
        user_id = uuid.uuid4()
        profile = Profile(id=user_id, email="test@example.com")
        self.session.add(profile)
        self.session.commit()
        
        # Первая настройка
        setting1 = UserSetting(user_id=user_id, default_model="gpt-4")
        self.session.add(setting1)
        self.session.commit()
        
        # Вторая настройка с тем же user_id должна вызвать ошибку
        setting2 = UserSetting(user_id=user_id, default_model="gpt-3")
        self.session.add(setting2)
        with pytest.raises(Exception):  # Unique constraint violation
            self.session.commit()

    def test_ai_provider_model_creation(self):
        """Тест создания модели AIProvider"""
        # Act
        provider = AIProvider(
            name="openai",
            display_name="OpenAI",
            website_url="https://openai.com",
            requires_api_key=True,
            is_active=True,
            pricing_info={"input": 0.001, "output": 0.002}
        )
        self.session.add(provider)
        self.session.commit()
        
        # Assert
        saved_provider = self.session.query(AIProvider).filter_by(name="openai").first()
        assert saved_provider is not None
        assert saved_provider.display_name == "OpenAI"
        assert saved_provider.website_url == "https://openai.com"
        assert saved_provider.requires_api_key is True
        assert saved_provider.is_active is True
        assert saved_provider.pricing_info == {"input": 0.001, "output": 0.002}

    def test_project_model_creation(self):
        """Тест создания модели Project"""
        # Arrange
        user_id = uuid.uuid4()
        project_id = uuid.uuid4()
        profile = Profile(id=user_id, email="test@example.com")
        self.session.add(profile)
        self.session.commit()
        
        # Act
        project = Project(
            id=project_id,
            user_id=user_id,
            name="Test Project",
            description="Test Description",
            ai_config={"model": "gpt-4", "temperature": 0.7},
            workspace_path="/workspace/test",
            is_active=True
        )
        self.session.add(project)
        self.session.commit()
        
        # Assert
        saved_project = self.session.query(Project).filter_by(id=project_id).first()
        assert saved_project is not None
        assert saved_project.name == "Test Project"
        assert saved_project.description == "Test Description"
        assert saved_project.ai_config == {"model": "gpt-4", "temperature": 0.7}
        assert saved_project.workspace_path == "/workspace/test"
        assert saved_project.is_active is True

    def test_chat_session_model_creation(self):
        """Тест создания модели ChatSession"""
        # Arrange
        user_id = uuid.uuid4()
        project_id = uuid.uuid4()
        session_id = uuid.uuid4()
        
        profile = Profile(id=user_id, email="test@example.com")
        project = Project(id=project_id, user_id=user_id, name="Test Project")
        self.session.add(profile)
        self.session.add(project)
        self.session.commit()
        
        # Act
        chat_session = ChatSession(
            id=session_id,
            project_id=project_id,
            user_id=user_id,
            title="Test Chat",
            is_active=True
        )
        self.session.add(chat_session)
        self.session.commit()
        
        # Assert
        saved_session = self.session.query(ChatSession).filter_by(id=session_id).first()
        assert saved_session is not None
        assert saved_session.title == "Test Chat"
        assert saved_session.is_active is True

    def test_chat_message_model_creation(self):
        """Тест создания модели ChatMessage"""
        # Arrange
        user_id = uuid.uuid4()
        project_id = uuid.uuid4()
        session_id = uuid.uuid4()
        message_id = uuid.uuid4()
        
        profile = Profile(id=user_id, email="test@example.com")
        project = Project(id=project_id, user_id=user_id, name="Test Project")
        chat_session = ChatSession(id=session_id, project_id=project_id, user_id=user_id)
        self.session.add(profile)
        self.session.add(project)
        self.session.add(chat_session)
        self.session.commit()
        
        # Act
        message = ChatMessage(
            id=message_id,
            session_id=session_id,
            role="user",
            content="Hello, world!",
            message_metadata={"tokens": 10, "model": "gpt-4"}
        )
        self.session.add(message)
        self.session.commit()
        
        # Assert
        saved_message = self.session.query(ChatMessage).filter_by(id=message_id).first()
        assert saved_message is not None
        assert saved_message.role == "user"
        assert saved_message.content == "Hello, world!"
        assert saved_message.message_metadata == {"tokens": 10, "model": "gpt-4"}

    def test_chat_message_role_constraint(self):
        """Тест ограничения роли в ChatMessage"""
        user_id = uuid.uuid4()
        project_id = uuid.uuid4()
        session_id = uuid.uuid4()
        
        profile = Profile(id=user_id, email="test@example.com")
        project = Project(id=project_id, user_id=user_id, name="Test Project")
        chat_session = ChatSession(id=session_id, project_id=project_id, user_id=user_id)
        self.session.add(profile)
        self.session.add(project)
        self.session.add(chat_session)
        self.session.commit()
        
        # Valid roles
        valid_roles = ["user", "assistant", "system"]
        for role in valid_roles:
            message = ChatMessage(session_id=session_id, role=role, content="Test")
            self.session.add(message)
            self.session.commit()
            self.session.delete(message)
        
        # Invalid role should fail
        message = ChatMessage(session_id=session_id, role="invalid", content="Test")
        self.session.add(message)
        with pytest.raises(Exception):  # Check constraint violation
            self.session.commit()

    def test_api_key_model_creation(self):
        """Тест создания модели APIKey"""
        # Arrange
        user_id = uuid.uuid4()
        key_id = uuid.uuid4()
        profile = Profile(id=user_id, email="test@example.com")
        self.session.add(profile)
        self.session.commit()
        
        # Act
        api_key = APIKey(
            id=key_id,
            user_id=user_id,
            provider="openai",
            encrypted_key="encrypted_key_data",
            is_active=True
        )
        self.session.add(api_key)
        self.session.commit()
        
        # Assert
        saved_key = self.session.query(APIKey).filter_by(id=key_id).first()
        assert saved_key is not None
        assert saved_key.provider == "openai"
        assert saved_key.encrypted_key == "encrypted_key_data"
        assert saved_key.is_active is True

    def test_api_key_provider_constraint(self):
        """Тест ограничения провайдера в APIKey"""
        user_id = uuid.uuid4()
        profile = Profile(id=user_id, email="test@example.com")
        self.session.add(profile)
        self.session.commit()
        
        # Valid providers
        valid_providers = ["openrouter", "openai", "anthropic", "groq"]
        for provider in valid_providers:
            api_key = APIKey(
                user_id=user_id,
                provider=provider,
                encrypted_key="test_key"
            )
            self.session.add(api_key)
            self.session.commit()
            self.session.delete(api_key)
        
        # Invalid provider should fail
        api_key = APIKey(
            user_id=user_id,
            provider="invalid",
            encrypted_key="test_key"
        )
        self.session.add(api_key)
        with pytest.raises(Exception):  # Check constraint violation
            self.session.commit()

    def test_file_model_creation(self):
        """Тест создания модели File"""
        # Arrange
        user_id = uuid.uuid4()
        project_id = uuid.uuid4()
        file_id = uuid.uuid4()
        
        profile = Profile(id=user_id, email="test@example.com")
        project = Project(id=project_id, user_id=user_id, name="Test Project")
        self.session.add(profile)
        self.session.add(project)
        self.session.commit()
        
        # Act
        file_obj = File(
            id=file_id,
            project_id=project_id,
            user_id=user_id,
            name="test.py",
            path="/workspace/test.py",
            content="print('Hello, world!')",
            file_type="python",
            size=1024
        )
        self.session.add(file_obj)
        self.session.commit()
        
        # Assert
        saved_file = self.session.query(File).filter_by(id=file_id).first()
        assert saved_file is not None
        assert saved_file.name == "test.py"
        assert saved_file.path == "/workspace/test.py"
        assert saved_file.content == "print('Hello, world!')"
        assert saved_file.file_type == "python"
        assert saved_file.size == 1024

    def test_ai_usage_model_creation(self):
        """Тест создания модели AIUsage"""
        # Arrange
        user_id = uuid.uuid4()
        project_id = uuid.uuid4()
        usage_id = uuid.uuid4()
        
        profile = Profile(id=user_id, email="test@example.com")
        project = Project(id=project_id, user_id=user_id, name="Test Project")
        self.session.add(profile)
        self.session.add(project)
        self.session.commit()
        
        # Act
        usage = AIUsage(
            id=usage_id,
            user_id=user_id,
            project_id=project_id,
            provider="openai",
            model="gpt-4",
            tokens_used=1000,
            cost=Decimal('0.0050')
        )
        self.session.add(usage)
        self.session.commit()
        
        # Assert
        saved_usage = self.session.query(AIUsage).filter_by(id=usage_id).first()
        assert saved_usage is not None
        assert saved_usage.provider == "openai"
        assert saved_usage.model == "gpt-4"
        assert saved_usage.tokens_used == 1000
        assert saved_usage.cost == Decimal('0.0050')

    def test_ai_usage_provider_constraint(self):
        """Тест ограничения провайдера в AIUsage"""
        user_id = uuid.uuid4()
        project_id = uuid.uuid4()
        
        profile = Profile(id=user_id, email="test@example.com")
        project = Project(id=project_id, user_id=user_id, name="Test Project")
        self.session.add(profile)
        self.session.add(project)
        self.session.commit()
        
        # Valid providers
        valid_providers = ["openrouter", "openai", "anthropic", "groq"]
        for provider in valid_providers:
            usage = AIUsage(
                user_id=user_id,
                project_id=project_id,
                provider=provider,
                model="test-model"
            )
            self.session.add(usage)
            self.session.commit()
            self.session.delete(usage)
        
        # Invalid provider should fail
        usage = AIUsage(
            user_id=user_id,
            project_id=project_id,
            provider="invalid",
            model="test-model"
        )
        self.session.add(usage)
        with pytest.raises(Exception):  # Check constraint violation
            self.session.commit()

    def test_cascade_deletion(self):
        """Тест каскадного удаления (только для PostgreSQL)"""
        # Arrange
        user_id = uuid.uuid4()
        project_id = uuid.uuid4()
        session_id = uuid.uuid4()
        
        profile = Profile(id=user_id, email="test@example.com")
        project = Project(id=project_id, user_id=user_id, name="Test Project")
        chat_session = ChatSession(id=session_id, project_id=project_id, user_id=user_id)
        user_setting = UserSetting(user_id=user_id, default_model="gpt-4")
        
        self.session.add(profile)
        self.session.add(project)
        self.session.add(chat_session)
        self.session.add(user_setting)
        self.session.commit()
        
        # Act - удаляем профиль
        self.session.delete(profile)
        self.session.commit()
        
        # Assert - в SQLite каскадное удаление работает по-другому
        # Проверяем что профиль удален
        assert self.session.query(Profile).filter_by(id=user_id).first() is None
        
        # В SQLite связанные записи остаются, но ссылки становятся недействительными
        # Это нормальное поведение для SQLite

    def test_model_relationships(self):
        """Тест связей между моделями"""
        # Arrange
        user_id = uuid.uuid4()
        project_id = uuid.uuid4()
        session_id = uuid.uuid4()
        message_id = uuid.uuid4()
        
        profile = Profile(id=user_id, email="test@example.com")
        project = Project(id=project_id, user_id=user_id, name="Test Project")
        chat_session = ChatSession(id=session_id, project_id=project_id, user_id=user_id)
        message = ChatMessage(id=message_id, session_id=session_id, role="user", content="Test")
        
        self.session.add_all([profile, project, chat_session, message])
        self.session.commit()
        
        # Act & Assert
        # Проверяем связи через foreign keys
        saved_message = self.session.query(ChatMessage).filter_by(id=message_id).first()
        assert saved_message.session_id == session_id
        
        saved_session = self.session.query(ChatSession).filter_by(id=session_id).first()
        assert saved_session.project_id == project_id
        assert saved_session.user_id == user_id
        
        saved_project = self.session.query(Project).filter_by(id=project_id).first()
        assert saved_project.user_id == user_id