"""
SQLAlchemy модели для Alembic autogenerate поддержки
"""
from sqlalchemy import Column, String, Integer, Boolean, DateTime, Text, JSON, DECIMAL, ForeignKey, UniqueConstraint, CheckConstraint
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.sql import func
import uuid

Base = declarative_base()

class Profile(Base):
    __tablename__ = 'profiles'
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email = Column(String, unique=True, nullable=False)
    full_name = Column(String)
    avatar_url = Column(String)
    subscription_tier = Column(String, default='free')
    subscription_status = Column(String, default='active')
    subscription_ends_at = Column(DateTime(timezone=True))
    api_credits_balance = Column(DECIMAL(10, 2), default=0.00)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    
    __table_args__ = (
        CheckConstraint("subscription_tier IN ('free', 'starter', 'professional', 'business', 'enterprise')"),
        CheckConstraint("subscription_status IN ('active', 'canceled', 'past_due', 'trialing')"),
    )

class UserSetting(Base):
    __tablename__ = 'user_settings'
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey('profiles.id', ondelete='CASCADE'), nullable=False)
    default_model = Column(String, default='deepseek/deepseek-v3')
    default_provider = Column(String, default='openrouter')
    auto_export = Column(Boolean, default=False)
    notifications_email = Column(Boolean, default=True)
    notifications_generation = Column(Boolean, default=True)
    theme = Column(String, default='light')
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    
    __table_args__ = (
        UniqueConstraint('user_id'),
        CheckConstraint("theme IN ('light', 'dark', 'auto')"),
    )

class AIProvider(Base):
    __tablename__ = 'ai_providers'
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String, unique=True, nullable=False)
    display_name = Column(String, nullable=False)
    website_url = Column(String)
    documentation_url = Column(String)
    requires_api_key = Column(Boolean, default=True)
    is_active = Column(Boolean, default=True)
    pricing_info = Column(JSON, default={})
    created_at = Column(DateTime(timezone=True), server_default=func.now())

class Project(Base):
    __tablename__ = 'projects'
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey('profiles.id', ondelete='CASCADE'), nullable=False)
    name = Column(String, nullable=False)
    description = Column(Text)
    ai_config = Column(JSON, default={})
    workspace_path = Column(String)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

class ChatSession(Base):
    __tablename__ = 'chat_sessions'
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    project_id = Column(UUID(as_uuid=True), ForeignKey('projects.id', ondelete='CASCADE'), nullable=False)
    user_id = Column(UUID(as_uuid=True), ForeignKey('profiles.id', ondelete='CASCADE'), nullable=False)
    title = Column(String)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

class ChatMessage(Base):
    __tablename__ = 'chat_messages'
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    session_id = Column(UUID(as_uuid=True), ForeignKey('chat_sessions.id', ondelete='CASCADE'), nullable=False)
    role = Column(String, nullable=False)
    content = Column(Text, nullable=False)
    message_metadata = Column(JSON, default={})
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    __table_args__ = (
        CheckConstraint("role IN ('user', 'assistant', 'system')"),
    )

class APIKey(Base):
    __tablename__ = 'api_keys'
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey('profiles.id', ondelete='CASCADE'), nullable=False)
    provider = Column(String, nullable=False)
    encrypted_key = Column(String, nullable=False)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    
    __table_args__ = (
        CheckConstraint("provider IN ('openrouter', 'openai', 'anthropic', 'groq')"),
    )

class File(Base):
    __tablename__ = 'files'
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    project_id = Column(UUID(as_uuid=True), ForeignKey('projects.id', ondelete='CASCADE'), nullable=False)
    user_id = Column(UUID(as_uuid=True), ForeignKey('profiles.id', ondelete='CASCADE'), nullable=False)
    name = Column(String, nullable=False)
    path = Column(String, nullable=False)
    content = Column(Text)
    file_type = Column(String)
    size = Column(Integer)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

class AIUsage(Base):
    __tablename__ = 'ai_usage'
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey('profiles.id', ondelete='CASCADE'), nullable=False)
    project_id = Column(UUID(as_uuid=True), ForeignKey('projects.id', ondelete='CASCADE'))
    provider = Column(String, nullable=False)
    model = Column(String, nullable=False)
    tokens_used = Column(Integer, default=0)
    cost = Column(DECIMAL(10, 4), default=0.0000)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    __table_args__ = (
        CheckConstraint("provider IN ('openrouter', 'openai', 'anthropic', 'groq')"),
    )