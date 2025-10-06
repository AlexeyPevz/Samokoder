from __future__ import annotations
from typing import TYPE_CHECKING, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy import String, Integer, JSON, DateTime
from enum import Enum as PythonEnum
from sqlalchemy.types import Enum as SQLAlchemyEnum
from cryptography.fernet import Fernet
from datetime import datetime

from samokoder.core.db.models.base import Base

if TYPE_CHECKING:
    from samokoder.core.db.models.project import Project

class Tier(PythonEnum):
    FREE = 'free'
    STARTER = 'starter'
    PRO = 'pro'
    TEAM = 'team'

class User(Base):
    __tablename__ = 'users'
    id: Mapped[int] = mapped_column(primary_key=True)
    email: Mapped[str] = mapped_column(String, unique=True, index=True)
    hashed_password: Mapped[str] = mapped_column(String, nullable=False)
    tier: Mapped[Tier] = mapped_column(SQLAlchemyEnum(Tier), default=Tier.FREE, nullable=False)
    projects_monthly_count: Mapped[int] = mapped_column(Integer, default=0)
    projects_total: Mapped[int] = mapped_column(Integer, default=0)
    api_keys: Mapped[dict] = mapped_column(JSON, default=dict)
    api_key_settings: Mapped[dict] = mapped_column(JSON, default=dict)  # Settings for each API key (provider, model, etc.)
    token_usage: Mapped[dict] = mapped_column(JSON, default=dict)  # Token usage tracking
    _github_token_encrypted: Mapped[str] = mapped_column("github_token", String, nullable=True)  # P2-2: Encrypted
    gitverse_token: Mapped[str] = mapped_column(String, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    projects: Mapped[list["Project"]] = relationship(back_populates="user")

    @staticmethod
    async def get_by_email(session: AsyncSession, email: str) -> Optional["User"]:
        result = await session.execute(select(User).where(User.email == email))
        return result.scalar_one_or_none()
    

    
    def get_api_key_settings(self) -> dict:
        """
        Get user's API key settings (provider, model, etc.)
        
        :return: Dictionary of API key settings
        """
        return self.api_key_settings or {}
    
    def update_api_key_settings(self, provider: str, settings: dict) -> None:
        """
        Update API key settings for a provider
        
        :param provider: Provider name
        :param settings: Settings to update
        """
        if not self.api_key_settings:
            self.api_key_settings = {}
        
        self.api_key_settings[provider] = settings
        
        # Mark the JSON field as modified to ensure SQLAlchemy picks up the change
        from sqlalchemy.orm.attributes import flag_modified
        flag_modified(self, "api_key_settings")
    
    def record_token_usage(self, provider: str, model: str, tokens: int) -> None:
        """
        Record token usage for a provider and model
        
        :param provider: Provider name
        :param model: Model name
        :param tokens: Number of tokens used
        """
        if not self.token_usage:
            self.token_usage = {}
        
        if provider not in self.token_usage:
            self.token_usage[provider] = {}
        
        if model not in self.token_usage[provider]:
            self.token_usage[provider][model] = {
                "total_tokens": 0,
                "requests": 0,
                "updated_at": datetime.utcnow().isoformat()
            }
        
        self.token_usage[provider][model]["total_tokens"] += tokens
        self.token_usage[provider][model]["requests"] += 1
        self.token_usage[provider][model]["updated_at"] = datetime.utcnow().isoformat()
        
        # Mark the JSON field as modified to ensure SQLAlchemy picks up the change
        from sqlalchemy.orm.attributes import flag_modified
        flag_modified(self, "token_usage")
    
    def get_token_usage(self) -> dict:
        """
        Get user's token usage statistics
        
        :return: Dictionary of token usage statistics
        """
        return self.token_usage or {}
    
    def reset_token_usage(self, provider: str = None, model: str = None) -> None:
        """
        Reset token usage statistics
        
        :param provider: Provider name (optional, reset all if not provided)
        :param model: Model name (optional, reset all models if not provided)
        """
        if not self.token_usage:
            return
        
        if provider and model:
            # Reset specific provider and model
            if provider in self.token_usage and model in self.token_usage[provider]:
                self.token_usage[provider][model] = {
                    "total_tokens": 0,
                    "requests": 0,
                    "updated_at": datetime.utcnow().isoformat()
                }
        elif provider:
            # Reset specific provider
            if provider in self.token_usage:
                for model_name in self.token_usage[provider]:
                    self.token_usage[provider][model_name] = {
                        "total_tokens": 0,
                        "requests": 0,
                        "updated_at": datetime.utcnow().isoformat()
                    }
        else:
            # Reset all usage
            self.token_usage = {}
        
        # Mark the JSON field as modified to ensure SQLAlchemy picks up the change
        from sqlalchemy.orm.attributes import flag_modified
        flag_modified(self, "token_usage")
    
    def set_encrypted_github_token(self, token: str, secret_key: bytes) -> None:
        """
        Encrypt and store GitHub token (P2-2: ASVS 6.2.1).
        
        :param token: GitHub personal access token
        :param secret_key: Encryption key
        """
        from samokoder.core.security.crypto import CryptoService
        crypto = CryptoService(secret_key)
        self._github_token_encrypted = crypto.encrypt(token)
    
    def get_decrypted_github_token(self, secret_key: bytes) -> str:
        """
        Decrypt and return GitHub token (P2-2).
        
        :param secret_key: Decryption key
        :return: Decrypted token or empty string if not set
        """
        if not self._github_token_encrypted:
            return ""
        from samokoder.core.security.crypto import CryptoService
        crypto = CryptoService(secret_key)
        return crypto.decrypt(self._github_token_encrypted)


