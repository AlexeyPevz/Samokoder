"""Model for tracking login attempts for brute force protection."""
from sqlalchemy import String, Boolean, Integer, DateTime
from sqlalchemy.orm import Mapped, mapped_column
from datetime import datetime
from samokoder.core.db.models.base import Base


class LoginAttempt(Base):
    """
    Tracks all login attempts for security monitoring and brute force protection.
    """
    __tablename__ = 'login_attempts'
    
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String, index=True, nullable=False)
    ip_address: Mapped[str] = mapped_column(String, nullable=False)
    success: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    user_id: Mapped[int] = mapped_column(Integer, nullable=True)
    user_agent: Mapped[str] = mapped_column(String, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)
