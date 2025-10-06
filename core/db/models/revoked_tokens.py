"""Model for tracking revoked JWT tokens."""
from sqlalchemy import String, DateTime
from sqlalchemy.orm import Mapped, mapped_column
from datetime import datetime
from samokoder.core.db.models.base import Base


class RevokedToken(Base):
    """
    Stores revoked JWT tokens by their jti (JWT ID).
    Used for implementing logout and token revocation.
    """
    __tablename__ = 'revoked_tokens'
    
    jti: Mapped[str] = mapped_column(String, primary_key=True, index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, index=True)
    revoked_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    reason: Mapped[str] = mapped_column(String, nullable=True)  # logout, security_breach, etc.
