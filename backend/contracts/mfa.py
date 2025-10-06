"""
MFA Service contracts
"""
from typing import Protocol, Dict, Any, Optional, List
from uuid import UUID

class MFAServiceProtocol(Protocol):
    """Protocol for MFA service implementations"""
    
    async def enable_mfa(
        self,
        user_id: UUID
    ) -> Dict[str, Any]:
        """
        Enable MFA for user.
        Returns QR code and secret for TOTP setup.
        """
        ...
    
    async def disable_mfa(
        self,
        user_id: UUID,
        verification_code: str
    ) -> bool:
        """Disable MFA for user after verification"""
        ...
    
    async def verify_totp(
        self,
        user_id: UUID,
        code: str
    ) -> bool:
        """Verify TOTP code for user"""
        ...
    
    async def generate_backup_codes(
        self,
        user_id: UUID,
        count: int = 10
    ) -> List[str]:
        """Generate backup codes for user"""
        ...
    
    async def verify_backup_code(
        self,
        user_id: UUID,
        code: str
    ) -> bool:
        """Verify and consume backup code"""
        ...
    
    async def get_mfa_status(
        self,
        user_id: UUID
    ) -> Dict[str, Any]:
        """Get MFA status for user"""
        ...
    
    async def send_sms_code(
        self,
        user_id: UUID,
        phone_number: str
    ) -> bool:
        """Send SMS verification code"""
        ...
    
    async def verify_sms_code(
        self,
        user_id: UUID,
        code: str
    ) -> bool:
        """Verify SMS code"""
        ...
