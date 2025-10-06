"""Centralized security audit logging."""
import logging
from typing import Optional
from datetime import datetime
import json


class AuditLogger:
    """Централизованное логирование событий безопасности согласно ASVS 7.1."""
    
    def __init__(self):
        self.logger = logging.getLogger("security.audit")
        # Ensure audit logs go to a separate file
        handler = logging.FileHandler("logs/security_audit.log")
        handler.setFormatter(logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s'
        ))
        self.logger.addHandler(handler)
        self.logger.setLevel(logging.INFO)
        
    def log_event(
        self,
        event_type: str,
        user_id: Optional[int] = None,
        email: Optional[str] = None,
        ip_address: Optional[str] = None,
        success: bool = True,
        details: Optional[dict] = None
    ):
        """
        Log a security event.
        
        Args:
            event_type: Type of security event (authentication, authorization, etc.)
            user_id: ID of user involved
            email: Email of user involved
            ip_address: IP address of request
            success: Whether the event was successful
            details: Additional event details
        """
        event = {
            "timestamp": datetime.utcnow().isoformat(),
            "event_type": event_type,
            "user_id": user_id,
            "email": email,
            "ip_address": ip_address,
            "success": success,
            "details": details or {}
        }
        
        log_message = json.dumps(event, ensure_ascii=False)
        
        if success:
            self.logger.info(log_message)
        else:
            self.logger.warning(log_message)
    
    def log_authentication(self, email: str, ip: str, success: bool, method: str = "password", user_id: Optional[int] = None):
        """Log authentication attempt (ASVS 2.2.2)."""
        self.log_event(
            "authentication",
            user_id=user_id,
            email=email,
            ip_address=ip,
            success=success,
            details={"method": method}
        )
    
    def log_authorization_failure(self, user_id: int, resource: str, action: str, ip: str):
        """Log authorization failure (ASVS 4.1.1)."""
        self.log_event(
            "authorization_failure",
            user_id=user_id,
            ip_address=ip,
            success=False,
            details={"resource": resource, "action": action}
        )
    
    def log_data_access(self, user_id: int, resource_type: str, resource_id: str, action: str):
        """Log sensitive data access (ASVS 7.1.1)."""
        self.log_event(
            "data_access",
            user_id=user_id,
            success=True,
            details={
                "resource_type": resource_type,
                "resource_id": resource_id,
                "action": action
            }
        )
    
    def log_configuration_change(self, user_id: int, setting: str, old_value: str, new_value: str):
        """Log configuration changes (ASVS 7.1.4)."""
        self.log_event(
            "configuration_change",
            user_id=user_id,
            success=True,
            details={
                "setting": setting,
                "old_value": old_value,
                "new_value": new_value
            }
        )
    
    def log_token_revocation(self, user_id: int, jti: str, reason: str):
        """Log token revocation (ASVS 3.5.3)."""
        self.log_event(
            "token_revocation",
            user_id=user_id,
            success=True,
            details={"jti": jti, "reason": reason}
        )
    
    def log_account_lockout(self, email: str, ip: str, failed_attempts: int):
        """Log account lockout due to brute force (ASVS 2.2.1)."""
        self.log_event(
            "account_lockout",
            email=email,
            ip_address=ip,
            success=False,
            details={"failed_attempts": failed_attempts}
        )


# Global instance
audit_logger = AuditLogger()
