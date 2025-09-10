# ADR-004: Security Configuration Management

**Статус:** Принято  
**Дата:** 2025-01-27  
**Участники:** CTO, Security Architect, DevOps Engineer

## Контекст

Проект "Самокодер" обрабатывает чувствительные данные (API ключи, пользовательские данные) и требует enterprise-level security configuration management.

## Проблема

Текущие проблемы безопасности:
- Секреты в .env файле (риск exposure)
- Отсутствие ротации ключей
- Нет разделения секретов по окружениям
- Отсутствие audit trail для конфигураций

## Решение

### 1. Secret Management Strategy

#### Development Environment
```bash
# .env.development
SUPABASE_URL=https://dev.supabase.co
SUPABASE_ANON_KEY=dev_key_here
API_ENCRYPTION_KEY=dev_encryption_key
```

#### Production Environment
```bash
# Использование внешнего secret management
# AWS Secrets Manager / HashiCorp Vault / Azure Key Vault
SECRETS_PROVIDER=aws-secrets-manager
SECRETS_REGION=us-east-1
SECRETS_PREFIX=/samokoder/production/
```

### 2. Key Rotation Strategy

```python
# backend/security/key_rotation.py
from datetime import datetime, timedelta
from typing import Dict, List

class KeyRotationManager:
    def __init__(self, secrets_provider):
        self.secrets_provider = secrets_provider
        self.rotation_schedule = {
            'api_encryption_key': timedelta(days=90),
            'jwt_secret': timedelta(days=30),
            'csrf_secret': timedelta(days=60)
        }
    
    async def check_rotation_needed(self) -> List[str]:
        """Check which keys need rotation"""
        keys_to_rotate = []
        
        for key_name, rotation_period in self.rotation_schedule.items():
            last_rotation = await self.get_last_rotation_date(key_name)
            if datetime.now() - last_rotation > rotation_period:
                keys_to_rotate.append(key_name)
        
        return keys_to_rotate
    
    async def rotate_key(self, key_name: str) -> str:
        """Rotate a specific key"""
        # Generate new key
        new_key = self.generate_secure_key(key_name)
        
        # Update in secret store
        await self.secrets_provider.update_secret(key_name, new_key)
        
        # Log rotation
        await self.log_key_rotation(key_name)
        
        return new_key
```

### 3. Environment-Specific Configuration

```python
# config/environments/
├── base.py          # Common settings
├── development.py   # Dev-specific
├── staging.py       # Staging-specific
├── production.py    # Production-specific
└── testing.py       # Test-specific

# config/environments/production.py
from .base import BaseSettings
from backend.security.secrets_manager import AWSSecretsManager

class ProductionSettings(BaseSettings):
    secrets_provider = AWSSecretsManager()
    
    # Override sensitive settings
    def __init__(self):
        super().__init__()
        self.load_secrets_from_provider()
    
    def load_secrets_from_provider(self):
        """Load secrets from external provider"""
        self.supabase_url = self.secrets_provider.get_secret('supabase_url')
        self.supabase_anon_key = self.secrets_provider.get_secret('supabase_anon_key')
        self.api_encryption_key = self.secrets_provider.get_secret('api_encryption_key')
```

### 4. Secret Providers

```python
# backend/security/secrets_manager.py
from abc import ABC, abstractmethod
from typing import Optional

class SecretsProvider(ABC):
    @abstractmethod
    async def get_secret(self, key: str) -> Optional[str]:
        pass
    
    @abstractmethod
    async def set_secret(self, key: str, value: str) -> bool:
        pass

class AWSSecretsManager(SecretsProvider):
    def __init__(self, region: str = "us-east-1"):
        import boto3
        self.client = boto3.client('secretsmanager', region_name=region)
    
    async def get_secret(self, key: str) -> Optional[str]:
        try:
            response = self.client.get_secret_value(SecretId=key)
            return response['SecretString']
        except Exception as e:
            logger.error(f"Failed to get secret {key}: {e}")
            return None

class HashiCorpVault(SecretsProvider):
    def __init__(self, vault_url: str, token: str):
        import hvac
        self.client = hvac.Client(url=vault_url, token=token)
    
    async def get_secret(self, key: str) -> Optional[str]:
        try:
            response = self.client.secrets.kv.v2.read_secret_version(path=key)
            return response['data']['data']['value']
        except Exception as e:
            logger.error(f"Failed to get secret {key}: {e}")
            return None
```

### 5. Configuration Validation

```python
# backend/security/config_validator.py
from pydantic import BaseModel, validator
from typing import List

class SecurityConfig(BaseModel):
    api_encryption_key: str
    jwt_secret: str
    csrf_secret: str
    cors_origins: List[str]
    
    @validator('api_encryption_key')
    def validate_encryption_key(cls, v):
        if len(v) < 32:
            raise ValueError('Encryption key must be at least 32 characters')
        return v
    
    @validator('jwt_secret')
    def validate_jwt_secret(cls, v):
        if len(v) < 64:
            raise ValueError('JWT secret must be at least 64 characters')
        return v
    
    @validator('cors_origins')
    def validate_cors_origins(cls, v):
        if not v:
            raise ValueError('CORS origins cannot be empty')
        return v
```

### 6. Audit and Monitoring

```python
# backend/security/security_audit.py
from datetime import datetime
from typing import Dict, Any

class SecurityAuditor:
    def __init__(self, audit_logger):
        self.audit_logger = audit_logger
    
    async def log_config_access(self, config_key: str, user_id: str):
        """Log configuration access"""
        await self.audit_logger.log({
            'event': 'config_access',
            'config_key': config_key,
            'user_id': user_id,
            'timestamp': datetime.now().isoformat(),
            'severity': 'info'
        })
    
    async def log_key_rotation(self, key_name: str, rotated_by: str):
        """Log key rotation"""
        await self.audit_logger.log({
            'event': 'key_rotation',
            'key_name': key_name,
            'rotated_by': rotated_by,
            'timestamp': datetime.now().isoformat(),
            'severity': 'warning'
        })
    
    async def log_security_violation(self, violation_type: str, details: Dict[str, Any]):
        """Log security violation"""
        await self.audit_logger.log({
            'event': 'security_violation',
            'violation_type': violation_type,
            'details': details,
            'timestamp': datetime.now().isoformat(),
            'severity': 'critical'
        })
```

## Реализация

### Фаза 1: Secret Management (1 неделя)
- [ ] Настроить AWS Secrets Manager / Vault
- [ ] Создать Secret Providers
- [ ] Мигрировать существующие секреты

### Фаза 2: Key Rotation (1 неделя)
- [ ] Реализовать KeyRotationManager
- [ ] Настроить автоматическую ротацию
- [ ] Создать monitoring для ротации

### Фаза 3: Environment Separation (3 дня)
- [ ] Создать environment-specific конфигурации
- [ ] Обновить deployment scripts
- [ ] Протестировать в разных окружениях

### Фаза 4: Audit and Monitoring (3 дня)
- [ ] Реализовать SecurityAuditor
- [ ] Настроить audit logging
- [ ] Создать security dashboards

## Последствия

### Положительные
- Enterprise-level security
- Автоматическая ротация ключей
- Audit trail для всех изменений
- Разделение секретов по окружениям

### Негативные
- Сложность настройки
- Зависимость от внешних сервисов
- Стоимость secret management
- Требует DevOps экспертизы

## Альтернативы

1. **Environment variables** - отклонено для production
2. **Config files** - отклонено из-за security рисков
3. **Kubernetes Secrets** - рассмотрено для K8s deployment

## Мониторинг

- Secret access patterns
- Key rotation success/failure
- Security violation attempts
- Configuration drift detection

## Rollback Plan

В случае проблем:
1. Откат к предыдущей версии конфигурации
2. Восстановление секретов из backup
3. Анализ security logs
4. Исправление и повторное развертывание