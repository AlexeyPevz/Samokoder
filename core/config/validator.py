"""Validator for configuration security."""
import secrets
import logging
from typing import Optional

logger = logging.getLogger(__name__)

# Список дефолтных/небезопасных секретов
DEFAULT_SECRETS = [
    "your-super-secret-jwt-key-change-in-production-minimum-32-characters-for-security",
    "9761242676a4c005fca8992c05f3d06241b122a52dc291dd091081028c4f3ab3",
    "your-super-secret-app-key-change-in-production-minimum-32-characters-for-security",
]


def generate_secret_key(length: int = 64) -> str:
    """Генерирует криптографически стойкий секретный ключ.
    
    Args:
        length: Длина ключа в байтах (по умолчанию 64)
    
    Returns:
        URL-safe base64 строка
    """
    return secrets.token_urlsafe(length)


def validate_secret_key(secret: str, environment: str, key_name: str = "SECRET_KEY") -> bool:
    """Валидирует секретный ключ на безопасность.
    
    Args:
        secret: Секретный ключ для проверки
        environment: Текущее окружение (production, development, etc.)
        key_name: Имя ключа для логирования
    
    Returns:
        True если ключ валиден, False если есть проблемы
    
    Raises:
        ValueError: В продакшене с дефолтным ключом
    """
    # Проверка на пустой ключ
    if not secret or len(secret.strip()) == 0:
        logger.error(f"❌ {key_name} is empty!")
        if environment == "production":
            raise ValueError(f"{key_name} cannot be empty in production!")
        return False
    
    # Проверка на дефолтные значения
    if secret in DEFAULT_SECRETS:
        msg = f"⚠️  {key_name} is using DEFAULT value! This is INSECURE!"
        logger.warning(msg)
        
        if environment == "production":
            raise ValueError(
                f"{key_name} is using default value in production! "
                f"Please generate a unique key using: python -c 'import secrets; print(secrets.token_urlsafe(64))'"
            )
        else:
            logger.warning(f"💡 Generate a new {key_name}: python -c 'import secrets; print(secrets.token_urlsafe(64))'")
        return False
    
    # Проверка минимальной длины
    if len(secret) < 32:
        logger.warning(f"⚠️  {key_name} is too short (< 32 chars). Recommend at least 64 chars.")
        if environment == "production":
            raise ValueError(f"{key_name} must be at least 32 characters in production!")
        return False
    
    logger.info(f"✅ {key_name} validation passed")
    return True


def validate_config_security(config, fail_fast: bool = True) -> bool:
    """Валидирует безопасность всей конфигурации.
    
    Args:
        config: Объект конфигурации
        fail_fast: Если True, выбросит исключение при ошибках в production
    
    Returns:
        True если все проверки пройдены
    """
    environment = getattr(config, 'environment', 'development')
    
    logger.info(f"🔒 Validating security configuration (environment: {environment})")
    
    all_valid = True
    
    # Валидация SECRET_KEY
    try:
        valid = validate_secret_key(config.secret_key, environment, "SECRET_KEY")
        all_valid = all_valid and valid
    except ValueError as e:
        if fail_fast:
            raise
        logger.error(str(e))
        all_valid = False
    
    # Валидация APP_SECRET_KEY
    try:
        valid = validate_secret_key(config.app_secret_key, environment, "APP_SECRET_KEY")
        all_valid = all_valid and valid
    except ValueError as e:
        if fail_fast:
            raise
        logger.error(str(e))
        all_valid = False
    
    if all_valid:
        logger.info("✅ All security validations passed")
    else:
        logger.warning("⚠️  Some security validations failed")
    
    return all_valid
