"""
ASVS 2.8.1: Хранение MFA секретов
Исправление P0-4
"""
from typing import Optional, List
from backend.services.connection_manager import connection_manager
from backend.services.supabase_manager import execute_supabase_operation
from backend.services.encryption_service import get_encryption_service
import logging
import secrets

logger = logging.getLogger(__name__)

async def get_mfa_secret(user_id: str) -> Optional[str]:
    """
    Получает MFA секрет пользователя из БД
    
    ASVS 2.8.1: Секреты должны храниться в зашифрованном виде
    
    Args:
        user_id: ID пользователя
        
    Returns:
        MFA секрет или None если не настроен
    """
    try:
        supabase = connection_manager.get_pool('supabase')
        if not supabase:
            logger.error("Supabase unavailable for MFA secret retrieval")
            return None
        
        response = await execute_supabase_operation(
            lambda client: client.table("user_mfa_secrets")
                .select("encrypted_secret")
                .eq("user_id", user_id)
                .eq("is_active", True)
                .maybe_single()
                .execute(),
            "anon"
        )
        
        if response and response.data:
            # Расшифровываем секрет
            encryption_service = get_encryption_service()
            try:
                decrypted_secret = encryption_service.decrypt(
                    response.data["encrypted_secret"]
                )
                
                logger.info(
                    f"MFA secret retrieved",
                    extra={
                        "user_id": user_id[:8] + "***",
                        "event": "mfa_secret_retrieved"
                    }
                )
                
                return decrypted_secret
                
            except Exception as decrypt_error:
                logger.error(
                    f"Failed to decrypt MFA secret",
                    extra={
                        "user_id": user_id[:8] + "***",
                        "error": str(decrypt_error),
                        "event": "mfa_decrypt_error"
                    }
                )
                return None
        
        return None
        
    except Exception as e:
        logger.error(
            f"Error retrieving MFA secret",
            extra={
                "user_id": user_id[:8] + "***",
                "error": str(e),
                "event": "mfa_retrieval_error"
            }
        )
        return None

async def save_mfa_secret(user_id: str, secret: str) -> bool:
    """
    Сохраняет MFA секрет в БД
    
    ASVS 2.8.1: Секреты должны храниться в зашифрованном виде
    
    Args:
        user_id: ID пользователя
        secret: MFA секрет для сохранения
        
    Returns:
        True если успешно сохранено
    """
    try:
        supabase = connection_manager.get_pool('supabase')
        if not supabase:
            logger.error("Supabase unavailable for MFA secret storage")
            return False
        
        # Шифруем секрет перед сохранением
        encryption_service = get_encryption_service()
        try:
            encrypted_secret = encryption_service.encrypt(secret)
        except Exception as encrypt_error:
            logger.error(
                f"Failed to encrypt MFA secret",
                extra={
                    "user_id": user_id[:8] + "***",
                    "error": str(encrypt_error),
                    "event": "mfa_encrypt_error"
                }
            )
            return False
        
        # Сохраняем в БД (upsert для обновления существующих)
        await execute_supabase_operation(
            lambda client: client.table("user_mfa_secrets")
                .upsert({
                    "user_id": user_id,
                    "encrypted_secret": encrypted_secret,
                    "is_active": True
                }, on_conflict="user_id")
                .execute(),
            "anon"
        )
        
        logger.info(
            f"MFA secret saved",
            extra={
                "user_id": user_id[:8] + "***",
                "event": "mfa_secret_saved"
            }
        )
        
        return True
        
    except Exception as e:
        logger.error(
            f"Error saving MFA secret",
            extra={
                "user_id": user_id[:8] + "***",
                "error": str(e),
                "event": "mfa_save_error"
            }
        )
        return False

async def delete_mfa_secret(user_id: str) -> bool:
    """
    Удаляет MFA секрет пользователя
    
    ASVS 2.8.5: Возможность отключения MFA
    
    Args:
        user_id: ID пользователя
        
    Returns:
        True если успешно удалено
    """
    try:
        supabase = connection_manager.get_pool('supabase')
        if not supabase:
            logger.error("Supabase unavailable for MFA secret deletion")
            return False
        
        # Помечаем как неактивный (soft delete для аудита)
        await execute_supabase_operation(
            lambda client: client.table("user_mfa_secrets")
                .update({"is_active": False})
                .eq("user_id", user_id)
                .execute(),
            "anon"
        )
        
        logger.info(
            f"MFA disabled",
            extra={
                "user_id": user_id[:8] + "***",
                "event": "mfa_disabled"
            }
        )
        
        return True
        
    except Exception as e:
        logger.error(
            f"Error deleting MFA secret",
            extra={
                "user_id": user_id[:8] + "***",
                "error": str(e),
                "event": "mfa_delete_error"
            }
        )
        return False

async def get_backup_codes(user_id: str) -> Optional[List[str]]:
    """
    Получает backup коды пользователя
    
    ASVS 2.8.2: Backup коды для восстановления доступа
    
    Args:
        user_id: ID пользователя
        
    Returns:
        Список backup кодов или None
    """
    try:
        supabase = connection_manager.get_pool('supabase')
        if not supabase:
            logger.error("Supabase unavailable for backup codes retrieval")
            return None
        
        response = await execute_supabase_operation(
            lambda client: client.table("user_mfa_backup_codes")
                .select("code")
                .eq("user_id", user_id)
                .eq("is_used", False)
                .execute(),
            "anon"
        )
        
        if response and response.data:
            # Расшифровываем коды
            encryption_service = get_encryption_service()
            codes = []
            
            for row in response.data:
                try:
                    decrypted_code = encryption_service.decrypt(row["code"])
                    codes.append(decrypted_code)
                except Exception as decrypt_error:
                    logger.error(f"Failed to decrypt backup code: {decrypt_error}")
                    continue
            
            return codes if codes else None
        
        return None
        
    except Exception as e:
        logger.error(f"Error retrieving backup codes: {e}")
        return None

async def generate_backup_codes(user_id: str, count: int = 10) -> List[str]:
    """
    Генерирует новые backup коды
    
    ASVS 2.8.2: Backup коды для восстановления
    
    Args:
        user_id: ID пользователя
        count: Количество кодов (по умолчанию 10)
        
    Returns:
        Список сгенерированных backup кодов
    """
    try:
        supabase = connection_manager.get_pool('supabase')
        if not supabase:
            logger.error("Supabase unavailable for backup code generation")
            return []
        
        encryption_service = get_encryption_service()
        codes = []
        
        # Генерируем коды
        for _ in range(count):
            # Генерируем случайный 8-значный код
            code = f"{secrets.randbelow(100000000):08d}"
            codes.append(code)
            
            # Шифруем и сохраняем
            try:
                encrypted_code = encryption_service.encrypt(code)
                
                await execute_supabase_operation(
                    lambda client: client.table("user_mfa_backup_codes")
                        .insert({
                            "user_id": user_id,
                            "code": encrypted_code,
                            "is_used": False
                        })
                        .execute(),
                    "anon"
                )
                
            except Exception as save_error:
                logger.error(f"Failed to save backup code: {save_error}")
                continue
        
        logger.info(
            f"Generated {len(codes)} backup codes",
            extra={
                "user_id": user_id[:8] + "***",
                "count": len(codes),
                "event": "backup_codes_generated"
            }
        )
        
        return codes
        
    except Exception as e:
        logger.error(f"Error generating backup codes: {e}")
        return []

async def use_backup_code(user_id: str, code: str) -> bool:
    """
    Использует backup код для входа
    
    ASVS 2.8.2: Одноразовые backup коды
    
    Args:
        user_id: ID пользователя
        code: Backup код
        
    Returns:
        True если код валиден и не использован
    """
    try:
        supabase = connection_manager.get_pool('supabase')
        if not supabase:
            logger.error("Supabase unavailable for backup code validation")
            return False
        
        # Получаем все неиспользованные коды
        response = await execute_supabase_operation(
            lambda client: client.table("user_mfa_backup_codes")
                .select("id, code")
                .eq("user_id", user_id)
                .eq("is_used", False)
                .execute(),
            "anon"
        )
        
        if not response or not response.data:
            return False
        
        # Проверяем каждый код
        encryption_service = get_encryption_service()
        
        for row in response.data:
            try:
                decrypted_code = encryption_service.decrypt(row["code"])
                
                if decrypted_code == code:
                    # Помечаем как использованный
                    await execute_supabase_operation(
                        lambda client: client.table("user_mfa_backup_codes")
                            .update({"is_used": True})
                            .eq("id", row["id"])
                            .execute(),
                        "anon"
                    )
                    
                    logger.info(
                        f"Backup code used",
                        extra={
                            "user_id": user_id[:8] + "***",
                            "event": "backup_code_used"
                        }
                    )
                    
                    return True
                    
            except Exception as decrypt_error:
                logger.error(f"Failed to decrypt backup code: {decrypt_error}")
                continue
        
        return False
        
    except Exception as e:
        logger.error(f"Error using backup code: {e}")
        return False
