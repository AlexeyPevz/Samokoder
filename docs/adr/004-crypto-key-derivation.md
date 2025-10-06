# ADR 004: Унификация ключей для Fernet через деривацию

Дата: 2025-10-06

## Контекст

Сервис шифрования `CryptoService` использует библиотеку Fernet, которая требует ключ фиксированного формата: 32 байта, закодированные в urlsafe-base64. В конфигурации приложения `APP_SECRET_KEY` задаётся как обычная строка (например, токен, сгенерированный через `secrets.token_urlsafe(64)`). Ранее некоторые места кода напрямую создавали `Fernet(config.app_secret_key.encode())`, что не соответствует требованиям Fernet и может приводить к ошибкам в рантайме.

Примеры:

```
```36:41:api/routers/keys.py
    if not config.app_secret_key:
        raise HTTPException(status_code=500, detail="Application secret key is not configured")
    return Fernet(config.app_secret_key.encode())
```
```

## Решение

Ввести функцию деривации ключа на основе SHA-256: `_derive_fernet_key(secret)`, которая принимает произвольную строку/байты и возвращает валидный Fernet-ключ (urlsafe_base64(SHA256(secret))). Обновить `CryptoService`, чтобы:

- принимать как «сырой» секрет (строка/байты), так и уже готовый Fernet-ключ;
- по умолчанию применять деривацию инициализационного ключа;
- сохранить обратную совместимость, пытаясь интерпретировать исходное значение как готовый ключ, если деривация недоступна.

Изменения в коде:

```
```1:49:core/security/crypto.py
from cryptography.fernet import Fernet, InvalidToken
...
def _derive_fernet_key(secret: Union[str, bytes]) -> bytes:
    ...

class CryptoService:
    def __init__(self, secret_key: Union[str, bytes]):
        ...
        derived_key = _derive_fernet_key(secret_key)
        self.fernet = Fernet(derived_key)
```
```

И замена прямого использования `Fernet` на `CryptoService` в местах работы с ключами API:

```
```36:51:api/routers/keys.py
def get_crypto():
    config = get_config()
    return CryptoService(config.app_secret_key)

@router.post("/keys"...)
async def add_api_key(..., crypto: CryptoService = Depends(get_crypto)):
    encrypted_key = crypto.encrypt(key_data.api_key)
```
```

## Последствия

- Единообразная и безопасная работа с `APP_SECRET_KEY` независимо от его формата.
- Устранение риска рантайм-ошибок при инициализации `Fernet` (неверный размер/формат ключа).
- Минимальные изменения API — только внутренняя реализация.

## Статус

Принято. Вступает в силу с текущего релиза.
