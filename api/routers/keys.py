from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from samokoder.core.security.crypto import CryptoService
from typing import Dict, Any, Optional

from samokoder.core.db.session import get_async_db
from samokoder.core.db.models.user import User
from samokoder.api.routers.auth import get_current_user
from samokoder.core.config import get_config

router = APIRouter()

class ApiKeyCreate(BaseModel):
    provider: str
    api_key: str
    model: Optional[str] = None
    settings: Optional[Dict[str, Any]] = None

class ApiKeyResponse(BaseModel):
    provider: str
    display_key: str
    model: Optional[str] = None
    settings: Optional[Dict[str, Any]] = None

class ApiKeySettingsUpdate(BaseModel):
    model: Optional[str] = None
    settings: Optional[Dict[str, Any]] = None

class TokenUsageResponse(BaseModel):
    provider: str
    model: str
    total_tokens: int
    requests: int

def get_crypto():
    config = get_config()
    if not config.app_secret_key:
        raise HTTPException(status_code=500, detail="Application secret key is not configured")
    # Используем CryptoService, который сам корректно производит ключ для Fernet
    return CryptoService(config.app_secret_key)

@router.post("/keys", response_model=ApiKeyResponse)
async def add_api_key(
    key_data: ApiKeyCreate,
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user),
    crypto: CryptoService = Depends(get_crypto),
):
    encrypted_key = crypto.encrypt(key_data.api_key)
    # FIX: Handle short keys safely (< 4 characters)
    if len(key_data.api_key) >= 4:
        display_key = f"...-{key_data.api_key[-4:]}"
    else:
        display_key = "***"  # Don't reveal short keys
    
    # The api_keys field is a JSON field. We need to handle it as a dictionary.
    if current_user.api_keys is None:
        current_user.api_keys = {}
        
    current_user.api_keys[key_data.provider] = {
        "encrypted_key": encrypted_key,
        "display_key": display_key
    }
    
    # Save provider settings
    if key_data.model or key_data.settings:
        current_user.update_api_key_settings(key_data.provider, {
            "model": key_data.model,
            "settings": key_data.settings or {}
        })
    
    # Mark the JSON field as modified to ensure SQLAlchemy picks up the change
    from sqlalchemy.orm.attributes import flag_modified
    flag_modified(current_user, "api_keys")

    db.add(current_user)
    await db.commit()
    await db.refresh(current_user)
    
    # Get settings for response
    settings = current_user.get_api_key_settings().get(key_data.provider, {})
    
    return ApiKeyResponse(
        provider=key_data.provider, 
        display_key=display_key,
        model=settings.get("model"),
        settings=settings.get("settings")
    )

@router.get("/keys", response_model=list[ApiKeyResponse])
async def get_api_keys(current_user: User = Depends(get_current_user)):
    if not current_user.api_keys:
        return []
    
    # Get settings for each provider
    user_settings = current_user.get_api_key_settings()
    
    return [
        ApiKeyResponse(
            provider=provider, 
            display_key=data["display_key"],
            model=user_settings.get(provider, {}).get("model"),
            settings=user_settings.get(provider, {}).get("settings")
        )
        for provider, data in current_user.api_keys.items()
    ]

@router.delete("/keys/{provider}", status_code=204)
async def delete_api_key(provider: str, db: AsyncSession = Depends(get_async_db), current_user: User = Depends(get_current_user)):
    if not current_user.api_keys or provider not in current_user.api_keys:
        raise HTTPException(status_code=404, detail="API key for this provider not found")
    
    del current_user.api_keys[provider]
    
    # Also remove settings for this provider
    if current_user.api_key_settings and provider in current_user.api_key_settings:
        del current_user.api_key_settings[provider]
    
    from sqlalchemy.orm.attributes import flag_modified
    flag_modified(current_user, "api_keys")
    flag_modified(current_user, "api_key_settings")

    db.add(current_user)
    await db.commit()
    
    return

@router.put("/keys/{provider}/settings", response_model=ApiKeyResponse)
async def update_api_key_settings(
    provider: str, 
    settings_data: ApiKeySettingsUpdate, 
    db: AsyncSession = Depends(get_async_db), 
    current_user: User = Depends(get_current_user)
):
    if not current_user.api_keys or provider not in current_user.api_keys:
        raise HTTPException(status_code=404, detail="API key for this provider not found")
    
    # Update settings
    current_user.update_api_key_settings(provider, {
        "model": settings_data.model,
        "settings": settings_data.settings or {}
    })
    
    db.add(current_user)
    await db.commit()
    await db.refresh(current_user)
    
    # Get updated settings for response
    settings = current_user.get_api_key_settings().get(provider, {})
    
    return ApiKeyResponse(
        provider=provider,
        display_key=current_user.api_keys[provider]["display_key"],
        model=settings.get("model"),
        settings=settings.get("settings")
    )

@router.get("/keys/{provider}/usage", response_model=list[TokenUsageResponse])
async def get_token_usage(provider: str, current_user: User = Depends(get_current_user)):
    token_usage = current_user.get_token_usage()
    
    if provider not in token_usage:
        return []
    
    usage_data = []
    for model, data in token_usage[provider].items():
        usage_data.append(TokenUsageResponse(
            provider=provider,
            model=model,
            total_tokens=data["total_tokens"],
            requests=data["requests"]
        ))
    
    return usage_data

@router.get("/keys/usage", response_model=Dict[str, Dict[str, TokenUsageResponse]])
async def get_all_token_usage(current_user: User = Depends(get_current_user)):
    token_usage = current_user.get_token_usage()
    
    usage_data = {}
    for provider, models in token_usage.items():
        usage_data[provider] = {}
        for model, data in models.items():
            usage_data[provider][model] = TokenUsageResponse(
                provider=provider,
                model=model,
                total_tokens=data["total_tokens"],
                requests=data["requests"]
            )
    
    return usage_data
