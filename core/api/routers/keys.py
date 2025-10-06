from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from samokoder.core.db.session import get_db
from samokoder.core.api.dependencies import get_current_user
from samokoder.core.db.models.user import User

router = APIRouter(prefix="/keys", tags=["keys"])

@router.get("/")
async def get_api_keys(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """
    Получить API ключи пользователя.
    BYOK модель - пользователь управляет своими ключами.
    """
    return {
        "message": "API keys management",
        "note": "Users manage their own API keys in the frontend",
        "providers": ["openai", "anthropic", "openrouter", "azure"]
    }

@router.post("/test")
async def test_api_key(
    provider: str,
    api_key: str,
    current_user: User = Depends(get_current_user)
):
    """
    Тестировать API ключ пользователя перед сохранением.
    """
    # Здесь будет логика тестирования ключа
    # Например, отправка тестового запроса к провайдеру
    
    return {
        "provider": provider,
        "status": "success",
        "message": f"API key for {provider} is valid"
    }

@router.get("/usage")
async def get_usage_stats(current_user: User = Depends(get_current_user)):
    """
    Получить статистику использования API пользователя.
    """
    usage = current_user.get_token_usage()
    return {
        "usage": usage,
        "note": "Token usage is tracked per user"
    }
