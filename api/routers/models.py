from fastapi import APIRouter, HTTPException, Depends
from typing import Dict, List, Optional
from samokoder.core.db.models.user import User
from samokoder.api.routers.auth import get_current_user
from samokoder.core.api.middleware.tier_limits import TierLimitService

router = APIRouter()

# Model tier mapping - which models are allowed for which tiers
MODEL_TIER_MAP = {
    # Free tier models
    "gpt-3.5-turbo": "free",
    "gpt-4o-mini": "free",
    
    # Starter+ models
    "gpt-4o": "starter",
    "gpt-4-turbo": "starter",
    "gpt-4": "starter",
    
    # Pro+ models
    "claude-3-opus-20240229": "pro",
    "claude-3-sonnet-20240229": "pro",
    "claude-3-haiku-20240307": "pro",
    
    # Team models
    "claude-3-5-sonnet-20241022": "team",
    "claude-3-5-sonnet-20240620": "team",
}

PROVIDER_MODELS = {
    "openai": {
        "models": [
            {"id": "gpt-4o", "name": "GPT-4o", "context": 128000, "tier": "starter"},
            {"id": "gpt-4o-mini", "name": "GPT-4o Mini", "context": 128000, "tier": "free"},
            {"id": "gpt-4-turbo", "name": "GPT-4 Turbo", "context": 128000, "tier": "starter"},
            {"id": "gpt-4", "name": "GPT-4", "context": 8192, "tier": "starter"},
            {"id": "gpt-3.5-turbo", "name": "GPT-3.5 Turbo", "context": 16385, "tier": "free"},
        ],
        "default": "gpt-4o-mini"
    },
    "anthropic": {
        "models": [
            {"id": "claude-3-5-sonnet-20241022", "name": "Claude 3.5 Sonnet (New)", "context": 200000, "tier": "team"},
            {"id": "claude-3-5-sonnet-20240620", "name": "Claude 3.5 Sonnet", "context": 200000, "tier": "team"},
            {"id": "claude-3-opus-20240229", "name": "Claude 3 Opus", "context": 200000, "tier": "pro"},
            {"id": "claude-3-sonnet-20240229", "name": "Claude 3 Sonnet", "context": 200000, "tier": "pro"},
            {"id": "claude-3-haiku-20240307", "name": "Claude 3 Haiku", "context": 200000, "tier": "pro"},
        ],
        "default": "claude-3-5-sonnet-20241022"
    },
    "groq": {
        "models": [
            {"id": "llama-3.3-70b-versatile", "name": "Llama 3.3 70B", "context": 128000, "tier": "free"},
            {"id": "llama-3.1-70b-versatile", "name": "Llama 3.1 70B", "context": 128000, "tier": "free"},
            {"id": "llama-3.1-8b-instant", "name": "Llama 3.1 8B", "context": 128000, "tier": "free"},
            {"id": "mixtral-8x7b-32768", "name": "Mixtral 8x7B", "context": 32768, "tier": "free"},
        ],
        "default": "llama-3.3-70b-versatile"
    },
    "openrouter": {
        "models": [
            {"id": "openai/gpt-4-turbo", "name": "OpenAI: GPT-4 Turbo", "context": 128000, "tier": "starter"},
            {"id": "openai/gpt-3.5-turbo", "name": "OpenAI: GPT-3.5 Turbo", "context": 16385, "tier": "free"},
            {"id": "anthropic/claude-3-5-sonnet", "name": "Anthropic: Claude 3.5 Sonnet", "context": 200000, "tier": "team"},
            {"id": "anthropic/claude-3-opus", "name": "Anthropic: Claude 3 Opus", "context": 200000, "tier": "pro"},
            {"id": "google/gemini-pro-1.5", "name": "Google: Gemini Pro 1.5", "context": 1000000, "tier": "pro"},
            {"id": "meta-llama/llama-3-70b-instruct", "name": "Meta: Llama 3 70B", "context": 8192, "tier": "free"},
        ],
        "default": "anthropic/claude-3-5-sonnet"
    }
}

# Tier hierarchy for comparison
TIER_HIERARCHY = {
    "free": 0,
    "starter": 1,
    "pro": 2,
    "team": 3
}


def filter_models_by_tier(models: List[Dict], user_tier: str) -> List[Dict]:
    """Filter models based on user's tier."""
    user_tier_level = TIER_HIERARCHY.get(user_tier, 0)
    
    filtered_models = []
    for model in models:
        model_tier = model.get("tier", "free")
        model_tier_level = TIER_HIERARCHY.get(model_tier, 0)
        
        # Create a copy of the model dict
        model_copy = model.copy()
        
        if model_tier_level <= user_tier_level:
            model_copy["available"] = True
        else:
            model_copy["available"] = False
            model_copy["required_tier"] = model_tier
        
        filtered_models.append(model_copy)
    
    return filtered_models


@router.get("/models", response_model=Dict[str, Dict])
async def get_available_models(current_user: Optional[User] = Depends(get_current_user)):
    """Get list of available models for each provider, filtered by user tier."""
    if not current_user:
        # Return all models without filtering if not authenticated
        return PROVIDER_MODELS
    
    user_tier = current_user.tier.value
    filtered_providers = {}
    
    for provider, provider_data in PROVIDER_MODELS.items():
        filtered_providers[provider] = {
            "models": filter_models_by_tier(provider_data["models"], user_tier),
            "default": provider_data["default"]
        }
    
    return filtered_providers


@router.get("/models/{provider}", response_model=Dict)
async def get_provider_models(
    provider: str,
    current_user: Optional[User] = Depends(get_current_user)
):
    """Get list of models for a specific provider, filtered by user tier."""
    if provider not in PROVIDER_MODELS:
        raise HTTPException(status_code=404, detail=f"Provider {provider} not found")
    
    provider_data = PROVIDER_MODELS[provider]
    
    if not current_user:
        # Return all models without filtering if not authenticated
        return provider_data
    
    user_tier = current_user.tier.value
    
    return {
        "models": filter_models_by_tier(provider_data["models"], user_tier),
        "default": provider_data["default"]
    }
