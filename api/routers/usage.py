from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from samokoder.core.db.session import get_db
from samokoder.core.db.models.user import User
from samokoder.api.routers.auth import get_current_user
from typing import Dict, Any, List
import json

router = APIRouter()

@router.get("/usage/token")
async def get_token_usage(
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Get user's token usage statistics
    
    :param user: Current user
    :param db: Database session
    :return: Token usage statistics
    """
    try:
        token_usage = user.get_token_usage()
        return {
            "usage": token_usage
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error getting token usage: {str(e)}")


@router.get("/usage/token/provider/{provider}")
async def get_provider_token_usage(
    provider: str,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Get token usage statistics for a specific provider
    
    :param provider: Provider name
    :param user: Current user
    :param db: Database session
    :return: Provider token usage statistics
    """
    try:
        token_usage = user.get_token_usage()
        provider_usage = token_usage.get(provider, {})
        
        # Calculate totals for the provider
        total_tokens = sum(model["total_tokens"] for model in provider_usage.values())
        total_requests = sum(model["requests"] for model in provider_usage.values())
        
        return {
            "provider": provider,
            "usage": provider_usage,
            "totals": {
                "total_tokens": total_tokens,
                "total_requests": total_requests,
                "models_count": len(provider_usage)
            }
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error getting provider token usage: {str(e)}")


@router.get("/usage/token/provider/{provider}/model/{model}")
async def get_model_token_usage(
    provider: str,
    model: str,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Get token usage statistics for a specific provider and model
    
    :param provider: Provider name
    :param model: Model name
    :param user: Current user
    :param db: Database session
    :return: Model token usage statistics
    """
    try:
        token_usage = user.get_token_usage()
        model_usage = token_usage.get(provider, {}).get(model, {})
        
        return {
            "provider": provider,
            "model": model,
            "usage": model_usage
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error getting model token usage: {str(e)}")


@router.post("/usage/token/reset")
async def reset_token_usage(
    provider: str = None,
    model: str = None,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Reset token usage statistics
    
    :param provider: Provider name (optional, reset all if not provided)
    :param model: Model name (optional, reset all models if not provided)
    :param user: Current user
    :param db: Database session
    :return: Reset result
    """
    try:
        user.reset_token_usage(provider, model)
        db.commit()
        
        if provider and model:
            return {
                "success": True,
                "message": f"Token usage for {provider}:{model} has been reset"
            }
        elif provider:
            return {
                "success": True,
                "message": f"Token usage for provider {provider} has been reset"
            }
        else:
            return {
                "success": True,
                "message": "All token usage statistics have been reset"
            }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error resetting token usage: {str(e)}")


@router.get("/usage/token/summary")
async def get_token_usage_summary(
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Get a summary of token usage statistics
    
    :param user: Current user
    :param db: Database session
    :return: Token usage summary
    """
    try:
        token_usage = user.get_token_usage()
        
        # Calculate totals
        total_providers = len(token_usage)
        total_tokens = 0
        total_requests = 0
        provider_breakdown = {}
        
        for provider_name, provider_data in token_usage.items():
            provider_tokens = sum(model["total_tokens"] for model in provider_data.values())
            provider_requests = sum(model["requests"] for model in provider_data.values())
            
            total_tokens += provider_tokens
            total_requests += provider_requests
            
            provider_breakdown[provider_name] = {
                "tokens": provider_tokens,
                "requests": provider_requests,
                "models": len(provider_data)
            }
        
        return {
            "totals": {
                "providers": total_providers,
                "tokens": total_tokens,
                "requests": total_requests
            },
            "providers": provider_breakdown
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error getting token usage summary: {str(e)}")