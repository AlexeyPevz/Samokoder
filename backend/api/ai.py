"""
AI endpoints
"""
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import StreamingResponse
from backend.models.requests import ChatRequest, AIUsageRequest
from backend.models.responses import AIResponse, AIUsageStatsResponse, AIUsageInfo
from backend.auth.dependencies import get_current_user
from backend.middleware.secure_rate_limiter import ai_rate_limit
from backend.services.ai_service import get_ai_service
# from backend.services.connection_pool import connection_pool_manager
from backend.services.supabase_manager import execute_supabase_operation
import logging
import json

logger = logging.getLogger(__name__)

router = APIRouter()

@router.post("/chat", response_model=AIResponse)
async def chat_with_ai(
    chat_request: ChatRequest,
    current_user: dict = Depends(get_current_user),
    rate_limit: dict = Depends(ai_rate_limit)
):
    """Chat with AI endpoint"""
    try:
        ai_service = get_ai_service()
        
        # Get user's AI configuration
        # supabase = connection_pool_manager.get_supabase_client()
        settings_response = await execute_supabase_operation(
            lambda client: client.table("user_settings").select("*").eq("user_id", current_user["id"]),
            "anon"
        )
        
        user_settings = settings_response.data[0] if settings_response.data else {}
        
        # Prepare AI request
        ai_request = {
            "message": chat_request.message,
            "model": chat_request.model or user_settings.get("default_model", "deepseek/deepseek-v3"),
            "provider": chat_request.provider or user_settings.get("default_provider", "openrouter"),
            "context": {"context": chat_request.context} if chat_request.context else {},
            "stream": False
        }
        
        # Get AI response
        response = await ai_service.chat_completion(ai_request)
        
        # Log usage
        if response.get("usage"):
            usage_data = {
                "user_id": current_user["id"],
                "project_id": None,  # project_id не используется в ChatRequest
                "provider": ai_request["provider"],
                "model": ai_request["model"],
                "tokens_used": response["usage"].get("total_tokens", 0),
                "cost": response["usage"].get("cost", 0.0)
            }
            
            await execute_supabase_operation(
                lambda client: client.table("ai_usage").insert(usage_data),
                "anon"
            )
        
        return AIResponse(
            content=response["content"],
            model=ai_request["model"],
            provider=ai_request["provider"],
            response_time=response.get("response_time", 0.0),
            tokens_used=response.get("usage", {}).get("total_tokens"),
            cost_usd=response.get("usage", {}).get("total_cost"),
            usage=AIUsageInfo(
                prompt_tokens=response.get("usage", {}).get("prompt_tokens"),
                completion_tokens=response.get("usage", {}).get("completion_tokens"),
                total_tokens=response.get("usage", {}).get("total_tokens"),
                prompt_cost=response.get("usage", {}).get("prompt_cost"),
                completion_cost=response.get("usage", {}).get("completion_cost"),
                total_cost=response.get("usage", {}).get("total_cost")
            )
        )
        
    except Exception as e:
        logger.error(f"AI chat failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="AI chat failed"
        )

@router.post("/chat/stream")
async def chat_with_ai_stream(
    chat_request: ChatRequest,
    current_user: dict = Depends(get_current_user),
    rate_limit: dict = Depends(ai_rate_limit)
):
    """Stream chat with AI endpoint"""
    try:
        ai_service = get_ai_service()
        
        # Get user's AI configuration
        # supabase = connection_pool_manager.get_supabase_client()
        settings_response = await execute_supabase_operation(
            lambda client: client.table("user_settings").select("*").eq("user_id", current_user["id"]),
            "anon"
        )
        
        user_settings = settings_response.data[0] if settings_response.data else {}
        
        # Prepare AI request
        ai_request = {
            "message": chat_request.message,
            "model": chat_request.model or user_settings.get("default_model", "deepseek/deepseek-v3"),
            "provider": chat_request.provider or user_settings.get("default_provider", "openrouter"),
            "context": {"context": chat_request.context} if chat_request.context else {},
            "stream": True
        }
        
        async def generate_response():
            async for chunk in ai_service.chat_completion_stream(ai_request):
                yield f"data: {json.dumps(chunk)}\n\n"
            yield "data: [DONE]\n\n"
        
        return StreamingResponse(
            generate_response(),
            media_type="text/plain",
            headers={"Cache-Control": "no-cache", "Connection": "keep-alive"}
        )
        
    except Exception as e:
        logger.error(f"AI stream chat failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="AI stream chat failed"
        )

@router.get("/usage", response_model=AIUsageStatsResponse)
async def get_ai_usage(
    current_user: dict = Depends(get_current_user),
    days: int = 30,
    rate_limit: dict = Depends(ai_rate_limit)
):
    """Get AI usage statistics"""
    try:
        # supabase = connection_pool_manager.get_supabase_client()
        
        # Get usage data for the specified period
        from datetime import datetime, timedelta
        start_date = datetime.now() - timedelta(days=days)
        
        response = await execute_supabase_operation(
            lambda client: client.table("ai_usage").select("*").eq("user_id", current_user["id"]).gte("created_at", start_date.isoformat()),
            "anon"
        )
        
        usage_data = response.data
        
        # Calculate statistics
        total_tokens = sum(usage.get("tokens_used", 0) for usage in usage_data)
        total_cost = sum(usage.get("cost", 0.0) for usage in usage_data)
        
        # Group by provider
        provider_stats = {}
        for usage in usage_data:
            provider = usage.get("provider", "unknown")
            if provider not in provider_stats:
                provider_stats[provider] = {"tokens": 0, "cost": 0.0, "requests": 0}
            provider_stats[provider]["tokens"] += usage.get("tokens_used", 0)
            provider_stats[provider]["cost"] += usage.get("cost", 0.0)
            provider_stats[provider]["requests"] += 1
        
        return AIUsageStatsResponse(
            total_requests=len(usage_data),
            total_tokens=total_tokens,
            total_cost=total_cost,
            success_rate=100.0,  # Упрощенная логика - все запросы успешны
            providers=provider_stats
        )
        
    except Exception as e:
        logger.error(f"Failed to get AI usage: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get AI usage"
        )

@router.get("/providers")
async def get_ai_providers(
    current_user: dict = Depends(get_current_user),
    rate_limit: dict = Depends(ai_rate_limit)
):
    """Get available AI providers"""
    try:
        # supabase = connection_pool_manager.get_supabase_client()
        
        response = await execute_supabase_operation(
            lambda client: client.table("ai_providers").select("*").eq("is_active", True),
            "anon"
        )
        
        providers = []
        for provider in response.data:
            providers.append({
                "id": provider["id"],
                "name": provider["name"],
                "display_name": provider["display_name"],
                "website_url": provider["website_url"],
                "documentation_url": provider["documentation_url"],
                "requires_api_key": provider["requires_api_key"],
                "pricing_info": provider["pricing_info"]
            })
        
        return {"providers": providers}
        
    except Exception as e:
        logger.error(f"Failed to get AI providers: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get AI providers"
        )

@router.post("/validate-keys")
async def validate_ai_keys(
    keys_data: dict,
    current_user: dict = Depends(get_current_user),
    rate_limit: dict = Depends(ai_rate_limit)
):
    """Validate AI API keys"""
    try:
        # Mock validation - in real app would test each key
        validated_keys = {}
        errors = {}
        
        for provider, key in keys_data.items():
            if not key or len(key) < 10:
                errors[provider] = "Invalid key format"
            else:
                validated_keys[provider] = "valid"
        
        return {
            "validated_keys": validated_keys,
            "errors": errors,
            "total_valid": len(validated_keys),
            "total_invalid": len(errors)
        }
        
    except Exception as e:
        logger.error(f"Failed to validate AI keys: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to validate AI keys"
        )