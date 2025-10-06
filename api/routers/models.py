from fastapi import APIRouter, HTTPException
from typing import Dict

router = APIRouter()

# All models available - BYOK (Bring Your Own Key) model
# Users provide their own API keys, so all models are accessible
PROVIDER_MODELS = {
    "openai": {
        "models": [
            {"id": "gpt-4o", "name": "GPT-4o", "context": 128000},
            {"id": "gpt-4o-mini", "name": "GPT-4o Mini", "context": 128000},
            {"id": "gpt-4-turbo", "name": "GPT-4 Turbo", "context": 128000},
            {"id": "gpt-4", "name": "GPT-4", "context": 8192},
            {"id": "gpt-3.5-turbo", "name": "GPT-3.5 Turbo", "context": 16385},
        ],
        "default": "gpt-4o-mini"
    },
    "anthropic": {
        "models": [
            {"id": "claude-3-5-sonnet-20241022", "name": "Claude 3.5 Sonnet (New)", "context": 200000},
            {"id": "claude-3-5-sonnet-20240620", "name": "Claude 3.5 Sonnet", "context": 200000},
            {"id": "claude-3-opus-20240229", "name": "Claude 3 Opus", "context": 200000},
            {"id": "claude-3-sonnet-20240229", "name": "Claude 3 Sonnet", "context": 200000},
            {"id": "claude-3-haiku-20240307", "name": "Claude 3 Haiku", "context": 200000},
        ],
        "default": "claude-3-5-sonnet-20241022"
    },
    "groq": {
        "models": [
            {"id": "llama-3.3-70b-versatile", "name": "Llama 3.3 70B", "context": 128000},
            {"id": "llama-3.1-70b-versatile", "name": "Llama 3.1 70B", "context": 128000},
            {"id": "llama-3.1-8b-instant", "name": "Llama 3.1 8B", "context": 128000},
            {"id": "mixtral-8x7b-32768", "name": "Mixtral 8x7B", "context": 32768},
        ],
        "default": "llama-3.3-70b-versatile"
    },
    "openrouter": {
        "models": [
            {"id": "openai/gpt-4-turbo", "name": "OpenAI: GPT-4 Turbo", "context": 128000},
            {"id": "openai/gpt-3.5-turbo", "name": "OpenAI: GPT-3.5 Turbo", "context": 16385},
            {"id": "anthropic/claude-3-5-sonnet", "name": "Anthropic: Claude 3.5 Sonnet", "context": 200000},
            {"id": "anthropic/claude-3-opus", "name": "Anthropic: Claude 3 Opus", "context": 200000},
            {"id": "google/gemini-pro-1.5", "name": "Google: Gemini Pro 1.5", "context": 1000000},
            {"id": "meta-llama/llama-3-70b-instruct", "name": "Meta: Llama 3 70B", "context": 8192},
        ],
        "default": "anthropic/claude-3-5-sonnet"
    }
}

@router.get("/models", response_model=Dict[str, Dict])
async def get_available_models():
    """Get list of available models for each provider (no auth required - BYOK model)"""
    return PROVIDER_MODELS

@router.get("/models/{provider}", response_model=Dict)
async def get_provider_models(provider: str):
    """Get list of models for a specific provider (no auth required - BYOK model)"""
    if provider not in PROVIDER_MODELS:
        raise HTTPException(status_code=404, detail=f"Provider {provider} not found")
    return PROVIDER_MODELS[provider]
