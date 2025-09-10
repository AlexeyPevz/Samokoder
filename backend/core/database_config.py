"""
Database configuration and table names
"""
from typing import Dict, List

class DatabaseConfig:
    """Database configuration with table names and constants"""
    
    # Table names
    TABLES = {
        "profiles": "profiles",
        "user_settings": "user_settings", 
        "ai_providers": "ai_providers",
        "projects": "projects",
        "chat_sessions": "chat_sessions",
        "chat_messages": "chat_messages",
        "api_keys": "api_keys",
        "files": "files",
        "ai_usage": "ai_usage"
    }
    
    # Column names
    COLUMNS = {
        "id": "id",
        "user_id": "user_id",
        "project_id": "project_id",
        "session_id": "session_id",
        "email": "email",
        "created_at": "created_at",
        "updated_at": "updated_at",
        "is_active": "is_active"
    }
    
    # Common queries
    QUERIES = {
        "select_all": "*",
        "count_exact": "id",
        "order_created_desc": "created_at",
        "order_updated_desc": "updated_at"
    }
    
    # Pagination defaults
    PAGINATION = {
        "default_limit": 10,
        "max_limit": 100,
        "default_offset": 0
    }
    
    # Status values
    STATUS = {
        "active": "active",
        "inactive": "inactive",
        "deleted": "deleted"
    }
    
    # Subscription tiers
    SUBSCRIPTION_TIERS = {
        "free": "free",
        "starter": "starter", 
        "professional": "professional",
        "business": "business",
        "enterprise": "enterprise"
    }
    
    # Subscription statuses
    SUBSCRIPTION_STATUSES = {
        "active": "active",
        "canceled": "canceled",
        "past_due": "past_due",
        "trialing": "trialing"
    }
    
    # Chat message roles
    CHAT_ROLES = {
        "user": "user",
        "assistant": "assistant",
        "system": "system"
    }
    
    # AI providers
    AI_PROVIDERS = {
        "openrouter": "openrouter",
        "openai": "openai",
        "anthropic": "anthropic",
        "groq": "groq"
    }
    
    # User themes
    THEMES = {
        "light": "light",
        "dark": "dark",
        "auto": "auto"
    }

# Global instance
db_config = DatabaseConfig()