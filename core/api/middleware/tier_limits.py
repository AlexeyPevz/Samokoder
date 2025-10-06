"""
Comprehensive tier-based limits for monetization.

This module defines and enforces all tier-based restrictions including:
- Project creation limits
- Deployment limits  
- Export limits
- Git operations limits
- LLM model access restrictions
- API rate limits
"""

from enum import Enum
from typing import Dict, List, Optional, Set
from datetime import datetime, timedelta
import calendar
from fastapi import Depends, HTTPException
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from samokoder.core.db.models.user import User, Tier
from samokoder.core.db.models.project import Project
from samokoder.core.db.session import get_async_db
from samokoder.api.routers.auth import get_current_user


class TierFeature(str, Enum):
    """Features that can be restricted by tier."""
    CREATE_PROJECT = "create_project"
    DEPLOY = "deploy"
    EXPORT = "export"
    GIT_PUSH = "git_push"
    ADVANCED_MODELS = "advanced_models"  # GPT-4, Claude, etc.
    CUSTOM_TEMPLATES = "custom_templates"
    TEAM_COLLABORATION = "team_collaboration"
    PRIORITY_SUPPORT = "priority_support"
    CUSTOM_BRANDING = "custom_branding"


# Tier configuration with all limits and features
TIER_CONFIG: Dict[Tier, Dict] = {
    Tier.FREE: {
        "name": "Free",
        "price": 0,
        "limits": {
            "projects_monthly": 2,
            "projects_total": 2,
            "deployments_monthly": 0,  # No deployments
            "exports_monthly": 2,
            "git_pushes_monthly": 5,
        },
        "features": {
            TierFeature.CREATE_PROJECT: True,
            TierFeature.DEPLOY: False,
            TierFeature.EXPORT: True,
            TierFeature.GIT_PUSH: True,
            TierFeature.ADVANCED_MODELS: False,
            TierFeature.CUSTOM_TEMPLATES: False,
            TierFeature.TEAM_COLLABORATION: False,
            TierFeature.PRIORITY_SUPPORT: False,
            TierFeature.CUSTOM_BRANDING: False,
        },
        "allowed_models": ["gpt-3.5-turbo", "gpt-4o-mini"],
        "rate_limits": {
            "requests_per_minute": 30,
            "requests_per_hour": 1000,
            "requests_per_day": 10000,
        }
    },
    Tier.STARTER: {
        "name": "Starter",
        "price": 490,
        "limits": {
            "projects_monthly": 10,
            "projects_total": 100,
            "deployments_monthly": 10,
            "exports_monthly": 50,
            "git_pushes_monthly": 100,
        },
        "features": {
            TierFeature.CREATE_PROJECT: True,
            TierFeature.DEPLOY: True,
            TierFeature.EXPORT: True,
            TierFeature.GIT_PUSH: True,
            TierFeature.ADVANCED_MODELS: True,
            TierFeature.CUSTOM_TEMPLATES: True,
            TierFeature.TEAM_COLLABORATION: False,
            TierFeature.PRIORITY_SUPPORT: False,
            TierFeature.CUSTOM_BRANDING: False,
        },
        "allowed_models": ["gpt-3.5-turbo", "gpt-4o-mini", "gpt-4o", "gpt-4-turbo"],
        "rate_limits": {
            "requests_per_minute": 100,
            "requests_per_hour": 5000,
            "requests_per_day": 50000,
        }
    },
    Tier.PRO: {
        "name": "Pro",
        "price": 1490,
        "limits": {
            "projects_monthly": 50,
            "projects_total": float('inf'),
            "deployments_monthly": 100,
            "exports_monthly": float('inf'),
            "git_pushes_monthly": float('inf'),
        },
        "features": {
            TierFeature.CREATE_PROJECT: True,
            TierFeature.DEPLOY: True,
            TierFeature.EXPORT: True,
            TierFeature.GIT_PUSH: True,
            TierFeature.ADVANCED_MODELS: True,
            TierFeature.CUSTOM_TEMPLATES: True,
            TierFeature.TEAM_COLLABORATION: True,
            TierFeature.PRIORITY_SUPPORT: True,
            TierFeature.CUSTOM_BRANDING: False,
        },
        "allowed_models": [
            "gpt-3.5-turbo", "gpt-4o-mini", "gpt-4o", "gpt-4-turbo",
            "claude-3-opus", "claude-3-sonnet", "claude-3-haiku"
        ],
        "rate_limits": {
            "requests_per_minute": 200,
            "requests_per_hour": 10000,
            "requests_per_day": 100000,
        }
    },
    Tier.TEAM: {
        "name": "Team",
        "price": 2490,
        "limits": {
            "projects_monthly": float('inf'),
            "projects_total": float('inf'),
            "deployments_monthly": float('inf'),
            "exports_monthly": float('inf'),
            "git_pushes_monthly": float('inf'),
        },
        "features": {
            TierFeature.CREATE_PROJECT: True,
            TierFeature.DEPLOY: True,
            TierFeature.EXPORT: True,
            TierFeature.GIT_PUSH: True,
            TierFeature.ADVANCED_MODELS: True,
            TierFeature.CUSTOM_TEMPLATES: True,
            TierFeature.TEAM_COLLABORATION: True,
            TierFeature.PRIORITY_SUPPORT: True,
            TierFeature.CUSTOM_BRANDING: True,
        },
        "allowed_models": [
            "gpt-3.5-turbo", "gpt-4o-mini", "gpt-4o", "gpt-4-turbo",
            "claude-3-opus", "claude-3-sonnet", "claude-3-haiku",
            "claude-3.5-sonnet"
        ],
        "rate_limits": {
            "requests_per_minute": 500,
            "requests_per_hour": 20000,
            "requests_per_day": 200000,
        }
    }
}


class TierLimitService:
    """Service for checking and enforcing tier limits."""

    @staticmethod
    def get_tier_config(tier: Tier) -> Dict:
        """Get configuration for a specific tier."""
        return TIER_CONFIG.get(tier, TIER_CONFIG[Tier.FREE])

    @staticmethod
    def has_feature(user: User, feature: TierFeature) -> bool:
        """Check if user's tier has access to a feature."""
        config = TierLimitService.get_tier_config(user.tier)
        return config["features"].get(feature, False)

    @staticmethod
    def get_allowed_models(user: User) -> List[str]:
        """Get list of allowed LLM models for user's tier."""
        config = TierLimitService.get_tier_config(user.tier)
        return config["allowed_models"]

    @staticmethod
    def is_model_allowed(user: User, model: str) -> bool:
        """Check if a specific model is allowed for user's tier."""
        allowed = TierLimitService.get_allowed_models(user)
        return model in allowed

    @staticmethod
    async def get_monthly_usage(
        db: AsyncSession,
        user: User,
        model_class,
        date_field: str = "created_at"
    ) -> int:
        """Get count of records for current month."""
        now = datetime.utcnow()
        month_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        month_end = month_start + timedelta(days=calendar.monthrange(now.year, now.month)[1])

        query = select(func.count()).select_from(model_class).where(
            model_class.user_id == user.id,
            getattr(model_class, date_field) >= month_start,
            getattr(model_class, date_field) < month_end
        )
        result = await db.execute(query)
        return result.scalar() or 0

    @staticmethod
    async def check_project_limits(
        db: AsyncSession,
        user: User
    ) -> None:
        """Check if user can create a new project."""
        config = TierLimitService.get_tier_config(user.tier)
        limits = config["limits"]

        # Check monthly limit
        monthly_count = await TierLimitService.get_monthly_usage(db, user, Project)
        if monthly_count >= limits["projects_monthly"]:
            raise HTTPException(
                status_code=402,
                detail=f"Monthly project limit reached ({limits['projects_monthly']} projects). "
                       f"Upgrade to {Tier.STARTER.value if user.tier == Tier.FREE else Tier.PRO.value} for more projects."
            )

        # Check total limit
        total_query = select(func.count()).select_from(Project).where(
            Project.user_id == user.id
        )
        total_result = await db.execute(total_query)
        total_count = total_result.scalar() or 0

        if total_count >= limits["projects_total"]:
            raise HTTPException(
                status_code=402,
                detail=f"Total project limit reached ({limits['projects_total']} projects). "
                       f"Upgrade to {Tier.PRO.value} for unlimited projects."
            )

    @staticmethod
    async def check_feature_access(
        user: User,
        feature: TierFeature,
        upgrade_tier: Optional[Tier] = None
    ) -> None:
        """Check if user has access to a feature, raise exception if not."""
        if not TierLimitService.has_feature(user, feature):
            upgrade_msg = ""
            if upgrade_tier:
                upgrade_msg = f" Upgrade to {upgrade_tier.value} to access this feature."
            elif user.tier == Tier.FREE:
                upgrade_msg = f" Upgrade to {Tier.STARTER.value} or higher to access this feature."
            
            raise HTTPException(
                status_code=403,
                detail=f"Feature '{feature.value}' is not available in your current plan ({user.tier.value}).{upgrade_msg}"
            )

    @staticmethod
    async def check_operation_limit(
        db: AsyncSession,
        user: User,
        operation_type: str,
        limit_key: str
    ) -> None:
        """
        Check if user can perform an operation based on monthly limits.
        
        Args:
            db: Database session
            user: Current user
            operation_type: Type of operation (for tracking)
            limit_key: Key in limits dict (e.g., 'deployments_monthly')
        """
        config = TierLimitService.get_tier_config(user.tier)
        limit = config["limits"].get(limit_key, 0)
        
        if limit == float('inf'):
            return  # Unlimited
        
        # Track usage in user metadata (you may want to create separate tracking tables)
        usage_key = f"{operation_type}_monthly_count"
        current_usage = user.token_usage.get(usage_key, 0) if user.token_usage else 0
        
        if current_usage >= limit:
            raise HTTPException(
                status_code=402,
                detail=f"Monthly {operation_type} limit reached ({limit}). "
                       f"Upgrade your plan for more {operation_type}s."
            )


# Dependency functions for FastAPI routes

async def require_project_limits(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_db)
) -> None:
    """Dependency to check project creation limits."""
    await TierLimitService.check_project_limits(db, current_user)


async def require_deploy_access(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_db)
) -> None:
    """Dependency to check deployment access."""
    await TierLimitService.check_feature_access(
        current_user, 
        TierFeature.DEPLOY,
        upgrade_tier=Tier.STARTER
    )
    await TierLimitService.check_operation_limit(
        db, 
        current_user, 
        "deployment", 
        "deployments_monthly"
    )


async def require_export_access(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_db)
) -> None:
    """Dependency to check export access."""
    # Export is available for all tiers, just check limits
    await TierLimitService.check_operation_limit(
        db,
        current_user,
        "export",
        "exports_monthly"
    )


async def require_git_push_access(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_db)
) -> None:
    """Dependency to check git push access."""
    await TierLimitService.check_operation_limit(
        db,
        current_user,
        "git_push",
        "git_pushes_monthly"
    )


def require_model_access(model: str):
    """Dependency factory to check LLM model access."""
    async def _check(current_user: User = Depends(get_current_user)) -> None:
        if not TierLimitService.is_model_allowed(current_user, model):
            allowed = TierLimitService.get_allowed_models(current_user)
            raise HTTPException(
                status_code=403,
                detail=f"Model '{model}' is not available in your plan ({current_user.tier.value}). "
                       f"Available models: {', '.join(allowed)}. "
                       f"Upgrade to access more advanced models."
            )
    return _check


async def get_tier_info(current_user: User = Depends(get_current_user)) -> Dict:
    """Get tier information for current user."""
    config = TierLimitService.get_tier_config(current_user.tier)
    return {
        "tier": current_user.tier.value,
        "name": config["name"],
        "price": config["price"],
        "limits": config["limits"],
        "features": {k.value: v for k, v in config["features"].items()},
        "allowed_models": config["allowed_models"],
    }
