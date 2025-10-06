"""
Tests for tier-based monetization limits.
"""

import pytest
from unittest.mock import Mock, AsyncMock
from sqlalchemy.ext.asyncio import AsyncSession

from samokoder.core.db.models.user import User, Tier
from samokoder.core.db.models.project import Project
from samokoder.core.api.middleware.tier_limits import (
    TierLimitService,
    TierFeature,
    TIER_CONFIG,
)
from fastapi import HTTPException


class TestTierConfig:
    """Test tier configuration structure."""

    def test_all_tiers_have_config(self):
        """All tier types should have configuration."""
        for tier in Tier:
            assert tier in TIER_CONFIG
            config = TIER_CONFIG[tier]
            assert "name" in config
            assert "price" in config
            assert "limits" in config
            assert "features" in config
            assert "allowed_models" in config

    def test_tier_hierarchy(self):
        """Test that higher tiers have more features than lower tiers."""
        free_config = TIER_CONFIG[Tier.FREE]
        starter_config = TIER_CONFIG[Tier.STARTER]
        pro_config = TIER_CONFIG[Tier.PRO]
        team_config = TIER_CONFIG[Tier.TEAM]

        # Check project limits increase
        assert free_config["limits"]["projects_monthly"] < starter_config["limits"]["projects_monthly"]
        assert starter_config["limits"]["projects_monthly"] < pro_config["limits"]["projects_monthly"]

        # Check model access increases
        assert len(free_config["allowed_models"]) <= len(starter_config["allowed_models"])
        assert len(starter_config["allowed_models"]) <= len(pro_config["allowed_models"])
        assert len(pro_config["allowed_models"]) <= len(team_config["allowed_models"])

    def test_free_tier_limitations(self):
        """Free tier should have basic limitations."""
        free_config = TIER_CONFIG[Tier.FREE]
        
        # No deployments for free tier
        assert free_config["limits"]["deployments_monthly"] == 0
        
        # No advanced features
        assert free_config["features"][TierFeature.DEPLOY] == False
        assert free_config["features"][TierFeature.ADVANCED_MODELS] == False
        assert free_config["features"][TierFeature.TEAM_COLLABORATION] == False


class TestTierLimitService:
    """Test TierLimitService methods."""

    def test_get_tier_config(self):
        """Test getting tier configuration."""
        free_config = TierLimitService.get_tier_config(Tier.FREE)
        assert free_config["name"] == "Free"
        assert free_config["price"] == 0

        starter_config = TierLimitService.get_tier_config(Tier.STARTER)
        assert starter_config["name"] == "Starter"
        assert starter_config["price"] == 490

    def test_has_feature_free_tier(self):
        """Test feature access for free tier users."""
        user = Mock(spec=User)
        user.tier = Tier.FREE

        # Free tier has basic features
        assert TierLimitService.has_feature(user, TierFeature.CREATE_PROJECT)
        assert TierLimitService.has_feature(user, TierFeature.EXPORT)

        # But not premium features
        assert not TierLimitService.has_feature(user, TierFeature.DEPLOY)
        assert not TierLimitService.has_feature(user, TierFeature.ADVANCED_MODELS)
        assert not TierLimitService.has_feature(user, TierFeature.TEAM_COLLABORATION)

    def test_has_feature_starter_tier(self):
        """Test feature access for starter tier users."""
        user = Mock(spec=User)
        user.tier = Tier.STARTER

        # Starter has deployment
        assert TierLimitService.has_feature(user, TierFeature.DEPLOY)
        assert TierLimitService.has_feature(user, TierFeature.ADVANCED_MODELS)
        
        # But not team features
        assert not TierLimitService.has_feature(user, TierFeature.TEAM_COLLABORATION)

    def test_has_feature_pro_tier(self):
        """Test feature access for pro tier users."""
        user = Mock(spec=User)
        user.tier = Tier.PRO

        # Pro has all features except custom branding
        assert TierLimitService.has_feature(user, TierFeature.DEPLOY)
        assert TierLimitService.has_feature(user, TierFeature.ADVANCED_MODELS)
        assert TierLimitService.has_feature(user, TierFeature.TEAM_COLLABORATION)
        assert not TierLimitService.has_feature(user, TierFeature.CUSTOM_BRANDING)

    def test_has_feature_team_tier(self):
        """Test feature access for team tier users."""
        user = Mock(spec=User)
        user.tier = Tier.TEAM

        # Team has all features
        assert TierLimitService.has_feature(user, TierFeature.DEPLOY)
        assert TierLimitService.has_feature(user, TierFeature.ADVANCED_MODELS)
        assert TierLimitService.has_feature(user, TierFeature.TEAM_COLLABORATION)
        assert TierLimitService.has_feature(user, TierFeature.CUSTOM_BRANDING)

    def test_get_allowed_models_free(self):
        """Test allowed models for free tier."""
        user = Mock(spec=User)
        user.tier = Tier.FREE

        allowed = TierLimitService.get_allowed_models(user)
        assert "gpt-3.5-turbo" in allowed
        assert "gpt-4o-mini" in allowed
        assert "gpt-4o" not in allowed  # Not available in free tier

    def test_get_allowed_models_starter(self):
        """Test allowed models for starter tier."""
        user = Mock(spec=User)
        user.tier = Tier.STARTER

        allowed = TierLimitService.get_allowed_models(user)
        assert "gpt-3.5-turbo" in allowed
        assert "gpt-4o" in allowed
        assert "gpt-4-turbo" in allowed

    def test_is_model_allowed(self):
        """Test checking if specific model is allowed."""
        free_user = Mock(spec=User)
        free_user.tier = Tier.FREE

        starter_user = Mock(spec=User)
        starter_user.tier = Tier.STARTER

        # Free user can use basic models
        assert TierLimitService.is_model_allowed(free_user, "gpt-3.5-turbo")
        assert not TierLimitService.is_model_allowed(free_user, "gpt-4o")

        # Starter user can use advanced models
        assert TierLimitService.is_model_allowed(starter_user, "gpt-3.5-turbo")
        assert TierLimitService.is_model_allowed(starter_user, "gpt-4o")

    @pytest.mark.asyncio
    async def test_check_feature_access_allowed(self):
        """Test that check_feature_access passes for allowed features."""
        user = Mock(spec=User)
        user.tier = Tier.STARTER

        # Should not raise for allowed feature
        await TierLimitService.check_feature_access(user, TierFeature.DEPLOY)

    @pytest.mark.asyncio
    async def test_check_feature_access_denied(self):
        """Test that check_feature_access raises for denied features."""
        user = Mock(spec=User)
        user.tier = Tier.FREE

        # Should raise HTTPException for disallowed feature
        with pytest.raises(HTTPException) as exc_info:
            await TierLimitService.check_feature_access(user, TierFeature.DEPLOY)
        
        assert exc_info.value.status_code == 403
        assert "not available" in str(exc_info.value.detail).lower()

    @pytest.mark.asyncio
    async def test_check_project_limits_free_tier(self):
        """Test project limits for free tier."""
        user = Mock(spec=User)
        user.id = 1
        user.tier = Tier.FREE

        db = AsyncMock(spec=AsyncSession)
        
        # Mock monthly count = 2 (limit reached)
        db.execute = AsyncMock(return_value=Mock(scalar=Mock(return_value=2)))

        # Should raise because limit is 2 for free tier
        with pytest.raises(HTTPException) as exc_info:
            await TierLimitService.check_project_limits(db, user)
        
        assert exc_info.value.status_code == 402
        assert "limit reached" in str(exc_info.value.detail).lower()


class TestModelTierFiltering:
    """Test model tier filtering in models endpoint."""

    def test_filter_basic_models(self):
        """Test that basic models are available to all tiers."""
        from api.routers.models import filter_models_by_tier

        models = [
            {"id": "gpt-3.5-turbo", "name": "GPT-3.5 Turbo", "tier": "free"},
            {"id": "gpt-4o", "name": "GPT-4o", "tier": "starter"},
        ]

        # Free tier user should see gpt-3.5-turbo as available
        free_filtered = filter_models_by_tier(models, "free")
        assert free_filtered[0]["available"] == True
        assert free_filtered[1]["available"] == False
        assert free_filtered[1]["required_tier"] == "starter"

    def test_filter_advanced_models(self):
        """Test that advanced models are filtered correctly."""
        from api.routers.models import filter_models_by_tier

        models = [
            {"id": "gpt-3.5-turbo", "name": "GPT-3.5 Turbo", "tier": "free"},
            {"id": "claude-3-opus", "name": "Claude 3 Opus", "tier": "pro"},
        ]

        # Starter tier user should not see Claude as available
        starter_filtered = filter_models_by_tier(models, "starter")
        assert starter_filtered[0]["available"] == True
        assert starter_filtered[1]["available"] == False
        assert starter_filtered[1]["required_tier"] == "pro"

        # Pro tier user should see both as available
        pro_filtered = filter_models_by_tier(models, "pro")
        assert pro_filtered[0]["available"] == True
        assert pro_filtered[1]["available"] == True


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
