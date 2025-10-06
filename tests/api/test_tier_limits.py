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
            assert "rate_limits" in config
            # Note: No "allowed_models" because we use BYOK model

    def test_tier_hierarchy(self):
        """Test that higher tiers have more features than lower tiers."""
        free_config = TIER_CONFIG[Tier.FREE]
        starter_config = TIER_CONFIG[Tier.STARTER]
        pro_config = TIER_CONFIG[Tier.PRO]
        team_config = TIER_CONFIG[Tier.TEAM]

        # Check project limits increase
        assert free_config["limits"]["projects_monthly"] < starter_config["limits"]["projects_monthly"]
        assert starter_config["limits"]["projects_monthly"] < pro_config["limits"]["projects_monthly"]

        # Check rate limits increase
        assert free_config["rate_limits"]["requests_per_minute"] < starter_config["rate_limits"]["requests_per_minute"]
        assert starter_config["rate_limits"]["requests_per_minute"] < pro_config["rate_limits"]["requests_per_minute"]

    def test_free_tier_limitations(self):
        """Free tier should have basic limitations."""
        free_config = TIER_CONFIG[Tier.FREE]
        
        # No deployments for free tier
        assert free_config["limits"]["deployments_monthly"] == 0
        
        # No advanced features
        assert free_config["features"][TierFeature.DEPLOY] == False
        assert free_config["features"][TierFeature.TEAM_COLLABORATION] == False
        
        # But all models are available (BYOK)
        # No "allowed_models" field because we use BYOK model


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
        assert not TierLimitService.has_feature(user, TierFeature.TEAM_COLLABORATION)

    def test_has_feature_starter_tier(self):
        """Test feature access for starter tier users."""
        user = Mock(spec=User)
        user.tier = Tier.STARTER

        # Starter has deployment and custom templates
        assert TierLimitService.has_feature(user, TierFeature.DEPLOY)
        assert TierLimitService.has_feature(user, TierFeature.CUSTOM_TEMPLATES)
        
        # But not team features
        assert not TierLimitService.has_feature(user, TierFeature.TEAM_COLLABORATION)

    def test_has_feature_pro_tier(self):
        """Test feature access for pro tier users."""
        user = Mock(spec=User)
        user.tier = Tier.PRO

        # Pro has all features except custom branding
        assert TierLimitService.has_feature(user, TierFeature.DEPLOY)
        assert TierLimitService.has_feature(user, TierFeature.CUSTOM_TEMPLATES)
        assert TierLimitService.has_feature(user, TierFeature.TEAM_COLLABORATION)
        assert not TierLimitService.has_feature(user, TierFeature.CUSTOM_BRANDING)

    def test_has_feature_team_tier(self):
        """Test feature access for team tier users."""
        user = Mock(spec=User)
        user.tier = Tier.TEAM

        # Team has all features
        assert TierLimitService.has_feature(user, TierFeature.DEPLOY)
        assert TierLimitService.has_feature(user, TierFeature.CUSTOM_TEMPLATES)
        assert TierLimitService.has_feature(user, TierFeature.TEAM_COLLABORATION)
        assert TierLimitService.has_feature(user, TierFeature.CUSTOM_BRANDING)

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


class TestBYOKModel:
    """Test BYOK (Bring Your Own Key) model - all models available to all users."""

    def test_models_available_to_all(self):
        """Test that all models are available regardless of tier (BYOK)."""
        from api.routers.models import PROVIDER_MODELS

        # Check that models don't have tier restrictions
        for provider, provider_data in PROVIDER_MODELS.items():
            for model in provider_data["models"]:
                # Models should not have 'tier' field in BYOK model
                assert "tier" not in model, f"Model {model['id']} should not have tier restriction in BYOK model"
                
    def test_no_auth_required_for_models(self):
        """Test that models endpoint doesn't require authentication (BYOK)."""
        # This is a documentation test - the actual endpoint should work without auth
        # In BYOK model, users use their own API keys, so model list is public
        pass


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
