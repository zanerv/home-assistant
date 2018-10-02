"""Tests for the auth models."""
from homeassistant.auth import models, permissions


def test_owner_fetching_owner_permissions():
    """Test we fetch the owner permissions for an owner user."""
    group = models.Group(name="Test Group", policy=None)
    owner = models.User(name="Test User", group=group, is_owner=True)
    assert owner.permissions is permissions.OwnerPermissions

    user = models.User(name="Test User", group=group)
    user2 = models.User(name="Test User 2", group=group)
    assert user.permissions is user2.permissions
    assert user.permissions is not owner.permissions
