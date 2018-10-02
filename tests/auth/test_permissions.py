"""Tests for the auth permission system."""
from homeassistant.core import State
from homeassistant.auth import permissions


def test_entities_none():
    """Test entity ID policy."""
    policy = None
    compiled = permissions._compile_entities(policy)
    assert not compiled('light.kitchen', [])


def test_entities_empty():
    """Test entity ID policy."""
    policy = {}
    permissions.ENTITY_POLICY_SCHEMA(policy)
    compiled = permissions._compile_entities(policy)
    assert not compiled('light.kitchen', [])


def test_entities_false():
    """Test entity ID policy."""
    policy = False
    permissions.ENTITY_POLICY_SCHEMA(policy)
    compiled = permissions._compile_entities(policy)
    assert not compiled('light.kitchen', [])


def test_entities_true():
    """Test entity ID policy."""
    policy = True
    permissions.ENTITY_POLICY_SCHEMA(policy)
    compiled = permissions._compile_entities(policy)
    assert compiled('light.kitchen', [])


def test_entities_domains_true():
    """Test entity ID policy."""
    policy = {
        'domains': True
    }
    permissions.ENTITY_POLICY_SCHEMA(policy)
    compiled = permissions._compile_entities(policy)
    assert compiled('light.kitchen', [])


def test_entities_domains_false():
    """Test entity ID policy."""
    policy = {
        'domains': False
    }
    permissions.ENTITY_POLICY_SCHEMA(policy)
    compiled = permissions._compile_entities(policy)
    assert not compiled('light.kitchen', [])


def test_entities_domains_domain_true():
    """Test entity ID policy."""
    policy = {
        'domains': {
            'light': True
        }
    }
    permissions.ENTITY_POLICY_SCHEMA(policy)
    compiled = permissions._compile_entities(policy)
    assert compiled('light.kitchen', [])
    assert not compiled('switch.kitchen', [])


def test_entities_domains_domain_false():
    """Test entity ID policy."""
    policy = {
        'domains': {
            'light': False
        }
    }
    permissions.ENTITY_POLICY_SCHEMA(policy)
    compiled = permissions._compile_entities(policy)
    assert not compiled('light.kitchen', [])
    assert not compiled('switch.kitchen', [])


def test_entities_entity_ids_true():
    """Test entity ID policy."""
    policy = {
        'entity_ids': True
    }
    permissions.ENTITY_POLICY_SCHEMA(policy)
    compiled = permissions._compile_entities(policy)
    assert compiled('light.kitchen', [])


def test_entities_entity_ids_false():
    """Test entity ID policy."""
    policy = {
        'entity_ids': False
    }
    permissions.ENTITY_POLICY_SCHEMA(policy)
    compiled = permissions._compile_entities(policy)
    assert not compiled('light.kitchen', [])


def test_entities_entity_ids_entity_id_true():
    """Test entity ID policy."""
    policy = {
        'entity_ids': {
            'light.kitchen': True
        }
    }
    permissions.ENTITY_POLICY_SCHEMA(policy)
    compiled = permissions._compile_entities(policy)
    assert compiled('light.kitchen', [])
    assert not compiled('switch.kitchen', [])


def test_entities_entity_ids_entity_id_false():
    """Test entity ID policy."""
    policy = {
        'entity_ids': {
            'light.kitchen': False
        }
    }
    permissions.ENTITY_POLICY_SCHEMA(policy)
    compiled = permissions._compile_entities(policy)
    assert not compiled('light.kitchen', [])
    assert not compiled('switch.kitchen', [])


def test_policy_perm_filter_entities():
    """Test filtering entitites."""
    states = [
        State('light.kitchen', 'on'),
        State('light.living_room', 'off'),
        State('light.balcony', 'on'),
    ]
    perm = permissions.PolicyPermissions({
        'entities': {
            'entity_ids': {
                'light.kitchen': True,
                'light.balcony': True,
            }
        }
    })
    filtered = perm.filter_entities(states)
    assert len(filtered) == 2
    assert filtered == [states[0], states[2]]


def test_owner_permissions():
    """Test owner permissions access all."""
    assert permissions.OwnerPermissions.check_entity('light.kitchen')
    states = [
        State('light.kitchen', 'on'),
        State('light.living_room', 'off'),
        State('light.balcony', 'on'),
    ]
    assert permissions.OwnerPermissions.filter_entities(states) == states


def test_default_policy_allow_all():
    """Test that the default policy is to allow all entity actions."""
    perm = permissions.PolicyPermissions(permissions.DEFAULT_POLICY)
    assert perm.check_entity('light.kitchen')
    states = [
        State('light.kitchen', 'on'),
        State('light.living_room', 'off'),
        State('light.balcony', 'on'),
    ]
    assert perm.filter_entities(states) == states
