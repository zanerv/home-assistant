"""Permissions for Home Assistant."""
from typing import (
    Any, Callable, Dict, List, Mapping, Tuple, Union, cast)  # noqa: F401

import voluptuous as vol

from homeassistant.core import State

SUBCATEGORY_TYPE = Union[Mapping[str, bool], bool]
CATEGORY_TYPE = Union[Mapping[str, SUBCATEGORY_TYPE], bool, None]
POLICY_TYPE = Mapping[str, CATEGORY_TYPE]


# Policy if user has no policy applied.
DEFAULT_POLICY = {
    "entities": True
}  # type: POLICY_TYPE

ENTITY_POLICY_SCHEMA = vol.Any(bool, vol.Schema({
    vol.Optional('domains'): vol.Any(bool, vol.Schema({
        str: bool
    })),
    vol.Optional('entity_ids'): vol.Any(bool, vol.Schema({
        str: bool
    })),
}))

POLICY_SCHEMA = vol.Schema({
    vol.Optional('entities'): ENTITY_POLICY_SCHEMA
})


class AbstractPermissions:
    """Default permissions class."""

    def check_entity(self, entity_id: str, *keys: str) -> bool:
        """Test if we can access entity."""
        raise NotImplementedError

    def filter_entities(self, entities: List[State]) -> List[State]:
        """Filter a list of entities for what the user is allowed to see."""
        raise NotImplementedError


class PolicyPermissions(AbstractPermissions):
    """Handle permissions."""

    def __init__(self, policy: POLICY_TYPE) -> None:
        """Initialize the permission class."""
        self._policy = policy
        self._compiled = {}  # type: Dict[str, Callable[..., bool]]

    def check_entity(self, entity_id: str, *keys: str) -> bool:
        """Test if we can access entity."""
        func = self._policy_func('entities', _compile_entities)
        return func(entity_id, keys)

    def filter_entities(self, entities: List[State]) -> List[State]:
        """Filter a list of entities for what the user is allowed to see."""
        func = self._policy_func('entities', _compile_entities)
        keys = ('read',)
        return [entity for entity in entities if func(entity.entity_id, keys)]

    def _policy_func(self, category: str,
                     compile_func: Callable[[CATEGORY_TYPE], Callable]) \
            -> Callable[..., bool]:
        """Get a policy function."""
        func = self._compiled.get(category)

        if func:
            return func

        func = self._compiled[category] = compile_func(
            self._policy.get(category))
        return func

    def __eq__(self, other: Any) -> bool:
        """Equals check."""
        # pylint: disable=protected-access
        return (isinstance(other, PolicyPermissions) and
                other._policy == self._policy)


class _OwnerPermissions(AbstractPermissions):
    """Owner permissions."""

    # pylint: disable=no-self-use

    def check_entity(self, entity_id: str, *keys: str) -> bool:
        """Test if we can access entity."""
        return True

    def filter_entities(self, entities: List[State]) -> List[State]:
        """Filter a list of entities for what the user is allowed to see."""
        return entities


OwnerPermissions = _OwnerPermissions()  # pylint: disable=invalid-name


def _compile_entities(policy: CATEGORY_TYPE) \
        -> Callable[[str, Tuple[str]], bool]:
    """Compile policy into a function that tests policy."""
    # None, Empty Dict, False
    if not policy:
        return lambda entity_id, keys: False

    if policy is True:
        return lambda entity_id, keys: True

    assert isinstance(policy, dict)

    domains = policy.get('domains')
    entity_ids = policy.get('entity_ids')

    funcs = []  # type: List[Callable[[str, Tuple[str]], Union[None, bool]]]

    # The order of these functions matter. The more precise are at the top.
    # If a function returns None, they cannot handle it.
    # If a function returns a boolean, that's the result to return.

    # Setting entity_ids to a boolean is final decision for permissions
    # So return right away.
    if isinstance(entity_ids, bool):
        def apply_entity_id_policy(entity_id: str, keys: Tuple[str]) -> bool:
            """Test if allowed entity_id."""
            return entity_ids  # type: ignore

        return apply_entity_id_policy

    elif entity_ids is not None:
        def allowed_entity_id(entity_id: str, keys: Tuple[str]) \
                -> Union[None, bool]:
            """Test if allowed entity_id."""
            return entity_ids.get(entity_id)  # type: ignore

        funcs.append(allowed_entity_id)

    if isinstance(domains, bool):
        def allowed_domain(entity_id: str, keys: Tuple[str]) \
                -> Union[None, bool]:
            """Test if allowed domain."""
            return domains

        funcs.append(allowed_domain)

    elif domains is not None:
        def allowed_domain(entity_id: str, keys: Tuple[str]) \
                -> Union[None, bool]:
            """Test if allowed domain."""
            domain = entity_id.split(".", 1)[0]
            return domains.get(domain)  # type: ignore

        funcs.append(allowed_domain)

    if not funcs:
        return lambda entity_id, keys: False

    if len(funcs) == 1:
        func = funcs[0]
        return lambda entity_id, keys: func(entity_id, keys) is True

    def apply_policy(entity_id: str, keys: Tuple[str]) -> bool:
        """Apply several policies."""
        for func in funcs:
            result = func(entity_id, keys)
            if result is not None:
                return result
        return False

    return apply_policy
