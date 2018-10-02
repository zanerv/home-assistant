"""Permissions for Home Assistant."""
import voluptuous as vol

# Policy if user has no policy applied.
DEFAULT_POLICY = {
    "entities": True
}

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


class DefaultPermissions:
    """Default permissions class."""

    def check_entity(self, entity_id: str, *keys):
        """Test if we can access entity."""
        raise NotImplementedError

    def filter_entities(self, entities):
        """Filter a list of entities for what the user is allowed to see."""
        raise NotImplementedError


class PolicyPermissions(DefaultPermissions):
    """Handle permissions."""

    def __init__(self, policy):
        """Initialize the permission class."""
        self._policy = policy
        self._compiled = {}

    def check_entity(self, entity_id: str, *keys):
        """Test if we can access entity."""
        func = self._policy_func('entities', _compile_entities)
        return func(entity_id, keys)

    def filter_entities(self, entities):
        """Filter a list of entities for what the user is allowed to see."""
        func = self._policy_func('entities', _compile_entities)
        keys = ('read',)
        return [entity for entity in entities if func(entity.entity_id, keys)]

    def _policy_func(self, category, compile_func):
        """Get a policy function."""
        func = self._compiled.get(category)

        if func:
            return func

        func = self._compiled[category] = compile_func(
            self._policy.get(category))
        return func

    def __eq__(self, other):
        """Equals check."""
        # pylint: disable=protected-access
        return (isinstance(other, PolicyPermissions) and
                other._policy == self._policy)


class _OwnerPermissions(DefaultPermissions):
    """Owner permissions."""
    # pylint: disable=no-self-use

    def check_entity(self, entity_id: str, *keys):
        """Test if we can access entity."""
        return True

    def filter_entities(self, entities):
        """Filter a list of entities for what the user is allowed to see."""
        return entities


OwnerPermissions = _OwnerPermissions()


def _compile_entities(policy):
    """Compile policy into a function that tests policy."""
    # None, Empty Dict, False
    if not policy:
        return lambda entity_id, keys: False

    if policy is True:
        return lambda entity_id, keys: True

    domains = policy.get('domains')
    entity_ids = policy.get('entity_ids')

    # Setting domains or entity_ids to True whitelists all entities
    if domains is True or entity_ids is True:
        return lambda entity_id, keys: True

    funcs = []

    # If it's False, no need to process it.
    if domains and domains is not False:
        def allowed_domain(entity_id, keys):
            """Test if allowed domain."""
            domain = entity_id.split(".", 1)[0]
            return domains.get(domain) is True

        funcs.append(allowed_domain)

    # If it's False, no need to process it.
    if entity_ids and entity_ids is not False:
        def allowed_entity_id(entity_id, keys):
            """Test if allowed domain."""
            return entity_ids.get(entity_id) is True

        funcs.append(allowed_entity_id)

    if not funcs:
        return lambda entity_id, keys: False

    if len(funcs) == 1:
        return funcs[0]

    return lambda entity_id, keys: any(func(entity_id, keys) for func in funcs)
