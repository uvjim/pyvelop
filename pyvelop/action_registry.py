"""Construct the action registry for the API."""

from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from enum import IntEnum, auto
from types import MappingProxyType
from typing import Any


class ActionScope(IntEnum):
    """Possible scopes used for the actions."""

    MESH = auto()
    NODE = auto()


@dataclass(frozen=True, slots=True)
class ActionDefinition:
    """Representation of the API action."""

    key: str
    action: str
    scope: ActionScope = ActionScope.MESH
    payload: dict[str, Any] = field(default_factory=dict, kw_only=True)
    redactions: set[str] = field(default_factory=set, kw_only=True)


@dataclass(slots=True)
class ActionRegistry:
    """Registry of known actions for the API."""

    _storage: dict[str, ActionDefinition]
    _frozen: bool = False

    def __init__(self, actions: Iterable[ActionDefinition]) -> None:
        """Initialise the action registry and mark as read-only."""

        _store: dict[str, ActionDefinition] = {}
        for action in actions:
            # region #-- validate the key --#
            if not action.key:
                raise ValueError
            if action.key in _store:
                raise ValueError
            if not action.key.isidentifier():
                raise ValueError
            # endregion

            _store[action.key] = action

        object.__setattr__(self, "_storage", MappingProxyType(_store))
        object.__setattr__(self, "_frozen", True)

    def __getitem__(self, key: str) -> ActionDefinition:
        """Allow [] access to the registry."""

        return self._storage[key]

    def __getattr__(self, name: str) -> ActionDefinition:
        """Allow . access to the registry."""

        try:
            return self._storage[name]
        except KeyError as exc:
            raise AttributeError(name) from exc

    def __iter__(self) -> Iterator[str]:
        """Allow iteration over the registry keys."""

        return iter(self._storage)

    def __setattr__(self, name: str, value: Any) -> None:
        """Disallow updates after initialising."""

        if getattr(self, "_frozen", False):
            raise AttributeError(f"{type(self).__name__} is read-only after initialization")
        super().__setattr__(name, value)

    def items(self):
        """Return the registry items."""

        return self._storage.items()

    def keys(self):
        """Return the registry keys."""

        return self._storage.keys()

    def values(self):
        """Return the registry values."""

        return self._storage.values()
