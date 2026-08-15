"""Representation on an attribute for any MeshEntity and the Mesh itself."""

# region #-- imports --#
from __future__ import annotations

from collections.abc import Iterable, Iterator, Sized
from dataclasses import asdict, dataclass, field
from enum import StrEnum, auto
from typing import Any

from .action_registry import ActionKey

# endregion


class AttributeAction(StrEnum):
    """Possible actions for the action of an attribute in the audit histroy."""

    INIT = auto()
    REPLACE = auto()
    MERGE = auto()


@dataclass(frozen=True, slots=True)
class AttributeAuditEntry[PropType]:
    """Representation of an audit log entry."""

    source: ActionKey
    value: PropType
    type: AttributeAction = field(default=AttributeAction.INIT, kw_only=True)

    def as_dict(self) -> dict[str, Any]:
        """Return a dictionary representation of the object."""

        return asdict(self)


@dataclass(frozen=True)
class MeshAttribute[PropType]:
    """Base representation of an attribute."""

    value: PropType
    audit: tuple[AttributeAuditEntry, ...]

    def __bool__(self) -> bool:
        """Truthy method based on wrapped value."""

        return bool(self.value)

    def __eq__(self, other) -> bool:
        """Equal comparison method based on wrapped value."""

        return self.value == other

    def __getattr__(self, name: str):
        """Missing attribute lookup."""

        return getattr(self.value, name)

    def __iter__(self) -> Iterator[Any]:
        """Iterate over wrapped value."""

        if isinstance(self.value, Iterable):
            return iter(self.value)
        raise TypeError(f"{type(self.value).__name__} does not support iteration")

    def __len__(self) -> int:
        """Length method based on wrapped value."""

        if isinstance(self.value, Sized):
            return len(self.value)
        raise TypeError(f"{type(self.value).__name__} does not support len()")

    def __str__(self) -> str:
        """Return the string representation based on the wrapped value."""

        return str(self.value)

    def __repr__(self) -> str:
        """Return the repr string."""

        return f"{self.__class__.__name__}(value={self.value!r})"
