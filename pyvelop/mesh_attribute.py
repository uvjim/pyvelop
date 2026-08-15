"""Representation on an attribute for any MeshEntity and the Mesh itself."""

# region #-- imports --#
from __future__ import annotations

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
        """Truthy method."""

        return bool(self.value)

    def __eq__(self, other) -> bool:
        """Equal comparison method."""

        return self.value == other

    def __str__(self) -> str:
        """Return the string representation."""

        return str(self.value)

    def __repr__(self) -> str:
        """Return the repr string."""

        return f"{self.__class__.__name__}(value={self.value!r})"
