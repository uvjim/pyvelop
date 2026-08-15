"""Representation on an attribute for any MeshEntity and the Mesh itself."""

# region #-- imports --#
from __future__ import annotations

import enum
import inspect
import logging
from collections.abc import Iterable, Iterator, Mapping, Sized
from dataclasses import dataclass, field
from enum import StrEnum, auto
from typing import Any, cast

from .action_registry import ActionKey

# endregion

_LOGGER = logging.getLogger(__name__)


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

    def to_dict(self) -> dict[str, Any]:
        """Return a dictionary representation of the object."""

        return {
            "source": str(self.source),
            "value": self.value,
            "type": self.type.value,
        }


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

    def to_dict(self, *, include_audit: bool = True) -> Any:
        """Convert the instance to a dictionary."""

        def to_jsonable(obj: PropType) -> Any:
            """Convert an arbitrary object to a structure json.dumps can handle."""

            # basic JSON types
            if obj is None or isinstance(obj, (str, int, float, bool)):
                return obj

            # enums
            if isinstance(obj, enum.Enum):
                val = obj.value
                return val if isinstance(val, (str, int, float, bool, type(None))) else repr(obj)

            # to_dict
            if hasattr(obj, "to_dict") and callable(getattr(obj, "to_dict", None)):
                meth = cast(Any, obj).to_dict
                if "include_audit" in inspect.signature(meth).parameters:
                    return meth(include_audit=include_audit)
                return meth()

            # mappings
            if isinstance(obj, Mapping):
                return {str(k): to_jsonable(v) for k, v in obj.items()}

            # lists/tuples
            if isinstance(obj, (list, tuple)):
                return [to_jsonable(v) for v in obj]

            # other iterables -> best-effort to list
            if isinstance(obj, Iterable) and not isinstance(obj, (str, bytes, bytearray)):
                try:
                    return [to_jsonable(v) for v in obj]
                except TypeError:
                    return repr(obj)

            # last resort
            return repr(obj)

        if include_audit:
            ret = {"value": to_jsonable(self.value)}
            ret.update({"audit": [entry.to_dict() for entry in self.audit]})
        else:
            ret = to_jsonable(self.value)

        return ret
