"""Types."""

# region #-- imports --#
from dataclasses import dataclass
from enum import StrEnum, auto

from aiohttp import ClientSession

# endregion


@dataclass
class MeshDetails:
    """Details of the mesh being connected to."""

    host: str
    password: str
    request_timeout: float
    session: ClientSession
    user: str

    def __repr__(self) -> str:
        """Friendly string representation of the class."""
        return f"{self.__class__.__name__}: {self.host}"


class NodeType(StrEnum):
    """Enumeration for node types."""

    PRIMARY = auto()
    SECONDARY = auto()
    UNKNOWN = auto()


class SignalStrength(StrEnum):
    """Enumeration for signal strength."""

    EXCELLENT = auto()
    FAIR = auto()
    GOOD = auto()
    WEAK = auto()
