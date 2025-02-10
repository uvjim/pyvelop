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


class NodeType(StrEnum):
    """Enumeration for node types."""

    PRIMARY = auto()
    SECONDARY = auto()
