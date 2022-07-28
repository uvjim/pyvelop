"""Exceptions for the pyvelop module."""


class MeshBadResponse(Exception):
    """API returns a bad response."""

    def __init__(self) -> None:
        """Initialise and default message."""
        super().__init__("Bad Response")


class MeshConnectionError(Exception):
    """Connection error for the API."""

    def __init__(self) -> None:
        """Initialise and default message."""
        super().__init__("Connection Error")


class MeshDeviceNotFoundResponse(Exception):
    """Device is not found in the mesh."""

    def __init__(self) -> None:
        """Initialise and default message."""
        super().__init__("Device not found")


class MeshInvalidArguments(Exception):
    """Invalid arguments have been passed to a function."""

    def __init__(self) -> None:
        """Initialise and default message."""
        super().__init__("Invalid Arguments")


class MeshInvalidCredentials(Exception):
    """Credentials are invalid."""

    def __init__(self) -> None:
        """Initialise and default message."""
        super().__init__("Invalid Credentials")


class MeshInvalidInput(Exception):
    """Parameters passed to the API are in valid."""


class MeshInvalidOutput(Exception):
    """Invalid information would be returned from the API."""


class MeshNodeNotPrimary(Exception):
    """API call being used on a node that isn't the primary."""

    def __init__(self) -> None:
        """Initialise and default message."""
        super().__init__("Node not Primary")


class MeshTimeoutError(Exception):
    """Timeout error for the API."""

    def __init__(self) -> None:
        """Initialise and default message."""
        super().__init__("Timeout Error")


class MeshTooManyMatches(Exception):
    """Too many matching devices when only one should be found."""

    def __init__(self) -> None:
        """Initialise and default message."""
        super().__init__("Too Many Matches")
