"""Exceptions for the pyvelop module."""


class MeshException(Exception):
    """Base Exsception for the Mesh."""


class MeshBadResponse(MeshException):
    """API returns a bad response."""

    def __init__(self) -> None:
        """Initialise and default message."""
        super().__init__("Bad Response")


class MeshCannotDeleteDevice(MeshException):
    """Unable to delete device."""

    def __init__(self) -> None:
        """Initialise and default message."""
        super().__init__("Unable to delete the device")


class MeshConnectionError(MeshException):
    """Connection error for the API."""

    def __init__(self) -> None:
        """Initialise and default message."""
        super().__init__("Connection Error")


class MeshDeviceNotFoundResponse(MeshException):
    """Device is not found in the mesh."""

    def __init__(self) -> None:
        """Initialise and default message."""
        super().__init__("Device not found")


class MeshInvalidArguments(MeshException):
    """Invalid arguments have been passed to a function."""

    def __init__(self) -> None:
        """Initialise and default message."""
        super().__init__("Invalid Arguments")


class MeshInvalidCredentials(MeshException):
    """Credentials are invalid."""

    def __init__(self) -> None:
        """Initialise and default message."""
        super().__init__("Invalid Credentials")


class MeshInvalidInput(MeshException):
    """Parameters passed to the API are in valid."""


class MeshInvalidOutput(MeshException):
    """Invalid information would be returned from the API."""


class MeshNeedsGatherDetails(MeshException):
    """Must run the async_gather_details method first."""


class MeshNodeNotPrimary(MeshException):
    """API call being used on a node that isn't the primary."""

    def __init__(self) -> None:
        """Initialise and default message."""
        super().__init__("Node not Primary")


class MeshTimeoutError(MeshException):
    """Timeout error for the API."""

    def __init__(self) -> None:
        """Initialise and default message."""
        super().__init__("Timeout Error")


class MeshTooManyMatches(MeshException):
    """Too many matching devices when only one should be found."""

    def __init__(self) -> None:
        """Initialise and default message."""
        super().__init__("Too Many Matches")
