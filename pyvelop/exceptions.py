"""Exceptions for the pyvelop module."""

# region #-- imports --#
from __future__ import annotations

# endregion


class MeshException(Exception):
    """Base Exception for the Mesh."""


class MeshActionUnknown(MeshException):
    """Action not known by the mesh."""

    def __init__(self, action: str) -> None:
        """Initialise with optional info."""
        self.action: str = action
        super().__init__(f"Unknown action URI, {self.action}")


class MeshActionVersionNotImplemented(MeshException):
    """Action with the specified version has not been implemented."""


class MeshAlreadyInProgress(MeshException):
    """API returns an already in progress response."""

    def __init__(self) -> None:
        """Initialise and default message."""
        super().__init__("Specified action already in progress")


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


class MeshDeviceDbFailure(MeshException):
    """DeviceDBFailure reported by the API."""


class MeshDeviceNotFoundResponse(MeshException):
    """Device is not found in the mesh."""

    def __init__(self, devices: list[str] | None = None) -> None:
        """Initialise and default message."""
        self.devices = devices or []
        super().__init__("Device(s) not found")


class MeshInvalidCredentials(MeshException):
    """Credentials are invalid."""

    def __init__(self, details=None) -> None:
        """Initialise and default message."""
        super().__init__("Invalid Credentials")
        self.details = details or {}


class MeshInvalidInput(MeshException):
    """Parameters passed to the API are in valid."""

    def __init__(self, info: object | None = None) -> None:
        """Initialise with optional info."""
        super().__init__(str(info) if info is not None else "Invalid Input")


class MeshInvalidOutput(MeshException):
    """Invalid information would be returned from the API."""

    def __init__(self, info: object | None = None) -> None:
        """Initialise with optional info."""
        super().__init__(str(info) if info is not None else "Invalid Output")


class MeshNeedsInitialise(MeshException):
    """Must run the async_initialise method first."""

    def __init__(self) -> None:
        """Initialise and default message."""
        super().__init__("You must call the initialise method first")


class MeshNodeNotPrimary(MeshException):
    """API call being used on a node that isn't the primary."""

    def __init__(self) -> None:
        """Initialise and default message."""
        super().__init__("Node not Primary")


class MeshTimeoutError(MeshException):
    """Raised when a mesh action exceeds its timeout."""
