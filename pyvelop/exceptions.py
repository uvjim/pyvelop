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


class MeshCredentialCheckDelayed(MeshException):
    """An attempt to check credentials was made, but the check has been delayed by a previous check.

    The `details` attribute will determine: -
    - the number of attempts remaining
    - the amount of seconds before you should try again
    """

    msg: str = "Credential checking is subject to a delay"

    def __init__(self, msg: str | None = None, *, details=None) -> None:
        """Initialise and default message."""
        exc_msg: str = msg if msg is not None else self.msg
        super().__init__(exc_msg)
        self.details = details or {}


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

    msg: str = "Invalid credentials"

    def __init__(self, msg: str | None = None, *, details=None) -> None:
        """Initialise and default message."""
        exc_msg: str = msg if msg is not None else self.msg
        super().__init__(exc_msg)
        self.details = details or {}


class MeshInvalidCredentialsNoRetry(MeshInvalidCredentials):
    """Credentials are invalid.  Each retry attempt will be rejected.

    This guard is in place to stop the module from depleting the potential retry attempts
    too much. The expectation is that the user should now login using the Linksys app or Web UI
    to follow password policies that are enforced there.
    """

    msg: str = "Credential retry boundary reached"


class MeshInvalidCredentialsWithDelay(MeshInvalidCredentials):
    """Credentials are invalid, but you must delay before retrying.

    The `details` attribute will determine: -
    - the number of attempts remaining
    - the delay time before retry
    """


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
