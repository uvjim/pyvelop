"""Exceptions for the pyvelop module"""


class MeshBadResponse(Exception):
    """API returns a bad response"""

    def __init__(self) -> None:
        super().__init__("Bad Response")


class MeshDeviceNotFoundResponse(Exception):
    """Device is not found in the mesh"""

    def __init__(self) -> None:
        super().__init__("Device not found")


class MeshInvalidArguments(Exception):
    """Invalid arguments have been passed to a function"""

    def __init__(self) -> None:
        super().__init__("Invalid Arguments")


class MeshInvalidCredentials(Exception):
    """Credentials are invalid"""

    def __init__(self) -> None:
        super().__init__("Invalid Credentials")


class MeshInvalidInput(Exception):
    """Parameters passed to the API are in valid

    Explanatory text is passed in the args parameter
    """

    def __init__(self, args) -> None:
        super().__init__(args)


class MeshTooManyMatches(Exception):
    """Too many matching devices when only one should be found"""

    def __init__(self) -> None:
        super().__init__("Too Many Matches")
