"""Logging."""

# region #-- imports --#
import inspect
import logging

# endregion


def set_logging_format(
    *, prefix: str = "", include_lineno: bool = False, include_func_name: bool = False
) -> str:
    """Set the format used by loggers."""

    format: list[str] = logging.BASIC_FORMAT.split(":")
    if include_lineno:
        format.insert(-1, "%(lineno)d")
    if include_func_name:
        format.insert(-1, "%(funcName)s")
    if prefix != "":
        format[-1] = f"{prefix}{format[-1]}"
    return ":".join(format)


class Logger:
    """Provide functions for managing log messages."""

    def __init__(self, unique_id: str = "", prefix: str = ""):
        """Initialise."""
        self._unique_id: str = unique_id
        self._prefix: str = prefix

    def format(
        self, message: str, include_caller: bool = True, include_lineno: bool = False
    ) -> str:
        """Format a log message in the correct format."""
        caller: str = ""
        if include_caller:
            caller_frame = inspect.stack()[1]
            caller = caller_frame.function
            line_no: str = f" --> line: {caller_frame.lineno}" if include_lineno else ""
        unique_id: str = f" ({self._unique_id})" if self._unique_id else ""
        if any([self._prefix, caller, unique_id, line_no]):
            message = f" --> {message}"
        return f"{self._prefix}{caller}{unique_id}{line_no}{message}"
