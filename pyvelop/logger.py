"""Logging."""

# region #-- imports --#
import copy
import inspect
import logging
from typing import Any

# endregion

DEF_REDACTED: str = "**REDACTED**"


def set_logging_format(
    *, prefix: str = "", include_lineno: bool = False, include_func_name: bool = False
) -> str:
    """Set the format used by loggers."""

    format: list[str] = str(logging.BASIC_FORMAT).split(":")
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

    def redact(
        self, data: dict[str, Any], to_redact: set[str] = set()
    ) -> dict[str, Any]:
        """Redact sensitive data in a dict. Dotted paths may traverse dicts and lists."""
        ret: dict[str, Any] = copy.deepcopy(data)

        def apply_redaction(obj: Any, parts: list[str]) -> None:
            if not parts:
                return

            # If we're at the final key, redact it wherever obj is a dict.
            if len(parts) == 1:
                key = parts[0]
                if isinstance(obj, dict) and key in obj:
                    obj[key] = DEF_REDACTED
                elif isinstance(obj, list):
                    for item in obj:
                        apply_redaction(item, parts)
                return

            # Still have more segments to traverse.
            head = parts[0]
            tail = parts[1:]

            if isinstance(obj, dict):
                if head in obj:
                    apply_redaction(obj[head], tail)

            elif isinstance(obj, list):
                for item in obj:
                    apply_redaction(item, parts)

        for redaction in to_redact:
            parts = [p for p in redaction.split(".") if p]
            if parts:
                apply_redaction(ret, parts)

        return ret
