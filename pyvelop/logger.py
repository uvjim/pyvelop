"""Logging wrapper."""

# region #-- imports --#
import copy
import inspect
import logging
from types import FrameType
from typing import Any

# endregion

DEF_REDACTED: str = "**REDACTED**"


class Logger:
    """Wrapper for logging.Logger class."""

    def __init__(self, logger: logging.Logger) -> None:
        """Initialise."""

        self._logger: logging.Logger = logger

    def __getattr__(self, name):
        """Pass through access to logging.Logger attributes."""

        return getattr(self._logger, name)

    def _format(self, msg: str) -> str:
        """Format the message using as required."""

        ret: str = msg
        caller_details: dict[str, Any] | None = None
        frame: FrameType | None = inspect.currentframe()
        try:
            if frame is not None:
                caller: FrameType | None = frame.f_back
                if caller is not None:
                    caller_class: Any = caller.f_locals.get("self")
                    if caller_class == self:  # go back again in the stack
                        caller = caller.f_back
                    if caller is not None:
                        caller_info: inspect.Traceback = inspect.getframeinfo(caller)
                        caller_details = {
                            "line_no": caller_info.lineno,
                            "func_name": caller_info.function,
                        }
        finally:
            del frame

        if caller_details is not None:
            ret = f"{caller_details.get("func_name")}:{caller_details.get("line_no")}:{msg}"

        return ret

    def debug(self, msg: str, *args: Any) -> None:
        """Passthrough for the debug logger."""

        self._logger.debug(self._format(msg % args))

    def get_logger(self) -> logging.Logger:
        """Return the logger that was initially passed in."""

        return self._logger

    def redact(self, data: dict[str, Any], to_redact: set[str] = set()) -> dict[str, Any]:
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
