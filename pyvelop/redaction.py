"""Encapsulate redaction functionality."""

# region #-- imports --#
import copy
from typing import Any

# endregion

DEF_REDACTED: str = "**REDACTED**"


def redact(data: dict[str, Any], to_redact: set[str] | None = None) -> dict[str, Any]:
    """Redact sensitive data in a dict. Dotted paths may traverse dicts and lists.

    :param data: A dictionary that holds the data to be redacted.
    :param to_redact: The dotted paths that should be redacted within the provided data.
    :return: A copy of the provided data with the specified parts redacted.
    """
    if to_redact is None:
        to_redact = set()
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
