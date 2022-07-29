"""The pyvelop module."""

# region #-- imports --#
from typing import Optional

# endregion


def signal_strength_to_text(rssi: Optional[int]) -> Optional[str]:
    """Convert the given RSSI value to a textual representation."""
    ret: Optional[str] = None
    if rssi is not None:
        if rssi <= 0:
            ret = "Excellent"
        if rssi <= -50:
            ret = "Good"
        if rssi <= -60:
            ret = "Fair"
        if rssi <= -70:
            ret = "Weak"

    return ret
