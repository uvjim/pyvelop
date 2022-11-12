"""The pyvelop module."""


def signal_strength_to_text(rssi: int | None) -> str | None:
    """Convert the given RSSI value to a textual representation."""
    ret: str | None = None
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
