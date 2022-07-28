"""The pyvelop module."""


def signal_strength_to_text(rssi: int) -> str:
    """Convert the given RSSI value to a textual representation."""
    ret: str = ""
    if rssi <= 0:
        ret = "Excellent"
    if rssi <= -50:
        ret = "Good"
    if rssi <= -60:
        ret = "Fair"
    if rssi <= -70:
        ret = "Weak"

    return ret
