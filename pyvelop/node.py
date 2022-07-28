"""Represents a node in the mesh."""

# region #-- imports --#
from __future__ import annotations

from typing import List, Optional

from . import signal_strength_to_text
from .base import MeshDevice

# endregion

NODE_TYPE_PRIMARY = "primary"
NODE_TYPE_SECONDARY = "secondary"


class Node(MeshDevice):
    """Representation of a node in the mesh.  A node provides the connectivity for a device."""

    def __init__(self, **kwargs):
        """Initialise the Node.

        All supplied are arguments are deemed as attributes and are stored in a private variable.

        :param kwargs: keyword arguments
        """
        super().__init__(**kwargs)
        self.__connected_devices: Optional[List] = None
        self.__parent_name: Optional[str] = None

    @property
    def backhaul(self) -> dict:
        """Get details about the backhaul."""
        ret = {}
        backhaul = self._attribs.get("backhaul", {})
        speed_mbps: Optional[float] = None
        try:
            speed_mbps = float(backhaul.get("speedMbps"))
        except (TypeError, ValueError):
            pass
        if backhaul:
            signal_strength_raw: int = backhaul.get("wirelessConnectionInfo", {}).get("stationRSSI")
            ret = {
                "connection": backhaul.get("connectionType"),
                "last_checked": backhaul.get("timestamp"),
                "speed_mbps": speed_mbps,
                "rrsi_dbm": signal_strength_raw,
                "signal_strength": signal_strength_to_text(rssi=signal_strength_raw),
            }

        return ret

    @property
    def connected_devices(self) -> List:
        """List of the devices that are connected to the node.

        :return: List of connected devices in alphabetical order sorted by device name
        """
        connected_devices = self.__connected_devices
        return sorted(connected_devices, key=lambda device: device.get("name"))

    @property
    def firmware(self) -> dict:
        """Get the firmware details for the node.

        N.B. The date doesn't seem to correlate to anything that I can see (I would have thought it was a build
        or install time but that doesn't seem to be the case)

        :return: A dictionary containing the firmware version and date
        """
        ret = {}
        if self._attribs.get("unit", {}):
            ret["version"] = self._attribs.get("unit", {}).get("firmwareVersion")
            ret["date"] = self._attribs.get("unit", {}).get("firmwareDate")
        available_updates = self._attribs.get("updates", {})
        if isinstance(available_updates, dict):
            available_updates = available_updates.get("availableUpdate", {})
            if available_updates:
                ret["latest_version"] = available_updates["firmwareVersion"]
                ret["latest_date"] = available_updates["firmwareDate"]
            else:
                ret["latest_version"] = ret["version"] if "version" in ret else None
                ret["latest_date"] = ret["date"] if "date" in ret else None
        return ret

    @property
    def hardware_version(self) -> str:
        """Get the hardware version of the node.

        :return: A string containing the hardware version
        """
        return self._attribs.get("model", {}).get("hardwareVersion")

    @property
    def last_update_check(self) -> Optional[str]:
        """Get the last time an update was checked for.

        :return: String containing the last update time as per the API
        """
        ret = self._attribs.get("updates", {}).get("lastSuccessfulCheckTime", None)
        return ret

    @property
    def manufacturer(self) -> str:
        """Get the node manufacturer.

        :return: String containing the name of the manufacturer
        """
        return self._attribs.get("model", {}).get("manufacturer")

    @property
    def model(self) -> str:
        """Get the model of the node.

        :return: A string containing the model
        """
        return self._attribs.get("model", {}).get("modelNumber")

    @property
    def parent_ip(self) -> Optional[str]:
        """Get the IP address of the node that this node is attached to.

        :return: A string containing the IP address of the parent or None if no parent
        """
        return self._attribs.get("backhaul", {}).get("parentIPAddress")

    @property
    def parent_name(self) -> str:
        """Return the parent name."""
        return self.__parent_name

    @property
    def serial(self) -> str:
        """Get the serial number of the node.

        :return: A string containing the serial number
        """
        return self._attribs.get("unit", {}).get("serialNumber")

    @property
    def type(self) -> str:
        """Get the node type.

        The node types are represented as primary or secondary.

        :return: A string containing the node type.
        """
        ret = ""
        native_type = self._attribs.get("nodeType", "").lower()
        if native_type == "master":
            ret = NODE_TYPE_PRIMARY
        elif native_type == "slave":
            ret = NODE_TYPE_SECONDARY
        return ret
