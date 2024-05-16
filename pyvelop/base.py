"""Base class for devices in the Velop mesh."""

# region #-- imports --#
from __future__ import annotations

from typing import Any, Dict, List

from . import signal_strength_to_text
from .const import DEF_EMPTY_NAME
# endregion


class MeshDevice:
    """A class that manages the common properties between the devices in the Velop mesh network."""

    def __init__(self, **kwargs) -> None:
        """Initialise the Mesh device.

        :param kwargs: Dictionary of named arguments
        """
        # -- make the private attributes for subclasses available to this class
        self._attribs: dict = kwargs
        self.__device_id = self._attribs.get("deviceID")

    def __repr__(self) -> str:
        """Make a pretty string representation of the class.

        :return: Takes the class name and the name of the device to build the representation
        """
        ret = f"{self.__class__.__name__}: "
        if self.name:
            ret += self.name
        return ret

    def _get_connected_adapter_details(
        self, mac: str, include_parent: bool = False
    ) -> Dict[str, Any]:
        """Return details about the connected adapter."""
        ret: Dict[str, Any] = {}

        adapter_details = [
            details
            for details in self._attribs.get("connections", [])
            if details.get("macAddress", "").lower() == mac.lower()
        ]

        if adapter_details:
            ret = {
                "guest_network": adapter_details[0].get("isGuest", False),
                "ip": adapter_details[0].get("ipAddress"),
                "ipv6": adapter_details[0].get("ipv6Address"),
                "mac": adapter_details[0].get("macAddress"),
            }
            if self.__class__.__name__.lower() == "device" and include_parent:
                ret["parent_id"] = adapter_details[0].get("parentDeviceID")

        return ret

    def _get_user_property(self, name: str) -> str | None:
        """Get the given property from the user properties."""
        ret = None

        user_properties: List[dict] = self._attribs.get("properties", [])
        user_prop: List[dict] | str = [
            prop for prop in user_properties if prop.get("name") == name
        ]
        if user_prop:
            ret = user_prop[0].get("value")

        return ret

    def _get_reservation_details(self, mac: str) -> Dict[str, Any]:
        """Get DHCP reservation details for the given MAC."""
        ret: Dict[str, Any] = {}

        ret["reservation"] = False
        if (
            reservation_details := self._attribs.get("reservation_details")
        ) is not None:
            if reservation_details.get("macAddress", "").lower() == mac.lower():
                ret["reservation"] = True
                ret["reservation_description"] = reservation_details.get(
                    "description", ""
                )

        return ret

    def _get_signal_details(self, mac: str) -> Dict[str, Any]:
        """Get the signal details for the given MAC."""
        ret: Dict[str, Any] = {}

        if (conn_details := self._attribs.get("connection_details")) is not None:
            if conn_details.get("macAddress", "").lower() == mac.lower():
                ret["rssi"] = conn_details.get("wireless", {}).get("signalDecibels")
                ret["signal_strength"] = signal_strength_to_text(ret["rssi"])

        return ret

    @property
    def connected_adapters(self) -> List[dict[str, Any]]:
        """Get the network adapters that are connected to the mesh.

        :return: a list of dictionaries that contain the MAC, IP and Guest Network status of the adapter
        """
        ret: List[Dict[str, Any]] = []

        for adapter in self._attribs.get("connections", []):
            adapter_details: Dict[str, Any] = self._get_connected_adapter_details(
                mac=adapter.get("macAddress", "")
            )

            signal_details: Dict[str, Any] = self._get_signal_details(
                mac=adapter.get("macAddress", "")
            )

            reservation_details: Dict[str, Any] = self._get_reservation_details(
                mac=adapter.get("macAddress", "")
            )

            ret.append(dict(**reservation_details, **signal_details, **adapter_details))

        return ret

    @property
    def name(self) -> str:
        """Get the name of the device.

        Decision on the name to use is as follows: -

            - User set name
            - Friendly name
            - DEF_EMPTY_NAME if no name is found

        :return: A string containing the name of the device
        """
        return (
            self._get_user_property(name="userDeviceName")
            or self._attribs.get("friendlyName")
            or DEF_EMPTY_NAME
        )

    @property
    def network(self) -> List[dict]:
        """Get all the adapters the device has installed.

        :return: List of dictionaries containing details of adapaters.
        """
        ret = []

        # -- get the adapters --#
        my_adapters = self._attribs.get("knownInterfaces", [])
        if my_adapters:
            for adapter in my_adapters:
                props = {
                    "mac": adapter.get("macAddress"),
                    "type": adapter.get("interfaceType"),
                }
                if adapter.get("band"):
                    props["band"] = adapter.get("band")
                ret.append(props)
        # -- get the IP addresses, parentId and additional connection details if relevant --#
        for idx, adapter in enumerate(ret):
            adapter_details: Dict[str, Any] = self._get_connected_adapter_details(
                mac=adapter.get("mac"), include_parent=True
            )

            signal_details: Dict[str, Any] = self._get_signal_details(
                mac=adapter.get("mac")
            )
            reservation_details: Dict[str, Any] = self._get_reservation_details(
                mac=adapter.get("mac", "")
            )

            ret[idx].update(**signal_details, **reservation_details, **adapter_details)

        return ret

    @property
    def results_time(self) -> str:
        """Get the time that the API was queried for the device results.

        :return: The time the scan was executed
        """
        return self._attribs.get("results_time")

    @property
    def status(self) -> bool:
        """Get whether the device is currently connected to the mesh or not.

        Assumes that if there are no connections specified for the device then it is offline.

        :return: True if connected.  False if not.
        """
        conns = self._attribs.get("connections", [])
        ret = True if conns else False
        return ret

    @property
    def ui_type(self) -> str | None:
        """Get the type assigned to the device as per the web UI."""
        return self._get_user_property(name="userDeviceType")

    @property
    def unique_id(self) -> str:
        """Return the device_id as unique_id."""
        return self.__device_id
