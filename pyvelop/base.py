"""Base class for devices in the Velop mesh"""

from typing import (
    List,
    Optional,
    Union,
)


class MeshDevice:
    """A class that manages the common properties between the devices in the Velop mesh network"""

    def __init__(self, **kwargs) -> None:
        """Constructor.

        :param kwargs: Dictionary of named arguments
        """

        # -- make the private attributes for subclasses available to this class
        self._attribs: dict = kwargs
        self.__device_id = self._attribs.get("deviceID")
        return

    def __repr__(self) -> str:
        """Make a pretty string representation of the class

        :return: Takes the class name and the name of the device to build the representation
        """

        ret = f"{self.__class__.__name__}: "
        if self.name:
            ret += self.name
        return ret

    def _get_user_property(self, name: str) -> Optional[str]:
        """Get the given property from the user properties"""

        ret = None

        user_properties: List[dict] = self._attribs.get("properties", [])
        user_prop: Union[List[dict], str] = [
            prop
            for prop in user_properties
            if prop.get("name") == name
        ]
        if user_prop:
            ret = user_prop[0].get("value")

        return ret

    @property
    def connected_adapters(self) -> List[dict]:
        """Get the network adapters that are connected to the mesh

        :return: a list of dictionaries that contain the MAC, IP and Guest Network status of the adapter
        """

        ret = [
            {
                "mac": adapter.get("macAddress"),
                "ip": adapter.get("ipAddress"),
                "guest_network": adapter.get("isGuest", False),
            }
            for adapter in self._attribs.get("connections", [])
        ]
        return ret

    @property
    def name(self) -> str:
        """Get the name of the device.  Decision on the name to use is as follows: -

            - User set name
            - Friendly name
            - "Network Device" if no name is found

        :return: A string containing the name of the device
        """

        return (
            self._get_user_property(name="userDeviceName")
            or self._attribs.get("friendlyName")
            or "Network Device"
        )

    @property
    def network(self) -> List[dict]:
        """Get all the adapters the device has installed

        :return: List of dictionaries containing MAC, IP, Wi-Fi band, Parent unique ID.
        """

        ret = []

        # -- get the adapters --#
        my_adapters = self._attribs.get("knownInterfaces", [])
        if my_adapters:
            for adapter in my_adapters:
                props = {"mac": adapter.get("macAddress"), "type": adapter.get("interfaceType")}
                if adapter.get("band"):
                    props["band"] = adapter.get("band")
                ret.append(props)
        # -- get the IP addresses and parentId if relevant --#
        for idx, adapter in enumerate(ret):
            adapter_details = self._attribs.get("connections", [])
            adapter_details = [details for details in adapter_details if details["macAddress"] == adapter["mac"]]
            if adapter_details:
                ret[idx]["ip"] = adapter_details[0].get("ipAddress")
                ret[idx]["guest_network"] = adapter_details[0].get("isGuest", False)
                if self.__class__.__name__.lower() == "device":
                    ret[idx]["parent_id"] = adapter_details[0].get("parentDeviceID")
        return ret

    @property
    def results_time(self) -> str:
        """Get the time that the API was queried for the device results

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
    def unique_id(self) -> str:
        """"""

        return self.__device_id
