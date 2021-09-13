"""Represents a node in the mesh"""

from typing import List, Union

from .base import MeshBase


class Node(MeshBase):
    """Representation of a node in the mesh.  A node provides the connectivity for a device.

    Properties:
        connected_devices (List): The devices that are connected to the node
        firmware (dict): Represents the firmware for the node
        manufacturer (str): The manufacturer of the node
        model (str): The node model
        parent_ip (str): The IP address of the parent for the node
        serial (str): The serial number of the node
        type (str): The node type
    """

    def __init__(self, **kwargs):
        """Constructor

        All supplied are arguments are deemed as attributes and are stored in a private variable.

        :param kwargs: keyword arguments
        """
        self.__attributes = kwargs
        self.__device_id = self.__attributes.get("deviceID")
        super().__init__(**kwargs)

    @property
    def connected_devices(self) -> List:
        """List of the devices that are connected to the node

        :return:
        """
        return self.__connected_devices

    @property
    def firmware(self) -> dict:
        """Get the firmware details for the node.

        N.B. The date doesn't seem to correlate to anything that I can see (I would have thought it was a build
        or install time but that doesn't seem to be the case)

        :return: A dictionary containing the firmware version and date
        """

        ret = {}
        if self.__attributes.get("unit", {}):
            ret["version"] = self.__attributes.get("unit", {}).get("firmwareVersion")
            ret["date"] = self.__attributes.get("unit", {}).get("firmwareDate")
        return ret

    @property
    def manufacturer(self) -> str:
        """Get the node manufacturer

        :return: String containing the name of the manufacturer
        """

        return self.__attributes.get("model", {}).get("manufacturer")

    @property
    def model(self) -> str:
        """Get the model of the node

        :return: A string containing the model
        """

        return self.__attributes.get("model", {}).get("modelNumber")

    @property
    def parent_ip(self) -> Union[str, None]:
        """Get the IP address of the node that this node is attached to.

        :return: A string containing the IP address of the parent or None if no parent
        """

        return self.__attributes.get("backhaul", {}).get("parentIPAddress")

    @property
    def serial(self) -> str:
        """Get the serial number of the node

        :return: A string containing the serial number
        """

        return self.__attributes.get("unit", {}).get("serialNumber")

    @property
    def type(self) -> str:
        """Get the node type.

        The node types are represented as primary or secondary.

        :return: A string containing the node type.
        """

        ret = ""
        native_type = self.__attributes.get("nodeType", "").lower()
        if native_type == "master":
            ret = "primary"
        elif native_type == "slave":
            ret = "secondary"
        return ret
