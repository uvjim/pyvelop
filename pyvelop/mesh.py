"""Representation of the mesh."""

# region #-- imports --#
from __future__ import annotations

import json
import logging
import time
from typing import Dict, List, Mapping, Optional

import aiohttp

from . import const
from . import jnap as api
from .decorators import needs_gather_details
from .device import Device
from .exceptions import (
    MeshDeviceNotFoundResponse,
    MeshInvalidArguments,
    MeshInvalidInput,
    MeshTooManyMatches,
)
from .logger import LoggerFormatter
from .node import NODE_TYPE_PRIMARY, Node

# endregion

_LOGGER = logging.getLogger(__name__)
_LOGGER_VERBOSE = logging.getLogger(f"{__name__}.verbose")

# region #-- attributes for results --#
ATTR_BACKHAUL_INFO: str = "backhaul"
ATTR_FIRMWARE_UPDATE_SETTINGS: str = "firmware_update_settings"
ATTR_GUEST_NETWORK_INFO: str = "guest_network"
ATTR_NETWORK_CONNECTIONS: str = "network_connections"
ATTR_NODES: str = "nodes"
ATTR_PARENTAL_CONTROL_INFO: str = "parental_control"
ATTR_PROCESSED_DEVICES: str = "devices"
ATTR_SPEEDTEST_RESULTS: str = "speedtest_results"
ATTR_SPEEDTEST_STATUS: str = "speedtest_status"
ATTR_RAW_DEVICES: str = "raw_devices"
ATTR_STORAGE_INFO: str = "storage"
ATTR_UPDATE_FIRMWARE_STATE: str = "check_update_state"
ATTR_WAN_INFO: str = "wan_info"
# endregion

JNAP_ACTION_TO_ATTRIBUTE: dict = {
    api.Actions.GET_BACKHAUL: ATTR_BACKHAUL_INFO,
    api.Actions.GET_DEVICES: ATTR_RAW_DEVICES,
    api.Actions.GET_FIRMWARE_UPDATE_SETTINGS: ATTR_FIRMWARE_UPDATE_SETTINGS,
    api.Actions.GET_GUEST_NETWORK_INFO: ATTR_GUEST_NETWORK_INFO,
    api.Actions.GET_NETWORK_CONNECTIONS: ATTR_NETWORK_CONNECTIONS,
    api.Actions.GET_PARENTAL_CONTROL_INFO: ATTR_PARENTAL_CONTROL_INFO,
    api.Actions.GET_SPEEDTEST_RESULTS: ATTR_SPEEDTEST_RESULTS,
    api.Actions.GET_SPEEDTEST_STATUS: ATTR_SPEEDTEST_STATUS,
    api.Actions.GET_WAN_INFO: ATTR_WAN_INFO,
    api.Actions.GET_UPDATE_FIRMWARE_STATE: ATTR_UPDATE_FIRMWARE_STATE,
}


def _process_speedtest_results(
    speedtest_results=None, only_latest: bool = False, only_completed: bool = False
) -> List:
    """Take the results from the API for a Speedtest instance and convert to something usable/more compact.

    :param speedtest_results: The results as they were returned from the API
    :param only_latest: True if you only want to return the latest result
    :param only_completed: True if you only want to return completed tests, i.e. not ones currently running
    :return: A list of dictionaries containing the relevant information
    """
    if speedtest_results is None:
        speedtest_results = []

    ret = [
        {
            "timestamp": result.get("timestamp", None),
            "exit_code": result.get("speedTestResult", {}).get("exitCode", None),
            "latency": result.get("speedTestResult", {}).get("latency", None),
            "upload_bandwidth": result.get("speedTestResult", {}).get(
                "uploadBandwidth", None
            ),
            "download_bandwidth": result.get("speedTestResult", {}).get(
                "downloadBandwidth", None
            ),
            "result_id": result.get("speedTestResult", {}).get("resultID", None),
        }
        for result in speedtest_results
    ]

    if only_completed:
        ret = [
            result
            for result in ret
            if result.get("exit_code", "").lower() not in ["unavailable"]
        ]

    if only_latest:
        if ret:
            ret = [ret[0]]

    return ret


def _get_speedtest_state(speedtest_results=None) -> str:
    """Process the Speedtest results to get a textual state."""
    if speedtest_results is None:
        speedtest_results = {}

    if speedtest_results:
        if speedtest_results.get("uploadBandwidth", 0):
            ret = "Checking upload speed"
        elif speedtest_results.get("downloadBandwidth", 0):
            ret = "Checking download speed"
        elif speedtest_results.get("latency"):
            ret = "Checking latency"
        elif speedtest_results.get("serverID", "") == "0":
            ret = "Detecting server"
        else:
            ret = ""
    else:
        ret = ""

    return ret


class Mesh(LoggerFormatter):
    """Representation of the Velop Mesh.

    **All properties are point in time from when the last async_gather_details was executed.**

    If you need live information then call the corresponding method.
    """

    def __init__(
        self,
        node: str,
        password: str,
        request_timeout: Optional[int] = 10,
        session: Optional[aiohttp.ClientSession] = None,
        username: str = "admin",
    ) -> None:
        """Initialise the Mesh.

        :param node: The node we should make a connection to
        :param password: password to use
        :param request_timeout: number of seconds to time out the request; default 10s
        :param session: session to use in for interacting with the Mesh
        :param username: username to use; default admin
        """
        super().__init__()

        _LOGGER.debug(self.message_format("entered"))

        self._node: str = node
        self._mesh_attributes: Dict = {}
        self._session: aiohttp.ClientSession = session
        self._timeout: int = request_timeout or 10

        # flag used to denote that a full gather has been executed
        self.__gather_details_executed: bool = (  # pylint: disable=unused-private-member
            False
        )

        self.__username: str = username
        self.__password: str = password
        self.__passed_session: bool = False

        _LOGGER.debug(
            self.message_format("Session was passed in: %s"),
            "Yes" if self._session is not None else "No",
        )
        if self._session:
            self.__passed_session = True
        else:
            self.__create_session()

        _LOGGER.debug(
            self.message_format("%s version: %s"), __package__, const._PACKAGE_VERSION
        )
        _LOGGER.debug(self.message_format("Initialised mesh for %s"), self._node)
        _LOGGER.debug(self.message_format("exited"))

    async def __aenter__(self):
        """Asynchronous enter magic method."""
        return self

    async def __aexit__(self, exc_type, exc, traceback) -> None:
        """Asynchronous exit magic method."""
        await self.async_close()

    def __repr__(self) -> str:
        """Friendly string representation of the class.

        :return: Uses the class name and the node we're connected to for the representation
        """
        return f"{self.__class__.__name__}: {self._node}"

    # region #-- private methods --#
    async def _async_make_request(
        self, action: str, payload=None, node_address: Optional[str] = None
    ) -> dict:
        """Execute the API request against the connected node.

        :param action: The JNAP action to execute
        :param payload: The relevant payload for the action
        :param node_address: The node to send the request to (only valid for a subset of actions)
        :return: The JSON response or raises an error if need be
        """
        _LOGGER.debug(self.message_format("entered"))

        if node_address is not None and action != api.Actions.REBOOT:
            raise MeshInvalidArguments

        if payload is None:
            payload = []

        if (
            not self.__passed_session and self._session.closed
        ):  # session closed so recreate it
            _LOGGER_VERBOSE.debug(self.message_format("session was closed, reopening"))
            self.__create_session()
        req = api.Request(
            action=action,
            password=self.__password,
            payload=payload,
            session=self._session,
            target=node_address or self._node,
            username=self.__username,
        )
        try:
            req_resp = await req.execute(timeout=self._timeout)
        except Exception as err:
            raise err from None
        else:
            _LOGGER.debug(self.message_format("exited"))
            return req_resp.data

    async def _async_gather_details(self, **kwargs) -> dict:
        """Work is done here to gather the necessary details for mesh.

        :param include_backhaul: True to include backhaul details
        :param include_devices: True to include devices
        :param include_firmware_update: True to include the current firmware update details (does not issue a check)
        :param include_firmware_update_settings: True to include the current settings for firmware updates
        :param include_guest_wifi: True to include details about the guest Wi-Fi
        :param include_network_connections: True to include details about network connections
        :param include_parental_control: True to include details about Parental Control
        :param include_speedtest_results: True to include the latest completed Speedtest result
        :param include_speedtest_status: True to include the currently running speedtest status
        :param include_storage: True to include the external storage details if available
        :param include_wan: True to include WAN details
        :return: A dictionary containing the relevant details.  Keys used will match those of the instance variable.
        """
        _LOGGER.debug(self.message_format("entered, args: %s"), json.dumps(kwargs))

        ret = {}
        payload: List = []

        # region #-- prepare the request payload --#
        # -- get the devices --#
        if kwargs.get("include_devices"):
            payload.append({"action": api.Actions.GET_DEVICES})

        if kwargs.get("include_firmware_update_settings"):
            payload.append({"action": api.Actions.GET_FIRMWARE_UPDATE_SETTINGS})

        # -- get the backhaul info  --#
        if kwargs.get("include_backhaul") or kwargs.get("include_devices"):
            payload.append({"action": api.Actions.GET_BACKHAUL})

        # -- get the guest WiFi details --#
        if kwargs.get("include_guest_wifi"):
            payload.append({"action": api.Actions.GET_GUEST_NETWORK_INFO})

        # -- get the network connection details --#
        if kwargs.get("include_network_connections"):
            payload.append({"action": api.Actions.GET_NETWORK_CONNECTIONS})

        # -- get the Parental Control details --#
        if kwargs.get("include_parental_control") or kwargs.get("include_devices"):
            payload.append({"action": api.Actions.GET_PARENTAL_CONTROL_INFO})

        # -- get the current Speedtest status --#
        if kwargs.get("include_speedtest_status"):
            payload.append({"action": api.Actions.GET_SPEEDTEST_STATUS})

        # -- get the latest Speedtest result --#
        if kwargs.get("include_speedtest_results"):
            payload.append(
                {
                    "action": api.Actions.GET_SPEEDTEST_RESULTS,
                    "request": {
                        **api.Defaults.PAYLOADS.get(api.Actions.GET_SPEEDTEST_RESULTS),
                        "lastNumberOfResults": 10,
                    },
                }
            )

        # -- get the update check details --#
        if kwargs.get("include_firmware_update"):
            payload.append({"action": api.Actions.GET_UPDATE_FIRMWARE_STATE})

        # -- get the WAN details --#
        if kwargs.get("include_wan"):
            payload.append({"action": api.Actions.GET_WAN_INFO})

        # set default request for each action in the transaction
        payload = list(
            map(
                lambda p: (
                    (dict(**p, **{"request": {}}) if p.get("request") is None else p)
                ),
                payload,
            )
        )
        # endregion

        resp = await self._async_make_request(
            action=api.Actions.TRANSACTION, payload=payload
        )
        if resp:
            responses = resp
            # region #-- prepare all the raw details --#
            for idx, req in enumerate(payload):
                # don't wrap in try/except should be good here
                api_response = api.Response(
                    action=req.get("action"), data=responses[idx]
                )
                if req.get("action") in JNAP_ACTION_TO_ATTRIBUTE:
                    ret[JNAP_ACTION_TO_ATTRIBUTE[req.get("action")]] = api_response.data
            # endregion

            # region #-- handle devices --#
            if ATTR_RAW_DEVICES in ret:
                devices = []
                # region #-- build the properties for the device types --#
                for device in ret[ATTR_RAW_DEVICES].get("devices", []):
                    device["results_time"]: int = int(time.time())
                    if "nodeType" in device:
                        # region #-- determine the backhaul information --#
                        device_backhaul = [
                            bi
                            for bi in ret[ATTR_BACKHAUL_INFO].get("backhaulDevices", [])
                            if bi.get("deviceUUID") == device.get("deviceID")
                        ]
                        device_backhaul = device_backhaul[0] if device_backhaul else {}
                        # endregion

                        # region #-- calculate if there is a firmware update available --#
                        node_firmware: List | dict = {}
                        if ATTR_UPDATE_FIRMWARE_STATE in ret:
                            firmware_status = ret[ATTR_UPDATE_FIRMWARE_STATE].get(
                                "firmwareUpdateStatus", []
                            )
                            node_firmware = [
                                firmware_details
                                for firmware_details in firmware_status
                                if firmware_details.get("deviceUUID")
                                == device.get("deviceID")
                            ]
                            node_firmware = node_firmware[0] if node_firmware else {}
                        # endregion

                        devices.append(
                            Node(
                                **device,
                                **{
                                    "backhaul": device_backhaul,
                                    "updates": node_firmware,
                                },
                            )
                        )
                    else:
                        devices.append(Device(**device))
                # endregion

                # region #-- post processing devices and nodes --#
                for node in devices:
                    if node.__class__.__name__.lower() == "node":
                        # region #-- calculate the connected devices for nodes --#
                        connected_devices: List = []
                        parent_name: Optional[str] = None
                        for device in devices:
                            for adapter in device.network:
                                if adapter.get("parent_id") == node.unique_id:
                                    connected_devices.append(
                                        {
                                            "name": device.name,
                                            "ip": adapter.get("ip"),
                                            "type": adapter.get("type"),
                                            "guest_network": adapter.get(
                                                "guest_network"
                                            ),
                                        }
                                    )
                                if node.parent_ip and not parent_name:
                                    if node.parent_ip == adapter.get("ip"):
                                        parent_name = device.name
                        setattr(node, "_Node__parent_name", parent_name)
                        setattr(node, "_Node__connected_devices", connected_devices)
                        # endregion
                    elif node.__class__.__name__.lower() == "device":
                        # region #-- calculate parent name for devices --#
                        attrib_connections = getattr(node, "_attribs", {}).get(
                            "connections", []
                        )
                        parent: Optional[str] = None
                        for conn in attrib_connections:
                            if conn.get("parentDeviceID", ""):
                                try:
                                    parent = [
                                        device.name
                                        for device in devices
                                        if device.unique_id
                                        == conn.get("parentDeviceID")
                                    ][0]
                                except IndexError:
                                    pass
                        setattr(node, "_Device__parent_name", parent)
                        # endregion

                        network_adapater_macs = [
                            adapter.get("mac") for adapter in node.network
                        ]
                        # region #-- get the parental control details --#
                        pc_schedule: List = []
                        for mac in network_adapater_macs:
                            for rule in ret[ATTR_PARENTAL_CONTROL_INFO].get(
                                "rules", []
                            ):
                                if mac in rule.get("macAddresses", []):
                                    pc_schedule.append(rule)
                                    break
                        getattr(node, "_attribs", {})["parental_controls"] = pc_schedule
                        # endregion

                        # region #-- get additional connection details --#
                        if ATTR_NETWORK_CONNECTIONS in ret:
                            for mac in network_adapater_macs:
                                for conn_details in ret[ATTR_NETWORK_CONNECTIONS].get(
                                    "nodeWirelessConnections", []
                                ):
                                    node_connections: List[Mapping] = conn_details.get(
                                        "connections", {}
                                    )
                                    for connection in node_connections:
                                        if mac == connection.get("macAddress"):
                                            getattr(node, "_attribs", {})[
                                                "connection_details"
                                            ] = connection
                                            break
                        # endregion
                # endregion

                ret[ATTR_PROCESSED_DEVICES] = devices or []
            # endregion

        # region #-- separate requests where they could easily cause an error if not supported --#
        # -- get the storage details --#
        if kwargs.get("include_storage"):
            payload = [
                {
                    "action": api.Actions.GET_STORAGE_SMB_SERVER,
                    "request": {},
                },
                {
                    "action": api.Actions.GET_STORAGE_PARTITIONS,
                    "request": {},
                },
            ]
            try:
                resp = await self._async_make_request(
                    action=api.Actions.TRANSACTION, payload=payload
                )
            except MeshInvalidInput:
                _LOGGER.debug(self.message_format("storage function not supported"))
            else:
                if resp:
                    ret[ATTR_STORAGE_INFO] = {
                        "smb_server_settings": resp[0].get(
                            api.Response.DATA_KEY_SINGLE, {}
                        ),
                        "available_partitions": resp[1].get(
                            api.Response.DATA_KEY_SINGLE, {}
                        ),
                    }
        # endregion

        _LOGGER.debug(self.message_format("exited"))
        return ret

    def __create_session(self) -> None:
        """Initialise a session and ensure that errors are raised based on the HTTP status codes.

        :return: None
        """
        _LOGGER_VERBOSE.debug(self.message_format("entered"))
        self._session = aiohttp.ClientSession(raise_for_status=True)
        _LOGGER_VERBOSE.debug(self.message_format("exited"))

    # endregion

    # region #-- public methods --#
    async def async_check_for_updates(self) -> None:
        """Ask the mesh to look for new versions of firmware for the nodes.

        Only a check is done.  The firmware isn't actually updated.

        :return: None
        """
        _LOGGER.debug(self.message_format("entered"))
        await self._async_make_request(
            action=api.Actions.UPDATE_FIRMWARE, payload={"onlyCheck": True}
        )
        _LOGGER.debug(self.message_format("exited"))

    async def async_close(self) -> None:
        """Close the session to the mesh.

        :return: None
        """
        if not self.__passed_session:
            _LOGGER.debug(self.message_format("entered"))
            await self._session.close()
            _LOGGER.debug(self.message_format("exited"))

    async def async_delete_device(self, **kwargs) -> None:
        """Delete a device from the device list on the mesh.

        Supports deleting by device ID or device name.
        Will error if neither the device ID nor name are given.
        Will error if multiple devices match the given name.

        :param kwargs: keyword arguments (device_id, device_name)
        :return: None
        """
        _LOGGER.debug(self.message_format("entered, args: %s"), kwargs)

        device_id: str
        if "device_id" in kwargs:
            device_id = kwargs.get("device_id")
        elif "device_name" in kwargs:
            dev: Device
            device = [
                dev
                for dev in self._mesh_attributes[ATTR_PROCESSED_DEVICES]
                if dev.name == kwargs.get("device_name")
            ]
            if len(device) == 0:
                raise MeshDeviceNotFoundResponse

            if len(device) > 1:
                raise MeshTooManyMatches

            device_id = device[0].unique_id
        else:
            device_id = ""

        if device_id:
            payload = {"deviceID": device_id}
            await self._async_make_request(
                action=api.Actions.DELETE_DEVICE, payload=payload
            )
        else:
            raise MeshInvalidArguments

        _LOGGER.debug(self.message_format("exited"))

    async def async_gather_details(self) -> None:
        """Gather all the details and initialise what the mesh looks like.

        Sets the instance variables as necessary.

        :return: None
        """
        _LOGGER.debug(self.message_format("entered"))

        details = await self._async_gather_details(
            include_backhaul=True,
            include_devices=True,
            include_firmware_update=True,
            include_firmware_update_settings=True,
            include_guest_wifi=True,
            include_network_connections=True,
            include_parental_control=True,
            include_speedtest_results=True,
            include_speedtest_status=True,
            include_storage=True,
            include_wan=True,
        )

        # region #-- split the devices into their types --#
        _LOGGER_VERBOSE.debug(self.message_format("Populating nodes"))
        self._mesh_attributes[ATTR_NODES] = [
            device
            for device in details[ATTR_PROCESSED_DEVICES]
            if device.__class__.__name__.lower() == "node"
        ]
        _LOGGER_VERBOSE.debug(
            self.message_format("Populated %i nodes"),
            len(self._mesh_attributes[ATTR_NODES]),
        )

        _LOGGER_VERBOSE.debug(self.message_format("Populating devices"))
        self._mesh_attributes[ATTR_PROCESSED_DEVICES] = [
            device
            for device in details.get(ATTR_PROCESSED_DEVICES, [])
            if device.__class__.__name__.lower() == "device"
        ]
        _LOGGER_VERBOSE.debug(
            self.message_format("Populated %i devices"),
            len(self._mesh_attributes[ATTR_PROCESSED_DEVICES]),
        )
        # endregion

        # region #-- manage the other attributes --#
        details.pop(ATTR_PROCESSED_DEVICES)
        for attr in details:
            _LOGGER_VERBOSE.debug(self.message_format("Populating %s"), attr)
            self._mesh_attributes[attr] = details[attr]
        # endregion

        self.__gather_details_executed = True  # pylint: disable=unused-private-member
        _LOGGER.debug(self.message_format("exited"))

    async def async_get_device_from_id(
        self, device_id: str, force_refresh: bool = False
    ) -> Device | Node:
        """Get a Device or Node object based on the ID.

        By default, the stored information is used, but you can refresh it from the API.
        Raises an error if the device is not found.

        :param device_id: The ID of the device to get details about
        :param force_refresh: True to re-query the API for the latest details
        :return: Device or Node object whichever is applicable
        """
        _LOGGER.debug(
            self.message_format("entered, device_id: %s, force_refresh: %s"),
            device_id,
            force_refresh,
        )

        all_devices: List[Device | Node]
        if not force_refresh:
            all_devices = self.devices + self.nodes
        else:
            resp = await self._async_gather_details(
                include_devices=True,
            )
            all_devices = resp.get(ATTR_PROCESSED_DEVICES)

        try:
            ret = [device for device in all_devices if device.unique_id == device_id][0]
        except IndexError as err:
            raise MeshDeviceNotFoundResponse from err

        _LOGGER.debug(self.message_format("exited"))
        return ret

    async def async_get_device_from_mac_address(
        self, mac_address: str, force_refresh: bool = False
    ) -> Device | Node:
        """To get a Device or Node object based on the MAC address.

        Searches through all known adapters on the device to find a match.
        By default, the stored information is used, but you can refresh it from the API.
        Raises an error if the device is not found.

        :param mac_address: The MAC address to search for
        :param force_refresh: True to re-query the details from the API
        :return:  Device or Node object whichever is applicable
        """
        _LOGGER.debug(
            self.message_format("entered, mac_address: %s, force_refresh: %s"),
            mac_address,
            force_refresh,
        )

        ret: Optional[Device | Node] = None

        all_devices: List[Device | Node]
        if not force_refresh:
            all_devices = self.nodes + self.devices
        else:
            resp = await self._async_gather_details(
                include_devices=True,
            )
            all_devices = resp.get(ATTR_PROCESSED_DEVICES)

        for device in all_devices:
            if device.network:
                for adapter in device.network:
                    if adapter.get("mac").lower() == mac_address.lower():
                        ret = device
                        break

        if not ret:
            raise MeshDeviceNotFoundResponse

        _LOGGER.debug(self.message_format("exited"))
        return ret

    async def async_get_devices(self) -> List[Device]:
        """Get the devices from the API.

        To be used only if needing to query devices and get the details returned.
        Returns the devices in alphabetical order based on the name.

        :return: List of device objects
        """
        _LOGGER.debug(self.message_format("entered"))

        all_devices = await self._async_gather_details(
            include_devices=True,
            include_network_connections=True,
        )
        ret: List[Device] = [
            device
            for device in all_devices.get(ATTR_PROCESSED_DEVICES, [])
            if device.__class__.__name__.lower() == "device"
        ]
        ret = sorted(ret, key=lambda device: device.name)

        _LOGGER.debug(self.message_format("exited"))
        return ret

    async def async_get_speedtest_results(
        self, count: int = 1, only_latest: bool = False, only_completed: bool = False
    ) -> List:
        """Retrieve Speedtest results.

        :param count: the number of results to return; defaults to 1
        :param only_latest: True to only return the latest result
        :param only_completed: True to only return results that are not currently running
        :return: List of dictionaries containing the result details
        """
        _LOGGER.debug(self.message_format("entered"))

        payload = {
            **api.Defaults.PAYLOADS.get(api.Actions.GET_SPEEDTEST_RESULTS, {}),
            "lastNumberOfResults": count,
        }
        resp = await self._async_make_request(
            action=api.Actions.GET_SPEEDTEST_RESULTS, payload=payload
        )
        healthcheck_results = resp.get("healthCheckResults")

        _LOGGER.debug(self.message_format("exited"))
        return _process_speedtest_results(
            speedtest_results=healthcheck_results,
            only_latest=only_latest,
            only_completed=only_completed,
        )

    async def async_get_speedtest_state(self) -> str:
        """Return a textual representation of the stage of a Speedtest.

        The API does not return a stage so this has to be inferred by the results.

        :return: A string containing the stage
        """
        _LOGGER.debug(self.message_format("entered"))

        resp = await self._async_gather_details(include_speedtest_status=True)
        ret = _get_speedtest_state(
            speedtest_results=resp[ATTR_SPEEDTEST_STATUS].get("speedTestResult", {})
        )

        _LOGGER.debug(self.message_format("exited"))
        return ret

    async def async_get_update_state(self) -> bool:
        """Get the state of the running check for updates.

        :return: True if still running, False if not
        """
        _LOGGER.debug(self.message_format("entered"))

        resp = await self._async_gather_details(include_firmware_update=True)

        node_results = resp.get(ATTR_UPDATE_FIRMWARE_STATE, {}).get(
            "firmwareUpdateStatus", []
        )
        all_states = ["pendingOperation" in node for node in node_results]

        ret: bool = any(all_states)

        _LOGGER.debug(self.message_format("exited"))
        return ret

    async def async_reboot_node(self, node_name: str, force: bool = False) -> None:
        """Reboot the given node.

        N.B. Rebooting the primary node will cause all nodes to reboot. If you're sure you want to
        reboot the primary node, set the `force` parameter to `True`

        :param node_name: the name of the node to restart
        :param force: True to acknowledge the primary node, ignored for everything else
        :return: None
        """
        _LOGGER.debug(
            self.message_format("entered, node_name: %s, force: %s"), node_name, force
        )

        node_details: List[Node] = [
            node for node in self.nodes if node.name.lower() == node_name.lower()
        ]
        if not node_details:
            raise MeshDeviceNotFoundResponse

        if node_details[0].type == NODE_TYPE_PRIMARY and not force:
            raise MeshInvalidInput(f"{node_name} is a primary node. Use the force.")

        node_ip = [
            adapter.get("ip")
            for adapter in node_details[0].network
            if adapter.get("ip")
        ]
        if not node_ip:
            raise MeshInvalidInput(f"{node_name}: no valid address found")

        await self._async_make_request(
            action=api.Actions.REBOOT, node_address=node_ip[0]
        )

        _LOGGER.debug(self.message_format("exited"))

    async def async_set_guest_wifi_state(self, state: bool) -> None:
        """Set the state of the guest Wi-Fi.

        The radios object is a required parameter for the API call but isn't handled in this method.
        Instead, a call is made to retrieve the existing settings and those are relayed back.  This assumes that
        a guest network has been created in the official UI.

        :param state: True to enable, False to disable
        :return: None
        """
        _LOGGER.debug(self.message_format("entered, state: %s"), state)

        # get the current radio settings from the API; they may have changed
        resp = await self._async_gather_details(include_guest_wifi=True)
        radios = resp.get("radios", [])

        payload = {
            "isGuestNetworkEnabled": state,
            "radios": radios,
        }
        await self._async_make_request(
            action=api.Actions.SET_GUEST_NETWORK, payload=payload
        )

        _LOGGER.debug(self.message_format("exited"))

    async def async_set_parental_control_state(self, state: bool) -> None:
        """Set the state of the Parental Control feature.

        The rules are a required parameter for the API call but are not handled in this method.
        Instead, a call is made to retrieve the existing rules and those are relayed back.

        :param state: True to enabled, False to disable
        :return: None
        """
        _LOGGER.debug(self.message_format("entered, state: %s"), state)
        # get the current rules from the API because they may be different
        resp = await self._async_gather_details(include_parental_control=True)
        rules = resp.get("rules", [])

        payload = {
            "isParentalControlEnabled": state,
            "rules": rules,
        }
        await self._async_make_request(
            action=api.Actions.SET_PARENTAL_CONTROL_INFO, payload=payload
        )

        _LOGGER.debug(self.message_format("exited"))

    async def async_start_speedtest(self) -> None:
        """Instruct the mesh to carry out a Speedtest.

        A Speedtest is a long-running task.  You should use the async_get_speedtest_state method to understand
        the progress of the task.

        :return: None
        """
        _LOGGER.debug(self.message_format("entered"))

        payload = {"runHealthCheckModule": "SpeedTest"}
        await self._async_make_request(
            action=api.Actions.START_SPEEDTEST, payload=payload
        )

        _LOGGER.debug(self.message_format("exited"))

    async def async_test_credentials(self) -> bool:
        """Check the provided credentials are valid.

        :return: True if valid, False if not
        """
        _LOGGER.debug(self.message_format("entered"))

        ret: bool = False
        try:
            await self._async_make_request(action=api.Actions.CHECK_PASSWORD)
            ret = True
        except Exception:  # pylint: disable=broad-except
            pass

        _LOGGER.debug(self.message_format("exited"))
        return ret

    # endregion

    # region #-- properties --#
    @property
    @needs_gather_details
    def check_for_update_status(self) -> bool:
        """Get the state of checking for an update as at the last time details were gathered.

        If you need the live state then use the async_get_update_state to re-query the API.

        :return: True if checking, False if not
        """
        node_results = self._mesh_attributes[ATTR_UPDATE_FIRMWARE_STATE].get(
            "firmwareUpdateStatus", []
        )
        all_states = ["pendingOperation" in node for node in node_results]
        ret = any(all_states)

        return ret

    @property
    @needs_gather_details
    def connected_node(self) -> str:
        """Get the node in the mesh that we are connected to.

        :return: A string containing the node IP address
        """
        return self._node

    @property
    @needs_gather_details
    def devices(self) -> List:
        """Get the devices in the mesh.

        The list will be returned in alphabetical order based on the device name.
        N.B. this will not include the nodes.

        :return: A list containing Device objects
        """
        return sorted(
            self._mesh_attributes.get(ATTR_PROCESSED_DEVICES, []),
            key=lambda device: device.name,
        )

    @property
    @needs_gather_details
    def firmware_update_setting(self) -> Optional[str]:
        """Get the current setting for firmware updates.

        :return: a lowercase string representing the update method
        """
        return (
            self._mesh_attributes.get(ATTR_FIRMWARE_UPDATE_SETTINGS, {})
            .get("updatePolicy", "")
            .lower()
            or None
        )

    @property
    @needs_gather_details
    def guest_wifi_enabled(self) -> bool:
        """Get the state of the guest Wi-Fi.

        :return: True if enabled, False if not
        """
        return self._mesh_attributes[ATTR_GUEST_NETWORK_INFO].get(
            "isGuestNetworkEnabled", False
        )

    @property
    @needs_gather_details
    def guest_wifi_details(self) -> List:
        """Get the guest network Wi-Fi details.

        :return: A list of dictionaries containing the SSID and band for the networks
        """
        ret = [
            {
                "ssid": radio.get("guestSSID"),
                "band": radio.get("radioID").split("_")[-1],
            }
            for idx, radio in enumerate(
                self._mesh_attributes[ATTR_GUEST_NETWORK_INFO].get("radios", [])
            )
        ]
        return ret

    @property
    @needs_gather_details
    def latest_speedtest_result(self) -> Optional[Dict]:
        """Get the Speedtest results.

        N.B. If you need more results see the async_get_speedtest_results method

        :return: the Speedtest results
        """
        ret = _process_speedtest_results(
            speedtest_results=self._mesh_attributes[ATTR_SPEEDTEST_RESULTS].get(
                "healthCheckResults", []
            ),
            only_completed=True,
            only_latest=True,
        )
        if ret:
            ret = ret[0]

        return ret or None

    @property
    @needs_gather_details
    def nodes(self) -> List:
        """Get the nodes in the mesh.

        The return is sorted in alphabetical order based on node name.

        :return: A list of Node objects
        """
        ret: List = []
        if ATTR_NODES in self._mesh_attributes:
            ret = sorted(self._mesh_attributes[ATTR_NODES], key=lambda node: node.name)
        return ret

    @property
    @needs_gather_details
    def parental_control_enabled(self) -> Optional[bool]:
        """Get the state of the Parental Control feature.

        :return: True if enabled, False if not
        """
        ret: Optional[bool] = None
        if ATTR_PARENTAL_CONTROL_INFO in self._mesh_attributes:
            ret = self._mesh_attributes[ATTR_PARENTAL_CONTROL_INFO].get(
                "isParentalControlEnabled", False
            )
        return ret

    @property
    @needs_gather_details
    def speedtest_status(self) -> str:
        """Return the current status of the Speedtest.

        :return: Textual representation of the Speedtest state
        """
        ret = _get_speedtest_state(
            speedtest_results=self._mesh_attributes.get(ATTR_SPEEDTEST_STATUS, {}).get(
                "speedTestResult", {}
            )
        )

        return ret

    @property
    @needs_gather_details
    def storage_available(self) -> List:
        """Get available shared partitions.

        :return: List of the available storage devices and their properties
        """
        ret: List = []
        node: List[Node]
        device: dict
        storage_available = self._mesh_attributes.get(ATTR_STORAGE_INFO, {}).get(
            "available_partitions", {}
        )
        for storage_node in storage_available.get("storageNodes", []):
            for device in storage_node.get("storageDevices", []):
                for partition in device.get("partitions", []):
                    node = [
                        _n
                        for _n in self.nodes
                        if _n.unique_id == storage_node.get("deviceID")
                    ]
                    if node:
                        ip_addr = [
                            adapter.get("ip")
                            for adapter in node[0].connected_adapters
                            if adapter.get("ip")
                        ]
                        used_percent: Optional[int] = None
                        try:
                            used_percent = round(
                                (partition.get("usedKB") / partition.get("availableKB"))
                                * 100,
                                2,
                            )
                        except ZeroDivisionError:
                            pass
                        ret.append(
                            {
                                "available_kb": partition.get("availableKB"),
                                "ip": ip_addr[0],
                                "label": partition.get("label"),
                                "last_checked": storage_node.get("timestamp"),
                                "used_kb": partition.get("usedKB"),
                                "used_percent": used_percent,
                            }
                        )

        return ret

    @property
    @needs_gather_details
    def storage_settings(self) -> dict:
        """Get the settings for shared partitions.

        :return: Dictionary of the storage settings
        """
        ret = self._mesh_attributes.get(ATTR_STORAGE_INFO, {}).get(
            "smb_server_settings", {}
        )
        if ret:
            ret = {"anonymous_access": ret.get("isAnonymousAccessEnabled")}

        return ret

    @property
    @needs_gather_details
    def wan_dns(self) -> List:
        """Get the WAN DNS servers.

        :return: A list containing the IP addresses of the WAN DNS servers
        """
        ret = [
            val
            for key, val in self._mesh_attributes.get(ATTR_WAN_INFO, {})
            .get("wanConnection", {})
            .items()
            if key.startswith("dnsServer")
        ]

        return ret

    @property
    @needs_gather_details
    def wan_ip(self) -> Optional[str]:
        """Get the WAN IP address.

        :return: A string containing the IP address for the WAN
        """
        return (
            self._mesh_attributes.get(ATTR_WAN_INFO, {})
            .get("wanConnection", {})
            .get("ipAddress")
        )

    @property
    @needs_gather_details
    def wan_mac(self) -> Optional[str]:
        """Get the WAN MAC.

        :return: A string containing the MAC address for the WAN adapter
        """
        return self._mesh_attributes.get(ATTR_WAN_INFO, {}).get("macAddress", "")

    @property
    @needs_gather_details
    def wan_status(self) -> bool:
        """Get the status of the WAN.

        :return: True if connected, False if not
        """
        return (
            self._mesh_attributes.get(ATTR_WAN_INFO, {}).get("wanStatus", "").lower()
            == "connected"
        )

    # endregion
