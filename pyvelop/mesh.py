"""Representation of the mesh"""

# region #-- imports --#
from __future__ import annotations

import json
import logging
import time
from typing import (
    Dict,
    List,
    Optional,
)

import aiohttp

from . import (
    const,
    jnap as api,
)
from .device import Device
from .exceptions import (
    MeshBadResponse,
    MeshDeviceNotFoundResponse,
    MeshInvalidArguments,
    MeshInvalidCredentials,
    MeshInvalidInput,
    MeshInvalidOutput,
    MeshNodeNotPrimary,
    MeshTooManyMatches,
)
from .logger import LoggerFormatter
from .node import (
    Node,
    NODE_TYPE_PRIMARY
)

# endregion

_LOGGER = logging.getLogger(__name__)
_LOGGER_VERBOSE = logging.getLogger(f"{__name__}.verbose")

# region #-- attributes used for the mesh --#
ATTR_MESH_BACKHAUL: str = "backhaul"
ATTR_MESH_CONNECTED_NODE: str = "connected_node"
ATTR_MESH_DEVICES: str = "devices"
ATTR_MESH_GUEST_NETWORK_INFO: str = "guest_network"
ATTR_MESH_NODES: str = "nodes"
ATTR_MESH_PARENTAL_CONTROL_INFO: str = "parental_control"
ATTR_MESH_RAW_DEVICES: str = "raw_devices"
ATTR_MESH_SPEEDTEST_RESULTS: str = "speedtest_results"
ATTR_MESH_SPEEDTEST_STATE: str = "speedtest_state"
ATTR_MESH_STORAGE: str = "storage"
ATTR_MESH_UPDATE_FIRMWARE_STATE: str = "check_update_state"
ATTR_MESH_UPDATE_SETTINGS: str = "update_settings"
ATTR_MESH_WAN_INFO: str = "wan_info"
# endregion

# region #-- default payloads --#
DEF_JNAP_CHECK_FIRMWARE_PAYLOAD: dict = {
    "onlyCheck": True
}
DEF_JNAP_SPEEDTEST_PAYLOAD: dict = {
    "healthCheckModule": "SpeedTest",
    "includeModuleResults": True,
    "lastNumberOfResults": 1,
}
# endregion

JNAP_TO_ATTRIBUTE: Dict[str, str] = {
    api.Actions.GET_BACKHAUL: ATTR_MESH_BACKHAUL,
    api.Actions.GET_DEVICES: ATTR_MESH_RAW_DEVICES,
    api.Actions.GET_GUEST_NETWORK_INFO: ATTR_MESH_GUEST_NETWORK_INFO,
    api.Actions.GET_PARENTAL_CONTROL_INFO: ATTR_MESH_PARENTAL_CONTROL_INFO,
    api.Actions.GET_SPEEDTEST_RESULTS: ATTR_MESH_SPEEDTEST_RESULTS,
    api.Actions.GET_SPEEDTEST_STATE: ATTR_MESH_SPEEDTEST_STATE,
    api.Actions.GET_UPDATE_FIRMWARE_STATE: ATTR_MESH_UPDATE_FIRMWARE_STATE,
    api.Actions.GET_UPDATE_SETTINGS: ATTR_MESH_UPDATE_SETTINGS,
    api.Actions.GET_WAN_INFO: ATTR_MESH_WAN_INFO,
}


def _process_speedtest_results(speedtest_results=None, only_latest: bool = False, only_completed: bool = False) -> List:
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
            "upload_bandwidth": result.get("speedTestResult", {}).get("uploadBandwidth", None),
            "download_bandwidth": result.get("speedTestResult", {}).get("downloadBandwidth", None),
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
    """Process the Speedtest results to get a textual state"""

    if speedtest_results is None:
        speedtest_results = {}

    if speedtest_results:
        if speedtest_results.get("uploadBandwidth", 0):
            ret = "Checking upload speed"
        elif speedtest_results.get("downloadBandwidth", 0):
            ret = "Checking download speed"
        elif speedtest_results.get("latency"):
            ret = "Checking latency"
        elif speedtest_results.get("serverID", "") == '0':
            ret = "Detecting server"
        else:
            ret = ""
    else:
        ret = ""

    return ret


class Mesh(LoggerFormatter):
    """Representation of the Velop Mesh

    **All properties are point in time from when the last async_gather_details was executed.**

    If you need live information then call the corresponding method.
    """

    def __init__(
        self,
        node: str,
        password: str,
        username: str = "admin",
        request_timeout: Optional[int] = None,
    ) -> None:
        """Constructor

        :param node: The node we should make a connection to
        :param password: password to use
        :param username: username to use; default admin
        :param request_timeout: number of seconds to time out the request; default 10s
        """

        super().__init__()
        _LOGGER.debug(self.message_format("entered"))
        # noinspection PyProtectedMember
        _LOGGER.debug(self.message_format("%s version: %s"), __package__, const._PACKAGE_VERSION)

        if request_timeout is None:
            request_timeout = 10

        self._password: str = password
        self._session: aiohttp.ClientSession
        self._timeout: int = request_timeout
        self._username: str = username

        self._mesh_attributes: dict = {  # initialise the attributes for the mesh
            ATTR_MESH_BACKHAUL: {},
            ATTR_MESH_CONNECTED_NODE: node,
            ATTR_MESH_DEVICES: [],
            ATTR_MESH_GUEST_NETWORK_INFO: {},
            ATTR_MESH_NODES: [],
            ATTR_MESH_PARENTAL_CONTROL_INFO: {},
            ATTR_MESH_RAW_DEVICES: {},
            ATTR_MESH_SPEEDTEST_RESULTS: {},
            ATTR_MESH_STORAGE: {},
            ATTR_MESH_UPDATE_FIRMWARE_STATE: [],
            ATTR_MESH_UPDATE_SETTINGS: {},
            ATTR_MESH_WAN_INFO: {},
        }

        self.__create_session()

        _LOGGER.debug(self.message_format("Initialised mesh for %s"), self._mesh_attributes[ATTR_MESH_CONNECTED_NODE])

    async def __aenter__(self):
        """Asynchronous enter magic method"""

        return self

    async def __aexit__(self, exc_type, exc, traceback) -> None:
        """Asynchronous exit magic method"""
        await self.async_close()

    def __repr__(self) -> str:
        """Friendly string representation of the class

        :return: Uses the class name and the node we're connected to for the representation
        """

        ret = f"{self.__class__.__name__}: {self._mesh_attributes[ATTR_MESH_CONNECTED_NODE]}"

        return ret

    def __create_session(self) -> None:
        """Initialise a session and ensure that errors are raised based on the HTTP status codes

        :return: None
        """

        _LOGGER_VERBOSE.debug(self.message_format("entered"))
        self._session = aiohttp.ClientSession(raise_for_status=True)
        _LOGGER_VERBOSE.debug(self.message_format("exited"))

    async def _async_make_request(
        self,
        action: str,
        node_address: Optional[str] = None,
        payload: Optional[List[Dict] | Dict] = None
    ) -> Dict:
        """Send the API request

        :param action: the JNAP action to use in the request
        :param node_address: the target to send the request to (defaults to the connected node)
        :param payload: additional data for the request

        :return: dictionary containing the results of the request
        """

        _LOGGER.debug(self.message_format("entered"))
        target = node_address or self._mesh_attributes[ATTR_MESH_CONNECTED_NODE]
        req = api.Request(
            action=action,
            password=self._password,
            payload=payload,
            session=self._session,
            target=target,
            username=self._username,
        )
        _LOGGER.debug(self.message_format("request, target: %s, action: %s, payload: %s"), target, action, payload)
        resp = await req.execute(timeout=self._timeout)
        if resp.is_successful:
            _LOGGER.debug(self.message_format("exited"))
            return resp.data.get(api.Response.RESULT_KEY)
        else:
            # -- process errors --#
            responses = (
                resp.data.get(api.Response.RESULT_KEY).get(api.Response.RESULTS_KEY_TRANSACTION)
                if isinstance(resp.data.get(api.Response.RESULT_KEY).get(api.Response.RESULTS_KEY_TRANSACTION), List)
                else
                [resp.data]
            )

            err = None
            for r in responses:
                err = None
                res_error = (
                    r.get(api.Response.RESULT_KEY)
                    if isinstance(r.get(api.Response.RESULT_KEY), str)
                    else r.get(api.Response.RESULT_KEY, {}).get(api.Response.RESULT_KEY)
                )
                if res_error == "_ErrorAbortedAction":
                    err = MeshInvalidInput(r.get(api.Response.RESULTS_KEY_ERROR))
                elif res_error == "_ErrorInvalidInput":
                    err = MeshInvalidInput(r.get(api.Response.RESULTS_KEY_ERROR))
                elif res_error == "_ErrorInvalidOutput":
                    err = MeshInvalidOutput(r.get(api.Response.RESULTS_KEY_ERROR))
                elif res_error == "_ErrorUnauthorized":
                    err = MeshInvalidCredentials
                elif res_error == "_ErrorUnknownAction":
                    err = MeshInvalidInput((
                        r.get(api.Response.RESULTS_KEY_ERROR)
                        or f"Unknown action URI '{r.get(api.Response.ACTION_KEY)}'"
                    ))
                elif res_error == "ErrorDeviceNotInMasterMode":
                    err = MeshNodeNotPrimary

                if err:
                    break

            if err is None:
                _LOGGER.error("Unknown error received: %s", json.dumps(responses))
                err = MeshBadResponse

            raise err from None

    async def _async_gather_details(
            self,
            **kwargs,
    ) -> dict:
        """Work is done here to gather the necessary details for mesh.

        :param include_backhaul: True to include backhaul details
        :param include_devices: True to include devices
        :param include_firmware_update: True to include the current firmware update details (does not issue a check)
        :param include_guest_wifi: True to include details about the guest Wi-Fi
        :param include_parental_control: True to include details about Parental Control
        :param include_speedtest_results: True to include the latest completed Speedtest result
        :param include_storage: True to include the external storage details if available
        :param include_update_settings: True to include the fiwmware update settings
        :param include_wan: True to include WAN details
        :return: A dictionary containing the relevant details.  Keys used will match those of the instance variable.
        """

        _LOGGER.debug(self.message_format("entered, args: %s"), json.dumps(kwargs))

        ret = {}
        payload: List = []

        # -- get the devices --#
        if kwargs.get("include_devices"):
            payload.append({
                "action": api.Actions.GET_DEVICES,
                "request": {},
            })

        # -- get the backhaul info  --#
        if kwargs.get("include_backhaul") or kwargs.get("include_devices"):
            payload.append({
                "action": api.Actions.GET_BACKHAUL,
                "request": {},
            })

        # -- get the guest WiFi details --#
        if kwargs.get("include_guest_wifi"):
            payload.append({
                "action": api.Actions.GET_GUEST_NETWORK_INFO,
                "request": {},
            })

        # -- get the Parental Control details --#
        if kwargs.get("include_parental_control"):
            payload.append({
                "action": api.Actions.GET_PARENTAL_CONTROL_INFO,
                "request": {},
            })

        # -- get the current Speedtest state --#
        if kwargs.get("include_speedtest_state"):
            payload.append({
                "action": api.Actions.GET_SPEEDTEST_STATE,
                "request": {}
            })

        # -- get the latest Speedtest result --#
        if kwargs.get("include_speedtest_results"):
            payload.append({
                "action": api.Actions.GET_SPEEDTEST_RESULTS,
                "request": {**DEF_JNAP_SPEEDTEST_PAYLOAD, "lastNumberOfResults": 10},
            })

        # -- get the update check details --#
        if kwargs.get("include_firmware_update"):
            payload.append({
                "action": api.Actions.GET_UPDATE_FIRMWARE_STATE,
                "request": {},
            })

        # -- get the settings for firmware updates --#
        if kwargs.get("include_update_settings"):
            payload.append({
                "action": api.Actions.GET_UPDATE_SETTINGS,
                "request": {},
            })

        # -- get the WAN details --#
        if kwargs.get("include_wan"):
            payload.append({
                "action": api.Actions.GET_WAN_INFO,
                "request": {},
            })

        responses = await self._async_make_request(action=api.Actions.TRANSACTION, payload=payload)
        if responses:
            # region #-- populate standard attributes --#
            # these are attributes that need no further processing
            for idx, itm in enumerate(payload):
                action = itm.get("action")
                if action:
                    attr = JNAP_TO_ATTRIBUTE.get(action)
                    if attr:
                        ret[attr] = responses[idx].get(api.Response.RESULTS_KEY_SINGLE, {})
            # endregion

            # region #-- populate device and node details --#
            if ret[ATTR_MESH_RAW_DEVICES]:
                device_info = ret[ATTR_MESH_RAW_DEVICES].get("devices", [])

                # region #-- build the properties for the device types --#
                devices = []
                backhaul_info = ret[ATTR_MESH_BACKHAUL].get("backhaulDevices", [])
                for device in device_info:
                    if "nodeType" in device:
                        # region #-- determine the backhaul information --#
                        device_backhaul = [bi for bi in backhaul_info if bi.get("deviceUUID") == device.get("deviceID")]
                        if device_backhaul:
                            device_backhaul = device_backhaul[0]
                        else:
                            device_backhaul = {}
                        # endregion

                        # region #-- calculate if there is a firmware update available --#
                        node_firmware: List | dict = {}
                        if ATTR_MESH_UPDATE_FIRMWARE_STATE in ret:
                            firmware_status = ret[ATTR_MESH_UPDATE_FIRMWARE_STATE].get("firmwareUpdateStatus", [])
                            node_firmware = [
                                firmware_details
                                for firmware_details in firmware_status
                                if firmware_details.get("deviceUUID") == device.get("deviceID")
                            ]
                            if node_firmware:
                                node_firmware = node_firmware[0]
                            else:
                                node_firmware = {}
                        # endregion

                        n = Node(
                            **device,
                            **{
                                "backhaul": device_backhaul,
                                "updates": node_firmware,
                                "results_time": int(time.time())
                            }
                        )
                        devices.append(n)
                    else:
                        d = Device(
                            **device,
                            **{
                                "results_time": int(time.time())
                            }
                        )
                        devices.append(d)
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
                                    connected_devices.append({
                                        "name": device.name,
                                        "ip": adapter.get("ip"),
                                        "type": adapter.get("type"),
                                        "guest_network": adapter.get("guest_network")
                                    })
                                if node.parent_ip and not parent_name:
                                    if node.parent_ip == adapter.get("ip"):
                                        parent_name = device.name
                        setattr(node, "_Node__parent_name", parent_name)
                        setattr(node, "_Node__connected_devices", connected_devices)
                        # endregion
                    elif node.__class__.__name__.lower() == "device":
                        # region #-- calculate parent name for devices --#
                        attrib_connections = getattr(node, "_attribs", {}).get("connections", [])
                        parent: Optional[str] = None
                        for conn in attrib_connections:
                            if conn.get("parentDeviceID", ""):
                                try:
                                    parent = [
                                        device.name
                                        for device in devices
                                        if device.unique_id == conn.get("parentDeviceID")
                                    ][0]
                                except IndexError:
                                    pass
                        setattr(node, "_Device__parent_name", parent)
                        # endregion
                        # region #-- get the parental control details --#
                        pc_schedule: List = []
                        network_adapater_macs = [adapter.get("mac") for adapter in node.network]
                        for mac in network_adapater_macs:
                            for rule in ret[ATTR_MESH_PARENTAL_CONTROL_INFO].get("rules", []):
                                if mac in rule.get("macAddresses", []):
                                    pc_schedule.append(rule)
                                    break
                        getattr(node, "_attribs", {})["parental_controls"] = pc_schedule
                        # endregion
                # endregion

                if devices:
                    ret[ATTR_MESH_DEVICES] = devices
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
                responses = await self._async_make_request(action=api.Actions.TRANSACTION, payload=payload)
            except MeshInvalidInput:
                pass
            else:
                if responses:
                    ret[ATTR_MESH_STORAGE] = {
                        "smb_server_settings": responses[0].get(api.Response.RESULTS_KEY_SINGLE, {}),
                        "available_partitions": responses[1].get(api.Response.RESULTS_KEY_SINGLE, {})
                    }
        # endregion

        _LOGGER.debug(self.message_format("exited"))
        return ret

    # region #-- public methods --#
    async def async_check_for_updates(self) -> None:
        """Ask the mesh to look for new versions of firmware for the nodes

        Only a check is done.  The firmware isn't actually updated.

        :return: None
        """

        _LOGGER.debug(self.message_format("entered"))

        await self._async_make_request(
            action=api.Actions.UPDATE_FIRMWARE,
            payload=DEF_JNAP_CHECK_FIRMWARE_PAYLOAD,
        )

        _LOGGER.debug(self.message_format("exited"))

    async def async_close(self) -> None:
        """Close the session to the mesh

        :return: None
        """

        _LOGGER.debug(self.message_format("Closing session to: %s"), self.connected_node)
        return await self._session.close()

    async def async_delete_device(self, **kwargs) -> None:
        """Delete a device from the device list on the mesh

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
            d: Device
            device = [d for d in self._mesh_attributes[ATTR_MESH_DEVICES] if d.name == kwargs.get("device_name")]
            if len(device) == 0:
                raise MeshDeviceNotFoundResponse
            elif len(device) > 1:
                raise MeshTooManyMatches
            else:
                device_id = device[0].unique_id
        else:
            device_id = ""

        if device_id:
            payload = {
                "deviceID": device_id
            }
            await self._async_make_request(action=api.Actions.DELETE_DEVICE, payload=payload)
        else:
            raise MeshInvalidArguments

        _LOGGER.debug(self.message_format("exited"))

    async def async_gather_details(self) -> None:
        """Gather all the details and initialise what the mesh looks like

        Sets the instance variables as necessary.

        :return: None
        """

        _LOGGER.debug(self.message_format("entered"))

        details = await self._async_gather_details(
            include_backhaul=True,
            include_devices=True,
            include_guest_wifi=True,
            include_parental_control=True,
            include_speedtest_results=True,
            include_wan=True,
            include_firmware_update=True,
            include_speedtest_state=True,
            include_storage=True,
            include_update_settings=True,
        )

        # region #-- split the devices into their types --#
        _LOGGER.debug(self.message_format("Populating nodes"))
        self._mesh_attributes[ATTR_MESH_NODES] = [
            device
            for device in details[ATTR_MESH_DEVICES]
            if device.__class__.__name__.lower() == "node"
        ]
        _LOGGER.debug(self.message_format("Populated %i nodes"), len(self._mesh_attributes[ATTR_MESH_NODES]))

        _LOGGER.debug(self.message_format("Populating devices"))
        self._mesh_attributes[ATTR_MESH_DEVICES] = [
            device
            for device in details.get(ATTR_MESH_DEVICES, [])
            if device.__class__.__name__.lower() == "device"
        ]
        _LOGGER.debug(self.message_format("Populated %i devices"), len(self._mesh_attributes[ATTR_MESH_DEVICES]))
        # endregion

        # region #-- manage the other attributes --#
        details.pop(ATTR_MESH_DEVICES)
        for attr in details:
            _LOGGER_VERBOSE.debug(self.message_format("Populating %s"), attr)
            self._mesh_attributes[attr] = details[attr]
        # endregion

        _LOGGER.debug(self.message_format("exited"))

    async def async_get_device_from_id(self, device_id: str, force_refresh: bool = False) -> Device | Node:
        """Get a Device or Node object based on the ID.

        By default, the stored information is used, but you can refresh it from the API.
        Raises an error if the device is not found.

        :param device_id: The ID of the device to get details about
        :param force_refresh: True to re-query the API for the latest details
        :return: Device or Node object whichever is applicable
        """

        _LOGGER.debug(self.message_format("entered, device_id: %s, force_refresh: %s"), device_id, force_refresh)

        all_devices: List[Device | Node]
        if not force_refresh:
            all_devices = self.devices + self.nodes
        else:
            resp = await self._async_gather_details(
                include_devices=True,
            )
            all_devices = resp.get(ATTR_MESH_DEVICES)

        try:
            ret = [device for device in all_devices if device.unique_id == device_id][0]
        except IndexError:
            raise MeshDeviceNotFoundResponse

        _LOGGER.debug(self.message_format("exited"))
        return ret

    async def async_get_device_from_mac_address(
            self,
            mac_address: str,
            force_refresh: bool = False
    ) -> Device | Node:
        """To get a Device or Node object based on the MAC address.

        Searches through all known adapters on the device to find a match.
        By default, the stored information is used, but you can refresh it from the API.
        Raises an error if the device is not found.

        :param mac_address: The MAC address to search for
        :param force_refresh: True to re-query the details from the API
        :return:  Device or Node object whichever is applicable
        """

        _LOGGER.debug(self.message_format("entered, MAC: %s, force_refresh: %s"), mac_address, force_refresh)

        # noinspection PyTypeChecker
        ret: Optional[Device | Node] = None

        all_devices: List[Device | Node]
        if not force_refresh:
            all_devices = self.nodes + self.devices
        else:
            resp = await self._async_gather_details(
                include_devices=True,
            )
            all_devices = resp.get(ATTR_MESH_DEVICES)

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
        """Get the devices from the API

        To be used only if needing to query devices and get the details returned.
        Returns the devices in alphabetical order based on the name.

        :return: List of device objects
        """

        _LOGGER.debug(self.message_format("entered"))

        all_devices = await self._async_gather_details(
            include_devices=True,
        )
        ret: List[Device] = [
            device
            for device in all_devices.get(ATTR_MESH_DEVICES, [])
            if device.__class__.__name__.lower() == "device"
        ]
        ret = sorted(ret, key=lambda device: device.name)

        _LOGGER.debug(self.message_format("exited"))
        return ret

    async def async_get_speedtest_results(
            self,
            count: int = 1,
            only_latest: bool = False,
            only_completed: bool = False
    ) -> List:
        """Retrieve Speedtest results.

        :param count: the number of results to return; defaults to 1
        :param only_latest: True to only return the latest result
        :param only_completed: True to only return results that are not currently running
        :return: List of dictionaries containing the result details
        """

        _LOGGER.debug(self.message_format("entered"))

        payload = {**DEF_JNAP_SPEEDTEST_PAYLOAD, "lastNumberOfResults": count}
        resp = await self._async_make_request(action=api.Actions.GET_SPEEDTEST_RESULTS, payload=payload)
        healthcheck_results = resp.get(api.Response.RESULTS_KEY_SINGLE, {}).get("healthCheckResults")

        _LOGGER.debug(self.message_format("exited"))
        return _process_speedtest_results(
            speedtest_results=healthcheck_results,
            only_latest=only_latest,
            only_completed=only_completed
        )

    async def async_get_speedtest_state(self) -> str:
        """Return a textual representation of the stage of a Speedtest

        The API does not return a stage so this has to be inferred by the results.

        :return: A string containing the stage
        """

        _LOGGER.debug(self.message_format("entered"))

        resp = await self._async_gather_details(include_speedtest_state=True)
        ret = resp[ATTR_MESH_SPEEDTEST_STATE]

        _LOGGER.debug(self.message_format("exited"))
        return ret

    async def async_get_update_state(self) -> bool:
        """Get the state of the running check for updates

        :return: True if still running, False if not
        """

        _LOGGER.debug(self.message_format("entered"))

        resp = await self._async_gather_details(
            include_firmware_update=True
        )
        node_results = resp.get(ATTR_MESH_UPDATE_FIRMWARE_STATE, {}).get("firmwareUpdateStatus", [])
        all_states = ["pendingOperation" in node for node in node_results]

        ret: bool = any(all_states)

        _LOGGER.debug(self.message_format("exited"))
        return ret

    async def async_reboot_node(self, node_name: str, force: bool = False) -> None:
        """Reboot the given node

        N.B. Rebooting the primary node will cause all nodes to reboot. If you're sure you want to
        reboot the primary node, set the `force` parameter to `True`

        :param node_name: the name of the node to restart
        :param force: True to acknowledge the primary node, ignored for everything else
        :return: None
        """

        _LOGGER.debug(self.message_format("entered, node: %s, force: %s"), node_name, force)

        node_details: List[Node] = [
            node
            for node in self.nodes
            if node.name.lower() == node_name.lower()
        ]
        if not node_details:
            raise MeshDeviceNotFoundResponse

        if node_details[0].type == NODE_TYPE_PRIMARY and not force:
            # noinspection PyTypeChecker
            raise MeshInvalidInput(f"{node_name} is a primary node. Use the force.")

        node_ip = [
            adapter.get("ip")
            for adapter in node_details[0].network
            if adapter.get("ip")
        ]
        if not node_ip:
            # noinspection PyTypeChecker
            raise MeshInvalidInput(f"{node_name}: no valid address found")

        await self._async_make_request(
            action=api.Actions.REBOOT,
            node_address=api.Request.jnap_url(target=node_ip[0])
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

        _LOGGER.debug(self.message_format("entered, state %s"), 'on' if state else 'off')

        resp = await self._async_gather_details(  # get the current radio settings from the API; they may have changed
            include_guest_wifi=True,
        )
        radios = resp.get("radios", [])
        payload = {
            "isGuestNetworkEnabled": state,
            "radios": radios,
        }
        await self._async_make_request(action=api.Actions.SET_GUEST_NETWORK, payload=payload)

        _LOGGER.debug(self.message_format("exited"))

    async def async_set_parental_control_state(self, state: bool) -> None:
        """Set the state of the Parental Control feature.

        The rules are a required parameter for the API call but are not handled in this method.
        Instead, a call is made to retrieve the existing rules and those are relayed back.

        :param state: True to enabled, False to disable
        :return: None
        """

        _LOGGER.debug(self.message_format("entered, state: %s"), 'on' if state else 'off')
        resp = await self._async_gather_details(  # get the current rules from the API because they may be different
            include_parental_control=True,
        )
        rules = resp.get("rules", [])
        payload = {
            "isParentalControlEnabled": state,
            "rules": rules,
        }
        await self._async_make_request(action=api.Actions.SET_PARENTAL_CONTROL_INFO, payload=payload)

        _LOGGER.debug(self.message_format("exited"))

    async def async_start_speedtest(self) -> None:
        """Instruct the mesh to carry out a Speedtest

        A Speedtest is a long-running task.  You should use the async_get_speedtest_state method to understand
        the progress of the task.

        :return: None
        """

        _LOGGER.debug(self.message_format("entered"))

        payload = {
            "runHealthCheckModule": "SpeedTest"
        }
        await self._async_make_request(action=api.Actions.START_SPEEDTEST, payload=payload)

        _LOGGER.debug(self.message_format("exited"))

    async def async_test_credentials(self) -> bool:
        """Check the provided credentials are valid

        :return: True if valid, False if not
        """

        _LOGGER.debug(self.message_format("entered"))

        ret = await self._async_make_request(action=api.Actions.CHECK_PASSWORD)
        ret = True if ret.get("result", False) else False

        _LOGGER.debug(self.message_format("exited"))
        return ret
    # endregion

    # region #-- properties --#
    @property
    def check_for_update_status(self) -> bool:
        """Get the state of checking for an update as at the last time details were gathered.

        If you need the live state then use the async_get_update_state to re-query the API.

        :return: True if checking, False if not
        """

        node_results = self._mesh_attributes[ATTR_MESH_UPDATE_FIRMWARE_STATE].get("firmwareUpdateStatus", [])
        all_states = ["pendingOperation" in node for node in node_results]

        return any(all_states)

    @property
    def connected_node(self) -> str:
        """Get the node in the mesh that we are connected to

        :return: A string containing the node IP address
        """

        return self._mesh_attributes[ATTR_MESH_CONNECTED_NODE]

    @property
    def devices(self) -> List:
        """Get the devices in the mesh.

        The list will be returned in alphabetical order based on the device name.
        N.B. this will not include the nodes.

        :return: A list containing Device objects
        """

        return sorted(self._mesh_attributes[ATTR_MESH_DEVICES], key=lambda device: device.name)

    @property
    def guest_wifi_enabled(self) -> bool:
        """Get the state of the guest Wi-Fi.

        :return: True if enabled, False if not
        """

        return self._mesh_attributes[ATTR_MESH_GUEST_NETWORK_INFO].get("isGuestNetworkEnabled", False)

    @property
    def guest_wifi_details(self) -> List:
        """Get the guest network Wi-Fi details

        :return: A list of dictionaries containing the SSID and band for the networks
        """

        ret = [
            {
                "ssid": radio.get("guestSSID"),
                "band": radio.get("radioID").split("_")[-1],
            }
            for idx, radio in enumerate(self._mesh_attributes[ATTR_MESH_GUEST_NETWORK_INFO].get("radios", []))
        ]
        return ret

    @property
    def nodes(self) -> List:
        """Get the nodes in the mesh

        The return is sorted in alphabetical order based on node name.

        :return: A list of Node objects
        """

        return sorted(self._mesh_attributes[ATTR_MESH_NODES], key=lambda node: node.name)

    @property
    def parental_control_enabled(self) -> bool:
        """Get the state of the Parental Control feature

        :return: True if enabled, False if not
        """

        return self._mesh_attributes[ATTR_MESH_PARENTAL_CONTROL_INFO].get("isParentalControlEnabled", False)

    @property
    def speedtest_status(self) -> str:
        """Returns the current status of the Speedtest"""

        return self._mesh_attributes[ATTR_MESH_SPEEDTEST_STATE].get("speedTestResult", "")

    @property
    def speedtest_results(self) -> List:
        """Get the Speedtest results

        N.B. Currently this only returns the latest result completed result.  If you need more results see the
        async_get_speedtest_results method

        :return: A list containing the Speedtest results
        """

        ret = _process_speedtest_results(
            self._mesh_attributes[ATTR_MESH_SPEEDTEST_RESULTS].get("healthCheckResults", []),
            only_completed=True,
            only_latest=True
        )
        return ret

    @property
    def storage_available(self) -> List:
        """Get available shared partitions"""

        ret: List = []
        n: List[Node]
        device: dict
        storage_available = self._mesh_attributes.get(ATTR_MESH_STORAGE, {}).get("available_partitions", {})
        for node in storage_available.get("storageNodes", []):
            for device in node.get("storageDevices", []):
                for partition in device.get("partitions", []):
                    n = [_n for _n in self.nodes if _n.unique_id == node.get("deviceID")]
                    if n:
                        ip = [adapter.get("ip") for adapter in n[0].connected_adapters if adapter.get("ip")]
                        ret.append({
                            "available_kb": partition.get("availableKB"),
                            "ip": ip[0],
                            "label": partition.get("label"),
                            "last_checked": node.get("timestamp"),
                            "used_kb": partition.get("usedKB"),
                            "used_percent": round((partition.get("usedKB") / partition.get("availableKB")) * 100, 2),
                        })

        return ret

    @property
    def storage_settings(self) -> dict:
        """Get the settings for shared partitions"""

        ret = self._mesh_attributes.get(ATTR_MESH_STORAGE, {}).get("smb_server_settings", {})
        if ret:
            ret = {
                "anonymous_access": ret.get("isAnonymousAccessEnabled")
            }

        return ret

    @property
    def update_type(self) -> Optional[str]:
        """Get the update setting for firmware

        N.B. Known values: "manual", "automaticallycheckandinstall"

        :return: representation of the update type
        """

        update_setting: Optional[str] = self._mesh_attributes.get(
            ATTR_MESH_UPDATE_SETTINGS, {}
        ).get("updatePolicy")
        return update_setting.lower() if update_setting is not None else None

    @property
    def wan_dns(self) -> List:
        """Get the WAN DNS servers

        :return: A list containing the IP addresses of the WAN DNS servers
        """

        return [
            val
            for key, val in self._mesh_attributes[ATTR_MESH_WAN_INFO].get("wanConnection", {}).items()
            if key.startswith("dnsServer")
        ]

    @property
    def wan_ip(self) -> str:
        """Get the WAN IP address

        :return: A string containing the IP address for the WAN
        """

        return self._mesh_attributes[ATTR_MESH_WAN_INFO].get("wanConnection", {}).get("ipAddress")

    @property
    def wan_mac(self) -> str:
        """Get the WAN MAC

        :return: A string containing the MAC address for the WAN adapter
        """

        return self._mesh_attributes[ATTR_MESH_WAN_INFO].get("macAddress", "")

    @property
    def wan_status(self) -> bool:
        """Get the status of the WAN

        :return: True if connected, False if not
        """

        return self._mesh_attributes[ATTR_MESH_WAN_INFO].get("wanStatus", "").lower() == "connected"
    # endregion
