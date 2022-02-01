"""Representation of the mesh"""

import base64
import json
import logging
import time
from asyncio.exceptions import TimeoutError
from typing import Optional, Union, List

import aiohttp
from aiohttp.client_exceptions import (
    ClientConnectionError,
    ClientConnectorError,
)

from . import const
from .device import Device
from .exceptions import (
    MeshBadResponse,
    MeshConnectionError,
    MeshDeviceNotFoundResponse,
    MeshInvalidArguments,
    MeshInvalidCredentials,
    MeshInvalidInput,
    MeshInvalidOutput,
    MeshNodeNotPrimary,
    MeshTimeoutError,
    MeshTooManyMatches,
)
from .node import Node

_LOGGER = logging.getLogger(__name__)
_LOGGER_VERBOSE = logging.getLogger(f"{__name__}.verbose")


def _get_action_index(action: str, payload: List[dict]) -> Union[int, None]:
    """Determine which index the supplied action is in the JNAP transaction results

    The results are returned in a list in the order they were requested, but we don't really
    now which order this will be because actions could be added to the payload dynamically.

    :param action: The JNAP action to look for
    :param payload: The payload list as it was passed to the API
    :return: The index of the action or None if it isn't found
    """

    ret = [idx for idx, p in enumerate(payload) if p.get("action") == action]
    if ret:
        ret = ret[0]
    else:
        ret = None

    return ret


def _is_valid_response(response: Union[aiohttp.ClientResponse, dict]) -> bool:
    """Check to see if the response returned from the API was valid.

    At this point we're just checking if it is valid JSON and the result is 'OK'

    :param response: Either the response as received from the API or a dictionary representing a response.
    :return: True if the response is valid.  False if not.
    """

    ret = False
    json_response = {}
    if isinstance(response, aiohttp.ClientResponse):
        try:
            json_response = response.json()
        except json.JSONDecodeError as err:
            _LOGGER.error(err)
    elif isinstance(response, dict):
        json_response = response

    if json_response.get("result") == "OK":
        ret = True

    return ret


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
            if result.get("exit_code", "").lower() not in const.DEF_JNAP_SPEEDTEST_RESULTS_INVALID
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


def _process_raw_device_results(device_results=None) -> None:
    """Add the required details to the device results.

    The results are modified in place.

    :param device_results: list of the results as returned by the API
    :return: No return
    """

    if device_results is None:
        device_results = []

    for device in device_results:
        device["results_time"]: int = int(time.time())


class Mesh:
    """Representation of the Velop Mesh

    **All properties are point in time from when the last async_gather_details was executed.**

    If you need live information then call the corresponding method.
    """

    def __init__(self, node: str, password: str, username: str = "admin", request_timeout: Union[int, None] = None):
        """Constructor

        :param node: The node we should make a connection to
        :param password: password to use
        :param username: username to use; default admin
        :param request_timeout: number of seconds to time out the request; default 10s
        """

        if request_timeout is None:
            request_timeout = 10

        self._session: aiohttp.ClientSession

        self.__mesh_attributes: dict = {  # initialise the attributes for the mesh
            const.ATTR_MESH_CONNECTED_NODE: node,
            const.ATTR_MESH_DEVICES: [],
            const.ATTR_MESH_GUEST_NETWORK_INFO: {},
            const.ATTR_MESH_NODES: [],
            const.ATTR_MESH_PARENTAL_CONTROL_INFO: {},
            const.ATTR_MESH_SPEEDTEST_RESULTS: [],
            const.ATTR_MESH_UPDATE_FIRMWARE_STATE: [],
            const.ATTR_MESH_WAN_INFO: {},
        }

        self.__api_url: str = self.__get_api_url(self.__mesh_attributes[const.ATTR_MESH_CONNECTED_NODE])
        self.__username: str = username
        self.__password: str = password
        self.__timeout: int = request_timeout
        self.__create_session()

        # noinspection PyProtectedMember
        _LOGGER.debug("%s version: %s", __package__, const._PACKAGE_VERSION)
        _LOGGER.debug("Initialised mesh for %s", self.__mesh_attributes[const.ATTR_MESH_CONNECTED_NODE])

    async def __aenter__(self):
        """Asynchronous enter magic method"""

        return self

    async def __aexit__(self, exc_type, exc, traceback) -> None:
        """Asynchronous exit magic method"""
        await self.close()

    def __repr__(self) -> str:
        """Friendly string representation of the class

        :return: Uses the class name and the node we're connected to for the representation
        """

        ret = f"{self.__class__.__name__}: {self.__mesh_attributes[const.ATTR_MESH_CONNECTED_NODE]}"

        return ret

    @staticmethod
    def __get_api_url(host: str) -> str:
        """Build the base URL for the API

        :host: the host name of the node
        """

        # noinspection HttpUrlsUsage
        return f"http://{host}/JNAP/"

    async def __async_make_request(self, action: str, payload=None, node_address: Optional[str] = None) -> dict:
        """Execute the API request against the connected node.

        :param action: The JNAP action to execute
        :param payload: The relevant payload for the action
        :param node_address: The node to send the request to (only valid for a subset of actions)
        :return: THe JSON response or raises an error if need be
        """

        _LOGGER_VERBOSE.debug(
            "URL: %s, Action: %s, Payload: %s, Timeout: %i",
            node_address,
            action,
            json.dumps(payload),
            self.__timeout
        )

        if node_address is not None and action != const.ACTION_JNAP_REBOOT:
            raise MeshInvalidArguments

        if node_address is None:
            node_address = self.__api_url

        if payload is None:
            payload = []

        headers = self.__get_headers()
        headers["X-JNAP-Action"] = action
        try:
            if self._session.closed:  # session closed so recreate it
                _LOGGER_VERBOSE.debug("Session was closed.")
                self.__create_session()
            resp = await self._session.post(url=node_address, headers=headers, json=payload, timeout=self.__timeout)
        except TimeoutError:
            raise MeshTimeoutError
        except (ClientConnectionError, ClientConnectorError,):
            raise MeshConnectionError
        except aiohttp.ClientError:
            raise
        else:
            try:
                resp_json = await resp.json()
            except aiohttp.ClientError:
                raise MeshBadResponse
            else:
                _LOGGER_VERBOSE.debug("Response: %s", json.dumps(resp_json))
                if _is_valid_response(response=resp_json):
                    ret = resp_json
                else:  # process API specific errors
                    if "responses" not in resp_json:
                        resp_json = {"responses": [resp_json]}

                    err = None
                    for resp in resp_json.get("responses", []):
                        err = None
                        if resp.get("result") == "_ErrorInvalidInput":
                            err = MeshInvalidInput(resp.get("error"))
                        elif resp.get("result") == "_ErrorInvalidOutput":
                            err = MeshInvalidOutput(resp.get("error"))
                        elif resp.get("result") == "_ErrorUnauthorized":
                            err = MeshInvalidCredentials
                        elif resp.get("result") == "_ErrorUnknownAction":
                            # noinspection PyTypeChecker
                            err = MeshInvalidInput("Unknown JNAP Action")
                        elif resp.get("result") == "ErrorDeviceNotInMasterMode":
                            err = MeshNodeNotPrimary
                        elif resp.get("result") != "OK" and not resp.get("result").startswith("_"):
                            err = MeshInvalidInput(resp.get("result"))

                        if err:
                            break

                    if not err:
                        _LOGGER.error("Unknown error received: %s", json.dumps(resp_json))
                        err = MeshBadResponse

                    raise err

        return ret

    async def __async_gather_details(
            self,
            **kwargs,
    ) -> dict:
        """Work is done here to gather the necessary details for mesh.

        :param include_backhaul: True to include backhaul details
        :param include_devices: True to include devices
        :param include_guest_wifi: True to include details about the guest Wi-Fi
        :param include_parental_control: True to include details about Parental Control
        :param include_speedtest_results: True to include the latest completed Speedtest result
        :param include_firmware_update: True to include the current firmware update details (does not issue a check)
        :param include_wan: True to include WAN details
        :return: A dictionary containing the relevant details.  Keys used will match those of the instance variable.
        """

        _LOGGER.debug("Gathering details: %s", json.dumps(kwargs))

        ret = {}
        payload: List = []

        # -- get the devices --#
        if kwargs.get("include_devices"):
            payload.append({
                "action": const.ACTION_JNAP_GET_DEVICES,
                "request": {},
            })

        # -- get the backhaul info  --#
        if kwargs.get("include_backhaul"):
            payload.append({
                "action": const.ACTION_JNAP_GET_BACKHAUL,
                "request": {},
            })

        # -- get the guest WiFi details --#
        if kwargs.get("include_guest_wifi"):
            payload.append({
                "action": const.ACTION_JNAP_GET_GUEST_NETWORK_INFO,
                "request": {},
            })

        # -- get the Parental Control details --#
        if kwargs.get("include_parental_control"):
            payload.append({
                "action": const.ACTION_JNAP_GET_PARENTAL_CONTROL_INFO,
                "request": {},
            })

        # -- get the current Speedtest state --#
        if kwargs.get("include_speedtest_state"):
            payload.append({
                "action": const.ACTION_JNAP_GET_SPEEDTEST_STATE,
                "request": {}
            })

        # -- get the latest Speedtest result --#
        if kwargs.get("include_speedtest_results"):
            payload.append({
                "action": const.ACTION_JNAP_GET_SPEEDTEST_RESULTS,
                "request": {**const.DEF_JNAP_SPEEDTEST_PAYLOAD, "lastNumberOfResults": 10},
            })

        # -- get the update check details --#
        if kwargs.get("include_firmware_update"):
            payload.append({
                "action": const.ACTION_JNAP_GET_UPDATE_FIRMWARE_STATE,
                "request": {},
            })

        # -- get the WAN details --#
        if kwargs.get("include_wan"):
            payload.append({
                "action": const.ACTION_JNAP_GET_WAN_INFO,
                "request": {},
            })

        resp = await self.__async_make_request(action=const.ACTION_JNAP_TRANSACTION, payload=payload)
        responses = resp.get("responses", [])
        if responses:
            # region #-- populate the update check details --#
            # this needs to happen early because we'll use the results when populating the node details
            idx = _get_action_index(
                action=const.ACTION_JNAP_GET_UPDATE_FIRMWARE_STATE,
                payload=payload
            )
            if idx is not None:
                ret[const.ATTR_MESH_UPDATE_FIRMWARE_STATE] = responses[idx] \
                    .get(const.KEY_ACTION_JNAP_RESPONSE_RESULTS, {})
            # endregion

            # region #-- populate device and node details --#
            idx = _get_action_index(
                action=const.ACTION_JNAP_GET_DEVICES,
                payload=payload
            )
            device_info: List[dict] = []
            if idx is not None:
                device_info = responses[idx] \
                    .get(const.KEY_ACTION_JNAP_RESPONSE_RESULTS, {}) \
                    .get("devices", [])
                _process_raw_device_results(device_results=device_info)

            idx = _get_action_index(
                action=const.ACTION_JNAP_GET_BACKHAUL,
                payload=payload
            )
            backhaul_info: dict = {}
            if idx is not None:
                backhaul_info = responses[idx] \
                    .get(const.KEY_ACTION_JNAP_RESPONSE_RESULTS, {}) \
                    .get("backhaulDevices", [])

            # region #-- build the properties for the device types --#
            devices = []
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
                    node_firmware: Union[List, dict] = {}
                    if const.ATTR_MESH_UPDATE_FIRMWARE_STATE in ret:
                        firmware_status = ret[const.ATTR_MESH_UPDATE_FIRMWARE_STATE].get("firmwareUpdateStatus", [])
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
                    n = Node(**device, **{"backhaul": device_backhaul, "updates": node_firmware})
                    devices.append(n)
                else:
                    d = Device(**device)
                    devices.append(d)
            # endregion

            # region #-- post processing devices and nodes --#
            for node in devices:
                if node.__class__.__name__.lower() == "node":
                    # region #-- calculate the connected devices for nodes --#
                    connected_devices: List = []
                    parent_name: Union[str, None] = None
                    for device in devices:
                        for adapter in device.network:
                            if adapter.get("parent_id") == node.unique_id:
                                connected_devices.append({
                                    "name": device.name,
                                    "ip": adapter.get("ip"),
                                    "type": adapter.get("type"),
                                })
                            if node.parent_ip and not parent_name:
                                if node.parent_ip == adapter.get("ip"):
                                    parent_name = device.name
                    setattr(node, "parent_name", parent_name)
                    setattr(node, "_Node__connected_devices", connected_devices)
                    # endregion
                elif node.__class__.__name__.lower() == "device":
                    # region #-- calculate parent name for devices --#
                    attrib_connections = getattr(node, "_Device__attributes", {}).get("connections", [])
                    parent: Union[str, None] = None
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
                    setattr(node, "parent_name", parent)
                    # endregion
                    # region #-- get the parental control details --#
                    pc_schedule: List = []
                    if kwargs.get("include_parental_control"):
                        idx = _get_action_index(
                            action=const.ACTION_JNAP_GET_PARENTAL_CONTROL_INFO,
                            payload=payload
                        )
                        if idx is not None:
                            pc_details = responses[idx] \
                                .get(const.KEY_ACTION_JNAP_RESPONSE_RESULTS, {})
                            network_adapater_macs = [adapter.get("mac") for adapter in node.network]
                            for mac in network_adapater_macs:
                                for rule in pc_details.get("rules", []):
                                    if mac in rule.get("macAddresses", []):
                                        pc_schedule.append(rule)
                                        break
                    getattr(node, "_Device__attributes", {})["parental_controls"] = pc_schedule
                    # endregion
            # endregion

            if devices:
                ret[const.ATTR_MESH_DEVICES] = devices
            # endregion

            # region #-- populate the Guest Wi-Fi details --#
            idx = _get_action_index(
                action=const.ACTION_JNAP_GET_GUEST_NETWORK_INFO,
                payload=payload
            )
            if idx is not None:
                ret[const.ATTR_MESH_GUEST_NETWORK_INFO] = responses[idx] \
                    .get(const.KEY_ACTION_JNAP_RESPONSE_RESULTS, {})
            # endregion

            # region #-- populate the Parental Control details --#
            idx = _get_action_index(
                action=const.ACTION_JNAP_GET_PARENTAL_CONTROL_INFO,
                payload=payload
            )
            if idx is not None:
                ret[const.ATTR_MESH_PARENTAL_CONTROL_INFO] = responses[idx] \
                    .get(const.KEY_ACTION_JNAP_RESPONSE_RESULTS, {})
            # endregion

            # region #-- populate the WAN details --#
            idx = _get_action_index(
                action=const.ACTION_JNAP_GET_WAN_INFO,
                payload=payload
            )
            if idx is not None:
                ret[const.ATTR_MESH_WAN_INFO] = responses[idx] \
                    .get(const.KEY_ACTION_JNAP_RESPONSE_RESULTS, {})
            # endregion

            # region #-- populate the latest Speedtest results --#
            idx = _get_action_index(
                action=const.ACTION_JNAP_GET_SPEEDTEST_RESULTS,
                payload=payload
            )
            if idx is not None:
                speedtest_results = responses[idx] \
                    .get(const.KEY_ACTION_JNAP_RESPONSE_RESULTS, {}) \
                    .get("healthCheckResults", [])
                speedtest_results = _process_speedtest_results(
                    speedtest_results,
                    only_completed=True,
                    only_latest=True
                )
                ret[const.ATTR_MESH_SPEEDTEST_RESULTS] = speedtest_results
            # endregion

            # region #-- populate the current Speedtest status --#
            idx = _get_action_index(
                action=const.ACTION_JNAP_GET_SPEEDTEST_STATE,
                payload=payload
            )
            if idx is not None:
                ret[const.ATTR_MESH_SPEEDTEST_STATE] = _get_speedtest_state(
                    speedtest_results=responses[idx]
                    .get(const.KEY_ACTION_JNAP_RESPONSE_RESULTS, {})
                    .get("speedTestResult", {})
                )
            # endregion

        return ret

    async def __async_set_guest_wifi_state(self, state: bool, radios: Union[List, None] = None) -> None:
        """Set the state of the guest Wi-Fi in the mesh

        :param state: True to enable, False to disable
        :param radios: The radio information that should also be supplied
        :return: None
        """

        if radios is None:
            radios = []

        _LOGGER.debug("Setting the guest Wi-Fi to: %s", 'on' if state else 'off')
        payload = {
            "isGuestNetworkEnabled": state,
            "radios": radios,
        }
        await self.__async_make_request(action=const.ACTION_JNAP_SET_GUEST_NETWORK, payload=payload)

    async def __async_set_parental_control_state(self, state: bool, rules: Union[List, None] = None) -> None:
        """Set the state of Parental Control in the mesh

        :param state: True to enable, False to disable
        :param rules: The rules that should also be supplied
        :return: None
        """

        if rules is None:
            rules = []

        _LOGGER.debug("Setting parental controls to: %s", 'on' if state else 'off')
        payload = {
            "isParentalControlEnabled": state,
            "rules": rules,
        }
        await self.__async_make_request(action=const.ACTION_JNAP_SET_PARENTAL_CONTROL_INFO, payload=payload)

        return

    def __create_session(self) -> None:
        """Initialise a session and ensure that errors are raised based on the HTTP status codes

        :return: None
        """

        _LOGGER_VERBOSE.debug("Creating session.")
        self._session = aiohttp.ClientSession(raise_for_status=True)

    def __credentials(self) -> str:
        """Get the authorisation string for the Mesh

        :return:
        """

        return base64.b64encode(bytes(f"{self.__username}:{self.__password}", "utf-8")).decode("ascii")

    def __get_headers(self) -> dict:
        """Get the headers base headers for making an API call

        :return: dictionary of the required information
        """

        return {
            "X-JNAP-Authorization": f"Basic {self.__credentials()}",
            "Content-Type": "application/json; charset=UTF-8"
        }

    async def async_check_for_updates(self) -> None:
        """Ask the mesh to look for new versions of firmware for the nodes

        Only a check is done.  The firmware isn't actually updated.

        :return: None
        """

        _LOGGER.debug("Initiating a check for new firmware")

        await self.__async_make_request(
            action=const.ACTION_JNAP_UPDATE_FIRMWARE,
            payload=const.DEF_JNAP_CHECK_FIRMWARE_PAYLOAD,
        )

        return

    async def async_delete_device(self, **kwargs) -> None:
        """Delete a device from the device list on the mesh

        Supports deleting by device ID or device name.
        Will error if neither the device ID nor name are given.
        Will error if multiple devices match the given name.

        :param kwargs: keyword arguments (device_id, device_name)
        :return: None
        """

        _LOGGER.debug("Deleting device: %s", kwargs)

        device_id: str
        if "device_id" in kwargs:
            device_id = kwargs.get("device_id")
        elif "device_name" in kwargs:
            d: Device
            device = [d for d in self.__mesh_attributes[const.ATTR_MESH_DEVICES] if d.name == kwargs.get("device_name")]
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
            await self.__async_make_request(action=const.ACTION_JNAP_DELETE_DEVICE, payload=payload)
        else:
            raise MeshInvalidArguments

    async def async_gather_details(self) -> None:
        """Gather all the details and initialise what the mesh looks like

        Sets the instance variables as necessary.

        :return: None
        """

        details = await self.__async_gather_details(
            include_backhaul=True,
            include_devices=True,
            include_guest_wifi=True,
            include_parental_control=True,
            include_speedtest_results=True,
            include_wan=True,
            include_firmware_update=True,
            include_speedtest_state=True,
        )

        # region #-- split the devices into their types --#
        _LOGGER.debug("Populating nodes")
        self.__mesh_attributes[const.ATTR_MESH_NODES] = [
            device
            for device in details[const.ATTR_MESH_DEVICES]
            if device.__class__.__name__.lower() == "node"
        ]
        _LOGGER.debug("Populated %i nodes", len(self.__mesh_attributes[const.ATTR_MESH_NODES]))

        _LOGGER.debug("Populating devices")
        self.__mesh_attributes[const.ATTR_MESH_DEVICES] = [
            device
            for device in details.get(const.ATTR_MESH_DEVICES, [])
            if device.__class__.__name__.lower() == "device"
        ]
        _LOGGER.debug("Populated %i devices", len(self.__mesh_attributes[const.ATTR_MESH_DEVICES]))
        # endregion

        # region #-- manage the other attributes --#
        details.pop(const.ATTR_MESH_DEVICES)
        for attr in details:
            _LOGGER_VERBOSE.debug("Populating %s", attr)
            self.__mesh_attributes[attr] = details[attr]
        # endregion

    # noinspection DuplicatedCode
    async def async_get_device_from_id(self, device_id: str, force_refresh: bool = False) -> Union[Device, Node]:
        """Get a Device or Node object based on the ID.

        By default, the stored information is used, but you can refresh it from the API.
        Raises an error if the device is not found.

        :param device_id: The ID of the device to get details about
        :param force_refresh: True to re-query the API for the latest details
        :return: Device or Node object whichever is applicable
        """

        _LOGGER.debug("Getting device for ID: %s (force_refresh=%s)", device_id, force_refresh)

        all_devices: List[Union[Device, Node]]
        if not force_refresh:
            all_devices = self.devices + self.nodes
        else:
            resp = await self.__async_gather_details(
                include_devices=True,
            )
            all_devices = resp.get(const.ATTR_MESH_DEVICES)

        try:
            ret = [device for device in all_devices if device.unique_id == device_id][0]
        except IndexError:
            raise MeshDeviceNotFoundResponse

        return ret

    # noinspection DuplicatedCode
    async def async_get_device_from_mac_address(
            self,
            mac_address: str,
            force_refresh: bool = False
    ) -> Union[Device, Node]:
        """To get a Device or Node object based on the MAC address.

        Searches through all known adapters on the device to find a match.
        By default, the stored information is used, but you can refresh it from the API.
        Raises an error if the device is not found.

        :param mac_address: The MAC address to search for
        :param force_refresh: True to re-query the details from the API
        :return:  Device or Node object whichever is applicable
        """

        _LOGGER.debug("Getting device for AMC: %s (force_refresh=%s)", mac_address, force_refresh)

        # noinspection PyTypeChecker
        ret: Union[Device, Node] = None

        all_devices: List[Union[Device, Node]]
        if not force_refresh:
            all_devices = self.nodes + self.devices
        else:
            resp = await self.__async_gather_details(
                include_devices=True,
            )
            all_devices = resp.get(const.ATTR_MESH_DEVICES)

        for device in all_devices:
            if device.network:
                for adapter in device.network:
                    if adapter.get("mac").lower() == mac_address.lower():
                        ret = device
                        break

        if not ret:
            raise MeshDeviceNotFoundResponse

        return ret

    async def async_get_devices(self) -> List[Device]:
        """Get the devices from the API

        To be used only if needing to query devices and get the details returned.
        Returns the devices in alphabetical order based on the name.

        :return: List of device objects
        """

        _LOGGER.debug("Getting devices from the API")

        all_devices = await self.__async_gather_details(
            include_devices=True,
        )
        ret: List[Device] = [
            device
            for device in all_devices.get(const.ATTR_MESH_DEVICES, [])
            if device.__class__.__name__.lower() == "device"
        ]
        ret = sorted(ret, key=lambda device: device.name)

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

        _LOGGER.debug("Gathering Speedtest results: %s")

        payload = {**const.DEF_JNAP_SPEEDTEST_PAYLOAD, "lastNumberOfResults": count}
        resp = await self.__async_make_request(action=const.ACTION_JNAP_GET_SPEEDTEST_RESULTS, payload=payload)
        healthcheck_results = resp.get(const.KEY_ACTION_JNAP_RESPONSE_RESULTS, {}).get("healthCheckResults")

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

        _LOGGER.debug("Getting the current state of the Speedtest")

        resp = await self.__async_gather_details(
            include_speedtest_state=True,
        )
        ret = resp[const.ATTR_MESH_SPEEDTEST_STATE]

        _LOGGER.debug("Speedtest state: %s", ret)

        return ret

    async def async_get_update_state(self) -> bool:
        """Get the state of the running check for updates

        :return: True if still running, False if not
        """

        _LOGGER.debug("Getting the current state of the update check")

        resp = await self.__async_gather_details(
            include_firmware_update=True
        )
        node_results = resp.get(const.ATTR_MESH_UPDATE_FIRMWARE_STATE, {}).get("firmwareUpdateStatus", [])
        all_states = ["pendingOperation" in node for node in node_results]

        ret: bool = any(all_states)

        _LOGGER.debug("Update check state: %s", ret)

        return ret

    async def async_reboot_node(self, node_name: str, force: bool = False) -> None:
        """Reboot the given node

        N.B. Rebooting the primary node will cause all nodes to reboot. If you're sure you want to
        reboot the primary node, set the `force` parameter to `True`

        :param node_name: the name of the node to restart
        :param force: True to acknowledge the primary node, ignored for everything else
        :return: None
        """

        _LOGGER.debug("Rebooting node: %s", node_name)

        node_details: List[Node] = [
            node
            for node in self.nodes
            if node.name.lower() == node_name.lower()
        ]
        if not node_details:
            raise MeshDeviceNotFoundResponse

        if node_details[0].type == const.NODE_TYPE_PRIMARY and not force:
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

        await self.__async_make_request(
            action=const.ACTION_JNAP_REBOOT,
            node_address=self.__get_api_url(host=node_ip[0])
        )

    async def async_set_guest_wifi_state(self, state: bool) -> None:
        """Set the state of the guest Wi-Fi.

        The radios object is a required parameter for the API call but isn't handled in this method.
        Instead, a call is made to retrieve the existing settings and those are relayed back.  This assumes that
        a guest network has been created in the official UI.

        :param state: True to enable, False to disable
        :return: None
        """

        resp = await self.__async_gather_details(  # get the current radio settings from the API; they may have changed
            include_guest_wifi=True,
        )
        radios = resp.get("radios", [])
        await self.__async_set_guest_wifi_state(state=state, radios=radios)

    async def async_set_parental_control_state(self, state: bool) -> None:
        """Set the state of the Parental Control feature.

        The rules are a required parameter for the API call but are not handled in this method.
        Instead, a call is made to retrieve the existing rules and those are relayed back.

        :param state: True to enabled, False to disable
        :return: None
        """

        resp = await self.__async_gather_details(  # get the current rules from the API because they may be different
            include_parental_control=True,
        )
        rules = resp.get("rules", [])
        await self.__async_set_parental_control_state(state=state, rules=rules)

    async def async_start_speedtest(self) -> None:
        """Instruct the mesh to carry out a Speedtest

        A Speedtest is a long-running task.  You should use the async_get_speedtest_state method to understand
        the progress of the task.

        :return: None
        """

        _LOGGER.debug("Executing Speedtest")

        payload = {
            "runHealthCheckModule": "SpeedTest"
        }
        await self.__async_make_request(action=const.ACTION_JNAP_START_SPEEDTEST, payload=payload)

        return

    async def async_test_credentials(self) -> bool:
        """Check the provided credentials are valid

        :return: True if valid, False if not
        """

        _LOGGER.debug("Checking credentials against %s", self.__mesh_attributes[const.ATTR_MESH_CONNECTED_NODE])

        ret = await self.__async_make_request(action=const.ACTION_JNAP_CHECK_PASSWORD)
        ret = True if ret.get("result", False) else False

        return ret

    async def close(self) -> None:
        """Close the session to the mesh

        :return: None
        """

        _LOGGER.debug("Closing session to: %s", self.connected_node)

        return await self._session.close()

    @property
    def check_for_update_status(self) -> bool:
        """Get the state of checking for an update as at the last time details were gathered.

        If you need the live state then use the async_get_update_state to re-query the API.

        :return: True if checking, False if not
        """

        node_results = self.__mesh_attributes[const.ATTR_MESH_UPDATE_FIRMWARE_STATE].get("firmwareUpdateStatus", [])
        all_states = ["pendingOperation" in node for node in node_results]

        return any(all_states)

    @property
    def connected_node(self) -> str:
        """Get the node in the mesh that we are connected to

        :return: A string containing the node IP address
        """

        return self.__mesh_attributes[const.ATTR_MESH_CONNECTED_NODE]

    @property
    def devices(self) -> List:
        """Get the devices in the mesh.

        The list will be returned in alphabetical order based on the device name.
        N.B. this will not include the nodes.

        :return: A list containing Device objects
        """

        return sorted(self.__mesh_attributes[const.ATTR_MESH_DEVICES], key=lambda device: device.name)

    @property
    def guest_wifi_enabled(self) -> bool:
        """Get the state of the guest Wi-Fi.

        :return: True if enabled, False if not
        """

        return self.__mesh_attributes[const.ATTR_MESH_GUEST_NETWORK_INFO].get("isGuestNetworkEnabled", False)

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
            for idx, radio in enumerate(self.__mesh_attributes[const.ATTR_MESH_GUEST_NETWORK_INFO].get("radios", []))
        ]
        return ret

    @property
    def nodes(self) -> List:
        """Get the nodes in the mesh

        The return is sorted in alphabetical order based on node name.

        :return: A list of Node objects
        """

        return sorted(self.__mesh_attributes[const.ATTR_MESH_NODES], key=lambda node: node.name)

    @property
    def parental_control_enabled(self) -> bool:
        """Get the state of the Parental Control feature

        :return: True if enabled, False if not
        """

        return self.__mesh_attributes[const.ATTR_MESH_PARENTAL_CONTROL_INFO].get("isParentalControlEnabled", False)

    @property
    def speedtest_status(self) -> str:
        """Returns the current status of the Speedtest"""

        return self.__mesh_attributes[const.ATTR_MESH_SPEEDTEST_STATE]

    @property
    def speedtest_results(self) -> List:
        """Get the Speedtest results

        N.B. Currently this only returns the latest result completed result.  If you need more results see the
        async_get_speedtest_results method

        :return: A list containing the Speedtest results
        """

        return self.__mesh_attributes[const.ATTR_MESH_SPEEDTEST_RESULTS]

    @property
    def wan_dns(self) -> List:
        """Get the WAN DNS servers

        :return: A list containing the IP addresses of the WAN DNS servers
        """

        return [
            val
            for key, val in self.__mesh_attributes[const.ATTR_MESH_WAN_INFO].get("wanConnection", {}).items()
            if key.startswith("dnsServer")
        ]

    @property
    def wan_ip(self) -> str:
        """Get the WAN IP address

        :return: A string containing the IP address for the WAN
        """

        return self.__mesh_attributes[const.ATTR_MESH_WAN_INFO].get("wanConnection", {}).get("ipAddress")

    @property
    def wan_mac(self) -> str:
        """Get the WAN MAC

        :return: A string containing the MAC address for the WAN adapter
        """

        return self.__mesh_attributes[const.ATTR_MESH_WAN_INFO].get("macAddress", "")

    @property
    def wan_status(self) -> bool:
        """Get the status of the WAN

        :return: True if connected, False if not
        """

        return self.__mesh_attributes[const.ATTR_MESH_WAN_INFO].get("wanStatus", "").lower() == "connected"
