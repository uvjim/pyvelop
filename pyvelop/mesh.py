"""Representation of the mesh."""

# region #-- imports --#
from __future__ import annotations

import asyncio
import contextlib
import logging
import time
from collections.abc import Coroutine, Iterable
from typing import Any

from aiohttp import ClientSession

from . import __version__, camel_to_snake
from . import jnap as api
from .const import DeviceProperty, MeshCapability, UiType
from .decorators import deprecated, needs_initialise
from .exceptions import (
    MeshAlreadyInProgress,
    MeshDeviceNotFoundResponse,
    MeshException,
    MeshInvalidArguments,
    MeshInvalidCredentials,
    MeshInvalidInput,
    MeshInvalidOutput,
    MeshTooManyMatches,
)
from .logger import Logger
from .mesh_entity import DeviceEntity, ParentalControl
from .node import Node, NodeType
from .types import MeshDetails

# endregion

_ATTR_PROCESSED_DEVICES: str = "devices"
_LOGGER = logging.getLogger(__name__)
_LOGGER_VERBOSE = logging.getLogger(f"{__name__}.verbose")


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


def _process_speedtest_results(
    speedtest_results=None, only_latest: bool = False, only_completed: bool = False
) -> list:
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


def _get_parental_control_device_attributes(
    schedule: dict[str, str], urls: list[str]
) -> dict[str, list[str | dict[str, str]]]:
    """Determine what happens with device properties for parental control."""
    ret = {
        "remove": [],
        "modify": [],
    }
    if schedule == ParentalControl.ALL_ALLOWED_SCHEDULE() and not urls:
        ret["remove"].extend(
            [
                DeviceProperty.ACTUAL_WAN_SCHEDULE.value,
                DeviceProperty.BLOCK_ALL_MANUALLY.value,
                DeviceProperty.SHOW_IN_PC_LIST.value,
            ]
        )

    if (
        schedule != ParentalControl.ALL_ALLOWED_SCHEDULE()
        or schedule == ParentalControl.ALL_ALLOWED_SCHEDULE()
        and urls
    ):
        ret["modify"].append(
            {"name": DeviceProperty.SHOW_IN_PC_LIST.value, "value": "true"}
        )
        if schedule == ParentalControl.ALL_PAUSED_SCHEDULE():
            ret["modify"].append(
                {"name": DeviceProperty.BLOCK_ALL_MANUALLY.value, "value": "true"}
            )
        else:
            ret["remove"].append(DeviceProperty.BLOCK_ALL_MANUALLY.value)

    return ret


class Mesh:
    """Representation of the Velop Mesh.

    **All properties are point in time from when the last async_gather_details was executed.**

    If you need live information then call the corresponding method.
    """

    def __init__(
        self,
        node: str,
        password: str,
        request_timeout: int = 10,
        session: ClientSession | None = None,
        username: str = "admin",
    ) -> None:
        """Initialise the Mesh.

        :param node: The node we should make a connection to
        :param password: password to use
        :param request_timeout: number of seconds to time out the request; default 10s
        :param session: session to use in for interacting with the Mesh
        :param username: username to use; default admin
        """
        self._log_formatter = Logger()

        _LOGGER.debug(self._log_formatter.format("entered"))

        self._mesh_attributes: dict = {}
        _session: ClientSession = (
            session if session is not None else self.__create_session()
        )
        self._mesh_details: MeshDetails = MeshDetails(
            host=node,
            password=password,
            request_timeout=request_timeout,
            session=_session,
            user=username,
        )
        self._mesh_capabilities: list[MeshCapability] = []
        self._mesh_capabilities_device_details: list[MeshCapability] = []

        # flag used to denote that initialise has been executed
        self.__initialise_executed: bool = False
        self.__passed_session: bool = isinstance(session, ClientSession)

        _LOGGER.debug(
            self._log_formatter.format("Session was passed in: %s"),
            "Yes" if self.__passed_session else "No",
        )

        _LOGGER.debug(
            self._log_formatter.format("%s version: %s"),
            __package__,
            __version__,
        )
        _LOGGER.debug(
            self._log_formatter.format(
                "Initialised mesh for %s with request timeout %ss"
            ),
            self._mesh_details.host,
            self._mesh_details.request_timeout,
        )
        _LOGGER.debug(self._log_formatter.format("exited"))

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
    def __create_session(self) -> ClientSession:
        """Initialise a session and ensure that errors are raised based on the HTTP status codes.

        :return: None
        """
        _LOGGER_VERBOSE.debug(self._log_formatter.format("entered"))
        session = ClientSession(raise_for_status=True)
        _LOGGER_VERBOSE.debug(self._log_formatter.format("exited"))
        return session

    async def _async_make_request(
        self,
        action: str,
        node_address: str | None = None,
        payload: list[dict] | dict | None = None,
        raise_on_error: bool = True,
    ) -> tuple[api.Request, api.Response]:
        """Execute the API request against the connected node.

        :param action: The JNAP action to execute
        :param node_address: The node to send the request to (only valid for a subset of actions)
        :param payload: The relevant payload for the action
        :param raise_on_error: Raise an error if one is found

        :return: tuple containing the request and response objects or raises an error if need be
        """
        _LOGGER.debug(self._log_formatter.format("entered"))

        if node_address is not None and action != api.Actions.REBOOT:
            raise MeshInvalidArguments

        if payload is None:
            payload = []

        if (
            not self.__passed_session and self._mesh_details.session.closed
        ):  # session closed so recreate it
            _LOGGER_VERBOSE.debug(
                self._log_formatter.format("session was closed, reopening")
            )
            self._mesh_details.session = self.__create_session()

        req = api.Request(
            action=action if not isinstance(action, api.Actions) else action.value,
            password=self._mesh_details.password,
            payload=payload,
            raise_on_error=raise_on_error,
            session=self._mesh_details.session,
            target=node_address or self._mesh_details.host,
            username=self._mesh_details.user,
        )
        try:
            req_resp = await req.execute(timeout=self._mesh_details.request_timeout)
        except Exception as err:
            raise err from None

        _LOGGER.debug(self._log_formatter.format("exited"))
        return (req, req_resp)

    async def _async_gather_details(self, capabilities: list[MeshCapability]) -> dict:
        """Work is done here to gather the necessary details for mesh.

        :return: A dictionary containing the relevant details.
        """
        _LOGGER.debug(self._log_formatter.format("entered, args: %s"), capabilities)

        ret = {}
        payload_safe: list[dict[str, Any]] = []
        request_unsafe: list = []

        for capability in capabilities:
            jnap_action: api.Actions = api.Actions[capability.name]
            payload_safe.append(
                {
                    "action": jnap_action.value,
                    "request": api.Defaults.payloads[jnap_action],
                }
            )

        request_safe = self._async_make_request(
            action=api.Actions.TRANSACTION,
            payload=payload_safe,
            raise_on_error=False,
        )

        responses: list[tuple[api.Request, api.Response]] = await asyncio.gather(
            request_safe, *request_unsafe
        )

        # region #-- prepare all the raw details --#
        def _set_raw_value(action: str, data: list[dict] | dict | None) -> None:
            """Set the raw values."""
            try:
                api_response: api.Response = api.Response(action=action, data=data)
            except MeshException as err:
                _LOGGER.debug(self._log_formatter.format("%s"), err)
            else:
                capability: MeshCapability = MeshCapability[api.Actions(action).name]
                ret[capability.value] = api_response.data

        response: tuple[api.Request, api.Response]
        for response in responses:
            req, resp = response
            if req.action == api.Actions.TRANSACTION:
                for idx, action_response in enumerate(resp.data or {}):
                    _set_raw_value(
                        action=req.payload[idx].get("action"), data=action_response
                    )
            else:
                _set_raw_value(action=req.action, data=getattr(resp, "_data", {}))
        # endregion

        # region #-- handle mesh entities --#
        devices: list[Node] = []
        mesh_entities: list[DeviceEntity] = []
        discovered_mesh_entities: list[dict[str, Any]] = ret.get(
            MeshCapability.GET_DEVICES.value, {}
        ).get("devices", [])
        # region #-- build the properties for the mesh entity types --#
        for entity in discovered_mesh_entities:
            entity_data: dict[str, Any] = {}
            entity_data["results_time"] = int(time.time())
            if "nodeType" not in entity:
                entity_data.update(entity)
                # region #-- get the device parent --#
                dev_parent: str | None = None
                dev_connections: list[dict[str, Any]] = []
                for dev_connections in entity_data.get("connections", []):
                    if (
                        dev_parent_id := dev_connections.get("parentDeviceID")
                    ) is not None:
                        dev_parent = [
                            DeviceEntity(dev, self._mesh_details).name
                            for dev in discovered_mesh_entities
                            if dev.get("deviceID") == dev_parent_id
                        ]
                entity_data["parent_name"] = dev_parent[0] if dev_parent else dev_parent
                # endregion
                # region #-- process MAC based information --#
                dev_pc_schedule: list = []
                dev_adapter_macs: list[str] = [
                    dev_adapter.get("macAddress")
                    for dev_adapter in entity.get("knownInterfaces", [])
                ]
                for dev_mac in dev_adapter_macs:
                    # region #-- get parental control details --#
                    for rule in ret.get(
                        MeshCapability.GET_PARENTAL_CONTROL_INFO.value, {}
                    ).get("rules", []):
                        if dev_mac in rule.get("macAddresses", []):
                            dev_pc_schedule.append(rule)
                            break
                    entity_data["parental_controls"] = dev_pc_schedule
                    # endregion
                    # region #-- get reservation info --#
                    for reservation in (
                        ret.get(MeshCapability.GET_LAN_SETTINGS.value, {})
                        .get("dhcpSettings", {})
                        .get("reservations", [])
                    ):
                        if reservation.get("macAddress", "").lower() == dev_mac.lower():
                            entity_data["reservation_details"] = reservation
                            break
                    # endregion
                    # region #-- additional connection details --#
                    for conn_details in ret.get(
                        MeshCapability.GET_NETWORK_CONNECTIONS.value, {}
                    ).get("nodeWirelessConnections", []):
                        for connection in conn_details.get("connections", {}):
                            if dev_mac == connection.get("macAddress"):
                                entity_data["connection_details"] = connection
                                break
                    # endregion
                # endregion
                mesh_entities.append(DeviceEntity(entity_data, self._mesh_details))
            else:
                # region #-- determine the backhaul information --#
                device_backhaul = [
                    bi
                    for bi in ret.get(MeshCapability.GET_BACKHAUL.value, {}).get(
                        "backhaulDevices", []
                    )
                    if bi.get("deviceUUID") == entity.get("deviceID")
                ]
                # endregion

                # region #-- calculate if there is a firmware update available --#
                node_firmware: list | dict = {}
                if MeshCapability.GET_UPDATE_FIRMWARE_STATE.value in ret:
                    node_firmware = [
                        firmware_details
                        for firmware_details in ret[
                            MeshCapability.GET_UPDATE_FIRMWARE_STATE.value
                        ].get("firmwareUpdateStatus", [])
                        if firmware_details.get("deviceUUID") == entity.get("deviceID")
                    ]
                # endregion

                devices.append(
                    Node(
                        **entity,
                        **{
                            "backhaul": device_backhaul[0] if device_backhaul else {},
                            "updates": node_firmware[0] if node_firmware else {},
                        },
                    )
                )
        # endregion

        # region #-- post processing nodes --#
        for node in devices:
            # region #-- calculate the connected devices for nodes --#
            connected_devices: list = []
            parent_name: str | None = None
            for device in mesh_entities:
                for adapter in device.adapter_info:
                    if adapter.get("parent_id") == node.unique_id:
                        connected_devices.append(
                            {
                                "name": device.name,
                                "ip": adapter.get("ip"),
                                "type": adapter.get("type"),
                                "guest_network": adapter.get("guest_network"),
                            }
                        )
                    if (
                        node.parent_ip
                        and not parent_name
                        and node.parent_ip == adapter.get("ip")
                    ):
                        parent_name = device.name
            setattr(node, "_Node__parent_name", parent_name)
            setattr(node, "_Node__connected_devices", connected_devices)
            # endregion
        # endregion

        devices.extend(mesh_entities)
        ret[_ATTR_PROCESSED_DEVICES] = devices or []
        # endregion

        _LOGGER.debug(self._log_formatter.format("exited"))
        return ret

    async def _async_set_device_property(
        self, device_id: str, name: DeviceProperty | str, value: str
    ) -> None:
        """Set the given device property to the given value.

        :param device_id: the unique id of the device.
        :param name: the name of the property to set the value for.
        :param value: the value to set the property to.

        :return: None
        """
        _LOGGER.debug(
            self._log_formatter.format("entered, name: %s, value: %s"), name, value
        )

        try:
            await self._async_make_request(
                action=api.Actions.SET_DEVICE_PROPERTY,
                payload={
                    "deviceID": device_id,
                    "propertiesToModify": [
                        {
                            "name": (
                                name.value if isinstance(name, DeviceProperty) else name
                            ),
                            "value": value,
                        }
                    ],
                },
            )
        except MeshException as err:
            _LOGGER.error(err)
        except Exception as err:
            _LOGGER.error(err)

        _LOGGER.debug(self._log_formatter.format("exited"))

    # endregion

    # region #-- public methods --#
    async def async_check_for_updates(self) -> None:
        """Ask the mesh to look for new versions of firmware for the nodes.

        Only a check is done.  The firmware isn't actually updated.

        :return: None
        """
        _LOGGER.debug(self._log_formatter.format("entered"))
        await self._async_make_request(
            action=api.Actions.UPDATE_FIRMWARE, payload={"onlyCheck": True}
        )
        _LOGGER.debug(self._log_formatter.format("exited"))

    async def async_close(self) -> None:
        """Close the session to the mesh.

        :return: None
        """
        if not self.__passed_session:
            _LOGGER.debug(self._log_formatter.format("entered"))
            await self._mesh_details.session.close()
            _LOGGER.debug(self._log_formatter.format("exited"))

    @deprecated(solution="Use the async_delete method on the Device object.")
    async def async_delete_device_by_id(self, device: str) -> None:
        """Delete a device from the device list on the mesh by its ID.

        :param device: the unique id of the device to delete

        :return: None
        """
        _LOGGER.debug(self._log_formatter.format("entered, device: %s"), device)

        await self._async_make_request(
            action=api.Actions.DELETE_DEVICE, payload={"deviceID": device}
        )

    @deprecated(solution="Use the async_delete method on the Device object.")
    async def async_delete_device_by_name(self, device: str) -> None:
        """Delete a device from the device list on the mesh by name.

        Will error if multiple devices match the given name or no matching
        device is found.

        :param device: the name of the device to delete

        :return: None
        """
        _LOGGER.debug(self._log_formatter.format("entered, name: %s"), device)

        device: list[DeviceEntity] = [
            dev
            for dev in self._mesh_attributes[_ATTR_PROCESSED_DEVICES]
            if dev.name == device
        ]
        if len(device) == 0:
            raise MeshDeviceNotFoundResponse

        if len(device) > 1:
            raise MeshTooManyMatches

        await self.async_delete_device_by_id(device=device[0].unique_id)

        _LOGGER.debug(self._log_formatter.format("exited"))

    async def async_detect_capabilities(self) -> list[MeshCapability]:
        """Attempt to detect the capabilities of the Mesh.

        :return: list of capabilities for the mesh.
        """
        ret: list[str] = []
        requests: list[Coroutine] = []
        for qry in MeshCapability:
            action_name: str = qry.name
            requests.append(
                self._async_make_request(
                    action=getattr(api.Actions, action_name),
                    payload=api.Defaults.payloads[getattr(api.Actions, action_name)],
                    raise_on_error=False,
                )
            )

        responses: list[tuple[api.Request, api.Response]] = await asyncio.gather(
            *requests
        )
        for idx, resp in enumerate(responses):
            _, jnap_response = resp
            if "result" in jnap_response.data:
                continue
            ret.append(list(MeshCapability)[idx])

        self._mesh_capabilities = ret
        return self._mesh_capabilities

    @needs_initialise
    async def async_gather_details(self) -> None:
        """Gather all the details and initialise what the mesh looks like.

        Sets the instance variables as necessary.

        :return: None
        """
        _LOGGER.debug(self._log_formatter.format("entered"))

        self._mesh_attributes: dict[
            int | str, list[DeviceEntity | Node] | dict[str, Any]
        ] = await self._async_gather_details(self._mesh_capabilities)
        _LOGGER.debug(self._log_formatter.format("exited"))

    async def async_get_channel_scan_info(self) -> dict[str, Any]:
        """Get the current state of the channel scan.

        :return: dictionary containing the channel scan results
        """
        resp = await self._async_gather_details(
            [MeshCapability.GET_CHANNEL_SCAN_STATUS]
        )
        return resp.get(MeshCapability.GET_CHANNEL_SCAN_STATUS.value)

    @needs_initialise
    async def async_get_device_from_id(
        self,
        device_id: Iterable[str],
        force_refresh: bool = False,
        raise_for_missing: bool = True,
    ) -> list[DeviceEntity | Node]:
        """Get a Device or Node object based on the ID.

        By default, the stored information is used, but you can refresh it from the API.
        Raises an error if the device is not found.

        :param device_id: Iterable of device IDs to get details about
        :param force_refresh: True to re-query the API for the latest details
        :param raise_for_missing: True to raise an error when a device is not found

        :return: List of Device or Node objects whichever is applicable
        """
        _LOGGER.debug(
            self._log_formatter.format("entered, device_id: %s, force_refresh: %s"),
            device_id,
            force_refresh,
        )

        all_devices: list[DeviceEntity | Node]
        if not force_refresh:
            all_devices = self.devices + self.nodes
        else:
            resp = await self._async_gather_details(
                self._mesh_capabilities_device_details
            )
            all_devices = resp.get(_ATTR_PROCESSED_DEVICES)

        if not all_devices:
            raise MeshInvalidOutput from None

        ret = [device for device in all_devices if device.unique_id in device_id]
        if len(ret) != len(device_id) and raise_for_missing:
            found_ids = [device.unique_id for device in ret]
            raise MeshDeviceNotFoundResponse(
                devices=list(set(device_id).difference(found_ids))
            )

        _LOGGER.debug(self._log_formatter.format("exited"))
        return ret

    @needs_initialise
    async def async_get_device_from_mac_address(
        self,
        mac_address: Iterable[str],
        force_refresh: bool = False,
        raise_for_missing: bool = True,
    ) -> DeviceEntity | Node:
        """To get a Device or Node object based on the MAC address.

        Searches through all known adapters on the device to find a match.
        By default, the stored information is used, but you can refresh it from the API.
        Raises an error if the device is not found.

        :param mac_address: An iterable containing MAC address to search for
        :param force_refresh: True to re-query the details from the API
        :param raise_for_missing: True to raise exception when a device is not found

        :return:  Device or Node object whichever is applicable
        """
        _LOGGER.debug(
            self._log_formatter.format("entered, mac_address: %s, force_refresh: %s"),
            mac_address,
            force_refresh,
        )

        ret: list[DeviceEntity | Node] = []
        lower_macs: list[str] = list(map(str.lower, mac_address))
        found_macs: list[str] = []

        all_devices: list[DeviceEntity | Node]
        if not force_refresh:
            all_devices = self.nodes + self.devices
        else:
            resp = await self._async_gather_details(
                self._mesh_capabilities_device_details
            )
            all_devices = resp.get(_ATTR_PROCESSED_DEVICES)

        for device in all_devices:
            if device.network:
                for adapter in device.network:
                    if adapter.get("mac").lower() in lower_macs:
                        ret.append(device)
                        found_macs.append(adapter.get("mac").lower())
                        break

        if len(ret) != len(mac_address) and raise_for_missing:
            raise MeshDeviceNotFoundResponse(
                devices=list(set(lower_macs).difference(found_macs))
            )

        _LOGGER.debug(self._log_formatter.format("exited"))
        return ret

    @needs_initialise
    async def async_get_devices(self) -> list[DeviceEntity]:
        """Get the devices from the API.

        To be used only if needing to query devices and get the details returned.
        Returns the devices in alphabetical order based on the name.

        :return: List of device objects
        """
        _LOGGER.debug(self._log_formatter.format("entered"))

        all_devices = await self._async_gather_details(
            self._mesh_capabilities_device_details
        )
        ret: list[DeviceEntity] = [
            device
            for device in all_devices.get(_ATTR_PROCESSED_DEVICES, [])
            if isinstance(device, DeviceEntity)
        ]
        ret = sorted(ret, key=lambda device: device.name)

        _LOGGER.debug(self._log_formatter.format("exited"))
        return ret

    async def async_get_speedtest_results(
        self, count: int = 1, only_latest: bool = False, only_completed: bool = False
    ) -> list:
        """Retrieve Speedtest results.

        :param count: the number of results to return; defaults to 1
        :param only_latest: True to only return the latest result
        :param only_completed: True to only return results that are not currently running

        :return: List of dictionaries containing the result details
        """
        _LOGGER.debug(self._log_formatter.format("entered"))

        payload = {
            **api.Defaults.payloads[api.Actions.GET_SPEEDTEST_RESULTS],
            "lastNumberOfResults": count,
        }
        _, resp = await self._async_make_request(
            action=api.Actions.GET_SPEEDTEST_RESULTS, payload=payload
        )

        _LOGGER.debug(self._log_formatter.format("exited"))
        return _process_speedtest_results(
            speedtest_results=resp.data.get("healthCheckResults"),
            only_latest=only_latest,
            only_completed=only_completed,
        )

    async def async_get_speedtest_state(self) -> str:
        """Return a textual representation of the stage of a Speedtest.

        The API does not return a stage so this has to be inferred by the results.

        :return: A string containing the stage
        """
        _LOGGER.debug(self._log_formatter.format("entered"))

        resp = await self._async_gather_details([MeshCapability.GET_SPEEDTEST_STATUS])
        ret = _get_speedtest_state(
            speedtest_results=resp[MeshCapability.GET_SPEEDTEST_STATUS.value].get(
                "speedTestResult", {}
            )
        )

        _LOGGER.debug(self._log_formatter.format("exited"))
        return ret

    async def async_get_update_state(self) -> bool:
        """Get the state of the running check for updates.

        :return: True if still running, False if not
        """
        _LOGGER.debug(self._log_formatter.format("entered"))

        resp = await self._async_gather_details(
            [MeshCapability.GET_UPDATE_FIRMWARE_STATE]
        )

        node_results = resp.get(MeshCapability.GET_UPDATE_FIRMWARE_STATE.value, {}).get(
            "firmwareUpdateStatus", []
        )
        all_states = ["pendingOperation" in node for node in node_results]

        ret: bool = any(all_states)

        _LOGGER.debug(self._log_formatter.format("exited"))
        return ret

    async def async_get_upnp_state(self) -> dict[str, bool]:
        """Retrieve the current state of UPnP.

        :return: dictionary containing information about the state of UPnP functionality
        """

        _LOGGER.debug(self._log_formatter.format("entered"))

        resp = await self._async_gather_details([MeshCapability.GET_UPNP_SETTINGS])

        ret = resp.get(MeshCapability.GET_UPNP_SETTINGS.value, {})

        _LOGGER.debug(self._log_formatter.format("exited"))
        return ret

    async def async_initialise(self) -> None:
        """Initialise the connection to the Mesh.

        Probes for capabilities and retrieves details for the discovered capabilities.

        :return: None
        """

        await self.async_detect_capabilities()
        self.__initialise_executed = (
            True  # flag here so that async_gather_details will run
        )
        self._mesh_capabilities_device_details = [
            capability
            for capability in [
                MeshCapability.GET_DEVICES,
                MeshCapability.GET_LAN_SETTINGS,
                MeshCapability.GET_NETWORK_CONNECTIONS,
                MeshCapability.GET_PARENTAL_CONTROL_INFO,
            ]
            if capability in self._mesh_capabilities
        ]

        await self.async_gather_details()

    async def async_reboot_node(self, node_name: str, force: bool = False) -> None:
        """Reboot the given node.

        Rebooting the primary node will cause all nodes to reboot. If you're sure you want to
        reboot the primary node, set the `force` parameter to `True`

        :param node_name: the name of the node to restart
        :param force: True to acknowledge the primary node, ignored for everything else

        :return: None
        """
        _LOGGER.debug(
            self._log_formatter.format("entered, node_name: %s, force: %s"),
            node_name,
            force,
        )

        node_details: list[Node] = [
            node for node in self.nodes if node.name.lower() == node_name.lower()
        ]
        if not node_details:
            raise MeshDeviceNotFoundResponse

        if node_details[0].type == NodeType.PRIMARY and not force:
            raise MeshInvalidInput(f"{node_name} is a primary node. Use the force.")

        node_ip: list[str] | None = [
            adapter.get("ip")
            for adapter in node_details[0].connected_adapters
            if adapter.get("ip") and adapter.get("primary")
        ]

        if not node_ip:
            raise MeshInvalidInput(f"{node_name}: no valid address found")

        await self._async_make_request(
            action=api.Actions.REBOOT, node_address=node_ip[0]
        )

        _LOGGER.debug(self._log_formatter.format("exited"))

    @deprecated(solution="Use the async_rename method on the Device object.")
    async def async_rename_device(self, device_id: str, name: str) -> None:
        """Rename the given device.

        :param device_id: The unique id of the device to rename.
        :param name: The new name to set for the device.

        :return: None
        """
        _LOGGER.debug(self._log_formatter.format("entered"))

        await self._async_set_device_property(
            device_id, DeviceProperty.DEVICE_NAME, name
        )

        _LOGGER.debug(self._log_formatter.format("exited"))

    @deprecated(solution="Use the async_set_icon method on the Device object.")
    async def async_set_device_icon(self, device_id: str, icon: UiType | str) -> None:
        """Set the icon of the device.

        :param device_id: The unique id of the device to set the icon for.
        :param icon: The icon slug to set for the device.

        :return: None
        """

        _LOGGER.debug(self._log_formatter.format("entered"))

        _icon: UiType
        if not isinstance(icon, UiType):
            if icon not in UiType:
                raise ValueError("Invalid icon specified")

            _icon = UiType(icon)
        else:
            _icon = icon

        await self._async_set_device_property(
            device_id,
            DeviceProperty.UI_TYPE,
            _icon.value.replace("_", "-"),
        )

        _LOGGER.debug(self._log_formatter.format("exited"))

    async def async_set_guest_wifi_state(self, state: bool) -> None:
        """Set the state of the guest Wi-Fi.

        The radios object is a required parameter for the API call but isn't handled in this method.
        Instead, a call is made to retrieve the existing settings and those are relayed back.  This assumes that
        a guest network has been created in the official UI.

        :param state: True to enable, False to disable

        :return: None
        """
        _LOGGER.debug(self._log_formatter.format("entered, state: %s"), state)

        # get the current radio settings from the API; they may have changed
        resp = await self._async_gather_details([MeshCapability.GET_GUEST_NETWORK_INFO])
        radios = resp.get("radios", [])

        payload = {
            "isGuestNetworkEnabled": state,
            "radios": radios,
        }
        await self._async_make_request(
            action=api.Actions.SET_GUEST_NETWORK, payload=payload
        )

        _LOGGER.debug(self._log_formatter.format("exited"))

    async def async_set_homekit_state(self, state: bool) -> None:
        """Set the state of the HomeKit feature.

        :param state: True to enable, False to disable

        :return: None
        """
        _LOGGER.debug(self._log_formatter.format("entered, state: %s"), state)
        await self._async_make_request(
            action=api.Actions.SET_HOMEKIT_SETTINGS, payload={"isEnabled": state}
        )
        _LOGGER.debug(self._log_formatter.format("exited"))

    @deprecated(
        solution="Use the async_set_parental_control_rules method on the Device object."
    )
    async def async_set_parental_control_rules(
        self, device_id: str, rules: dict[str, str], force_enable: bool = False
    ) -> None:
        """Set the parental control schedule for the given device.

        :param device_id: The unique identifier for the device
        :param rules: A dictionary of time string pairs in the form: `"monday": "00:00-02:00,17:30:18:00"`
        :param force_enable: True to enable Parental Control, False to leave in current state

        :return: None
        """
        _LOGGER.debug(
            self._log_formatter.format("entered, device_id: %s, rules: %s"),
            device_id,
            rules,
        )

        current_schedule: dict[str, str] = {}

        # region #-- get the device details --#
        device: list[DeviceEntity | Node] = await self.async_get_device_from_id(
            device_id=[device_id],
        )
        device_mac: str = device[0].adapter_info[0].get("mac")
        if device_mac is None:
            raise MeshException("No MAC available")
        # endregion

        # -- get the current rules as they may have changed --#
        current_parental_control_info: dict[int | str, Any] = (
            await self._async_gather_details([MeshCapability.GET_PARENTAL_CONTROL_INFO])
        )
        current_parental_control_info = current_parental_control_info.get(
            MeshCapability.GET_PARENTAL_CONTROL_INFO.value, {}
        )

        # region #-- determine the rules --#
        keep_rules: list[dict[str, Any]] = [
            rule
            for rule in current_parental_control_info.get("rules", [])
            if device_mac.upper() not in rule.get("macAddresses", [])
        ]
        this_device_rules: list[dict[str, Any]] = [
            rule
            for rule in current_parental_control_info.get("rules", [])
            if device_mac.upper() in rule.get("macAddresses", [])
        ]
        new_rule = ParentalControl.human_readable_to_binary(to_encode=rules)
        if this_device_rules:  # already has rules
            current_schedule = this_device_rules[0]["wanSchedule"]

        cached_schedule: dict[str, str] = getattr(device[0], "_get_user_property")(
            DeviceProperty.ACTUAL_WAN_SCHEDULE
        )

        if new_rule != ParentalControl.ALL_ALLOWED_SCHEDULE():
            _LOGGER.debug(self._log_formatter.format("Adding new rules"))
            if this_device_rules:
                this_device_rules[0]["wanSchedule"] = new_rule
            else:
                this_device_rules.append(
                    ParentalControl.create_rule(
                        mac_address=device_mac,
                        schedule=new_rule,
                        schedule_to_binary=False,
                    )
                )
        else:
            if cached_schedule:
                _LOGGER.debug(
                    self._log_formatter.format("Restoring backed up schedule")
                )
                new_rule = ParentalControl.backup_to_binary(schedule=cached_schedule)
                this_device_rules[0]["wanSchedule"] = new_rule
            else:
                if len(this_device_rules) > 0 and this_device_rules[0].get(
                    "blockedURLs", []
                ):
                    _LOGGER.debug(
                        self._log_formatter.format(
                            "Blocked URLs found, applying permissive rule"
                        )
                    )
                    this_device_rules[0]["wanSchedule"] = new_rule
                else:
                    _LOGGER.debug(self._log_formatter.format("Removing from rules"))
                    this_device_rules = []
        # endregion

        requests: list = [  # build a list of requests to send
            self._async_make_request(
                action=api.Actions.SET_PARENTAL_CONTROL_INFO,
                payload={
                    "isParentalControlEnabled": (
                        True
                        if force_enable
                        else current_parental_control_info.get(
                            "isParentalControlEnabled", True
                        )
                    ),
                    "rules": keep_rules + this_device_rules,
                },
            )
        ]

        # region #-- calculate the device properties to update --#
        device_properties: dict[str, list[str, dict[str, str]]] = (
            _get_parental_control_device_attributes(
                schedule=new_rule,
                urls=(
                    this_device_rules[0].get("blockedURLs", [])
                    if this_device_rules
                    else []
                ),
            )
        )
        if new_rule == ParentalControl.ALL_PAUSED_SCHEDULE():
            if current_schedule:
                device_properties["modify"].append(
                    {
                        "name": DeviceProperty.ACTUAL_WAN_SCHEDULE.value,
                        "value": ParentalControl.encode_for_backup(
                            schedule=current_schedule
                        ),
                    }
                )
        else:
            if cached_schedule:
                device_properties["remove"].append(
                    DeviceProperty.ACTUAL_WAN_SCHEDULE.value
                )

        if device_properties["modify"]:
            requests.append(
                self._async_make_request(
                    action=api.Actions.SET_DEVICE_PROPERTY,
                    payload={
                        "deviceID": device_id,
                        "propertiesToModify": device_properties["modify"],
                    },
                )
            )
        if device_properties["remove"]:
            requests.append(
                self._async_make_request(
                    action=api.Actions.SET_DEVICE_PROPERTY,
                    payload={
                        "deviceID": device_id,
                        "propertiesToRemove": device_properties["remove"],
                    },
                )
            )
        # endregion

        await asyncio.gather(*requests)

        _LOGGER.debug(self._log_formatter.format("exited"))

    @deprecated(
        solution="Use the async_set_parental_control_urls method on the Device object."
    )
    async def async_set_parental_control_urls(
        self,
        device_id: str,
        urls: list[str],
        force_enable: bool = False,
        merge: bool = True,
    ) -> None:
        """Set the URLs for Parental Control.

        :param device_id: The unique identifier for the device
        :param urls: List of the URLs to add
        :param force_enable: True to enable the rule if it isn't enabled
        :param merge: True to merge with existing URLs, False to replace

        :return: None
        """
        _LOGGER.debug(
            self._log_formatter.format(
                "entered, device_id: %s, urls: %s, force_enable: %s, merge: %s"
            ),
            device_id,
            urls,
            force_enable,
            merge,
        )

        # region #-- get the device details --#
        device: list[DeviceEntity | Node] = await self.async_get_device_from_id(
            device_id=[device_id],
        )
        device_mac: str = device[0].adapter_info[0].get("mac")
        if device_mac is None:
            raise MeshException("No MAC available")
        # endregion

        # -- get the current rules as they may have changed --#
        current_parental_control_info: dict[int | str, Any] = (
            await self._async_gather_details([MeshCapability.GET_PARENTAL_CONTROL_INFO])
        )
        current_parental_control_info = current_parental_control_info.get(
            MeshCapability.GET_PARENTAL_CONTROL_INFO.value, {}
        )

        # region #-- determine the rules --#
        keep_rules: list[dict[str, Any]] = [
            rule
            for rule in current_parental_control_info.get("rules", [])
            if device_mac.upper() not in rule.get("macAddresses", [])
        ]
        this_device_rules: list[dict[str, Any]] = [
            rule
            for rule in current_parental_control_info.get("rules", [])
            if device_mac.upper() in rule.get("macAddresses", [])
        ]
        if not this_device_rules:  # no existing rules so create all permissive
            this_device_rules.append(
                ParentalControl.create_rule(
                    blocked_urls=list(set(urls)),
                    mac_address=device_mac,
                    schedule=ParentalControl.ALL_ALLOWED_SCHEDULE(),
                    schedule_to_binary=False,
                )
            )
        else:
            if merge:
                this_device_rules[0]["blockedURLs"].extend(urls)
            else:
                this_device_rules[0]["blockedURLs"] = urls
            this_device_rules[0]["blockedURLs"] = list(
                set(this_device_rules[0]["blockedURLs"])
            )
        # endregion

        # region #-- build a list of requests to send --#
        device_properties: dict[str, list[str | dict[str, str]]] = (
            _get_parental_control_device_attributes(
                schedule=this_device_rules[0].get("wanSchedule", {}), urls=urls
            )
        )

        requests: list = [
            self._async_make_request(
                action=api.Actions.SET_PARENTAL_CONTROL_INFO,
                payload={
                    "isParentalControlEnabled": (
                        True
                        if force_enable
                        else current_parental_control_info.get(
                            "isParentalControlEnabled", True
                        )
                    ),
                    "rules": keep_rules
                    + (
                        this_device_rules
                        if DeviceProperty.SHOW_IN_PC_LIST.value
                        not in device_properties["remove"]
                        else []
                    ),
                },
            )
        ]

        if device_properties["modify"]:
            requests.append(
                self._async_make_request(
                    action=api.Actions.SET_DEVICE_PROPERTY,
                    payload={
                        "deviceID": device_id,
                        "propertiesToModify": device_properties["modify"],
                    },
                )
            )
        if device_properties["remove"]:
            requests.append(
                self._async_make_request(
                    action=api.Actions.SET_DEVICE_PROPERTY,
                    payload={
                        "deviceID": device_id,
                        "propertiesToRemove": device_properties["remove"],
                    },
                )
            )

        # endregion

        await asyncio.gather(*requests)

        _LOGGER.debug(self._log_formatter.format("exited"))

    async def async_set_parental_control_state(self, state: bool) -> None:
        """Set the state of the Parental Control feature. Rules are left intact.

        :param state: True to enabled, False to disable

        :return: None
        """
        _LOGGER.debug(self._log_formatter.format("entered, state: %s"), state)
        # get the current rules from the API because they may be different
        resp = await self._async_gather_details(
            [MeshCapability.GET_PARENTAL_CONTROL_INFO]
        )
        rules = resp.get("rules", [])

        payload = {
            "isParentalControlEnabled": state,
            "rules": rules,
        }
        await self._async_make_request(
            action=api.Actions.SET_PARENTAL_CONTROL_INFO, payload=payload
        )

        _LOGGER.debug(self._log_formatter.format("exited"))

    async def async_set_upnp_settings(
        self, enabled: bool, allow_change_settings: bool, allow_disable_internet: bool
    ) -> None:
        """Set the UPnP settings.

        :param enabled: True to enable UPnP, False to disable.
        :param allow_change_settings: Whether users can change settings when UPnP is enabled.
        :param allow_disable_internet: Whether users can disable the Internet when UPnP is enabled.

        :return: None
        """
        _LOGGER.debug(
            self._log_formatter.format(
                "entered, enabled: %s, allow_change_settings: %s, allow_disable_internet: %s"
            ),
            enabled,
            allow_change_settings,
            allow_disable_internet,
        )
        payload = {
            "isUPnPEnabled": enabled,
            "canUsersConfigure": allow_change_settings,
            "canUsersDisableWANAccess": allow_disable_internet,
        }
        await self._async_make_request(
            action=api.Actions.SET_UPNP_SETTINGS, payload=payload
        )
        _LOGGER.debug(self._log_formatter.format("exited"))

    async def async_set_wps_state(self, state: bool) -> None:
        """Set the state of the WPS feature.

        :param state: True to enable, False to disable

        :return: None
        """
        _LOGGER.debug(self._log_formatter.format("entered, state: %s"), state)
        await self._async_make_request(
            action=api.Actions.SET_WPS_SERVER_SETTINGS, payload={"enabled": state}
        )
        _LOGGER.debug(self._log_formatter.format("exited"))

    async def async_start_channel_scan(self) -> None:
        """Start a channel scan on the mesh.

        :return: None
        """
        _LOGGER.debug(self._log_formatter.format("entered"))

        try:
            await self._async_make_request(action=api.Actions.START_CHANNEL_SCAN)
        except MeshAlreadyInProgress as err:
            _LOGGER.debug(
                self._log_formatter.format("%s"),
                err,
            )
        except MeshInvalidInput as err:
            _LOGGER.warning(
                self._log_formatter.format(
                    "%s - are you sure the functionality is available"
                ),
                err,
            )

        _LOGGER.debug(self._log_formatter.format("exited"))

    async def async_start_speedtest(self) -> None:
        """Instruct the mesh to carry out a Speedtest.

        A Speedtest is a long-running task.  You should use the async_get_speedtest_state method to understand
        the progress of the task.

        :return: None
        """
        _LOGGER.debug(self._log_formatter.format("entered"))

        payload = {"runHealthCheckModule": "SpeedTest"}
        await self._async_make_request(
            action=api.Actions.START_SPEEDTEST, payload=payload
        )

        _LOGGER.debug(self._log_formatter.format("exited"))

    async def async_test_credentials(self) -> bool:
        """Check the provided credentials are valid.

        :return: True if valid, False if not
        """
        _LOGGER.debug(self._log_formatter.format("entered"))

        ret: bool = False
        try:
            await self._async_make_request(action=api.Actions.CHECK_PASSWORD)
            ret = True
        except MeshInvalidCredentials:
            pass
        except MeshException as err:
            _LOGGER.error(err)
            raise
        except Exception as err:
            _LOGGER.error(err)
            raise

        _LOGGER.debug(self._log_formatter.format("exited"))
        return ret

    # endregion

    # region #-- properties --#
    @property
    @needs_initialise
    def capabilities(self) -> list[MeshCapability]:
        """Get the list of capabilities that the Mesh supports.

        :return: list of mesh capabilities
        """
        return self._mesh_capabilities

    @property
    @needs_initialise
    def check_for_update_status(self) -> bool:
        """Get the state of checking for an update as at the last time details were gathered.

        If you need the live state then use the async_get_update_state to re-query the API.

        :return: True if checking
        """
        node_results = self._mesh_attributes.get(
            MeshCapability.GET_UPDATE_FIRMWARE_STATE.value, {}
        ).get("firmwareUpdateStatus", [])
        all_states = ["pendingOperation" in node for node in node_results]
        ret = any(all_states)

        return ret

    @property
    @needs_initialise
    def client_steering_enabled(self) -> bool | None:
        """Return if client steering is enabled.

        :return: True if enabled, False otherwise.
        """
        return self._mesh_attributes.get(
            MeshCapability.GET_TOPOLOGY_OPTIMISATION_SETTINGS.value, {}
        ).get("isClientSteeringEnabled")

    @property
    def connected_node(self) -> str:
        """Get the node in the mesh that we are connected to.

        :return: A string containing the node IP address
        """
        return self._mesh_details.host

    @property
    @needs_initialise
    def devices(self) -> list[DeviceEntity]:
        """Get the devices in the mesh.

        The list will be returned in alphabetical order based on the device name.
        N.B. this will not include the nodes.

        :return: A list containing Device objects
        """
        ret: list[DeviceEntity] = [
            device
            for device in self._mesh_attributes.get(_ATTR_PROCESSED_DEVICES, [])
            if isinstance(device, DeviceEntity)
        ]
        ret = sorted(ret, key=lambda device: device.name)
        return ret

    @property
    @needs_initialise
    def dhcp_enabled(self) -> bool | None:
        """Return if DHCP is enabled.

        :return: True if enabled, False otherwise
        """
        return self._mesh_attributes.get(MeshCapability.GET_LAN_SETTINGS.value, {}).get(
            "isDHCPEnabled"
        )

    @property
    @needs_initialise
    def dhcp_reservations(self) -> list[dict[str, str]]:
        """Return the DHCP reservations.

        :return: list of DHCP reservation details
        """
        ret: list[dict[str, str]] = []
        temp_dict: dict[str, str] = {}

        for reservation in (
            self._mesh_attributes.get(MeshCapability.GET_LAN_SETTINGS.value, {})
            .get("dhcpSettings", {})
            .get("reservations", [])
        ):
            temp_dict = {}
            for key, details in reservation.items():
                temp_dict[camel_to_snake(key)] = details
            ret.append(temp_dict)

        return ret

    @property
    @needs_initialise
    def express_forwarding_enabled(self) -> bool | None:
        """Return whether Express Forwarding is enabled.

        :return: True if enabled, False otherwise
        """
        return self._mesh_attributes.get(
            MeshCapability.GET_EXPRESS_FORWARDING.value, {}
        ).get("isExpressForwardingEnabled")

    @property
    @needs_initialise
    def express_forwarding_supported(self) -> bool | None:
        """Return whether Express Forwarding is supported.

        :return: True if enabled, False otherwise
        """
        return self._mesh_attributes.get(
            MeshCapability.GET_EXPRESS_FORWARDING.value, {}
        ).get("isExpressForwardingSupported")

    @property
    @needs_initialise
    def firmware_update_setting(self) -> str | None:
        """Get the current setting for firmware updates.

        :return: a lowercase string representing the update method
        """
        return (
            self._mesh_attributes.get(
                MeshCapability.GET_FIRMWARE_UPDATE_SETTINGS.value, {}
            )
            .get("updatePolicy", "")
            .lower()
            or None
        )

    @property
    @needs_initialise
    def guest_wifi_enabled(self) -> bool | None:
        """Get the state of the guest Wi-Fi.

        :return: True if enabled
        """
        return self._mesh_attributes.get(
            MeshCapability.GET_GUEST_NETWORK_INFO.value, {}
        ).get("isGuestNetworkEnabled")

    @property
    @needs_initialise
    def guest_wifi_details(self) -> list[dict[str, str]]:
        """Get the guest network Wi-Fi details.

        :return: A list of dictionaries containing the SSID and band for the networks
        """
        ret = [
            {
                "ssid": radio.get("guestSSID"),
                "band": radio.get("radioID").split("_")[-1],
            }
            for _, radio in enumerate(
                self._mesh_attributes.get(
                    MeshCapability.GET_GUEST_NETWORK_INFO.value, {}
                ).get("radios", [])
            )
        ]
        return ret

    @property
    @needs_initialise
    def homekit_enabled(self) -> bool | None:
        """Return if the HomeKit integration is enabled.

        :return: True if enabled, False otherwise
        """
        return self._mesh_attributes.get(
            MeshCapability.GET_HOMEKIT_SETTINGS.value, {}
        ).get("isEnabled")

    @property
    @needs_initialise
    def homekit_paired(self) -> bool | None:
        """Return if the HomeKit integration is paired.

        :return: True if enabled, False otherwise
        """
        return self._mesh_attributes.get(
            MeshCapability.GET_HOMEKIT_SETTINGS.value, {}
        ).get("isPaired")

    @property
    @needs_initialise
    def is_channel_scan_running(self) -> bool | None:
        """Get the current state of channel scanning.

        :return: True if enabled, False otherwise
        """
        return self._mesh_attributes.get(
            MeshCapability.GET_CHANNEL_SCAN_STATUS.value, {}
        ).get("isRunning")

    @property
    @needs_initialise
    def latest_speedtest_result(self) -> dict | None:
        """Get the Speedtest results.

        N.B. If you need more results see the async_get_speedtest_results method

        :return: the Speedtest results
        """
        ret = _process_speedtest_results(
            speedtest_results=self._mesh_attributes.get(
                MeshCapability.GET_SPEEDTEST_RESULTS.value, {}
            ).get("healthCheckResults", []),
            only_completed=True,
            only_latest=True,
        )
        if ret:
            ret = ret[0]

        return ret or None

    @property
    @needs_initialise
    def mac_filtering_addresses(self) -> list[str]:
        """Get addresses that are configured for MAC filtering.

        :return: list of MAC addresses
        """
        return self._mesh_attributes.get(
            MeshCapability.GET_MAC_FILTERING_SETTINGS.value, {}
        ).get("macAddresses", [])

    @property
    @needs_initialise
    def mac_filtering_enabled(self) -> bool:
        """Return if MAC filtering is enabled.

        :return: True if enabled, False otherwise
        """
        return (
            self._mesh_attributes.get(
                MeshCapability.GET_MAC_FILTERING_SETTINGS.value, {}
            )
            .get("macFilterMode", "")
            .lower()
            != "disabled"
        )

    @property
    @needs_initialise
    def mac_filtering_mode(self) -> str | None:
        """Return the MAC filtering mode.

        :return: string containing the filtering mode
        """
        if self.mac_filtering_enabled:
            return (
                self._mesh_attributes.get(
                    MeshCapability.GET_MAC_FILTERING_SETTINGS.value, {}
                )
                .get("macFilterMode", "")
                .lower()
            )

        return None

    @property
    @needs_initialise
    def node_steering_enabled(self) -> bool | None:
        """Return if node steering is enabled.

        :return: True if enabled, False otherwise
        """
        return self._mesh_attributes.get(
            MeshCapability.GET_TOPOLOGY_OPTIMISATION_SETTINGS.value, {}
        ).get("isNodeSteeringEnabled")

    @property
    @needs_initialise
    def nodes(self) -> list[Node]:
        """Get the nodes in the mesh.

        The return is sorted in alphabetical order based on node name.

        :return: A list of Node objects
        """
        ret: list = [
            node
            for node in self._mesh_attributes.get(_ATTR_PROCESSED_DEVICES, [])
            if isinstance(node, Node)
        ]

        ret = sorted(ret, key=lambda node: node.name)
        return ret

    @property
    @needs_initialise
    def parental_control_enabled(self) -> bool | None:
        """Get the state of the Parental Control feature.

        :return: True if enabled, False otherwise
        """
        return self._mesh_attributes.get(
            MeshCapability.GET_PARENTAL_CONTROL_INFO.value, {}
        ).get("isParentalControlEnabled")

    @property
    @needs_initialise
    def sip_enabled(self) -> bool | None:
        """Return whether SIP is enabled.

        :return: True if enabled, False otherwise
        """
        return self._mesh_attributes.get(MeshCapability.GET_ALG_SETTINGS.value, {}).get(
            "isSIPEnabled"
        )

    @property
    @needs_initialise
    def speedtest_status(self) -> str:
        """Return the current status of the Speedtest.

        :return: Textual representation of the Speedtest state
        """
        ret = _get_speedtest_state(
            speedtest_results=self._mesh_attributes.get(
                MeshCapability.GET_SPEEDTEST_STATUS.value, {}
            ).get("speedTestResult", {})
        )

        return ret

    @property
    @needs_initialise
    def storage_available(self) -> list:
        """Get available shared partitions.

        :return: List of the available storage devices and their properties
        """
        ret: list = []
        node: list[Node]
        device: dict
        storage_available = self._mesh_attributes.get(
            MeshCapability.GET_STORAGE_PARTITIONS.value, {}
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
                        used_percent: int | None = None
                        with contextlib.suppress(ZeroDivisionError):
                            used_percent = round(
                                (partition.get("usedKB") / partition.get("availableKB"))
                                * 100,
                                2,
                            )
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
    @needs_initialise
    def storage_settings(self) -> dict:
        """Get the settings for shared partitions.

        :return: dictionary of the storage settings
        """
        ret = self._mesh_attributes.get(MeshCapability.GET_STORAGE_SMB_SERVER.value, {})
        if ret:
            ret = {"anonymous_access": ret.get("isAnonymousAccessEnabled")}

        return ret

    @property
    def timeout(self) -> float:
        """Get the timeout for API requests.

        :return: the current timeout applied to requests
        """

        return self._mesh_details.request_timeout

    @timeout.setter
    def timeout(self, value: float) -> None:
        """Set the timeout for API requests.

        :param value: value to set for the timeout

        :return: None
        """

        _LOGGER.debug(
            self._log_formatter.format("setting request timeout to: %ss"), value
        )
        self._mesh_details.request_timeout = value

    @property
    @needs_initialise
    def upnp_enabled(self) -> bool | None:
        """Return whether UPnP is enabled.

        :return: True if enabled, False otherwise
        """
        return self._mesh_attributes.get(
            MeshCapability.GET_UPNP_SETTINGS.value, {}
        ).get("isUPnPEnabled")

    @property
    @needs_initialise
    def upnp_allow_change_settings(self) -> bool | None:
        """Return whether users can change settings when UPnP is enabled.

        :return: True if enabled, False otherwise
        """
        return self._mesh_attributes.get(
            MeshCapability.GET_UPNP_SETTINGS.value, {}
        ).get("canUsersConfigure")

    @property
    @needs_initialise
    def upnp_allow_disable_internet(self) -> bool | None:
        """Return whether users can change disable the Internet when UPnP is enabled.

        :return: True if enabled, False otherwise
        """
        return self._mesh_attributes.get(
            MeshCapability.GET_UPNP_SETTINGS.value, {}
        ).get("canUsersDisableWANAccess")

    @property
    @needs_initialise
    def wan_dns(self) -> list:
        """Get the WAN DNS servers.

        :return: A list containing the IP addresses of the WAN DNS servers
        """
        ret = [
            val
            for key, val in self._mesh_attributes.get(
                MeshCapability.GET_WAN_INFO.value, {}
            )
            .get("wanConnection", {})
            .items()
            if key.startswith("dnsServer")
        ]

        return ret

    @property
    @needs_initialise
    def wan_ip(self) -> str | None:
        """Get the WAN IP address.

        :return: A string containing the IP address for the WAN
        """
        return (
            self._mesh_attributes.get(MeshCapability.GET_WAN_INFO.value, {})
            .get("wanConnection", {})
            .get("ipAddress")
        )

    @property
    @needs_initialise
    def wan_mac(self) -> str | None:
        """Get the WAN MAC.

        :return: A string containing the MAC address for the WAN adapter
        """
        return self._mesh_attributes.get(MeshCapability.GET_WAN_INFO.value, {}).get(
            "macAddress", ""
        )

    @property
    @needs_initialise
    def wan_status(self) -> bool:
        """Get the status of the WAN.

        :return: True if connected, False if not
        """
        return (
            self._mesh_attributes.get(MeshCapability.GET_WAN_INFO.value, {})
            .get("wanStatus", "")
            .lower()
            == "connected"
        )

    @property
    @needs_initialise
    def wps_state(self) -> bool:
        """Return if WPS is enabled or not.

        :return: True if enabled, False otherwise
        """
        return self._mesh_attributes.get(
            MeshCapability.GET_WPS_SERVER_SETTINGS.value, {}
        ).get("enabled", False)

    # endregion
