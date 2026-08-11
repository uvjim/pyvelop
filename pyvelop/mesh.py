"""Representation of the mesh."""

# region #-- imports --#
from __future__ import annotations

import asyncio
import contextlib
import datetime as dt
import functools
import logging
import re
import time
import uuid
from collections.abc import Coroutine
from dataclasses import asdict, dataclass, field
from enum import StrEnum, auto
from types import MappingProxyType
from typing import Any, cast

from aiohttp import ClientSession

from . import __version__, camel_to_snake
from . import jnap as api
from .exceptions import (
    MeshAlreadyInProgress,
    MeshDeviceNotFoundResponse,
    MeshException,
    MeshInvalidArguments,
    MeshInvalidCredentials,
    MeshInvalidInput,
    MeshNeedsInitialise,
)
from .mesh_entity import (
    AdapterInfo,
    DeviceEntity,
    EntityDataProperties,
    NodeEntity,
    NodeType,
)

# endregion

type _ApiResponse = tuple[api.Request, api.Response]

_ATTR_PROCESSED_DEVICES: str = "processed_devices"
_LOGGER = logging.getLogger(__name__)
_LOGGER_VERBOSE = logging.getLogger(f"{__name__}.verbose")


class MeshCapability(StrEnum):
    """The possible capabilities available to the Mesh."""

    GET_ALG_SETTINGS = "alg_settings"
    GET_BACKHAUL = "backhaul"
    GET_CHANNEL_SCAN_STATUS = "channel_scan_status"
    GET_DEVICES = "devices"
    GET_EXPRESS_FORWARDING = "express_forwarding"
    GET_GUEST_NETWORK_INFO = "guest_network_info"
    GET_HOMEKIT_SETTINGS = "homekit_settings"
    GET_LAN_SETTINGS = "lan_setting"
    GET_LED_NIGHT_MODE = "led_night_mode"
    GET_MAC_FILTERING_SETTINGS = "mac_filtering_settings"
    GET_MLO_SETTINGS = "mlo_settings"
    GET_NODE_WIRELESS_CONNECTIONS = "node_wireless_connections"
    GET_PARENTAL_CONTROL_INFO = "parental_control_info"
    GET_SCHEDULED_REBOOT_SETTINGS = "scheduled_reboot_settings"
    GET_SPEEDTEST_RESULTS = "speedtest_results"
    GET_SPEEDTEST_STATUS = "speedtest_status"
    GET_SPEEDTEST_TYPES = "speedtest_types"
    GET_STORAGE_PARTITIONS = "storage_partitions"
    GET_STORAGE_SMB_SERVER = "storage_smb_server"
    GET_TOPOLOGY_OPTIMISATION_SETTINGS = "topology_optimisation_settings"
    GET_UPDATE_FIRMWARE_STATE = "update_firmware_state"
    GET_UPDATE_SETTINGS = "firmware_update_settings"
    GET_UPNP_SETTINGS = "upnp_settings"
    GET_WAN_INFO = "wan_info"
    GET_WPS_SERVER_SETTINGS = "wps_server_settings"


class NightModeState(StrEnum):
    """Possible states for the night mode functionality."""

    ALWAYS = auto()
    NIGHT_MODE = auto()
    OFF = auto()


class ScheduledRebootInterval(StrEnum):
    """Representation of the available scheduled reboot intervals."""

    MONTHLY = "Monthly"
    WEEKLY = "Weekly"


class SpeedtestExitCode(StrEnum):
    """Possible exit codes for speedtest."""

    EXCECUTION_ERROR = "SpeedTestExecutionError"
    SUCCESS = "Success"
    UNAVAILABLE = "Unavailable"


class SpeedtestStatus(StrEnum):
    """Possible Speedtest statuses."""

    CHECKING_DOWNLOAD_SPEED = auto()
    CHECKING_LATENCY = auto()
    CHECKING_UPLOAD_SPEED = auto()
    DETECTING_SERVER = auto()
    FINISHED = auto()
    NOT_RUNNING = auto()
    UNKNOWN = auto()


@dataclass(slots=True)
class MeshDetails:
    """Details of the mesh being connected to."""

    host: str
    password: str
    request_timeout: float
    session: ClientSession
    user: str

    def __repr__(self) -> str:
        """Friendly string representation of the class."""
        return f"{self.__class__.__name__}: {self.host}"


@dataclass(frozen=True, slots=True)
class SpeedtestResult:
    """Representation of the results of a speedtest."""

    timestamp: dt.datetime
    download_bandwidth: int
    exit_code: SpeedtestExitCode
    friendly_status: SpeedtestStatus = field(init=False)
    latency: int
    result_id: int
    server_id: str
    upload_bandwidth: int

    def __post_init__(self):
        """Derive a friendly status from the available results."""

        _friendly_status: SpeedtestStatus = SpeedtestStatus.UNKNOWN
        if self.exit_code == SpeedtestExitCode.SUCCESS:
            _friendly_status = SpeedtestStatus.NOT_RUNNING
        elif self.server_id == "0":
            _friendly_status = SpeedtestStatus.DETECTING_SERVER
        elif self.latency == 0:
            _friendly_status = SpeedtestStatus.CHECKING_LATENCY
        elif self.download_bandwidth == 0:
            _friendly_status = SpeedtestStatus.CHECKING_DOWNLOAD_SPEED
        elif self.upload_bandwidth == 0:
            _friendly_status = SpeedtestStatus.CHECKING_UPLOAD_SPEED

        object.__setattr__(self, "friendly_status", _friendly_status)

    def as_dict(self) -> dict[str, Any]:
        """Representation of the class."""

        ret: dict[str, Any] = asdict(self)
        return ret


def needs_initialise(func: Any) -> Any:
    """Ensure that async_initialise has been executed."""

    def wrapper(self: Mesh, *args: Any, **kwargs: Any) -> Any:
        """Wrap the required function."""
        if not self.has_initialised:
            raise MeshNeedsInitialise from None
        return func(self, *args, **kwargs)

    wrapped = functools.wraps(func)(wrapper)
    return wrapped


FeatureCapabilities: MappingProxyType[str, set[MeshCapability]] = MappingProxyType(
    {
        "devices": {
            MeshCapability.GET_DEVICES,
            MeshCapability.GET_LAN_SETTINGS,
            MeshCapability.GET_NODE_WIRELESS_CONNECTIONS,
            MeshCapability.GET_PARENTAL_CONTROL_INFO,
        },
        "parental_control": {
            MeshCapability.GET_PARENTAL_CONTROL_INFO,
        },
        "speedtest": {
            MeshCapability.GET_SPEEDTEST_RESULTS,
            MeshCapability.GET_SPEEDTEST_STATUS,
        },
    }
)


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
        *,
        username: str = "admin",
        disable_redaction: bool = False,
        supplementary_redactions: dict[str, set[str]] | None = None,
    ) -> None:
        """Initialise the Mesh.

        :param node: The node we should make a connection to
        :param password: password to use
        :param request_timeout: number of seconds to time out the request; default 10s
        :param session: session to use in for interacting with the Mesh
        :param username: username to use; default admin
        """

        self._disable_redaction: bool = disable_redaction
        # flag used to denote that initialise has been executed
        self._initialise_executed: bool = False
        self._last_gather_details: dict[str, float | None] = {
            "gather_end": None,
            "gather_start": None,
            "process_end": None,
            "process_start": None,
        }
        self._mesh_attributes: dict[str, list[DeviceEntity] | list[NodeEntity] | api.JnapResponse] = {}
        _session: ClientSession = session if session is not None else self.__create_session()
        self._mesh_details: MeshDetails = MeshDetails(
            host=node,
            password=password,
            request_timeout=request_timeout,
            session=_session,
            user=username,
        )
        self._mesh_capabilities: list[MeshCapability] = []
        self._supplementary_redactions: dict[str, set[str]] | None = supplementary_redactions
        self.__passed_session: bool = isinstance(session, ClientSession)

        _LOGGER.debug(
            "session was passed in: %s",
            "yes" if self.__passed_session else "no",
        )

        _LOGGER.debug(
            "%s version: %s",
            __package__,
            __version__,
        )
        _LOGGER.debug(
            "initialised mesh for %s with request timeout %ss",
            self._mesh_details.host,
            self._mesh_details.request_timeout,
        )

    async def __aenter__(self) -> Mesh:
        """Asynchronous enter magic method."""
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: Any,
    ) -> None:
        """Asynchronous exit magic method."""
        await self.async_close()

    def __repr__(self) -> str:
        """Friendly string representation of the class.

        :return: Uses the class name and the node we're connected to for the representation
        """
        return f"{self.__class__.__name__}: {self._mesh_details.host}"

    def __create_session(self) -> ClientSession:
        """Initialise a session and ensure that errors are raised based on the HTTP status codes.

        :return: None
        """
        session = ClientSession(raise_for_status=True)
        return session

    def _process_speedtest_results(self, results: dict[str, Any]) -> SpeedtestResult:
        """Build a SpeedtestResult object from the provisded results."""

        if "speedTestResult" not in results:
            raise ValueError

        result_set: dict[str, Any] | None = results.get("speedTestResult")
        props: dict[str, Any] = {}
        if result_set is not None:
            props = {
                "download_bandwidth": result_set.get("downloadBandwidth"),
                "exit_code": SpeedtestExitCode(result_set.get("exitCode")),
                "latency": result_set.get("latency"),
                "result_id": result_set.get("resultID"),
                "server_id": result_set.get("serverID"),
                "timestamp": (
                    dt.datetime.fromisoformat(results.get("timestamp", ""))
                    if results.get("timestamp") is not None
                    else dt.datetime.min
                ),
                "upload_bandwidth": result_set.get("uploadBandwidth"),
            }

        return SpeedtestResult(**props)

    async def _async_make_request(
        self,
        action: str,
        *,
        node_address: str | None = None,
        payload: list[dict[str, Any]] | dict[str, Any] | None = None,
        raise_on_error: bool = True,
    ) -> _ApiResponse:
        """Execute the API request against the connected node.

        :param action: The JNAP action to execute
        :param node_address: The node to send the request to (only valid for a subset of actions)
        :param payload: The relevant payload for the action
        :param raise_on_error: Raise an error if one is found

        :return: tuple containing the request and response objects or raises an error if need be
        """
        if node_address is not None and action != api.Actions.REBOOT:
            raise MeshInvalidArguments

        if payload is None:
            payload = []

        if not self.__passed_session and self._mesh_details.session.closed:  # session closed so recreate it
            self._mesh_details.session = self.__create_session()

        req = api.Request(
            action=action if not isinstance(action, api.Actions) else action.value,
            password=self._mesh_details.password,
            payload=payload,
            raise_on_error=raise_on_error,
            session=self._mesh_details.session,
            target=node_address or self._mesh_details.host,
            username=self._mesh_details.user,
            redact=self._disable_redaction is False,
            supplementary_redactions=self._supplementary_redactions,
        )
        try:
            req_resp = await req.execute(timeout=self._mesh_details.request_timeout)
        except Exception as err:
            raise err from None

        return (req, req_resp)

    async def _async_gather_details(  # noqa: C901
        self,
        capabilities: list[MeshCapability],
        *,
        track_time: bool = False,
    ) -> dict[str, Any]:
        """Work is done here to gather the necessary details for mesh.

        :return: A dictionary containing the relevant details.
        """

        ret: dict[str, Any] = {}
        payload: list[dict[str, Any]] = []

        # region #-- establish available capabilities for the requests --#
        for capability in capabilities:
            jnap_action: api.Actions = api.Actions[capability.name]
            payload.append(
                {
                    "action": jnap_action.value,
                    "request": api.Defaults.get(jnap_action.name, {}),
                }
            )
        # endregion

        if track_time:
            self._last_gather_details.update({"gather_start": time.time()})

        responses: tuple[_ApiResponse, ...] = await asyncio.gather(
            self._async_make_request(api.Actions.TRANSACTION, payload=payload)
        )

        if track_time:
            self._last_gather_details.update({"gather_end": time.time()})
            self._last_gather_details.update({"process_start": time.time()})

        # region #-- prepare all the raw details --#
        def _set_raw_value(action: str, data: api.JnapResponse | None) -> None:
            """Set the raw values."""
            try:
                api_response: api.Response = api.Response(action=action, data=data)
            except MeshException as err:
                _LOGGER.debug("%s", err)
            else:
                capability: MeshCapability = MeshCapability[api.Actions(action).name]
                ret[capability.value] = api_response.data

        for response in responses:
            req, resp = response
            if req.action == api.Actions.TRANSACTION:
                if resp.data is not None and isinstance(resp.data, list):
                    for idx, action_response in enumerate(resp.data):
                        if isinstance(req.payload, list):
                            _set_raw_value(
                                action=req.payload[idx].get("action", ""),
                                data=action_response,
                            )
            else:
                _set_raw_value(action=req.action, data=getattr(resp, "_data", {}))
        # endregion

        # region #-- handle mesh entities --#
        mesh_entities: list[DeviceEntity | NodeEntity] = []
        discovered_mesh_entities: list[dict[str, Any]] = cast(
            list[dict[str, Any]],
            ret.get(MeshCapability.GET_DEVICES.value, {}).get("devices", []),
        )
        # region #-- build the properties for the mesh entity types --#
        for entity in discovered_mesh_entities:
            entity_data: dict[str, Any] = {}
            # stamp the gather time into each entity
            entity_data[EntityDataProperties.RESULTS_TIME] = self._last_gather_details.get("gather_end")
            entity_data.update(entity)
            if "nodeType" not in entity:
                # region #-- process MAC based information --#
                dev_pc_schedule: list[dict[str, Any]] = []
                dev_adapter_macs: list[str] = [
                    dev_adapter.get("macAddress")
                    for dev_adapter in entity.get(EntityDataProperties.KNOWN_INTERFACES, [])
                ]
                for dev_mac in dev_adapter_macs:
                    # region #-- get parental control details --#
                    for rule in ret.get(MeshCapability.GET_PARENTAL_CONTROL_INFO.value, {}).get("rules", []):
                        if dev_mac in rule.get("macAddresses", []):
                            dev_pc_schedule.append(rule)
                            break
                    entity_data[EntityDataProperties.PARENTAL_CONTROLS] = dev_pc_schedule
                    # endregion
                    # region #-- get reservation info --#
                    for reservation in (
                        ret.get(MeshCapability.GET_LAN_SETTINGS.value, {})
                        .get("dhcpSettings", {})
                        .get("reservations", [])
                    ):
                        if reservation.get("macAddress", "").lower() == dev_mac.lower():
                            entity_data[EntityDataProperties.RESERVATION_DETAILS] = reservation
                            break
                    # endregion
                    # region #-- additional connection details --#
                    for nwc in ret.get(MeshCapability.GET_NODE_WIRELESS_CONNECTIONS.value, {}).get(
                        "nodeWirelessConnections", []
                    ):
                        for connection in nwc.get("connections", {}):
                            if dev_mac == connection.get("macAddress"):
                                entity_data[EntityDataProperties.WIRELESS_CONNECTION_DETAILS] = connection
                                break
                    # endregion
                # endregion
            else:
                # region #-- determine the backhaul information --#
                entity_data[EntityDataProperties.BACKHAUL] = next(
                    (
                        bi
                        for bi in ret.get(MeshCapability.GET_BACKHAUL.value, {}).get("backhaulDevices", [])
                        if bi.get("deviceUUID") == entity.get("deviceID")
                    ),
                    {},
                )
                # endregion
                # region #-- calculate if there is a firmware update available --#
                if MeshCapability.GET_UPDATE_FIRMWARE_STATE.value in ret:
                    entity_data[EntityDataProperties.FIRMWARE_DETAILS] = next(
                        (
                            fds
                            for fds in ret[MeshCapability.GET_UPDATE_FIRMWARE_STATE.value].get(
                                "firmwareUpdateStatus", []
                            )
                            if fds.get("deviceUUID") == entity.get("deviceID")
                        ),
                        {},
                    )
                # endregion

            if "nodeType" not in entity:
                mesh_entities.append(DeviceEntity(entity_data, self._mesh_details))
            else:
                mesh_entities.append(NodeEntity(entity_data, self._mesh_details))
        # endregion

        # region #-- remedial work for the entities --#
        # handle information here that needs a reference to the DeviceEntity or NodeEntity.
        for node_or_device in mesh_entities:
            # region #-- establish the parent/child relationship for entities
            parent_node: str | NodeEntity | None = None
            if isinstance(node_or_device, NodeEntity):
                # region #-- use backhaul information to set for a node --#
                parent_ip: str | None = node_or_device.raw_details.get("backhaul", {}).get("parentIPAddress")
                if parent_ip is not None:
                    for n in mesh_entities:
                        if isinstance(n, NodeEntity):
                            nadi: AdapterInfo | None = next((adi for adi in n.adapter_info if adi.primary), None)
                            if nadi is not None and parent_ip == nadi.ip:
                                parent_node = n
                                break
                # endregion
            elif isinstance(node_or_device, DeviceEntity) and node_or_device.status:
                # region #-- check in the connections list for a parent ID --#
                parent_node = next(
                    (conn.get("parentDeviceID") for conn in node_or_device.raw_details.get("connections", [])), None
                )
                # endregion
                if not parent_node:
                    # region #-- let's look in the wireless node connections for a parent --#
                    adapter_macs: set[str] = {adi.mac for adi in node_or_device.adapter_info if adi.mac is not None}
                    if adapter_macs:
                        for nwc in ret.get(MeshCapability.GET_NODE_WIRELESS_CONNECTIONS.value, {}).get(
                            "nodeWirelessConnections", []
                        ):
                            if any(pd.get("macAddress") in adapter_macs for pd in nwc.get("connections", [])):
                                parent_node = nwc.get("deviceID")
                                break
                    # endregion

            if parent_node and not isinstance(parent_node, NodeEntity):  # we have the ID so let's get the NodeEntity
                parent_node = cast(
                    NodeEntity | None, next((n for n in mesh_entities if n.unique_id == parent_node), None)
                )
            if isinstance(parent_node, NodeEntity):
                node_or_device._update_parent(parent_node)
                if isinstance(node_or_device, DeviceEntity):
                    parent_node._update_connected_devices(node_or_device)

        # endregion

        ret[_ATTR_PROCESSED_DEVICES] = mesh_entities or []
        # endregion

        if track_time:
            self._last_gather_details.update({"process_end": time.time()})

        return ret

    async def async_check_for_updates(self) -> None:
        """Ask the mesh to look for new versions of firmware for the nodes.

        Only a check is done.  The firmware isn't actually updated.

        :return: None
        """

        await self._async_make_request(action=api.Actions.UPDATE_FIRMWARE, payload={"onlyCheck": True})

    async def async_close(self) -> None:
        """Close the session to the mesh.

        :return: None
        """
        if not self.__passed_session:
            await self._mesh_details.session.close()

    async def async_clear_speedtest_results(self) -> None:
        """Clear the speedtest results."""

        await self._async_make_request(api.Actions.CLEAR_SPEEDTEST_RESULTS.value)

    async def async_detect_capabilities(self) -> list[MeshCapability]:
        """Attempt to detect the capabilities of the Mesh.

        :return: list of capabilities for the mesh.
        """
        _is_bridge_mode: bool = False
        ret: list[MeshCapability] = []
        requests: list[Coroutine[Any, Any, _ApiResponse]] = []
        for qry in MeshCapability:
            action_name: str = qry.name
            requests.append(
                self._async_make_request(
                    action=getattr(api.Actions, action_name),
                    payload=api.Defaults.get(action_name, {}),
                    raise_on_error=False,
                )
            )

        responses: list[tuple[api.Request, api.Response]] = await asyncio.gather(*requests)
        for idx, resp in enumerate(responses):
            _, jnap_response = resp
            if isinstance(jnap_response.data, dict) and "result" in jnap_response.data:
                _LOGGER.debug(
                    "capability not found: %s, response: %s",
                    list(MeshCapability)[idx],
                    jnap_response.data,
                )
                continue

            if jnap_response.action == api.Actions.GET_WAN_INFO:
                _is_bridge_mode = (
                    cast(dict[str, Any], jnap_response.data).get("detectedWANType", "").lower() == "bridge"
                )
            ret.append(list(MeshCapability)[idx])

        # region #-- tidy up capabilities --#
        # tidying for bridge mode is based on https://support.linksys.com/kb/article/319-en/
        capabilities_to_remove: set[MeshCapability] = set()
        for resp in responses:
            if resp[0].action == api.Actions.GET_SPEEDTEST_TYPES.value:
                # region #-- remove speedtest related capabilities if they aren't really available --#
                # Some seem to provide access to the underlying APIs still but the app/web UI only shows options for 3rd party testing.
                _LOGGER.debug("establishing if speedtest is actually available")
                healthcheck_modules: set[str] = set(
                    cast(api.JnapResponse, resp[1].data).get("supportedHealthCheckModules", [])
                )

                valid_onboard_speedtest: set[str] = {"SpeedTest"}
                if valid_onboard_speedtest.isdisjoint(healthcheck_modules):
                    _LOGGER.debug("speedtest isn't really available, %s", healthcheck_modules)
                    capabilities_to_remove = capabilities_to_remove.union(FeatureCapabilities.get("speedtest", set()))
                # endregion
            elif resp[0].action == api.Actions.GET_PARENTAL_CONTROL_INFO:
                # region #-- tidy up for bridge mode --#
                if _is_bridge_mode:
                    _LOGGER.debug("in bridge mode so removing parental control capability")
                    capabilities_to_remove = capabilities_to_remove.union(
                        FeatureCapabilities.get("parental_control", set())
                    )
                # endregion
        for capability in capabilities_to_remove:
            if capability in ret:
                ret.remove(capability)
        # endregion

        self._mesh_capabilities = ret
        return self._mesh_capabilities

    @needs_initialise
    async def async_gather_details(self) -> None:
        """Gather all the details and initialise what the mesh looks like.

        Sets the instance variables as necessary.

        :return: None
        """

        self._mesh_attributes = await self._async_gather_details(
            self._mesh_capabilities,
            track_time=True,
        )

    async def async_get_channel_scan_info(self) -> dict[str, Any] | None:
        """Get the current state of the channel scan.

        :return: dictionary containing the channel scan results
        """
        resp = await self._async_gather_details([MeshCapability.GET_CHANNEL_SCAN_STATUS])
        return resp.get(MeshCapability.GET_CHANNEL_SCAN_STATUS.value)

    @needs_initialise
    async def async_get_devices(
        self,
        identity: tuple[str, ...] | None = None,
        *,
        force_refresh: bool = False,
        raise_for_missing: bool = True,
    ) -> list[DeviceEntity]:
        """Get matching devices if identity is specified, or all devices.

        To be used only if needing to query devices and get the details returned.
        Returns the devices in alphabetical order based on the name.

        :return: List of device objects
        """

        all_devices: list[DeviceEntity] = []
        ret: list[DeviceEntity] = []

        if force_refresh:
            gathered_devices = await self._async_gather_details(
                [cap for cap in FeatureCapabilities.get("devices", {}) if cap in self._mesh_capabilities]
            )
            all_devices = [
                dev for dev in gathered_devices.get(_ATTR_PROCESSED_DEVICES, []) if type(dev) is DeviceEntity
            ]
        else:
            all_devices = self.devices

        if identity is None:
            ret = all_devices
        else:
            found: DeviceEntity | None = None
            identity_formatted: tuple[str, ...] = tuple(map(str.lower, map(str.strip, identity)))
            identity_found: list[str | uuid.UUID] = []
            for ident in identity_formatted:
                try:  # match a GUID?
                    _ = uuid.UUID(str(ident))
                    found = next(
                        (
                            dev
                            for dev in all_devices
                            if type(dev) is DeviceEntity
                            and dev.unique_id is not None
                            and dev.unique_id.lower() == ident
                        ),
                        None,
                    )
                except ValueError:  # not a GUID
                    regex_pattern: str = r"^[a-f0-9]{2}((:|-)*[a-f0-9]{2}){5}$"
                    if (  # MAC address?
                        re.match(
                            pattern=regex_pattern,
                            string=str(ident),
                            flags=re.IGNORECASE,
                        )
                        is not None
                    ):
                        found = next(
                            dev
                            for dev in all_devices
                            if type(dev) is DeviceEntity
                            and next(
                                (adapter for adapter in dev.adapter_info if str(adapter.mac).strip().lower() == ident),
                                None,
                            )
                        )
                    else:
                        found = next(
                            (
                                dev
                                for dev in all_devices
                                if type(dev) is DeviceEntity and dev.name.strip().lower() == ident
                            ),
                            None,
                        )

                if found is not None:
                    identity_found.append(ident)
                    ret.append(found)

            if len(ret) != len(identity) and raise_for_missing:
                raise MeshDeviceNotFoundResponse(devices=list(set(identity_formatted).difference(identity_found)))

        ret = sorted(ret, key=lambda device: device.name)

        return ret

    @needs_initialise
    async def async_get_speedtest_results(
        self, count: int = 1, only_latest: bool = False, only_completed: bool = False
    ) -> list[SpeedtestResult]:
        """Retrieve Speedtest results.

        :param count: the number of results to return; defaults to 1
        :param only_latest: True to only return the latest result
        :param only_completed: True to only return results that are not currently running

        :return: List of dictionaries containing the result details
        """

        healthcheck_modules: set[str] | None = set(
            cast(
                api.JnapResponse,
                self._mesh_attributes.get(MeshCapability.GET_SPEEDTEST_TYPES.value, {}),
            ).get("supportedHealthCheckModules", [])
        )

        if "SpeedTest" not in healthcheck_modules:
            raise MeshInvalidArguments

        payload = {
            **api.Defaults.get(api.Actions.GET_SPEEDTEST_RESULTS.name, {}),
            "healthCheckModule": "SpeedTest",
            "lastNumberOfResults": count,
        }
        _, resp = await self._async_make_request(action=api.Actions.GET_SPEEDTEST_RESULTS, payload=payload)

        ret: list[SpeedtestResult] = []
        if resp.data is not None and not isinstance(resp.data, list):
            speedtest_results = resp.data.get("healthCheckResults", [])
            for res in speedtest_results:
                ret.append(self._process_speedtest_results(res))
            if only_completed:
                ret = [result for result in ret if result.exit_code not in (None, SpeedtestExitCode.UNAVAILABLE)]
            if only_latest:
                ret = [sorted(ret, key=lambda itm: itm.timestamp, reverse=True)[0]]

        return ret

    @needs_initialise
    async def async_get_speedtest_state(self) -> SpeedtestResult:
        """Return a textual representation of the stage of a Speedtest.

        The API does not return a stage so this has to be inferred by the results.

        :return: A string containing the stage
        """

        resp = await self._async_gather_details([MeshCapability.GET_SPEEDTEST_STATUS])
        ret = self._process_speedtest_results(resp.get(MeshCapability.GET_SPEEDTEST_STATUS.value, {}))

        return ret

    async def async_get_update_state(self) -> bool:
        """Get the state of the running check for updates.

        :return: True if still running, False if not
        """

        resp = await self._async_gather_details([MeshCapability.GET_UPDATE_FIRMWARE_STATE])

        node_results = resp.get(MeshCapability.GET_UPDATE_FIRMWARE_STATE.value, {}).get("firmwareUpdateStatus", [])
        all_states = ["pendingOperation" in node for node in node_results]

        ret: bool = any(all_states)

        return ret

    async def async_get_upnp_state(self) -> dict[str, bool]:
        """Retrieve the current state of UPnP.

        :return: dictionary containing information about the state of UPnP functionality
        """

        resp = await self._async_gather_details([MeshCapability.GET_UPNP_SETTINGS])

        ret = cast(dict[str, bool], resp.get(MeshCapability.GET_UPNP_SETTINGS.value, {}))

        return ret

    async def async_initialise(self) -> None:
        """Initialise the connection to the Mesh.

        Probes for capabilities and retrieves details for the discovered capabilities.

        :return: None
        """

        await self.async_detect_capabilities()
        self._initialise_executed = True  # flag here so that async_gather_details will run
        await self.async_gather_details()

    async def async_reboot_mesh(self) -> None:
        """Reboot the mesh."""

        found_node: NodeEntity | None = next(
            (node for node in self.nodes if node.type == NodeType.PRIMARY),
            None,
        )

        if found_node is None:
            raise MeshDeviceNotFoundResponse

        await found_node.async_reboot(True)

    async def async_set_guest_wifi_state(self, state: bool) -> None:
        """Set the state of the guest Wi-Fi.

        The radios object is a required parameter for the API call but isn't handled in this method.
        Instead, a call is made to retrieve the existing settings and those are relayed back.  This assumes that
        a guest network has been created in the official UI.

        :param state: True to enable, False to disable

        :return: None
        """

        # get the current radio settings from the API; they may have changed
        resp = await self._async_gather_details([MeshCapability.GET_GUEST_NETWORK_INFO])
        radios = resp.get(MeshCapability.GET_GUEST_NETWORK_INFO.value, {}).get("radios", [])

        for radio_details in radios:
            radio_details["isEnabled"] = state
            radio_details["broadcastGuestSSID"] = state

        payload = {
            "isGuestNetworkEnabled": state,
            "radios": radios,
        }
        await self._async_make_request(action=api.Actions.SET_GUEST_NETWORK, payload=payload)

    async def async_set_homekit_state(self, state: bool) -> None:
        """Set the state of the HomeKit feature.

        :param state: True to enable, False to disable

        :return: None
        """
        await self._async_make_request(action=api.Actions.SET_HOMEKIT_SETTINGS, payload={"isEnabled": state})

    async def async_set_night_mode_state(self, state: NightModeState) -> None:
        """Set the state of the the night mode functionality.

        :param state: the state that night mode should be set to

        :return: None
        """

        payload: dict[str, Any] = {
            "Enabled": True if state != NightModeState.OFF else False,
        }
        if state != NightModeState.OFF:
            if NightModeState.ALWAYS:
                payload["StartingTime"] = 0
                payload["EndingTime"] = 24
            elif NightModeState.NIGHT_MODE:
                payload["StartingTime"] = 20
                payload["EndingTime"] = 8

        await self._async_make_request(action=api.Actions.SET_LED_NIGHT_MODE, payload=payload)

    async def async_set_parental_control_state(self, state: bool) -> None:
        """Set the state of the Parental Control feature. Rules are left intact.

        :param state: True to enabled, False to disable

        :return: None
        """
        # get the current rules from the API because they may be different
        resp = await self._async_gather_details([MeshCapability.GET_PARENTAL_CONTROL_INFO])
        rules = resp.get("rules", [])

        payload = {
            "isParentalControlEnabled": state,
            "rules": rules,
        }
        await self._async_make_request(action=api.Actions.SET_PARENTAL_CONTROL_INFO, payload=payload)

    async def async_set_scheduled_reboot_interval(self, interval: ScheduledRebootInterval) -> None:
        """Set the reboot interval for the Scheduled Reboot feature and enable it.

        :param interval: a valid interval value

        :return: None
        """

        payload = {
            "isScheduledRebootEnabled": True,
            "rebootInterval": interval.value,
        }
        await self._async_make_request(
            action=api.Actions.SET_SCHEDULED_REBOOT_SETTINGS,
            payload=payload,
        )

    async def async_set_scheduled_reboot_state(self, state: bool) -> None:
        """Set the state of the Scheduled Reboot feature. Interval is left intact.

        :param state: True to enabled, False to disable

        :return: None
        """

        # get the current interval from the API because they may be different
        resp = await self._async_gather_details([MeshCapability.GET_SCHEDULED_REBOOT_SETTINGS])

        interval: str | None = resp.get(MeshCapability.GET_SCHEDULED_REBOOT_SETTINGS.value, {}).get("rebootInterval")

        if interval is None:
            raise MeshException("Interval setting not found")

        payload = {
            "isScheduledRebootEnabled": state,
            "rebootInterval": interval,
        }
        await self._async_make_request(
            action=api.Actions.SET_SCHEDULED_REBOOT_SETTINGS,
            payload=payload,
        )

    async def async_set_upnp_settings(
        self, enabled: bool, allow_change_settings: bool, allow_disable_internet: bool
    ) -> None:
        """Set the UPnP settings.

        :param enabled: True to enable UPnP, False to disable.
        :param allow_change_settings: Whether users can change settings when UPnP is enabled.
        :param allow_disable_internet: Whether users can disable the Internet when UPnP is enabled.

        :return: None
        """

        payload = {
            "isUPnPEnabled": enabled,
            "canUsersConfigure": allow_change_settings,
            "canUsersDisableWANAccess": allow_disable_internet,
        }
        await self._async_make_request(action=api.Actions.SET_UPNP_SETTINGS, payload=payload)

    async def async_set_wps_state(self, state: bool) -> None:
        """Set the state of the WPS feature.

        :param state: True to enable, False to disable

        :return: None
        """

        await self._async_make_request(action=api.Actions.SET_WPS_SERVER_SETTINGS, payload={"enabled": state})

    async def async_start_channel_scan(self) -> None:
        """Start a channel scan on the mesh.

        :return: None
        """

        try:
            await self._async_make_request(action=api.Actions.START_CHANNEL_SCAN)
        except MeshAlreadyInProgress as err:
            _LOGGER.debug(err)
        except MeshInvalidInput as err:
            _LOGGER.warning(
                "%s - are you sure the functionality is available",
                err,
            )

    @needs_initialise
    async def async_start_speedtest(self) -> None:
        """Instruct the mesh to carry out a Speedtest.

        A Speedtest is a long-running task.  You should use the async_get_speedtest_state method to understand
        the progress of the task.

        :return: None
        """

        healthcheck_modules: set[str] | None = set(
            cast(
                api.JnapResponse,
                self._mesh_attributes.get(MeshCapability.GET_SPEEDTEST_TYPES.value, {}),
            ).get("supportedHealthCheckModules", [])
        )

        if "SpeedTest" not in healthcheck_modules:
            raise MeshInvalidArguments

        payload: dict[str, Any] = {"runHealthCheckModule": "SpeedTest"}

        await self._async_make_request(action=api.Actions.START_SPEEDTEST, payload=payload)

    async def async_test_credentials(self) -> bool:
        """Check the provided credentials are valid.

        :return: True if valid, False if not
        """

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

        return ret

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

        attr: api.JnapResponse | Any = self._mesh_attributes.get(MeshCapability.GET_UPDATE_FIRMWARE_STATE.value, {})

        node_results = attr.get("firmwareUpdateStatus", [])
        all_states = ["pendingOperation" in node for node in node_results]
        ret = any(all_states)

        return ret

    @property
    @needs_initialise
    def client_steering_enabled(self) -> bool | None:
        """Return if client steering is enabled.

        :return: True if enabled, False otherwise.
        """

        attr = cast(
            dict[str, Any],
            self._mesh_attributes.get(MeshCapability.GET_TOPOLOGY_OPTIMISATION_SETTINGS.value, {}),
        )

        return cast(bool | None, attr.get("isClientSteeringEnabled"))

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

        attr = cast(
            dict[str, Any],
            self._mesh_attributes.get(MeshCapability.GET_LAN_SETTINGS.value, {}),
        )

        return cast(bool | None, attr.get("isDHCPEnabled"))

    @property
    @needs_initialise
    def dhcp_reservations(self) -> list[dict[str, str]]:
        """Return the DHCP reservations.

        :return: list of DHCP reservation details
        """
        ret: list[dict[str, str]] = []
        temp_dict: dict[str, str] = {}

        attr = cast(
            dict[str, Any],
            self._mesh_attributes.get(MeshCapability.GET_LAN_SETTINGS.value, {}),
        )

        for reservation in attr.get("dhcpSettings", {}).get("reservations", []):
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

        attr: api.JnapResponse | Any = self._mesh_attributes.get(MeshCapability.GET_EXPRESS_FORWARDING.value, {})

        return attr.get("isExpressForwardingEnabled")

    @property
    @needs_initialise
    def express_forwarding_supported(self) -> bool | None:
        """Return whether Express Forwarding is supported.

        :return: True if enabled, False otherwise
        """

        attr: api.JnapResponse | Any = self._mesh_attributes.get(MeshCapability.GET_EXPRESS_FORWARDING.value, {})

        return attr.get("isExpressForwardingSupported")

    @property
    @needs_initialise
    def firmware_update_setting(self) -> str | None:
        """Get the current setting for firmware updates.

        :return: a lowercase string representing the update method
        """

        attr: api.JnapResponse | Any = self._mesh_attributes.get(MeshCapability.GET_UPDATE_SETTINGS.value, {})

        return attr.get("updatePolicy", "").lower() or None

    @property
    @needs_initialise
    def guest_wifi_enabled(self) -> bool | None:
        """Get the state of the guest Wi-Fi.

        :return: True if enabled
        """

        attr = cast(
            dict[str, Any],
            self._mesh_attributes.get(MeshCapability.GET_GUEST_NETWORK_INFO.value, {}),
        )

        return cast(bool | None, attr.get("isGuestNetworkEnabled"))

    @property
    @needs_initialise
    def guest_wifi_details(self) -> list[dict[str, str]]:
        """Get the guest network Wi-Fi details.

        :return: A list of dictionaries containing the SSID and band for the networks
        """

        attr = cast(
            dict[str, Any],
            self._mesh_attributes.get(MeshCapability.GET_GUEST_NETWORK_INFO.value, {}),
        )
        radios = cast(list[dict[str, Any]], attr.get("radios", []))

        ret = [
            {
                "ssid": cast(str, radio.get("guestSSID")),
                "band": cast(str, radio.get("radioID", "")).split("_")[-1],
            }
            for radio in radios
        ]
        return ret

    @property
    def has_initialised(self) -> bool:
        """Return whether the mesh has been initialised or not.

        Initialising allows establishing the capabilities that are available as
        well as populating the necessary details for immediate use.

        :return: True if the mesh has been initialise, False otherwise
        """

        return self._initialise_executed

    @property
    @needs_initialise
    def homekit_enabled(self) -> bool | None:
        """Return if the HomeKit integration is enabled.

        :return: True if enabled, False otherwise
        """

        attr = cast(
            dict[str, Any],
            self._mesh_attributes.get(MeshCapability.GET_HOMEKIT_SETTINGS.value, {}),
        )

        return cast(bool | None, attr.get("isEnabled"))

    @property
    @needs_initialise
    def homekit_paired(self) -> bool | None:
        """Return if the HomeKit integration is paired.

        :return: True if enabled, False otherwise
        """

        attr = cast(
            dict[str, Any],
            self._mesh_attributes.get(MeshCapability.GET_HOMEKIT_SETTINGS.value, {}),
        )

        return cast(bool | None, attr.get("isPaired"))

    @property
    @needs_initialise
    def is_channel_scan_running(self) -> bool | None:
        """Get the current state of channel scanning.

        :return: True if enabled, False otherwise
        """

        attr = cast(
            dict[str, Any],
            self._mesh_attributes.get(MeshCapability.GET_CHANNEL_SCAN_STATUS.value, {}),
        )

        return cast(bool | None, attr.get("isRunning"))

    @property
    @needs_initialise
    def is_in_bridge_mode(self) -> bool:
        """Return whether the mesh is in bridge mode or not."""

        attr = cast(
            dict[str, Any],
            self._mesh_attributes.get(
                MeshCapability.GET_WAN_INFO.value,
                {},
            ),
        )

        return cast(str, attr.get("detectedWANType", "")).lower() == "bridge"

    @property
    def last_gather_details(self) -> dict[str, float | None]:
        """Return some timings about when the details were gathered.

        All times are epoch and are approximate.
        Available values are: -

        gather_start: when the requests started being made
        gather_end: when the requests were finshed
        process_start: when processing the results started
        process_end: when processing the results finished
        """

        return self._last_gather_details

    @property
    @needs_initialise
    def mac_filtering_addresses(self) -> list[str]:
        """Get addresses that are configured for MAC filtering.

        :return: list of MAC addresses
        """

        attr = cast(
            dict[str, Any],
            self._mesh_attributes.get(MeshCapability.GET_MAC_FILTERING_SETTINGS.value, {}),
        )

        return cast(list[str], attr.get("macAddresses", []))

    @property
    @needs_initialise
    def mac_filtering_enabled(self) -> bool:
        """Return if MAC filtering is enabled.

        :return: True if enabled, False otherwise
        """

        attr = cast(
            dict[str, Any],
            self._mesh_attributes.get(MeshCapability.GET_MAC_FILTERING_SETTINGS.value, {}),
        )

        return cast(str, attr.get("macFilterMode", "")).lower() != "disabled"

    @property
    @needs_initialise
    def mac_filtering_mode(self) -> str | None:
        """Return the MAC filtering mode.

        :return: string containing the filtering mode
        """
        if self.mac_filtering_enabled:
            attr = cast(
                dict[str, Any],
                self._mesh_attributes.get(MeshCapability.GET_MAC_FILTERING_SETTINGS.value, {}),
            )

            return cast(str, attr.get("macFilterMode", "")).lower()

        return None

    @property
    @needs_initialise
    def mlo_state(self) -> bool | None:
        """Retrieve the state of MLO.

        :return: True if enabled, False if disabled and None if not supported.
        """

        # {"isMLOSupported": true,"isMLOEnabled": false}

        ret: bool | None = None
        mlo_state: dict[str, bool] | None = cast(
            dict[str, bool] | None,
            self._mesh_attributes.get(MeshCapability.GET_MLO_SETTINGS.value),
        )
        if mlo_state is not None:
            ret = None if not mlo_state.get("isMLOSupported") else mlo_state.get("isMLOEnabled")

        return ret

    @property
    @needs_initialise
    def night_mode(self) -> NightModeState | None:
        """Return whether night mode is enabled.

        :return: True if enabled, False otherwise
        """

        ret: NightModeState | None = None
        attr: api.JnapResponse | Any = self._mesh_attributes.get(MeshCapability.GET_LED_NIGHT_MODE.value)

        if attr is not None:
            if not attr.get("Enable", False):
                ret = NightModeState.OFF
            else:
                if attr.get("StartingTime") == 0 and attr.get("EndingTime") == 24:
                    ret = NightModeState.ALWAYS
                elif attr.get("StartingTime") == 20 and attr.get("EndingTime") == 8:
                    ret = NightModeState.NIGHT_MODE

        return ret

    @property
    @needs_initialise
    def node_steering_enabled(self) -> bool | None:
        """Return if node steering is enabled.

        :return: True if enabled, False otherwise
        """

        attr: api.JnapResponse | Any = self._mesh_attributes.get(
            MeshCapability.GET_TOPOLOGY_OPTIMISATION_SETTINGS.value, {}
        )

        return attr.get("isNodeSteeringEnabled")

    @property
    @needs_initialise
    def nodes(self) -> list[NodeEntity]:
        """Get the nodes in the mesh.

        The return is sorted in alphabetical order based on node name.

        :return: A list of NodeEntity objects
        """
        ret: list[NodeEntity] = [
            node for node in self._mesh_attributes.get(_ATTR_PROCESSED_DEVICES, []) if isinstance(node, NodeEntity)
        ]

        ret = sorted(ret, key=lambda node: node.name)
        return ret

    @property
    @needs_initialise
    def parental_control_enabled(self) -> bool | None:
        """Get the state of the Parental Control feature.

        :return: True if enabled, False otherwise
        """

        attr: api.JnapResponse | Any = self._mesh_attributes.get(MeshCapability.GET_PARENTAL_CONTROL_INFO.value, {})

        return attr.get("isParentalControlEnabled")

    @property
    @needs_initialise
    def scheduled_reboot_enabled(self) -> bool | None:
        """Get the state of the Scheduled Reboot feature.

        :return: True if enabled, False otherwise
        """

        attr: api.JnapResponse | Any = self._mesh_attributes.get(MeshCapability.GET_SCHEDULED_REBOOT_SETTINGS.value, {})

        return attr.get("isScheduledRebootEnabled")

    @property
    @needs_initialise
    def scheduled_reboot_interval(self) -> ScheduledRebootInterval | None:
        """Get the interval for the Scheduled Reboot feature.

        :return: value representing the interval
        """

        ret: ScheduledRebootInterval | None = None
        attr: api.JnapResponse | Any = self._mesh_attributes.get(MeshCapability.GET_SCHEDULED_REBOOT_SETTINGS.value, {})
        val: str | None = attr.get("rebootInterval")
        if val is not None:
            ret = ScheduledRebootInterval(val)

        return ret

    @property
    @needs_initialise
    def sip_enabled(self) -> bool | None:
        """Return whether SIP is enabled.

        :return: True if enabled, False otherwise
        """

        attr: api.JnapResponse | Any = self._mesh_attributes.get(MeshCapability.GET_ALG_SETTINGS.value, {})

        return attr.get("isSIPEnabled")

    @property
    @needs_initialise
    def speedtest_results(self) -> list[SpeedtestResult]:
        """Return the available speedtest results."""

        ret: list[SpeedtestResult] = []

        speedtest_results: list[dict[str, Any]] = cast(
            dict[str, Any], self._mesh_attributes.get(MeshCapability.GET_SPEEDTEST_RESULTS.value, {})
        ).get("healthCheckResults", [])
        for res in speedtest_results:
            ret.append(self._process_speedtest_results(res))

        return ret

    @property
    @needs_initialise
    def storage_available(self) -> list[dict[str, Any]]:
        """Get available shared partitions.

        :return: List of the available storage devices and their properties
        """
        ret: list[dict[str, Any]] = []
        node: NodeEntity | None
        device: dict[str, Any]
        storage_available = cast(
            dict[str, Any],
            self._mesh_attributes.get(MeshCapability.GET_STORAGE_PARTITIONS.value, {}),
        )

        for storage_node in storage_available.get("storageNodes", []):
            for device in storage_node.get("storageDevices", []):
                for partition in device.get("partitions", []):
                    if (
                        node := next(
                            (_n for _n in self.nodes if _n.unique_id == storage_node.get("deviceID")),
                            None,
                        )
                    ) is not None:
                        used_percent: int | None = None
                        with contextlib.suppress(ZeroDivisionError):
                            used_percent = round(
                                (partition.get("usedKB") / partition.get("availableKB")) * 100,
                                2,
                            )
                        ret.append(
                            {
                                "available_kb": partition.get("availableKB"),
                                "ip": next(
                                    (adapter.ip for adapter in node.adapter_info if adapter.ip),
                                    None,
                                ),
                                "label": partition.get("label"),
                                "last_checked": storage_node.get("timestamp"),
                                "used_kb": partition.get("usedKB"),
                                "used_percent": used_percent,
                            }
                        )

        return ret

    @property
    @needs_initialise
    def storage_settings(self) -> dict[str, bool | None]:
        """Get the settings for shared partitions.

        :return: dictionary of the storage settings
        """

        attr = cast(
            dict[str, Any],
            self._mesh_attributes.get(
                MeshCapability.GET_STORAGE_SMB_SERVER.value,
                {},
            ),
        )

        return {"anonymous_access": cast(bool | None, attr.get("isAnonymousAccessEnabled"))}

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

        self._mesh_details.request_timeout = value

    @property
    @needs_initialise
    def upnp_enabled(self) -> bool | None:
        """Return whether UPnP is enabled.

        :return: True if enabled, False otherwise
        """

        attr: api.JnapResponse | Any = self._mesh_attributes.get(MeshCapability.GET_UPNP_SETTINGS.value, {})

        return attr.get("isUPnPEnabled")

    @property
    @needs_initialise
    def upnp_allow_change_settings(self) -> bool | None:
        """Return whether users can change settings when UPnP is enabled.

        :return: True if enabled, False otherwise
        """

        attr: api.JnapResponse | Any = self._mesh_attributes.get(MeshCapability.GET_UPNP_SETTINGS.value, {})

        return attr.get("canUsersConfigure")

    @property
    @needs_initialise
    def upnp_allow_disable_internet(self) -> bool | None:
        """Return whether users can change disable the Internet when UPnP is enabled.

        :return: True if enabled, False otherwise
        """

        attr: api.JnapResponse | Any = self._mesh_attributes.get(MeshCapability.GET_UPNP_SETTINGS.value, {})

        return attr.get("canUsersDisableWANAccess")

    @property
    @needs_initialise
    def wan_dns(self) -> list[str]:
        """Get the WAN DNS servers.

        :return: A list containing the IP addresses of the WAN DNS servers
        """

        attr: api.JnapResponse | Any = self._mesh_attributes.get(MeshCapability.GET_WAN_INFO.value, {})

        ret = [
            cast(str, val)
            for key, val in cast(dict[str, Any], attr.get("wanConnection", {})).items()
            if key.startswith("dnsServer")
        ]

        return ret

    @property
    @needs_initialise
    def wan_ip(self) -> str | None:
        """Get the WAN IP address.

        :return: A string containing the IP address for the WAN
        """

        attr = cast(
            dict[str, Any],
            self._mesh_attributes.get(
                MeshCapability.GET_WAN_INFO.value,
                {},
            ),
        )
        return cast(
            str | None,
            cast(dict[str, Any], attr.get("wanConnection", {})).get("ipAddress"),
        )

    @property
    @needs_initialise
    def wan_mac(self) -> str | None:
        """Get the WAN MAC.

        :return: A string containing the MAC address for the WAN adapter
        """

        attr = cast(
            dict[str, Any],
            self._mesh_attributes.get(
                MeshCapability.GET_WAN_INFO.value,
                {},
            ),
        )

        return cast(str, attr.get("macAddress", ""))

    @property
    @needs_initialise
    def wan_status(self) -> bool:
        """Get the status of the WAN.

        :return: True if connected, False if not
        """

        attr = cast(
            dict[str, Any],
            self._mesh_attributes.get(
                MeshCapability.GET_WAN_INFO.value,
                {},
            ),
        )

        return cast(str, attr.get("wanStatus", "")).lower() == "connected"

    @property
    @needs_initialise
    def wps_state(self) -> bool:
        """Return if WPS is enabled or not.

        :return: True if enabled, False otherwise
        """

        attr = cast(
            dict[str, Any],
            self._mesh_attributes.get(
                MeshCapability.GET_WPS_SERVER_SETTINGS.value,
                {},
            ),
        )

        return cast(bool, attr.get("enabled", False))
