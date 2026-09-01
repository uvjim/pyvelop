"""Representation of the mesh."""

# region #-- imports --#
from __future__ import annotations

import asyncio
import contextlib
import copy
import datetime as dt
import functools
import inspect
import json
import logging
import re
import time
import uuid
from collections import defaultdict
from collections.abc import Awaitable, Callable, Iterable, Mapping, Sequence
from dataclasses import asdict, dataclass, field
from enum import StrEnum, auto
from types import MappingProxyType
from typing import Any, Final, Literal, NamedTuple, cast, overload

import aiohttp
from aiohttp import ClientSession

from . import __version__, camel_to_snake
from . import jnap as api
from .action_registry import (
    ActionDefinition,
    ActionFeatures,
    ActionKey,
    ActionPurpose,
    Actions,
    ActionScope,
    ActionVersionMap,
)
from .exceptions import (
    MeshActionUnknown,
    MeshActionVersionNotImplemented,
    MeshAlreadyInProgress,
    MeshDeviceNotFoundResponse,
    MeshException,
    MeshInvalidCredentials,
    MeshInvalidOutput,
    MeshNeedsInitialise,
    MeshNodeNotPrimary,
)
from .jnap import (
    JnapPayloadSingle,
    JnapPayloadTransaction,
    JnapResponseSingle,
    JnapResponseTransaction,
)
from .logger import Logger
from .mesh_attribute import AttributeAction, AttributeAuditEntry, MeshAttribute
from .mesh_entity import (
    DeviceEntity,
    EntityDataProperties,
    NodeEntity,
    NodeType,
)
from .timeouts import poll_with_yield

# endregion


_LOGGER: Logger = Logger(logging.getLogger(__name__))
_LOGGER_VERBOSE = Logger(logging.getLogger(f"{__name__}.verbose"))


class CapabilityScopedGroups(NamedTuple):
    """Representation of the groups of capabilities."""

    mesh: tuple[MeshCapability, ...]
    node: tuple[MeshCapability, ...]


class FirmwareUpdatePolicy(StrEnum):
    """Possible values for the firmware update policy."""

    AUTO = "AutomaticallyCheckAndInstall"
    MANUAL = "Manual"


class MacFilteringMode(StrEnum):
    """Possible values for the MAC filtering mode."""

    ALLOW = "Allow"
    DENY = "Deny"
    DISABLED = "Disabled"


class NightModeState(StrEnum):
    """Possible states for the night mode functionality."""

    ALWAYS = auto()
    NIGHT_MODE = auto()
    OFF = auto()


class ProcessTimerLabels(StrEnum):
    """Possible timers that can be stored."""

    ENTITIES_PROCESS_END = auto()
    ENTITIES_PROCESS_START = auto()
    MESH_SCOPED_GATHER_DETAILS_END = auto()
    MESH_SCOPED_GATHER_DETAILS_START = auto()
    MESH_SCOPED_PROCESS_DETAILS_START = auto()
    MESH_SCOPED_PROCESS_DETAILS_END = auto()
    NODE_SCOPED_GATHER_DETAILS_END = auto()
    NODE_SCOPED_GATHER_DETAILS_START = auto()
    NODE_SCOPED_PROCESS_DETAILS_END = auto()
    NODE_SCOPED_PROCESS_DETAILS_START = auto()
    REMEDIAL_WORK_END = auto()
    REMEDIAL_WORK_START = auto()


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
    NOT_RUNNING = auto()
    UNKNOWN = auto()


class MeshCapability:
    """Representation of the capabilities implemented by this module."""

    def __init__(
        self,
        action_definition: ActionDefinition,
        mesh_details: MeshDetails | None = None,
        *,
        implemented_versions: tuple[int, ...] = (1,),
    ) -> None:
        """Initialise.

        :param action_definition:
        :param mesh_details:
        :param implemented_versions:
        """

        self._action_definition: ActionDefinition = action_definition
        self._action_unknown_callback: list[Callable[[str], None]] = []
        self._implemented_versions: tuple[int, ...] = implemented_versions
        self._mesh_details: MeshDetails | None = mesh_details
        self._service_versions: list[int] = []
        self._action_version: int = self._get_action_version()

    def __repr__(self) -> str:
        """Friendly represenation of the class."""

        return f"{self.__class__.__name__}: {self._action_definition.key}"

    def _get_action_version(self) -> int:
        """Calculate the action version to use."""

        ret: int = 1

        required_service_version: int = max(self.service_versions) if self.service_versions else 1
        latest_service_version: ActionVersionMap = max(
            (item for item in self._action_definition.version_map if item.service_version <= required_service_version),
            key=lambda item: item.service_version,
            default=ActionVersionMap(1, 1),
        )

        actual_version: int = (
            latest_service_version.action_version
            if latest_service_version.action_version in self._implemented_versions
            else max(
                (item for item in self._implemented_versions if item <= latest_service_version.action_version),
                default=1,
            )
        )

        ret = actual_version
        return ret

    @overload
    async def async_execute(
        self,
        *,
        node_address: str | None = None,
        payload: JnapPayloadTransaction,
        raise_on_error: bool = True,
    ) -> JnapResponseTransaction: ...

    @overload
    async def async_execute(
        self,
        *,
        node_address: str | None = None,
        payload: JnapPayloadSingle | None = None,
        raise_on_error: bool = True,
        timeout: float | None = None,
    ) -> JnapResponseSingle: ...

    async def async_execute(
        self,
        *,
        node_address: str | None = None,
        payload: JnapPayloadTransaction | JnapPayloadSingle | None = None,
        raise_on_error: bool = True,
        timeout: float | None = None,
    ) -> JnapResponseSingle | JnapResponseTransaction:
        """Execute the API request against the specified node.

        :param node_address: The node to send the request to will default to the primary node if not supplied
        :param payload: The relevant payload for the action
        :param raise_on_error: Raise an error if one is found
        :param timeout: timeout to apply to the request
        """

        ret: JnapResponseTransaction | JnapResponseSingle = {}
        if self._mesh_details is None:
            raise ValueError("mesh has not been set")

        req: api.Request = api.Request(
            action=self.action_uri,
            password=self._mesh_details.password,
            payload=payload or {},
            raise_on_error=raise_on_error,
            session=self._mesh_details.session,
            target=node_address or self._mesh_details.host,
            username=self._mesh_details.user,
            redact=self._mesh_details.redact,
            supplementary_redactions=self._mesh_details.supplementary_redactions,
        )
        try:
            req_timeout: float = self._mesh_details.request_timeout if timeout is None else timeout
            resp: api.Response = await req.execute(timeout=req_timeout)
            items = resp.items
            if isinstance(req.payload, dict):
                _data = items[0] if items else None
                if _data is not None:
                    ret = _data
            else:
                ret_list: list[dict[str, Any]] = []
                for item in items:
                    if not isinstance(item, dict):
                        continue

                    result: dict[str, Any] = {}
                    for key, value in item.items():
                        result[str(key)] = value

                    ret_list.append(result)
                ret = cast(JnapResponseTransaction, ret_list)
        except MeshActionUnknown as exc:
            _LOGGER_VERBOSE.debug("unknown action found: %s", exc.action)
            for func in self._action_unknown_callback:
                if callable(func):
                    func(exc.action)
            raise

        return ret

    def add_action_unknown_callback(self, func: Callable[[str], None]) -> None:
        """Add a function that should be called when an unknown action is encountered."""

        self._action_unknown_callback.append(func)

    def set_mesh_details(self, mesh_details: MeshDetails) -> None:
        """Update the details of the mesh."""

        self._mesh_details = mesh_details

    @property
    def action_definition(self) -> ActionDefinition:
        """Return the action definition."""

        return self._action_definition

    @property
    def action_version(self) -> int:
        """Retrieve the action version that will be used for the capability."""

        return self._action_version

    @property
    def action_uri(self) -> str:
        """Return a string representing the best action URI to use."""

        action_version: int = self.action_version
        ret: str = (
            f"{self._action_definition.action_base}{action_version}"
            if action_version != 1
            else self._action_definition.action_base
        )

        return ret

    @property
    def service_versions(self) -> Iterable[int]:
        """Retrieve the available service versions for the capability."""

        return self._service_versions

    @service_versions.setter
    def service_versions(self, value: Iterable[int]) -> None:
        """Update the services versions for the capability."""

        self._service_versions = list(value)
        self._action_version = self._get_action_version()


@dataclass(slots=True)
class MeshDetails:
    """Details of the mesh being connected to."""

    host: str
    request_timeout: float
    session: ClientSession
    user: str
    password: str = ""
    redact: bool = True
    supplementary_redactions: dict[str, set[str]] | None = None

    def __repr__(self) -> str:
        """Friendly string representation of the class.

        :return: Concatenation of the class name and the specified host,
        """
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


def needs_initialise[F: Callable[..., Any]](func: F) -> F:
    """Ensure that async_initialise has been executed."""

    @functools.wraps(func)
    def wrapper(self: Mesh, *args: Any, **kwargs: Any) -> Any:
        """Wrap the required function."""
        if not self.has_initialised:
            raise MeshNeedsInitialise from None
        return func(self, *args, **kwargs)

    return cast(F, wrapper)


SpeedtestStateCallback = Callable[[SpeedtestResult], None | Awaitable[None]]


_ACTION_BY_SERVICE: Final[Mapping[str, tuple[ActionDefinition, ...]]] = MappingProxyType(
    {
        name: tuple(obj for obj in Actions.values() if obj.service_base == name)
        for name in {obj.service_base for obj in Actions.values()}
    }
)


class Mesh:
    """Representation of the Velop Mesh.

    **All properties are point in time from when the last async_gather_details was executed.**

    If you need live information then call the corresponding method.
    """

    # set the default capabilities, these should be set for capabilities that are used early (typically without auth requirements)
    # and for those capabilities where multiple implemented versions exist.
    _DEF_MESH_CAPABILITIES: dict[ActionKey, MeshCapability] = {
        "CHECK_PASSWORD": MeshCapability(
            Actions.CHECK_PASSWORD,
        ),
        "GET_DEVICE_INFO": MeshCapability(
            action_definition=Actions.GET_DEVICE_INFO,
        ),
        "GET_DEVICE_MODE": MeshCapability(
            Actions.GET_DEVICE_MODE,
        ),
        "GET_DEVICES": MeshCapability(
            Actions.GET_DEVICES,
            implemented_versions=(3,),
        ),
        "GET_GUEST_NETWORK_INFO": MeshCapability(
            Actions.GET_GUEST_NETWORK_INFO,
            implemented_versions=(2,),
        ),
        "GET_NETWORK_CONNECTIONS": MeshCapability(
            Actions.GET_NETWORK_CONNECTIONS,
            implemented_versions=(2,),
        ),
        "GET_TOPOLOGY_OPTIMISATION_SETTINGS": MeshCapability(
            Actions.GET_TOPOLOGY_OPTIMISATION_SETTINGS,
            implemented_versions=(1, 2),
        ),
        "GET_WAN_INFO": MeshCapability(
            Actions.GET_WAN_INFO,
            implemented_versions=(1, 3),
        ),
        "SET_GUEST_NETWORK": MeshCapability(
            Actions.SET_GUEST_NETWORK,
            implemented_versions=(2,),
        ),
        "SET_LED_NIGHT_MODE": MeshCapability(
            Actions.SET_LED_NIGHT_MODE,
            implemented_versions=(2,),
        ),
    }

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
        self._last_gather_details: dict[str, float] = {}
        self._mesh_attributes: dict[ActionKey, Any] = {}
        self._mesh_entities: list[DeviceEntity | NodeEntity] = []
        self._password: str = password
        _session: ClientSession = session if session is not None else self.__create_session()
        self._mesh_details: MeshDetails = MeshDetails(
            host=node,
            redact=not disable_redaction,
            request_timeout=request_timeout,
            session=_session,
            supplementary_redactions=supplementary_redactions,
            user=username,
        )

        self._mesh_capabilities: dict[ActionKey, MeshCapability] = copy.deepcopy(type(self)._DEF_MESH_CAPABILITIES)
        for cap in self._mesh_capabilities.values():
            cap.set_mesh_details(self._mesh_details)

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

    def _build_mesh_entities(self, track_time, mesh_details: dict[ActionKey, Any]) -> list[DeviceEntity | NodeEntity]:
        """Build a list of mesh entities with the given information."""

        ret: list[DeviceEntity | NodeEntity] = []

        self._mark_time(track_time, ProcessTimerLabels.ENTITIES_PROCESS_START)
        # region #-- pre-index device ID based info --#
        backhaul_by_device_id: dict[str, Any] = {
            bi.get("deviceUUID"): bi
            for bi in mesh_details.get("GET_BACKHAUL", {}).get("backhaulDevices", [])
            if bi.get("deviceUUID")
        }
        firmware_by_device_id: dict[str, Any] = {
            fds.get("deviceUUID"): fds
            for fds in mesh_details.get("GET_UPDATE_FIRMWARE_STATE", {}).get("firmwareUpdateStatus", [])
            if fds.get("deviceUUID")
        }
        system_stats_by_device_id: dict[str, Any] = {
            stats.get("device_id"): stats
            for stats in mesh_details.get("GET_SYSTEM_STATS", [])
            if stats.get("device_id")
        }
        wifi_connections_by_id: dict[str, Any] = {
            nwc.get("deviceID"): nwc
            for nwc in mesh_details.get("GET_NODE_WIRELESS_CONNECTIONS", {}).get("nodeWirelessConnections", [])
            if nwc.get("deviceID")
        }
        # endregion

        # region #-- pre-index mac based information
        dhcp_reservations_by_mac: dict[str, Any] = {
            reservation["macAddress"].lower(): reservation
            for reservation in mesh_details.get(Actions.GET_LAN_SETTINGS.key, {})
            .get("dhcpSettings", {})
            .get("reservations", [])
            if reservation.get("macAddress")
        }
        network_connections_by_mac: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for connection in mesh_details.get("GET_NETWORK_CONNECTIONS", []):
            mac = connection.get("macAddress")
            if mac:
                network_connections_by_mac[mac.lower()].append(connection)
        node_wirless_connections_by_mac: dict[str, dict[str, Any]] = {
            mac.lower(): connection
            for connection in mesh_details.get(Actions.GET_NODE_WIRELESS_CONNECTIONS.key, {}).get("connections", [])
            if connection.get("macAddress")
        }
        parental_control_by_mac: dict[str, Any] = {
            mac.lower(): rule
            for rule in mesh_details.get("GET_PARENTAL_CONTROL_INFO", {}).get("rules", [])
            for mac in rule.get("macAddresses", [])
        }
        # endregion

        # we'll treat the information from GET_DEVICES as our starting point.
        for entity in mesh_details.get("GET_DEVICES", {}).get("devices", []):
            # prepare variables for holding processed data
            entity_dhcp_reservations: list[dict[str, Any]] = []
            entity_network_connections: list[dict[str, Any]] = []
            entity_pc_schedules: list[dict[str, Any]] = []
            entity_wifi_connections: list[dict[str, Any]] = []
            # entity_data will be used to store all the information needed to build the appropriate MeshEntity object.
            entity_data: dict[str, Any] = {}
            # stamp the gather time into each entity
            entity_data[EntityDataProperties.RESULTS_TIME] = self._last_gather_details.get(
                ProcessTimerLabels.MESH_SCOPED_GATHER_DETAILS_START.value
            )
            # all details as per the API response get added
            entity_data[EntityDataProperties.DEVICE_DETAILS] = entity
            # region #-- process additional information --#
            # this is gathered, infered and linked from other API calls
            if "nodeType" not in entity:  # process end devices connected to the mesh
                for adapter in entity.get("knownInterfaces", []):  # per MAC details
                    mac = adapter.get("macAddress", "").lower()

                    # region #-- get parental control details --#
                    if pc_rule := parental_control_by_mac.get(mac):
                        entity_pc_schedules.append(pc_rule)
                    # endregion

                    # region #-- get DHCP reservation info --#
                    if reservation := dhcp_reservations_by_mac.get(mac):
                        entity_dhcp_reservations.append(reservation)
                    # endregion

                    # region #-- wireless connection details --#
                    if connection := node_wirless_connections_by_mac.get(mac):
                        entity_wifi_connections.append(connection)
                    # endregion

                    # region #-- retrieve details from the node network connections --#
                    if conns := network_connections_by_mac.get(mac):
                        entity_network_connections.extend(conns)
                    # endregion

                entity_data[EntityDataProperties.NODE_NETWORK_CONNECTIONS] = entity_network_connections
                entity_data[EntityDataProperties.PARENTAL_CONTROLS] = entity_pc_schedules
                entity_data[EntityDataProperties.RESERVATION_DETAILS] = entity_dhcp_reservations
                entity_data[EntityDataProperties.WIRELESS_CONNECTION_DETAILS] = entity_wifi_connections
            else:  # process nodes connected to the mesh
                # region #-- determine the backhaul information --#
                if backhaul := backhaul_by_device_id.get(entity.get("deviceID")):
                    entity_data[EntityDataProperties.BACKHAUL] = backhaul
                # endregion

                # region #-- firmware update details --#
                if firmware := firmware_by_device_id.get(entity.get("deviceID")):
                    entity_data[EntityDataProperties.FIRMWARE_DETAILS] = firmware
                # endregion

                # region #-- wifi connection details --#
                if wifi_conn := wifi_connections_by_id.get(entity.get("deviceID")):
                    entity_data[EntityDataProperties.WIRELESS_CONNECTION_DETAILS] = wifi_conn.get("connections", [])
                # endregion

                # region #-- system stats --#
                if system_stats := system_stats_by_device_id.get(entity.get("deviceID")):
                    entity_data[EntityDataProperties.SYSTEM_STATS] = system_stats
                # endregion
            # endregion

            # region #-- build the MeshEntity objects --#
            if "nodeType" not in entity:
                cap_device: Mapping[ActionKey, MeshCapability] = MappingProxyType(
                    {
                        key: cap
                        for key, cap in self._mesh_capabilities.items()
                        if ActionScope.DEVICE in cap.action_definition.scope
                    }
                )
                ret.append(DeviceEntity(entity_data, cap_device, self._supplementary_redactions))
            else:
                cap_node: Mapping[ActionKey, MeshCapability] = MappingProxyType(
                    {
                        key: cap
                        for key, cap in self._mesh_capabilities.items()
                        if ActionScope.NODE in cap.action_definition.scope
                    }
                )
                ret.append(NodeEntity(entity_data, cap_node, self._supplementary_redactions))
            # endregion
        self._mark_time(track_time, ProcessTimerLabels.ENTITIES_PROCESS_END)

        return ret

    def _build_transaction_payload(
        self, required_capabilities: Iterable[MeshCapability], action_payloads: dict[ActionKey, Any] | None = None
    ) -> tuple[list[dict[str, Any]], ...]:
        """Build the payload for a transaction based on the given information.

        Up to two payloads are returned. Later versions of firmware seem to fail a transaction if there is a mixture
        of actions that require auth and those that don't.

        :param required_capabilities: the capabailities that should be included in the transaction request.
        :param action_payloads: dictionary containing the payloads for each action. If the action does not have
        a payload specified it defaults to an empty dictionary.
        """

        if action_payloads is None:
            action_payloads = {}

        payload_auth: list[dict[str, Any]] = []
        payload_no_auth: list[dict[str, Any]] = []
        ret: list[list[dict[str, Any]]] = []

        for cap in required_capabilities:
            entry: dict[str, Any] = {
                "action": cap.action_uri,
                "request": action_payloads.get(cap.action_definition.key, cap.action_definition.payload or {}),
            }
            if cap.action_definition.requires_auth:
                payload_auth.append(entry)
            else:
                payload_no_auth.append(entry)

        if payload_auth:
            ret.append(payload_auth)
        if payload_no_auth:
            ret.append(payload_no_auth)

        return tuple(ret)

    def _get_mesh_capability(self, capability: ActionKey) -> MeshCapability:
        """Retrieve the capability from the identified mesh capabilities.

        Raises ValueError if the capability isn't found.

        :param capability: the capabality to retrieve.
        :return: the MeshCapability object.
        """

        ret: MeshCapability | None = None
        if cap := self._mesh_capabilities.get(capability):
            ret = cap

        if ret is None:
            raise ValueError(f"Unknown capability ({capability})")

        return ret

    def _get_nodes_from_raw(self, raw_details: dict[ActionKey, Any]) -> list[dict[str, str]]:
        """Retrieve the nodes from raw details.

        :return: list of dictionaries containing the IP and unique_id
        """

        ret: list[dict[str, str]] = []

        for device in raw_details.get("GET_DEVICES", {}).get("devices", []):
            if "nodeType" not in device:
                continue

            ip_address = next(
                (
                    connection.get("ipAddress")
                    for connection in device.get("connections", [])
                    if connection.get("ipAddress")
                ),
                None,
            )

            if ip_address:
                ret.append({"id": device["deviceID"], "ip": ip_address})

        return ret

    def _group_sort_services(self, service_list: Iterable[str]) -> dict[str, list[int]]:

        groups = defaultdict(list)
        for value in service_list:
            match = re.match(r"^(.*?)(\d*)$", value)
            if match is not None:
                prefix = match.group(1)
                number = int(match.group(2)) if match.group(2) else 1

                groups[prefix].append((number, value))

        # Sort each group by the trailing number
        for prefix in groups:
            groups[prefix].sort(key=lambda item: item[0])

        # Get the grouped strings
        grouped_values: dict[str, list[int]] = {
            prefix: [number for number, value in items] for prefix, items in groups.items()
        }

        return grouped_values

    def _mark_time(self, enabled: bool, name: ProcessTimerLabels) -> None:
        """Stamp the time into the tracking object."""

        if enabled:
            self._last_gather_details[name.value] = time.time()

    def _process_speedtest_results(self, results: dict[str, Any]) -> SpeedtestResult:
        """Build a SpeedtestResult object from the provisded results."""

        if "speedTestResult" not in results:
            raise ValueError

        result_set: dict[str, Any] = results.get("speedTestResult", {})
        props: dict[str, Any] = {
            "download_bandwidth": result_set.get("downloadBandwidth"),
            "exit_code": SpeedtestExitCode(result_set.get("exitCode")),
            "latency": result_set.get("latency"),
            "result_id": result_set.get("resultID"),
            "server_id": result_set.get("serverID"),
            "timestamp": (
                dt.datetime.fromisoformat(results.get("timestamp", ""))
                if results.get("timestamp") is not None
                else dt.datetime.min.replace(tzinfo=dt.UTC)
            ),
            "upload_bandwidth": result_set.get("uploadBandwidth"),
        }
        return SpeedtestResult(**props)

    def _remediate_mesh_entities(
        self, track_time: bool, entity_details: list[DeviceEntity | NodeEntity]
    ) -> list[DeviceEntity | NodeEntity]:
        """Apply any remediations necessary to ensure mesh entity details are as complete as possible."""

        ret: list[DeviceEntity | NodeEntity] = []

        self._mark_time(track_time, ProcessTimerLabels.REMEDIAL_WORK_START)
        for node_or_device in entity_details:
            # region #-- establish the parent/child relationship for entities
            audit_history: list[AttributeAuditEntry] = []
            # check if the parent is known in GET_DEVICES - assumes the first connection that has a parent is correct
            parent_node: str | NodeEntity | None = next(
                (
                    conn.get("parentDeviceID")
                    for conn in node_or_device.raw_details.get(EntityDataProperties.DEVICE_DETAILS, {}).get(
                        "connections", []
                    )
                ),
                None,
            )
            audit_history.append(AttributeAuditEntry(EntityDataProperties.DEVICE_DETAILS.value, parent_node))
            if isinstance(node_or_device, NodeEntity):  # node?
                # use backhaul info
                parent_ip: str | None = node_or_device.raw_details.get(EntityDataProperties.BACKHAUL, {}).get(
                    "parentIPAddress"
                )
                if parent_ip is not None:
                    parent_node = next(
                        (
                            node
                            for node in entity_details
                            if isinstance(node, NodeEntity)
                            and any(adapter.primary and adapter.ip == parent_ip for adapter in node.adapter_info.value)
                        ),
                        None,
                    )
                    if parent_node is not None:
                        audit_history.append(
                            AttributeAuditEntry(
                                EntityDataProperties.BACKHAUL.value, parent_ip, kind=AttributeAction.REPLACE
                            )
                        )
            elif isinstance(node_or_device, DeviceEntity) and node_or_device.status:
                if not parent_node:
                    # region #-- let's look in the wireless node connections for a parent --#
                    adapter_macs: set[str] = {
                        adi.mac for adi in node_or_device.adapter_info.value if adi.mac is not None
                    }
                    if adapter_macs:
                        nodes = [node for node in entity_details if isinstance(node, NodeEntity)]
                        for node in nodes:
                            if any(
                                pd.get("macAddress") in adapter_macs
                                for pd in node.raw_details.get(EntityDataProperties.WIRELESS_CONNECTION_DETAILS, {})
                            ):
                                parent_node = node.unique_id.value
                                break
                        audit_history.append(
                            AttributeAuditEntry(
                                EntityDataProperties.WIRELESS_CONNECTION_DETAILS.value,
                                parent_node,
                                kind=AttributeAction.REPLACE,
                            )
                        )
                    # endregion

                if not parent_node:
                    # region #-- still no parent so let's look in the node network connections --#
                    nnc: list[dict[str, Any]] = cast(
                        list[dict[str, Any]],
                        node_or_device.raw_details.get(EntityDataProperties.NODE_NETWORK_CONNECTIONS, []),
                    )
                    for n in nnc:
                        parent_node = n.get("parent_id")
                        if parent_node is not None:
                            audit_history.append(
                                AttributeAuditEntry(
                                    EntityDataProperties.NODE_NETWORK_CONNECTIONS.value,
                                    parent_node,
                                    kind=AttributeAction.REPLACE,
                                )
                            )
                    # endregion

            if parent_node and not isinstance(parent_node, NodeEntity):  # we have the ID so let's get the NodeEntity
                parent_node = cast(
                    NodeEntity | None, next((n for n in entity_details if n.unique_id == parent_node), None)
                )
            if isinstance(parent_node, NodeEntity):
                node_or_device._update_parent(MeshAttribute(parent_node, tuple(audit_history)))
                if isinstance(node_or_device, DeviceEntity):
                    parent_node._update_connected_devices(node_or_device)

            ret.append(node_or_device)

        self._mark_time(track_time, ProcessTimerLabels.REMEDIAL_WORK_END)

        return ret

    def _remove_mesh_capability(self, action_uri: str) -> None:
        """Remove the given action key from the available capabilities.

        :param action_uri: the action uri of the capability that should be removed.
        """

        cap_remove: ActionKey | None = next(
            (cap_key for cap_key, cap in self._mesh_capabilities.items() if cap.action_uri == action_uri), None
        )
        if cap_remove is not None:
            _LOGGER_VERBOSE.debug("removing capability: %s", cap_remove)
            self._mesh_capabilities.pop(cap_remove, None)

    def _split_capability_into_scopes(self, capabilities: Iterable[MeshCapability]) -> CapabilityScopedGroups:
        """Group the given capabilities into scopes."""

        mesh: list[MeshCapability] = []
        node: list[MeshCapability] = []

        for cap in capabilities:
            if ActionScope.MESH in cap.action_definition.scope:
                mesh.append(cap)
            elif ActionScope.NODE in cap.action_definition.scope:
                node.append(cap)

        return CapabilityScopedGroups(tuple(mesh), tuple(node))

    async def _async_gather_mesh_details(
        self, track_time: bool, capabilities: Iterable[MeshCapability]
    ) -> dict[ActionKey, Any]:
        """Gather details from the mesh."""

        ret: dict[ActionKey, Any] = {}

        self._mark_time(track_time, ProcessTimerLabels.MESH_SCOPED_GATHER_DETAILS_START)
        _required_capabilities: list[MeshCapability] = list(capabilities)
        txn_payload: tuple[list[dict[str, Any]], ...] = self._build_transaction_payload(_required_capabilities)
        requests: list[Awaitable[JnapResponseTransaction]] = []
        for txn in txn_payload:
            cap: MeshCapability = self._get_mesh_capability("TRANSACTION")
            requests.append(cap.async_execute(payload=txn))

        try:
            responses = await asyncio.gather(*requests)
            capabilities_by_action_uri: dict[str, MeshCapability] = {
                cap.action_uri: cap for cap in _required_capabilities
            }
            for txn_idx, txn_response in enumerate(responses):
                for txn_payload_idx, resp in enumerate(txn_response):
                    action_uri: str = txn_payload[txn_idx][txn_payload_idx].get("action", "")
                    if cap_from_uri := capabilities_by_action_uri.get(action_uri):
                        ret.update({cap_from_uri.action_definition.key: resp})
        except MeshActionUnknown as exc:
            _LOGGER_VERBOSE.debug("retrying request")
            _required_capabilities = [cap for cap in _required_capabilities if cap.action_uri != exc.action]
            ret = await self._async_gather_mesh_details(track_time, _required_capabilities)

        self._mark_time(track_time, ProcessTimerLabels.MESH_SCOPED_GATHER_DETAILS_END)
        return ret

    async def _async_gather_node_details(
        self, track_time: bool, nodes: Iterable[dict[str, Any]], capabilities: Iterable[MeshCapability]
    ) -> dict[ActionKey, Any]:
        """Retrieve the details for node scoped requests."""

        ret: dict[ActionKey, Any] = {}

        _required_capabilities = tuple(capabilities)
        nodes = tuple(nodes)
        requests: list[Awaitable[JnapResponseTransaction]] = []
        txn_payload: tuple[list[dict[str, Any]], ...] = self._build_transaction_payload(_required_capabilities)

        if not _required_capabilities or not nodes or not txn_payload:
            return {}

        # region #-- build and make the requests --#
        self._mark_time(track_time, ProcessTimerLabels.NODE_SCOPED_GATHER_DETAILS_START)
        for node in nodes:
            cap: MeshCapability = self._get_mesh_capability("TRANSACTION")
            for txn in txn_payload:
                requests.append(
                    cap.async_execute(
                        node_address=node["ip"],
                        payload=txn,
                    )
                )

        responses = await asyncio.gather(*requests)
        self._mark_time(track_time, ProcessTimerLabels.NODE_SCOPED_GATHER_DETAILS_END)
        # endregion

        # region #-- process the responses --#
        self._mark_time(track_time, ProcessTimerLabels.NODE_SCOPED_PROCESS_DETAILS_START)
        capabilities_by_action_uri: dict[str, MeshCapability] = {cap.action_uri: cap for cap in _required_capabilities}

        for node_index, node in enumerate(nodes):  # loop through the nodes
            # region #-- extract responses for the node --#
            start = node_index * len(txn_payload)
            node_responses = responses[start : start + len(txn_payload)]
            # endregion

            # region #-- pair the payload with node response for subsequent processing --#
            # the node response will have multiple responses in it corresponding to the actions in the payload.
            # these need combining and tagging with the node id they came from.
            for payload, transaction_responses in zip(txn_payload, node_responses, strict=True):
                if not isinstance(transaction_responses, list):
                    continue

                for request, transaction_response in zip(payload, transaction_responses, strict=True):
                    if not isinstance(transaction_response, dict):
                        continue

                    # region #-- retrieve the capability so that we can get its key --#
                    action_uri = request.get("action", "")
                    capability = capabilities_by_action_uri.get(action_uri)

                    # unlikely to have a missing capability because this should be handled by the discovery process and
                    # main gathering method however, check here in case something becomes stale or external factors change this.
                    if capability is None:
                        _LOGGER_VERBOSE.warning("unknown action URI: %s", action_uri)
                        continue
                    # endregion

                    # region #-- update the return value accordingly --#
                    if capability.action_definition.key == "GET_NETWORK_CONNECTIONS":
                        val = [
                            {
                                **connection,
                                "parent_id": node["id"],
                            }
                            for connection in transaction_response.get("connections", [])
                        ]
                        ret.setdefault(capability.action_definition.key, []).extend(val)
                    else:
                        val = {
                            **transaction_response,
                            "device_id": node["id"],
                        }
                        ret.setdefault(capability.action_definition.key, []).append(val)
                    # endregion
            # endregion
        self._mark_time(track_time, ProcessTimerLabels.NODE_SCOPED_PROCESS_DETAILS_END)
        # endregion

        return ret

    async def _async_get_speedtest_results(
        self, *, count: int | None = None, result_ids: Sequence[int] | None = None
    ) -> list[SpeedtestResult]:
        """Retrieve speedtest results from the mesh."""

        if (count is None) == (result_ids is None):
            raise ValueError("Provide exactly one of count or result_ids")

        if count is not None and count < 1:
            raise ValueError("Count must be greater than zero")

        if result_ids is not None and not result_ids:
            return []

        cap: MeshCapability = self._get_mesh_capability("GET_SPEEDTEST_RESULTS")
        payload: JnapPayloadSingle = {**cap.action_definition.payload}
        if count is not None:
            payload["lastNumberOfResults"] = count

        if result_ids is not None:
            payload["resultIDs"] = list(result_ids)

        resp: JnapResponseSingle = await cap.async_execute(payload=payload)
        raw_results = resp.get("healthCheckResults")
        if raw_results is None:
            return []

        ret: list[SpeedtestResult] = []
        for raw_result in raw_results:
            try:
                result = self._process_speedtest_results(raw_result)
            except ValueError:
                pass
            else:
                ret.append(result)

        return ret

    async def async_check_for_updates(self) -> None:
        """Ask the mesh to look for new versions of firmware for the nodes.

        Only a check is done.  The firmware isn't actually updated.
        """

        cap: MeshCapability = self._get_mesh_capability("UPDATE_FIRMWARE")
        payload: JnapPayloadSingle = {
            "onlyCheck": True,
        }
        await cap.async_execute(payload=payload)

    async def async_close(self) -> None:
        """Close the session to the mesh.

        :return: None
        """
        if not self.__passed_session:
            await self._mesh_details.session.close()

    async def async_clear_speedtest_results(self) -> None:
        """Clear the speedtest results."""

        cap: MeshCapability = self._get_mesh_capability("CLEAR_SPEEDTEST_RESULTS")
        await cap.async_execute()

    async def async_detect_capabilities(self) -> tuple[ActionKey, ...]:
        """Attempt to detect the capabilities of the Mesh.

        This will read the services from the mesh and then build up the available capabilities.

        :return: capability keys for the mesh.
        """

        cap: MeshCapability
        cap_to_remove: set[ActionKey] = set()
        resp: dict[str, Any]
        ret: list[ActionKey] = []

        # region #-- query the node for capabilities --#
        # Credentials are not required for this and are currently not set in the MeshDetails object.
        # Check the capabilities first so action versions can be determined.
        cap = self._get_mesh_capability("GET_DEVICE_INFO")
        resp = await cap.async_execute()
        # endregion

        # region #-- populate available capabilities --#
        services: list[str] = resp.get("services", [])
        for service_base, service_versions in self._group_sort_services(services).items():
            actions: tuple[ActionDefinition, ...] = _ACTION_BY_SERVICE.get(service_base, ())
            for action in actions:
                if action.key not in self._mesh_capabilities:
                    self._mesh_capabilities[action.key] = MeshCapability(
                        action,
                        self._mesh_details,
                    )
                self._mesh_capabilities[action.key].add_action_unknown_callback(self._remove_mesh_capability)
                self._mesh_capabilities[action.key].service_versions = service_versions
        _display_versions: tuple[tuple[str, str, int, int], ...] = tuple(
            (
                action_name,
                cap.action_uri,
                cap.action_version,
                max(cap.service_versions, default=1),
            )
            for action_name, cap in self._mesh_capabilities.items()
        )
        _LOGGER_VERBOSE.debug("%s", json.dumps(_display_versions))
        # endregion

        # region #-- test the credentials --#
        self._mesh_details.password = self._password
        valid_credentials: bool = await self.async_test_credentials()
        if not valid_credentials:
            raise MeshInvalidCredentials()
        # endregion

        # region #-- query for speedtest availablility --#
        cap = self._get_mesh_capability("GET_SPEEDTEST_TYPES")
        resp = await cap.async_execute()
        _LOGGER_VERBOSE.debug("establishing if SpeedTest is really available")
        valid_speedtest: set[str] = {"SpeedTest"}
        healthcheck_modules: set[str] = set(resp.get("supportedHealthCheckModules", []))
        if valid_speedtest.isdisjoint(healthcheck_modules):
            _LOGGER_VERBOSE.debug("speedtest isn't really available, %s", healthcheck_modules)
            cap_speedtest: set[ActionKey] = {
                act.key
                for act in Actions.values()
                if act.features is not None and ActionFeatures.SPEEDTEST in act.features
            }
            cap_to_remove = cap_to_remove.union(cap_speedtest)
        else:
            _LOGGER_VERBOSE.debug("speedtest is available, %s", healthcheck_modules)
        # endregion

        # region #-- query for bridge mode --#
        # tidying for bridge mode is based on https://support.linksys.com/kb/article/319-en/
        cap = self._get_mesh_capability("GET_WAN_INFO")
        resp = await cap.async_execute()
        is_bridge_mode: bool = resp.get("detectedWANType", "").lower() == "bridge"
        if is_bridge_mode:
            cap_bridge_remove: set[ActionKey] = {
                act.key
                for act in Actions.values()
                if act.features is not None
                and any(feature in act.features for feature in (ActionFeatures.PARENTAL_CONTROL,))
            }
            cap_to_remove = cap_to_remove.union(cap_bridge_remove)
        # endregion

        # region #-- cleanup the capabilities --#
        for cap_key in cap_to_remove:
            self._mesh_capabilities.pop(cap_key, None)
        # endregion

        ret = sorted(
            cap_key
            for cap_key, cap in self._mesh_capabilities.items()
            if cap.action_definition.purpose == ActionPurpose.GET
        )
        return tuple(ret)

    @needs_initialise
    async def async_gather_details(
        self, required_capabilities: Iterable[MeshCapability] | None = None
    ) -> dict[ActionKey, Any]:
        """Retrieve all the details for the specified capabilities."""

        ret_mesh_details: dict[ActionKey, Any] = {}
        track_time: bool = False
        if required_capabilities:
            required_capabilities = tuple(required_capabilities)
        else:
            track_time = True
            required_capabilities = (
                cap for cap in self._mesh_capabilities.values() if cap.action_definition.purpose == ActionPurpose.GET
            )

        capability_scope_groups: CapabilityScopedGroups = self._split_capability_into_scopes(required_capabilities)

        # region #-- gather the details for the mesh scoped capabilities --#
        mesh_details: dict[ActionKey, Any] = await self._async_gather_mesh_details(
            track_time, capability_scope_groups.mesh
        )
        ret_mesh_details.update(mesh_details)
        # endregion

        # region #-- action per node requests --#
        nodes: list[dict[str, str]] = self._get_nodes_from_raw(ret_mesh_details)
        node_details: dict[ActionKey, Any] = await self._async_gather_node_details(
            track_time, nodes, capability_scope_groups.node
        )
        ret_mesh_details.update(node_details)
        # endregion

        return ret_mesh_details

    async def async_get_channel_scan_info(self) -> dict[str, Any]:
        """Get the current state of the channel scan.

        :return: dictionary containing the channel scan results
        """

        cap: MeshCapability = self._get_mesh_capability("GET_CHANNEL_SCAN_STATUS")
        ret: JnapResponseSingle = await cap.async_execute()

        return ret

    @needs_initialise
    async def async_get_devices(
        self,
        identity: tuple[str, ...] | None = None,
        *,
        force_refresh: bool = False,
        raise_for_missing: bool = True,
    ) -> tuple[DeviceEntity, ...]:
        """Get matching devices if identity is specified, or all devices.

        To be used only if needing to query devices and get the details returned.
        Returns the devices in alphabetical order based on the name.

        :return: List of device objects
        """

        all_devices: list[DeviceEntity] = []
        ret: list[DeviceEntity] = []

        if force_refresh:
            device_capabilities: set[MeshCapability] = {
                cap
                for cap in self._mesh_capabilities.values()
                if cap.action_definition.features is not None
                and ActionFeatures.DEVICE_INFO in cap.action_definition.features
            }
            device_details: dict[ActionKey, Any] = await self.async_gather_details(device_capabilities)
            device_entities: list[DeviceEntity | NodeEntity] = self._build_mesh_entities(False, device_details)
            device_entities: list[DeviceEntity | NodeEntity] = self._remediate_mesh_entities(False, device_entities)
            all_devices = [dev for dev in device_entities if isinstance(dev, DeviceEntity)]
        else:
            all_devices = list(self.devices)

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
                            and dev.unique_id.value is not None
                            and str(dev.unique_id).lower() == ident
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
                                (
                                    adapter
                                    for adapter in dev.adapter_info.value
                                    if str(adapter.mac).strip().lower() == ident
                                ),
                                None,
                            )
                        )
                    else:
                        found = next(
                            (
                                dev
                                for dev in all_devices
                                if type(dev) is DeviceEntity and str(dev.name).strip().lower() == ident
                            ),
                            None,
                        )

                if found is not None:
                    identity_found.append(ident)
                    ret.append(found)

            if len(ret) != len(identity) and raise_for_missing:
                raise MeshDeviceNotFoundResponse(devices=list(set(identity_formatted).difference(identity_found)))

        ret = sorted(ret, key=lambda device: str(device.name))

        return tuple(ret)

    @needs_initialise
    async def async_get_speedtest_result_by_id(self, result_ids: Sequence[int]) -> tuple[SpeedtestResult, ...]:
        """Retrieve speedtest results by ID.

        :param result_ids: the ids of the result objects you want to retrieve.
        :return: speedtest results detailing the requested IDs.
        """

        return tuple(await self._async_get_speedtest_results(result_ids=result_ids))

    @needs_initialise
    async def async_get_speedtest_results(
        self,
        count: int = 10,
        *,
        only_completed: bool = False,
    ) -> tuple[SpeedtestResult, ...]:
        """Retrieve the specified number of results from mesh optionally filtering to only completed results.

        :param count: the maximum number of results to return, before filtering.
        :param only_completed: optional filter allowing you to remove results that are not completed.
        :return: the optionally filtered speedtest results.
        """

        results = await self._async_get_speedtest_results(count=count)
        if only_completed:
            results = [result for result in results if result.exit_code != SpeedtestExitCode.UNAVAILABLE]

        return tuple(results)

    @needs_initialise
    async def async_get_speedtest_status(self) -> SpeedtestResult | None:
        """Return details about the current stage of a Speedtest.

        :return: Details about the current stage of the Speedtest.
        `None` is returned if the responses does not indicate a speedtest is runnig.
        """

        ret: SpeedtestResult | None = None
        cap: MeshCapability = self._get_mesh_capability("GET_SPEEDTEST_STATUS")
        result: JnapResponseSingle = await cap.async_execute()
        with contextlib.suppress(ValueError):
            ret = self._process_speedtest_results(result)

        return ret

    async def async_get_update_state(self) -> bool:
        """Get the state of the running check for updates.

        :return: True if still running, False if not
        """

        cap: MeshCapability = self._get_mesh_capability("GET_UPDATE_FIRMWARE_STATE")
        resp: JnapResponseSingle = await cap.async_execute()
        node_results = resp.get("firmwareUpdateStatus", [])
        all_states = ["pendingOperation" in node for node in node_results]

        ret: bool = any(all_states)

        return ret

    async def async_get_upnp_state(self) -> dict[str, bool]:
        """Retrieve the current state of UPnP.

        :return: dictionary containing information about the state of UPnP functionality
        """

        cap: MeshCapability = self._get_mesh_capability("GET_UPNP_SETTINGS")
        ret: JnapResponseSingle = await cap.async_execute()

        return ret

    async def async_initialise(self) -> None:
        """Initialise the connection to the Mesh.

        Probes for capabilities and retrieves details for the discovered capabilities.

        :return: None
        """

        # region #-- check that we're pointing to the primary node --#
        cap = self._get_mesh_capability("GET_DEVICE_MODE")
        resp: JnapResponseSingle = await cap.async_execute()
        if resp.get("mode", "").lower() != "master":
            raise MeshNodeNotPrimary
        # endregion

        # region #-- detect available capabilities --#
        await self.async_detect_capabilities()
        # endregion

        # flag here so that async_gather_details will run
        self._initialise_executed = True

        # region #-- retrieve mesh data and prepare the mesh entities --#
        self._mesh_attributes = await self.async_gather_details()

        ret_mesh_entities: list[DeviceEntity | NodeEntity] = self._build_mesh_entities(True, self._mesh_attributes)
        _remediated_devices: list[DeviceEntity | NodeEntity] = self._remediate_mesh_entities(True, ret_mesh_entities)
        self._mesh_entities = _remediated_devices
        # endregion

    async def async_ping(self) -> str | None:
        """Test to see if the mesh is reachable.

        :return: `pong` if the mesh was reachable, `None` otherwise.
        """

        ret: str | None = None
        with contextlib.suppress(
            TimeoutError, asyncio.TimeoutError, aiohttp.ClientConnectionError, aiohttp.ClientConnectorError
        ):
            resp = await self._mesh_details.session.head(
                api.jnap_url(self._mesh_details.host),
                raise_for_status=False,
                timeout=2,  # pyright:ignore[reportArgumentType] if float is passed it's classed as total
            )

            # the mesh will respond with an invalid URL as it hasn't been formatted properly
            if resp.status == 404:
                ret = "pong"

        return ret

    async def async_reboot_mesh(self, wait: bool = False) -> None:
        """Reboot the mesh.

        :param wait: `True` to wait for the reboot process to complete.
        """

        found_node: NodeEntity | None = next(
            (node for node in self.nodes if node.type == NodeType.PRIMARY),
            None,
        )

        if found_node is None:
            raise MeshDeviceNotFoundResponse

        await found_node.async_reboot(force=True, wait=wait)

    async def async_set_guest_wifi_state(self, state: bool) -> None:
        """Set the state of the guest Wi-Fi.

        The radios object is a required parameter for the API call but isn't handled in this method.
        Instead, a call is made to retrieve the existing settings and those are relayed back.  This assumes that
        a guest network has been created in the official UI.

        :param state: True to enable, False to disable

        :return: None
        """

        # get the current radio settings from the API; they may have changed
        cap: MeshCapability = self._get_mesh_capability("GET_GUEST_NETWORK_INFO")
        resp: JnapResponseSingle = await cap.async_execute()
        radios = resp.get("radios", [])

        for radio_details in radios:
            radio_details["isEnabled"] = state
            radio_details["broadcastGuestSSID"] = state

        payload = {
            "isGuestNetworkEnabled": state,
            "radios": radios,
        }
        cap = self._get_mesh_capability("SET_GUEST_NETWORK")
        await cap.async_execute(payload=payload)

    async def async_set_homekit_state(self, state: bool) -> None:
        """Set the state of the HomeKit feature.

        :param state: True to enable, False to disable

        :return: None
        """

        cap: MeshCapability = self._get_mesh_capability("SET_HOMEKIT_SETTINGS")
        await cap.async_execute(payload={"isEnabled": state})

    async def async_set_night_mode_state(self, state: NightModeState) -> None:
        """Set the state of the the night mode functionality.

        :param state: the state that night mode should be set to

        :return: None
        """

        payload: JnapPayloadSingle = {
            "Enabled": True if state != NightModeState.OFF else False,
        }
        if state != NightModeState.OFF:
            if state == NightModeState.ALWAYS:
                payload["StartingTime"] = 0
                payload["EndingTime"] = 24
            elif state == NightModeState.NIGHT_MODE:
                payload["StartingTime"] = 20
                payload["EndingTime"] = 8

        cap: MeshCapability = self._get_mesh_capability("SET_LED_NIGHT_MODE")
        await cap.async_execute(payload=payload)

    async def async_set_parental_control_state(self, state: bool) -> None:
        """Set the state of the Parental Control feature. Rules are left intact.

        :param state: True to enabled, False to disable

        :return: None
        """
        # get the current rules from the API because they may be different
        cap: MeshCapability = self._get_mesh_capability("GET_PARENTAL_CONTROL_INFO")
        resp: JnapResponseSingle = await cap.async_execute()
        rules = resp.get("rules", [])

        payload = {
            "isParentalControlEnabled": state,
            "rules": rules,
        }
        cap = self._get_mesh_capability("SET_PARENTAL_CONTROL_INFO")
        await cap.async_execute(payload=payload)

    async def async_set_scheduled_reboot_interval(self, interval: ScheduledRebootInterval) -> None:
        """Set the reboot interval for the Scheduled Reboot feature and enable it.

        :param interval: a valid interval value

        :return: None
        """

        payload: JnapPayloadSingle = {
            "isScheduledRebootEnabled": True,
            "rebootInterval": interval.value,
        }
        cap: MeshCapability = self._get_mesh_capability("SET_SCHEDULED_REBOOT_SETTINGS")
        await cap.async_execute(payload=payload)

    async def async_set_scheduled_reboot_state(self, state: bool) -> None:
        """Set the state of the Scheduled Reboot feature. Interval is left intact.

        :param state: True to enabled, False to disable

        :return: None
        """

        # get the current interval from the API because they may be different
        cap: MeshCapability = self._get_mesh_capability("GET_SCHEDULED_REBOOT_SETTINGS")
        resp: JnapResponseSingle = await cap.async_execute()

        interval: str | None = resp.get("rebootInterval")

        if interval is None:
            raise MeshException("Interval setting not found")

        payload = {
            "isScheduledRebootEnabled": state,
            "rebootInterval": interval,
        }

        cap = self._get_mesh_capability("SET_SCHEDULED_REBOOT_SETTINGS")
        await cap.async_execute(payload=payload)

    async def async_set_upnp_settings(
        self, enabled: bool, allow_change_settings: bool, allow_disable_internet: bool
    ) -> None:
        """Set the UPnP settings.

        :param enabled: True to enable UPnP, False to disable.
        :param allow_change_settings: Whether users can change settings when UPnP is enabled.
        :param allow_disable_internet: Whether users can disable the Internet when UPnP is enabled.

        :return: None
        """

        payload: JnapPayloadSingle = {
            "isUPnPEnabled": enabled,
            "canUsersConfigure": allow_change_settings,
            "canUsersDisableWANAccess": allow_disable_internet,
        }
        cap: MeshCapability = self._get_mesh_capability("SET_UPNP_SETTINGS")
        await cap.async_execute(payload=payload)

    async def async_set_wps_state(self, state: bool) -> None:
        """Set the state of the WPS feature.

        :param state: True to enable, False to disable
        """

        payload: JnapPayloadSingle = {"enabled": state}
        cap: MeshCapability = self._get_mesh_capability("SET_WPS_SERVER_SETTINGS")
        await cap.async_execute(payload=payload)

    async def async_start_channel_scan(self) -> None:
        """Start a channel scan on the mesh."""

        try:
            cap: MeshCapability = self._get_mesh_capability("START_CHANNEL_SCAN")
            await cap.async_execute()
        except MeshAlreadyInProgress as err:
            _LOGGER.debug("%s", err)

    @overload
    async def async_start_speedtest(
        self,
        *,
        wait: Literal[False] = False,
        callback_func: SpeedtestStateCallback | None = None,
    ) -> int: ...

    @overload
    async def async_start_speedtest(
        self,
        *,
        wait: Literal[True],
        callback_func: SpeedtestStateCallback | None = None,
    ) -> SpeedtestResult: ...

    @needs_initialise
    async def async_start_speedtest(
        self,
        *,
        wait: bool = False,
        callback_func: SpeedtestStateCallback | None = None,
    ) -> int | SpeedtestResult:
        """Start a Speedtest.

        A Speedtest is a long-running task. By default, this method returns after
        requesting the Speedtest. Set `wait` to true to poll until the Speedtest
        has completed.

        :param wait: Whether to wait for the Speedtest to complete before returning.
        :param callback_func: An optional synchronous or asynchronous callback invoked with each updated `SpeedtestResult` while waiting.
        The callback is not invoked when `wait` is false.
        :raises MeshInvalidOutput: if an invalid result is found.
        """

        # region #-- start the speedtest --#
        cap: MeshCapability = self._get_mesh_capability("START_SPEEDTEST")
        payload: JnapPayloadSingle = {
            "runHealthCheckModule": "SpeedTest",
        }
        resp: JnapResponseSingle = await cap.async_execute(payload=payload)
        result_id: int | None = resp.get("resultID")
        if result_id is None:
            raise MeshInvalidOutput("No result ID returned")
        # endregion

        if not wait:
            return result_id

        # region #-- wait and send progress if needed --#
        async for state in poll_with_yield(
            self.async_get_speedtest_status,
            interval=0.25,
            timeout=300.0,
        ):
            if state is None:
                break

            # the state isn't for the same speedtest
            if int(state.result_id) != result_id:
                break

            # process the callback
            if callback_func is not None:
                callback_result = callback_func(state)

                if inspect.isawaitable(callback_result):
                    await callback_result

            # must be finished
            if state.exit_code != SpeedtestExitCode.UNAVAILABLE:
                break
        # endregion

        # region #-- --#
        final_res: tuple[SpeedtestResult, ...] = await self.async_get_speedtest_result_by_id([result_id])
        if final_res:
            ret = final_res[0]
        # endregion

        return ret

    async def async_test_credentials(self) -> bool:
        """Check the provided credentials are valid.

        :return: True if valid, False if not
        """

        ret: bool = False
        payload: JnapPayloadSingle
        try:
            cap: MeshCapability = self._get_mesh_capability("CHECK_PASSWORD")
            if cap.action_version == 1:
                payload = {}
            else:
                raise MeshActionVersionNotImplemented(
                    f"{cap.action_definition.key} version {cap.action_version} has not been implemented"
                )
            await cap.async_execute(payload=payload)
            ret = True
        except MeshInvalidCredentials:
            pass
        except Exception as err:
            _LOGGER.error(err)
            raise

        return ret

    @property
    @needs_initialise
    def capabilities(self) -> tuple[ActionKey, ...]:
        """Get the list of capabilities that the Mesh supports.

        :return: mesh capabilities
        """

        ret: tuple[ActionKey, ...] = tuple(
            sorted(
                cap_key
                for cap_key, cap in self._mesh_capabilities.items()
                if cap.action_definition.purpose == ActionPurpose.GET
            )
        )

        return ret

    @property
    @needs_initialise
    def check_for_update_status(self) -> MeshAttribute[bool | None]:
        """Get the state of checking for an update as at the last time details were gathered.

        If you need the live state then use the async_get_update_state to re-query the API.

        :return: True if checking
        """

        node_results: list[dict[str, Any]] = self._mesh_attributes.get("GET_UPDATE_FIRMWARE_STATE", {}).get(
            "firmwareUpdateStatus", []
        )

        all_states = ["pendingOperation" in node for node in node_results]
        ret: bool = any(all_states)

        return MeshAttribute[bool | None](ret, (AttributeAuditEntry(Actions.GET_UPDATE_FIRMWARE_STATE.key, ret),))

    @property
    @needs_initialise
    def client_steering_enabled(self) -> MeshAttribute[bool | None]:
        """Return if client steering is enabled.

        :return: True if enabled, False otherwise.
        """

        attr: bool | None = self._mesh_attributes.get("GET_TOPOLOGY_OPTIMISATION_SETTINGS", {}).get(
            "isClientSteeringEnabled"
        )

        return MeshAttribute[bool | None](
            attr, (AttributeAuditEntry(Actions.GET_TOPOLOGY_OPTIMISATION_SETTINGS.key, attr),)
        )

    @property
    def connected_node(self) -> str:
        """Get the node in the mesh that we are connected to.

        :return: A string containing the node IP address
        """
        return self._mesh_details.host

    @property
    @needs_initialise
    def devices(self) -> tuple[DeviceEntity, ...]:
        """Get the devices in the mesh.

        The list will be returned in alphabetical order based on the device name.
        N.B. this will not include the nodes.

        :return: A list containing Device objects
        """
        ret: list[DeviceEntity] = [device for device in self._mesh_entities if isinstance(device, DeviceEntity)]
        ret = sorted(ret, key=lambda device: str(device.name))
        return tuple(ret)

    @property
    @needs_initialise
    def dhcp_enabled(self) -> MeshAttribute[bool | None]:
        """Return if DHCP is enabled.

        :return: True if enabled, False otherwise
        """

        attr: bool | None = self._mesh_attributes.get("GET_LAN_SETTINGS", {}).get("isDHCPEnabled")

        return MeshAttribute[bool | None](attr, (AttributeAuditEntry("GET_LAN_SETTINGS", attr),))

    @property
    @needs_initialise
    def dhcp_reservations(self) -> MeshAttribute[list[dict[str, str]]]:
        """Return the DHCP reservations.

        :return: list of DHCP reservation details
        """
        ret: list[dict[str, str]] = []
        temp_dict: dict[str, str] = {}

        all_reservations: list[dict[str, Any]] = (
            self._mesh_attributes.get("GET_LAN_SETTINGS", {}).get("dhcpSettings", {}).get("reservations", [])
        )

        for reservation in all_reservations:
            temp_dict = {}
            for key, details in reservation.items():
                temp_dict[camel_to_snake(key)] = details
            ret.append(temp_dict)

        return MeshAttribute[list[dict[str, str]]](ret, (AttributeAuditEntry("GET_LAN_SETTINGS", ret),))

    @property
    @needs_initialise
    def express_forwarding_enabled(self) -> MeshAttribute[bool | None]:
        """Return whether Express Forwarding is enabled.

        :return: True if enabled, False otherwise
        """

        attr: bool | None = self._mesh_attributes.get("GET_EXPRESS_FORWARDING", {}).get("isExpressForwardingEnabled")

        return MeshAttribute[bool | None](attr, (AttributeAuditEntry("GET_EXPRESS_FORWARDING", attr),))

    @property
    @needs_initialise
    def express_forwarding_supported(self) -> MeshAttribute[bool | None]:
        """Return whether Express Forwarding is supported.

        :return: True if enabled, False otherwise
        """

        attr: bool | None = self._mesh_attributes.get("GET_EXPRESS_FORWARDING", {}).get("isExpressForwardingSupported")

        return MeshAttribute[bool | None](attr, (AttributeAuditEntry("GET_EXPRESS_FORWARDING", attr),))

    @property
    @needs_initialise
    def firmware_update_setting(self) -> MeshAttribute[FirmwareUpdatePolicy | None]:
        """Get the current setting for firmware updates.

        :return: Policy used for updating firmware on the Mesh.
        """

        ret: FirmwareUpdatePolicy | None = None
        attr: str | None = self._mesh_attributes.get("GET_UPDATE_SETTINGS", {}).get("updatePolicy")
        if attr is not None:
            ret = FirmwareUpdatePolicy(attr)

        return MeshAttribute[FirmwareUpdatePolicy | None](ret, (AttributeAuditEntry("GET_UPDATE_SETTINGS", ret),))

    @property
    @needs_initialise
    def guest_wifi_enabled(self) -> MeshAttribute[bool | None]:
        """Get the state of the guest Wi-Fi.

        :return: True if enabled
        """

        attr: bool | None = self._mesh_attributes.get("GET_GUEST_NETWORK_INFO", {}).get("isGuestNetworkEnabled")

        return MeshAttribute[bool | None](attr, (AttributeAuditEntry("GET_GUEST_NETWORK_INFO", attr),))

    @property
    @needs_initialise
    def guest_wifi_details(self) -> MeshAttribute[list[dict[str, str]]]:
        """Get the guest network Wi-Fi details.

        :return: A list of dictionaries containing the SSID and band for the networks
        """

        radios: list[dict[str, str | bool]] = self._mesh_attributes.get("GET_GUEST_NETWORK_INFO", {}).get("radios", [])

        ret: list[dict[str, str]] = [
            {
                "ssid": cast(str, radio.get("guestSSID")),
                "band": cast(str, radio.get("radioID", "")).split("_")[-1],
            }
            for radio in radios
        ]
        return MeshAttribute[list[dict[str, str]]](ret, (AttributeAuditEntry("GET_GUEST_NETWORK_INFO", ret),))

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
    def homekit_enabled(self) -> MeshAttribute[bool | None]:
        """Return if the HomeKit integration is enabled.

        :return: True if enabled, False otherwise
        """

        attr: bool | None = self._mesh_attributes.get("GET_HOMEKIT_SETTINGS", {}).get("isEnabled")

        return MeshAttribute[bool | None](attr, (AttributeAuditEntry("GET_HOMEKIT_SETTINGS", attr),))

    @property
    @needs_initialise
    def homekit_paired(self) -> MeshAttribute[bool | None]:
        """Return if the HomeKit integration is paired.

        :return: True if enabled, False otherwise
        """

        attr: bool | None = self._mesh_attributes.get("GET_HOMEKIT_SETTINGS", {}).get("isPaired")

        return MeshAttribute[bool | None](attr, (AttributeAuditEntry("GET_HOMEKIT_SETTINGS", attr),))

    @property
    @needs_initialise
    def is_channel_scan_running(self) -> MeshAttribute[bool | None]:
        """Get the current state of channel scanning.

        :return: True if enabled, False otherwise
        """

        attr: bool | None = self._mesh_attributes.get("GET_CHANNEL_SCAN_STATUS", {}).get("isRunning")

        return MeshAttribute[bool | None](attr, (AttributeAuditEntry("GET_CHANNEL_SCAN_STATUS", attr),))

    @property
    @needs_initialise
    def is_in_bridge_mode(self) -> MeshAttribute[bool | None]:
        """Return whether the mesh is in bridge mode or not."""

        attr: bool = self._mesh_attributes.get("GET_WAN_INFO", {}).get("detectedWANType", "").lower() == "bridge"

        return MeshAttribute[bool | None](attr, (AttributeAuditEntry("GET_WAN_INFO", attr),))

    @property
    def last_gather_details(self) -> list[tuple[str, float]]:
        """Return some timings about when the details were gathered.

        All times are epoch and are approximate.
        """

        ret: list[tuple[str, float]] = list(self._last_gather_details.items())
        ret = sorted(ret, key=lambda itm: itm[1])
        return ret

    @property
    @needs_initialise
    def mac_filtering_addresses(self) -> MeshAttribute[list[str]]:
        """Get addresses that are configured for MAC filtering.

        :return: list of MAC addresses
        """

        attr: list[str] = self._mesh_attributes.get("GET_MAC_FILTERING_SETTINGS", {}).get("macAddresses", [])

        return MeshAttribute[list[str]](attr, (AttributeAuditEntry("GET_MAC_FILTERING_SETTINGS", attr),))

    @property
    @needs_initialise
    def mac_filtering_enabled(self) -> MeshAttribute[bool | None]:
        """Return if MAC filtering is enabled.

        :return: True if enabled, False otherwise
        """

        attr: bool = (
            self._mesh_attributes.get("GET_MAC_FILTERING_SETTINGS", {}).get("macFilterMode", "").lower() != "disabled"
        )

        return MeshAttribute[bool | None](attr, (AttributeAuditEntry("GET_MAC_FILTERING_SETTINGS", attr),))

    @property
    @needs_initialise
    def mac_filtering_mode(self) -> MeshAttribute[MacFilteringMode | None]:
        """Return the MAC filtering mode.

        :return: string containing the filtering mode
        """

        ret: MacFilteringMode | None = None
        _mode: str | None = self._mesh_attributes.get("GET_MAC_FILTERING_SETTINGS", {}).get("macFilterMode")
        if _mode is not None:
            ret = MacFilteringMode(_mode)

        return MeshAttribute[MacFilteringMode | None](ret, (AttributeAuditEntry("GET_MAC_FILTERING_SETTINGS", ret),))

    @property
    @needs_initialise
    def mlo_state(self) -> MeshAttribute[bool | None]:
        """Retrieve the state of MLO.

        :return: True if enabled, False if disabled and None if not supported.
        """

        ret: bool | None = None
        attr: dict[str, bool] | None = self._mesh_attributes.get("GET_MLO_SETTINGS")
        if attr is not None:
            ret = attr.get("isMLOEnabled")

        return MeshAttribute[bool | None](ret, (AttributeAuditEntry("GET_MLO_SETTINGS", ret),))

    @property
    @needs_initialise
    def night_mode(self) -> MeshAttribute[NightModeState | None]:
        """Return whether night mode is enabled.

        :return: True if enabled, False otherwise
        """

        ret: NightModeState | None = None
        attr: dict[str, bool | int] | None = self._mesh_attributes.get("GET_LED_NIGHT_MODE")

        if attr is not None:
            if not attr.get("Enable", False):
                ret = NightModeState.OFF
            else:
                if attr.get("StartingTime") == 0 and attr.get("EndingTime") == 24:
                    ret = NightModeState.ALWAYS
                elif attr.get("StartingTime") == 20 and attr.get("EndingTime") == 8:
                    ret = NightModeState.NIGHT_MODE

        return MeshAttribute[NightModeState | None](ret, (AttributeAuditEntry("GET_LED_NIGHT_MODE", ret),))

    @property
    @needs_initialise
    def node_steering_enabled(self) -> MeshAttribute[bool | None]:
        """Return if node steering is enabled.

        :return: True if enabled, False otherwise
        """

        attr: bool | None = self._mesh_attributes.get("GET_TOPOLOGY_OPTIMISATION_SETTINGS", {}).get(
            "isNodeSteeringEnabled"
        )

        return MeshAttribute[bool | None](attr, (AttributeAuditEntry("GET_TOPOLOGY_OPTIMISATION_SETTINGS", attr),))

    @property
    @needs_initialise
    def nodes(self) -> tuple[NodeEntity, ...]:
        """Get the nodes in the mesh.

        The return is sorted in alphabetical order based on node name.

        :return: A tuple of NodeEntity objects
        """
        ret: list[NodeEntity] = [node for node in self._mesh_entities if isinstance(node, NodeEntity)]

        ret = sorted(ret, key=lambda node: str(node.name))
        return tuple(ret)

    @property
    @needs_initialise
    def parental_control_enabled(self) -> MeshAttribute[bool | None]:
        """Get the state of the Parental Control feature.

        :return: True if enabled, False otherwise
        """

        attr: bool | None = self._mesh_attributes.get("GET_PARENTAL_CONTROL_INFO", {}).get("isParentalControlEnabled")

        return MeshAttribute[bool | None](attr, (AttributeAuditEntry("GET_PARENTAL_CONTROL_INFO", attr),))

    @property
    @needs_initialise
    def scheduled_reboot_enabled(self) -> MeshAttribute[bool | None]:
        """Get the state of the Scheduled Reboot feature.

        :return: True if enabled, False otherwise
        """

        attr: bool | None = self._mesh_attributes.get("GET_SCHEDULED_REBOOT_SETTINGS", {}).get(
            "isScheduledRebootEnabled"
        )

        return MeshAttribute[bool | None](attr, (AttributeAuditEntry("GET_SCHEDULED_REBOOT_SETTINGS", attr),))

    @property
    @needs_initialise
    def scheduled_reboot_interval(self) -> MeshAttribute[ScheduledRebootInterval | None]:
        """Get the interval for the Scheduled Reboot feature.

        :return: value representing the interval
        """

        ret: ScheduledRebootInterval | None = None
        attr: dict[str, Any] = self._mesh_attributes.get("GET_SCHEDULED_REBOOT_SETTINGS", {}).get("rebootInterval")
        if attr is not None:
            ret = ScheduledRebootInterval(attr)

        return MeshAttribute[ScheduledRebootInterval | None](
            ret, (AttributeAuditEntry("GET_SCHEDULED_REBOOT_SETTINGS", attr),)
        )

    @property
    @needs_initialise
    def sip_enabled(self) -> MeshAttribute[bool | None]:
        """Return whether SIP is enabled.

        :return: True if enabled, False otherwise
        """

        attr: bool | None = self._mesh_attributes.get("GET_ALG_SETTINGS", {}).get("isSIPEnabled")

        return MeshAttribute[bool | None](attr, (AttributeAuditEntry("GET_ALG_SETTINGS", attr),))

    @property
    @needs_initialise
    def speedtest_results(self) -> MeshAttribute[list[SpeedtestResult]]:
        """Return the available speedtest results."""

        ret: list[SpeedtestResult] = []

        speedtest_results: list[dict[str, Any]] = self._mesh_attributes.get("GET_SPEEDTEST_RESULTS", {}).get(
            "healthCheckResults", []
        )
        for res in speedtest_results:
            sres: SpeedtestResult | None = self._process_speedtest_results(res)
            if sres is not None:
                ret.append(sres)

        return MeshAttribute[list[SpeedtestResult]](ret, (AttributeAuditEntry("GET_SPEEDTEST_RESULTS", ret),))

    @property
    @needs_initialise
    def storage_available(self) -> MeshAttribute[list[dict[str, Any]]]:
        """Get available shared partitions.

        :return: List of the available storage devices and their properties
        """
        ret: list[dict[str, Any]] = []
        node: NodeEntity | None
        device: dict[str, Any]
        storage_available = self._mesh_attributes.get("GET_STORAGE_PARTITIONS", {})

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
                                    (adapter.ip for adapter in node.adapter_info.value if adapter.ip),
                                    None,
                                ),
                                "label": partition.get("label"),
                                "last_checked": storage_node.get("timestamp"),
                                "used_kb": partition.get("usedKB"),
                                "used_percent": used_percent,
                            }
                        )

        return MeshAttribute[list[dict[str, Any]]](ret, (AttributeAuditEntry("GET_STORAGE_PARTITIONS", ret),))

    @property
    @needs_initialise
    def storage_settings(self) -> MeshAttribute[dict[str, Any]]:
        """Get the settings for shared partitions.

        :return: dictionary of the storage settings
        """

        attr: dict[str, Any] = self._mesh_attributes.get("GET_STORAGE_SMB_SERVER", {})

        return MeshAttribute[dict[str, Any]](
            {"anonymous_access": attr.get("isAnonymousAccessEnabled")},
            (AttributeAuditEntry("GET_STORAGE_SMB_SERVER", attr),),
        )

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
    def upnp_enabled(self) -> MeshAttribute[bool | None]:
        """Return whether UPnP is enabled.

        :return: True if enabled, False otherwise
        """

        attr: bool | None = self._mesh_attributes.get("GET_UPNP_SETTINGS", {}).get("isUPnPEnabled")

        return MeshAttribute[bool | None](attr, (AttributeAuditEntry("GET_UPNP_SETTINGS", attr),))

    @property
    @needs_initialise
    def upnp_allow_change_settings(self) -> MeshAttribute[bool | None]:
        """Return whether users can change settings when UPnP is enabled.

        :return: True if enabled, False otherwise
        """

        attr: bool | None = self._mesh_attributes.get("GET_UPNP_SETTINGS", {}).get("canUsersConfigure")

        return MeshAttribute[bool | None](attr, (AttributeAuditEntry("GET_UPNP_SETTINGS", attr),))

    @property
    @needs_initialise
    def upnp_allow_disable_internet(self) -> MeshAttribute[bool | None]:
        """Return whether users can change disable the Internet when UPnP is enabled.

        :return: True if enabled, False otherwise
        """

        attr: bool | None = self._mesh_attributes.get("GET_UPNP_SETTINGS", {}).get("canUsersDisableWANAccess")

        return MeshAttribute[bool | None](attr, (AttributeAuditEntry("GET_UPNP_SETTINGS", attr),))

    @property
    @needs_initialise
    def wan_dns(self) -> MeshAttribute[list[str]]:
        """Get the WAN DNS servers.

        :return: A list containing the IP addresses of the WAN DNS servers
        """

        attr: dict[str, Any] = self._mesh_attributes.get("GET_WAN_INFO", {})
        ret = [val for key, val in attr.get("wanConnection", {}).items() if key.startswith("dnsServer")]

        return MeshAttribute[list[str]](ret, (AttributeAuditEntry("GET_WAN_INFO", ret),))

    @property
    @needs_initialise
    def wan_ip(self) -> MeshAttribute[str | None]:
        """Get the WAN IP address.

        :return: A string containing the IP address for the WAN
        """

        attr = self._mesh_attributes.get("GET_WAN_INFO", {}).get("wanConnection", {}).get("ipAddress")

        return MeshAttribute[str | None](attr, (AttributeAuditEntry("GET_WAN_INFO", attr),))

    @property
    @needs_initialise
    def wan_mac(self) -> MeshAttribute[str | None]:
        """Get the WAN MAC.

        :return: A string containing the MAC address for the WAN adapter
        """

        attr = self._mesh_attributes.get("GET_WAN_INFO", {}).get("macAddress")

        return MeshAttribute[str | None](attr, (AttributeAuditEntry("GET_WAN_INFO", attr),))

    @property
    @needs_initialise
    def wan_status(self) -> MeshAttribute[bool | None]:
        """Get the status of the WAN.

        :return: True if connected, False if not
        """

        attr = self._mesh_attributes.get("GET_WAN_INFO", {}).get("wanStatus", "").lower() == "connected"

        return MeshAttribute[bool | None](attr, (AttributeAuditEntry("GET_WAN_INFO", attr),))

    @property
    @needs_initialise
    def wps_state(self) -> MeshAttribute[bool | None]:
        """Return if WPS is enabled or not.

        :return: True if enabled, False otherwise
        """

        attr: bool | None = self._mesh_attributes.get("GET_WPS_SERVER_SETTINGS", {}).get("enabled")
        ret: MeshAttribute[bool | None] = MeshAttribute[bool | None](
            attr, (AttributeAuditEntry("GET_WPS_SERVER_SETTINGS", attr),)
        )

        return ret
