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
from collections import defaultdict
from collections.abc import Coroutine, Iterable
from dataclasses import asdict, dataclass, field
from enum import StrEnum, auto
from types import MappingProxyType
from typing import Any, NamedTuple, cast

import aiohttp
from aiohttp import ClientSession

from . import __version__, camel_to_snake
from . import jnap as api
from .action_registry import ActionDefinition, ActionKey, Actions, ActionScope
from .exceptions import (
    MeshAlreadyInProgress,
    MeshDeviceNotFoundResponse,
    MeshException,
    MeshInvalidArguments,
    MeshInvalidCredentials,
    MeshInvalidCredentialsUnlikely,
    MeshInvalidInput,
    MeshNeedsInitialise,
)
from .logger import Logger
from .mesh_attribute import AttributeAction, AttributeAuditEntry, MeshAttribute
from .mesh_entity import (
    DeviceEntity,
    EntityDataProperties,
    NodeEntity,
    NodeType,
)

# endregion

type ApiReqResp = tuple[api.Request, api.Response]

_ACTION_BY_NAME: dict[str, ActionDefinition] = {action.action: action for action in Actions.values()}
_ATTR_PROCESSED_DEVICES: str = "processed_devices"
_LOGGER: Logger = Logger(logging.getLogger(__name__))
_LOGGER_VERBOSE = logging.getLogger(f"{__name__}.verbose")


class CapabilityScopedGroups(NamedTuple):
    """Representation of the groups of capabilities."""

    mesh: tuple[ActionDefinition, ...]
    node: tuple[ActionDefinition, ...]


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


@dataclass(slots=True)
class MeshDetails:
    """Details of the mesh being connected to."""

    host: str
    password: str
    request_timeout: float
    session: ClientSession
    user: str

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


def needs_initialise(func: Any) -> Any:
    """Ensure that async_initialise has been executed."""

    def wrapper(self: Mesh, *args: Any, **kwargs: Any) -> Any:
        """Wrap the required function."""
        if not self.has_initialised:
            raise MeshNeedsInitialise from None
        return func(self, *args, **kwargs)

    wrapped = functools.wraps(func)(wrapper)
    return wrapped


FeatureCapabilities: MappingProxyType[str, set[ActionKey]] = MappingProxyType(
    {
        "devices": {
            "GET_DEVICES",
            "GET_LAN_SETTINGS",
            "GET_NODE_WIRELESS_CONNECTIONS",
            "GET_PARENTAL_CONTROL_INFO",
        },
        "parental_control": {
            "GET_PARENTAL_CONTROL_INFO",
        },
        "speedtest": {
            "GET_SPEEDTEST_RESULTS",
            "GET_SPEEDTEST_STATUS",
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
        self._last_gather_details: dict[str, float] = {}
        self._mesh_attributes: dict[str, Any] = {}
        _session: ClientSession = session if session is not None else self.__create_session()
        self._mesh_details: MeshDetails = MeshDetails(
            host=node,
            password=password,
            request_timeout=request_timeout,
            session=_session,
            user=username,
        )
        self._mesh_capabilities: set[ActionKey] = set()
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

    def _build_mesh_entities(self, track_time, mesh_details: dict[str, Any]) -> list[DeviceEntity | NodeEntity]:
        """Build a list of mesh entities with the given information."""

        ret: list[DeviceEntity | NodeEntity] = []

        self._mark_time(track_time, ProcessTimerLabels.ENTITIES_PROCESS_START)
        # region #-- pre-index device ID based info --#
        backhaul_by_device_id: dict[str, Any] = {
            bi.get("deviceUUID"): bi
            for bi in mesh_details.get(api.Actions.GET_BACKHAUL.key, {}).get("backhaulDevices", [])
            if bi.get("deviceUUID")
        }
        firmware_by_device_id: dict[str, Any] = {
            fds.get("deviceUUID"): fds
            for fds in mesh_details.get(api.Actions.GET_UPDATE_FIRMWARE_STATE.key, {}).get("firmwareUpdateStatus", [])
            if fds.get("deviceUUID")
        }
        wifi_connections_by_id: dict[str, Any] = {
            nwc.get("deviceID"): nwc
            for nwc in mesh_details.get(Actions.GET_NODE_WIRELESS_CONNECTIONS.key, {}).get(
                "nodeWirelessConnections", []
            )
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
        for connection in mesh_details.get(Actions.GET_NETWORK_CONNECTIONS.key, []):
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
            for rule in mesh_details.get(Actions.GET_PARENTAL_CONTROL_INFO.key, {}).get("rules", [])
            for mac in rule.get("macAddresses", [])
        }
        # endregion

        # we'll treat the information from GET_DEVICES as our starting point.
        for entity in mesh_details.get(api.Actions.GET_DEVICES.key, {}).get("devices", []):
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
            # endregion

            # region #-- build the MeshEntity objects --#
            if "nodeType" not in entity:
                ret.append(DeviceEntity(entity_data, self._mesh_details, self._supplementary_redactions))
            else:
                ret.append(NodeEntity(entity_data, self._mesh_details, self._supplementary_redactions))
            # endregion
        self._mark_time(track_time, ProcessTimerLabels.ENTITIES_PROCESS_END)

        return ret

    def _get_nodes_from_raw(self, raw_details: dict[str, Any]) -> list[dict[str, str]]:
        """Retrieve the nodes from raw details.

        :return: list of dictionaries containing the IP and unique_id
        """

        ret: list[dict[str, str]] = []

        for device in raw_details.get(Actions.GET_DEVICES.key, {}).get("devices", []):
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

    def _mark_time(self, enabled: bool, name: ProcessTimerLabels) -> None:
        """Stamp the time into the tracking object."""

        if enabled:
            self._last_gather_details[name.value] = time.time()

    def _parse_raw_value(self, action: str, data: dict[str, Any]) -> tuple[str, Any] | None:
        """Parse the data returned by the API ready for storing."""

        try:
            response = api.Response(action, data)
        except MeshException as exc:
            _LOGGER.debug("%s", exc)
            return None

        action_definition = _ACTION_BY_NAME.get(action)

        if action_definition is None or not response.data:
            return None

        return action_definition.key, response.data[0]

    def _process_node_response(
        self, node: dict[str, str], actions: Iterable[ActionDefinition], response: ApiReqResp
    ) -> dict[str, Any]:
        """Process the node scoped results."""

        _, api_response = response
        result: dict[str, Any] = {}

        for idx, action in enumerate(actions):
            if idx >= len(api_response.data):
                break

            try:
                parsed = api.Response(
                    action.action,
                    api_response.data[idx],
                )
            except MeshException as exc:
                _LOGGER.debug("%s", exc)
                continue

            if not parsed.data:
                continue

            data = parsed.data[0]

            if action.key == Actions.GET_NETWORK_CONNECTIONS.key:
                result[action.key] = [
                    {
                        **connection,
                        "parent_id": node["id"],
                    }
                    for connection in data.get("connections", [])
                ]
            else:
                result[action.key] = data

        return result

    def _process_speedtest_results(self, results: dict[str, Any]) -> SpeedtestResult | None:
        """Build a SpeedtestResult object from the provisded results."""

        if "speedTestResult" not in results:
            raise ValueError

        result_set: dict[str, Any] | None = results.get("speedTestResult")
        if result_set is None:
            return None

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
            # check if the parent is known in GetDevices3 - assumes the first connection that has a parent is correct
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
                                EntityDataProperties.BACKHAUL.value, parent_ip, type=AttributeAction.REPLACE
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
                                type=AttributeAction.REPLACE,
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
                                    type=AttributeAction.REPLACE,
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

    def _split_capability_into_scopes(self, capabilities: Iterable[ActionKey]) -> CapabilityScopedGroups:
        """Group the given capabilities into scopes."""

        mesh: list[ActionDefinition] = []
        node: list[ActionDefinition] = []

        for capability in capabilities:
            action = Actions[capability]

            if action.scope == ActionScope.MESH:
                mesh.append(action)
            elif action.scope == ActionScope.NODE:
                node.append(action)

        return CapabilityScopedGroups(tuple(mesh), tuple(node))

    async def _async_make_request(
        self,
        action: str,
        *,
        node_address: str | None = None,
        payload: list[dict[str, Any]] | dict[str, Any] | None = None,
        raise_on_error: bool = True,
    ) -> ApiReqResp:
        """Execute the API request against the connected node.

        :param action: The JNAP action to execute
        :param node_address: The node to send the request to
        :param payload: The relevant payload for the action
        :param raise_on_error: Raise an error if one is found

        :return: tuple containing the request and response objects or raises an error if need be
        """

        if payload is None:
            payload = []

        if not self.__passed_session and self._mesh_details.session.closed:  # session closed so recreate it
            self._mesh_details.session = self.__create_session()

        req: api.Request = api.Request(
            action=action,
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
            req_resp: api.Response = await req.execute(timeout=self._mesh_details.request_timeout)
        except MeshInvalidCredentialsUnlikely as exc:
            _LOGGER.debug("!!!")
            _LOGGER.debug("!!! %s !!!", exc)
            _LOGGER.debug("!!!")
            # only seen this exception happen with a transaction so re-raise
            if req.action != api.Actions.TRANSACTION.action:
                raise MeshInvalidCredentials() from exc

            # region #-- split the transaction and retry --#
            # When this exception is seen we need to do the following: -
            # - test whether the credentials are valid or not
            # - if they're not raise the MeshInvalidCredentials exception
            # - if they're valid still then (because resending the transaction doesn't solve it): -
            #   - split the transaction up into individual requests
            #   - send all requests and wair for responses
            #   - reconstruct the response as a transaction request (the caller is likely expecting that type of response)
            _LOGGER.debug("testing creds because they may have been invalid")
            valid_creds: bool = await self.async_test_credentials()

            if not valid_creds:
                _LOGGER.debug("tested creds and they are invalid")
                raise MeshInvalidCredentials()

            _LOGGER.debug("tested creds and they are valid, retrying as separate requests")
            req_ind = [
                api.Request(
                    action=cast(dict[str, Any], pi).get("action", ""),
                    password=self._mesh_details.password,
                    payload=cast(dict[str, Any], pi).get("request", {}),
                    raise_on_error=raise_on_error,
                    session=self._mesh_details.session,
                    target=node_address or self._mesh_details.host,
                    username=self._mesh_details.user,
                    redact=self._disable_redaction is False,
                    supplementary_redactions=self._supplementary_redactions,
                ).execute()
                for pi in req.payload
            ]
            req_ind_resp: list[api.Response] = await asyncio.gather(*req_ind)
            _LOGGER.debug("rebuilding output")
            req_resp = api.Response(
                action=api.Actions.TRANSACTION.action,
                data={
                    api.Response.RESULT_KEY: "OK",
                    api.Response.DATA_KEY_TRANSACTION: [
                        {api.Response.RESULT_KEY: "OK", api.Response.DATA_KEY_SINGLE: r.data[0]} for r in req_ind_resp
                    ],
                },
            )
            _LOGGER.debug("rebuilt output")
            # endregion
        except Exception as exc:
            raise exc from None

        return (req, req_resp)

    async def _async_gather_details(
        self,
        capabilities: Iterable[ActionKey],
        *,
        track_time: bool = False,
    ) -> dict[str, Any]:
        """Work is done here to gather the necessary details from the mesh.

        :return: A dictionary containing the relevant details.
        """

        ret: dict[str, Any] = {}

        capability_scope_groups: CapabilityScopedGroups = self._split_capability_into_scopes(capabilities)

        # region #-- gather the details for the mesh scoped capabilities --#
        ret.update(await self._async_gather_mesh_details(track_time, capability_scope_groups.mesh))
        # endregion

        # region #-- action per node requests --#
        nodes: list[dict[str, str]] = self._get_nodes_from_raw(ret)
        ret.update(await self._async_gather_node_details(track_time, nodes, capability_scope_groups.node))
        # endregion

        # region #-- prepare the mesh entities --#
        mesh_entities: list[DeviceEntity | NodeEntity] = self._build_mesh_entities(track_time, ret)
        # endregion

        # region #-- remedial work for the entities --#
        mesh_entities = self._remediate_mesh_entities(track_time, mesh_entities)
        # endregion

        ret[_ATTR_PROCESSED_DEVICES] = mesh_entities or []
        # endregion

        return ret

    async def _async_gather_mesh_details(
        self, track_time: bool, capabilities: Iterable[ActionDefinition]
    ) -> dict[str, Any]:
        """Build the instructions needed to gather details from the mesh, execute and return."""

        # region #-- build and make the request --#
        self._mark_time(track_time, ProcessTimerLabels.MESH_SCOPED_GATHER_DETAILS_START)
        actions = tuple(capabilities)
        payload = [{"action": action.action, "request": action.payload} for action in actions]

        if not payload:
            return {}

        response: ApiReqResp = await self._async_make_request(
            Actions.TRANSACTION.action,
            payload=payload,
        )
        self._mark_time(track_time, ProcessTimerLabels.MESH_SCOPED_GATHER_DETAILS_END)
        # endregion

        # region #-- process the responses --#
        self._mark_time(track_time, ProcessTimerLabels.MESH_SCOPED_PROCESS_DETAILS_START)
        ret: dict[str, Any] = {}
        _, api_response = response

        for requested, data in zip(payload, api_response.data):
            parsed_data: tuple[str, Any] | None = self._parse_raw_value(requested["action"], data)
            if parsed_data is not None:
                key, value = parsed_data
                ret[key] = value
        self._mark_time(track_time, ProcessTimerLabels.MESH_SCOPED_PROCESS_DETAILS_END)
        # endregion

        return ret

    async def _async_gather_node_details(
        self, track_time: bool, nodes: Iterable[dict[str, Any]], capabilities: Iterable[ActionDefinition]
    ) -> dict[str, Any]:
        """Retrieve the details for node scoped requests."""

        def _combine_node_results(results: Iterable[dict[str, Any]]) -> dict[str, Any]:
            combined: dict[str, Any] = {}

            for result in results:
                for key, value in result.items():
                    if key == Actions.GET_NETWORK_CONNECTIONS.key:
                        combined.setdefault(key, []).extend(value)
                    else:
                        combined.setdefault(key, value)

            return combined

        # region #-- build and make the requests --#
        self._mark_time(track_time, ProcessTimerLabels.NODE_SCOPED_GATHER_DETAILS_START)
        actions = tuple(capabilities)
        nodes = tuple(nodes)
        if not actions or not nodes:
            return {}

        requests = [
            self._async_make_request(
                Actions.TRANSACTION.action,
                payload=[{"action": action.action, "request": action.payload} for action in actions],
                node_address=node["ip"],
            )
            for node in nodes
        ]

        responses = await asyncio.gather(*requests)
        self._mark_time(track_time, ProcessTimerLabels.NODE_SCOPED_GATHER_DETAILS_END)
        # endregion

        # region #-- process the responses --#
        self._mark_time(track_time, ProcessTimerLabels.NODE_SCOPED_PROCESS_DETAILS_START)
        per_node_results = [
            self._process_node_response(node, actions, response) for node, response in zip(nodes, responses)
        ]
        ret = _combine_node_results(per_node_results)
        self._mark_time(track_time, ProcessTimerLabels.NODE_SCOPED_PROCESS_DETAILS_END)
        # endregion

        return ret

    async def async_check_for_updates(self) -> None:
        """Ask the mesh to look for new versions of firmware for the nodes.

        Only a check is done.  The firmware isn't actually updated.

        :return: None
        """

        await self._async_make_request(action=api.Actions.UPDATE_FIRMWARE.action, payload={"onlyCheck": True})

    async def async_close(self) -> None:
        """Close the session to the mesh.

        :return: None
        """
        if not self.__passed_session:
            await self._mesh_details.session.close()

    async def async_clear_speedtest_results(self) -> None:
        """Clear the speedtest results."""

        await self._async_make_request(api.Actions.CLEAR_SPEEDTEST_RESULTS.action)

    async def async_detect_capabilities(self) -> set[ActionKey]:
        """Attempt to detect the capabilities of the Mesh.

        :return: list of capabilities for the mesh.
        """
        _is_bridge_mode: bool = False
        ret: set[ActionKey] = set()
        requests: list[Coroutine[Any, Any, ApiReqResp]] = []
        # Scoping is ignored here - all requests are sent to the primary node.
        # This assumes the secondary nodes will have the same capability or send an error response accordingly at a later date.
        possible_capabilities: list[ActionDefinition] = [a for a in api.Actions.values() if a.is_capability]
        for qry in possible_capabilities:
            requests.append(
                self._async_make_request(
                    action=qry.action,
                    payload=qry.payload,
                    raise_on_error=False,
                )
            )

        responses: list[ApiReqResp] = await asyncio.gather(*requests)
        for idx, resp in enumerate(responses):
            _, jnap_response = resp
            data: dict[str, Any] | None = next(iter(jnap_response.data), None)
            if data is not None:
                if "result" in data:
                    _LOGGER.debug(
                        "capability not found: %s, response: %s",
                        possible_capabilities[idx].key,
                        jnap_response.data,
                    )
                    continue

                if jnap_response.action == api.Actions.GET_WAN_INFO.action:
                    _is_bridge_mode = data.get("detectedWANType", "").lower() == "bridge"
                ret.add(possible_capabilities[idx].key)

        # region #-- tidy up capabilities --#
        # tidying for bridge mode is based on https://support.linksys.com/kb/article/319-en/
        capabilities_to_remove: set[ActionKey] = set()
        for _, resp in responses:
            data: dict[str, Any] | None = next(iter(resp.data), None)
            if data is not None:
                if resp.action == api.Actions.GET_SPEEDTEST_TYPES.action:
                    # region #-- remove speedtest related capabilities if they aren't really available --#
                    # Some seem to provide access to the underlying APIs still but the app/web UI only shows options for 3rd party testing.
                    _LOGGER.debug("establishing if speedtest is actually available")
                    healthcheck_modules: set[str] = set(data.get("supportedHealthCheckModules", []))

                    valid_onboard_speedtest: set[str] = {"SpeedTest"}
                    if valid_onboard_speedtest.isdisjoint(healthcheck_modules):
                        _LOGGER.debug("speedtest isn't really available, %s", healthcheck_modules)
                        capabilities_to_remove = capabilities_to_remove.union(
                            FeatureCapabilities.get("speedtest", set())
                        )
                    # endregion
                elif resp.action == api.Actions.GET_PARENTAL_CONTROL_INFO:
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

        self._mesh_capabilities = set(ret)
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
        resp = await self._async_gather_details([api.Actions.GET_CHANNEL_SCAN_STATUS.key])
        return resp.get(api.Actions.GET_CHANNEL_SCAN_STATUS.key)

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
            self._mesh_attributes.get(api.Actions.GET_SPEEDTEST_TYPES.key, {}).get("supportedHealthCheckModules", [])
        )

        if "SpeedTest" not in healthcheck_modules:
            raise MeshInvalidArguments

        payload = {
            **api.Actions.GET_SPEEDTEST_RESULTS.payload,
            "healthCheckModule": "SpeedTest",
            "lastNumberOfResults": count,
        }
        _, resp = await self._async_make_request(action=api.Actions.GET_SPEEDTEST_RESULTS.action, payload=payload)
        data: dict[str, Any] | None = next(iter(resp.data), None)

        ret: list[SpeedtestResult] = []
        if data is not None:
            speedtest_results = data.get("healthCheckResults", [])
            for res in speedtest_results:
                sres: SpeedtestResult | None = self._process_speedtest_results(res)
                if sres is not None:
                    ret.append(sres)
            if only_completed:
                ret = [result for result in ret if result.exit_code not in (None, SpeedtestExitCode.UNAVAILABLE)]
            if only_latest and len(ret) != 0:
                ret = [sorted(ret, key=lambda itm: itm.timestamp, reverse=True)][0]

        return ret

    @needs_initialise
    async def async_get_speedtest_state(self) -> SpeedtestResult | None:
        """Return details about the current stage of a Speedtest.

        :return: Details about the current stage of the Speedtest.
        """

        ret: SpeedtestResult | None = None
        resp = await self._async_gather_details([api.Actions.GET_SPEEDTEST_STATUS.key])
        result: dict[str, Any] = resp.get(api.Actions.GET_SPEEDTEST_STATUS.key, {})
        if result:
            ret = self._process_speedtest_results(resp.get(api.Actions.GET_SPEEDTEST_STATUS.key, {}))

        return ret

    async def async_get_update_state(self) -> bool:
        """Get the state of the running check for updates.

        :return: True if still running, False if not
        """

        resp = await self._async_gather_details([api.Actions.GET_UPDATE_FIRMWARE_STATE.key])

        node_results = resp.get(api.Actions.GET_UPDATE_FIRMWARE_STATE.key, {}).get("firmwareUpdateStatus", [])
        all_states = ["pendingOperation" in node for node in node_results]

        ret: bool = any(all_states)

        return ret

    async def async_get_upnp_state(self) -> dict[str, bool]:
        """Retrieve the current state of UPnP.

        :return: dictionary containing information about the state of UPnP functionality
        """

        resp = await self._async_gather_details([api.Actions.GET_UPNP_SETTINGS.key])

        ret = cast(dict[str, bool], resp.get(api.Actions.GET_UPNP_SETTINGS.key, {}))

        return ret

    async def async_initialise(self) -> None:
        """Initialise the connection to the Mesh.

        Probes for capabilities and retrieves details for the discovered capabilities.

        :return: None
        """

        await self.async_detect_capabilities()
        self._initialise_executed = True  # flag here so that async_gather_details will run
        await self.async_gather_details()

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
            if resp.status == 404:  # the mesh will respond with an invalid URL as it hasn't been formatted properly
                ret = "pong"

        return ret

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
        resp = await self._async_gather_details([api.Actions.GET_GUEST_NETWORK_INFO.key])
        radios = resp.get(api.Actions.GET_GUEST_NETWORK_INFO.key, {}).get("radios", [])

        for radio_details in radios:
            radio_details["isEnabled"] = state
            radio_details["broadcastGuestSSID"] = state

        payload = {
            "isGuestNetworkEnabled": state,
            "radios": radios,
        }
        await self._async_make_request(action=api.Actions.SET_GUEST_NETWORK.action, payload=payload)

    async def async_set_homekit_state(self, state: bool) -> None:
        """Set the state of the HomeKit feature.

        :param state: True to enable, False to disable

        :return: None
        """
        await self._async_make_request(action=api.Actions.SET_HOMEKIT_SETTINGS.action, payload={"isEnabled": state})

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

        await self._async_make_request(action=api.Actions.SET_LED_NIGHT_MODE.action, payload=payload)

    async def async_set_parental_control_state(self, state: bool) -> None:
        """Set the state of the Parental Control feature. Rules are left intact.

        :param state: True to enabled, False to disable

        :return: None
        """
        # get the current rules from the API because they may be different
        resp = await self._async_gather_details([api.Actions.GET_PARENTAL_CONTROL_INFO.key])
        rules = resp.get("rules", [])

        payload = {
            "isParentalControlEnabled": state,
            "rules": rules,
        }
        await self._async_make_request(action=api.Actions.SET_PARENTAL_CONTROL_INFO.action, payload=payload)

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
            action=api.Actions.SET_SCHEDULED_REBOOT_SETTINGS.action,
            payload=payload,
        )

    async def async_set_scheduled_reboot_state(self, state: bool) -> None:
        """Set the state of the Scheduled Reboot feature. Interval is left intact.

        :param state: True to enabled, False to disable

        :return: None
        """

        # get the current interval from the API because they may be different
        resp = await self._async_gather_details([api.Actions.GET_SCHEDULED_REBOOT_SETTINGS.key])

        interval: str | None = resp.get(api.Actions.GET_SCHEDULED_REBOOT_SETTINGS.key, {}).get("rebootInterval")

        if interval is None:
            raise MeshException("Interval setting not found")

        payload = {
            "isScheduledRebootEnabled": state,
            "rebootInterval": interval,
        }
        await self._async_make_request(
            action=api.Actions.SET_SCHEDULED_REBOOT_SETTINGS.action,
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
        await self._async_make_request(action=api.Actions.SET_UPNP_SETTINGS.action, payload=payload)

    async def async_set_wps_state(self, state: bool) -> None:
        """Set the state of the WPS feature.

        :param state: True to enable, False to disable

        :return: None
        """

        await self._async_make_request(action=api.Actions.SET_WPS_SERVER_SETTINGS.action, payload={"enabled": state})

    async def async_start_channel_scan(self) -> None:
        """Start a channel scan on the mesh.

        :return: None
        """

        try:
            await self._async_make_request(action=api.Actions.START_CHANNEL_SCAN.action)
        except MeshAlreadyInProgress as err:
            _LOGGER.debug("%s", err)
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
            self._mesh_attributes.get(api.Actions.GET_SPEEDTEST_TYPES.key, {}).get("supportedHealthCheckModules", [])
        )

        if "SpeedTest" not in healthcheck_modules:
            raise MeshInvalidArguments

        payload: dict[str, Any] = {"runHealthCheckModule": "SpeedTest"}

        await self._async_make_request(action=api.Actions.START_SPEEDTEST.action, payload=payload)

    async def async_test_credentials(self) -> bool:
        """Check the provided credentials are valid.

        :return: True if valid, False if not
        """

        ret: bool = False
        try:
            await self._async_make_request(action=api.Actions.CHECK_PASSWORD.action)
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
    def capabilities(self) -> set[ActionKey]:
        """Get the list of capabilities that the Mesh supports.

        :return: list of mesh capabilities
        """
        return self._mesh_capabilities

    @property
    @needs_initialise
    def check_for_update_status(self) -> MeshAttribute[bool | None]:
        """Get the state of checking for an update as at the last time details were gathered.

        If you need the live state then use the async_get_update_state to re-query the API.

        :return: True if checking
        """

        node_results: list[dict[str, Any]] = self._mesh_attributes.get(
            api.Actions.GET_UPDATE_FIRMWARE_STATE.key, {}
        ).get("firmwareUpdateStatus", [])

        all_states = ["pendingOperation" in node for node in node_results]
        ret: bool = any(all_states)

        return MeshAttribute[bool | None](ret, (AttributeAuditEntry(api.Actions.GET_UPDATE_FIRMWARE_STATE.key, ret),))

    @property
    @needs_initialise
    def client_steering_enabled(self) -> MeshAttribute[bool | None]:
        """Return if client steering is enabled.

        :return: True if enabled, False otherwise.
        """

        attr: bool | None = self._mesh_attributes.get(api.Actions.GET_TOPOLOGY_OPTIMISATION_SETTINGS.key, {}).get(
            "isClientSteeringEnabled"
        )

        return MeshAttribute[bool | None](
            attr, (AttributeAuditEntry(api.Actions.GET_TOPOLOGY_OPTIMISATION_SETTINGS.key, attr),)
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
        ret: list[DeviceEntity] = [
            device
            for device in self._mesh_attributes.get(_ATTR_PROCESSED_DEVICES, [])
            if isinstance(device, DeviceEntity)
        ]
        ret = sorted(ret, key=lambda device: str(device.name))
        return tuple(ret)

    @property
    @needs_initialise
    def dhcp_enabled(self) -> MeshAttribute[bool | None]:
        """Return if DHCP is enabled.

        :return: True if enabled, False otherwise
        """

        attr: bool | None = self._mesh_attributes.get(api.Actions.GET_LAN_SETTINGS.key, {}).get("isDHCPEnabled")

        return MeshAttribute[bool | None](attr, (AttributeAuditEntry(api.Actions.GET_LAN_SETTINGS.key, attr),))

    @property
    @needs_initialise
    def dhcp_reservations(self) -> MeshAttribute[list[dict[str, str]]]:
        """Return the DHCP reservations.

        :return: list of DHCP reservation details
        """
        ret: list[dict[str, str]] = []
        temp_dict: dict[str, str] = {}

        all_reservations: list[dict[str, Any]] = (
            self._mesh_attributes.get(api.Actions.GET_LAN_SETTINGS.key, {})
            .get("dhcpSettings", {})
            .get("reservations", [])
        )

        for reservation in all_reservations:
            temp_dict = {}
            for key, details in reservation.items():
                temp_dict[camel_to_snake(key)] = details
            ret.append(temp_dict)

        return MeshAttribute[list[dict[str, str]]](ret, (AttributeAuditEntry(api.Actions.GET_LAN_SETTINGS.key, ret),))

    @property
    @needs_initialise
    def express_forwarding_enabled(self) -> MeshAttribute[bool | None]:
        """Return whether Express Forwarding is enabled.

        :return: True if enabled, False otherwise
        """

        attr: bool | None = self._mesh_attributes.get(api.Actions.GET_EXPRESS_FORWARDING.key, {}).get(
            "isExpressForwardingEnabled"
        )

        return MeshAttribute[bool | None](attr, (AttributeAuditEntry(api.Actions.GET_EXPRESS_FORWARDING.key, attr),))

    @property
    @needs_initialise
    def express_forwarding_supported(self) -> MeshAttribute[bool | None]:
        """Return whether Express Forwarding is supported.

        :return: True if enabled, False otherwise
        """

        attr: bool | None = self._mesh_attributes.get(api.Actions.GET_EXPRESS_FORWARDING.key, {}).get(
            "isExpressForwardingSupported"
        )

        return MeshAttribute[bool | None](attr, (AttributeAuditEntry(api.Actions.GET_EXPRESS_FORWARDING.key, attr),))

    @property
    @needs_initialise
    def firmware_update_setting(self) -> MeshAttribute[FirmwareUpdatePolicy | None]:
        """Get the current setting for firmware updates.

        :return: Policy used for updating firmware on the Mesh.
        """

        ret: FirmwareUpdatePolicy | None = None
        attr: str | None = self._mesh_attributes.get(api.Actions.GET_UPDATE_SETTINGS.key, {}).get("updatePolicy")
        if attr is not None:
            ret = FirmwareUpdatePolicy(attr)

        return MeshAttribute[FirmwareUpdatePolicy | None](
            ret, (AttributeAuditEntry(api.Actions.GET_UPDATE_SETTINGS.key, ret),)
        )

    @property
    @needs_initialise
    def guest_wifi_enabled(self) -> MeshAttribute[bool | None]:
        """Get the state of the guest Wi-Fi.

        :return: True if enabled
        """

        attr: bool | None = self._mesh_attributes.get(api.Actions.GET_GUEST_NETWORK_INFO.key, {}).get(
            "isGuestNetworkEnabled"
        )

        return MeshAttribute[bool | None](attr, (AttributeAuditEntry(api.Actions.GET_GUEST_NETWORK_INFO.key, attr),))

    @property
    @needs_initialise
    def guest_wifi_details(self) -> MeshAttribute[list[dict[str, str]]]:
        """Get the guest network Wi-Fi details.

        :return: A list of dictionaries containing the SSID and band for the networks
        """

        radios: list[dict[str, str | bool]] = self._mesh_attributes.get(api.Actions.GET_GUEST_NETWORK_INFO.key, {}).get(
            "radios", []
        )

        ret: list[dict[str, str]] = [
            {
                "ssid": cast(str, radio.get("guestSSID")),
                "band": cast(str, radio.get("radioID", "")).split("_")[-1],
            }
            for radio in radios
        ]
        return MeshAttribute[list[dict[str, str]]](
            ret, (AttributeAuditEntry(api.Actions.GET_GUEST_NETWORK_INFO.key, ret),)
        )

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

        attr: bool | None = self._mesh_attributes.get(api.Actions.GET_HOMEKIT_SETTINGS.key, {}).get("isEnabled")

        return MeshAttribute[bool | None](attr, (AttributeAuditEntry(api.Actions.GET_HOMEKIT_SETTINGS.key, attr),))

    @property
    @needs_initialise
    def homekit_paired(self) -> MeshAttribute[bool | None]:
        """Return if the HomeKit integration is paired.

        :return: True if enabled, False otherwise
        """

        attr: bool | None = self._mesh_attributes.get(api.Actions.GET_HOMEKIT_SETTINGS.key, {}).get("isPaired")

        return MeshAttribute[bool | None](attr, (AttributeAuditEntry(api.Actions.GET_HOMEKIT_SETTINGS.key, attr),))

    @property
    @needs_initialise
    def is_channel_scan_running(self) -> MeshAttribute[bool | None]:
        """Get the current state of channel scanning.

        :return: True if enabled, False otherwise
        """

        attr: bool | None = self._mesh_attributes.get(api.Actions.GET_CHANNEL_SCAN_STATUS.key, {}).get("isRunning")

        return MeshAttribute[bool | None](attr, (AttributeAuditEntry(api.Actions.GET_CHANNEL_SCAN_STATUS.key, attr),))

    @property
    @needs_initialise
    def is_in_bridge_mode(self) -> MeshAttribute[bool | None]:
        """Return whether the mesh is in bridge mode or not."""

        attr: bool = (
            self._mesh_attributes.get(api.Actions.GET_WAN_INFO.key, {}).get("detectedWANType", "").lower() == "bridge"
        )

        return MeshAttribute[bool | None](attr, (AttributeAuditEntry(api.Actions.GET_WAN_INFO.key, attr),))

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

        attr: list[str] = self._mesh_attributes.get(api.Actions.GET_MAC_FILTERING_SETTINGS.key, {}).get(
            "macAddresses", []
        )

        return MeshAttribute[list[str]](attr, (AttributeAuditEntry(api.Actions.GET_MAC_FILTERING_SETTINGS.key, attr),))

    @property
    @needs_initialise
    def mac_filtering_enabled(self) -> MeshAttribute[bool | None]:
        """Return if MAC filtering is enabled.

        :return: True if enabled, False otherwise
        """

        attr: bool = (
            self._mesh_attributes.get(api.Actions.GET_MAC_FILTERING_SETTINGS.key, {}).get("macFilterMode", "").lower()
            != "disabled"
        )

        return MeshAttribute[bool | None](
            attr, (AttributeAuditEntry(api.Actions.GET_MAC_FILTERING_SETTINGS.key, attr),)
        )

    @property
    @needs_initialise
    def mac_filtering_mode(self) -> MeshAttribute[MacFilteringMode | None]:
        """Return the MAC filtering mode.

        :return: string containing the filtering mode
        """

        ret: MacFilteringMode | None = None
        _mode: str | None = self._mesh_attributes.get(api.Actions.GET_MAC_FILTERING_SETTINGS.key, {}).get(
            "macFilterMode"
        )
        if _mode is not None:
            ret = MacFilteringMode(_mode)

        return MeshAttribute[MacFilteringMode | None](
            ret, (AttributeAuditEntry(api.Actions.GET_MAC_FILTERING_SETTINGS.key, ret),)
        )

    @property
    @needs_initialise
    def mlo_state(self) -> MeshAttribute[bool | None]:
        """Retrieve the state of MLO.

        :return: True if enabled, False if disabled and None if not supported.
        """

        ret: bool | None = None
        attr: dict[str, bool] | None = self._mesh_attributes.get(api.Actions.GET_MLO_SETTINGS.key)
        if attr is not None:
            ret = attr.get("isMLOEnabled")

        return MeshAttribute[bool | None](ret, (AttributeAuditEntry(api.Actions.GET_MLO_SETTINGS.key, ret),))

    @property
    @needs_initialise
    def night_mode(self) -> MeshAttribute[NightModeState | None]:
        """Return whether night mode is enabled.

        :return: True if enabled, False otherwise
        """

        ret: NightModeState | None = None
        attr: dict[str, bool | int] | None = self._mesh_attributes.get(api.Actions.GET_LED_NIGHT_MODE.key)

        if attr is not None:
            if not attr.get("Enable", False):
                ret = NightModeState.OFF
            else:
                if attr.get("StartingTime") == 0 and attr.get("EndingTime") == 24:
                    ret = NightModeState.ALWAYS
                elif attr.get("StartingTime") == 20 and attr.get("EndingTime") == 8:
                    ret = NightModeState.NIGHT_MODE

        return MeshAttribute[NightModeState | None](
            ret, (AttributeAuditEntry(api.Actions.GET_LED_NIGHT_MODE.key, ret),)
        )

    @property
    @needs_initialise
    def node_steering_enabled(self) -> MeshAttribute[bool | None]:
        """Return if node steering is enabled.

        :return: True if enabled, False otherwise
        """

        attr: bool | None = self._mesh_attributes.get(api.Actions.GET_TOPOLOGY_OPTIMISATION_SETTINGS.key, {}).get(
            "isNodeSteeringEnabled"
        )

        return MeshAttribute[bool | None](
            attr, (AttributeAuditEntry(api.Actions.GET_TOPOLOGY_OPTIMISATION_SETTINGS.key, attr),)
        )

    @property
    @needs_initialise
    def nodes(self) -> tuple[NodeEntity, ...]:
        """Get the nodes in the mesh.

        The return is sorted in alphabetical order based on node name.

        :return: A tuple of NodeEntity objects
        """
        ret: list[NodeEntity] = [
            node for node in self._mesh_attributes.get(_ATTR_PROCESSED_DEVICES, []) if isinstance(node, NodeEntity)
        ]

        ret = sorted(ret, key=lambda node: str(node.name))
        return tuple(ret)

    @property
    @needs_initialise
    def parental_control_enabled(self) -> MeshAttribute[bool | None]:
        """Get the state of the Parental Control feature.

        :return: True if enabled, False otherwise
        """

        attr: bool | None = self._mesh_attributes.get(api.Actions.GET_PARENTAL_CONTROL_INFO.key, {}).get(
            "isParentalControlEnabled"
        )

        return MeshAttribute[bool | None](attr, (AttributeAuditEntry(api.Actions.GET_PARENTAL_CONTROL_INFO.key, attr),))

    @property
    @needs_initialise
    def scheduled_reboot_enabled(self) -> MeshAttribute[bool | None]:
        """Get the state of the Scheduled Reboot feature.

        :return: True if enabled, False otherwise
        """

        attr: bool | None = self._mesh_attributes.get(api.Actions.GET_SCHEDULED_REBOOT_SETTINGS.key, {}).get(
            "isScheduledRebootEnabled"
        )

        return MeshAttribute[bool | None](
            attr, (AttributeAuditEntry(api.Actions.GET_SCHEDULED_REBOOT_SETTINGS.key, attr),)
        )

    @property
    @needs_initialise
    def scheduled_reboot_interval(self) -> MeshAttribute[ScheduledRebootInterval | None]:
        """Get the interval for the Scheduled Reboot feature.

        :return: value representing the interval
        """

        ret: ScheduledRebootInterval | None = None
        attr: dict[str, Any] = self._mesh_attributes.get(api.Actions.GET_SCHEDULED_REBOOT_SETTINGS.key, {}).get(
            "rebootInterval"
        )
        if attr is not None:
            ret = ScheduledRebootInterval(attr)

        return MeshAttribute[ScheduledRebootInterval | None](
            ret, (AttributeAuditEntry(api.Actions.GET_SCHEDULED_REBOOT_SETTINGS.key, attr),)
        )

    @property
    @needs_initialise
    def sip_enabled(self) -> MeshAttribute[bool | None]:
        """Return whether SIP is enabled.

        :return: True if enabled, False otherwise
        """

        attr: bool | None = self._mesh_attributes.get(api.Actions.GET_ALG_SETTINGS.key, {}).get("isSIPEnabled")

        return MeshAttribute[bool | None](attr, (AttributeAuditEntry(api.Actions.GET_ALG_SETTINGS.key, attr),))

    @property
    @needs_initialise
    def speedtest_results(self) -> MeshAttribute[list[SpeedtestResult]]:
        """Return the available speedtest results."""

        ret: list[SpeedtestResult] = []

        speedtest_results: list[dict[str, Any]] = self._mesh_attributes.get(
            api.Actions.GET_SPEEDTEST_RESULTS.key, {}
        ).get("healthCheckResults", [])
        for res in speedtest_results:
            sres: SpeedtestResult | None = self._process_speedtest_results(res)
            if sres is not None:
                ret.append(sres)

        return MeshAttribute[list[SpeedtestResult]](
            ret, (AttributeAuditEntry(api.Actions.GET_SPEEDTEST_RESULTS.key, ret),)
        )

    @property
    @needs_initialise
    def storage_available(self) -> MeshAttribute[list[dict[str, Any]]]:
        """Get available shared partitions.

        :return: List of the available storage devices and their properties
        """
        ret: list[dict[str, Any]] = []
        node: NodeEntity | None
        device: dict[str, Any]
        storage_available = self._mesh_attributes.get(api.Actions.GET_STORAGE_PARTITIONS.key, {})

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

        return MeshAttribute[list[dict[str, Any]]](
            ret, (AttributeAuditEntry(api.Actions.GET_STORAGE_PARTITIONS.key, ret),)
        )

    @property
    @needs_initialise
    def storage_settings(self) -> MeshAttribute[dict[str, Any]]:
        """Get the settings for shared partitions.

        :return: dictionary of the storage settings
        """

        attr: dict[str, Any] = self._mesh_attributes.get(
            api.Actions.GET_STORAGE_SMB_SERVER.key,
            {},
        )

        return MeshAttribute[dict[str, Any]](
            {"anonymous_access": attr.get("isAnonymousAccessEnabled")},
            (AttributeAuditEntry(api.Actions.GET_STORAGE_SMB_SERVER.key, attr),),
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

        attr: bool | None = self._mesh_attributes.get(api.Actions.GET_UPNP_SETTINGS.key, {}).get("isUPnPEnabled")

        return MeshAttribute[bool | None](attr, (AttributeAuditEntry(api.Actions.GET_UPNP_SETTINGS.key, attr),))

    @property
    @needs_initialise
    def upnp_allow_change_settings(self) -> MeshAttribute[bool | None]:
        """Return whether users can change settings when UPnP is enabled.

        :return: True if enabled, False otherwise
        """

        attr: bool | None = self._mesh_attributes.get(api.Actions.GET_UPNP_SETTINGS.key, {}).get("canUsersConfigure")

        return MeshAttribute[bool | None](attr, (AttributeAuditEntry(api.Actions.GET_UPNP_SETTINGS.key, attr),))

    @property
    @needs_initialise
    def upnp_allow_disable_internet(self) -> MeshAttribute[bool | None]:
        """Return whether users can change disable the Internet when UPnP is enabled.

        :return: True if enabled, False otherwise
        """

        attr: bool | None = self._mesh_attributes.get(api.Actions.GET_UPNP_SETTINGS.key, {}).get(
            "canUsersDisableWANAccess"
        )

        return MeshAttribute[bool | None](attr, (AttributeAuditEntry(api.Actions.GET_UPNP_SETTINGS.key, attr),))

    @property
    @needs_initialise
    def wan_dns(self) -> MeshAttribute[list[str]]:
        """Get the WAN DNS servers.

        :return: A list containing the IP addresses of the WAN DNS servers
        """

        attr: dict[str, Any] = self._mesh_attributes.get(api.Actions.GET_WAN_INFO.key, {})
        ret = [val for key, val in attr.get("wanConnection", {}).items() if key.startswith("dnsServer")]

        return MeshAttribute[list[str]](ret, (AttributeAuditEntry(api.Actions.GET_WAN_INFO.key, ret),))

    @property
    @needs_initialise
    def wan_ip(self) -> MeshAttribute[str | None]:
        """Get the WAN IP address.

        :return: A string containing the IP address for the WAN
        """

        attr = self._mesh_attributes.get(api.Actions.GET_WAN_INFO.key, {}).get("wanConnection", {}).get("ipAddress")

        return MeshAttribute[str | None](attr, (AttributeAuditEntry(api.Actions.GET_WAN_INFO.key, attr),))

    @property
    @needs_initialise
    def wan_mac(self) -> MeshAttribute[str | None]:
        """Get the WAN MAC.

        :return: A string containing the MAC address for the WAN adapter
        """

        attr = self._mesh_attributes.get(api.Actions.GET_WAN_INFO.key, {}).get("macAddress")

        return MeshAttribute[str | None](attr, (AttributeAuditEntry(api.Actions.GET_WAN_INFO.key, attr),))

    @property
    @needs_initialise
    def wan_status(self) -> MeshAttribute[bool | None]:
        """Get the status of the WAN.

        :return: True if connected, False if not
        """

        attr = self._mesh_attributes.get(api.Actions.GET_WAN_INFO.key, {}).get("wanStatus", "").lower() == "connected"

        return MeshAttribute[bool | None](attr, (AttributeAuditEntry(api.Actions.GET_WAN_INFO.key, attr),))

    @property
    @needs_initialise
    def wps_state(self) -> MeshAttribute[bool | None]:
        """Return if WPS is enabled or not.

        :return: True if enabled, False otherwise
        """

        attr: bool | None = self._mesh_attributes.get(api.Actions.GET_WPS_SERVER_SETTINGS.key, {}).get("enabled")
        ret: MeshAttribute[bool | None] = MeshAttribute[bool | None](
            attr, (AttributeAuditEntry(api.Actions.GET_WPS_SERVER_SETTINGS.key, attr),)
        )

        return ret
