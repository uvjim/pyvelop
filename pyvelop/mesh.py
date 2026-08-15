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
from collections.abc import Coroutine, Iterable
from dataclasses import asdict, dataclass, field
from enum import StrEnum, auto
from types import MappingProxyType
from typing import Any, cast

from aiohttp import ClientSession

from . import __version__, camel_to_snake
from . import jnap as api
from .action_registry import ActionDefinition, ActionKey, ActionScope
from .exceptions import (
    MeshAlreadyInProgress,
    MeshDeviceNotFoundResponse,
    MeshException,
    MeshInvalidArguments,
    MeshInvalidCredentials,
    MeshInvalidInput,
    MeshNeedsInitialise,
)
from .mesh_attribute import AttributeAction, AttributeAuditEntry, MeshAttribute
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
        :param node_address: The node to send the request to
        :param payload: The relevant payload for the action
        :param raise_on_error: Raise an error if one is found

        :return: tuple containing the request and response objects or raises an error if need be
        """

        if payload is None:
            payload = []

        if not self.__passed_session and self._mesh_details.session.closed:  # session closed so recreate it
            self._mesh_details.session = self.__create_session()

        req = api.Request(
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
            req_resp = await req.execute(timeout=self._mesh_details.request_timeout)
        except Exception as err:
            raise err from None

        return (req, req_resp)

    async def _async_gather_details(  # noqa: C901
        self,
        capabilities: Iterable[ActionKey],
        *,
        track_time: bool = False,
    ) -> dict[str, Any]:
        """Work is done here to gather the necessary details for mesh.

        :return: A dictionary containing the relevant details.
        """

        ret: dict[str, Any] = {}
        payload: list[dict[str, Any]] = []

        # region #-- only make requests for the discovered capabilities --#
        for capability in capabilities:
            jnap_action: ActionDefinition = api.Actions[capability]
            payload.append({"action": jnap_action.action, "request": jnap_action.payload})
        # endregion

        if track_time:
            self._last_gather_details.update({"capability_gather_start": time.time()})

        responses: tuple[_ApiResponse, ...] = await asyncio.gather(
            self._async_make_request(api.Actions.TRANSACTION.action, payload=payload)
        )

        if track_time:
            self._last_gather_details.update({"capability_gather_end": time.time()})
            self._last_gather_details.update({"capability_process_start": time.time()})

        def _set_raw_value(action: str, data: api.JnapResponse | None) -> None:
            """Set the return value with all the raw data as returned by the api.

            This uses the action key to construct the return.
            """
            try:
                api_response: api.Response = api.Response(action=action, data=data)
            except MeshException as err:
                _LOGGER.debug("%s", err)
            else:
                _action: api.ActionDefinition | None = next(
                    (a for a in api.Actions.values() if a.action == action), None
                )
                if _action is not None:
                    ret[_action.key] = api_response.data

        # region #-- prepare all the capability details --#
        # this ensures that the data from a singular request or a transaction is made available
        # in the return.
        for response in responses:
            req, resp = response
            if req.action == api.Actions.TRANSACTION.action:
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

        if track_time:
            self._last_gather_details.update({"capability_process_end": time.time()})
            self._last_gather_details.update({"per_node_gather_start": time.time()})

        # region #-- action per node requests --#
        # we'll only execute actions that are  scoped to the node here
        node_actions: list[ActionDefinition] = [
            action_definition
            for action_definition in api.Actions.values()
            if action_definition.scope == ActionScope.NODE
        ]
        # establish node IP addresses - quick and dirty here because we want the information back before full processing
        nodes: list[dict[str, str]] = []
        for dev in ret.get(api.Actions.GET_DEVICES.key, {}).get("devices", []):
            if "nodeType" in dev:
                ip_addr: str | None = next((conn.get("ipAddress") for conn in dev.get("connections", [])), None)
                if ip_addr is not None:
                    nodes.append({"id": dev.get("deviceID"), "ip": ip_addr})

        requests = []
        for n in nodes:
            payload.clear()
            for na in node_actions:
                payload.append({"action": na.action, "request": na.payload})
            requests.append(
                self._async_make_request(api.Actions.TRANSACTION.action, payload=payload, node_address=n.get("ip"))
            )

        node_responses: list[_ApiResponse] = await asyncio.gather(*requests)
        # process the responses - we'll amalgamate them.
        for idx_n, n in enumerate(nodes):
            _, nr = node_responses[idx_n]
            for idx_na, na in enumerate(node_actions):
                if na.key not in ret:
                    ret[na.key] = []
                if na.key == api.Actions.GET_NETWORK_CONNECTIONS.key:
                    ret[na.key].extend(
                        [
                            {**conn, "parent_id": n.get("id")}
                            for conn in cast(
                                api.JnapResponse,
                                api.Response(na.action, cast(list[api.JnapResponse], nr.data)[idx_na]).data,
                            ).get("connections", [])
                        ]
                    )
        # endregion

        if track_time:
            self._last_gather_details.update({"per_node_gather_end": time.time()})
            self._last_gather_details.update({"process_entities_start": time.time()})

        # region #-- process mesh entities --#
        mesh_entities: list[DeviceEntity | NodeEntity] = []
        # region #-- build the properties for the mesh entity types --#
        # we'll treat the information from GET_DEVICES as our starting point.
        for entity in ret.get(api.Actions.GET_DEVICES.key, {}).get("devices", []):
            # entity_data will be used to store all the information needed to build the appropriate MeshEntity object.
            entity_data: dict[str, Any] = {}
            # stamp the gather time into each entity
            entity_data[EntityDataProperties.RESULTS_TIME] = self._last_gather_details.get("capability_gather_end")
            # all details as per the API response get added
            entity_data[EntityDataProperties.DEVICE_DETAILS] = entity
            # region #-- process additional information --#
            # this is gathered, infered and linked from other API calls
            if "nodeType" not in entity:
                # region #-- process end devices connected to the mesh --#
                # region #-- link up MAC based information --#
                dev_adapter_macs: list[str] = [
                    dev_adapter.get("macAddress") for dev_adapter in entity.get("knownInterfaces", [])
                ]
                dev_pc_schedule: list[dict[str, Any]] = []
                for dev_mac in dev_adapter_macs:
                    # region #-- get parental control details --#
                    dev_pc_schedule: list[dict[str, Any]] = []
                    for rule in ret.get(api.Actions.GET_PARENTAL_CONTROL_INFO.key, {}).get("rules", []):
                        if dev_mac in rule.get("macAddresses", []):
                            dev_pc_schedule.append(rule)
                            break
                    entity_data[EntityDataProperties.PARENTAL_CONTROLS] = dev_pc_schedule
                    # endregion

                    # region #-- get DHCP reservation info --#
                    for reservation in (
                        ret.get(api.Actions.GET_LAN_SETTINGS.key, {}).get("dhcpSettings", {}).get("reservations", [])
                    ):
                        if reservation.get("macAddress", "").lower() == dev_mac.lower():
                            entity_data[EntityDataProperties.RESERVATION_DETAILS] = reservation
                            break
                    # endregion

                    # region #-- wireless connection details --#
                    for nwc in ret.get(api.Actions.GET_NODE_WIRELESS_CONNECTIONS.key, {}).get(
                        "nodeWirelessConnections", []
                    ):
                        if (
                            connection := next(
                                (c for c in nwc.get("connections", {}) if c.get("macAddress") == dev_mac), None
                            )
                        ) is not None:
                            entity_data[EntityDataProperties.WIRELESS_CONNECTION_DETAILS] = connection
                            break
                    # endregion

                    # region #-- retrieve details from the node network connections --#
                    node_connection: dict[str, Any] | None = next(
                        (
                            conn
                            for conn in ret.get(api.Actions.GET_NETWORK_CONNECTIONS.key, [])
                            if conn.get("macAddress") == dev_mac
                        ),
                        None,
                    )
                    entity_data[EntityDataProperties.NODE_NETWORK_CONNECTIONS] = node_connection
                    # endregion
                # endregion
                # endregion
            else:
                # region #-- process nodes connected to the mesh --#
                # region #-- determine the backhaul information --#
                entity_data[EntityDataProperties.BACKHAUL] = next(
                    (
                        bi
                        for bi in ret.get(api.Actions.GET_BACKHAUL.key, {}).get("backhaulDevices", [])
                        if bi.get("deviceUUID") == entity.get("deviceID")
                    ),
                    {},
                )
                # endregion

                # region #-- calculate if there is a firmware update available --#
                entity_data[EntityDataProperties.FIRMWARE_DETAILS] = next(
                    (
                        fds
                        for fds in ret.get(api.Actions.GET_UPDATE_FIRMWARE_STATE.key, {}).get(
                            "firmwareUpdateStatus", []
                        )
                        if fds.get("deviceUUID") == entity.get("deviceID")
                    ),
                    {},
                )
                # endregion
                # endregion

            # region #-- build the MeshEntity objects --#
            if "nodeType" not in entity:
                mesh_entities.append(DeviceEntity(entity_data, self._mesh_details, self._supplementary_redactions))
            else:
                mesh_entities.append(NodeEntity(entity_data, self._mesh_details, self._supplementary_redactions))
            # endregion
        # endregion
        # endregion
        # endregion

        if track_time:
            self._last_gather_details.update({"process_entities_stop": time.time()})
            self._last_gather_details.update({"remedial_work_start": time.time()})

        # region #-- remedial work for the entities --#
        # handle information here that needs a reference to the DeviceEntity or NodeEntity.
        for node_or_device in mesh_entities:
            audit_history: list[AttributeAuditEntry] = []
            # region #-- establish the parent/child relationship for entities
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
            if isinstance(node_or_device, NodeEntity):
                # region #-- use backhaul information to set parent for a node --#
                parent_ip: str | None = node_or_device.raw_details.get(EntityDataProperties.BACKHAUL, {}).get(
                    "parentIPAddress"
                )
                if parent_ip is not None:
                    for n in mesh_entities:
                        if isinstance(n, NodeEntity):
                            nadi: AdapterInfo | None = next((adi for adi in n.adapter_info.value if adi.primary), None)
                            if nadi is not None and parent_ip == nadi.ip:
                                parent_node = n
                                break
                    audit_history.append(
                        AttributeAuditEntry(
                            EntityDataProperties.BACKHAUL.value, parent_ip, type=AttributeAction.REPLACE
                        )
                    )
                # endregion
            elif isinstance(node_or_device, DeviceEntity) and node_or_device.status:
                if not parent_node:
                    # region #-- let's look in the wireless node connections for a parent --#
                    adapter_macs: set[str] = {
                        adi.mac for adi in node_or_device.adapter_info.value if adi.mac is not None
                    }
                    if adapter_macs:
                        for nwc in ret.get(api.Actions.GET_NODE_WIRELESS_CONNECTIONS.key, {}).get(
                            "nodeWirelessConnections", []
                        ):
                            if any(pd.get("macAddress") in adapter_macs for pd in nwc.get("connections", [])):
                                parent_node = nwc.get("deviceID")
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
                    nc: dict[str, Any] | None = node_or_device.raw_details.get(
                        EntityDataProperties.NODE_NETWORK_CONNECTIONS
                    )
                    if nc is not None:
                        parent_node = nc.get("parent_id")
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
                    NodeEntity | None, next((n for n in mesh_entities if n.unique_id == parent_node), None)
                )
            if isinstance(parent_node, NodeEntity):
                node_or_device._update_parent(MeshAttribute(parent_node, tuple(audit_history)))
                if isinstance(node_or_device, DeviceEntity):
                    parent_node._update_connected_devices(node_or_device)

        # endregion

        ret[_ATTR_PROCESSED_DEVICES] = mesh_entities or []
        # endregion

        if track_time:
            self._last_gather_details.update({"remedial_work_end": time.time()})

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
        requests: list[Coroutine[Any, Any, _ApiResponse]] = []
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

        responses: list[tuple[api.Request, api.Response]] = await asyncio.gather(*requests)
        for idx, resp in enumerate(responses):
            _, jnap_response = resp
            if isinstance(jnap_response.data, dict) and "result" in jnap_response.data:
                _LOGGER.debug(
                    "capability not found: %s, response: %s",
                    possible_capabilities[idx].key,
                    jnap_response.data,
                )
                continue

            if jnap_response.action == api.Actions.GET_WAN_INFO.action:
                _is_bridge_mode = (
                    cast(dict[str, Any], jnap_response.data).get("detectedWANType", "").lower() == "bridge"
                )
            ret.add(possible_capabilities[idx].key)

        # region #-- tidy up capabilities --#
        # tidying for bridge mode is based on https://support.linksys.com/kb/article/319-en/
        capabilities_to_remove: set[ActionKey] = set()
        for resp in responses:
            if resp[0].action == api.Actions.GET_SPEEDTEST_TYPES.action:
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

        ret: list[SpeedtestResult] = []
        if resp.data is not None and not isinstance(resp.data, list):
            speedtest_results = resp.data.get("healthCheckResults", [])
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
    def firmware_update_setting(self) -> MeshAttribute[str | None]:
        """Get the current setting for firmware updates.

        :return: a lowercase string representing the update method
        """

        ret: str | None = None
        attr: dict[str, Any] | None = self._mesh_attributes.get(api.Actions.GET_UPDATE_SETTINGS.key)
        if attr is not None:
            ret = attr.get("updatePolicy", "").lower()

        return MeshAttribute[str | None](ret, (AttributeAuditEntry(api.Actions.GET_UPDATE_SETTINGS.key, ret),))

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

        speedtest_results: list[dict[str, Any]] = cast(
            dict[str, Any], self._mesh_attributes.get(api.Actions.GET_SPEEDTEST_RESULTS.key, {})
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
