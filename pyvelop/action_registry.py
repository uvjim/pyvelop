"""Construct the action registry for the API."""

import logging
from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass, field
from enum import IntEnum, IntFlag, auto
from types import MappingProxyType
from typing import Any, Literal, NamedTuple

from .logger import Logger

_LOGGER_VERBOSE: Logger = Logger(logging.getLogger(f"{__name__}.verbose"))


ActionKey = Literal[
    "CHECK_PASSWORD",
    "CLEAR_SPEEDTEST_RESULTS",
    "DELETE_DEVICE",
    "GET_ALG_SETTINGS",
    "GET_BACKHAUL",
    "GET_CHANNEL_SCAN_STATUS",
    "GET_DEVICES",
    "GET_DEVICE_INFO",
    "GET_DEVICE_MODE",
    "GET_EXPRESS_FORWARDING",
    "GET_GUEST_NETWORK_INFO",
    "GET_HOMEKIT_SETTINGS",
    "GET_LAN_SETTINGS",
    "GET_LED_NIGHT_MODE",
    "GET_MAC_FILTERING_SETTINGS",
    "GET_MLO_SETTINGS",
    "GET_NETWORK_CONNECTIONS",
    "GET_NODE_WIRELESS_CONNECTIONS",
    "GET_PARENTAL_CONTROL_INFO",
    "GET_SCHEDULED_REBOOT_SETTINGS",
    "GET_SPEEDTEST_TYPES",
    "GET_SPEEDTEST_RESULTS",
    "GET_SPEEDTEST_STATUS",
    "GET_STORAGE_PARTITIONS",
    "GET_STORAGE_SMB_SERVER",
    "GET_SYSTEM_STATS",
    "GET_TOPOLOGY_OPTIMISATION_SETTINGS",
    "GET_UPDATE_FIRMWARE_STATE",
    "GET_UPDATE_SETTINGS",
    "GET_UPNP_SETTINGS",
    "GET_WAN_INFO",
    "GET_WPS_SERVER_SETTINGS",
    "REBOOT",
    "SET_DEVICE_PROPERTY",
    "SET_GUEST_NETWORK",
    "SET_HOMEKIT_SETTINGS",
    "SET_LED_NIGHT_MODE",
    "SET_PARENTAL_CONTROL_INFO",
    "SET_SCHEDULED_REBOOT_SETTINGS",
    "SET_UPNP_SETTINGS",
    "SET_WPS_SERVER_SETTINGS",
    "START_CHANNEL_SCAN",
    "START_SPEEDTEST",
    "TRANSACTION",
    "UPDATE_FIRMWARE",
]


class ActionFeatures(IntFlag):
    """Features that allow grouping of actions."""

    DEVICE_INFO = auto()
    SPEEDTEST = auto()
    PARENTAL_CONTROL = auto()


class ActionPurpose(IntEnum):
    """Purpose of the action."""

    GET = auto()
    INVOKE = auto()
    SET = auto()


class ActionScope(IntFlag):
    """Possible scopes used for the actions."""

    DEVICE = auto()
    MESH = auto()
    NODE = auto()


class ActionVersionMap(NamedTuple):
    """Maps the service version to an action version."""

    action_version: int
    service_version: int


@dataclass(frozen=True, slots=True)
class ActionDefinition:
    """Representation of the API action.

    :param key: unique identifier for the action.
    :param action_base: the action URL without the version number.
    :param service_base: the service URL without the version number.
    :param available_in_bridge_mode: True (default) to allow usage when the mesh is in bridge mode.
    :param features: feature flags pertinent to the definition.
    :param payload: default payload to be used when sending a request.
    :param purpose: what the purpose is for the action.
    :param redactions: definition of the default redactions that should be applied when logging.
    :param scope: where the action should be targeted.
    :param version_map: definition of what action versions are available in which service.
    """

    key: ActionKey
    action_base: str
    service_base: str
    available_in_bridge_mode: bool = field(default=True, kw_only=True)
    features: ActionFeatures | None = field(default=None, kw_only=True)
    payload: dict[str, Any] = field(default_factory=dict, kw_only=True)
    purpose: ActionPurpose = field(default=ActionPurpose.GET, kw_only=True)
    redactions: set[str] = field(default_factory=set, kw_only=True)
    requires_auth: bool = field(default=True, kw_only=True)
    scope: ActionScope = field(default=ActionScope.MESH, kw_only=True)
    version_map: tuple[ActionVersionMap, ...] = field(
        default=(ActionVersionMap(action_version=1, service_version=1),), kw_only=True
    )


class ActionRegistry(Mapping[ActionKey, ActionDefinition]):
    """Read-only registry of known actions for the API."""

    __slots__ = "_storage"

    def __init__(self, actions: Iterable[ActionDefinition]) -> None:
        """Initialise the action registry and mark as read-only.

        :params actions: definitions to be added to he registry.
        """

        store: dict[ActionKey, ActionDefinition] = {}
        for action in actions:
            # region #-- validate the key --#
            if not action.key:
                raise ValueError(f"No action key has been provided, {action.key}")
            if action.key in store:
                raise ValueError(f"Duplicate action key has been provided, {action.key}")
            if not action.key.isidentifier():
                raise ValueError(f"Invalid identifier supplied, {action.key}")
            # endregion

            store[action.key] = action

        self._storage = MappingProxyType(store)

    def __getitem__(self, key: ActionKey) -> ActionDefinition:
        """Return the action definition for the given key."""

        return self._storage[key]

    def __getattr__(self, name: ActionKey) -> ActionDefinition:
        """Return the action definition for the given attribute name."""

        if name not in self._storage:
            raise AttributeError(name)

        return self._storage[name]

    def __iter__(self) -> Iterator[ActionKey]:
        """Yield the registry keys."""
        return iter(self._storage)

    def __len__(self) -> int:
        """Return the number of actions in the registry."""
        return len(self._storage)


Actions: ActionRegistry = ActionRegistry(
    (
        ActionDefinition(
            "CHECK_PASSWORD",
            "http://linksys.com/jnap/core/CheckAdminPassword",
            "http://linksys.com/jnap/core/Core",
            purpose=ActionPurpose.INVOKE,
            redactions={
                "adminPassword",  # this is added in both
            },
            requires_auth=False,
            version_map=(
                ActionVersionMap(action_version=1, service_version=1),
                # adds: expects an object to be passed in the body
                ActionVersionMap(action_version=2, service_version=2),
                ActionVersionMap(action_version=3, service_version=7),
            ),
        ),
        ActionDefinition(
            "CLEAR_SPEEDTEST_RESULTS",
            "http://linksys.com/jnap/healthcheck/ClearHealthCheckHistory",
            "http://linksys.com/jnap/healthcheck/HealthCheckManager",
            purpose=ActionPurpose.INVOKE,
        ),
        ActionDefinition(
            "DELETE_DEVICE",
            "http://linksys.com/jnap/devicelist/DeleteDevice",
            "http://linksys.com/jnap/devicelist/DeviceList",
            purpose=ActionPurpose.INVOKE,
            scope=ActionScope.DEVICE,
        ),
        ActionDefinition(
            "GET_ALG_SETTINGS",
            "http://linksys.com/jnap/firewall/GetALGSettings",
            "http://linksys.com/jnap/firewall/Firewall",
        ),
        ActionDefinition(
            "GET_BACKHAUL",
            "http://linksys.com/jnap/nodes/diagnostics/GetBackhaulInfo",
            "http://linksys.com/jnap/nodes/diagnostics/Diagnostics",
            version_map=(
                ActionVersionMap(action_version=1, service_version=1),
                # can't see a difference as yet
                ActionVersionMap(action_version=2, service_version=6),
            ),
        ),
        ActionDefinition(
            "GET_CHANNEL_SCAN_STATUS",
            "http://linksys.com/jnap/nodes/setup/GetSelectedChannels",
            "http://linksys.com/jnap/nodes/setup/Setup",
        ),
        ActionDefinition(
            "GET_DEVICE_INFO",
            "http://linksys.com/jnap/core/GetDeviceInfo",
            "http://linksys.com/jnap/core/Core",
            redactions={
                "serialNumber",
            },
            requires_auth=False,
        ),
        ActionDefinition(
            "GET_DEVICE_MODE",
            "http://linksys.com/jnap/nodes/smartmode/GetDeviceMode",
            "https://www.linksys.com/jnap/nodes/smartmode/SmartMode",
            requires_auth=False,
        ),
        ActionDefinition(
            "GET_DEVICES",
            "http://linksys.com/jnap/devicelist/GetDevices",
            "http://linksys.com/jnap/devicelist/DeviceList",
            features=ActionFeatures.DEVICE_INFO,
            redactions={
                "devices.connections.macAddress",
                "devices.friendlyName",  # the name identified by the Mesh
                "devices.knownInterfaces.macAddress",
                "devices.properties",  # user supplied information and cache for parental control
                "devices.unit.serialNumber",
            },
            version_map=(
                # don't use - seems to be missing most information
                ActionVersionMap(action_version=1, service_version=1),
                ActionVersionMap(action_version=3, service_version=4),
            ),
        ),
        ActionDefinition(
            "GET_EXPRESS_FORWARDING",
            "http://linksys.com/jnap/router/GetExpressForwardingSettings",
            "http://linksys.com/jnap/router/Router",
            version_map=(ActionVersionMap(action_version=1, service_version=6),),
        ),
        ActionDefinition(
            "GET_GUEST_NETWORK_INFO",
            "http://linksys.com/jnap/guestnetwork/GetGuestRadioSettings",
            "http://linksys.com/jnap/guestnetwork/GuestNetwork",
            redactions={
                "radios.guestSSID",
                "radios.guestWPAPassphrase",
            },
            version_map=(
                ActionVersionMap(action_version=1, service_version=1),
                # adds: isGuestNetworkEnabled
                # removes: maxSimultaneousGuests, guestPasswordRestrictions, maxSimultaneousGuestsLimit
                ActionVersionMap(action_version=2, service_version=4),
            ),
        ),
        ActionDefinition(
            "GET_HOMEKIT_SETTINGS",
            "http://linksys.com/jnap/homekit/GetHomeKitSettings",
            "http://linksys.com/jnap/homekit/HomeKit",
        ),
        ActionDefinition(
            "GET_LAN_SETTINGS",
            "http://linksys.com/jnap/router/GetLANSettings",
            "http://linksys.com/jnap/router/Router",
            features=ActionFeatures.DEVICE_INFO,
            redactions={
                "hostName",
                "dhcpSettings.reservations",
            },
        ),
        ActionDefinition(
            "GET_LED_NIGHT_MODE",
            "http://linksys.com/jnap/routerleds/GetLedNightModeSetting",
            "http://linksys.com/jnap/routerleds/RouterLEDs",
            version_map=(ActionVersionMap(action_version=1, service_version=4),),
        ),
        ActionDefinition(
            "GET_MAC_FILTERING_SETTINGS",
            "http://linksys.com/jnap/macfilter/GetMACFilterSettings",
            "http://linksys.com/jnap/macfilter/MACFilter",
            redactions={
                "macAddresses",
            },
        ),
        ActionDefinition(
            "GET_MLO_SETTINGS",
            "http://linksys.com/jnap/wirelessap/GetMLOSettings",
            "http://linksys.com/jnap/wirelessap/MultiLinkOperation",
        ),
        ActionDefinition(
            "GET_NETWORK_CONNECTIONS",
            "http://linksys.com/jnap/networkconnections/GetNetworkConnections",
            "http://linksys.com/jnap/networkconnections/NetworkConnections",
            features=ActionFeatures.DEVICE_INFO,
            scope=ActionScope.NODE,
            redactions={
                "connections.macAddress",
                "connections.wireless.bssid",
            },
            version_map=(
                ActionVersionMap(action_version=1, service_version=1),
                # adds: radioID
                ActionVersionMap(action_version=2, service_version=2),
            ),
        ),
        ActionDefinition(
            "GET_NODE_WIRELESS_CONNECTIONS",
            "http://linksys.com/jnap/nodes/networkconnections/GetNodesWirelessNetworkConnections",
            "http://linksys.com/jnap/nodes/networkconnections/NodesNetworkConnections",
            features=ActionFeatures.DEVICE_INFO,
            redactions={
                "nodeWirelessConnections.connections.wireless.bssid",
                "nodeWirelessConnections.connections.macAddress",
            },
            version_map=(
                ActionVersionMap(action_version=1, service_version=1),
                ActionVersionMap(action_version=2, service_version=2),
            ),
        ),
        ActionDefinition(
            "GET_PARENTAL_CONTROL_INFO",
            "http://linksys.com/jnap/parentalcontrol/GetParentalControlSettings",
            "http://linksys.com/jnap/parentalcontrol/ParentalControl",
            features=ActionFeatures.DEVICE_INFO | ActionFeatures.PARENTAL_CONTROL,
            redactions={
                "rules.macAddresses",
            },
            scope=ActionScope.DEVICE | ActionScope.MESH,
        ),
        ActionDefinition(
            "GET_SCHEDULED_REBOOT_SETTINGS",
            "http://linksys.com/jnap/diagnostics/GetScheduledRebootSettings",
            "http://linksys.com/jnap/diagnostics/ScheduledReboot",
        ),
        ActionDefinition(
            "GET_SPEEDTEST_RESULTS",
            "http://linksys.com/jnap/healthcheck/GetHealthCheckResults",
            "http://linksys.com/jnap/healthcheck/HealthCheckManager",
            features=ActionFeatures.SPEEDTEST,
            payload={
                "healthCheckModule": "SpeedTest",
                "includeModuleResults": True,
                "lastNumberOfResults": 1,
            },
        ),
        ActionDefinition(
            "GET_SPEEDTEST_STATUS",
            "http://linksys.com/jnap/healthcheck/GetHealthCheckStatus",
            "http://linksys.com/jnap/healthcheck/HealthCheckManager",
            features=ActionFeatures.SPEEDTEST,
        ),
        ActionDefinition(
            "GET_SPEEDTEST_TYPES",
            "http://linksys.com/jnap/healthcheck/GetSupportedHealthCheckModules",
            "http://linksys.com/jnap/healthcheck/HealthCheckManager",
        ),
        ActionDefinition(
            "GET_STORAGE_PARTITIONS",
            "http://linksys.com/jnap/nodes/storage/GetNodesPartitions",
            "http://linksys.com/jnap/nodes/storage/Storage",
        ),
        ActionDefinition(
            "GET_STORAGE_SMB_SERVER",
            "http://linksys.com/jnap/nodes/storage/GetSMBServerSettings",
            "http://linksys.com/jnap/nodes/storage/SMBServer",
        ),
        ActionDefinition(
            "GET_SYSTEM_STATS",
            "http://linksys.com/jnap/diagnostics/GetSystemStats",
            "http://linksys.com/jnap/diagnostics/Diagnostics",
            features=ActionFeatures.DEVICE_INFO,
            scope=ActionScope.NODE,
            version_map=(
                ActionVersionMap(action_version=1, service_version=1),
                # adds: CPULoad, MemoryLoad
                ActionVersionMap(action_version=2, service_version=10),
            ),
        ),
        ActionDefinition(
            "GET_TOPOLOGY_OPTIMISATION_SETTINGS",
            "http://linksys.com/jnap/nodes/topologyoptimization/GetTopologyOptimizationSettings",
            "http://linksys.com/jnap/nodes/topologyoptimization/TopologyOptimization",
            version_map=(
                ActionVersionMap(action_version=1, service_version=1),
                # adds: isNodeSteeringEnabled
                ActionVersionMap(action_version=2, service_version=2),
            ),
        ),
        ActionDefinition(
            "GET_UPDATE_FIRMWARE_STATE",
            "http://linksys.com/jnap/nodes/firmwareupdate/GetFirmwareUpdateStatus",
            "http://linksys.com/jnap/nodes/firmwareupdate/FirmwareUpdate",
        ),
        ActionDefinition(
            "GET_UPDATE_SETTINGS",
            "http://linksys.com/jnap/firmwareupdate/GetFirmwareUpdateSettings",
            "http://linksys.com/jnap/firmwareupdate/FirmwareUpdate",
        ),
        ActionDefinition(
            "GET_UPNP_SETTINGS",
            "http://linksys.com/jnap/routerupnp/GetUPnPSettings",
            "http://linksys.com/jnap/routerupnp/RouterUPnP",
        ),
        ActionDefinition(
            "GET_WAN_INFO",
            "http://linksys.com/jnap/router/GetWANStatus",
            "http://linksys.com/jnap/router/Router",
            redactions={
                "linkLocalIPv6Address",
                "macAddress",
                "wanConnection.dnsServer1",
                "wanConnection.dnsServer2",
                "wanConnection.dnsServer3",
                "wanConnection.gateway",
                "wanConnection.ipAddress",
            },
            requires_auth=False,
            version_map=(
                ActionVersionMap(action_version=1, service_version=1),
                # seems to be unknown by any of my test nodes
                ActionVersionMap(action_version=2, service_version=3),
                # adds: supportedIPv6WANTypes, supportedWANCombinations
                ActionVersionMap(action_version=3, service_version=5),
            ),
        ),
        ActionDefinition(
            "GET_WPS_SERVER_SETTINGS",
            "http://linksys.com/jnap/wirelessap/GetWPSServerSettings",
            "http://linksys.com/jnap/wirelessap/WirelessAP",
        ),
        ActionDefinition(
            "REBOOT",
            "http://linksys.com/jnap/core/Reboot",
            "http://linksys.com/jnap/core/Core",
            purpose=ActionPurpose.INVOKE,
            scope=ActionScope.NODE,
            version_map=(
                ActionVersionMap(action_version=1, service_version=1),
                ActionVersionMap(action_version=1, service_version=8),
            ),
        ),
        ActionDefinition(
            "SET_DEVICE_PROPERTY",
            "http://linksys.com/jnap/devicelist/SetDeviceProperties",
            "http://linksys.com/jnap/devicelist/DeviceList",
            purpose=ActionPurpose.SET,
            scope=ActionScope.DEVICE,
        ),
        ActionDefinition(
            "SET_GUEST_NETWORK",
            "http://linksys.com/jnap/guestnetwork/SetGuestRadioSettings",
            "http://linksys.com/jnap/guestnetwork/GuestNetwork",
            purpose=ActionPurpose.SET,
            version_map=(
                ActionVersionMap(action_version=1, service_version=1),
                ActionVersionMap(action_version=2, service_version=4),
            ),
        ),
        ActionDefinition(
            "SET_HOMEKIT_SETTINGS",
            "http://linksys.com/jnap/homekit/SetHomeKitSettings",
            "http://linksys.com/jnap/homekit/HomeKit",
            purpose=ActionPurpose.SET,
        ),
        ActionDefinition(
            "SET_LED_NIGHT_MODE",
            "http://linksys.com/jnap/routerleds/SetLedNightModeSetting",
            "http://linksys.com/jnap/routerleds/RouterLEDs",
            purpose=ActionPurpose.SET,
            version_map=(
                ActionVersionMap(action_version=1, service_version=1),
                ActionVersionMap(action_version=2, service_version=4),
            ),
        ),
        ActionDefinition(
            "SET_PARENTAL_CONTROL_INFO",
            "http://linksys.com/jnap/parentalcontrol/SetParentalControlSettings",
            "http://linksys.com/jnap/parentalcontrol/ParentalControl",
            purpose=ActionPurpose.SET,
        ),
        ActionDefinition(
            "SET_SCHEDULED_REBOOT_SETTINGS",
            "http://linksys.com/jnap/diagnostics/SetScheduledRebootSettings",
            "http://linksys.com/jnap/diagnostics/ScheduledReboot",
            purpose=ActionPurpose.SET,
        ),
        ActionDefinition(
            "SET_UPNP_SETTINGS",
            "http://linksys.com/jnap/routerupnp/SetUPnPSettings",
            "http://linksys.com/jnap/routerupnp/RouterUPnP",
            purpose=ActionPurpose.SET,
        ),
        ActionDefinition(
            "SET_WPS_SERVER_SETTINGS",
            "http://linksys.com/jnap/wirelessap/SetWPSServerSettings",
            "http://linksys.com/jnap/wirelessap/WirelessAP",
            purpose=ActionPurpose.SET,
        ),
        ActionDefinition(
            "START_CHANNEL_SCAN",
            "http://linksys.com/jnap/nodes/setup/StartAutoChannelSelection",
            "http://linksys.com/jnap/nodes/setup/Setup",
            purpose=ActionPurpose.INVOKE,
        ),
        ActionDefinition(
            "START_SPEEDTEST",
            "http://linksys.com/jnap/healthcheck/RunHealthCheck",
            "http://linksys.com/jnap/healthcheck/HealthCheckManager",
            purpose=ActionPurpose.INVOKE,
        ),
        ActionDefinition(
            "TRANSACTION",
            "http://linksys.com/jnap/core/Transaction",
            "http://linksys.com/jnap/core/Core",
            purpose=ActionPurpose.INVOKE,
        ),
        ActionDefinition(
            "UPDATE_FIRMWARE",
            "http://linksys.com/jnap/nodes/firmwareupdate/UpdateFirmwareNow",
            "http://linksys.com/jnap/nodes/firmwareupdate/FirmwareUpdate",
            purpose=ActionPurpose.INVOKE,
        ),
    )
)
