"""Construct the action registry for the API."""

from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from enum import IntEnum, auto
from types import MappingProxyType
from typing import Any, Literal

ActionKey = Literal[
    "CHECK_PASSWORD",
    "CLEAR_SPEEDTEST_RESULTS",
    "DELETE_DEVICE",
    "GET_ALG_SETTINGS",
    "GET_BACKHAUL",
    "GET_CHANNEL_SCAN_STATUS",
    "GET_DEVICES",
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


class ActionScope(IntEnum):
    """Possible scopes used for the actions."""

    MESH = auto()
    NODE = auto()


@dataclass(frozen=True, slots=True)
class ActionDefinition:
    """Representation of the API action."""

    key: ActionKey
    action: str
    is_capability: bool = field(default=False, kw_only=True)
    payload: dict[str, Any] = field(default_factory=dict, kw_only=True)
    redactions: set[str] = field(default_factory=set, kw_only=True)
    scope: ActionScope = field(default=ActionScope.MESH, kw_only=True)


@dataclass(slots=True)
class ActionRegistry:
    """Registry of known actions for the API."""

    _storage: dict[str, ActionDefinition]
    _frozen: bool = False

    def __init__(self, actions: Iterable[ActionDefinition]) -> None:
        """Initialise the action registry and mark as read-only."""

        _store: dict[str, ActionDefinition] = {}
        for action in actions:
            # region #-- validate the key --#
            if not action.key:
                raise ValueError("No action key has been provided, %s", action.key)
            if action.key in _store:
                raise ValueError("Duplicate action key has been provided, %s", action.key)
            if not action.key.isidentifier():
                raise ValueError("Invalid identifier supplied, %s", action.key)
            # endregion

            _store[action.key] = action

        object.__setattr__(self, "_storage", MappingProxyType(_store))
        object.__setattr__(self, "_frozen", True)

    def __getitem__(self, key: ActionKey) -> ActionDefinition:
        """Allow [] access to the registry."""

        return self._storage[key]

    def __getattr__(self, name: ActionKey) -> ActionDefinition:
        """Allow . access to the registry."""

        try:
            return self._storage[name]
        except KeyError as exc:
            raise AttributeError(name) from exc

    def __iter__(self) -> Iterator[str]:
        """Allow iteration over the registry keys."""

        return iter(self._storage)

    def __setattr__(self, name: str, value: Any) -> None:
        """Disallow updates after initialising."""

        if getattr(self, "_frozen", False):
            raise AttributeError(f"{type(self).__name__} is read-only after initialization")
        super().__setattr__(name, value)

    def items(self):
        """Return the registry items."""

        return self._storage.items()

    def keys(self):
        """Return the registry keys."""

        return self._storage.keys()

    def values(self):
        """Return the registry values."""

        return self._storage.values()


Actions: ActionRegistry = ActionRegistry(
    (
        ActionDefinition(
            "CHECK_PASSWORD",
            "http://linksys.com/jnap/core/CheckAdminPassword",
        ),
        ActionDefinition(
            "CLEAR_SPEEDTEST_RESULTS",
            "http://linksys.com/jnap/healthcheck/ClearHealthCheckHistory",
        ),
        ActionDefinition(
            "DELETE_DEVICE",
            "http://linksys.com/jnap/devicelist/DeleteDevice",
        ),
        ActionDefinition(
            "GET_ALG_SETTINGS",
            "http://linksys.com/jnap/firewall/GetALGSettings",
            is_capability=True,
        ),
        ActionDefinition(
            "GET_BACKHAUL",
            "http://linksys.com/jnap/nodes/diagnostics/GetBackhaulInfo",
            is_capability=True,
        ),
        ActionDefinition(
            "GET_CHANNEL_SCAN_STATUS",
            "http://linksys.com/jnap/nodes/setup/GetSelectedChannels",
            is_capability=True,
        ),
        ActionDefinition(
            "GET_DEVICES",
            "http://linksys.com/jnap/devicelist/GetDevices3",
            is_capability=True,
            redactions={
                "devices.connections.macAddress",
                "devices.friendlyName",  # the name identified by the Mesh
                "devices.knownInterfaces.macAddress",
                "devices.properties",  # user supplied information and cache for parental control
                "devices.unit.serialNumber",
            },
        ),
        ActionDefinition(
            "GET_EXPRESS_FORWARDING",
            "http://linksys.com/jnap/router/GetExpressForwardingSettings",
            is_capability=True,
        ),
        ActionDefinition(
            "GET_GUEST_NETWORK_INFO",
            "http://linksys.com/jnap/guestnetwork/GetGuestRadioSettings2",
            is_capability=True,
            redactions={
                "radios.guestSSID",
                "radios.guestWPAPassphrase",
            },
        ),
        ActionDefinition(
            "GET_HOMEKIT_SETTINGS",
            "http://linksys.com/jnap/homekit/GetHomeKitSettings",
            is_capability=True,
        ),
        ActionDefinition(
            "GET_LAN_SETTINGS",
            "http://linksys.com/jnap/router/GetLANSettings",
            is_capability=True,
            redactions={
                "hostName",
                "reservations",
            },
        ),
        ActionDefinition(
            "GET_LED_NIGHT_MODE",
            "http://linksys.com/jnap/routerleds/GetLedNightModeSetting",
            is_capability=True,
        ),
        ActionDefinition(
            "GET_MAC_FILTERING_SETTINGS",
            "http://linksys.com/jnap/macfilter/GetMACFilterSettings",
            is_capability=True,
            redactions={
                "macAddresses",
            },
        ),
        ActionDefinition(
            "GET_MLO_SETTINGS",
            "http://linksys.com/jnap/wirelessap/GetMLOSettings",
            is_capability=True,
        ),
        ActionDefinition(
            "GET_NETWORK_CONNECTIONS",
            "http://linksys.com/jnap/networkconnections/GetNetworkConnections2",
            scope=ActionScope.NODE,
            redactions={
                "connections.macAddress",
                "connections.wireless.bssid",
            },
        ),
        ActionDefinition(
            "GET_NODE_WIRELESS_CONNECTIONS",
            "http://linksys.com/jnap/nodes/networkconnections/GetNodesWirelessNetworkConnections",
            is_capability=True,
            redactions={
                "nodeWirelessConnections.connections.wireless.bssid",
                "nodeWirelessConnections.connections.macAddress",
            },
        ),
        ActionDefinition(
            "GET_PARENTAL_CONTROL_INFO",
            "http://linksys.com/jnap/parentalcontrol/GetParentalControlSettings",
            is_capability=True,
            redactions={
                "rules.macAddresses",
            },
        ),
        ActionDefinition(
            "GET_SCHEDULED_REBOOT_SETTINGS",
            "http://linksys.com/jnap/diagnostics/GetScheduledRebootSettings",
            is_capability=True,
        ),
        ActionDefinition(
            "GET_SPEEDTEST_RESULTS",
            "http://linksys.com/jnap/healthcheck/GetHealthCheckResults",
            is_capability=True,
            payload={
                "healthCheckModule": "SpeedTest",
                "includeModuleResults": True,
                "lastNumberOfResults": 10,
            },
        ),
        ActionDefinition(
            "GET_SPEEDTEST_STATUS",
            "http://linksys.com/jnap/healthcheck/GetHealthCheckStatus",
        ),
        ActionDefinition(
            "GET_SPEEDTEST_TYPES",
            "http://linksys.com/jnap/healthcheck/GetSupportedHealthCheckModules",
            is_capability=True,
        ),
        ActionDefinition(
            "GET_STORAGE_PARTITIONS",
            "http://linksys.com/jnap/nodes/storage/GetNodesPartitions",
            is_capability=True,
        ),
        ActionDefinition(
            "GET_STORAGE_SMB_SERVER",
            "http://linksys.com/jnap/nodes/storage/GetSMBServerSettings",
            is_capability=True,
        ),
        ActionDefinition(
            "GET_TOPOLOGY_OPTIMISATION_SETTINGS",
            "http://linksys.com/jnap/nodes/topologyoptimization/GetTopologyOptimizationSettings2",
            is_capability=True,
        ),
        ActionDefinition(
            "GET_UPDATE_FIRMWARE_STATE",
            "http://linksys.com/jnap/nodes/firmwareupdate/GetFirmwareUpdateStatus",
            is_capability=True,
        ),
        ActionDefinition(
            "GET_UPDATE_SETTINGS",
            "http://linksys.com/jnap/firmwareupdate/GetFirmwareUpdateSettings",
            is_capability=True,
        ),
        ActionDefinition(
            "GET_UPNP_SETTINGS",
            "http://linksys.com/jnap/routerupnp/GetUPnPSettings",
            is_capability=True,
        ),
        ActionDefinition(
            "GET_WAN_INFO",
            "http://linksys.com/jnap/router/GetWANStatus3",
            is_capability=True,
            redactions={
                "linkLocalIPv6Address",
                "macAddress",
                "wanConnection.dnsServer1",
                "wanConnection.dnsServer2",
                "wanConnection.dnsServer3",
                "wanConnection.gateway",
                "wanConnection.ipAddress",
            },
        ),
        ActionDefinition(
            "GET_WPS_SERVER_SETTINGS",
            "http://linksys.com/jnap/wirelessap/GetWPSServerSettings",
            is_capability=True,
        ),
        ActionDefinition(
            "REBOOT",
            "http://linksys.com/jnap/core/Reboot",
        ),
        ActionDefinition(
            "SET_DEVICE_PROPERTY",
            "http://linksys.com/jnap/devicelist/SetDeviceProperties",
        ),
        ActionDefinition(
            "SET_GUEST_NETWORK",
            "http://linksys.com/jnap/guestnetwork/SetGuestRadioSettings2",
        ),
        ActionDefinition(
            "SET_HOMEKIT_SETTINGS",
            "http://linksys.com/jnap/homekit/SetHomeKitSettings",
        ),
        ActionDefinition(
            "SET_LED_NIGHT_MODE",
            "http://linksys.com/jnap/routerleds/SetLedNightModeSetting2",
        ),
        ActionDefinition(
            "SET_PARENTAL_CONTROL_INFO",
            "http://linksys.com/jnap/parentalcontrol/SetParentalControlSettings",
        ),
        ActionDefinition(
            "SET_SCHEDULED_REBOOT_SETTINGS",
            "http://linksys.com/jnap/diagnostics/SetScheduledRebootSettings",
        ),
        ActionDefinition(
            "SET_UPNP_SETTINGS",
            "http://linksys.com/jnap/routerupnp/SetUPnPSettings",
        ),
        ActionDefinition(
            "SET_WPS_SERVER_SETTINGS",
            "http://linksys.com/jnap/wirelessap/SetWPSServerSettings",
        ),
        ActionDefinition(
            "START_CHANNEL_SCAN",
            "http://linksys.com/jnap/nodes/setup/StartAutoChannelSelection",
        ),
        ActionDefinition(
            "START_SPEEDTEST",
            "http://linksys.com/jnap/healthcheck/RunHealthCheck",
        ),
        ActionDefinition(
            "TRANSACTION",
            "http://linksys.com/jnap/core/Transaction",
        ),
        ActionDefinition(
            "UPDATE_FIRMWARE",
            "http://linksys.com/jnap/nodes/firmwareupdate/UpdateFirmwareNow",
        ),
    )
)
