"""Interact with the JNAP API."""

# region #-- imports --#
from __future__ import annotations

import base64
import copy
import json
import logging
from typing import Any, cast

import aiohttp

from .action_registry import ActionDefinition, ActionRegistry, ActionScope
from .exceptions import (
    MeshAlreadyInProgress,
    MeshBadResponse,
    MeshCannotDeleteDevice,
    MeshConnectionError,
    MeshDeviceDbFailure,
    MeshException,
    MeshInvalidCredentials,
    MeshInvalidInput,
    MeshInvalidOutput,
    MeshNodeNotPrimary,
    MeshTimeoutError,
)
from .logger import Logger

# endregion

type JnapResponse = dict[str, Any]

_LOGGER = logging.getLogger(__name__)
_LOGGER_VERBOSE = logging.getLogger(f"{__name__}.verbose")


def jnap_url(target: str) -> str:
    """Return the URL that should be used for the request.

    :param target: the API host
    :return: string containing the base URL for all JNAP requests
    """
    return f"http://{target}/JNAP/"


class Request:
    """Represents a request for the API."""

    def __init__(
        self,
        action: str,
        password: str,
        target: str,
        payload: list[dict[str, Any]] | dict[str, Any] | None = None,
        raise_on_error: bool = True,
        session: aiohttp.ClientSession | None = None,
        username: str = "admin",
        redact: bool = True,
        supplementary_redactions: dict[str, set[str]] | None = None,
    ) -> None:
        """Initialise a request.

        :param action: the JNAP action to carry out
        :param password: the password required to communicate with the target
        :param target: the node to send the request to
        :param payload: the additional configuration to pass along with the action
        :param raise_on_error: raise an error if one is found
        :param session: an existing session to use
        :param username: the username required to communicate with the target
        """
        self._action: str = action
        self._creds: str = base64.b64encode(bytes(f"{username}:{password}", "utf-8")).decode("ascii")
        self._log_formatter = Logger(prefix=f"{self.__class__.__name__}.")
        self._payload: list[dict[str, Any]] | dict[str, Any] | None = payload
        self._raise_on_error: bool = raise_on_error
        self._redact: bool = redact
        self._session: aiohttp.ClientSession = (
            session if session is not None else aiohttp.ClientSession(raise_for_status=True)
        )
        self._supplementary_redactions: dict[str, set[str]] = supplementary_redactions or {}

        if self._payload is None:
            self._payload = []
        self._jnap_url: str = jnap_url(target=target)

    async def execute(self, timeout: float = 10) -> Response:
        """Send the request.

        :param timeout: the timeout in seconds for the request, defaults to 10s
        :return: a Response object representing the returned results
        """

        def _build_redactions(key: str) -> set[str]:

            ret: set[str] = set()
            default_redactions: set[str]
            action: ActionDefinition | None = next((a for a in Actions.values() if a.action == key), None)

            if action is not None:
                default_redactions = action.redactions
                ret = default_redactions.union(self._supplementary_redactions.get(action.key, set()))

            return ret

        headers: dict[str, str] = {
            "X-JNAP-Authorization": f"Basic {self._creds}",
            "Content-Type": "application/json; charset=UTF-8",
            "X-JNAP-Action": self._action,
        }

        resp: aiohttp.ClientResponse | None = None
        try:
            resp = await self._session.post(
                url=self._jnap_url,
                headers=headers,
                json=self._payload or {},
                timeout=timeout,
            )
            resp_json: JnapResponse = await resp.json()
        except TimeoutError as err:
            raise MeshTimeoutError from err
        except (
            aiohttp.ClientConnectionError,
            aiohttp.ClientConnectorError,
            aiohttp.ContentTypeError,
        ) as err:
            _LOGGER.error(self._log_formatter.format("%s"), err)
            raise MeshConnectionError from None
        except json.JSONDecodeError as err:
            _LOGGER.error(self._log_formatter.format("%s"), err)
            raise err from None

        # region #-- log the response --#
        to_log: dict[str, Any] = {
            "action": self._action,
            "payload": self._payload,
            "response": copy.deepcopy(resp_json),
        }
        if self._action != Actions.TRANSACTION.action:
            if self._redact and to_log["response"].get("result") == "OK":
                to_log["response"].update(
                    {
                        "output": self._log_formatter.redact(
                            to_log["response"].get("output", {}),
                            _build_redactions(self._action),
                        )
                    }
                )
        else:
            for idx, r_json in enumerate(to_log["response"].get("responses", [])):
                action: str = cast(list, self._payload)[idx].get("action", "") if self._payload is not None else ""
                redactions = _build_redactions(action)
                if self._redact and r_json.get("result") == "OK":
                    r_json.update({"output": self._log_formatter.redact(r_json.get("output", {}), redactions)})

        _LOGGER_VERBOSE.debug(json.dumps(to_log))
        # endregion

        ret = Response(action=self.action, data=resp_json, raise_on_error=self._raise_on_error)

        return ret

    # region #-- properties --#
    @property
    def action(self) -> str:
        """Return the action used in the request.

        :return: string containing the action
        """
        return self._action

    @property
    def payload(self) -> list[dict[str, Any]] | dict[str, Any] | None:
        """Return the payload used for the request.

        :return: list[dict] | dict | None containing the payload
        """
        return self._payload

    # endregion


class Response:
    """Represents a response from the API."""

    DATA_KEY_SINGLE: str = "output"
    DATA_KEY_TRANSACTION: str = "responses"
    RESULT_KEY: str = "result"

    def __init__(self, action: str, data: JnapResponse | None, raise_on_error: bool = True) -> None:
        """Initialise the response.

        :param action: The action that was issued in the request to cause the response
        :param data: The JSON response received in response to the API call
        """
        self._action: str = action
        self._data: JnapResponse | None = data
        self._log_formatter = Logger(prefix=f"{self.__class__.__name__}.")
        self._raise_on_error: bool = raise_on_error

        self._process_data()

    def _process_data(self) -> None:
        """Process the given data to check for errors."""

        if self._data is None:
            return

        if self._data.get(self.RESULT_KEY) != "OK" and self._raise_on_error:
            responses = (
                self._data.get(self.DATA_KEY_TRANSACTION, {})
                if self.action == Actions.TRANSACTION.action
                else [self._data]
            )
            if responses is None:
                raise MeshException("error processing response")

            err: MeshException | None = None
            for resp in responses:
                err = None
                if resp is None:
                    err = MeshInvalidOutput(resp)
                elif resp.get(self.RESULT_KEY) == "_ErrorInvalidInput":
                    err = MeshInvalidInput(resp.get("error"))
                elif resp.get(self.RESULT_KEY) == "_ErrorInvalidOutput":
                    err = MeshInvalidOutput(resp.get("error"))
                elif resp.get(self.RESULT_KEY) == "_ErrorUnauthorized":
                    err = MeshInvalidCredentials()
                elif resp.get(self.RESULT_KEY) == "_ErrorUnknownAction":
                    action = (
                        resp.get("error")
                        if self.action == Actions.TRANSACTION.action
                        else f"Unknown action URI '{self.action}'"
                    )
                    err = MeshInvalidInput(action)
                elif resp.get(self.RESULT_KEY) == "ErrorAutoChannelSelectionAlreadyInProgress":
                    err = MeshAlreadyInProgress()
                elif resp.get(self.RESULT_KEY) == "ErrorCannotDeleteDevice":
                    err = MeshCannotDeleteDevice()
                elif resp.get(self.RESULT_KEY) == "ErrorDeviceDBFailure":
                    err = MeshDeviceDbFailure(resp.get(self.DATA_KEY_SINGLE, {}).get("ErrorInfo", ""))
                elif resp.get(self.RESULT_KEY) == "ErrorDeviceNotInMasterMode":
                    err = MeshNodeNotPrimary()
                elif resp.get(self.RESULT_KEY) == "ErrorInvalidWANSchedule":
                    err = MeshInvalidInput("Invalid WAN Schedule")
                elif resp.get(self.RESULT_KEY) == "ErrorRulesOverlap":
                    err = MeshInvalidInput("Rules Overlap")
                elif resp.get(self.RESULT_KEY) == "ErrorUnknownDevice":
                    err = MeshInvalidInput("Unknown Device")
                elif resp.get(self.RESULT_KEY, "").startswith("_"):
                    err = MeshInvalidInput(f"{resp.get(self.RESULT_KEY)}: '{self.action}'")
                else:
                    err = MeshException(f"{resp}: '{self.action}'")

                if err:
                    break

            if err is None:
                _LOGGER.error(
                    self._log_formatter.format("unknown error received: %s"),
                    self._data,
                )
                err = MeshBadResponse()

            raise err

    # region #-- properties --#
    @property
    def action(self) -> str:
        """Return the action that resulted in the response.

        :return: string containing the action
        """
        return self._action

    @property
    def data(self) -> JnapResponse | list[JnapResponse] | None:
        """Return the response data."""

        if self._data is None:
            return None

        ret = (
            self._data.get(self.DATA_KEY_TRANSACTION)
            if self.action == Actions.TRANSACTION.action
            else self._data.get(self.DATA_KEY_SINGLE, self._data)
        )

        return ret

    # endregion


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
        ),
        ActionDefinition(
            "GET_BACKHAUL",
            "http://linksys.com/jnap/nodes/diagnostics/GetBackhaulInfo",
        ),
        ActionDefinition(
            "GET_CHANNEL_SCAN_STATUS",
            "http://linksys.com/jnap/nodes/setup/GetSelectedChannels",
        ),
        ActionDefinition(
            "GET_DEVICES",
            "http://linksys.com/jnap/devicelist/GetDevices3",
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
        ),
        ActionDefinition(
            "GET_GUEST_NETWORK_INFO",
            "http://linksys.com/jnap/guestnetwork/GetGuestRadioSettings2",
            redactions={
                "radios.guestSSID",
                "radios.guestWPAPassphrase",
            },
        ),
        ActionDefinition(
            "GET_HOMEKIT_SETTINGS",
            "http://linksys.com/jnap/homekit/GetHomeKitSettings",
        ),
        ActionDefinition(
            "GET_LAN_SETTINGS",
            "http://linksys.com/jnap/router/GetLANSettings",
            redactions={
                "hostName",
                "reservations",
            },
        ),
        ActionDefinition(
            "GET_LED_NIGHT_MODE",
            "http://linksys.com/jnap/routerleds/GetLedNightModeSetting",
        ),
        ActionDefinition(
            "GET_MAC_FILTERING_SETTINGS",
            "http://linksys.com/jnap/macfilter/GetMACFilterSettings",
            redactions={
                "macAddresses",
            },
        ),
        ActionDefinition(
            "GET_MLO_SETTINGS",
            "http://linksys.com/jnap/wirelessap/GetMLOSettings",
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
            redactions={
                "nodeWirelessConnections.connections.wireless.bssid",
                "nodeWirelessConnections.connections.macAddress",
            },
        ),
        ActionDefinition(
            "GET_PARENTAL_CONTROL_INFO",
            "http://linksys.com/jnap/parentalcontrol/GetParentalControlSettings",
            redactions={
                "rules.macAddresses",
            },
        ),
        ActionDefinition(
            "GET_SCHEDULED_REBOOT_SETTINGS",
            "http://linksys.com/jnap/diagnostics/GetScheduledRebootSettings",
        ),
        ActionDefinition(
            "GET_SPEEDTEST_TYPES",
            "http://linksys.com/jnap/healthcheck/GetSupportedHealthCheckModules",
        ),
        ActionDefinition(
            "GET_SPEEDTEST_RESULTS",
            "http://linksys.com/jnap/healthcheck/GetHealthCheckResults",
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
            "GET_STORAGE_PARTITIONS",
            "http://linksys.com/jnap/nodes/storage/GetNodesPartitions",
        ),
        ActionDefinition(
            "GET_STORAGE_SMB_SERVER",
            "http://linksys.com/jnap/nodes/storage/GetSMBServerSettings",
        ),
        ActionDefinition(
            "GET_TOPOLOGY_OPTIMISATION_SETTINGS",
            "http://linksys.com/jnap/nodes/topologyoptimization/GetTopologyOptimizationSettings2",
        ),
        ActionDefinition(
            "GET_UPDATE_FIRMWARE_STATE",
            "http://linksys.com/jnap/nodes/firmwareupdate/GetFirmwareUpdateStatus",
        ),
        ActionDefinition(
            "GET_UPDATE_SETTINGS",
            "http://linksys.com/jnap/firmwareupdate/GetFirmwareUpdateSettings",
        ),
        ActionDefinition(
            "GET_UPNP_SETTINGS",
            "http://linksys.com/jnap/routerupnp/GetUPnPSettings",
        ),
        ActionDefinition(
            "GET_WAN_INFO",
            "http://linksys.com/jnap/router/GetWANStatus3",
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
