"""Interact with the JNAP API."""

# region #-- imports --#
from __future__ import annotations

import base64
import json
import logging
from collections import defaultdict
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

import aiohttp

from .const import DEF_REDACT
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


def jnap_url(target) -> str:
    """Return the URL that should be used for the request.

    :param target: the API host
    :return: string containing the base URL for all JNAP requests
    """
    return f"http://{target}/JNAP/"


class Actions(StrEnum):
    """Represents the available actions."""

    CHECK_PASSWORD = "http://linksys.com/jnap/core/CheckAdminPassword"
    DELETE_DEVICE = "http://linksys.com/jnap/devicelist/DeleteDevice"
    GET_ALG_SETTINGS = "http://linksys.com/jnap/firewall/GetALGSettings"
    GET_BACKHAUL = "http://linksys.com/jnap/nodes/diagnostics/GetBackhaulInfo"
    GET_CHANNEL_SCAN_STATUS = "http://linksys.com/jnap/nodes/setup/GetSelectedChannels"
    GET_DEVICES = "http://linksys.com/jnap/devicelist/GetDevices3"
    GET_EXPRESS_FORWARDING = (
        "http://linksys.com/jnap/router/GetExpressForwardingSettings"
    )
    GET_FIRMWARE_UPDATE_SETTINGS = (
        "http://linksys.com/jnap/firmwareupdate/GetFirmwareUpdateSettings"
    )
    GET_GUEST_NETWORK_INFO = (
        "http://linksys.com/jnap/guestnetwork/GetGuestRadioSettings2"
    )
    GET_HOMEKIT_SETTINGS = "http://linksys.com/jnap/homekit/GetHomeKitSettings"
    GET_LAN_SETTINGS = "http://linksys.com/jnap/router/GetLANSettings"
    GET_MAC_FILTERING_SETTINGS = (
        "http://linksys.com/jnap/macfilter/GetMACFilterSettings"
    )
    GET_NETWORK_CONNECTIONS = "http://linksys.com/jnap/nodes/networkconnections/GetNodesWirelessNetworkConnections"
    GET_PARENTAL_CONTROL_INFO = (
        "http://linksys.com/jnap/parentalcontrol/GetParentalControlSettings"
    )
    GET_SPEEDTEST_RESULTS = "http://linksys.com/jnap/healthcheck/GetHealthCheckResults"
    GET_SPEEDTEST_STATUS = "http://linksys.com/jnap/healthcheck/GetHealthCheckStatus"
    GET_STORAGE_PARTITIONS = "http://linksys.com/jnap/nodes/storage/GetNodesPartitions"
    GET_STORAGE_SMB_SERVER = (
        "http://linksys.com/jnap/nodes/storage/GetSMBServerSettings"
    )
    GET_TOPOLOGY_OPTIMISATION_SETTINGS = "http://linksys.com/jnap/nodes/topologyoptimization/GetTopologyOptimizationSettings2"
    GET_UPDATE_FIRMWARE_STATE = (
        "http://linksys.com/jnap/nodes/firmwareupdate/GetFirmwareUpdateStatus"
    )
    GET_UPDATE_SETTINGS = (
        "http://linksys.com/jnap/firmwareupdate/GetFirmwareUpdateSettings"
    )
    GET_UPNP_SETTINGS = "http://linksys.com/jnap/routerupnp/GetUPnPSettings"
    GET_WAN_INFO = "http://linksys.com/jnap/router/GetWANStatus3"
    GET_WPS_SERVER_SETTINGS = "http://linksys.com/jnap/wirelessap/GetWPSServerSettings"
    REBOOT = "http://linksys.com/jnap/core/Reboot"
    SET_DEVICE_PROPERTY = "http://linksys.com/jnap/devicelist/SetDeviceProperties"
    SET_GUEST_NETWORK = "http://linksys.com/jnap/guestnetwork/SetGuestRadioSettings2"
    SET_HOMEKIT_SETTINGS = "http://linksys.com/jnap/homekit/SetHomeKitSettings"
    SET_PARENTAL_CONTROL_INFO = (
        "http://linksys.com/jnap/parentalcontrol/SetParentalControlSettings"
    )
    SET_UPNP_SETTINGS = "http://linksys.com/jnap/routerupnp/SetUPnPSettings"
    SET_WPS_SERVER_SETTINGS = "http://linksys.com/jnap/wirelessap/SetWPSServerSettings"
    START_CHANNEL_SCAN = "http://linksys.com/jnap/nodes/setup/StartAutoChannelSelection"
    START_SPEEDTEST = "http://linksys.com/jnap/healthcheck/RunHealthCheck"
    TRANSACTION = "http://linksys.com/jnap/core/Transaction"
    UPDATE_FIRMWARE = "http://linksys.com/jnap/nodes/firmwareupdate/UpdateFirmwareNow"


@dataclass
class Defaults:
    """Represents the default payloads required for requests."""

    payloads = defaultdict(dict)
    payloads[Actions.GET_SPEEDTEST_RESULTS] = {
        "healthCheckModule": "SpeedTest",
        "includeModuleResults": True,
        "lastNumberOfResults": 10,
    }


class Request:
    """Represents a request for the API."""

    def __init__(
        self,
        action: str,
        password: str,
        target: str,
        payload: list[dict] | dict | None = None,
        raise_on_error: bool = True,
        session: aiohttp.ClientSession | None = None,
        username: str = "admin",
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
        self._creds: str = base64.b64encode(
            bytes(f"{username}:{password}", "utf-8")
        ).decode("ascii")
        self._log_formatter = Logger(prefix=f"{self.__class__.__name__}.")
        self._payload: list[dict] | dict | None = payload
        self._raise_on_error: bool = raise_on_error
        self._session: aiohttp.ClientSession = (
            session
            if session is not None
            else aiohttp.ClientSession(raise_for_status=True)
        )

        if self._payload is None:
            self._payload = []
        self._jnap_url: str = jnap_url(target=target)

    async def execute(self, timeout: float = 10) -> Response:
        """Send the request.

        :param timeout: the timeout in seconds for the request, defaults to 10s
        :return: a Response object representing the returned results
        """
        _LOGGER.debug(self._log_formatter.format("entered"))

        headers: dict[str, str] = {
            "X-JNAP-Authorization": f"Basic {self._creds}",
            "Content-Type": "application/json; charset=UTF-8",
            "X-JNAP-Action": self._action,
        }

        _LOGGER.debug(
            self._log_formatter.format(
                "URL: %s, Headers: %s, Payload: %s, Timeout: %i"
            ),
            self._jnap_url,
            {
                key: value if key not in ("X-JNAP-Authorization") else DEF_REDACT
                for key, value in headers.items()
            },
            json.dumps(self._payload),
            timeout,
        )

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
            _LOGGER.debug(self._log_formatter.format("resp: %s"), resp)
            _LOGGER.error(self._log_formatter.format("%s"), err)
            raise err from None

        _LOGGER_VERBOSE.debug(
            self._log_formatter.format("action: %s --> payload: %s --> response: %s"),
            self.action,
            self.payload,
            resp_json,
        )

        ret = Response(
            action=self.action, data=resp_json, raise_on_error=self._raise_on_error
        )

        _LOGGER.debug(self._log_formatter.format("exited"))
        return ret

    # region #-- properties --#
    @property
    def action(self) -> str:
        """Return the action used in the request.

        :return: string containing the action
        """
        return self._action

    @property
    def payload(self) -> list[dict] | dict | None:
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

    def __init__(
        self, action: str, data: JnapResponse | None, raise_on_error: bool = True
    ) -> None:
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
                if self.action == Actions.TRANSACTION
                else [self._data]
            )
            if responses is None:
                raise MeshException("error processing response")

            err = None
            for resp in responses:
                err = None
                if resp is None:
                    err = MeshInvalidOutput(resp)
                elif resp.get(self.RESULT_KEY) == "_ErrorInvalidInput":
                    err = MeshInvalidInput(resp.get("error"))
                elif resp.get(self.RESULT_KEY) == "_ErrorInvalidOutput":
                    err = MeshInvalidOutput(resp.get("error"))
                elif resp.get(self.RESULT_KEY) == "_ErrorUnauthorized":
                    err = MeshInvalidCredentials
                elif resp.get(self.RESULT_KEY) == "_ErrorUnknownAction":
                    action = (
                        resp.get("error")
                        if self.action == Actions.TRANSACTION
                        else f"Unknown action URI '{self.action}'"
                    )
                    err = MeshInvalidInput(action)
                elif (
                    resp.get(self.RESULT_KEY)
                    == "ErrorAutoChannelSelectionAlreadyInProgress"
                ):
                    err = MeshAlreadyInProgress
                elif resp.get(self.RESULT_KEY) == "ErrorCannotDeleteDevice":
                    err = MeshCannotDeleteDevice
                elif resp.get(self.RESULT_KEY) == "ErrorDeviceDBFailure":
                    err = MeshDeviceDbFailure(
                        resp.get(self.DATA_KEY_SINGLE, {}).get("ErrorInfo", "")
                    )
                elif resp.get(self.RESULT_KEY) == "ErrorDeviceNotInMasterMode":
                    err = MeshNodeNotPrimary
                elif resp.get(self.RESULT_KEY) == "ErrorInvalidWANSchedule":
                    err = MeshInvalidInput("Invalid WAN Schedule")
                elif resp.get(self.RESULT_KEY) == "ErrorRulesOverlap":
                    err = MeshInvalidInput("Rules Overlap")
                elif resp.get(self.RESULT_KEY) == "ErrorUnknownDevice":
                    err = MeshInvalidInput("Unknown Device")
                elif resp.get(self.RESULT_KEY, "").startswith("_"):
                    err = MeshInvalidInput(
                        f"{resp.get(self.RESULT_KEY)}: '{self.action}'"
                    )
                else:
                    err = MeshException(f"{resp}: '{self.action}'")

                if err:
                    break

            if err is None:
                _LOGGER.error(
                    self._log_formatter.format("unknown error received: %s"),
                    self._data,
                )
                err = MeshBadResponse

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
            return

        ret = (
            self._data.get(self.DATA_KEY_TRANSACTION)
            if self.action == Actions.TRANSACTION
            else self._data.get(self.DATA_KEY_SINGLE, self._data)
        )

        return ret

    # endregion
