"""Interact with the JNAP API."""

# region #-- imports --#
from __future__ import annotations

import asyncio
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
    MeshException,
    MeshInvalidCredentials,
    MeshInvalidInput,
    MeshInvalidOutput,
    MeshNodeNotPrimary,
    MeshTimeoutError,
)
from .logger import Logger

# endregion

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

    CHECK_PASSWORD = f"http://linksys.com/jnap/core/CheckAdminPassword"
    DELETE_DEVICE = f"http://linksys.com/jnap/devicelist/DeleteDevice"
    GET_ALG_SETTINGS = f"http://linksys.com/jnap/firewall/GetALGSettings"
    GET_BACKHAUL = f"http://linksys.com/jnap/nodes/diagnostics/GetBackhaulInfo"
    GET_CHANNEL_SCAN_STATUS = f"http://linksys.com/jnap/nodes/setup/GetSelectedChannels"
    GET_DEVICES = f"http://linksys.com/jnap/devicelist/GetDevices3"
    GET_EXPRESS_FORWARDING = (
        f"http://linksys.com/jnap/router/GetExpressForwardingSettings"
    )
    GET_FIRMWARE_UPDATE_SETTINGS = (
        f"http://linksys.com/jnap/firmwareupdate/GetFirmwareUpdateSettings"
    )
    GET_GUEST_NETWORK_INFO = (
        f"http://linksys.com/jnap/guestnetwork/GetGuestRadioSettings2"
    )
    GET_HOMEKIT_SETTINGS = f"http://linksys.com/jnap/homekit/GetHomeKitSettings"
    GET_LAN_SETTINGS = f"http://linksys.com/jnap/router/GetLANSettings"
    GET_MAC_FILTERING_SETTINGS = (
        f"http://linksys.com/jnap/macfilter/GetMACFilterSettings"
    )
    GET_NETWORK_CONNECTIONS = f"http://linksys.com/jnap/nodes/networkconnections/GetNodesWirelessNetworkConnections"
    GET_PARENTAL_CONTROL_INFO = (
        f"http://linksys.com/jnap/parentalcontrol/GetParentalControlSettings"
    )
    GET_SPEEDTEST_RESULTS = f"http://linksys.com/jnap/healthcheck/GetHealthCheckResults"
    GET_SPEEDTEST_STATUS = f"http://linksys.com/jnap/healthcheck/GetHealthCheckStatus"
    GET_STORAGE_PARTITIONS = f"http://linksys.com/jnap/nodes/storage/GetNodesPartitions"
    GET_STORAGE_SMB_SERVER = (
        f"http://linksys.com/jnap/nodes/storage/GetSMBServerSettings"
    )
    GET_TOPOLOGY_OPTIMISATION_SETTINGS = f"http://linksys.com/jnap/nodes/topologyoptimization/GetTopologyOptimizationSettings2"
    GET_UPDATE_FIRMWARE_STATE = (
        f"http://linksys.com/jnap/nodes/firmwareupdate/GetFirmwareUpdateStatus"
    )
    GET_UPDATE_SETTINGS = (
        f"http://linksys.com/jnap/firmwareupdate/GetFirmwareUpdateSettings"
    )
    GET_UPNP_SETTINGS = f"http://linksys.com/jnap/routerupnp/GetUPnPSettings"
    GET_WAN_INFO = f"http://linksys.com/jnap/router/GetWANStatus3"
    GET_WPS_SERVER_SETTINGS = f"http://linksys.com/jnap/wirelessap/GetWPSServerSettings"
    REBOOT = f"http://linksys.com/jnap/core/Reboot"
    SET_DEVICE_PROPERTY = f"http://linksys.com/jnap/devicelist/SetDeviceProperties"
    SET_GUEST_NETWORK = f"http://linksys.com/jnap/guestnetwork/SetGuestRadioSettings2"
    SET_HOMEKIT_SETTINGS = f"http://linksys.com/jnap/homekit/SetHomeKitSettings"
    SET_PARENTAL_CONTROL_INFO = (
        f"http://linksys.com/jnap/parentalcontrol/SetParentalControlSettings"
    )
    SET_UPNP_SETTINGS = f"http://linksys.com/jnap/routerupnp/SetUPnPSettings"
    SET_WPS_SERVER_SETTINGS = f"http://linksys.com/jnap/wirelessap/SetWPSServerSettings"
    START_CHANNEL_SCAN = (
        f"http://linksys.com/jnap/nodes/setup/StartAutoChannelSelection"
    )
    START_SPEEDTEST = f"http://linksys.com/jnap/healthcheck/RunHealthCheck"
    TRANSACTION = f"http://linksys.com/jnap/core/Transaction"
    UPDATE_FIRMWARE = f"http://linksys.com/jnap/nodes/firmwareupdate/UpdateFirmwareNow"


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
        self._session: aiohttp.ClientSession | None = session or aiohttp.ClientSession(
            raise_for_status=True
        )

        self._jnap_url: str = jnap_url(target=target)

    async def execute(self, timeout: int = 10) -> Response:
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
            resp_json = await resp.json()
        except asyncio.TimeoutError as err:
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

        ret: Response = Response(
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
        self, action: str, data: dict[str, Any], raise_on_error: bool = True
    ) -> None:
        """Initialise the response.

        :param action: The action that was issued in the request to cause the response
        :param data: The JSON response received in response to the API call
        """
        self._action: str = action
        self._data: dict[str, Any] = data
        self._log_formatter = Logger(prefix=f"{self.__class__.__name__}.")
        self._raise_on_error: bool = raise_on_error

        self._process_data()

    def _process_data(self) -> None:
        """Process the given data to check for errors."""
        if self._data.get(self.RESULT_KEY) != "OK" and self._raise_on_error:
            responses = self.data if self.action == Actions.TRANSACTION else [self.data]

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
    def data(self) -> dict[str, Any]:
        """Return the response data."""
        ret = (
            self._data.get(self.DATA_KEY_TRANSACTION)
            if self.action == Actions.TRANSACTION
            else self._data.get(self.DATA_KEY_SINGLE, self._data)
        )

        return ret

    # endregion
