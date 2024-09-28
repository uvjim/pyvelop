"""Interact with the JNAP API."""

# region #-- imports --#
from __future__ import annotations

import asyncio
import base64
import json
import logging
from collections import defaultdict
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List

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


class Actions(str, Enum):
    """Represents the available actions."""

    ROOT: str = "http://linksys.com/jnap"

    CHECK_PASSWORD: str = f"{ROOT}/core/CheckAdminPassword"
    DELETE_DEVICE: str = f"{ROOT}/devicelist/DeleteDevice"
    GET_ALG_SETTINGS: str = f"{ROOT}/firewall/GetALGSettings"
    GET_BACKHAUL: str = f"{ROOT}/nodes/diagnostics/GetBackhaulInfo"
    GET_CHANNEL_SCAN_STATUS: str = f"{ROOT}/nodes/setup/GetSelectedChannels"
    GET_DEVICES: str = f"{ROOT}/devicelist/GetDevices3"
    GET_EXPRESS_FORWARDING: str = f"{ROOT}/router/GetExpressForwardingSettings"
    GET_FIRMWARE_UPDATE_SETTINGS: str = (
        f"{ROOT}/firmwareupdate/GetFirmwareUpdateSettings"
    )
    GET_GUEST_NETWORK_INFO: str = f"{ROOT}/guestnetwork/GetGuestRadioSettings2"
    GET_HOMEKIT_SETTINGS: str = f"{ROOT}/homekit/GetHomeKitSettings"
    GET_LAN_SETTINGS: str = f"{ROOT}/router/GetLANSettings"
    GET_MAC_FILTERING_SETTINGS: str = f"{ROOT}/macfilter/GetMACFilterSettings"
    GET_NETWORK_CONNECTIONS: str = (
        f"{ROOT}/nodes/networkconnections/GetNodesWirelessNetworkConnections"
    )
    GET_PARENTAL_CONTROL_INFO: str = (
        f"{ROOT}/parentalcontrol/GetParentalControlSettings"
    )
    GET_SPEEDTEST_RESULTS: str = f"{ROOT}/healthcheck/GetHealthCheckResults"
    GET_SPEEDTEST_STATUS: str = f"{ROOT}/healthcheck/GetHealthCheckStatus"
    GET_STORAGE_PARTITIONS: str = f"{ROOT}/nodes/storage/GetNodesPartitions"
    GET_STORAGE_SMB_SERVER: str = f"{ROOT}/nodes/storage/GetSMBServerSettings"
    GET_TOPOLOGY_OPTIMISATION_SETTINGS: str = (
        f"{ROOT}/nodes/topologyoptimization/GetTopologyOptimizationSettings2"
    )
    GET_UPDATE_FIRMWARE_STATE: str = (
        f"{ROOT}/nodes/firmwareupdate/GetFirmwareUpdateStatus"
    )
    GET_UPDATE_SETTINGS: str = f"{ROOT}/firmwareupdate/GetFirmwareUpdateSettings"
    GET_UPNP_SETTINGS: str = f"{ROOT}/routerupnp/GetUPnPSettings"
    GET_WAN_INFO: str = f"{ROOT}/router/GetWANStatus3"
    GET_WPS_SERVER_SETTINGS: str = f"{ROOT}/wirelessap/GetWPSServerSettings"
    REBOOT: str = f"{ROOT}/core/Reboot"
    SET_DEVICE_PROPERTY: str = f"{ROOT}/devicelist/SetDeviceProperties"
    SET_GUEST_NETWORK: str = f"{ROOT}/guestnetwork/SetGuestRadioSettings2"
    SET_HOMEKIT_SETTINGS: str = f"{ROOT}/homekit/SetHomeKitSettings"
    SET_PARENTAL_CONTROL_INFO: str = (
        f"{ROOT}/parentalcontrol/SetParentalControlSettings"
    )
    SET_WPS_SERVER_SETTINGS: str = f"{ROOT}/wirelessap/SetWPSServerSettings"
    START_CHANNEL_SCAN: str = f"{ROOT}/nodes/setup/StartAutoChannelSelection"
    START_SPEEDTEST: str = f"{ROOT}/healthcheck/RunHealthCheck"
    TRANSACTION: str = f"{ROOT}/core/Transaction"
    UPDATE_FIRMWARE: str = f"{ROOT}/nodes/firmwareupdate/UpdateFirmwareNow"

    @classmethod
    def is_unsafe(cls, action: str) -> bool:
        """Return if the action is unsafe."""
        return action in {
            "GET_HOMEKIT_SETTINGS",
            "GET_NETWORK_CONNECTIONS",
            "GET_STORAGE_SMB_SERVER",
            "GET_STORAGE_PARTITIONS",
        }


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
        payload: List[Dict] | Dict | None = None,
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
        self._payload: List[Dict] | Dict | None = payload
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

        headers: Dict[str, str] = {
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
    def payload(self) -> List[Dict] | Dict | None:
        """Return the payload used for the request.

        :return: Optional[List[Dict] | Dict] containing the payload
        """
        return self._payload

    # endregion


class Response:
    """Represents a response from the API."""

    DATA_KEY_SINGLE: str = "output"
    DATA_KEY_TRANSACTION: str = "responses"
    RESULT_KEY: str = "result"

    def __init__(
        self, action: str, data: Dict[str, Any], raise_on_error: bool = True
    ) -> None:
        """Initialise the response.

        :param action: The action that was issued in the request to cause the response
        :param data: The JSON response received in response to the API call
        """
        self._action: str = action
        self._data: Dict[str, Any] = data
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
    def data(self) -> Dict[str, Any]:
        """Return the response data."""
        ret = (
            self._data.get(self.DATA_KEY_TRANSACTION)
            if self.action == Actions.TRANSACTION
            else self._data.get(self.DATA_KEY_SINGLE, self._data)
        )

        return ret

    # endregion
