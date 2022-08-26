"""Interact with the JNAP API."""

# region #-- imports --#
from __future__ import annotations

import asyncio
import base64
import json
import logging
from typing import Any, Dict, List, Optional

import aiohttp

from .exceptions import (
    MeshBadResponse,
    MeshConnectionError,
    MeshInvalidCredentials,
    MeshInvalidInput,
    MeshInvalidOutput,
    MeshNodeNotPrimary,
    MeshTimeoutError,
)
from .logger import LoggerFormatter

# endregion

_LOGGER = logging.getLogger(__name__)


def jnap_url(target) -> str:
    """Return the URL that should be used for the request.

    :param target: the API host
    :return: string containing the base URL for all JNAP requests
    """
    return f"http://{target}/JNAP/"


class Actions:
    """Represents the available actions."""

    ROOT: str = "http://linksys.com/jnap"

    CHECK_PASSWORD: str = f"{ROOT}/core/CheckAdminPassword"
    DELETE_DEVICE: str = f"{ROOT}/devicelist/DeleteDevice"
    GET_BACKHAUL: str = f"{ROOT}/nodes/diagnostics/GetBackhaulInfo"
    GET_DEVICES: str = f"{ROOT}/devicelist/GetDevices3"
    GET_FIRMWARE_UPDATE_SETTINGS: str = (
        f"{ROOT}/firmwareupdate/GetFirmwareUpdateSettings"
    )
    GET_GUEST_NETWORK_INFO: str = f"{ROOT}/guestnetwork/GetGuestRadioSettings2"
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
    GET_UPDATE_FIRMWARE_STATE: str = (
        f"{ROOT}/nodes/firmwareupdate/GetFirmwareUpdateStatus"
    )
    GET_UPDATE_SETTINGS: str = f"{ROOT}/firmwareupdate/GetFirmwareUpdateSettings"
    GET_WAN_INFO: str = f"{ROOT}/router/GetWANStatus3"
    REBOOT: str = f"{ROOT}/core/Reboot"
    SET_GUEST_NETWORK: str = f"{ROOT}/guestnetwork/SetGuestRadioSettings2"
    SET_PARENTAL_CONTROL_INFO: str = (
        f"{ROOT}/parentalcontrol/SetParentalControlSettings"
    )
    START_SPEEDTEST: str = f"{ROOT}/healthcheck/RunHealthCheck"
    TRANSACTION: str = f"{ROOT}/core/Transaction"
    UPDATE_FIRMWARE: str = f"{ROOT}/nodes/firmwareupdate/UpdateFirmwareNow"


class Defaults:
    """Represents the default payloads required for requests."""

    PAYLOADS: Dict[str, Dict] = {
        Actions.GET_SPEEDTEST_RESULTS: {
            "healthCheckModule": "SpeedTest",
            "includeModuleResults": True,
            "lastNumberOfResults": 1,
        },
    }


class Request(LoggerFormatter):
    """Represents a request for the API."""

    def __init__(
        self,
        action: str,
        password: str,
        target: str,
        payload: Optional[List[Dict] | Dict] = None,
        session: Optional[aiohttp.ClientSession] = None,
        username: str = "admin",
    ) -> None:
        """Initialise a request.

        :param action: the JNAP action to carry out
        :param password: the password required to communicate with the target
        :param target: the node to send the request to
        :param payload: the additional configuration to pass along with the action
        :param session: an existing session to use
        :param username: the username required to communicate with the target
        """
        super().__init__(prefix=f"{self.__class__.__name__}.")

        self._action: str = action
        self._creds: str = base64.b64encode(
            bytes(f"{username}:{password}", "utf-8")
        ).decode("ascii")
        self._payload: Optional[List[Dict] | Dict] = payload
        self._session: Optional[
            aiohttp.ClientSession
        ] = session or aiohttp.ClientSession(raise_for_status=True)
        self._target: str = target

        self._jnap_url: str = jnap_url(target=self._target)

    async def execute(self, timeout: int = 10) -> Response:
        """Send the request.

        :param timeout: the timeout in seconds for the request, defaults to 10s
        :return: a Response object representing the returned results
        """
        _LOGGER.debug(self.message_format("entered"))

        headers: Dict[str, str] = {
            "X-JNAP-Authorization": f"Basic {self._creds}",
            "Content-Type": "application/json; charset=UTF-8",
            "X-JNAP-Action": self._action,
        }

        _LOGGER.debug(
            self.message_format("URL: %s, Headers: %s, Payload: %s, Timeout: %i"),
            self._jnap_url,
            headers,
            json.dumps(self._payload),
            timeout,
        )

        resp: Optional[aiohttp.ClientResponse] = None
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
        ):
            raise MeshConnectionError from None
        except json.JSONDecodeError as err:
            _LOGGER.debug(self.message_format("resp: %s"), resp)
            _LOGGER.error(self.message_format("%s"), err)
            raise err from None

        _LOGGER.debug(self.message_format("exited"))
        return Response(action=self._action, data=resp_json)


class Response(LoggerFormatter):
    """Represents a response from the API."""

    DATA_KEY_SINGLE: str = "output"
    DATA_KEY_TRANSACTION: str = "responses"
    RESULT_KEY: str = "result"

    def __init__(self, action: str, data: Dict[str, Any]) -> None:
        """Initialise the response.

        :param action: The action that was issued in the request to cause the response
        :param data: The JSON response received in response to the API call
        """
        super().__init__(prefix=f"{self.__class__.__name__}.")

        self._action: str = action
        self._data: Dict[str, Any] = data

        self._process_data()

    def _process_data(self) -> None:
        """Process the given data to check for errors."""
        if self._data.get(self.RESULT_KEY) != "OK":
            responses = self.data if self.action == Actions.TRANSACTION else [self.data]

            err = None
            for resp in responses:
                err = None
                if resp.get(self.RESULT_KEY) == "_ErrorInvalidInput":
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
                elif resp.get(self.RESULT_KEY) == "ErrorDeviceNotInMasterMode":
                    err = MeshNodeNotPrimary
                elif resp.get(self.RESULT_KEY).startswith("_"):
                    err = MeshInvalidInput(resp.get(self.RESULT_KEY))

                if err:
                    break

            if err is None:
                _LOGGER.error(
                    self.message_format("unknown error received: %s"), self._data
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
            else self._data.get(self.DATA_KEY_SINGLE)
        )

        return ret

    # endregion
