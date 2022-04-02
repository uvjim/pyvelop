""""""

# region #-- imports --#
from __future__ import annotations

import base64
import json
import logging
from asyncio import TimeoutError
from typing import (
    Dict,
    List,
    Optional,
)

import aiohttp
from aiohttp.client_exceptions import (
    ClientConnectionError,
    ClientConnectorError,
    ContentTypeError,
)

from .exceptions import (
    MeshConnectionError,
    MeshTimeoutError,
)
from .logger import LoggerFormatter

# endregion


_LOGGER = logging.getLogger(__name__)


class Actions:
    """Represents the available actions"""

    # noinspection HttpUrlsUsage
    ROOT: str = "http://linksys.com/jnap"
    
    CHECK_PASSWORD: str = f"{ROOT}/core/CheckAdminPassword"
    DELETE_DEVICE: str = f"{ROOT}/devicelist/DeleteDevice"
    GET_BACKHAUL: str = f"{ROOT}/nodes/diagnostics/GetBackhaulInfo"
    GET_DEVICES: str = f"{ROOT}/devicelist/GetDevices3"
    GET_GUEST_NETWORK_INFO: str = f"{ROOT}/guestnetwork/GetGuestRadioSettings2"
    GET_PARENTAL_CONTROL_INFO: str = f"{ROOT}/parentalcontrol/GetParentalControlSettings"
    GET_SPEEDTEST_RESULTS: str = f"{ROOT}/healthcheck/GetHealthCheckResults"
    GET_SPEEDTEST_STATE: str = f"{ROOT}/healthcheck/GetHealthCheckStatus"
    GET_STORAGE_PARTITIONS: str = f"{ROOT}/nodes/storage/GetNodesPartitions"
    GET_STORAGE_SMB_SERVER: str = f"{ROOT}/nodes/storage/GetSMBServerSettings"
    GET_UPDATE_FIRMWARE_STATE: str = f"{ROOT}/nodes/firmwareupdate/GetFirmwareUpdateStatus"
    GET_UPDATE_SETTINGS: str = f"{ROOT}/firmwareupdate/GetFirmwareUpdateSettings"
    GET_WAN_INFO: str = f"{ROOT}/router/GetWANStatus3"
    REBOOT: str = f"{ROOT}/core/Reboot"
    SET_GUEST_NETWORK: str = f"{ROOT}/guestnetwork/SetGuestRadioSettings2"
    SET_PARENTAL_CONTROL_INFO: str = f"{ROOT}/parentalcontrol/SetParentalControlSettings"
    START_SPEEDTEST: str = f"{ROOT}/healthcheck/RunHealthCheck"
    TRANSACTION: str = f"{ROOT}/core/Transaction"
    UPDATE_FIRMWARE: str = f"{ROOT}/nodes/firmwareupdate/UpdateFirmwareNow"


class Request(LoggerFormatter):
    """"""

    def __init__(
        self,
        action: str,
        password: str,
        target: str,
        payload: Optional[List[Dict], Dict] = None,
        session: Optional[aiohttp.ClientSession] = None,
        username: str = "admin",
    ) -> None:
        """Constructor

        :param action: the JNAP action to carry out
        :param password: the password required to communicate with the target
        :param target: the node to send the request to
        :param payload: the additional configuration to pass along with the action
        :param session: an existing session to use
        :param username: the username required to communicate with the target
        """

        super().__init__(prefix=f"{self.__class__.__name__}.")

        self._action: str | List[str] = action
        self._creds: str = base64.b64encode(bytes(f"{username}:{password}", "utf-8")).decode("ascii")
        self._payload: Optional[List[Dict], Dict] = payload
        self._session: Optional[aiohttp.ClientSession] = session or aiohttp.ClientSession(raise_for_status=True)
        self._target: str = target

        self._jnap_url: str = self.jnap_url(target=self._target)

    @staticmethod
    def jnap_url(target) -> str:
        """Return the URL that should be used for the request"""

        # noinspection HttpUrlsUsage
        return f"http://{target}/JNAP/"

    async def execute(self, timeout: int = 10) -> Response:
        """Send the request"""

        _LOGGER.debug(self.message_format("entered"))

        headers: Dict[str, str] = {
            "X-JNAP-Authorization": f"Basic {self._creds}",
            "Content-Type": "application/json; charset=UTF-8",
            "X-JNAP-Action": self._action
        }

        _LOGGER.debug(
            self.message_format("URL: %s, Headers: %s, Payload: %s, Timeout: %i"),
            self._jnap_url,
            headers,
            json.dumps(self._payload),
            timeout
        )

        try:
            resp = await self._session.post(
                url=self._jnap_url,
                headers=headers,
                json=self._payload or {},
                timeout=timeout
            )
            resp_json = await resp.json()
        except TimeoutError:
            raise MeshTimeoutError
        except (ClientConnectionError, ClientConnectorError, ContentTypeError,):
            raise MeshConnectionError from None
        except json.JSONDecodeError as err:
            raise err from None

        _LOGGER.debug(self.message_format("exited"))
        return Response(action=self._action, data=resp_json)


class Response(LoggerFormatter):
    """"""

    ACTION_KEY: str = "action"
    RESULT_KEY: str = "result"
    RESULTS_KEY_SINGLE: str = "output"
    RESULTS_KEY_TRANSACTION: str = "responses"
    RESULTS_KEY_ERROR: str = "error"

    def __init__(self, action: str, data: Dict) -> None:
        """Constructor"""

        super().__init__(prefix=f"{self.__class__.__name__}.")

        self._action: str = action
        self._data: Dict = data

    @property
    def action(self) -> str:
        """Return the action associated with the response"""

        return self._action

    @property
    def data(self) -> Dict:
        """Return the data as returned by the API"""

        ret: Dict = {
            self.ACTION_KEY: self._action
        }
        if self.is_successful:
            ret[self.RESULT_KEY] = (
                    self._data.get(self.RESULTS_KEY_SINGLE)
                    or self._data.get(self.RESULTS_KEY_TRANSACTION)
            )
        else:
            ret[self.RESULT_KEY] = self._data

        return ret

    @property
    def is_successful(self) -> bool:
        """Check if the response indicates a successful request

        :return: True if successful otherwise False
        """

        return self._data.get(self.RESULT_KEY) == "OK"
