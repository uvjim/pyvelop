"""Interact with the JNAP API"""

# region #-- imports --#
from __future__ import annotations

import json
import logging
from typing import (
    Any,
    Dict,
)

from .exceptions import (
    MeshBadResponse,
    MeshInvalidCredentials,
    MeshInvalidInput,
    MeshInvalidOutput,
    MeshNodeNotPrimary,
)
from .logger import LoggerFormatter

# endregion

_LOGGER = logging.getLogger(__name__)


def jnap_url(target) -> str:
    """Return the URL that should be used for the request

    :param target: the API host
    :return: string containing the base URL for all JNAP requests
    """

    # noinspection HttpUrlsUsage
    return f"http://{target}/JNAP/"


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


class Defaults:
    """Represents the default payloads required for requests"""

    PAYLOADS: Dict[str, Dict] = {
        Actions.GET_SPEEDTEST_RESULTS: {
            "healthCheckModule": "SpeedTest",
            "includeModuleResults": True,
            "lastNumberOfResults": 1,
        },
    }


class Response(LoggerFormatter):
    """Represents a response from the API"""

    DATA_KEY_SINGLE: str = "output"
    DATA_KEY_TRANSACTION: str = "responses"
    RESULT_KEY: str = "result"

    def __init__(self, action: str, data: Dict[str, Any]) -> None:
        """Constructor

        :param action: The action that was issued in the request to cause the response
        :param data: The JSON response received in response to the API call
        """

        super().__init__(prefix=f"{self.__class__.__name__}.")

        self._action: str = action
        self._data: Dict[str, Any] = data

        self._process_data()

    def _process_data(self) -> None:
        """Process the given data to check for errors"""

        if self._data.get(self.RESULT_KEY) != "OK":
            responses = (
                self.data
                if self.action == Actions.TRANSACTION
                else [self.data]
            )

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
                _LOGGER.error(self.message_format("unknown error received: %s"), json.dumps(self._data))
                err = MeshBadResponse

            raise err

    # region #-- properties --#
    @property
    def action(self) -> str:
        """Return the action that resulted in the response

        :return: string containing the action
        """

        return self._action

    @property
    def data(self) -> Dict[str, Any]:
        """"""

        ret = (
            self._data.get(self.DATA_KEY_TRANSACTION)
            if self.action == Actions.TRANSACTION
            else self._data.get(self.DATA_KEY_SINGLE)
        )

        return ret
    # endregion
