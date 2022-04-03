"""Interact with the JNAP API"""

# region #-- imports --#
from __future__ import annotations

from typing import Dict


# endregion


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


class Response:
    """Represents a response from the API"""

    DATA_KEY_SINGLE: str = "output"
    DATA_KEY_TRANSACTION: str = "responses"
