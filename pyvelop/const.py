"""Constants for the pyvelop module"""

from typing import List

# region #-- generic details --#
_PACKAGE_NAME = "pyvelop"
_PACKAGE_AUTHOR = "uvjim"
_PACKAGE_VERSION = "2022.2.6"
# endregion

# region #-- JNAP actions --#
# noinspection HttpUrlsUsage
ACTION_JNAP_ROOT: str = "http://linksys.com/jnap"
# noinspection DuplicatedCode
ACTION_JNAP_CHECK_PASSWORD: str = f"{ACTION_JNAP_ROOT}/core/CheckAdminPassword"
ACTION_JNAP_DELETE_DEVICE: str = f"{ACTION_JNAP_ROOT}/devicelist/DeleteDevice"
ACTION_JNAP_GET_BACKHAUL: str = f"{ACTION_JNAP_ROOT}/nodes/diagnostics/GetBackhaulInfo"
ACTION_JNAP_GET_DEVICES: str = f"{ACTION_JNAP_ROOT}/devicelist/GetDevices3"
ACTION_JNAP_GET_GUEST_NETWORK_INFO: str = f"{ACTION_JNAP_ROOT}/guestnetwork/GetGuestRadioSettings2"
ACTION_JNAP_GET_PARENTAL_CONTROL_INFO: str = f"{ACTION_JNAP_ROOT}/parentalcontrol/GetParentalControlSettings"
ACTION_JNAP_GET_SPEEDTEST_RESULTS: str = f"{ACTION_JNAP_ROOT}/healthcheck/GetHealthCheckResults"
ACTION_JNAP_GET_SPEEDTEST_STATE: str = f"{ACTION_JNAP_ROOT}/healthcheck/GetHealthCheckStatus"
ACTION_JNAP_GET_STORAGE_PARTITIONS: str = f"{ACTION_JNAP_ROOT}/nodes/storage/GetNodesPartitions"
# noinspection DuplicatedCode
ACTION_JNAP_GET_STORAGE_SMB_SERVER: str = f"{ACTION_JNAP_ROOT}/nodes/storage/GetSMBServerSettings"
ACTION_JNAP_GET_UPDATE_FIRMWARE_STATE: str = f"{ACTION_JNAP_ROOT}/nodes/firmwareupdate/GetFirmwareUpdateStatus"
ACTION_JNAP_GET_WAN_INFO: str = f"{ACTION_JNAP_ROOT}/router/GetWANStatus3"
ACTION_JNAP_REBOOT: str = f"{ACTION_JNAP_ROOT}/core/Reboot"
ACTION_JNAP_SET_GUEST_NETWORK: str = f"{ACTION_JNAP_ROOT}/guestnetwork/SetGuestRadioSettings2"
ACTION_JNAP_SET_PARENTAL_CONTROL_INFO: str = f"{ACTION_JNAP_ROOT}/parentalcontrol/SetParentalControlSettings"
ACTION_JNAP_START_SPEEDTEST: str = f"{ACTION_JNAP_ROOT}/healthcheck/RunHealthCheck"
ACTION_JNAP_TRANSACTION: str = f"{ACTION_JNAP_ROOT}/core/Transaction"
ACTION_JNAP_UPDATE_FIRMWARE: str = f"{ACTION_JNAP_ROOT}/nodes/firmwareupdate/UpdateFirmwareNow"
# endregion

# region #-- attributes used for the mesh --#
ATTR_MESH_CONNECTED_NODE = "connected_node"
ATTR_MESH_DEVICES = "devices"
ATTR_MESH_GUEST_NETWORK_INFO = "guest_network"
ATTR_MESH_NODES = "nodes"
ATTR_MESH_PARENTAL_CONTROL_INFO = "parental_control"
ATTR_MESH_SPEEDTEST_RESULTS = "speedtest_results"
ATTR_MESH_SPEEDTEST_STATE = "speedtest_state"
ATTR_MESH_STORAGE = "storage"
ATTR_MESH_UPDATE_FIRMWARE_STATE = "check_update_state"
ATTR_MESH_WAN_INFO = "wan_info"
# endregion

# region #-- default payloads for the actions --#
DEF_JNAP_SPEEDTEST_PAYLOAD: dict = {
    "healthCheckModule": "SpeedTest",
    "includeModuleResults": True,
    "lastNumberOfResults": 1,
}
DEF_JNAP_CHECK_FIRMWARE_PAYLOAD: dict = {
    "onlyCheck": True
}
# endregion

# region #-- default result sets --#
DEF_JNAP_SPEEDTEST_RESULTS_INVALID: List[str] = [
    "unavailable"
]
# endregion

# region #-- keys that are used in responses --#
KEY_ACTION_JNAP_RESPONSE_RESULTS: str = "output"
# endregion


# region #-- node types --#
NODE_TYPE_PRIMARY = "primary"
NODE_TYPE_SECONDARY = "secondary"
# endregion
