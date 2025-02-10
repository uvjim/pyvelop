"""Constants for the pyvelop module."""

from enum import IntEnum, StrEnum, auto

DEF_REDACT: str = "**REDACTED**"
DEF_EMPTY_NAME: str = "Network Device"


class DeviceProperty(StrEnum):
    """Property names for user device properties."""

    ACTUAL_WAN_SCHEDULE = "actualWanSchedule"
    BLOCK_ALL_MANUALLY = "blockAllManually"
    DEVICE_NAME = "userDeviceName"
    MANUFACTURER = "userDeviceManufacturer"
    MODEL = "userDeviceModelNumber"
    OPERATING_SYSTEM = "userDeviceOS"
    SHOW_IN_PC_LIST = "showInPCList"
    UI_TYPE = "userDeviceType"


class ParentalControlActionType(StrEnum):
    """Representation of parental control time actions."""

    BLOCKED = "0"
    UNBLOCKED = "1"


class UiType(StrEnum):
    """Available values for the device types used in the UI."""

    THREED_PRINTER = "3d-printer"
    AIR_PURIFIER = auto()
    AMAZON_DOT = auto()
    AMAZON_ECHO = auto()
    AMAZON_FIRETV_CUBE = auto()
    AMAZON_SHOW = auto()
    AMAZON_SPOT = auto()
    AMAZON_TAP = auto()
    ANDROID_WHITE = auto()
    APPLE_HOMEPOD = auto()
    APPLE_TIME_CAPSULE = auto()
    APPLE_TV = auto()
    APPLE_WATCH = auto()
    APPLICATION = auto()
    AUTOMATION_HUB = auto()
    CHROMECAST = auto()
    DESKTOP_MAC = auto()
    DESKTOP_PC = auto()
    DEVICE_ROUTER = auto()
    DIGITAL_CAMERA = auto()
    DIGITAL_MEDIA_PLAYER = auto()
    DOORBELL_CAM = auto()
    DVR = auto()
    FAN_CEILING = auto()
    FAN_SMALL = auto()
    GAME_CONSOLES = auto()
    GATEWAY = auto()
    GENERIC_CAMERA = auto()
    GENERIC_CELLPHONE = auto()
    GENERIC_DEVICE = auto()
    GENERIC_DISPLAY = auto()
    GENERIC_DRONE = auto()
    GENERIC_REMOTE = auto()
    GENERIC_ROBOT = auto()
    GENERIC_TABLET = auto()
    GENERIC_TABLET_WHITE = auto()
    GOOGLE_HOME = auto()
    GOOGLE_HOME_MINI = auto()
    GROUP2 = auto()
    GROUP2_2X = "group2@2x"
    GROUP2_3X = "group2@3x"
    GROUP5 = auto()
    GROUP5_2X = "group5@2x"
    GROUP5_3X = "group5@3x"
    IPAD_PRO_BLACK = auto()
    IPAD_PRO_WHITE = auto()
    LAPTOP_MAC = auto()
    LAPTOP_PC = auto()
    LINKSYS_BRIDGE = auto()
    LINKSYS_EXTENDER = auto()
    LINKSYS_VELOP = auto()
    MEDIA_ADAPTER = auto()
    MEDIA_STICK = auto()
    MX42 = auto()
    NEST_CAM = auto()
    NEST_HELLO = auto()
    NET_CAMERA = auto()
    NET_DRIVE = auto()
    NODE = auto()
    NODE_2X = "node@2x"
    NODE_3X = "node@3x"
    NODEICON_3X = "nodeicon@3x"
    PET_FEEDER = auto()
    PHOTO_FRAME = auto()
    PHYN_ASSISTANT = auto()
    PHYN_PLUS = auto()
    POWER_STRIP = auto()
    PRINT_SERVER = auto()
    PRINTER_INKJET = auto()
    PRINTER_LASER = auto()
    PRINTER_PHOTO = auto()
    ROUTER_DEFAULT = auto()
    ROUTER_EA2700 = auto()
    ROUTER_EA2750 = auto()
    ROUTER_EA3500 = auto()
    ROUTER_EA4500 = auto()
    ROUTER_EA6100 = auto()
    ROUTER_EA6300 = auto()
    ROUTER_EA6350 = auto()
    ROUTER_EA6350V4 = auto()
    ROUTER_EA6900 = auto()
    ROUTER_EA7200 = auto()
    ROUTER_EA7500 = auto()
    ROUTER_EA7500V3 = auto()
    ROUTER_EA8300 = auto()
    ROUTER_EA8500 = auto()
    ROUTER_EA9200 = auto()
    ROUTER_EA9300 = auto()
    ROUTER_EA9300_ = auto()
    ROUTER_EA9350 = auto()
    ROUTER_EA9500 = auto()
    ROUTER_MR6350 = auto()
    ROUTER_MR7350 = auto()
    ROUTER_MR7500 = auto()
    ROUTER_MX5300 = auto()
    ROUTER_NODES = auto()
    ROUTER_WHW01 = auto()
    ROUTER_WHW01B = auto()
    ROUTER_WHW01P = auto()
    ROUTER_WHW03B = auto()
    ROUTER_WRT1200AC = auto()
    ROUTER_WRT1900AC = auto()
    SECURITY_SYSTEM = auto()
    SERVER_MAC = auto()
    SERVER_PC = auto()
    SET_TOP_BOX = auto()
    SMART_CAR = auto()
    SMART_CROCKPOT = auto()
    SMART_LOCK = auto()
    SMART_MRCOFFEE = auto()
    SMART_SCALE = auto()
    SMART_SMOKE_DETECTOR = auto()
    SMART_SPEAKER = auto()
    SMART_SPRINKLER = auto()
    SMART_THERMOSTAT = auto()
    SMART_VACUUM = auto()
    SMART_VALVE = auto()
    SMART_WATCH = auto()
    SMARTPHONE = auto()
    SMARTPHONE_ANDROID = auto()
    SMARTPHONE_MAC = auto()
    SOUND_BAR = auto()
    SOUNDFORM_ELITE = auto()
    SOUNDFORM_ELITE_WHITE = auto()
    TABLET_EREADER = auto()
    TABLET_MAC = auto()
    TABLET_PC = auto()
    TV_HDTV = auto()
    VOIP_PHONE = auto()
    VR_HEADSET = auto()
    WEMO_DEVICE = auto()
    WEMO_DIMMER = auto()
    WEMO_INSIGHT = auto()
    WEMO_LEDBULB = auto()
    WEMO_LIGHTSWITCH = auto()
    WEMO_LINK = auto()
    WEMO_MAKER = auto()
    WEMO_MINI = auto()
    WEMO_NETCAM = auto()
    WEMO_OUTDOOR_PLUG = auto()
    WEMO_SENSOR = auto()
    WEMO_SOCKET = auto()
    WHIRLPOOL_FRIDGE = auto()
    WHW01 = auto()
    WHW01P = auto()
    WIRED_BRIDGE = auto()


class Weekdays(IntEnum):
    """Definition for weekdays."""

    SUNDAY = 0
    MONDAY = auto()
    TUESDAY = auto()
    WEDNESDAY = auto()
    THURSDAY = auto()
    FRIDAY = auto()
    SATURDAY = auto()


class MeshCapability(StrEnum):
    """The possible capabilities available to the Mesh."""

    GET_ALG_SETTINGS = "alg_settings"
    GET_BACKHAUL = "backhaul"
    GET_CHANNEL_SCAN_STATUS = "channel_scan_status"
    GET_DEVICES = "devices"
    GET_EXPRESS_FORWARDING = "express_forwarding"
    GET_FIRMWARE_UPDATE_SETTINGS = "firmware_update_settings"
    GET_GUEST_NETWORK_INFO = "guest_network_info"
    GET_HOMEKIT_SETTINGS = "homekit_settings"
    GET_LAN_SETTINGS = "lan_setting"
    GET_MAC_FILTERING_SETTINGS = "mac_filtering_settings"
    GET_NETWORK_CONNECTIONS = "network_connections"
    GET_PARENTAL_CONTROL_INFO = "parental_control_info"
    GET_SPEEDTEST_RESULTS = "speedtest_results"
    GET_SPEEDTEST_STATUS = "speedtest_status"
    GET_STORAGE_PARTITIONS = "storage_partitions"
    GET_STORAGE_SMB_SERVER = "storage_smb_server"
    GET_TOPOLOGY_OPTIMISATION_SETTINGS = "topology_optimisation_settings"
    GET_UPDATE_FIRMWARE_STATE = "update_firmware_state"
    GET_UPNP_SETTINGS = "upnp_settings"
    GET_WAN_INFO = "wan_info"
    GET_WPS_SERVER_SETTINGS = "wps_server_settings"
