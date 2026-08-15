"""Representations of entities on the mesh."""

# region #-- imports --#
from __future__ import annotations

import asyncio
import base64
import contextlib
import datetime as dt
import logging
from collections import namedtuple
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from enum import IntEnum, StrEnum, auto
from typing import TYPE_CHECKING, Any, cast, final, override

from . import jnap as api
from .action_registry import ActionKey, Actions, ActionScope
from .exceptions import MeshException, MeshInvalidInput
from .logger import Logger
from .mesh_attribute import AttributeAction, AttributeAuditEntry, MeshAttribute

if TYPE_CHECKING:
    from .mesh import MeshDetails

# endregion

_LOGGER: logging.Logger = logging.getLogger(__name__)

EMPTY_NAME: str = "Network Device"


class ConnectionType(StrEnum):
    """Connection types."""

    UNKNOWN = "Unknown"
    WIRED = "Wired"
    WIRELESS = "Wireless"


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


class EntityDataProperties(StrEnum):
    """Property names to retrieve from raw data."""

    BACKHAUL = Actions.GET_BACKHAUL.key
    CONNECTED_ENTITIES = "connected_entities"
    DEVICE_DETAILS = Actions.GET_DEVICES.key
    FIRMWARE_DETAILS = Actions.GET_UPDATE_FIRMWARE_STATE.key
    NODE_NETWORK_CONNECTIONS = Actions.GET_NETWORK_CONNECTIONS.key
    PARENT_ENTITY = "parent_entity"
    PARENTAL_CONTROLS = Actions.GET_PARENTAL_CONTROL_INFO.key
    RESERVATION_DETAILS = Actions.GET_LAN_SETTINGS.key
    RESULTS_TIME = "results_time"
    WIRELESS_CONNECTION_DETAILS = Actions.GET_NODE_WIRELESS_CONNECTIONS.key


class NodeType(StrEnum):
    """Enumeration for node types."""

    PRIMARY = auto()
    SECONDARY = auto()
    UNKNOWN = auto()


class ParentalControlActionType(StrEnum):
    """Representation of parental control time actions."""

    BLOCKED = "0"
    UNBLOCKED = "1"


class SignalStrength(StrEnum):
    """Enumeration for signal strength."""

    EXCELLENT = auto()
    FAIR = auto()
    GOOD = auto()
    WEAK = auto()


class UiType(StrEnum):
    """Available values for the device types used in the UI."""

    AIR_PURIFIER = "air-purifier"
    AMAZON_DOT = "amazon-dot"
    AMAZON_ECHO = "amazon-echo"
    AMAZON_FIRETV_CUBE = "amazon-firetv-cube"
    AMAZON_SHOW = "amazon-show"
    AMAZON_SPOT = "amazon-spot"
    AMAZON_TAP = "amazon-tap"
    ANDROID_WHITE = "android-white"
    APPLE_HOMEPOD = "apple-homepod"
    APPLE_TV = "apple-tv"
    APPLE_WATCH = "apple-watch"
    AUTOMATION_HUB = "automation-hub"
    DESKTOP_MAC = "desktop-mac"
    DESKTOP_PC = "desktop-pc"
    DEVICE_ROUTER = "device-router"
    DIGITAL_CAMERA = "digital-camera"
    DIGITAL_MEDIA_PLAYER = "digital-media-player"
    DOORBELL_CAM = "doorbell-cam"
    DVR = "dvr"
    EXTENDER_RE7000 = "extender-re7000"
    FAN_CEILING = "fan-ceiling"
    FAN_SMALL = "fan-small"
    GAME_CONSOLES = "game-consoles"
    GATEWAY = "gateway"
    GENERIC_CAMERA = "generic-camera"
    GENERIC_CELLPHONE = "generic-cellphone"
    GENERIC_DEVICE = "generic-device"
    GENERIC_DISPLAY = "generic-display"
    GENERIC_DRONE = "generic-drone"
    GENERIC_REMOTE = "generic-remote"
    GENERIC_ROBOT = "generic-robot"
    GENERIC_TABLET = "generic-tablet"
    GENERIC_TABLET_WHITE = "generic-tablet-white"
    GOOGLE_HOME = "google-home"
    IPAD_PRO_BLACK = "ipad-pro-black"
    IPAD_PRO_WHITE = "ipad-pro-white"
    LAPTOP_MAC = "laptop-mac"
    LAPTOP_PC = "laptop-pc"
    LINKSYS_BRIDGE = "linksys-bridge"
    LINKSYS_EXTENDER = "linksys-extender"
    MEDIA_ADAPTER = "media-adapter"
    MEDIA_STICK = "media-stick"
    NEST_CAM = "nest-cam"
    NEST_HELLO = "nest-hello"
    NET_CAMERA = "net-camera"
    NET_DRIVE = "net-drive"
    PET_FEEDER = "pet-feeder"
    PHOTO_FRAME = "photo-frame"
    PHYN_ASSISTANT = "phyn_assistant"
    PHYN_PLUS = "phyn-plus"
    POWER_STRIP = "power-strip"
    PRINT_SERVER = "print-server"
    PRINTER_INKJET = "printer-inkjet"
    PRINTER_LASER = "printer-laser"
    PRINTER_PHOTO = "printer-photo"
    ROUTER_DEFAULT = "router-default"
    ROUTER_EA2700 = "router-ea2700"
    ROUTER_EA3500 = "router-ea3500"
    ROUTER_EA4500 = "router-ea4500"
    ROUTER_EA6100 = "router-ea6100"
    ROUTER_EA6200 = "router-ea6200"
    ROUTER_EA6300 = "router-ea6300"
    ROUTER_EA6350 = "router-ea6350"
    ROUTER_EA6400 = "router-ea6400"
    ROUTER_EA6500 = "router-ea6500"
    ROUTER_EA6700 = "router-ea6700"
    ROUTER_EA6900 = "router-ea6900"
    ROUTER_EA7400 = "router-ea7400"
    ROUTER_EA7500 = "router-ea7500"
    ROUTER_EA8300 = "router-ea8300"
    ROUTER_EA8500 = "router-ea8500"
    ROUTER_EA9200 = "router-ea9200"
    ROUTER_EA9300 = "router-ea9300"
    ROUTER_EA9500 = "router-ea9500"
    ROUTER_WHW03 = "router-whw03"
    ROUTER_WRT1200AC = "router-wrt1200ac"
    ROUTER_WRT1900AC = "router-wrt1900ac"
    ROUTER_XAC1200 = "router-xac1200"
    ROUTER_XAC1900 = "router-xac1900"
    SECURITY_SYSTEM = "security-system"
    SERVER_MAC = "server-mac"
    SERVER_PC = "server-pc"
    SET_TOP_BOX = "set-top-box"
    SMART_CAR = "smart-car"
    SMART_CROCKPOT = "smart-crockpot"
    SMART_LOCK = "smart-lock"
    SMART_MRCOFFEE = "smart-mrcoffee"
    SMART_SCALE = "smart-scale"
    SMART_SMOKE_DETECTOR = "smart-smoke-detector"
    SMART_SPEAKER = "smart-speaker"
    SMART_SPRINKLER = "smart-sprinkler"
    SMART_THERMOSTAT = "smart-thermostat"
    SMART_VACUUM = "smart-vacuum"
    SMART_VALVE = "smart-valve"
    SMART_WATCH = "smart-watch"
    SMARTPHONE = "smartphone"
    SOUND_BAR = "sound-bar"
    SOUNDFORM_ELITE = "soundform-elite"
    SOUNDFORM_ELITE_WHITE = "soundform-elite-white"
    TABLET_EREADER = "tablet-ereader"
    TABLET_PC = "tablet-pc"
    THREE_D_PRINTER = "three-d-printer"
    TV_HDTV = "tv-hdtv"
    VOIP_PHONE = "voip-phone"
    VR_HEADSET = "vr-headset"
    WEMO_DEVICE = "wemo-device"
    WEMO_INSIGHT = "wemo-insight"
    WEMO_LEDBULB = "wemo-ledbulb"
    WEMO_LIGHTSWITCH = "wemo-lightswitch"
    WEMO_LINK = "wemo-link"
    WEMO_MAKER = "wemo-maker"
    WEMO_MINI = "wemo-mini"
    WEMO_NETCAM = "wemo-netcam"
    WEMO_OUTDOOR_PLUG = "wemo-outdoor-plug"
    WEMO_SENSOR = "wemo-sensor"
    WEMO_SOCKET = "wemo-socket"
    WHIRLPOOL_FRIDGE = "whirlpool-fridge"
    WIRED_BRIDGE = "wired-bridge"


class Weekdays(IntEnum):
    """Definition for weekdays."""

    SUNDAY = 0
    MONDAY = auto()
    TUESDAY = auto()
    WEDNESDAY = auto()
    THURSDAY = auto()
    FRIDAY = auto()
    SATURDAY = auto()


@dataclass(frozen=True, slots=True)
class AdapterInfo:
    """Representation of adapter information."""

    band: str | None = None
    connected: bool = False
    guest_network: bool | None = None
    ip: str | None = None
    ipv6: str | None = None
    mac: str | None = None
    negotiated_mbps: int | None = None
    parent_id: str | None = None
    reservation: bool = False
    reservation_description: str | None = None
    rssi_dbm: int | None = None
    signal_strength: SignalStrength | None = None
    type: ConnectionType = ConnectionType.UNKNOWN

    def to_dict(self) -> dict[str, Any]:
        """Return the instance as a dictionary."""

        return {
            "band": self.band,
            "connected": self.connected,
            "guest_network": self.guest_network,
            "ip": self.ip,
            "ipv6": self.ipv6,
            "mac": self.mac,
            "negotiated_mbps": self.negotiated_mbps,
            "parent_id": self.parent_id,
            "reservation": self.reservation,
            "reservation_description": self.reservation_description,
            "rssi_dbm": self.rssi_dbm,
            "signal_strength": self.signal_strength.value if self.signal_strength is not None else None,
            "type": self.type.value,
        }


@dataclass(frozen=True, slots=True)
class NodeAdapterInfo(AdapterInfo):
    """Representation of adapter information for a node."""

    primary: bool = False

    @override
    def to_dict(self) -> dict[str, Any]:

        ret = super().to_dict()
        ret.update(
            {
                "primary": self.primary,
            }
        )

        return ret


@dataclass(frozen=True, slots=True)
class BackhaulInfo:
    """Representation of backhaul information."""

    connection: ConnectionType | None
    last_checked: dt.datetime | None
    speed_mbps: float | None
    rssi_dbm: int | None
    signal_strength: SignalStrength | None

    def to_dict(self) -> dict[str, Any]:
        """Return the instance as a dictionary."""

        return {
            "connection": self.connection.value if self.connection else None,
            "last_checked": "",
            "speed_mbps": self.speed_mbps,
            "rssi_dbm": self.rssi_dbm,
            "signal_strength": self.signal_strength.value if self.signal_strength is not None else None,
        }


class ParentalControl:
    """Class to manage parental control schedules."""

    BINARY_LENGTH: int = 48
    DEFAULT_DESCRIPTION: str = "default description"

    ALL_ALLOWED_SCHEDULE: Callable[..., dict[str, Any]] = lambda: {
        day.name.lower(): ParentalControlActionType.UNBLOCKED.value * ParentalControl.BINARY_LENGTH for day in Weekdays
    }

    ALL_PAUSED_SCHEDULE: Callable[..., dict[str, Any]] = lambda: {
        day.name.lower(): ParentalControlActionType.BLOCKED.value * ParentalControl.BINARY_LENGTH for day in Weekdays
    }

    def __init__(self, rule: dict[str, Any]) -> None:
        """Initialise.

        :param rule: a single rule object as returned by the API
        """
        self._rule: dict[str, Any] = rule

    @staticmethod
    def _human_readable(schedule: dict[str, Any]) -> dict[str, list[str]]:
        """Make the given schedule human readable."""
        ret: dict[str, list[str]] = {}
        for day, sched in schedule.items():
            ret[day.lower()] = []
            idx: int = 0
            while idx < ParentalControl.BINARY_LENGTH:
                block_start: int | None = (
                    sched.index(ParentalControlActionType.BLOCKED.value, idx)
                    if sched is not None and ParentalControlActionType.BLOCKED.value in sched[idx + 1 :]
                    else None
                )
                if block_start is None:
                    break
                block_end: int | None = (
                    sched.index(ParentalControlActionType.UNBLOCKED.value, block_start + 1)
                    if sched is not None and ParentalControlActionType.UNBLOCKED.value in sched[block_start + 1 :]
                    else None
                )
                start_time = dt.time(
                    hour=int(block_start / 2),
                    minute=(30 if block_start % 2 == 1 else 0),
                )
                end_time = (
                    dt.time(
                        hour=int(block_end / 2),
                        minute=(30 if block_end % 2 == 1 else 0),
                    )
                    if block_end
                    else dt.time(hour=0, minute=0)
                )
                ret[day.lower()].append(f"{start_time.strftime('%H:%M')}-{end_time.strftime('%H:%M')}")
                if block_end is not None:
                    idx = block_end + 1
                else:
                    idx = ParentalControl.BINARY_LENGTH

        return ret

    @staticmethod
    def backup_to_binary(schedule: str) -> dict[str, str]:
        """Decode the schedule for restoring to the device."""
        ret: dict[str, str] = {}
        decoded = base64.b64decode(schedule) if schedule else b""
        sorted_schedule: str = ""
        for chunk in decoded:
            sorted_schedule += f"{int(chunk):08b}"

        for daily_schedule in range(0, len(list(Weekdays))):
            start = daily_schedule * ParentalControl.BINARY_LENGTH
            ret[Weekdays(daily_schedule).name.lower()] = sorted_schedule[start : start + ParentalControl.BINARY_LENGTH]

        return ret

    @staticmethod
    def encode_for_backup(schedule: dict[str, str]) -> str:
        """Encode the schedule for storage in a property."""
        ret: str = ""
        chunk_length: int = 8
        sorted_schedule: str = "".join([schedule[day.name.lower()] for day in list(Weekdays)])
        sorted_chunks: list[str] = [
            (sorted_schedule[i : i + chunk_length]) for i in range(0, len(sorted_schedule), chunk_length)
        ]

        chunk_chars = bytearray()
        for chunk in sorted_chunks:
            chunk_chars.append(int(chunk, base=2))

        if chunk_chars:
            ret = base64.b64encode(chunk_chars).decode()
        else:
            ret = ""
        return ret

    @staticmethod
    def create_rule(
        mac_address: str,
        schedule: dict[str, Any],
        blocked_urls: list[str] | None = None,
        schedule_to_binary: bool = True,
    ) -> dict[str, Any]:
        """Generate a rule dictionary that can be passed to the API."""
        ret: dict[str, Any] = {
            "blockedURLs": blocked_urls if blocked_urls is not None else [],
            "description": ParentalControl.DEFAULT_DESCRIPTION,
            "isEnabled": True,
            "macAddresses": [mac_address],
            "wanSchedule": (schedule if not schedule_to_binary else ParentalControl.human_readable_to_binary(schedule)),
        }
        return ret

    @staticmethod
    def human_readable_to_binary(
        to_encode: str | dict[str, Any],
    ) -> str | dict[str, Any]:
        """Encode the human readable information to something that can be stored."""
        fake_day: str = "sunday"
        to_process: dict[str, Any]
        if isinstance(to_encode, str):
            to_process = {fake_day: to_encode}
        else:
            to_process = to_encode
            if len(to_process) > len(Weekdays):
                raise ValueError("Too many arguments")

        ret_dict: dict[str, str] = {}
        for day, schedule in to_process.items():
            default_binary = [ParentalControlActionType.UNBLOCKED.value] * ParentalControl.BINARY_LENGTH
            if schedule is not None:
                time_schedules: list[str] = schedule.split(",")
                TimeBlock = namedtuple("TimeBlock", ["start", "end"])
                for schedule in time_schedules:
                    times: list[str] = schedule.split("-")
                    time_block: TimeBlock = TimeBlock(
                        dt.datetime.strptime(times[0].strip(), "%H:%M"),
                        dt.datetime.strptime(times[1].strip(), "%H:%M"),
                    )
                    if (  # midnight to midnight
                        time_block.start == time_block.end
                        and time_block.start.hour == 0
                        and time_block.start.minute == 0
                    ):
                        offset_start = 0
                        offset_end = ParentalControl.BINARY_LENGTH
                    elif (  # time wrapping
                        time_block.end < time_block.start and str(time_block.end.time()) != "00:00:00"
                    ):
                        offset_start = 0
                        offset_end = ParentalControl.BINARY_LENGTH
                    else:  # normal time
                        offset_start = time_block.start.hour * 2 + (1 if time_block.start.minute >= 30 else 0)
                        offset_end = (  # extend to end if midnight is the end time
                            time_block.end.hour
                            if time_block.end.hour != 0 or (time_block.end.hour == 0 and time_block.start.hour == 0)
                            else 24
                        ) * 2 + (1 if time_block.end.minute >= 30 else 0)

                    for idx in range(offset_start, offset_end):
                        default_binary[idx] = ParentalControlActionType.BLOCKED.value

                    if all(  # break out early if all blocked
                        val == ParentalControlActionType.BLOCKED.value for val in default_binary
                    ):
                        break

            ret_dict[day] = "".join(default_binary)

        if isinstance(to_encode, str):
            return ret_dict[fake_day]

        return ret_dict

    @staticmethod
    def binary_to_human_readable(
        to_decode: str | dict[str, str],
    ) -> str | dict[str, list[str]]:
        """Decode the binary format string to humand readble form."""
        ret: str | dict[str, list[str]]
        if isinstance(to_decode, str):
            fake_day: str = "sunday"
            fake_obj = {fake_day: to_decode}
            fake_ret = ParentalControl._human_readable(fake_obj)
            ret = ",".join(fake_ret[fake_day])
        else:
            ret = ParentalControl._human_readable(to_decode)

        return ret

    @property
    def blocked_urls(self) -> list[str]:
        """Return blocked URLs."""
        return cast(list[str], self._rule.get("blockedURLs", []))

    @property
    def description(self) -> str:
        """Return the rule description."""
        return cast(str, self._rule.get("description", ParentalControl.DEFAULT_DESCRIPTION))

    @property
    def human_readable(self) -> dict[str, list[str]]:
        """Return the schedule in human readable form."""
        return self._human_readable(schedule=self.schedule)

    @property
    def is_enabled(self) -> bool:
        """Return whether the rule is enabled or not."""
        return cast(bool, self._rule.get("isEnabled", True))

    @property
    def is_paused(self) -> bool:
        """Return whether the rule is all blocking."""
        return self.schedule == ParentalControl.ALL_PAUSED_SCHEDULE()

    @property
    def mac_addresses(self) -> list[str]:
        """Return the MAC addresses the rule is for."""
        return cast(list[str], self._rule.get("macAddresses", []))

    @final
    @property
    def rule(self) -> dict[str, Any]:
        """Return the rule."""
        return {
            "blockedURLs": self.blocked_urls,
            "description": self.description,
            "isEnabled": self.is_enabled,
            "macAddresses": self.mac_addresses,
            "wanSchedule": self.schedule,
        }

    @property
    def schedule(self) -> dict[str, str]:
        """Return the current internet access schedule used in the rule."""
        return cast(dict[str, str], self._rule.get("wanSchedule", {}))


class MeshEntity:
    """Represents a base level entity on the mesh."""

    def __init__(
        self,
        data: dict[str, Any],
        mesh_details: MeshDetails,
        supplementary_redactions: dict[str, set[str]] | None = None,
    ) -> None:
        """Initialise."""

        self._data: dict[str, Any] = data
        self._log_formatter = Logger()
        self._mesh_details: MeshDetails = mesh_details
        self._supplementary_redactions: dict[str, set[str]] | None = supplementary_redactions

    def __repr__(self) -> str:
        """Make a pretty string representation of the class.

        :return: Takes the class name and the name of the device to build the representation
        """
        ret = f"{self.__class__.__name__}: "
        if self.name:
            ret += str(self.name)
        return ret

    def _get_user_property(self, property_name: DeviceProperty) -> str | None:
        """Get the given property from the user properties."""
        ret: str | None = None

        user_properties: list[dict[str, Any]] = self._data.get(EntityDataProperties.DEVICE_DETAILS, {}).get(
            "properties", []
        )
        user_prop: list[dict[str, Any]] = [prop for prop in user_properties if prop.get("name") == property_name.value]
        if user_prop:
            ret = user_prop[0].get("value")

        return ret

    @staticmethod
    def _signal_strength_to_text(rssi: int | None) -> SignalStrength | None:
        """Convert the given RSSI value to a textual representation."""
        ret: SignalStrength | None = None
        if rssi is not None:
            if rssi <= 0:
                ret = SignalStrength.EXCELLENT
            if rssi <= -50:
                ret = SignalStrength.GOOD
            if rssi <= -60:
                ret = SignalStrength.FAIR
            if rssi <= -70:
                ret = SignalStrength.WEAK

        return ret

    def _update_connected_devices(self, new_device: MeshEntity) -> None:
        """Update the connected devices."""

        cur_devices: list[MeshEntity] = self._data.get(EntityDataProperties.CONNECTED_ENTITIES, [])
        cur_devices.append(new_device)
        self._data.update({EntityDataProperties.CONNECTED_ENTITIES: cur_devices})

    def _update_parent(self, new_parent: MeshAttribute[NodeEntity | None]) -> None:
        """Set the parent entity for this entity."""

        self._data.update({EntityDataProperties.PARENT_ENTITY: new_parent})

    async def _async_api_request(
        self,
        action: str,
        payload: list[dict[str, Any]] | dict[str, Any] | None = None,
        *,
        ip: str | None = None,
        raise_on_error: bool = True,
    ) -> api.Response:
        """Make a request to the API."""
        req = api.Request(
            action=action,
            password=self._mesh_details.password,
            payload=payload,
            raise_on_error=raise_on_error,
            session=self._mesh_details.session,
            target=ip or self._mesh_details.host,
            username=self._mesh_details.user,
            supplementary_redactions=self._supplementary_redactions,
        )
        try:
            resp = await req.execute(timeout=self._mesh_details.request_timeout)
        except Exception as exc:
            raise exc from None

        return resp

    def to_dict(self) -> dict[str, Any]:
        """Return the instance as a dictionary."""

        ret: dict[str, Any] = {
            "adapter_info": [adi.to_dict() for adi in self.adapter_info.value],
            "description": self.description.to_dict(),
            "manufacturer": self.manufacturer.to_dict(),
            "model": self.model.to_dict(),
            "name": self.name.to_dict(),
            "parent": {"audit": [ae.to_dict() for ae in self.parent_name.audit], "value": repr(self.parent.value)},
            "parent_ip": self.parent_ip.to_dict(),
            "parent_ipv6": self.parent_ipv6.to_dict(),
            "parent_name": self.parent_name.to_dict(),
            "results_time": self.results_time,
            "serial": self.serial.to_dict(),
            "status": self.status.to_dict(),
            "ui_type": self.ui_type.to_dict(),
            "unique_id": self.unique_id.to_dict(),
        }

        return ret

    @property
    def adapter_info(self) -> MeshAttribute[list[AdapterInfo]]:
        """Retrieve details about the entity's adapters.

        :return: Adapter details
        """

        audit_history: list[AttributeAuditEntry] = []
        ret: list[AdapterInfo] = []
        props: dict[str, Any] = {}

        # -- get the adapters based on known interfaces --#
        my_adapters: list[dict[str, Any]] = self._data.get(EntityDataProperties.DEVICE_DETAILS, {}).get(
            "knownInterfaces", []
        )
        for adapter in my_adapters:
            props: dict[str, Any] = {}
            props_adapter: dict[str, Any] = {
                "band": adapter.get("band"),
                "mac": adapter.get("macAddress"),
            }
            audit_history.append(AttributeAuditEntry(EntityDataProperties.DEVICE_DETAILS.value, props_adapter))
            props.update(props_adapter)

            # region #-- derive details from the device details --#
            props_ci: dict[str, Any] = {}
            connection_info: dict[str, Any] | None = next(
                (
                    conn
                    for conn in self._data.get(EntityDataProperties.DEVICE_DETAILS, {}).get("connections", [])
                    if conn.get("macAddress", "").lower() == adapter.get("macAddress", "").lower()
                ),
                None,
            )
            if connection_info is not None:
                props_ci = {
                    "guest_network": connection_info.get("isGuest", False),
                    "ip": connection_info.get("ipAddress"),
                    "ipv6": connection_info.get("ipv6Address"),
                }
                audit_history.append(
                    AttributeAuditEntry(EntityDataProperties.DEVICE_DETAILS.value, props_ci, type=AttributeAction.MERGE)
                )
                props.update(props_ci)
            # endregion

            # region #-- derive reservation information --#
            props_reservation: dict[str, Any] = {}
            reservation_info: dict[str, Any] | None = self._data.get(EntityDataProperties.RESERVATION_DETAILS)
            if reservation_info is not None:
                props_reservation = {
                    "reservation": bool(reservation_info),
                    "reservation_description": reservation_info.get("description"),
                }
                audit_history.append(
                    AttributeAuditEntry(
                        EntityDataProperties.RESERVATION_DETAILS.value, props_reservation, type=AttributeAction.MERGE
                    )
                )
                props.update(props_reservation)
            # endregion

            # region #-- derive wireless information --#
            props_wifi: dict[str, Any] = {}
            wifi_info: dict[str, Any] | None = self._data.get(EntityDataProperties.WIRELESS_CONNECTION_DETAILS)
            if (
                wifi_info is not None
                and wifi_info.get("macAddress", "").lower() == adapter.get("macAddress", "").lower()
            ):
                signal_strength: SignalStrength | None = self._signal_strength_to_text(
                    wifi_info.get("wireless", {}).get("signalDecibels")
                )
                props_wifi = {
                    "negotiated_mbps": wifi_info.get("negotiatedMbps"),
                    "rssi_dbm": wifi_info.get("wireless", {}).get("signalDecibels"),
                    "signal_strength": signal_strength,
                }
                audit_history.append(
                    AttributeAuditEntry(
                        EntityDataProperties.WIRELESS_CONNECTION_DETAILS.value, props_wifi, type=AttributeAction.MERGE
                    )
                )
                props.update(props_wifi)
            # endregion

            # region #-- derive the adapter connection type --#
            adapter_conn_type: ConnectionType = ConnectionType(adapter.get("interfaceType", "Unknown"))
            props_type: dict[str, Any] = {
                "type": adapter_conn_type,
            }
            audit_history.append(
                AttributeAuditEntry(
                    EntityDataProperties.DEVICE_DETAILS.value,
                    props_type,
                    type=AttributeAction.MERGE,
                )
            )

            if adapter_conn_type == ConnectionType.UNKNOWN and props_wifi:
                props_type = {
                    "type": ConnectionType.WIRELESS,
                }
                audit_history.append(
                    AttributeAuditEntry(
                        EntityDataProperties.WIRELESS_CONNECTION_DETAILS.value,
                        props_type,
                        type=AttributeAction.MERGE,
                    )
                )

            if adapter_conn_type == ConnectionType.UNKNOWN:
                node_network_conns: dict[str, Any] | None = self._data.get(
                    EntityDataProperties.NODE_NETWORK_CONNECTIONS
                )
                if node_network_conns is not None:
                    props_type = {
                        "type": ConnectionType.WIRELESS if node_network_conns.get("wireless") else ConnectionType.WIRED
                    }
                    audit_history.append(
                        AttributeAuditEntry(
                            EntityDataProperties.NODE_NETWORK_CONNECTIONS.value,
                            props_type,
                            type=AttributeAction.MERGE,
                        )
                    )
            props.update(props_type)
            # endregion

            # region #-- infer the adapter connected state if we can --#
            adapter_conn_state: bool = bool(connection_info)
            props_state: dict[str, bool] = {
                "connected": adapter_conn_state,
            }
            audit_history.append(
                AttributeAuditEntry(EntityDataProperties.DEVICE_DETAILS.value, props_state, type=AttributeAction.MERGE)
            )
            if not adapter_conn_state and wifi_info:
                props["connected"] = True
                audit_history.append(
                    AttributeAuditEntry(
                        EntityDataProperties.DEVICE_DETAILS.value, props_state, type=AttributeAction.MERGE
                    )
                )
            props.update(props_state)
            # endregion

            # region #-- parent details --#
            if props.get("connected"):
                parent: MeshAttribute[NodeEntity | None] | None = cast(
                    MeshAttribute[NodeEntity | None] | None, self._data.get(EntityDataProperties.PARENT_ENTITY)
                )
                props_parent: dict[str, Any] = {}
                if parent is not None and parent.value is not None:
                    props_parent = {"parent_id": parent.value.unique_id.value}
                audit_history.append(
                    AttributeAuditEntry(
                        EntityDataProperties.DEVICE_DETAILS.value, props_parent, type=AttributeAction.MERGE
                    )
                )
                props.update(props_parent)
            # endregion

            ret.append(AdapterInfo(**props))

        return MeshAttribute[list[AdapterInfo]](ret, tuple(audit_history))

    @property
    def description(self) -> MeshAttribute[str | None]:
        """Get the description.

        :return: Device description as per the mesh
        """

        attr: str | None = self._data.get(EntityDataProperties.DEVICE_DETAILS, {}).get("model", {}).get("description")

        return MeshAttribute[str | None](attr, (AttributeAuditEntry(EntityDataProperties.DEVICE_DETAILS.value, attr),))

    @property
    def manufacturer(self) -> MeshAttribute[str | None]:
        """Get the node manufacturer.

        :return: String containing the name of the manufacturer
        """

        ret: str | None = self._data.get(EntityDataProperties.DEVICE_DETAILS, {}).get("model", {}).get("manufacturer")

        return MeshAttribute[str | None](ret, (AttributeAuditEntry(EntityDataProperties.DEVICE_DETAILS.value, ret),))

    @property
    def model(self) -> MeshAttribute[str | None]:
        """Get the model.

        :return: Model as found by the mesh
        """

        ret: str | None = self._get_user_property(DeviceProperty.MODEL) or self._data.get(
            EntityDataProperties.DEVICE_DETAILS, {}
        ).get("model", {}).get("modelNumber")

        return MeshAttribute[str | None](ret, (AttributeAuditEntry(EntityDataProperties.DEVICE_DETAILS.value, ret),))

    @property
    def name(self) -> MeshAttribute[str]:
        """Retrieve the name of the entity.

        :return: The name of the entity
        """

        audit: list[AttributeAuditEntry] = []
        name_discovered: str | None = self._data.get(EntityDataProperties.DEVICE_DETAILS, {}).get("friendlyName")
        audit.append(AttributeAuditEntry(EntityDataProperties.DEVICE_DETAILS.value, name_discovered))
        name_user: str | None = self._get_user_property(DeviceProperty.DEVICE_NAME)
        if name_user:
            audit.append(
                AttributeAuditEntry(EntityDataProperties.DEVICE_DETAILS.value, name_user, type=AttributeAction.REPLACE)
            )

        ret = name_user or name_discovered or EMPTY_NAME

        if ret == EMPTY_NAME:
            audit.append(
                AttributeAuditEntry(EntityDataProperties.DEVICE_DETAILS.value, EMPTY_NAME, type=AttributeAction.REPLACE)
            )

        return MeshAttribute[str](ret, tuple(audit))

    @property
    def parent(self) -> MeshAttribute[NodeEntity | None]:
        """Return the parent entity."""

        ret: NodeEntity | None = None
        audit_history: tuple[AttributeAuditEntry, ...] = ()
        parent: MeshAttribute[NodeEntity | None] | None = self._data.get(EntityDataProperties.PARENT_ENTITY)
        if parent is not None:
            ret = parent.value
            audit_history = parent.audit

        return MeshAttribute[NodeEntity | None](ret, audit_history)

    @property
    def parent_ip(self) -> MeshAttribute[str | None]:
        """IP of the parent node.

        :return: The IP of the parent node or None if no node has been identified.
        """

        audit_history: tuple[AttributeAuditEntry, ...] = ()
        ret: str | None = None
        parent: MeshAttribute[NodeEntity | None] | None = self._data.get(EntityDataProperties.PARENT_ENTITY)
        if parent is not None and parent.value is not None:
            parent_adi: NodeAdapterInfo | None = next(
                (adi for adi in parent.value.adapter_info.value if adi.primary), None
            )
            if parent_adi is not None:
                audit_history = parent.value.adapter_info.audit
                ret = parent_adi.ip

        return MeshAttribute[str | None](ret, tuple(audit_history))

    @property
    def parent_ipv6(self) -> MeshAttribute[str | None]:
        """IPv6 of the parent node.

        :return: The IPv6 of the parent node or None if no node has been identified.
        """

        audit_history: tuple[AttributeAuditEntry, ...] = ()
        ret: str | None = None
        parent: MeshAttribute[NodeEntity | None] | None = self._data.get(EntityDataProperties.PARENT_ENTITY)
        if parent is not None and parent.value is not None:
            parent_adi: NodeAdapterInfo | None = next(
                (adi for adi in parent.value.adapter_info.value if adi.primary), None
            )
            if parent_adi is not None:
                audit_history = parent.value.adapter_info.audit
                ret = parent_adi.ipv6

        return MeshAttribute[str | None](ret, tuple(audit_history))

    @property
    def parent_name(self) -> MeshAttribute[str | None]:
        """Name of the node the device is connected to.

        :return: The parent node name or None if no node has been identified.
        """

        audit_history: tuple[AttributeAuditEntry, ...] = ()
        ret: str | None = None
        parent: MeshAttribute[NodeEntity | None] | None = self._data.get(EntityDataProperties.PARENT_ENTITY)
        if parent is not None and parent.value is not None:
            parent_name: MeshAttribute[str] = parent.value.name
            audit_history = parent_name.audit
            ret = parent_name.value

        return MeshAttribute[str | None](ret, audit_history)

    @property
    def raw_details(self) -> dict[str, Any]:
        """Return the raw details used to build the entity."""

        return self._data

    @property
    def results_time(self) -> int | None:
        """Get the time that the API was queried for the device results.

        :return: The time the scan was executed
        """
        return cast(int | None, self._data.get(EntityDataProperties.RESULTS_TIME))

    @property
    def serial(self) -> MeshAttribute[str | None]:
        """Get the serial number of the node.

        :return: A string containing the serial number
        """

        ret: str | None = self._data.get(EntityDataProperties.DEVICE_DETAILS, {}).get("unit", {}).get("serialNumber")

        return MeshAttribute[str | None](ret, (AttributeAuditEntry(EntityDataProperties.DEVICE_DETAILS.value, ret),))

    @property
    def status(self) -> MeshAttribute[bool | None]:
        """Get whether the device is currently connected to the mesh or not.

        Assumes that if there are no connections specified for the device then it is offline.
        Will also check if there are wireless connection details because these shouldn't exist if the device is offline.

        :return: True if connected. False if not.
        """

        audit: list[AttributeAuditEntry] = []
        conns: bool = bool(self._data.get(EntityDataProperties.DEVICE_DETAILS.value, {}).get("connections", []))
        audit.append(AttributeAuditEntry(EntityDataProperties.DEVICE_DETAILS.value, conns))
        if not conns:  # check if there are wireless connection details
            conns = bool(self._data.get(EntityDataProperties.WIRELESS_CONNECTION_DETAILS, {}))
            audit.append(
                AttributeAuditEntry(
                    EntityDataProperties.WIRELESS_CONNECTION_DETAILS.value, conns, type=AttributeAction.REPLACE
                )
            )

        return MeshAttribute[bool | None](conns, tuple(audit))

    @property
    def ui_type(self) -> MeshAttribute[UiType | str | None]:
        """Get the type assigned to the device as per the web UI.

        :return: The icon slug if available.  None otherwise.
        """

        ret: UiType | str | None = None
        ui_type: str | None = self._get_user_property(DeviceProperty.UI_TYPE)
        if ui_type is not None:
            try:
                ret = UiType(ui_type)
            except ValueError:
                ret = ui_type

        return MeshAttribute[UiType | str | None](
            ret, (AttributeAuditEntry(EntityDataProperties.DEVICE_DETAILS.value, ret),)
        )

    @property
    def unique_id(self) -> MeshAttribute[str | None]:
        """Return the unique id of the entity."""

        ret: str | None = self._data.get(EntityDataProperties.DEVICE_DETAILS, {}).get("deviceID")

        return MeshAttribute[str | None](ret, (AttributeAuditEntry(EntityDataProperties.DEVICE_DETAILS.value, ret),))


class DeviceEntity(MeshEntity):
    """Represents a user device in the mesh, i.e. not a node."""

    def _get_parental_control_device_attributes(
        self,
        schedule: dict[str, Any],
        urls: list[str],
    ) -> dict[str, Any]:
        """Determine what happens with device properties for parental control."""
        ret: dict[str, list[Any]] = {
            "remove": [],
            "modify": [],
        }
        if schedule == ParentalControl.ALL_ALLOWED_SCHEDULE() and not urls:
            ret["remove"].extend(
                [
                    DeviceProperty.ACTUAL_WAN_SCHEDULE.value,
                    DeviceProperty.BLOCK_ALL_MANUALLY.value,
                    DeviceProperty.SHOW_IN_PC_LIST.value,
                ]
            )

        if (
            schedule != ParentalControl.ALL_ALLOWED_SCHEDULE()
            or schedule == ParentalControl.ALL_ALLOWED_SCHEDULE()
            and urls
        ):
            ret["modify"].append({"name": DeviceProperty.SHOW_IN_PC_LIST.value, "value": "true"})
            if schedule == ParentalControl.ALL_PAUSED_SCHEDULE():
                ret["modify"].append({"name": DeviceProperty.BLOCK_ALL_MANUALLY.value, "value": "true"})
            else:
                ret["remove"].append(DeviceProperty.BLOCK_ALL_MANUALLY.value)

        return ret

    async def async_delete(self) -> None:
        """Delete the device from the mesh.

        The device must be offline to succeddfully be deleted.

        :return: None
        """

        await self._async_api_request(api.Actions.DELETE_DEVICE.action, {"deviceID": self.unique_id.value})

    async def async_rename(self, name: str) -> None:
        """Set the name of the device.

        :param name: The new name for the device.

        :return: None
        """

        payload: dict[str, Any] = {
            "deviceID": self.unique_id.value,
            "propertiesToModify": [
                {
                    "name": DeviceProperty.DEVICE_NAME.value,
                    "value": name,
                }
            ],
        }

        await self._async_api_request(api.Actions.SET_DEVICE_PROPERTY.action, payload)

    async def async_set_icon(self, icon: UiType | str) -> None:
        """Set the icon for the device.

        :param icon: the icon slug to set.

        :return: None
        """

        _icon: UiType
        if not isinstance(icon, UiType):
            if icon not in UiType:
                raise ValueError("Invalid icon specified")

            _icon = UiType(icon)
        else:
            _icon = icon

        payload: dict[str, Any] = {
            "deviceID": self.unique_id.value,
            "propertiesToModify": [
                {
                    "name": DeviceProperty.UI_TYPE.value,
                    "value": _icon.value.replace("_", "-"),
                }
            ],
        }

        await self._async_api_request(api.Actions.SET_DEVICE_PROPERTY.action, payload)

    async def async_set_parental_control_rules(self, rules: dict[str, Any], force_enable: bool = False) -> None:
        """Set the parental control schedule for the given device.

        :param rules: A dictionary of time string pairs in the form: `"monday": "00:00-02:00,17:30:18:00"`
        :param force_enable: True to enable Parental Control, False to leave in current state

        :return: None
        """
        _LOGGER.debug(
            self._log_formatter.format("entered, rules: %s"),
            rules,
        )

        current_schedule: dict[str, str] = {}
        keep_rules: list[dict[str, Any]] = []
        this_device_rules: list[dict[str, Any]] = []

        # region #-- get the device MAC --#
        device_mac: str | None = self.adapter_info.value[0].mac
        if device_mac is None:
            raise MeshException("No MAC available")
        # endregion

        # -- get the current rules as they may have changed --#
        live_pc_info = await self._async_api_request(api.Actions.GET_PARENTAL_CONTROL_INFO.action)

        # region #-- determine the rules --#
        if live_pc_info and isinstance(live_pc_info.data, dict):
            keep_rules = [
                rule
                for rule in live_pc_info.data.get("rules", [])
                if device_mac.upper() not in rule.get("macAddresses", [])
            ]
            this_device_rules = [
                rule
                for rule in live_pc_info.data.get("rules", [])
                if device_mac.upper() in rule.get("macAddresses", [])
            ]

        if this_device_rules:  # already has rules
            current_schedule = this_device_rules[0]["wanSchedule"]

        cached_schedule = self._get_user_property(DeviceProperty.ACTUAL_WAN_SCHEDULE)
        new_rule = ParentalControl.human_readable_to_binary(rules)
        if new_rule != ParentalControl.ALL_ALLOWED_SCHEDULE():
            _LOGGER.debug(self._log_formatter.format("adding new rules"))
            if this_device_rules:
                this_device_rules[0]["wanSchedule"] = new_rule
            else:
                if isinstance(new_rule, dict):
                    this_device_rules.append(
                        ParentalControl.create_rule(
                            mac_address=device_mac,
                            schedule=new_rule,
                            schedule_to_binary=False,
                        )
                    )
        else:
            if cached_schedule:
                _LOGGER.debug(self._log_formatter.format("restoring backed up schedule"))
                new_rule = ParentalControl.backup_to_binary(cached_schedule)
                this_device_rules[0]["wanSchedule"] = new_rule
            else:
                if len(this_device_rules) > 0 and this_device_rules[0].get("blockedURLs", []):
                    _LOGGER.debug(self._log_formatter.format("blocked URLs found, applying permissive rule"))
                    this_device_rules[0]["wanSchedule"] = new_rule
                else:
                    _LOGGER.debug(self._log_formatter.format("removing from rules"))
                    this_device_rules = []
        # endregion

        requests = [  # build a list of requests to send
            self._async_api_request(
                api.Actions.SET_PARENTAL_CONTROL_INFO.action,
                {
                    "isParentalControlEnabled": (
                        True
                        if force_enable
                        else (
                            live_pc_info.data.get("isParentalControlEnabled", True)
                            if live_pc_info and isinstance(live_pc_info.data, dict)
                            else True
                        )
                    ),
                    "rules": keep_rules + this_device_rules,
                },
            )
        ]

        # region #-- calculate the device properties to update --#
        device_properties = self._get_parental_control_device_attributes(
            schedule=new_rule if isinstance(new_rule, dict) else {},
            urls=(this_device_rules[0].get("blockedURLs", []) if this_device_rules else []),
        )

        if new_rule == ParentalControl.ALL_PAUSED_SCHEDULE():
            if current_schedule:
                device_properties["modify"].append(
                    {
                        "name": DeviceProperty.ACTUAL_WAN_SCHEDULE.value,
                        "value": ParentalControl.encode_for_backup(current_schedule),
                    }
                )
        else:
            if cached_schedule:
                device_properties["remove"].append(DeviceProperty.ACTUAL_WAN_SCHEDULE.value)

        if device_properties["modify"]:
            requests.append(
                self._async_api_request(
                    api.Actions.SET_DEVICE_PROPERTY.action,
                    {
                        "deviceID": self.unique_id.value,
                        "propertiesToModify": device_properties["modify"],
                    },
                )
            )

        if device_properties["remove"]:
            requests.append(
                self._async_api_request(
                    api.Actions.SET_DEVICE_PROPERTY.action,
                    {
                        "deviceID": self.unique_id.value,
                        "propertiesToRemove": device_properties["remove"],
                    },
                )
            )
        # endregion

        await asyncio.gather(*requests)

    async def async_set_parental_control_urls(
        self,
        urls: list[str],
        *,
        force_enable: bool = False,
        merge: bool = True,
    ) -> None:
        """Set the URLs for Parental Control.

        :param urls: List of the URLs to add
        :param force_enable: True to enable the rule if it isn't enabled
        :param merge: True to merge with existing URLs, False to replace

        :return: None
        """
        _LOGGER.debug(
            self._log_formatter.format("entered, urls: %s, merge: %s"),
            urls,
            merge,
        )

        keep_rules: list[dict[str, Any]] = []
        this_device_rules: list[dict[str, Any]] = []

        # region #-- get the MAC address details --#
        device_mac: str | None = self.adapter_info.value[0].mac
        if device_mac is None:
            raise MeshException("No MAC available")
        # endregion

        # -- get the current rules as they may have changed --#
        live_pc_info = await self._async_api_request(api.Actions.GET_PARENTAL_CONTROL_INFO.action)

        # region #-- determine the rules --#
        if live_pc_info and isinstance(live_pc_info.data, dict):
            keep_rules = [
                rule
                for rule in live_pc_info.data.get("rules", [])
                if device_mac.upper() not in rule.get("macAddresses", [])
            ]
            this_device_rules = [
                rule
                for rule in live_pc_info.data.get("rules", [])
                if device_mac.upper() in rule.get("macAddresses", [])
            ]

        if not this_device_rules:  # no existing rules so create all permissive
            this_device_rules.append(
                ParentalControl.create_rule(
                    blocked_urls=list(set(urls)),
                    mac_address=device_mac,
                    schedule=ParentalControl.ALL_ALLOWED_SCHEDULE(),
                    schedule_to_binary=False,
                )
            )
        else:
            if merge:
                this_device_rules[0]["blockedURLs"].extend(urls)
            else:
                this_device_rules[0]["blockedURLs"] = urls
            this_device_rules[0]["blockedURLs"] = list(set(this_device_rules[0]["blockedURLs"]))
        # endregion
        # endregion

        # region #-- build a list of requests to send --#
        device_properties: dict[str, list[str | dict[str, str]]] = self._get_parental_control_device_attributes(
            this_device_rules[0].get("wanSchedule", {}),
            urls,
        )

        requests: list[Awaitable[api.Response]] = [
            self._async_api_request(
                api.Actions.SET_PARENTAL_CONTROL_INFO.action,
                {
                    "isParentalControlEnabled": (
                        True
                        if force_enable
                        else (
                            live_pc_info.data.get("isParentalControlEnabled", True)
                            if isinstance(live_pc_info.data, dict)
                            else True
                        )
                    ),
                    "rules": keep_rules
                    + (
                        this_device_rules
                        if DeviceProperty.SHOW_IN_PC_LIST.value not in device_properties["remove"]
                        else []
                    ),
                },
            )
        ]

        if device_properties["modify"]:
            requests.append(
                self._async_api_request(
                    api.Actions.SET_DEVICE_PROPERTY.action,
                    {
                        "deviceID": self.unique_id.value,
                        "propertiesToModify": device_properties["modify"],
                    },
                )
            )
        if device_properties["remove"]:
            requests.append(
                self._async_api_request(
                    api.Actions.SET_DEVICE_PROPERTY.action,
                    {
                        "deviceID": self.unique_id.value,
                        "propertiesToRemove": device_properties["remove"],
                    },
                )
            )
        # endregion

        await asyncio.gather(*requests)

    @override
    def to_dict(self) -> dict[str, Any]:

        ret = super().to_dict()
        ret.update(
            {
                "operating_system": self.operating_system.to_dict(),
                "parental_control_schedule": self.parental_control_schedule.to_dict(),
            }
        )

        return ret

    @property
    def operating_system(self) -> MeshAttribute[str | None]:
        """Get the OS.

        :return: The OS as identified by the mesh
        """
        ret: str | None = self._get_user_property(DeviceProperty.OPERATING_SYSTEM) or self._data.get(
            EntityDataProperties.DEVICE_DETAILS, {}
        ).get("unit", {}).get("operatingSystem")

        return MeshAttribute[str | None](ret, (AttributeAuditEntry(EntityDataProperties.DEVICE_DETAILS.value, ret),))

    @property
    def parental_control_schedule(self) -> MeshAttribute[dict[str, Any]]:
        """Return the schedule of the parental controls for the device.

        An empty dictionary means that there are no parental controls in place

        :return: dictionary containing the parental controls for the device.
        """
        ret: dict[str, Any] = {}
        for rule in self._data.get(EntityDataProperties.PARENTAL_CONTROLS, []):
            pc_details: ParentalControl = ParentalControl(rule)
            ret = {
                "blocked_internet_access": pc_details.human_readable,
                "blocked_sites": pc_details.blocked_urls,
            }

        return MeshAttribute[dict[str, Any]](
            ret, (AttributeAuditEntry(EntityDataProperties.PARENTAL_CONTROLS.value, ret),)
        )


class NodeEntity(MeshEntity):
    """Represents a node on the mesh."""

    async def async_execute_action(self, action_key: ActionKey) -> api.Response:
        """Execute the given action against the node."""

        if action_key not in api.Actions:
            raise ValueError(f"Invalid action key passed in ({action_key})")
        if Actions[action_key].scope != ActionScope.NODE:
            raise ValueError(f"Not a valid node action ({action_key})")

        # region #-- establish the correct IP to use --#
        target_ip: str | None = next(
            (adapter.ip for adapter in self.adapter_info.value if adapter.ip and adapter.primary),
            None,
        )
        if not target_ip:
            raise MeshInvalidInput(f"{self.name}: no valid address found")
        # endregion

        return await self._async_api_request(Actions[action_key].action, Actions[action_key].payload, ip=target_ip)

    async def async_reboot(self, force: bool = False) -> None:
        """Reboot the node.

        Rebooting the primary node will cause all nodes to reboot. If you're sure you want to
        reboot the primary node, set the `force` parameter to `True`

        :param force: True to acknowledge the primary node, ignored for everything else

        :return: None
        """
        _LOGGER.debug(
            self._log_formatter.format("entered, force: %s"),
            force,
        )

        # region #-- check for primary node --#
        if self.type == NodeType.PRIMARY and not force:
            raise MeshInvalidInput(f"{self.name} is a primary node. Use the force.")
        # endregion

        # region #-- establish the correct IP to use --#
        target_ip: str | None = next(
            (adapter.ip for adapter in self.adapter_info.value if adapter.ip and adapter.primary),
            None,
        )
        if not target_ip:
            raise MeshInvalidInput(f"{self.name}: no valid address found")
        # endregion

        # region #-- do the reboot --#
        await self._async_api_request(api.Actions.REBOOT.action, ip=target_ip)
        # endregion

        _LOGGER.debug(self._log_formatter.format("exited"))

    @override
    def to_dict(self) -> dict[str, Any]:

        ret: dict[str, Any] = super().to_dict()
        ret.update(
            {
                "adapter_info": [adi.to_dict() for adi in self.adapter_info.value],
                "backhaul": self.backhaul.to_dict(),
                "connected_devices": [repr(dev) for dev in self.connected_devices],
                "firmware": self.firmware.to_dict(),
                "hardware_version": self.hardware_version.to_dict(),
                "last_update_check": self.last_update_check.to_dict(),
                "type": self.type.to_dict(),
            }
        )

        return ret

    @property
    def adapter_info(self) -> MeshAttribute[list[NodeAdapterInfo]]:
        """Retrieve details about the entity's adapters.

        :return: Adapter details including reservation, Wi-Fi, IP and Guest details.
            Additionally includes whether it is the primary adapter or not.
        """

        super_adapters: MeshAttribute[list[AdapterInfo]] = super().adapter_info

        audit_history: list[AttributeAuditEntry] = list(super_adapters.audit)
        ret: list[NodeAdapterInfo] = []
        backhaul: dict[str, Any] = self._data.get(EntityDataProperties.BACKHAUL, {})
        for adapter in super_adapters.value:
            props: dict[str, Any] = adapter.to_dict()
            props_primary: dict[str, bool] = {"primary": False}
            if adapter.ip == backhaul.get("ipAddress"):
                props_primary["primary"] = True
                audit_history.append(
                    AttributeAuditEntry(EntityDataProperties.BACKHAUL.value, props_primary, type=AttributeAction.MERGE)
                )
            elif self.type == NodeType.PRIMARY:
                props_primary["primary"] = True
                audit_history.append(
                    AttributeAuditEntry(
                        EntityDataProperties.DEVICE_DETAILS.value, props_primary, type=AttributeAction.MERGE
                    )
                )
            props.update(props_primary)
            props["type"] = ConnectionType(props["type"])
            ret.append(NodeAdapterInfo(**props))

        return MeshAttribute[list[NodeAdapterInfo]](ret, tuple(audit_history))

    @property
    def backhaul(self) -> MeshAttribute[BackhaulInfo | None]:
        """Get details about the backhaul."""
        ret: BackhaulInfo | None = None
        backhaul = self._data.get(EntityDataProperties.BACKHAUL, {})
        speed_mbps: float | None = None
        with contextlib.suppress(TypeError, ValueError):
            speed_mbps = float(backhaul.get("speedMbps"))

        if backhaul:
            signal_strength_raw: int | None = backhaul.get("wirelessConnectionInfo", {}).get("stationRSSI")
            ret = BackhaulInfo(
                **{
                    "connection": ConnectionType(backhaul.get("connectionType", "unknown")),
                    "last_checked": (
                        dt.datetime.fromisoformat(backhaul.get("timestamp"))
                        if backhaul.get("timestamp") is not None
                        else None
                    ),
                    "speed_mbps": speed_mbps,
                    "rssi_dbm": signal_strength_raw,
                    "signal_strength": self._signal_strength_to_text(signal_strength_raw),
                }
            )

        return MeshAttribute[BackhaulInfo | None](ret, (AttributeAuditEntry(EntityDataProperties.BACKHAUL.value, ret),))

    @property
    def connected_devices(self) -> tuple[DeviceEntity, ...]:
        """List of the devices that are connected to the node.

        :return: List of connected devices in alphabetical order sorted by device name
        """

        ret: list[DeviceEntity] = sorted(
            self._data.get(EntityDataProperties.CONNECTED_ENTITIES, []), key=lambda dev: dev.name.value
        )

        return tuple(ret)

    @property
    def firmware(self) -> MeshAttribute[dict[str, Any]]:
        """Get the firmware details for the node.

        N.B. The date doesn't seem to correlate to anything that I can see (I would have thought it was a build
        or install time but that doesn't seem to be the case)

        :return: A dictionary containing the firmware version and date
        """

        audit_history: list[AttributeAuditEntry] = []
        ret: dict[str, Any] = {}
        if (unit_details := self._data.get(EntityDataProperties.DEVICE_DETAILS, {}).get("unit")) is not None:
            props_device: dict[str, Any] = {
                "version": unit_details.get("firmwareVersion"),
                "date": unit_details.get("firmwareDate"),
            }
            audit_history.append(
                AttributeAuditEntry(
                    EntityDataProperties.DEVICE_DETAILS.value,
                    props_device,
                )
            )
            ret.update(props_device)
        available_updates = self._data.get(EntityDataProperties.FIRMWARE_DETAILS, {}).get("availableUpdate")
        if available_updates is not None:
            props_available: dict[str, Any] = {
                "latest_version": available_updates.get("firmwareVersion"),
                "latest_date": available_updates.get("firmwareDate"),
            }
            audit_history.append(
                AttributeAuditEntry(
                    EntityDataProperties.FIRMWARE_DETAILS.value, props_available, type=AttributeAction.MERGE
                )
            )
            ret.update(props_available)
        return MeshAttribute[dict[str, Any]](ret, tuple(audit_history))

    @property
    def hardware_version(self) -> MeshAttribute[str | None]:
        """Get the hardware version of the node.

        :return: A string containing the hardware version
        """

        ret: str | None = (
            self._data.get(EntityDataProperties.DEVICE_DETAILS, {}).get("model", {}).get("hardwareVersion")
        )

        return MeshAttribute[str | None](ret, (AttributeAuditEntry(EntityDataProperties.DEVICE_DETAILS.value, ret),))

    @property
    def last_update_check(self) -> MeshAttribute[str | None]:
        """Get the last time an update was checked for.

        :return: String containing the last update time as per the API
        """

        ret: str | None = self._data.get(EntityDataProperties.FIRMWARE_DETAILS, {}).get("lastSuccessfulCheckTime")

        return MeshAttribute[str | None](ret, (AttributeAuditEntry(EntityDataProperties.FIRMWARE_DETAILS.value, ret),))

    @property
    def type(self) -> MeshAttribute[NodeType]:
        """Get the node type.

        The node types are represented as primary or secondary.

        :return: A NodeType enumeration containing the node type.
        """
        ret = NodeType.UNKNOWN
        native_type = self._data.get(EntityDataProperties.DEVICE_DETAILS, {}).get("nodeType", "").lower()
        if native_type == "master":
            ret = NodeType.PRIMARY
        elif native_type == "slave":
            ret = NodeType.SECONDARY

        return MeshAttribute[NodeType](
            ret, (AttributeAuditEntry(EntityDataProperties.DEVICE_DETAILS.value, native_type),)
        )
