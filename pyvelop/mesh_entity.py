"""Representations of entities on the mesh."""

# region #-- imports --#
from __future__ import annotations

import asyncio
import base64
import contextlib
import datetime as dt
import logging
import math
import re
from abc import ABC, abstractmethod
from collections.abc import Awaitable, Callable, Iterable, Mapping
from dataclasses import dataclass
from enum import Enum, IntEnum, StrEnum, auto
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, cast, final, overload, override

from .action_registry import ActionKey, Actions
from .exceptions import MeshException, MeshInvalidInput, MeshTimeoutError
from .logger import Logger
from .mesh_attribute import AttributeAction, AttributeAuditEntry, MeshAttribute
from .timeouts import wait_until

if TYPE_CHECKING:
    from .jnap import JnapPayloadSingle, JnapResponseSingle
    from .mesh import MeshCapability

# endregion

_LOGGER: Logger = Logger(logging.getLogger(__name__))
_LOGGER_VERBOSE: Logger = Logger(logging.getLogger(f"{__name__}.verbose"))

EMPTY_NAME: str = "Network Device"


def is_timestamp_recent(date_string: str | None, value: int, unit: str = "minutes") -> bool:
    """Check if a given ISO 8601 timestamp is within a specified time window from the current time.

    :param date_string: The timestamp string to validate, expected in ISO 8601 format (e.g., '2026-10-29T13:39:53Z').
    :param value: The numerical value of the time window.
    :param unit: The unit of time to use for the window (e.g., 'seconds', 'minutes', 'hours', 'days').
                Must correspond to a valid timedelta keyword argument.
    :return: True if the timestamp is between the current time and the calculated threshold, False otherwise.
    """

    if not date_string:
        return False

    try:
        timestamp = dt.datetime.fromisoformat(date_string)
        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=dt.UTC)
        now = dt.datetime.now(dt.UTC)
        threshold = dt.timedelta(**{unit: value})
        return dt.timedelta(0) <= (now - timestamp) <= threshold
    except (ValueError, TypeError):
        return False


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
    ETHERNET_PORT_CONNECTIONS = Actions.GET_ETHERNET_PORT_CONNECTIONS.key
    FIRMWARE_DETAILS = Actions.GET_UPDATE_FIRMWARE_STATE.key
    NODE_NETWORK_CONNECTIONS = Actions.GET_NETWORK_CONNECTIONS.key
    PARENT_ENTITY = "parent_entity"
    PARENTAL_CONTROLS = Actions.GET_PARENTAL_CONTROL_INFO.key
    RESERVATION_DETAILS = Actions.GET_LAN_SETTINGS.key
    RESULTS_TIME = "results_time"
    SYSTEM_STATS = Actions.GET_SYSTEM_STATS.key
    WIRELESS_CONNECTION_DETAILS = Actions.GET_NODE_WIRELESS_CONNECTIONS.key


class EthernetPortType(StrEnum):
    """Enumeration for port ethernet types."""

    LAN = auto()
    WAN = auto()


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


class MeshSerialiser:
    """Provides functionality to serialize complex objects and custom classes into formats compatible with JSON serialisation."""

    _EXPORT_PROPERTIES: tuple[str, ...] = ()

    def _serialise(self, value: Any, *, include_audit: bool = False) -> Any:
        """Recursively transforms objects into types that can be serialized by `json.dump` or `json.dumps`.

        :param value: The object or value to be serialized.
        :param include_audit: Whether to include audit-related metadata during serialisation of objects that support it.
        :return: A JSON-serialisable representation of the input value.
        """

        if isinstance(value, Enum):
            return self._serialise(value.value, include_audit=include_audit)

        if value is None or isinstance(value, (bool, int, float, str)):
            return value

        if hasattr(value, "to_dict"):
            return value.to_dict(include_audit=include_audit)

        if isinstance(value, Mapping):
            return {k: self._serialise(v) for k, v in value.items()}

        if isinstance(value, Iterable):
            return [self._serialise(i) for i in value]

        if isinstance(value, dt.datetime):
            return value.isoformat()

        return value.__repr__

    def to_dict(self, *, include_audit: bool = False) -> dict[str, Any]:
        """Serialises the current instance into a dictionary based on the defined export properties.

        :param include_audit: Whether to include audit-related metadata in the serialised properties.
        :return: A dictionary containing the serialised values of all properties listed in `_EXPORT_PROPERTIES`.
        """

        result = {}
        for prop in self._EXPORT_PROPERTIES:
            try:
                val = getattr(self, prop)
                result[prop] = self._serialise(val, include_audit=include_audit)
            except AttributeError:
                continue
        return result


@dataclass(frozen=True, slots=True)
class AdapterInfo(MeshSerialiser):
    """Representation of adapter information."""

    _EXPORT_PROPERTIES = tuple(
        {
            "band",
            "connected",
            "guest_network",
            "ip",
            "ipv6",
            "mac",
            "negotiated_mbps",
            "parent_id",
            "reservation",
            "reservation_description",
            "rssi_dbm",
            "rssi_dbm_timestamp",
            "signal_strength",
            "type",
        }
    )

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
    rssi_dbm_timestamp: dt.datetime | None = None
    signal_strength: SignalStrength | None = None
    type: ConnectionType = ConnectionType.UNKNOWN


@dataclass(frozen=True, slots=True)
class EthernetPortConnection(MeshSerialiser):
    """Representation of an ethernet port."""

    _EXPORT_PROPERTIES = tuple(
        {
            "index",
            "kind",
            "negotiated_speed_mbps",
            "speed",
        }
    )

    index: int
    speed: str
    kind: EthernetPortType

    @property
    def negotiated_speed_mbps(self) -> float | None:
        """Parse a speed string (e.g., '1Gbps', '100Mbps') and calculate the speed in Mbps.

        This parser is permissive so any additional text after the intended speed is thrown
        away, e.g. "1Gbps extra". The extra is thrown away and the conversion completed
        accordingly.

        :param speed_str: The speed string to parse.
        :returns: The equivalent speed in Mbps as an integer.
        :raises ValueError: If the string format is not recognised.
        """

        if self.speed.strip().lower() == "none":
            return None

        # match digits (including decimals) and the unit
        match = re.match(r"([\d.]+)\s*([a-zA-Z]+)", self.speed.strip())
        if not match:
            return None

        value = float(match.group(1))
        unit = match.group(2).lower()

        if unit == "gbps":
            return float(value * 1000)
        elif unit == "mbps":
            return float(value)
        elif unit == "kbps":
            return float(value / 1000)
        else:
            raise ValueError(f"Unsupported unit: {unit}. Please use Gbps, Mbps, or Kbps.")


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
class BackhaulInfo(MeshSerialiser):
    """Representation of backhaul information."""

    _EXPORT_PROPERTIES = tuple(
        {
            "connection",
            "last_checked",
            "speed_mbps",
            "rssi_dbm",
            "signal_strength",
        }
    )

    connection: ConnectionType | None
    last_checked: dt.datetime | None
    speed_mbps: float | None
    rssi_dbm: int | None
    signal_strength: SignalStrength | None


class ParentalControl:
    """Class to manage parental control schedules."""

    SLOTS_PER_HOUR: int = 2
    HOURS_PER_DAY: int = 24
    BINARY_LENGTH: int = HOURS_PER_DAY * SLOTS_PER_HOUR
    DEFAULT_DESCRIPTION: str = "default description"
    KNOWN_RULE_KEYS: MappingProxyType[str, type] = MappingProxyType(
        {
            "blockedURLs": list,
            "description": str,
            "isEnabled": bool,
            "macAddresses": list,
            "wanSchedule": dict,
        }
    )

    @staticmethod
    def all_allowed_schedule() -> dict[str, str]:
        """Return a schedule that allows internet access all day."""
        return {
            day.name.lower(): ParentalControlActionType.UNBLOCKED.value * ParentalControl.BINARY_LENGTH
            for day in Weekdays
        }

    @staticmethod
    def all_paused_schedule() -> dict[str, str]:
        """Return a schedule that blocks internet access all day."""
        return {
            day.name.lower(): ParentalControlActionType.BLOCKED.value * ParentalControl.BINARY_LENGTH
            for day in Weekdays
        }

    def __init__(self, rule: dict[str, Any]) -> None:
        """Initialise.

        :param rule: a single rule object as returned by the API
        """
        self._rule: dict[str, Any] = rule
        self._validate_rule()

    def _validate_rule(self) -> bool:
        """Ensure the rule has the correct shape as expected by the known returns from the API.

        Checks allow for additional keys to be provided.

        :retun: `True` if a valid rule.
        :raises TypeError: If the rule is not of the correct type.
        :raises ValueError: If the rule does not match the expected shape.
        """

        if not isinstance(self._rule, dict):
            raise TypeError("Rule must be a dictionary")

        # check that all expected fields are present
        missing = set(self.KNOWN_RULE_KEYS) - self._rule.keys()
        if missing:
            raise ValueError(f"Missing rule keys: {', '.join(sorted(missing))}")

        # check the field types are valid
        invalid_fields: list[str] = [
            name
            for name, expected_type in self.KNOWN_RULE_KEYS.items()
            if not isinstance(self._rule[name], expected_type)
        ]
        if invalid_fields:
            raise TypeError(f"Invalid types for: {", ".join(invalid_fields)}")

        for field in ("blockedURLs", "macAddresses"):
            if not all(isinstance(value, str) for value in self._rule[field]):
                raise ValueError(f"Invalid values for: {field}")

        # check for valid wanSchedule
        days_week = {day.name.lower() for day in Weekdays}
        if set(days_week) != set(self._rule["wanSchedule"]):
            raise ValueError("Rule scheduled days are not valid")

        for day, binary_schedule in cast(dict[str, str], self._rule["wanSchedule"]).items():
            if (
                not isinstance(binary_schedule, str)
                or len(binary_schedule) != self.BINARY_LENGTH
                or any(char not in "01" for char in binary_schedule)
            ):
                raise ValueError(f"Invalid schedule for {day}")

        return True

    @staticmethod
    def _human_readable(schedule: dict[str, str]) -> dict[str, list[str]]:
        """Make the given schedule human readable.

        :param schedule: A dictionary detailing the day and the binary strings.
        :return: A dictionary detailing the day and the human-readable times.
        """
        ret: dict[str, list[str]] = {}
        for day, sched in schedule.items():
            if not all(char in "01" for char in sched):
                raise ValueError(f"Invalid binary string: {sched}")

            ret[day.lower()] = []
            idx: int = 0
            while idx < ParentalControl.BINARY_LENGTH:
                block_start: int | None = (
                    sched.index(ParentalControlActionType.BLOCKED.value, idx)
                    if sched is not None and ParentalControlActionType.BLOCKED.value in sched[idx:]
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
    def _time_block_offsets(start: dt.datetime, end: dt.datetime) -> tuple[int, int]:
        """Return the half-hour offsets covered by a time block."""
        if ParentalControl._is_full_day_block(start, end):
            return 0, ParentalControl.BINARY_LENGTH
        if ParentalControl._is_wrapping_block(start, end):
            raise ValueError(f"Time block cannot wrap across midnight: {start:%H:%M}-{end:%H:%M}")

        offset_start = start.hour * 2 + (1 if start.minute >= 30 else 0)
        offset_end = (end.hour if end.hour != 0 or start.hour == 0 else 24) * 2 + (1 if end.minute >= 30 else 0)
        return offset_start, offset_end

    @staticmethod
    def _is_full_day_block(start: dt.datetime, end: dt.datetime) -> bool:
        """Return whether a block covers the full day explicitly."""
        midnight = dt.time(0, 0)
        return start == end and start.time() == midnight

    @staticmethod
    def _is_wrapping_block(start: dt.datetime, end: dt.datetime) -> bool:
        """Return whether a block wraps past midnight without ending at midnight."""
        return end < start and end.time() != dt.time(0, 0)

    @staticmethod
    def backup_to_binary(schedule: str) -> dict[str, str]:
        """Decode the schedule for restoring to the device."""
        ret: dict[str, str] = {}
        decoded = base64.b64decode(schedule) if schedule else b""
        sorted_schedule: str = ""
        for chunk in decoded:
            sorted_schedule += f"{int(chunk):08b}"

        for daily_schedule in range(len(list(Weekdays))):
            start = daily_schedule * ParentalControl.BINARY_LENGTH
            ret[Weekdays(daily_schedule).name.lower()] = sorted_schedule[start : start + ParentalControl.BINARY_LENGTH]

        return ret

    @staticmethod
    def encode_for_backup(schedule: dict[str, str]) -> str:
        """Encode the schedule for storage in a property.

        :param schedule:
        return: The encoded value that can be stored in the mesh as a backup.
        """
        ret: str = ""
        chunk_length: int = 8
        sorted_schedule: str = "".join(
            [
                schedule.get(day.name.lower(), ParentalControl.all_allowed_schedule()[day.name.lower()])
                for day in Weekdays
            ]
        )
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

    @overload
    @staticmethod
    def human_readable_to_binary(to_encode: str) -> str: ...

    @overload
    @staticmethod
    def human_readable_to_binary(to_encode: dict[str, str]) -> dict[str, str]: ...

    @staticmethod
    def human_readable_to_binary(
        to_encode: str | dict[str, str],
    ) -> str | dict[str, str]:
        """Encode the human readable information to something that can be stored.

        :param: Comma separated timespans, e.g. 00:00-01:00.
        If `to_decode` is a dictionary it should be in the form: - `{<weekeday_in_english_lowercase>: <comma_separated_timespans>, ...}`
        :return: Binary string or dictionary of binary string rperesentations of the human-readable times.
        """
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
            binary_schedule = [ParentalControlActionType.UNBLOCKED.value] * ParentalControl.BINARY_LENGTH
            if schedule is not None:
                time_schedules: list[str] = schedule.split(",")
                for schedule in time_schedules:
                    times: list[str] = schedule.split("-")
                    start = dt.datetime.strptime(times[0].strip(), "%H:%M").replace(tzinfo=dt.UTC)
                    end = dt.datetime.strptime(times[1].strip(), "%H:%M").replace(tzinfo=dt.UTC)
                    offset_start, offset_end = ParentalControl._time_block_offsets(
                        start,
                        end,
                    )

                    for idx in range(offset_start, offset_end):
                        binary_schedule[idx] = ParentalControlActionType.BLOCKED.value

                    if all(  # break out early if all blocked
                        value == ParentalControlActionType.BLOCKED.value for value in binary_schedule
                    ):
                        break

            ret_dict[day] = "".join(binary_schedule)

        if isinstance(to_encode, str):
            return ret_dict[fake_day]

        return ret_dict

    @overload
    @staticmethod
    def binary_to_human_readable(to_decode: str) -> str: ...

    @overload
    @staticmethod
    def binary_to_human_readable(to_decode: dict[str, str]) -> dict[str, list[str]]: ...

    @staticmethod
    def binary_to_human_readable(
        to_decode: str | Mapping[str, str],
    ) -> str | dict[str, list[str]]:
        """Decode the binary format string to human-readable form.

        :param to_decode: The binary string or dictionary containing the binary strings to convert
        If `to_decode` is a dictionary it should be in the form: - `{<weekeday_in_english_lowercase>: <binary_string>, ...}`
        :return: The human readable represenation of the given binary times.
        """
        ret: str | dict[str, list[str]]
        if isinstance(to_decode, str):
            fake_day: str = "sunday"
            single_day_schedule = ParentalControl._human_readable({fake_day: to_decode})
            ret = ",".join(single_day_schedule[fake_day])
        else:
            ret = ParentalControl._human_readable(dict(to_decode))

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
        return self.schedule == ParentalControl.all_paused_schedule()

    @property
    def mac_addresses(self) -> list[str]:
        """Return the MAC addresses the rule is for."""
        return cast(list[str], self._rule.get("macAddresses", []))

    @final
    @property
    def rule(self) -> dict[str, Any]:
        """Return the rule including any additional keys that were specified at initialisation."""

        additional_keys = set(self._rule.keys()).difference(self.KNOWN_RULE_KEYS.keys())
        additionals = {ak: self._rule[ak] for ak in additional_keys}

        return {
            "blockedURLs": self.blocked_urls,
            "description": self.description,
            "isEnabled": self.is_enabled,
            "macAddresses": self.mac_addresses,
            "wanSchedule": self.schedule,
            **additionals,
        }

    @property
    def schedule(self) -> dict[str, str]:
        """Return the current internet access schedule used in the rule."""
        return cast(dict[str, str], self._rule.get("wanSchedule", {}))


class MeshEntity(ABC):
    """Represents a base level entity on the mesh."""

    def __init__(
        self,
        data: dict[str, Any],
        capabilities: Mapping[ActionKey, MeshCapability] | None = None,
        supplementary_redactions: dict[str, set[str]] | None = None,
    ) -> None:
        """Initialise."""

        self._data: dict[str, Any] = data
        self._supplementary_redactions: dict[str, set[str]] | None = supplementary_redactions
        self._capabilities: Mapping[ActionKey, MeshCapability] = capabilities or MappingProxyType({})

    def __repr__(self) -> str:
        """Make a pretty string representation of the class.

        :return: Takes the class name and the name of the device to build the representation
        """
        ret = f"{self.__class__.__name__}: "
        if self.name:
            ret += str(self.name)
        return ret

    def _derive_adi_connected_state(
        self,
        adapter_index: int,
        connection_type: ConnectionType,
        device_connections: dict[str, Any],
        node_network_connection_info: dict[str, Any] | None,
        node_wireless_connection_info: dict[str, Any],
    ) -> tuple[dict[str, Any], tuple[AttributeAuditEntry, ...]]:
        """Derive whether an adapter is currently connected.

        The device details provide the initial connection state. Wireless connection
        details can mark an otherwise disconnected adapter as connected, while the
        absence of those details can mark a wireless adapter as disconnected. A
        matching network connection can then restore the connected state.

        :param adapter_index: Zero-based index of the adapter being processed.
        :param connection_type: The adapter's derived connection type.
        :param device_connections: Connection details reported by ``GET_DEVICES``.
        :param node_network_connection_info: Matching network connection details, if available.
        :param node_wireless_connection_info: Matching wireless connection details, if available.
        :return: A tuple containing the derived properties and their audit entries.
        """

        adi_key = "connected"
        audit_history: list[AttributeAuditEntry] = []
        ret = None

        def log_audit(source: ActionKey, conn_state: bool, action: AttributeAction):
            audit_history.append(AttributeAuditEntry(source, {adi_key: conn_state}, index=adapter_index, kind=action))

        # GET_DEVICES value
        get_devices_state: bool = bool(device_connections)
        if get_devices_state != ret:
            log_audit(
                "GET_DEVICES", get_devices_state, AttributeAction.INIT if ret is None else AttributeAction.REPLACE
            )
            ret = get_devices_state

        # GET_NODE_WIRELESS_CONNECTIONS value
        wifi_is_recent: bool = False
        wifi_info_rate_limit: float | None = Actions.REFRESH_NODE_WIRELESS_CONNECTIONS.rate_limit_secs
        if wifi_info_rate_limit is not None:
            wifi_info_threshold: int = math.ceil(wifi_info_rate_limit) * 2
            wifi_is_recent = is_timestamp_recent(
                node_wireless_connection_info.get("timestamp"),
                wifi_info_threshold,
                "seconds",
            )
        if wifi_is_recent:
            wifi_state: bool = bool(node_wireless_connection_info)
            if connection_type == ConnectionType.WIRELESS and wifi_state != ret:
                log_audit(
                    "GET_NODE_WIRELESS_CONNECTIONS",
                    wifi_state,
                    AttributeAction.INIT if ret is None else AttributeAction.REPLACE,
                )
                ret = wifi_state

        # GET_NETWORK_CONNECTIONS value
        if node_network_connection_info:
            nnc_state = (
                bool(node_network_connection_info.get("wireless", {}).get("signalDecibels"))
                if connection_type == ConnectionType.WIRELESS
                else bool(node_network_connection_info)
            )
            if nnc_state != ret:
                log_audit(
                    "GET_NETWORK_CONNECTIONS",
                    nnc_state,
                    AttributeAction.INIT if ret is None else AttributeAction.REPLACE,
                )
                ret = nnc_state

        return ({adi_key: ret}, tuple(audit_history))

    def _derive_adi_connection_type(
        self,
        adapter_index: int,
        adapter_info: dict[str, Any],
        device_info: dict[str, Any],
        node_network_connection_info: list[dict[str, Any]],
        node_wireless_connection_info: dict[str, Any],
    ) -> tuple[dict[str, Any], tuple[AttributeAuditEntry, ...]]:
        """Derive the adapter connection type.

        The interface type reported by `GET_DEVICES` is used initially. Wireless
        connection details take precedence, followed by network connection details.

        :param adapter_index: Zero-based index of the adapter being processed.
        :param adapter_info: Adapter details reported by ``GET_DEVICES``.
        :param device_info: Matching device connection details.
        :param node_network_connection_info: Matching network connection details.
        :param node_wireless_connection_info: Matching wireless connection details.
        :return: The derived connection type and its audit entries.
        :raises ValueError: If an adapter connection type is invalid.
        """

        adi_key = "type"
        audit_history: list[AttributeAuditEntry] = []

        def log_audit(source: ActionKey, conn_type: ConnectionType, action: AttributeAction):
            audit_history.append(AttributeAuditEntry(source, {adi_key: conn_type}, index=adapter_index, kind=action))

        # initial value
        connection_type = ConnectionType(adapter_info.get("interfaceType", "Unknown"))
        log_audit("GET_DEVICES", connection_type, AttributeAction.INIT)

        # override from wireless info
        if connection_type in (ConnectionType.WIRED, ConnectionType.UNKNOWN) and node_wireless_connection_info:
            connection_type = ConnectionType.WIRELESS
            log_audit("GET_NODE_WIRELESS_CONNECTIONS", connection_type, AttributeAction.REPLACE)

        # override from network connection info
        if node_network_connection_info:
            has_signal = any(nnc.get("wireless", {}).get("signalDecibels") for nnc in node_network_connection_info)

            if connection_type != ConnectionType.WIRELESS and has_signal:
                connection_type = ConnectionType.WIRELESS
                log_audit("GET_NETWORK_CONNECTIONS", connection_type, AttributeAction.REPLACE)
            elif connection_type == ConnectionType.UNKNOWN:
                connection_type = ConnectionType.WIRED
                log_audit("GET_NETWORK_CONNECTIONS", connection_type, AttributeAction.REPLACE)

        return ({adi_key: connection_type}, tuple(audit_history))

    def _derive_adi_guest_network(
        self, adapter_index: int, device_info: dict[str, Any] | None
    ) -> tuple[dict[str, Any], tuple[AttributeAuditEntry, ...]]:
        """Derive whether the adapter uses the guest network.

        :param adapter_index: Zero-based index of the adapter being processed.
        :param device_info: Matching device connection details, if available.
        :return: The guest-network state and its audit entries.
        """

        audit_history: list[AttributeAuditEntry] = []
        guest_network: bool | None = device_info.get("isGuest") if device_info else None
        guest_ret = {"guest_network": guest_network}
        audit_history.append(AttributeAuditEntry("GET_DEVICES", guest_ret, index=adapter_index))
        return (guest_ret, tuple(audit_history))

    def _derive_adi_ip_details(
        self, adapter_index: int, device_info: dict[str, Any]
    ) -> tuple[dict[str, Any], tuple[AttributeAuditEntry, ...]]:
        """Derive the IP details for an adapter.

        :param adapter_index: Zero-based index of the adapter being processed.
        :param device_info: Matching device connection details.
        :return: The IPv4 and IPv6 details and their audit entries.
        """

        audit_history: list[AttributeAuditEntry] = []
        ip_details = {"ip": device_info.get("ipAddress"), "ipv6": device_info.get("ipv6Address")}
        audit_history.append(AttributeAuditEntry("GET_DEVICES", ip_details, index=adapter_index))
        return (ip_details, tuple(audit_history))

    def _derive_adi_mac(
        self, adapter_index: int, adapter_info: dict[str, Any]
    ) -> tuple[dict[str, Any], tuple[AttributeAuditEntry, ...]]:
        """Derive the MAC address for an adapter.

        :param adapter_index: Zero-based index of the adapter being processed.
        :param adapter_info: Adapter details reported by ``GET_DEVICES``.
        :return: The MAC address and its audit entries.
        """

        audit_history: list[AttributeAuditEntry] = []
        mac: dict[str, Any] = {"mac": adapter_info.get("macAddress")}
        audit_history.append(AttributeAuditEntry("GET_DEVICES", mac, index=adapter_index))
        return (mac, tuple(audit_history))

    def _derive_adi_parent_id(
        self, adapter_index: int, connected: bool, parent_info: MeshAttribute[NodeEntity | None] | None
    ) -> tuple[dict[str, Any], tuple[AttributeAuditEntry, ...]]:
        """Record the parent-entity state for an adapter.

        :param adapter_index: Zero-based index of the adapter being processed.
        :param connected: Current connected state of the adapter.
        :param parent_info: Parent entity information, if available.
        :return: An empty property mapping and the associated audit entries.
        """

        audit_history: list[AttributeAuditEntry] = []
        parent_id: str | None = (
            None
            if not parent_info or not parent_info.value or not parent_info.value.unique_id.value
            else parent_info.value.unique_id.value
        )
        audit_history.append(
            AttributeAuditEntry("GET_DEVICES", {"parent_id": parent_id}, index=adapter_index, kind=AttributeAction.INIT)
        )

        return ({}, tuple(audit_history))

    def _derive_adi_reservation(
        self, adapter_index: int, reservation_info: list[dict[str, Any]]
    ) -> tuple[dict[str, Any], tuple[AttributeAuditEntry, ...]]:
        """Derive the DHCP reservation details for an adapter.

        :param adapter_index: Zero-based index of the adapter being processed.
        :param reservation_info: DHCP reservations matching the adapter.
        :return: The reservation state and description, together with audit entries.
        :raises ValueError: If more than one matching reservation is provided.
        """

        if len(reservation_info) > 1:
            raise ValueError("Unexpected DHCP reservation data")

        audit_history: list[AttributeAuditEntry] = []
        reservation = {
            "reservation": bool(reservation_info),
            "reservation_description": next(iter(reservation_info), {}).get("description"),
        }
        audit_history.append(
            AttributeAuditEntry("GET_LAN_SETTINGS", reservation, index=adapter_index, kind=AttributeAction.INIT)
        )

        return (reservation, tuple(audit_history))

    def _derive_adi_wireless_information(
        self,
        adapter_index: int,
        adapter_info: dict[str, Any],
        node_network_connection_info: dict[str, Any] | None,
        node_wireless_connection_info: dict[str, Any],
    ) -> tuple[dict[str, Any], tuple[AttributeAuditEntry, ...]]:
        """Derive wireless information for an adapter.

        The adapter band reported by `GET_DEVICES` is used initially. Matching
        wireless connection details then replace the band and provide negotiated
        speed, RSSI, timestamp, and signal strength. Network connection details may
        provide additional speed or signal information when wireless details are
        incomplete.

        :param adapter_index: Zero-based index of the adapter being processed.
        :param adapter_info: Adapter details reported by `GET_DEVICES`.
        :param node_network_connection_info: Matching network connection details, if available.
        :param node_wireless_connection_info: Matching wireless connection details, if available.
        :return: The derived wireless properties and their audit entries.
        """

        audit_history: list[AttributeAuditEntry] = []
        ret: dict[str, Any] = {}

        # initial value
        props_device: dict[str, Any] = {"band": adapter_info.get("band")}
        audit_history.append(
            AttributeAuditEntry("GET_DEVICES", props_device, index=adapter_index, kind=AttributeAction.INIT)
        )
        ret.update(props_device)

        # override from node wireless connection info
        props_wifi: dict[str, Any] = {}
        if node_wireless_connection_info:
            wifi_info: dict[str, Any] = node_wireless_connection_info.get("wireless", {})
            rssi_dbm: int | None = self._rssi_dbm(wifi_info.get("signalDecibels"))
            props_wifi = {
                "band": wifi_info.get("band"),
                "negotiated_mbps": node_wireless_connection_info.get("negotiatedMbps"),
                "rssi_dbm": rssi_dbm,
                "rssi_dbm_timestamp": node_wireless_connection_info.get("timestamp"),
                "signal_strength": self._signal_strength_to_text(rssi_dbm),
            }
            audit_history.append(
                AttributeAuditEntry(
                    "GET_NODE_WIRELESS_CONNECTIONS", props_wifi, index=adapter_index, kind=AttributeAction.REPLACE
                )
            )
            ret.update(props_wifi)

        # override relevant info from node network connection info
        if node_network_connection_info:
            props_nnc: dict[str, Any] = {"negotiated_mbps": node_network_connection_info.get("negotiatedMbps")}
            if (
                rssi_dbm := self._rssi_dbm(node_network_connection_info.get("wireless", {}).get("signalDecibels"))
            ) is not None and not props_wifi.get("rssi_dbm"):
                props_nnc.update(
                    {
                        "rssi_dbm": rssi_dbm,
                        "rssi_dbm_timestamp": None,
                        "signal_strength": self._signal_strength_to_text(rssi_dbm),
                    }
                )
            audit_history.append(
                AttributeAuditEntry(
                    "GET_NETWORK_CONNECTIONS", props_nnc, index=adapter_index, kind=AttributeAction.MERGE
                )
            )
            ret.update(props_nnc)

        return (ret, tuple(audit_history))

    def _get_capability(self, capability: ActionKey) -> MeshCapability:
        """Retrieve the capability from the identified available capabilities.

        Raises ValueError if the capability isn't found.

        :param capability: the capabality to retrieve.
        :return: the MeshCapability object.
        """

        ret: MeshCapability | None = None
        if (cap := self._capabilities.get(capability)) and cap.is_valid is not False:
            ret = cap

        if ret is None:
            raise ValueError(f"Unknown capability ({capability})")

        return ret

    def _get_user_property(self, property_name: DeviceProperty) -> str | None:
        """Get the given property from the user properties."""
        ret: str | None = None

        user_properties: list[dict[str, Any]] = self._data.get(EntityDataProperties.DEVICE_DETAILS, {}).get(
            "properties", []
        )
        user_prop: dict[str, Any] | None = next(
            (prop for prop in user_properties if prop.get("name") == property_name.value), None
        )
        if user_prop is not None:
            ret = user_prop.get("value")

        return ret

    def _process_single_adapter(
        self, index: int, adapter_info: dict[str, Any]
    ) -> tuple[dict[str, Any], tuple[AttributeAuditEntry, ...]]:
        """Process the supplied details for a single adapter.

        Combines adapter, device connection, network connection, wireless connection,
        and reservation data into the properties exposed by `AdapterInfo`. Audit
        entries are collected for each derived or overridden property.

        :param index: Zero-based index of the adapter being processed.
        :param adapter_info: Adapter details reported by `GET_DEVICES`.
        :return: The derived adapter properties and their audit entries.
        :raises ValueError: If multiple matching wireless connections or DHCP
            reservations are found, or if an unsupported connection type is provided.
        """

        get_device_details: dict[str, Any] = self._data.get(EntityDataProperties.DEVICE_DETAILS, {})
        props: dict[str, Any] = {}
        audit_history: list[AttributeAuditEntry] = []

        # derive MAC information
        mac_value, mac_audit = self._derive_adi_mac(index, adapter_info)
        self._update_and_log_audit(props, audit_history, mac_value, audit_entries=mac_audit)

        # prep all the info we need to use for making decisions
        mac_lower: str = props.get("mac", "").lower()
        connections = get_device_details.get("connections", [])
        get_devices_connections = next((c for c in connections if c.get("macAddress", "").lower() == mac_lower), {})
        node_network_conns_info: list[dict[str, Any]] = self._data.get(
            EntityDataProperties.NODE_NETWORK_CONNECTIONS, []
        )
        reservation_info: list[dict[str, Any]] = [
            ri
            for ri in self._data.get(EntityDataProperties.RESERVATION_DETAILS, [])
            if ri.get("macAddress", "").lower() == mac_lower
        ]
        wifi_conn_info_matches: list[dict[str, Any]] = [
            wi
            for wi in self._data.get(EntityDataProperties.WIRELESS_CONNECTION_DETAILS, [])
            if wi.get("macAddress", "").lower() == mac_lower
        ]
        if len(wifi_conn_info_matches) > 1:
            raise ValueError("Unexpected wi-fi data")
        wifi_conn_info = next(iter(wifi_conn_info_matches), {})

        # derive connection type
        type_value, type_audit = self._derive_adi_connection_type(
            index,
            adapter_info,
            get_devices_connections,
            node_network_conns_info,
            wifi_conn_info,
        )
        self._update_and_log_audit(props, audit_history, type_value, audit_entries=type_audit)

        # establish network connection information to use
        conn_type = props.get("type")
        nnc: dict[str, Any] | None = None
        for n in node_network_conns_info:
            has_signal = bool(n.get("wireless", {}).get("signalDecibels"))
            if (conn_type == ConnectionType.WIRED and not has_signal) or (
                conn_type == ConnectionType.WIRELESS and has_signal
            ):
                nnc = n
                break

        # subsequent derivations
        derivations: list[tuple[Callable[..., tuple[Any, tuple[AttributeAuditEntry, ...]]], tuple[Any, ...]]] = [
            (self._derive_adi_wireless_information, (index, adapter_info, nnc, wifi_conn_info)),
            (self._derive_adi_ip_details, (index, get_devices_connections)),
            (self._derive_adi_guest_network, (index, get_device_details)),
            (self._derive_adi_reservation, (index, reservation_info)),
            (
                self._derive_adi_connected_state,
                (index, props.get("type", ConnectionType.UNKNOWN), get_devices_connections, nnc, wifi_conn_info),
            ),
            (
                self._derive_adi_parent_id,
                (index, props.get("connected", False), self._data.get(EntityDataProperties.PARENT_ENTITY)),
            ),
        ]
        for func, args in derivations:
            val, audit = func(*args)
            self._update_and_log_audit(props, audit_history, val, audit_entries=audit)

        return (props, tuple(audit_history))

    def _rssi_dbm(self, value: Any) -> int | None:
        """Return the value if it is a plausible RSSI in dBm, otherwise None.

        A received signal is always negative in dBm; some JNAP responses report non-dBm values in the same field.

        :param value: Value as reported by the JNAP API.
        :return: Valid RSSI value or `None` if invalid.
        """
        if isinstance(value, int) and not isinstance(value, bool) and value < 0:
            return value

        return None

    def _signal_strength_to_text(self, rssi: int | None) -> SignalStrength | None:
        """Convert the given RSSI value to a textual representation.

        :param rssi: RSSI value to convert to a textual representation.
        :return: `SignalStrength` enum value representing the textual representation or `None`.
        """

        if rssi is None:
            return None

        if rssi <= -70:
            return SignalStrength.WEAK
        if rssi <= -60:
            return SignalStrength.FAIR
        if rssi <= -50:
            return SignalStrength.GOOD

        return SignalStrength.EXCELLENT

    def _update_connected_devices(self, new_device: MeshEntity) -> None:
        """Update the connected devices."""

        cur_devices: list[MeshEntity] = self._data.get(EntityDataProperties.CONNECTED_ENTITIES, [])
        cur_devices.append(new_device)
        self._data.update({EntityDataProperties.CONNECTED_ENTITIES: cur_devices})

    @overload
    def _update_and_log_audit(
        self,
        props: dict[str, Any],
        audit_history: list[AttributeAuditEntry],
        data: dict[str, Any],
        *,
        source: ActionKey,
        index: int | None = None,
        kind: AttributeAction = AttributeAction.MERGE,
    ) -> None: ...

    @overload
    def _update_and_log_audit(
        self,
        props: dict[str, Any],
        audit_history: list[AttributeAuditEntry],
        data: dict[str, Any],
        *,
        audit_entries: tuple[AttributeAuditEntry, ...] | AttributeAuditEntry,
    ) -> None: ...

    def _update_and_log_audit(
        self,
        props: dict[str, Any],
        audit_history: list[AttributeAuditEntry],
        data: dict[str, Any],
        *,
        source: ActionKey | None = None,
        index: int | None = None,
        kind: AttributeAction = AttributeAction.MERGE,
        audit_entries: tuple[AttributeAuditEntry, ...] | AttributeAuditEntry | None = None,
    ) -> None:
        """Updates the provided properties dictionary and logs the change to the audit history.

        If audit_entries is provided, it is used to populate the history; otherwise, a new
        entry is created using the specified index and kind. This ensures that the
        mutation of the properties is synchronised with the audit trail.

        :param props: The properties dictionary to be mutated.
        :param audit_history: The tuple of audit entries where the change should be recorded.
        :param data: The data to apply to the properties and include in the audit.
        :param source: The key identifying the source of the action.
        :param index: The index associated with the attribute change (ignored if audit_entries is provided).
        :param kind: The type of attribute action being performed (ignored if audit_entries is provided).
        :param audit_entries: Optional custom audit entry or entries to log instead of generating one.
        :return: None
        """

        if audit_entries is not None:
            if isinstance(audit_entries, tuple):
                audit_history.extend(audit_entries)
            else:
                audit_history.append(audit_entries)
        else:
            if source is None:
                raise TypeError("_update_and_log_audit() missing 1 required keyword-only argument: 'source'")

            audit_history.append(AttributeAuditEntry(source, data, index=index, kind=kind))

        props.update(data)

    def _update_parent(self, new_parent: MeshAttribute[NodeEntity | None]) -> None:
        """Set the parent entity for this entity."""

        self._data.update({EntityDataProperties.PARENT_ENTITY: new_parent})

    @abstractmethod
    def to_dict(self, *, include_audit: bool = False) -> dict[str, Any]:
        """Return the instance as a dictionary."""

        _adi: Any = None
        if include_audit:
            _adi = {"audit": [ae.to_dict() for ae in self.adapter_info.audit]}
            _adi.update({"value": [adi.to_dict() for adi in self.adapter_info.value]})
        else:
            _adi = [adi.to_dict() for adi in self.adapter_info.value]

        _parent: Any = None
        if include_audit:
            _parent = {"audit": [ae.to_dict() for ae in self.parent_name.audit]}
            _parent.update({"value": repr(self.parent.value)})
        else:
            _parent = repr(self.parent.value)

        ret: dict[str, Any] = {
            "adapter_info": _adi,
            "description": self.description.to_dict(include_audit=include_audit),
            "manufacturer": self.manufacturer.to_dict(include_audit=include_audit),
            "model": self.model.to_dict(include_audit=include_audit),
            "name": self.name.to_dict(include_audit=include_audit),
            "parent": _parent,
            "parent_ip": self.parent_ip.to_dict(include_audit=include_audit),
            "parent_ipv6": self.parent_ipv6.to_dict(include_audit=include_audit),
            "parent_name": self.parent_name.to_dict(include_audit=include_audit),
            "results_time": self.results_time,
            "serial": self.serial.to_dict(include_audit=include_audit),
            "status": self.status.to_dict(include_audit=include_audit),
            "ui_type": self.ui_type.to_dict(include_audit=include_audit),
            "unique_id": self.unique_id.to_dict(include_audit=include_audit),
        }

        return ret

    @property
    def adapter_info(self) -> MeshAttribute[tuple[AdapterInfo, ...]]:
        """Get details about the network adapters.

        :return: Adapter information that has been derived from various sources on the mesh.
        """

        audit_history: list[AttributeAuditEntry] = []
        ret: list[AdapterInfo] = []

        get_device_details: dict[str, Any] = self._data.get(EntityDataProperties.DEVICE_DETAILS, {})
        my_adapters: list[dict[str, Any]] = get_device_details.get("knownInterfaces", [])

        for idx, adapter in enumerate(my_adapters):
            adapter_props, adapter_audit = self._process_single_adapter(idx, adapter)
            ret.append(AdapterInfo(**adapter_props))
            audit_history.extend(adapter_audit)

        return MeshAttribute[tuple[AdapterInfo, ...]](tuple(ret), tuple(audit_history))

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
                AttributeAuditEntry(EntityDataProperties.DEVICE_DETAILS.value, name_user, kind=AttributeAction.REPLACE)
            )

        ret = name_user or name_discovered or EMPTY_NAME

        if ret == EMPTY_NAME:
            audit.append(
                AttributeAuditEntry(EntityDataProperties.DEVICE_DETAILS.value, EMPTY_NAME, kind=AttributeAction.REPLACE)
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

        results_time_raw: int | None = self._data.get(EntityDataProperties.RESULTS_TIME)
        if results_time_raw is None:
            return None

        return math.ceil(results_time_raw)

    @property
    def serial(self) -> MeshAttribute[str | None]:
        """Get the serial number of the node.

        :return: A string containing the serial number
        """

        ret: str | None = self._data.get(EntityDataProperties.DEVICE_DETAILS, {}).get("unit", {}).get("serialNumber")

        return MeshAttribute[str | None](ret, (AttributeAuditEntry(EntityDataProperties.DEVICE_DETAILS.value, ret),))

    @property
    @abstractmethod
    def status(self) -> MeshAttribute[bool | None]:
        """Get whether the device is currently connected to the mesh or not.

        :return: True if connected. False if not.
        """

        raise NotImplementedError

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
        if schedule == ParentalControl.all_allowed_schedule() and not urls:
            ret["remove"].extend(
                [
                    DeviceProperty.ACTUAL_WAN_SCHEDULE.value,
                    DeviceProperty.BLOCK_ALL_MANUALLY.value,
                    DeviceProperty.SHOW_IN_PC_LIST.value,
                ]
            )

        if (
            schedule != ParentalControl.all_allowed_schedule()
            or schedule == ParentalControl.all_allowed_schedule()
            and urls
        ):
            ret["modify"].append({"name": DeviceProperty.SHOW_IN_PC_LIST.value, "value": "true"})
            if schedule == ParentalControl.all_paused_schedule():
                ret["modify"].append({"name": DeviceProperty.BLOCK_ALL_MANUALLY.value, "value": "true"})
            else:
                ret["remove"].append(DeviceProperty.BLOCK_ALL_MANUALLY.value)

        return ret

    async def async_delete(self) -> None:
        """Delete the device from the mesh.

        The device must be offline to succeddfully be deleted.
        """

        payload: JnapPayloadSingle = {
            "deviceID": self.unique_id.value,
        }
        cap: MeshCapability = self._get_capability("DELETE_DEVICE")
        await cap.async_execute(payload=payload)

    async def async_rename(self, name: str) -> None:
        """Set the name of the device.

        :param name: The new name for the device.
        """

        payload: JnapPayloadSingle = {
            "deviceID": self.unique_id.value,
            "propertiesToModify": [
                {
                    "name": DeviceProperty.DEVICE_NAME.value,
                    "value": name,
                }
            ],
        }
        cap: MeshCapability = self._get_capability("SET_DEVICE_PROPERTY")
        await cap.async_execute(payload=payload)

    async def async_reset_icon(self) -> None:
        """Reset the icon for the device."""

        payload: JnapPayloadSingle = {
            "deviceID": self.unique_id.value,
            "propertiesToRemove": [DeviceProperty.UI_TYPE.value],
        }

        cap: MeshCapability = self._get_capability("SET_DEVICE_PROPERTY")
        await cap.async_execute(payload=payload)

    async def async_reset_name(self) -> None:
        """Reset the name for the device."""

        payload: JnapPayloadSingle = {
            "deviceID": self.unique_id.value,
            "propertiesToRemove": [DeviceProperty.DEVICE_NAME.value],
        }

        cap: MeshCapability = self._get_capability("SET_DEVICE_PROPERTY")
        await cap.async_execute(payload=payload)

    async def async_set_icon(self, icon: UiType | str) -> None:
        """Set the icon for the device.

        :param icon: the icon slug to set.
        """

        _icon: UiType
        if not isinstance(icon, UiType):
            if icon not in UiType:
                raise ValueError("Invalid icon specified")

            _icon = UiType(icon)
        else:
            _icon = icon

        payload: JnapPayloadSingle = {
            "deviceID": self.unique_id.value,
            "propertiesToModify": [
                {
                    "name": DeviceProperty.UI_TYPE.value,
                    "value": _icon.value.replace("_", "-"),
                }
            ],
        }

        cap: MeshCapability = self._get_capability("SET_DEVICE_PROPERTY")
        await cap.async_execute(payload=payload)

    async def async_set_parental_control_rules(self, rules: dict[str, Any], force_enable: bool = False) -> None:
        """Set the parental control schedule for the given device.

        :param rules: A dictionary of time string pairs in the form: `"monday": "00:00-02:00,17:30:18:00"`
        :param force_enable: True to enable Parental Control, False to leave in current state
        """
        _LOGGER_VERBOSE.debug("entered, rules: %s", rules)

        current_schedule: dict[str, str] = {}
        keep_rules: list[dict[str, Any]] = []
        this_device_rules: list[dict[str, Any]] = []

        # get the device MAC
        device_mac: str | None = self.adapter_info.value[0].mac
        if device_mac is None:
            raise MeshException("No MAC available")
        device_mac = device_mac.upper()
        # endregion

        # get the current rules as they may have changed
        cap: MeshCapability = self._get_capability("GET_PARENTAL_CONTROL_INFO")
        live_pc_info: JnapResponseSingle = await cap.async_execute()

        # determine the rules
        if live_pc_info:
            keep_rules = [
                rule for rule in live_pc_info.get("rules", []) if device_mac not in rule.get("macAddresses", [])
            ]
            this_device_rules = [
                rule for rule in live_pc_info.get("rules", []) if device_mac in rule.get("macAddresses", [])
            ]

        if this_device_rules:  # already has rules
            current_schedule = this_device_rules[0]["wanSchedule"]

        cached_schedule: str | None = self._get_user_property(DeviceProperty.ACTUAL_WAN_SCHEDULE)
        new_rule = ParentalControl.human_readable_to_binary(rules)
        if new_rule != ParentalControl.all_allowed_schedule():
            _LOGGER_VERBOSE.debug("adding new rules")
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
                _LOGGER_VERBOSE.debug("restoring backed up schedule")
                new_rule = ParentalControl.backup_to_binary(cached_schedule)
                this_device_rules[0]["wanSchedule"] = new_rule
            else:
                if len(this_device_rules) > 0 and this_device_rules[0].get("blockedURLs", []):
                    _LOGGER_VERBOSE.debug("blocked URLs found, applying permissive rule")
                    this_device_rules[0]["wanSchedule"] = new_rule
                else:
                    _LOGGER_VERBOSE.debug("removing from rules")
                    this_device_rules = []

        cap = self._get_capability("SET_PARENTAL_CONTROL_INFO")
        requests: list[Awaitable[JnapResponseSingle]] = []
        requests.append(
            cap.async_execute(
                payload={
                    "isParentalControlEnabled": (
                        True
                        if force_enable
                        else (live_pc_info.get("isParentalControlEnabled", True) if live_pc_info else True)
                    ),
                    "rules": keep_rules + this_device_rules,
                }
            )
        )

        # calculate the device properties to update
        cap = self._get_capability("SET_DEVICE_PROPERTY")
        device_properties = self._get_parental_control_device_attributes(
            schedule=new_rule if isinstance(new_rule, dict) else {},
            urls=(this_device_rules[0].get("blockedURLs", []) if this_device_rules else []),
        )

        if new_rule == ParentalControl.all_paused_schedule():
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
                cap.async_execute(
                    payload={
                        "deviceID": self.unique_id.value,
                        "propertiesToModify": device_properties["modify"],
                    }
                )
            )

        if device_properties["remove"]:
            requests.append(
                cap.async_execute(
                    payload={
                        "deviceID": self.unique_id.value,
                        "propertiesToRemove": device_properties["remove"],
                    }
                )
            )

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
        """
        _LOGGER_VERBOSE.debug(
            "entered, urls: %s, merge: %s",
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
        cap: MeshCapability = self._get_capability("GET_PARENTAL_CONTROL_INFO")
        live_pc_info: JnapResponseSingle = await cap.async_execute()

        # region #-- determine the rules --#
        if live_pc_info:
            keep_rules = [
                rule for rule in live_pc_info.get("rules", []) if device_mac.upper() not in rule.get("macAddresses", [])
            ]
            this_device_rules = [
                rule for rule in live_pc_info.get("rules", []) if device_mac.upper() in rule.get("macAddresses", [])
            ]

        if not this_device_rules:  # no existing rules so create all permissive
            this_device_rules.append(
                ParentalControl.create_rule(
                    blocked_urls=list(set(urls)),
                    mac_address=device_mac,
                    schedule=ParentalControl.all_allowed_schedule(),
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

        cap = self._get_capability("SET_PARENTAL_CONTROL_INFO")
        requests: list[Awaitable[JnapResponseSingle]] = [
            cap.async_execute(
                payload={
                    "isParentalControlEnabled": (
                        True
                        if force_enable
                        else (live_pc_info.get("isParentalControlEnabled", True) if live_pc_info else True)
                    ),
                    "rules": keep_rules
                    + (
                        this_device_rules
                        if DeviceProperty.SHOW_IN_PC_LIST.value not in device_properties["remove"]
                        else []
                    ),
                }
            )
        ]

        cap = self._get_capability("SET_DEVICE_PROPERTY")
        if device_properties["modify"]:
            requests.append(
                cap.async_execute(
                    payload={
                        "deviceID": self.unique_id.value,
                        "propertiesToModify": device_properties["modify"],
                    }
                )
            )
        if device_properties["remove"]:
            requests.append(
                cap.async_execute(
                    payload={
                        "deviceID": self.unique_id.value,
                        "propertiesToRemove": device_properties["remove"],
                    }
                )
            )
        # endregion

        await asyncio.gather(*requests)

    @override
    def to_dict(self, *, include_audit: bool = False) -> dict[str, Any]:

        ret = super().to_dict(include_audit=include_audit)
        ret.update(
            {
                "operating_system": self.operating_system.to_dict(include_audit=include_audit),
                "parental_control_schedule": self.parental_control_schedule.to_dict(include_audit=include_audit),
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

    @property
    @override
    def status(self) -> MeshAttribute[bool | None]:

        audit_history: list[AttributeAuditEntry] = []
        ret: bool | None = None

        _adapter_info: MeshAttribute[tuple[AdapterInfo, ...]] = self.adapter_info
        adi: AdapterInfo | None = next(iter(_adapter_info), None)  # assume a single adapter
        if adi is not None:
            ret = adi.connected
            audit_history = [ae for ae in _adapter_info.audit if "connected" in ae.value]
            # modify the audit log to show the first entry as he initial one.
            # do this otherwise it could show as merge which makes no sense in this context.
            if audit_history:
                audit_history.insert(
                    0,
                    AttributeAuditEntry(
                        audit_history[0].source,
                        audit_history[0].value,
                        kind=AttributeAction.INIT,
                        index=audit_history[0].index,
                    ),
                )
                audit_history.pop(1)

        return MeshAttribute[bool | None](ret, tuple(audit_history))


class NodeEntity(MeshEntity):
    """Represents a node on the mesh."""

    async def _is_node_reachable(self) -> bool:
        """Determine if the node is reachable."""
        try:
            await self.async_execute_action("GET_SYSTEM_STATS", timeout=2)
            return True
        except Exception:  # noqa: BLE001
            return False

    async def async_execute_action(self, action_key: ActionKey, *, timeout: float | None = None) -> JnapResponseSingle:
        """Execute the given action against the node."""

        if action_key not in Actions:
            raise ValueError(f"Invalid action key passed in ({action_key})")
        if action_key not in self._capabilities:
            raise ValueError(f"Not a valid node action ({action_key})")

        # region #-- establish the correct IP to use --#
        target_ip: str | None = next(
            (adapter.ip for adapter in self.adapter_info.value if adapter.ip and adapter.primary),
            None,
        )
        if not target_ip:
            raise MeshInvalidInput(f"{self.name}: no valid address found")
        # endregion

        cap: MeshCapability = self._get_capability(action_key)
        return await cap.async_execute(node_address=target_ip)

    async def async_reboot(
        self,
        *,
        force: bool = False,
        timeout: float = 300.0,
        wait: bool = False,
        wait_for: Callable[[], Awaitable[bool]] | None = None,
    ) -> bool:
        """Reboot the node.

        If `wait` is True, the caller may provide a readiness probe via `wait_for`, which will be
        polled until it returns True or the timeout expires.

        Rebooting the primary node will cause all nodes to reboot. If you're sure you want to
        reboot the primary node, set the `force` parameter to `True`

        :param force: `True` to acknowledge the primary node, ignored for everything else
        :param timeout: Maximum time in seconds to wait for the readiness probe.
        :param wait: `True` to wait for the reboot to complete before returning
        :param wait_for: Probe function that returns `True` when the node is reachable again.
        Defaults to an internal check of reachability.
        """
        _LOGGER_VERBOSE.debug("entered, force: %s", force)

        ret: bool = False

        # region #-- check for primary node --#
        if self.type == NodeType.PRIMARY and not force:
            raise MeshInvalidInput(f"{self.name} is a primary node, use the force.")
        # endregion

        # region #-- do the reboot --#
        prev_uptime: int = self.uptime.value or -1
        await self.async_execute_action("REBOOT")
        # endregion

        # region #-- wait if it was requested --#
        if wait:
            # make sure the reboot has started
            _LOGGER_VERBOSE.debug(f"waiting for {self.name} to reboot")
            _LOGGER_VERBOSE.debug(f"backing off for reboot process to start on {self.name}")
            await asyncio.sleep(20)
            probe = wait_for or self._is_node_reachable
            interval: float = 10.0
            # wait (or timeout waiting) for the node to be reachable again
            await wait_until(
                condition=probe,
                timeout=timeout,
                interval=interval,
                exc_cls=MeshTimeoutError,
            )
            _LOGGER_VERBOSE.debug(f"{self.name} is reachable, checking if it rebooted")
            resp: JnapResponseSingle = await self.async_execute_action("GET_SYSTEM_STATS")
            cur_uptime: int = resp.get("uptimeSeconds", -1)
            if cur_uptime > prev_uptime:
                _LOGGER_VERBOSE.debug(
                    f"it doesn't look like {self.name} actually rebooted, uptime is too high, {cur_uptime}"
                )
            else:
                _LOGGER_VERBOSE.debug(f"{self.name} has rebooted, uptime {cur_uptime}")
                ret = True
        # endregion

        _LOGGER_VERBOSE.debug("exited")
        return ret

    @override
    def to_dict(self, *, include_audit: bool = False) -> dict[str, Any]:

        ret: dict[str, Any] = super().to_dict(include_audit=include_audit)

        ret.update(
            {
                "backhaul": self.backhaul.to_dict(include_audit=include_audit),
                "connected_devices": [repr(dev) for dev in self.connected_devices],
                "firmware": self.firmware.to_dict(include_audit=include_audit),
                "hardware_version": self.hardware_version.to_dict(include_audit=include_audit),
                "last_reboot": self.last_reboot.to_dict(include_audit=include_audit),
                "last_update_check": self.last_update_check.to_dict(include_audit=include_audit),
                "uptime": self.uptime.to_dict(include_audit=include_audit),
                "type": self.type.to_dict(include_audit=include_audit),
            }
        )

        return ret

    @property
    def adapter_info(self) -> MeshAttribute[tuple[NodeAdapterInfo, ...]]:
        """Retrieve details about the entity's adapters.

        :return: Adapter details including reservation, Wi-Fi, IP and Guest details.
            Additionally includes whether it is the primary adapter or not.
        """

        super_adapters: MeshAttribute[tuple[AdapterInfo, ...]] = super().adapter_info

        audit_history: list[AttributeAuditEntry] = list(super_adapters.audit)
        ret: list[NodeAdapterInfo] = []
        backhaul: dict[str, Any] = self._data.get(EntityDataProperties.BACKHAUL, {})
        for idx, adapter in enumerate(super_adapters.value):
            props: dict[str, Any] = adapter.to_dict()
            props_primary: dict[str, bool] = {"primary": False}
            if adapter.ip == backhaul.get("ipAddress"):
                props_primary["primary"] = True
                self._update_and_log_audit(
                    props,
                    audit_history,
                    props_primary,
                    source=EntityDataProperties.BACKHAUL.value,
                    index=idx,
                    kind=AttributeAction.INIT,
                )
            elif self.type == NodeType.PRIMARY:
                props_primary["primary"] = True
                self._update_and_log_audit(
                    props,
                    audit_history,
                    props_primary,
                    source=EntityDataProperties.DEVICE_DETAILS.value,
                    index=idx,
                    kind=AttributeAction.INIT,
                )
            props["type"] = ConnectionType(props["type"])
            ret.append(NodeAdapterInfo(**props))

        return MeshAttribute[tuple[NodeAdapterInfo, ...]](tuple(ret), tuple(audit_history))

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
                connection=ConnectionType(backhaul.get("connectionType", "unknown")),
                last_checked=(
                    dt.datetime.fromisoformat(backhaul.get("timestamp"))
                    if backhaul.get("timestamp") is not None
                    else None
                ),
                speed_mbps=speed_mbps,
                rssi_dbm=signal_strength_raw,
                signal_strength=self._signal_strength_to_text(signal_strength_raw),
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
    def ethernet_port_info(self) -> MeshAttribute[tuple[EthernetPortConnection, ...]]:
        """Retrieve the connection status and negotiated speeds for all Ethernet ports.

        :returns: A MeshAttribute containing a tuple of `EthernetPortConnection` objects
                  for both WAN and LAN ports.
        """
        cap: ActionKey = "GET_ETHERNET_PORT_CONNECTIONS"
        ret: list[EthernetPortConnection] = []
        audit_history: list[AttributeAuditEntry] = []

        eth_connections: dict[str, Any] = self._data.get(EntityDataProperties.ETHERNET_PORT_CONNECTIONS, {})

        # map data keys to their respective port types
        port_mapping = {
            "wanPortConnection": EthernetPortType.WAN,
            "lanPortConnections": EthernetPortType.LAN,
        }

        for key, port_type in port_mapping.items():
            ports = eth_connections.get(key, [])
            ports_list = ports if isinstance(ports, list) else [ports]

            for idx, speed in enumerate(ports_list):
                connection = EthernetPortConnection(
                    index=idx,
                    speed=speed,
                    kind=port_type,
                )
                ret.append(connection)
                audit_history.append(AttributeAuditEntry(cap, connection, index=len(ret) - 1))

        return MeshAttribute(tuple(ret), tuple(audit_history))

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
            self._update_and_log_audit(
                ret,
                audit_history,
                props_device,
                source=EntityDataProperties.DEVICE_DETAILS.value,
                kind=AttributeAction.INIT,
            )

        props_available: dict[str, Any] = {}
        props_available_src: ActionKey
        available_updates = self._data.get(EntityDataProperties.FIRMWARE_DETAILS, {}).get("availableUpdate")
        if available_updates is not None:
            props_available = {
                "latest_version": available_updates.get("firmwareVersion"),
                "latest_date": available_updates.get("firmwareDate"),
            }
            props_available_src = EntityDataProperties.FIRMWARE_DETAILS.value
        else:
            props_available = {
                "latest_version": props_device.get("version"),
                "latest_date": props_device.get("date"),
            }
            props_available_src = EntityDataProperties.DEVICE_DETAILS.value
            audit_history.append(
                AttributeAuditEntry(
                    EntityDataProperties.DEVICE_DETAILS.value, props_available, kind=AttributeAction.MERGE
                )
            )
        self._update_and_log_audit(
            ret,
            audit_history,
            props_available,
            source=props_available_src,
            kind=AttributeAction.INIT,
        )

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
    def last_reboot(self) -> MeshAttribute[dt.datetime | None]:
        """Return the number of seconds the node has been running."""

        ret: dt.datetime | None = None

        uptime: MeshAttribute[int | None] = self.uptime
        if uptime.value is not None and self.results_time is not None:
            ret = dt.datetime.fromtimestamp(self.results_time - uptime.value, tz=dt.UTC)

        return MeshAttribute[dt.datetime | None](ret, uptime.audit)

    @property
    def last_update_check(self) -> MeshAttribute[dt.datetime | None]:
        """Get the last time an update was checked for.

        :return: String containing the last update time as per the API
        """

        ret: dt.datetime | None = None
        _attr: str | None = self._data.get(EntityDataProperties.FIRMWARE_DETAILS, {}).get("lastSuccessfulCheckTime")
        if _attr is not None:
            ret = dt.datetime.fromisoformat(_attr)

        return MeshAttribute[dt.datetime | None](
            ret, (AttributeAuditEntry(EntityDataProperties.FIRMWARE_DETAILS.value, _attr),)
        )

    @property
    @override
    def status(self) -> MeshAttribute[bool | None]:

        audit_history: list[AttributeAuditEntry] = []
        ret: bool | None = None

        _adapter_info: MeshAttribute[tuple[NodeAdapterInfo, ...]] = self.adapter_info
        adi: tuple[int, NodeAdapterInfo] | None = next(((i, a) for i, a in enumerate(_adapter_info) if a.primary), None)
        if adi is not None:
            ret = adi[1].connected
            audit_history = [ae for ae in _adapter_info.audit if "connected" in ae.value and ae.index == adi[0]]
            # modify the audit log to show the first entry as he initial one.
            # do this otherwise it could show as merge which makes no sense in this context.
            if audit_history:
                audit_history.insert(
                    0, AttributeAuditEntry(audit_history[0].source, audit_history[0].value, kind=AttributeAction.INIT)
                )
                audit_history.pop(1)

        return MeshAttribute[bool | None](ret, tuple(audit_history))

    @property
    def uptime(self) -> MeshAttribute[int | None]:
        """Return the number of seconds the node has been running."""

        ret: int | None = self._data.get(EntityDataProperties.SYSTEM_STATS, {}).get("uptimeSeconds")

        return MeshAttribute[int | None](ret, (AttributeAuditEntry(EntityDataProperties.SYSTEM_STATS.value, ret),))

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
