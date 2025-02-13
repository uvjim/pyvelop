"""Representations of entities on the mesh."""

# region #-- imports --#
import asyncio
import base64
import contextlib
import datetime
import logging
from collections import namedtuple
from typing import Any, final

from . import jnap as api
from .const import (
    DEF_EMPTY_NAME,
    DeviceProperty,
    ParentalControlActionType,
    UiType,
    Weekdays,
)
from .exceptions import MeshException, MeshInvalidInput
from .logger import Logger
from .types import MeshDetails, NodeType, SignalStrength

# endregion

_LOGGER: logging.Logger = logging.getLogger(__name__)


class ParentalControl:
    """Class to manage parental control schedules."""

    BINARY_LENGTH: int = 48
    DEFAULT_DESCRIPTION: str = "default description"

    ALL_ALLOWED_SCHEDULE: dict[str, str] = lambda: {
        day.name.lower(): ParentalControlActionType.UNBLOCKED.value
        * ParentalControl.BINARY_LENGTH
        for day in Weekdays
    }

    ALL_PAUSED_SCHEDULE: dict[str, str] = lambda: {
        day.name.lower(): ParentalControlActionType.BLOCKED.value
        * ParentalControl.BINARY_LENGTH
        for day in Weekdays
    }

    def __init__(self, rule: dict[str, Any]) -> None:
        """Initialise.

        :param rule: a single rule object as returned by the API
        """
        self._rule: dict[str, Any] = rule

    @staticmethod
    def _human_readable(schedule: dict[str, str]) -> dict[str, list[str]]:
        """Make the given schedule human readable."""
        ret = {}
        for day, sched in schedule.items():
            ret[day] = []
            idx = 0
            while idx < __class__.BINARY_LENGTH:
                block_start: int | None = (
                    sched.index(ParentalControlActionType.BLOCKED.value, idx)
                    if ParentalControlActionType.BLOCKED.value in sched[idx + 1 :]
                    else None
                )
                block_end: int | None = None
                if block_start is None:
                    break
                block_end = (
                    sched.index(
                        ParentalControlActionType.UNBLOCKED.value, block_start + 1
                    )
                    if ParentalControlActionType.UNBLOCKED.value
                    in sched[block_start + 1 :]
                    else None
                )
                start_time = datetime.time(
                    hour=int(block_start / 2),
                    minute=(30 if block_start % 2 == 1 else 0),
                )
                end_time = (
                    datetime.time(
                        hour=int(block_end / 2),
                        minute=(30 if block_end % 2 == 1 else 0),
                    )
                    if block_end
                    else datetime.time(hour=0, minute=0)
                )
                ret[day].append(
                    f"{start_time.strftime('%H:%M')}-{end_time.strftime('%H:%M')}"
                )
                if block_end is not None:
                    idx = block_end + 1
                else:
                    idx = __class__.BINARY_LENGTH

        return ret

    # region #-- public methods --#
    @staticmethod
    def backup_to_binary(schedule: str) -> dict[str, str]:
        """Decode the schedule for restoring to the device."""
        ret: dict[str, str] = {}
        decoded = schedule and base64.b64decode(schedule)
        sorted_schedule: str = ""
        for chunk in decoded:
            sorted_schedule += f"{int(chunk):08b}"

        for daily_schedule in range(0, len(list(Weekdays))):
            start = daily_schedule * __class__.BINARY_LENGTH
            ret[Weekdays(daily_schedule).name] = sorted_schedule[
                start : start + __class__.BINARY_LENGTH
            ]

        return ret

    @staticmethod
    def encode_for_backup(schedule: dict[str, str]) -> str:
        """Encode the schedule for storage in a property."""
        ret: str = ""
        chunk_length: int = 8
        sorted_schedule: str = "".join([schedule[day.name] for day in list(Weekdays)])
        sorted_chunks: list[str] = [
            (sorted_schedule[i : i + chunk_length])
            for i in range(0, len(sorted_schedule), chunk_length)
        ]

        chunk_chars: bytearray = bytearray()
        for chunk in sorted_chunks:
            chunk_chars.append(int(chunk, base=2))

        ret = chunk_chars and base64.b64encode(chunk_chars).decode()
        return ret

    @staticmethod
    def create_rule(
        mac_address: str,
        schedule: dict[str, str],
        blocked_urls: list[str] | None = None,
        schedule_to_binary: bool = True,
    ) -> dict[str, Any]:
        """Generate a rule dictionary that can be passed to the API."""
        ret: dict[str, Any] = {
            "blockedURLs": blocked_urls if blocked_urls is not None else [],
            "description": __class__.DEFAULT_DESCRIPTION,
            "isEnabled": True,
            "macAddresses": [mac_address],
            "wanSchedule": (
                schedule
                if not schedule_to_binary
                else __class__.human_readable_to_binary(schedule)
            ),
        }
        return ret

    @staticmethod
    def human_readable_to_binary(
        to_encode: str | dict[str, str]
    ) -> str | dict[str, str]:
        """Encode the human readable information to somethings that can be stored."""
        fake_day = "sunday"
        if isinstance(to_encode, str):
            to_process = {fake_day: to_encode}
        else:
            to_process = to_encode
            if len(to_process) > len(Weekdays):
                raise ValueError("Too many arguments")
            if len(to_process) < len(Weekdays):
                for idx in range(len(to_process), len(Weekdays)):
                    to_process[Weekdays(idx).name.lower()] = None

        ret: str | dict[str, str] = {}
        for day, schedule in to_process.items():
            default_binary = [
                ParentalControlActionType.UNBLOCKED.value
            ] * __class__.BINARY_LENGTH
            if schedule is not None:
                time_schedules: list[str] = schedule.split(",")
                TimeBlock = namedtuple("TimeBlock", ["start", "end"])
                for schedule in time_schedules:
                    times: list[str] = schedule.split("-")
                    time_block: TimeBlock = TimeBlock(
                        datetime.datetime.strptime(times[0].strip(), "%H:%M"),
                        datetime.datetime.strptime(times[1].strip(), "%H:%M"),
                    )
                    if (  # midnight to midnight
                        time_block.start == time_block.end
                        and time_block.start.hour == 0
                        and time_block.start.minute == 0
                    ):
                        offset_start = 0
                        offset_end = __class__.BINARY_LENGTH
                    elif (  # time wrapping
                        time_block.end < time_block.start
                        and str(time_block.end.time()) != "00:00:00"
                    ):
                        offset_start = 0
                        offset_end = __class__.BINARY_LENGTH
                    else:  # normal time
                        offset_start = time_block.start.hour * 2 + (
                            1 if time_block.start.minute >= 30 else 0
                        )
                        offset_end = (  # extend to end if midnight is the end time
                            time_block.end.hour
                            if time_block.end.hour != 0
                            or (time_block.end.hour == 0 and time_block.start.hour == 0)
                            else 24
                        ) * 2 + (1 if time_block.end.minute >= 30 else 0)

                    for idx in range(offset_start, offset_end):
                        default_binary[idx] = ParentalControlActionType.BLOCKED.value

                    if all(  # break out early if all blocked
                        val == ParentalControlActionType.BLOCKED.value
                        for val in default_binary
                    ):
                        break

            ret[day] = "".join(default_binary)

        if isinstance(to_encode, str):
            ret = ret[fake_day]

        return ret

    @staticmethod
    def binary_to_human_readable(
        to_decode: str | dict[str, str]
    ) -> str | dict[str, list[str]]:
        """Decode the binary format string to humand readble form."""
        if isinstance(to_decode, str):
            fake_day = "sunday"
            fake_obj = {fake_day: to_decode}
            fake_ret = ParentalControl._human_readable(schedule=fake_obj)
            ret = fake_ret[fake_day]
        else:
            ret = ParentalControl._human_readable(schedule=to_decode)

        return ret

    # endregion

    # region #-- properties --#
    @property
    def blocked_urls(self) -> list[str]:
        """Return blocked URLs."""
        return self._rule.get("blockedURLs", [])

    @property
    def description(self) -> str:
        """Return the rule description."""
        return self._rule.get("description", __class__.DEFAULT_DESCRIPTION)

    @property
    def human_readable(self) -> dict[str, list[str]]:
        """Return the schedule in human readable form."""
        return self._human_readable(schedule=self.schedule)

    @property
    def is_enabled(self) -> bool:
        """Return whether the rule is enabled or not."""
        return self._rule.get("isEnabled", True)

    @property
    def is_paused(self) -> bool:
        """Return whether the rule is all blocking."""
        return self.schedule == __class__.ALL_PAUSED_SCHEDULE()

    @property
    def mac_addresses(self) -> list[str]:
        """Return the MAC addresses the rule is for."""
        return self._rule.get("macAddresses", [])

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
        return self._rule.get("wanSchedule", {})

    # endregion


class MeshEntity:
    """Represents a base level entity on the mesh."""

    def __init__(self, data: dict, mesh_details: MeshDetails) -> None:
        """Initialise."""

        self._data: dict = data
        self._log_formatter = Logger()
        self._mesh_details: MeshDetails = mesh_details

    def __repr__(self) -> str:
        """Make a pretty string representation of the class.

        :return: Takes the class name and the name of the device to build the representation
        """
        ret = f"{self.__class__.__name__}: "
        if self.name:
            ret += self.name
        return ret

    def _get_user_property(self, property_name: DeviceProperty) -> str | None:
        """Get the given property from the user properties."""
        ret = None

        user_properties: list[dict] = self._data.get("properties", [])
        user_prop: list[dict] | str = [
            prop for prop in user_properties if prop.get("name") == property_name.value
        ]
        if user_prop:
            ret = user_prop[0].get("value")

        return ret

    @staticmethod
    def _signal_strength_to_text(rssi: int | None) -> SignalStrength | None:
        """Convert the given RSSI value to a textual representation."""
        ret: str | None = None
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

    async def _async_api_request(
        self,
        action: api.Actions,
        payload: list[dict] | dict | None = None,
        *,
        ip: str | None = None,
        raise_on_error: bool = True,
    ) -> None:
        """Make a request to the API."""
        req = api.Request(
            action=action.value,
            password=self._mesh_details.password,
            payload=payload,
            raise_on_error=raise_on_error,
            session=self._mesh_details.session,
            target=ip or self._mesh_details.host,
            username=self._mesh_details.user,
        )
        try:
            resp: api.Response = await req.execute(
                timeout=self._mesh_details.request_timeout
            )
        except Exception as exc:
            raise exc from None

        return resp

    @property
    def adapter_info(self) -> list[dict[str, Any]]:
        """Retrieve details about the entity's adapters.

        :return: Adapter details including reservation, Wi-Fi, IP and Guest details
        """

        ret = []

        # -- get the adapters --#
        my_adapters = self._data.get("knownInterfaces", [])
        if my_adapters:
            for adapter in my_adapters:
                connection_info: list[dict[str, Any]] = [
                    c
                    for c in self._data.get("connections", [])
                    if c.get("macAddress", "").lower()
                    == adapter.get("macAddress", "").lower()
                ]
                reservation_info: dict[str, Any] = (
                    self._data.get("reservation_details", {})
                    if self._data.get("reservation_details", {})
                    .get("macAddress", "")
                    .lower()
                    == adapter.get("macAddress", "").lower()
                    else {}
                )
                wifi_info: dict[str, Any] = (
                    self._data.get("connection_details", {})
                    if self._data.get("connection_details", {})
                    .get("macAddress", "")
                    .lower()
                    == adapter.get("macAddress", "").lower()
                    else {}
                )
                signal_strength: SignalStrength | None = self._signal_strength_to_text(
                    wifi_info.get("wireless", {}).get("signalDecibels")
                )
                props = {
                    "band": adapter.get("band"),
                    "connected": bool(connection_info),
                    "guest_network": (
                        None
                        if not connection_info
                        else connection_info[0].get("isGuest", False)
                    ),
                    "ip": (
                        None
                        if not connection_info
                        else connection_info[0].get("ipAddress")
                    ),
                    "ipv6": (
                        None
                        if not connection_info
                        else connection_info[0].get("ipv6Address")
                    ),
                    "mac": adapter.get("macAddress"),
                    "parent_id": (
                        None
                        if not connection_info
                        else connection_info[0].get("parentDeviceID")
                    ),
                    "reservation": bool(reservation_info),
                    "reservation_description": reservation_info.get("description"),
                    "rssi": wifi_info.get("wireless", {}).get("signalDecibels"),
                    "signal_strength": (
                        signal_strength.value.lower()
                        if signal_strength is not None
                        else None
                    ),
                    "type": adapter.get("interfaceType"),
                }
                ret.append(props)

        return ret

    @property
    def name(self) -> str:
        """Retrieve the name of the entity.

        :return: The name of the entity
        """
        ret = (
            self._get_user_property(DeviceProperty.DEVICE_NAME)
            or self._data.get("friendlyName")
            or DEF_EMPTY_NAME
        )

        return ret

    @property
    def parent_name(self) -> str | None:
        """Name of the node the device is connected to.

        :return: The parent node name or None if no node has been identified.
        """
        return self._data.get("parent_name")

    @property
    def results_time(self) -> str:
        """Get the time that the API was queried for the device results.

        :return: The time the scan was executed
        """
        return self._data.get("results_time")

    @property
    def status(self) -> bool:
        """Get whether the device is currently connected to the mesh or not.

        Assumes that if there are no connections specified for the device then it is offline.

        :return: True if connected. False if not.
        """
        conns = self._data.get("connections", [])
        ret = True if conns else False
        return ret

    @property
    def ui_type(self) -> str | None:
        """Get the type assigned to the device as per the web UI.

        :return: The icon slug if available.  None otherwise.
        """
        return self._get_user_property(DeviceProperty.UI_TYPE)

    @property
    def unique_id(self) -> str:
        """Return the unique id of the entity."""
        return self._data.get("deviceID")


class DeviceEntity(MeshEntity):
    """Represents a user device in the mesh, i.e. not a node."""

    def _get_parental_control_device_attributes(
        self,
        schedule: dict[str, str],
        urls: list[str],
    ) -> dict[str, list[str | dict[str, str]]]:
        """Determine what happens with device properties for parental control."""
        ret = {
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
            ret["modify"].append(
                {"name": DeviceProperty.SHOW_IN_PC_LIST.value, "value": "true"}
            )
            if schedule == ParentalControl.ALL_PAUSED_SCHEDULE():
                ret["modify"].append(
                    {"name": DeviceProperty.BLOCK_ALL_MANUALLY.value, "value": "true"}
                )
            else:
                ret["remove"].append(DeviceProperty.BLOCK_ALL_MANUALLY.value)

        return ret

    async def async_delete(self) -> None:
        """Delete the device from the mesh.

        The device must be offline to succeddfully be deleted.

        :return: None
        """
        _LOGGER.debug(self._log_formatter.format("entered"))

        await self._async_api_request(
            api.Actions.DELETE_DEVICE, {"deviceID": self.unique_id}
        )

        _LOGGER.debug(self._log_formatter.format("exited"))

    async def async_rename(self, name: str) -> None:
        """Set the name of the device.

        :param name: The new name for the device.

        :return: None
        """
        _LOGGER.debug(self._log_formatter.format("entered, name: %s"), name)

        payload: dict[str, Any] = {
            "deviceID": self.unique_id,
            "propertiesToModify": [
                {
                    "name": DeviceProperty.DEVICE_NAME.value,
                    "value": name,
                }
            ],
        }

        await self._async_api_request(api.Actions.SET_DEVICE_PROPERTY, payload)

        _LOGGER.debug(self._log_formatter.format("exited"))

    async def async_set_icon(self, icon: UiType | str) -> None:
        """Set the icon for the device.

        :param icon: the icon slug to set.

        :return: None
        """
        _LOGGER.debug(self._log_formatter.format("entered, icon: %s"), icon)

        _icon: UiType
        if not isinstance(icon, UiType):
            if icon not in UiType:
                raise ValueError("Invalid icon specified")

            _icon = UiType(icon)
        else:
            _icon = icon

        payload: dict[str, Any] = {
            "deviceID": self.unique_id,
            "propertiesToModify": [
                {
                    "name": DeviceProperty.UI_TYPE.value,
                    "value": _icon.value.replace("_", "-"),
                }
            ],
        }

        await self._async_api_request(api.Actions.SET_DEVICE_PROPERTY, payload)

        _LOGGER.debug(self._log_formatter.format("exited"))

    async def async_set_parental_control_rules(
        self, rules: dict[str, str], force_enable: bool = False
    ) -> None:
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

        # region #-- get the device MAC --#
        device_mac: str = self.adapter_info[0].get("mac")
        if device_mac is None:
            raise MeshException("No MAC available")
        # endregion

        # -- get the current rules as they may have changed --#
        live_pc_info: api.Response = await self._async_api_request(
            api.Actions.GET_PARENTAL_CONTROL_INFO
        )

        # region #-- determine the rules --#
        keep_rules: list[dict[str, Any]] = [
            rule
            for rule in live_pc_info.data.get("rules", [])
            if device_mac.upper() not in rule.get("macAddresses", [])
        ]
        this_device_rules: list[dict[str, Any]] = [
            rule
            for rule in live_pc_info.data.get("rules", [])
            if device_mac.upper() in rule.get("macAddresses", [])
        ]
        new_rule = ParentalControl.human_readable_to_binary(to_encode=rules)
        if this_device_rules:  # already has rules
            current_schedule = this_device_rules[0]["wanSchedule"]

        cached_schedule: dict[str, str] = self._get_user_property(
            DeviceProperty.ACTUAL_WAN_SCHEDULE
        )
        if new_rule != ParentalControl.ALL_ALLOWED_SCHEDULE():
            _LOGGER.debug(self._log_formatter.format("Adding new rules"))
            if this_device_rules:
                this_device_rules[0]["wanSchedule"] = new_rule
            else:
                this_device_rules.append(
                    ParentalControl.create_rule(
                        mac_address=device_mac,
                        schedule=new_rule,
                        schedule_to_binary=False,
                    )
                )
        else:
            if cached_schedule:
                _LOGGER.debug(
                    self._log_formatter.format("Restoring backed up schedule")
                )
                new_rule = ParentalControl.backup_to_binary(schedule=cached_schedule)
                this_device_rules[0]["wanSchedule"] = new_rule
            else:
                if len(this_device_rules) > 0 and this_device_rules[0].get(
                    "blockedURLs", []
                ):
                    _LOGGER.debug(
                        self._log_formatter.format(
                            "Blocked URLs found, applying permissive rule"
                        )
                    )
                    this_device_rules[0]["wanSchedule"] = new_rule
                else:
                    _LOGGER.debug(self._log_formatter.format("Removing from rules"))
                    this_device_rules = []
        # endregion

        requests: list = [  # build a list of requests to send
            self._async_api_request(
                api.Actions.SET_PARENTAL_CONTROL_INFO,
                {
                    "isParentalControlEnabled": (
                        True
                        if force_enable
                        else live_pc_info.get("isParentalControlEnabled", True)
                    ),
                    "rules": keep_rules + this_device_rules,
                },
            )
        ]

        # region #-- calculate the device properties to update --#
        device_properties: dict[str, list[str, dict[str, str]]] = (
            self._get_parental_control_device_attributes(
                schedule=new_rule,
                urls=(
                    this_device_rules[0].get("blockedURLs", [])
                    if this_device_rules
                    else []
                ),
            )
        )
        if new_rule == ParentalControl.ALL_PAUSED_SCHEDULE():
            if current_schedule:
                device_properties["modify"].append(
                    {
                        "name": DeviceProperty.ACTUAL_WAN_SCHEDULE.value,
                        "value": ParentalControl.encode_for_backup(
                            schedule=current_schedule
                        ),
                    }
                )
        else:
            if cached_schedule:
                device_properties["remove"].append(
                    DeviceProperty.ACTUAL_WAN_SCHEDULE.value
                )

        if device_properties["modify"]:
            requests.append(
                self._async_api_request(
                    api.Actions.SET_DEVICE_PROPERTY,
                    {
                        "deviceID": self.unique_id,
                        "propertiesToModify": device_properties["modify"],
                    },
                )
            )
        if device_properties["remove"]:
            requests.append(
                self._async_api_request(
                    api.Actions.SET_DEVICE_PROPERTY,
                    {
                        "deviceID": self.unique_id,
                        "propertiesToRemove": device_properties["remove"],
                    },
                )
            )
        # endregion

        await asyncio.gather(*requests)

        _LOGGER.debug(self._log_formatter.format("exited"))

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

        # region #-- get the MAC address details --#
        device_mac: str = self.adapter_info[0].get("mac")
        if device_mac is None:
            raise MeshException("No MAC available")
        # endregion

        # -- get the current rules as they may have changed --#
        live_pc_info: api.Response = await self._async_api_request(
            api.Actions.GET_PARENTAL_CONTROL_INFO
        )

        # region #-- determine the rules --#
        keep_rules: list[dict[str, Any]] = [
            rule
            for rule in live_pc_info.data.get("rules", [])
            if device_mac.upper() not in rule.get("macAddresses", [])
        ]
        this_device_rules: list[dict[str, Any]] = [
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
            this_device_rules[0]["blockedURLs"] = list(
                set(this_device_rules[0]["blockedURLs"])
            )
        # endregion
        # endregion

        # region #-- build a list of requests to send --#
        device_properties: dict[str, list[str | dict[str, str]]] = (
            self._get_parental_control_device_attributes(
                this_device_rules[0].get("wanSchedule", {}),
                urls,
            )
        )

        requests: list = [
            self._async_api_request(
                api.Actions.SET_PARENTAL_CONTROL_INFO,
                {
                    "isParentalControlEnabled": (
                        True
                        if force_enable
                        else live_pc_info.get("isParentalControlEnabled", True)
                    ),
                    "rules": keep_rules
                    + (
                        this_device_rules
                        if DeviceProperty.SHOW_IN_PC_LIST.value
                        not in device_properties["remove"]
                        else []
                    ),
                },
            )
        ]

        if device_properties["modify"]:
            requests.append(
                self._async_api_request(
                    api.Actions.SET_DEVICE_PROPERTY,
                    {
                        "deviceID": self.unique_id,
                        "propertiesToModify": device_properties["modify"],
                    },
                )
            )
        if device_properties["remove"]:
            requests.append(
                self._async_api_request(
                    api.Actions.SET_DEVICE_PROPERTY,
                    {
                        "deviceID": self.unique_id,
                        "propertiesToRemove": device_properties["remove"],
                    },
                )
            )
        # endregion

        await asyncio.gather(*requests)

        _LOGGER.debug(self._log_formatter.format("exited"))

    @property
    def description(self) -> str | None:
        """Get the description.

        :return: Device description as per the mesh
        """
        return self._data.get("model", {}).get("description", None)

    @property
    def manufacturer(self) -> str | None:
        """Get the manufacturer.

        :return: Manufacturer as found by the mesh
        """

        ret: str | None = self._get_user_property(
            DeviceProperty.MANUFACTURER
        ) or self._data.get("model", {}).get("manufacturer", None)

        return ret

    @property
    def model(self) -> str | None:
        """Get the model.

        :return: Model as found by the mesh
        """

        ret: str | None = self._get_user_property(
            DeviceProperty.MODEL
        ) or self._data.get("model", {}).get("modelNumber", None)

        return ret

    @property
    def operating_system(self) -> str | None:
        """Get the OS.

        :return: The OS as identified by the mesh
        """
        ret: str | None = self._get_user_property(
            DeviceProperty.OPERATING_SYSTEM
        ) or self._data.get("unit", {}).get("operatingSystem", None)

        return ret

    @property
    def parental_control_schedule(self) -> dict[str, Any]:
        """Return the schedule of the parental controls for the device.

        An empty dictionary means that there are no parental controls in place

        :return: dictionary containing the parental controls for the device.
        """
        ret: dict = {}
        if self._data.get("parental_controls"):
            for rule in self._data.get("parental_controls"):
                pc_details: ParentalControl = ParentalControl(rule=rule)
                ret = {
                    "blocked_internet_access": pc_details.human_readable,
                    "blocked_sites": pc_details.blocked_urls,
                }

        return ret

    @property
    def serial(self) -> str | None:
        """Get the serial number."""
        return self._data.get("unit", {}).get("serialNumber", None)


class NodeEntity(MeshEntity):
    """Represents a node on the mesh."""

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
            (
                adapter.get("ip")
                for adapter in self.adapter_info
                if adapter.get("ip") and adapter.get("primary")
            ),
            None,
        )
        if not target_ip:
            raise MeshInvalidInput(f"{self.name}: no valid address found")
        # endregion

        # region #-- do the reboot --#
        await self._async_api_request(api.Actions.REBOOT, ip=target_ip)
        # endregion

        _LOGGER.debug(self._log_formatter.format("exited"))

    @property
    def adapter_info(self) -> list[dict[str, Any]]:
        """Retrieve details about the entity's adapters.

        :return: Adapter details including reservation, Wi-Fi, IP and Guest details.
            Additionally includes whether it is the primary adapter or not.
        """

        super_adapters: list[dict[str, Any]] = super().adapter_info
        backhaul: dict[str, Any] = self._data.get("backhaul", {})
        for adapter in super_adapters:
            adapter["primary"] = (
                True
                if adapter.get("ip") == backhaul.get("ipAddress")
                or self.type == NodeType.PRIMARY
                else False
            )

        return super_adapters

    @property
    def backhaul(self) -> dict[str, Any]:
        """Get details about the backhaul."""
        ret = {}
        backhaul = self._data.get("backhaul", {})
        speed_mbps: float | None = None
        with contextlib.suppress(TypeError, ValueError):
            speed_mbps = float(backhaul.get("speedMbps"))

        if backhaul:
            signal_strength_raw: int | None = backhaul.get(
                "wirelessConnectionInfo", {}
            ).get("stationRSSI")
            signal_strength: SignalStrength | None = self._signal_strength_to_text(
                signal_strength_raw
            )
            ret = {
                "connection": backhaul.get("connectionType"),
                "last_checked": backhaul.get("timestamp"),
                "speed_mbps": speed_mbps,
                "rssi_dbm": signal_strength_raw,
                "signal_strength": (
                    signal_strength.value.lower()
                    if signal_strength is not None
                    else None
                ),
            }

        return ret

    @property
    def connected_devices(self) -> list[dict[str, Any]]:
        """List of the devices that are connected to the node.

        :return: List of connected devices in alphabetical order sorted by device name
        """
        connected_devices: list[dict[str, Any]] = self._data.get(
            "connected_devices", []
        )
        return sorted(connected_devices, key=lambda device: device.get("name"))

    @property
    def firmware(self) -> dict:
        """Get the firmware details for the node.

        N.B. The date doesn't seem to correlate to anything that I can see (I would have thought it was a build
        or install time but that doesn't seem to be the case)

        :return: A dictionary containing the firmware version and date
        """
        ret = {}
        if (unit_details := self._data.get("unit")) is not None:
            ret["version"] = unit_details.get("firmwareVersion")
            ret["date"] = unit_details.get("firmwareDate")
        available_updates = self._data.get("firmware_updates", {}).get(
            "availableUpdate", {}
        )
        if available_updates:
            ret["latest_version"] = available_updates["firmwareVersion"]
            ret["latest_date"] = available_updates["firmwareDate"]
        else:
            ret["latest_version"] = ret.get("version", None)
            ret["latest_date"] = ret.get("date", None)
        return ret

    @property
    def hardware_version(self) -> str:
        """Get the hardware version of the node.

        :return: A string containing the hardware version
        """
        return self._data.get("model", {}).get("hardwareVersion")

    @property
    def last_update_check(self) -> str | None:
        """Get the last time an update was checked for.

        :return: String containing the last update time as per the API
        """
        ret = self._data.get("firmware_updates", {}).get("lastSuccessfulCheckTime")
        return ret

    @property
    def manufacturer(self) -> str:
        """Get the node manufacturer.

        :return: String containing the name of the manufacturer
        """
        return self._data.get("model", {}).get("manufacturer")

    @property
    def model(self) -> str:
        """Get the model of the node.

        :return: A string containing the model
        """
        return self._data.get("model", {}).get("modelNumber")

    @property
    def parent_ip(self) -> str | None:
        """IP of the parent node.

        :return: The IP of the parent node or None if no node has been identified.
        """
        return self._data.get("backhaul", {}).get("parentIPAddress")

    @property
    def serial(self) -> str:
        """Get the serial number of the node.

        :return: A string containing the serial number
        """
        return self._data.get("unit", {}).get("serialNumber")

    @property
    def type(self) -> NodeType:
        """Get the node type.

        The node types are represented as primary or secondary.

        :return: A NodeType enumeration containing the node type.
        """
        ret = ""
        native_type = self._data.get("nodeType", "").lower()
        if native_type == "master":
            ret = NodeType.PRIMARY
        elif native_type == "slave":
            ret = NodeType.SECONDARY
        return ret
