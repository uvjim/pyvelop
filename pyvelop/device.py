"""Representation of a mesh device."""

# region #-- imports --#
from __future__ import annotations

import base64
import datetime
from collections import namedtuple
from enum import IntEnum, StrEnum
from typing import Any, final

from .base import MeshDevice

# endregion


class ParentalControlActionType(StrEnum):
    """Representation of parental control time actions."""

    BLOCKED = "0"
    UNBLOCKED = "1"


class ParentalControl:
    """Class to manage parental control schedules."""

    BINARY_LENGTH: int = 48
    DEFAULT_DESCRIPTION: str = "default description"
    WEEKDAYS: IntEnum = IntEnum(
        "Weekdays",
        ("sunday", "monday", "tuesday", "wednesday", "thursday", "friday", "saturday"),
        start=0,
    )

    ALL_ALLOWED_SCHEDULE: dict[str, str] = lambda: {
        day.name: ParentalControlActionType.UNBLOCKED.value
        * ParentalControl.BINARY_LENGTH
        for day in ParentalControl.WEEKDAYS
    }

    ALL_PAUSED_SCHEDULE: dict[str, str] = lambda: {
        day.name: ParentalControlActionType.BLOCKED.value
        * ParentalControl.BINARY_LENGTH
        for day in ParentalControl.WEEKDAYS
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

        for daily_schedule in range(0, len(list(__class__.WEEKDAYS))):
            start = daily_schedule * __class__.BINARY_LENGTH
            ret[__class__.WEEKDAYS(daily_schedule).name] = sorted_schedule[
                start : start + __class__.BINARY_LENGTH
            ]

        return ret

    @staticmethod
    def encode_for_backup(schedule: dict[str, str]) -> str:
        """Encode the schedule for storage in a property."""
        ret: str = ""
        chunk_length: int = 8
        sorted_schedule: str = "".join(
            [schedule[day.name] for day in list(__class__.WEEKDAYS)]
        )
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
            if len(to_process) > len(__class__.WEEKDAYS):
                raise ValueError("Too many arguments")
            if len(to_process) < len(__class__.WEEKDAYS):
                for idx in range(len(to_process), len(__class__.WEEKDAYS)):
                    to_process[__class__.WEEKDAYS(idx).name] = None

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


class Device(MeshDevice):
    """Represents a user device in the mesh, i.e. not a node."""

    # region #-- properties --#
    @property
    def description(self) -> str | None:
        """Get the description.

        :return: Device description as per Velop
        """
        return self._attribs.get("model", {}).get("description", None)

    @property
    def manufacturer(self) -> str | None:
        """Get the manufacturer.

        :return: Manufacturer as found by the Velop
        """
        return self._get_user_property(
            name="userDeviceManufacturer"
        ) or self._attribs.get("model", {}).get("manufacturer", None)

    @property
    def model(self) -> str | None:
        """Get the model.

        :return: Model as found by the Velop
        """
        return self._get_user_property(
            name="userDeviceModelNumber"
        ) or self._attribs.get("model", {}).get("modelNumber", None)

    @property
    def operating_system(self) -> str | None:
        """Get the OS.

        :return: The OS as identified by the Velop
        """
        return self._get_user_property(name="userDeviceOS") or self._attribs.get(
            "unit", {}
        ).get("operatingSystem", None)

    @property
    def parental_control_schedule(self) -> dict[str, Any]:
        """Return the schedule of the parental controls for the device.

        An empty dictionary means that there are no parental controls in place
        """
        ret: dict = {}
        if self._attribs.get("parental_controls"):
            for rule in self._attribs.get("parental_controls"):
                pc_details: ParentalControl = ParentalControl(rule=rule)
                ret = {
                    "blocked_internet_access": pc_details.human_readable,
                    "blocked_sites": pc_details.blocked_urls,
                }

        return ret

    @property
    def parent_name(self) -> str | None:
        """Name of the node the device is connected to."""
        return self._attribs.get("parent_name")

    @property
    def serial(self) -> str | None:
        """Get the serial number."""
        return self._attribs.get("unit", {}).get("serialNumber", None)

    # endregion
