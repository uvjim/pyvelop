"""Representation of a mesh device."""

# region #-- imports --#
from __future__ import annotations

import base64
import datetime
from collections import namedtuple
from enum import IntEnum
from typing import Any, Dict, List, final

from .base import MeshDevice

# endregion


class ParentalControl:
    """Class to manage parental control schedules."""

    BINARY_LENGTH: int = 48
    BLOCKED: str = "0"
    UNBLOCKED: str = "1"
    WEEKDAYS: IntEnum = IntEnum(
        "Weekdays",
        ("sunday", "monday", "tuesday", "wednesday", "thursday", "friday", "saturday"),
        start=0,
    )

    def __init__(
        self, rule: Dict[str, Any], cached_schedule: str | None = None
    ) -> None:
        """Initialise.

        :param rule:
        :param: cached_schedule:
        """
        self._rule: Dict[str, Any] = rule or {}
        self._cached_schedule: str | None = cached_schedule

    def _decode_for_restore(self, schedule: str) -> Dict[str, str]:
        """Decode the schedule for restoring to the device."""
        ret: Dict[str, str] = {}
        chunk_length: int = 48
        decoded = schedule and base64.b64decode(schedule)
        sorted_schedule: str = ""
        for chunk in decoded:
            sorted_schedule += f"{int(chunk):08b}"

        for daily_schedule in range(0, len(list(self.WEEKDAYS))):
            start = daily_schedule * chunk_length
            ret[self.WEEKDAYS(daily_schedule).name] = sorted_schedule[
                start : start + chunk_length
            ]

        return ret

    @staticmethod
    def _human_readable(schedule: Dict[str, str]) -> Dict[str, List[str]]:
        """Make the given schedule human readable."""
        ret = {}
        for day, sched in schedule.items():
            schedule_text: List = []
            schedule_list = list(sched)
            start: datetime = None
            end: datetime = None
            for pos, minute in enumerate(schedule_list):
                if not start and minute == __class__.BLOCKED:
                    start: datetime = (
                        datetime.datetime.combine(
                            datetime.datetime.today(), datetime.datetime.min.time()
                        )
                        + datetime.timedelta(minutes=pos * 30)
                    ).time()
                    if end:
                        end = None
                if start and (
                    minute == __class__.UNBLOCKED or pos == len(schedule_list) - 1
                ):
                    if pos == len(schedule_list) - 1:
                        pos += 1
                    end: datetime = (
                        datetime.datetime.combine(
                            datetime.datetime.today(), datetime.datetime.min.time()
                        )
                        + datetime.timedelta(minutes=pos * 30)
                    ).time()
                    schedule_text.append(
                        f"{start.strftime('%H:%M')}-{end.strftime('%H:%M')}"
                    )
                    if start:
                        start = None

            ret[day] = schedule_text

        return ret

    # region #-- public methods --#
    def encode_for_backup(self, schedule: Dict[str, str]) -> str:
        """Encode the schedule for storage in a property."""
        ret: str = ""
        chunk_length: int = 8
        sorted_schedule: str = "".join(
            [schedule[day.name] for day in list(self.WEEKDAYS)]
        )
        sorted_chunks: List[str] = [
            (sorted_schedule[i : i + chunk_length])
            for i in range(0, len(sorted_schedule), chunk_length)
        ]

        chunk_chars: bytearray = bytearray()
        for chunk in sorted_chunks:
            chunk_chars.append(int(chunk, base=2))

        ret = chunk_chars and base64.b64encode(chunk_chars).decode()
        return ret

    @staticmethod
    def human_readable_to_binary(
        to_encode: str | Dict[str, str]
    ) -> str | Dict[str, str]:
        """Encode the human readble information to somethings that can be stored."""
        fake_day = "sunday"
        if isinstance(to_encode, str):
            to_process = {fake_day: to_encode}
        else:
            to_process = to_encode
            if len(to_process) > len(__class__.WEEKDAYS):
                raise ValueError("Too many arguments")
            if len(to_process) < len(__class__.WEEKDAYS) and len(to_process) > 1:
                for idx in range(len(to_process), len(__class__.WEEKDAYS)):
                    to_process[__class__.WEEKDAYS(idx).name] = None

        ret: str | Dict[str, str] = {}
        for day, schedule in to_process.items():
            default_binary = [__class__.UNBLOCKED] * __class__.BINARY_LENGTH
            if schedule is not None:
                time_schedules: List[str] = schedule.split(",")
                TimeBlock = namedtuple("TimeBlock", ["start", "end"])
                for schedule in time_schedules:
                    times: List[str] = schedule.split("-")
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
                        default_binary[idx] = __class__.BLOCKED

                    if all(  # break out early if all blocked
                        val == __class__.BLOCKED for val in default_binary
                    ):
                        break

            ret[day] = "".join(default_binary)

        if isinstance(to_encode, str):
            ret = ret[fake_day]

        return ret

    @staticmethod
    def binary_to_human_readable(
        to_decode: str | Dict[str, str]
    ) -> str | Dict[str, List[str]]:
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
    def blocked_urls(self) -> List[str]:
        """Return blocked URLs."""
        return self._rule.get("blockedURLs", [])

    @property
    def cached_schedule(self) -> Dict[str, str]:
        """Return the cached schedule."""
        if self._cached_schedule is not None:
            return self._decode_for_restore(self._cached_schedule)

        return None

    @property
    def description(self) -> str:
        """Return the rule description."""
        return self._rule.get("description", "default description")

    @property
    def human_readable_cached_schedule(self) -> Dict[str, List[str]]:
        """Return the cached schedule in human readable form."""
        if self.cached_schedule is not None:
            return self._human_readable(self.cached_schedule)

        return None

    @property
    def human_readable_schedule(self) -> Dict[str, List[str]]:
        """Return the schedule in human readable form."""
        return self._human_readable(self.schedule)

    @property
    def is_enabled(self) -> bool:
        """Return whether the rule is enabled or not."""
        return self._rule.get("isEnabled", True)

    @property
    def is_paused(self) -> bool:
        """Return whether the rule is all blocking."""
        return self.schedule == self.paused_schedule

    @property
    def mac_addresses(self) -> List[str]:
        """Return the MAC addresses the rule is for."""
        return self._rule.get("macAddresses", [])

    @final
    @property
    def paused_schedule(self) -> Dict[str, str]:
        """Return a paused schedule."""
        return {day.name: self.BLOCKED * 48 for day in self.WEEKDAYS}

    @final
    @property
    def rule(self) -> Dict[str, Any]:
        """Return the rule."""
        return {
            "blockedURLs": self.blocked_urls,
            "description": self.description,
            "isEnabled": self.is_enabled,
            "macAddresses": self.mac_addresses,
            "wanSchedule": self.schedule,
        }

    @property
    def schedule(self) -> Dict[str, str]:
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
    def parental_control_schedule(self) -> dict:
        """Return the schedule of the parental controls for the device.

        An empty dictionary means that there are no parental controls in place
        """
        ret: dict = {}
        if self._attribs.get("parental_controls"):
            for rule in self._attribs.get("parental_controls"):
                pc_details: ParentalControl = ParentalControl(rule=rule)
                ret = {
                    "blocked_internet_access": pc_details.human_readable_schedule,
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
