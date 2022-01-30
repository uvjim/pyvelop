"""Representation of a mesh device"""

import datetime
from typing import List

from .base import MeshDevice


def _textualise_schedule(schedules: dict) -> dict:
    """Establish a textual version of the schedule

    The schedule is stored in a string of 48 characters ('0's and '1's) representing 30-minute periods.
    '0' is blocked, '1' is allowed.

    :param schedules: dictionary representing the schedules as per the API
    :return: a dictionary showing the times that internet access is blocked and the sites that are also blocked
    """

    _pc_schedule_blocked: str = "0"
    _pc_schedule_unblocked: str = "1"

    ret: dict = {}

    for day, schedule in schedules.items():
        schedule_text: List = []
        schedule_list = list(schedule)
        start: datetime = None
        end: datetime = None
        for pos, minute in enumerate(schedule_list):
            if not start and minute == _pc_schedule_blocked:
                start: datetime = (
                            datetime.datetime.combine(datetime.datetime.today(), datetime.datetime.min.time())
                            + datetime.timedelta(minutes=pos * 30)).time()
                if end:
                    end = None
            if start and (minute == _pc_schedule_unblocked or pos == len(schedule_list) - 1):
                if pos == len(schedule_list) - 1:
                    pos += 1
                end: datetime = (
                            datetime.datetime.combine(datetime.datetime.today(), datetime.datetime.min.time())
                            + datetime.timedelta(minutes=pos * 30)).time()
                schedule_text.append(f"{start.strftime('%H:%M')}-{end.strftime('%H:%M')}")
                if start:
                    start = None

        ret[day] = schedule_text

    return ret


class Device(MeshDevice):
    """Represents a user device in the mesh, i.e. not a node"""

    def __init__(self, **kwargs):
        """Constructor

        :param kwargs: keyword arguments
        """
        super().__init__(**kwargs)

    @property
    def parental_control_schedule(self) -> dict:
        """Return the schedule of the parental controls for the device

        An empty dictionary means that there are no parental controls in place
        """

        ret: dict = {}
        if self._attribs.get("parental_controls"):
            for rule in self._attribs.get("parental_controls"):
                ret = {
                    "blocked_internet_access": _textualise_schedule(rule.get("wanSchedule", {})),
                    "blocked_sites": rule.get("blockedURLs", []),
                }

        return ret
