"""pyvelop CLI."""

# region #-- imports --#
from __future__ import annotations

import contextlib
import datetime as dt
import json
import logging
import sys
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import fields, is_dataclass
from enum import StrEnum, auto
from types import MappingProxyType
from typing import Any, cast

import aiohttp
import asyncclick as click
import pandas as pd

from .action_registry import ActionDefinition, ActionKey, Actions, ActionScope
from .exceptions import (
    MeshConnectionError,
    MeshDeviceNotFoundResponse,
    MeshException,
    MeshInvalidCredentials,
    MeshNodeNotPrimary,
    MeshTimeoutError,
)
from .logger import Logger
from .mesh import (
    Mesh,
    NightModeState,
    ScheduledRebootInterval,
    SpeedtestResult,
)
from .mesh_attribute import MeshAttribute
from .mesh_entity import (
    BackhaulInfo,
    DeviceEntity,
    NodeEntity,
    NodeType,
    ParentalControl,
    Weekdays,
)

# endregion


class MeshWorkflows:
    """Namespaced CLI workflows for the mesh."""

    @staticmethod
    async def channel_scan_info(mesh: Mesh) -> dict[str, Any]:
        """Rerieve the channel scan information.

        :return: details about the last channel scan.
        """
        return await mesh.async_get_channel_scan_info()

    @staticmethod
    async def detect_capabilities(mesh: Mesh) -> tuple[Mapping[str, Any], ...]:
        """Retrieve the mesh capabilities from the last time they were discovered.

        :return: the capabilities that were discovered on the mesh.
        """
        ret = mesh.capabilities
        return ret

    @staticmethod
    async def channel_scan_start(mesh: Mesh) -> None:
        """Start a channel scan."""
        await mesh.async_start_channel_scan()

    @staticmethod
    async def check_for_updates(mesh: Mesh) -> None:
        """Check for updates to the mesh nodes."""
        await mesh.async_check_for_updates()

    @staticmethod
    async def guest_wifi_state(mesh: Mesh, enabled: bool) -> None:
        """Change the state of guest Wi-Fi.

        :param enabled: `True` to turn the feature on.
        """
        await mesh.async_set_guest_wifi_state(enabled)

    @staticmethod
    async def homekit_state(mesh: Mesh, enabled: bool) -> None:
        """Change the state of the HomeKit feature.

        :param enabled: `True` to turn the feature on.
        """
        await mesh.async_set_homekit_state(enabled)

    @staticmethod
    async def night_mode_state(mesh: Mesh, state: NightModeState) -> None:
        """Change the state of the night mode functionality.

        :param state: the intended state.
        """
        await mesh.async_set_night_mode_state(state)

    @staticmethod
    async def parental_control_state(mesh: Mesh, enabled: bool) -> None:
        """Change the state of the parental control feature.

        :param enabled: `True` to turn the feature on.
        """
        await mesh.async_set_parental_control_state(enabled)

    @staticmethod
    async def speedtest_clear_results(mesh: Mesh) -> None:
        """Clear all Speedtest results from the mesh."""
        await mesh.async_clear_speedtest_results()

    @staticmethod
    async def speedtest_get_results(mesh: Mesh) -> tuple[SpeedtestResult, ...]:
        """Retrieve the Speedtest results from the mesh."""
        ret: tuple[SpeedtestResult, ...] = await mesh.async_get_speedtest_results(count=10)
        return ret

    @staticmethod
    async def speedtest_get_status(mesh: Mesh) -> None:
        """Retrieve the current speedtest state from the mesh."""
        await mesh.async_get_speedtest_status()

    @staticmethod
    async def speedtest_start(mesh: Mesh) -> int | SpeedtestResult:
        """Start a Speedtest on the mesh.

        The function waits for the test to complete and displays the results.

        :return: details of the executed speedtest.
        """

        def _display_progress(info: SpeedtestResult) -> None:
            """Display the progress of the speedtest."""

            _output(None, f"{json.dumps(info, default=json_default)}\n")

        ret = await mesh.async_start_speedtest(wait=True, callback_func=_display_progress)

        return ret

    @staticmethod
    async def upnp_state(mesh, enabled: bool) -> None:
        """Change the state of the UPnP feature.

        :param enabled: `True` to turn the feature on.
        """

        cur_settings: dict[str, bool] = await mesh.async_get_upnp_state()
        new_upnp_settings_off: dict[str, bool] = {
            "enabled": enabled,
            "allow_change_settings": cur_settings.get("canUsersConfigure", enabled),
            "allow_disable_internet": cur_settings.get("canUsersDisableWANAccess", enabled),
        }

        await mesh.async_set_upnp_settings(**new_upnp_settings_off)


class StandardCommand(click.Command):
    """Define standard options that should be used with all commands."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """Initialise."""
        super().__init__(*args, **kwargs)

        def _setup_logging(_: click.Context, param: click.Option, value: Any) -> None:
            """Handle logging."""
            if param.name == "verbose":
                if value:
                    logging.basicConfig(format="%(levelname)s:%(asctime)s:%(name)s:%(message)s")
                    _LOGGER.setLevel(logging.DEBUG)
                    _LOGGER.debug("args: %s", sys.argv[1:])
                    _LOGGER.debug("Setting up logging")
                    if value > 1:
                        logging.getLogger(__package__).setLevel(logging.DEBUG)
                        logging.getLogger(f"{__package__}.jnap").setLevel(logging.WARNING)
                        logging.getLogger(f"{__package__}.jnap.verbose").setLevel(logging.WARNING)
                        logging.getLogger(f"{__package__}.mesh.verbose").setLevel(logging.WARNING)
                        logging.getLogger(f"{__package__}.mesh_entity.verbose").setLevel(logging.WARNING)
                        if value > 2:
                            logging.getLogger(f"{__package__}.mesh.verbose").setLevel(logging.DEBUG)
                            logging.getLogger(f"{__package__}.mesh_entity.verbose").setLevel(logging.DEBUG)
                            if value > 3:
                                logging.getLogger(f"{__package__}.jnap").setLevel(logging.DEBUG)
                                if value > 4:
                                    logging.getLogger(f"{__package__}.jnap.verbose").setLevel(logging.DEBUG)

        standard_options: list[click.Option] = [
            click.Option(
                ("-a", "--primary-node"),
                help="The primary node to direct all queries to.",
                required=True,
                type=str,
            ),
            click.Option(
                ("-c", "--create-session"),
                default=True,
                help="Supply this argument to create a session to pass into the library.",
                hidden=True,
                is_flag=True,
            ),
            click.Option(
                ("-p", "--password"),
                help="The local mesh password.",
                prompt=True,
                required=True,
            ),
            click.Option(
                ("--redact-file",),
                help="Path to the file that provides supplementary redactions.",
                type=click.File(),
            ),
            click.Option(
                ("--redact/--no-redact",),
                default=True,
                help="Redact sensitive information from the debug output. This doesn't affect intended CLI output.",
                is_flag=True,
            ),
            click.Option(
                ("-t", "--timeout"),
                default=30,
                help="The timeout for a request.",
                type=int,
            ),
            click.Option(
                ("-u", "--username"),
                default="admin",
                help="The username for communications.",
                type=str,
            ),
            click.Option(
                ("-v", "--verbose"),
                callback=_setup_logging,
                count=True,
                help="Set the verbosity of logging. Adding more increases the level.",
            ),
        ]

        standard_options.reverse()
        for opt in standard_options:
            self.params.insert(0, opt)

    async def invoke(self, ctx: click.Context) -> Any:
        """Initialise the session if need be and defer to normal processing."""

        create_session = ctx.params.get("create_session", True)

        if not create_session:
            return await super().invoke(ctx)

        async with aiohttp.ClientSession(raise_for_status=True) as session:
            ctx.obj = session
            return await super().invoke(ctx)


# CLI workflow mappings
MESH_WORKFLOWS: Mapping[str, Callable[[Mesh], Awaitable[Any]]] = MappingProxyType(
    {
        "channel_scan_info": MeshWorkflows.channel_scan_info,
        "channel_scan_start": MeshWorkflows.channel_scan_start,
        "detect_capabilities": MeshWorkflows.detect_capabilities,
        "guest_wifi_off": lambda mesh: MeshWorkflows.guest_wifi_state(mesh, False),
        "guest_wifi_on": lambda mesh: MeshWorkflows.guest_wifi_state(mesh, True),
        "homekit_off": lambda mesh: MeshWorkflows.homekit_state(mesh, False),
        "homekit_on": lambda mesh: MeshWorkflows.homekit_state(mesh, True),
        "night_mode_always": lambda mesh: MeshWorkflows.night_mode_state(mesh, NightModeState.ALWAYS),
        "night_mode_off": lambda mesh: MeshWorkflows.night_mode_state(mesh, NightModeState.OFF),
        "night_mode_on": lambda mesh: MeshWorkflows.night_mode_state(mesh, NightModeState.NIGHT_MODE),
        "parental_control_off": lambda mesh: MeshWorkflows.parental_control_state(mesh, False),
        "parental_control_on": lambda mesh: MeshWorkflows.parental_control_state(mesh, True),
        "speedtest_clear_results": MeshWorkflows.speedtest_clear_results,
        "speedtest_results": MeshWorkflows.speedtest_get_results,
        "speedtest_status": MeshWorkflows.speedtest_get_status,
        "speedtest_start": MeshWorkflows.speedtest_start,
        "update_check_start": MeshWorkflows.check_for_updates,
        "upnp_off": lambda mesh: MeshWorkflows.upnp_state(mesh, False),
        "upnp_on": lambda mesh: MeshWorkflows.upnp_state(mesh, True),
        "wps_off": lambda mesh: mesh.async_set_wps_state(False),
        "wps_on": lambda mesh: mesh.async_set_wps_state(True),
    }
)


class AllowedChecks(StrEnum):
    """Possible checks that can be carried out by diagnostics."""

    NETWORK_DETAILS = auto()


_LOGGER: Logger = Logger(logging.getLogger(f"{__package__}.cli"))


def get_properties[T](cls: type[T]) -> set[str]:
    """Retrieve effective properties and dataclass fields for a class.

    Python properties are collected according to normal MRO resolution.
    Dataclass fields are also included when ``cls`` is a dataclass.

    :param cls:
        The class to inspect.
    :returns:
        The names of the class's effective properties and dataclass fields.
    """

    properties: set[str] = set()
    seen: set[str] = set()

    # Respect normal attribute resolution when inspecting properties.
    for base in cls.__mro__:
        for name, value in base.__dict__.items():
            if name in seen:
                continue

            seen.add(name)

            if isinstance(value, property):
                properties.add(name)

    # dataclasses.fields() includes inherited dataclass fields and excludes
    # ClassVar and InitVar fields.
    if is_dataclass(cls):
        properties.update(field.name for field in fields(cls))

    return properties


def json_default(obj: Any) -> Any:
    """Serialise objects that cannot otherwise be serialised.

    :returns: a serialisable object for `json.dump` or `json.dumps`.
    """

    if isinstance(obj, SpeedtestResult):
        return obj.as_dict()
    elif isinstance(obj, MappingProxyType):
        return obj.copy()

    return obj.__repr__


@click.group()
@click.version_option(package_name=__package__)
async def cli() -> None:
    """CLI for interacting with the pyvelop module."""


@cli.group(name="device")
@click.help_option()
async def device_group() -> None:
    """Work with devices on the mesh."""


@device_group.command(cls=StandardCommand, name="attribute")
@click.argument("device")
@click.argument("attribute", type=click.Choice(tuple(get_properties(DeviceEntity)), case_sensitive=False))
@click.pass_context
async def device_attr(
    ctx: click.Context,
    /,
    device: str,
    attribute: str,
    **_: Any,
) -> None:
    """Retrieve details about a specific mesh attribute."""

    devices: tuple[DeviceEntity, ...] | None = await _get_device_details(ctx=ctx, device=(device,))
    if devices is not None:
        for found_device in devices:
            attr: Any = getattr(found_device, attribute, None)
            _display_attribute(attribute, attr)


@device_group.command(cls=StandardCommand, name="delete")
@click.pass_context
@click.argument("device")
async def device_delete(
    ctx: click.Context,
    /,
    device: str,
    **_: Any,
) -> None:
    """Delete a device on the Mesh."""

    dev = (device,)
    devices = await _get_device_details(ctx, dev)

    if devices is not None:
        for found_device in devices:
            await found_device.async_delete()


@device_group.command(cls=StandardCommand, name="details")
@click.pass_context
@click.argument("device", nargs=-1)
@click.option("--outfile", default=None, required=False)
async def device_details(
    ctx: click.Context,
    /,
    device: tuple[str, ...],
    outfile: str | None = None,
    **_: Any,
) -> None:
    """Display details about a device on the Mesh."""
    devices = await _get_device_details(ctx=ctx, device=device)

    if devices is not None:
        _output(outfile, "# Device Details\n")
        for found_device in devices:
            data: dict[str, Any] = {
                "Queried at": (
                    dt.datetime.fromtimestamp(found_device.results_time).replace(tzinfo=dt.UTC)
                    if found_device.results_time is not None
                    else None
                ),
                "Device ID": found_device.unique_id.value,
                "Online": found_device.status.value,
                "Parent": found_device.parent_name.value,
                "Manufacturer": found_device.manufacturer.value,
                "Model": found_device.model.value,
                "Description": found_device.description.value,
                "Operating system": found_device.operating_system.value,
                "Serial #": found_device.serial.value,
                "Icon type": found_device.ui_type.value,
            }
            _display(
                outfile,
                pd.DataFrame.from_dict(data, orient="index", columns=[""]),
                index=True,
                title=found_device.name.value,
            )
            _display(
                outfile,
                pd.DataFrame(found_device.adapter_info.value),
                title="# Connections",
            )
            num_blocked_sites = len(found_device.parental_control_schedule.value.get("blocked_sites", []))
            if num_blocked_sites > 0:
                _display(
                    outfile,
                    pd.DataFrame(
                        found_device.parental_control_schedule.get("blocked_sites"),
                        columns=["site"],
                    ),
                    title="Parental Control",
                )
            schedule = found_device.parental_control_schedule.get("blocked_internet_access", {})
            if num_blocked_sites == 0 and schedule:
                _display(
                    outfile,
                    pd.DataFrame.from_dict(schedule, orient="index"),
                    index=True,
                    title="Parental Control",
                )
            else:
                _display(
                    outfile,
                    pd.DataFrame.from_dict(schedule, orient="index"),
                    index=True,
                )


@device_group.command(cls=StandardCommand, name="internet_access")
@click.pass_context
@click.argument("device_id")
@click.option("--block/--no-block", default=False)
async def device_internet_access(
    ctx: click.Context,
    /,
    device_id: str,
    block: bool,
    **_: Any,
) -> None:
    """Block/Unblock access to the internet."""
    dev_id = (device_id,)
    devices = await _get_device_details(ctx, dev_id)

    if devices is not None:
        for found_device in devices:
            try:
                rules_to_apply = {}
                for weekday in Weekdays:
                    rules_to_apply[weekday.name.lower()] = (
                        None
                        if not block
                        else ParentalControl.binary_to_human_readable(
                            ParentalControl.ALL_PAUSED_SCHEDULE().get(weekday.name.lower(), "")
                        )
                    )
                await found_device.async_set_parental_control_rules(
                    rules=rules_to_apply,
                    force_enable=True if block else False,
                )
            except MeshDeviceNotFoundResponse as err:
                _LOGGER.error("Device not found: %s", err.devices[0])
            except MeshException as err:
                _LOGGER.error(err)


@device_group.command(cls=StandardCommand, name="rename")
@click.pass_context
@click.argument("device_id")
@click.argument("new_name")
async def device_rename(ctx: click.Context, /, device_id: str, new_name: str, **_: Any) -> None:
    """Rename the given device."""

    dev_id = (device_id,)
    devices = await _get_device_details(ctx, dev_id)

    if devices is not None:
        for found_device in devices:
            await found_device.async_rename(new_name)


@device_group.command(cls=StandardCommand, name="set_icon")
@click.pass_context
@click.argument("device_id")
@click.argument("icon")
async def device_set_icon(ctx: click.Context, /, device_id: str, icon: str, **_: Any) -> None:
    """Set the icon for the given device."""

    dev_id = (device_id,)
    devices = await _get_device_details(ctx, dev_id)
    if devices is not None:
        for found_device in devices:
            await found_device.async_set_icon(icon.lower())


@device_group.command(cls=StandardCommand, name="set_rules")
@click.pass_context
@click.argument("device_id")
@click.option("--sunday")
@click.option("--monday")
@click.option("--tuesday")
@click.option("--wednesday")
@click.option("--thursday")
@click.option("--friday")
@click.option("--saturday")
async def device_pc_set_rules(
    ctx: click.Context,
    /,
    device_id: str,
    sunday: str,
    monday: str,
    tuesday: str,
    wednesday: str,
    thursday: str,
    friday: str,
    saturday: str,
    **_: Any,
) -> None:
    """Set the parental control rules."""

    rules_to_apply: dict[str, Any] = {
        day.name.lower(): (locals().get(day.name.lower()) if locals().get(day.name.lower()) else None)
        for day in Weekdays
    }

    dev_id = (device_id,)
    devices = await _get_device_details(ctx, dev_id)

    if devices is not None:
        for found_device in devices:
            await found_device.async_set_parental_control_rules(
                rules_to_apply,
                force_enable=True,
            )


@device_group.command(cls=StandardCommand, name="set_urls")
@click.pass_context
@click.argument("device_id")
@click.argument("urls", nargs=-1)
@click.option("--merge/--no-merge", default=True)
async def device_pc_set_urls(
    ctx: click.Context, /, device_id: str, merge: bool, urls: tuple[str, ...], **_: Any
) -> None:
    """Set the parental control URLs."""

    dev_id = (device_id,)
    devices = await _get_device_details(ctx, dev_id)

    if devices is not None:
        for found_device in devices:
            await found_device.async_set_parental_control_urls(
                list(urls),
                force_enable=True,
                merge=merge,
            )


@cli.group(name="diagnostics")
@click.help_option()
async def diagnostics_group() -> None:
    """Carry out some diagnostic checks on the Mesh."""


@diagnostics_group.command(cls=StandardCommand, name="check")
@click.argument("check", type=click.Choice(tuple(check.value for check in AllowedChecks), case_sensitive=False))
@click.pass_context
async def diagnostics(
    ctx: click.Context,
    /,
    check: AllowedChecks,
    **_: Any,
) -> None:
    """Execute some diagnostics tests on the mesh results."""

    async def _diagnostics(mesh: Mesh) -> None:
        devices: tuple[DeviceEntity, ...] = mesh.devices

        if check == AllowedChecks.NETWORK_DETAILS:
            ret_devices: set[DeviceEntity] = {d for d in devices if d.status}
            ret: list[dict[str, Any]] = [
                {
                    "id": d.unique_id,
                    "name": d.name,
                    "parent": d.parent_name,
                    "parent_id": next(adi.parent_id for adi in d.adapter_info.value),
                    "connection_type": next(adi.type for adi in d.adapter_info.value),
                    "mac": next(adi.mac for adi in d.adapter_info.value),
                    "ip": next(adi.ip for adi in d.adapter_info.value),
                    "ipv6": next(adi.ipv6 for adi in d.adapter_info.value),
                }
                for d in ret_devices
            ]
            _display(
                None,
                pd.DataFrame(ret, index=pd.RangeIndex(start=1, stop=len(ret) + 1)),
                index=True,
                title="Devices Without a Parent",
            )

    await _with_mesh(ctx, _diagnostics)


@cli.group(name="example")
@click.help_option()
async def example_group() -> None:
    """Manage available examples."""


@example_group.command(name="create")
@click.argument("path", type=click.Path(dir_okay=False, writable=True, resolve_path=True))
@click.argument("example", type=click.Choice(("redact_file",), case_sensitive=False))
def create(example: str, path: str) -> None:
    """Create an example file."""

    if example == "redact_file":
        output: dict[str, list[str]] = {
            "comments": [
                "This is an example file for helping specify supplementary redaction paths.",
                "The file is used to add additional item paths to be redacted per capability.",
                "The file is formatted using the capability name as the key with a list of paths that should be redacted.",
                "Examples of item path processing: -",
                "`macAddress` will redact the attribute at the root level of the API response for that capability.",
                "`wanConnection.dnsServer1` will redact the `dnsServer1` attribute within the `wanConnection` object.",
                "`devices.connections.macAddress` just like before this will navigate through the object to redact the `macAddress` attribute.",
                "When the redaction process encounters a list the remaining path is used within that list.",
                "using `devices.connections.macAddress` as the example;",
                "`devices` is a list so all items in the `devices` are searched for a `connections` object.",
                "It just so happens in this case that `connections` is also a list, so all those items are searched for `macAddress`.",
                "This means that all `macAddress` attributes for all items in that API response will be redacted.",
                "The defaults have been detailed in this file.",
            ]
        }
        possible_actions: list[ActionDefinition] = list(Actions.values())
        output.update({action.key: list(action.redactions) for action in possible_actions})

    with open(path, "w") as fp:
        fp.write(json.dumps(output, indent=4))
    click.echo(path)


@cli.group(name="mesh")
@click.help_option()
async def mesh_group() -> None:
    """Work with the mesh."""


@mesh_group.command(cls=StandardCommand, name="action")
@click.argument("action", type=click.Choice(tuple(MESH_WORKFLOWS), case_sensitive=False))
@click.pass_context
async def mesh_action(
    ctx: click.Context,
    /,
    action: str,
    **_: Any,
) -> None:
    """Carry out a specified action on the mesh."""

    workflow = MESH_WORKFLOWS[action]

    ret = await _with_mesh(ctx, workflow)
    _output(None, json.dumps(ret, default=json_default))


@mesh_group.command(cls=StandardCommand, name="attribute")
@click.argument("attribute", type=click.Choice(tuple(get_properties(Mesh)), case_sensitive=False))
@click.pass_context
async def mesh_attr(
    ctx: click.Context,
    /,
    attribute: str,
    **_: Any,
) -> None:
    """Retrieve details about a specific mesh attribute."""

    async def _mesh_attr(mesh: Mesh) -> None:
        attr: Any = getattr(mesh, attribute, None)
        _display_attribute(attribute, attr)

    await _with_mesh(ctx, _mesh_attr)


@mesh_group.command(cls=StandardCommand, name="details")
@click.option("--outfile", default=None, required=False)
@click.pass_context
async def mesh_details(
    ctx: click.Context,
    /,
    outfile: str | None = None,
    **_: Any,
) -> None:
    """Get details about the Mesh."""

    async def _mesh_details(mesh: Mesh) -> None:
        data: dict[str, Any] = {}
        _output(outfile, "# Mesh Details\n")
        data = {k: dt.datetime.fromtimestamp(v).replace(tzinfo=dt.UTC) for k, v in mesh.last_gather_details}
        data.update(
            {
                "duration": dt.timedelta(
                    seconds=(mesh.last_gather_details[-1][1] - mesh.last_gather_details[0][1])
                ).total_seconds()
            }
        )
        _display(
            outfile,
            pd.DataFrame.from_dict(
                data,
                orient="index",
                columns=[""],
            ),
            index=True,
        )
        _display(
            outfile,
            pd.DataFrame(
                mesh.capabilities,
                index=pd.RangeIndex(start=1, stop=len(mesh.capabilities) + 1),
            ),
            index=True,
            title="Capabilities",
        )
        mesh_capabilities: set[str] = {cap.get("key", "") for cap in mesh.capabilities}
        if Actions.GET_LED_NIGHT_MODE.key in mesh_capabilities:
            data = {"Night mode": str(mesh.night_mode)}
            _display(
                outfile,
                pd.DataFrame.from_dict(data, orient="index", columns=[""]),
                index=True,
                title="Night mode",
            )
        if Actions.GET_SCHEDULED_REBOOT_SETTINGS.key in mesh_capabilities:
            data = {
                "Enabled": mesh.scheduled_reboot_enabled.value,
                "Interval": (str(mesh.scheduled_reboot_interval) if mesh.scheduled_reboot_interval else None),
            }
            _display(
                outfile,
                pd.DataFrame.from_dict(data, orient="index", columns=[""]),
                index=True,
                title="Scheduled Reboot Settings",
            )
        if Actions.GET_WAN_INFO.key in mesh_capabilities:
            data = {
                "Internet connected": mesh.wan_status.value,
                "Bridge mode": mesh.is_in_bridge_mode.value,
                "Public IP": mesh.wan_ip.value,
                "WAN MAC": mesh.wan_mac.value,
            }
            _display(
                outfile,
                pd.DataFrame.from_dict(data, orient="index", columns=[""]),
                index=True,
                title="WAN Info",
            )
        if Actions.GET_LAN_SETTINGS.key in mesh_capabilities:
            data = {
                "DHCP enabled": mesh.dhcp_enabled.value,
            }
            _display(
                outfile,
                pd.DataFrame.from_dict(data, orient="index", columns=[""]),
                index=True,
                title="LAN Settings",
            )
            _display(
                outfile,
                pd.DataFrame(
                    mesh.dhcp_reservations.value,
                    index=pd.RangeIndex(start=1, stop=(len(mesh.dhcp_reservations) + 1)),
                ),
                index=True,
                title="DHCP Reservations",
            )
        if Actions.GET_TOPOLOGY_OPTIMISATION_SETTINGS.key in mesh_capabilities:
            data = {
                "Client steering enabled": mesh.client_steering_enabled.value,
                "Node steering enabled": mesh.node_steering_enabled.value,
            }
            _display(
                outfile,
                pd.DataFrame.from_dict(data, orient="index", columns=[""]),
                index=True,
                title="Topology Optimisation Settings",
            )
        if Actions.GET_MLO_SETTINGS.key in mesh_capabilities:
            data = {"Enabled": (mesh.mlo_state.value if mesh.mlo_state.value is not None else "Unsupported")}
            _display(
                outfile,
                pd.DataFrame.from_dict(data, orient="index", columns=[""]),
                index=True,
                title="Multi-Link Operation (MLO)",
            )
        if Actions.GET_EXPRESS_FORWARDING.key in mesh_capabilities:
            data = {
                "Supported": mesh.express_forwarding_supported.value,
                "Enabled": mesh.express_forwarding_enabled.value,
            }
            _display(
                outfile,
                pd.DataFrame.from_dict(data, orient="index", columns=[""]),
                index=True,
                title="Express Forwarding",
            )
        if Actions.GET_PARENTAL_CONTROL_INFO.key in mesh_capabilities:
            data = {
                "Enabled": mesh.parental_control_enabled.value,
            }
            _display(
                outfile,
                pd.DataFrame.from_dict(data, orient="index", columns=[""]),
                index=True,
                title="Parental Control",
            )
        if Actions.GET_MAC_FILTERING_SETTINGS.key in mesh_capabilities:
            data = {
                "Enabled": mesh.mac_filtering_enabled.value,
                "Mode": str(mesh.mac_filtering_mode),
                "Filters": (mesh.mac_filtering_addresses.value if len(mesh.mac_filtering_addresses) > 0 else None),
            }
            _display(
                outfile,
                pd.DataFrame.from_dict(data, orient="index", columns=[""]),
                index=True,
                title="MAC Filtering",
            )
        if Actions.GET_WPS_SERVER_SETTINGS.key in mesh_capabilities:
            data = {
                "Enabled": mesh.wps_state.value,
            }
            _display(
                outfile,
                pd.DataFrame.from_dict(data, orient="index", columns=[""]),
                index=True,
                title="WPS Settings",
            )
        if Actions.GET_ALG_SETTINGS.key in mesh_capabilities:
            data = {
                "Enabled": mesh.sip_enabled.value,
            }
            _display(
                outfile,
                pd.DataFrame.from_dict(data, orient="index", columns=[""]),
                index=True,
                title="SIP Settings",
            )
        if Actions.GET_HOMEKIT_SETTINGS.key in mesh_capabilities:
            data = {
                "Enabled": mesh.homekit_enabled.value,
                "Paired": mesh.homekit_paired.value,
            }
            _display(
                outfile,
                pd.DataFrame.from_dict(data, orient="index", columns=[""]),
                index=True,
                title="HomeKit Settings",
            )
        if Actions.GET_UPNP_SETTINGS.key in mesh_capabilities:
            data = {
                "Enabled": mesh.upnp_enabled.value,
                "allow_change_settings": mesh.upnp_allow_change_settings.value,
                "allow_disable_internet": mesh.upnp_allow_disable_internet.value,
            }
            _display(
                outfile,
                pd.DataFrame.from_dict(data, orient="index", columns=[""]),
                index=True,
                title="UPnP Settings",
            )
        if Actions.GET_DEVICES.key in mesh_capabilities:
            data_list: list[str | dict[str, Any]] = [n.name.value for n in mesh.nodes]
            _display(
                outfile,
                pd.DataFrame(
                    data_list,
                    columns=["name"],
                    index=pd.RangeIndex(start=1, stop=(len(data_list) + 1)),
                ),
                index=True,
                title="Nodes",
            )
        if Actions.GET_SPEEDTEST_RESULTS.key in mesh_capabilities:
            _display(
                outfile,
                pd.DataFrame(
                    mesh.speedtest_results.value,
                    index=pd.RangeIndex(start=1, stop=len(mesh.speedtest_results) + 1),
                ),
                index=True,
                title="Speedtest Results",
            )
        if Actions.GET_GUEST_NETWORK_INFO.key in mesh_capabilities:
            data = {
                "Enabled": mesh.guest_wifi_enabled.value,
            }
            _display(
                outfile,
                pd.DataFrame.from_dict(data, orient="index", columns=[""]),
                index=True,
                title="Guest Network Settings",
            )
            _display(
                outfile,
                pd.DataFrame.from_dict(cast(dict[str, Any], mesh.guest_wifi_details.value)),
                title="# Networks",
            )
        if Actions.GET_STORAGE_PARTITIONS.key in mesh_capabilities:
            _display(
                outfile,
                pd.DataFrame(mesh.storage_available.value),
                title="File Shares",
            )
        if Actions.GET_DEVICES.key in mesh_capabilities:
            data_list = [
                {"name": d.name.value, "ip": d.adapter_info.value[0].ip if d.adapter_info else None}
                for d in mesh.devices
                if d.status.value
            ]
            _display(
                outfile,
                pd.DataFrame(
                    data_list,
                    index=pd.RangeIndex(start=1, stop=(len(data_list) + 1)),
                ),
                index=True,
                title="Online Devices",
            )
            data_list = [d.name.value for d in mesh.devices if not d.status.value]
            _display(
                outfile,
                pd.DataFrame(
                    data_list,
                    columns=["name"],
                    index=pd.RangeIndex(start=1, stop=(len(data_list) + 1)),
                ),
                index=True,
                title="Offline Devices",
            )

    await _with_mesh(ctx, _mesh_details)


@mesh_group.command(cls=StandardCommand, name="ping")
@click.pass_context
async def mesh_ping(
    ctx: click.Context,
    /,
    **_: Any,
):
    """Test connecting to the mesh.

    You get the option to try again allowing you to disconnect if needed.
    """

    async def _ping(mesh: Mesh) -> None:
        click.echo(await mesh.async_ping())
        if click.confirm(text="Do you want to try again?"):
            click.echo(await mesh.async_ping())

    await _with_mesh(ctx, _ping)


@mesh_group.command(cls=StandardCommand, name="scheduled_reboot")
@click.option("--interval")
@click.pass_context
async def mesh_scheduled_reboot(
    ctx: click.Context,
    /,
    interval: str | None = None,
    **_: Any,
) -> None:
    """Change state of the Scheduled Reboot feature."""

    async def _mesh_scheduled_reboot(mesh: Mesh) -> None:
        if interval is None:
            _LOGGER.debug("disabling scheduled reboots")
            await mesh.async_set_scheduled_reboot_state(state=False)
        else:
            _LOGGER.debug("setting scheduled reboot interval to %s", interval.title())
            await mesh.async_set_scheduled_reboot_interval(interval=ScheduledRebootInterval(interval.title()))

    await _with_mesh(ctx, _mesh_scheduled_reboot)


@cli.group(name="node")
@click.help_option()
async def node_group() -> None:
    """Work with nodes on the Mesh."""


@node_group.command(cls=StandardCommand, name="attribute")
@click.argument("node_name")
@click.argument("attribute", type=click.Choice(tuple(get_properties(NodeEntity)), case_sensitive=False))
@click.pass_context
async def node_attr(
    ctx: click.Context,
    /,
    node_name: str,
    attribute: str,
    **_: Any,
) -> None:
    """Retrieve details about a specific mesh attribute."""

    async def _node_attr(mesh: Mesh) -> None:
        nodes: tuple[NodeEntity, ...] = mesh.nodes
        if not nodes:
            click.echo("No nodes found")
        else:
            found_node = next((node for node in nodes if node.name.value == node_name), None)
            if found_node is None:
                _write_error(f"Node not found ({node_name})")
            else:
                attr: Any = getattr(found_node, attribute, None)
                _display_attribute(attribute, attr)

    await _with_mesh(ctx, _node_attr)


@node_group.command(cls=StandardCommand, name="details")
@click.argument("node_name")
@click.option("--outfile", default=None, required=False)
@click.pass_context
async def node_details(
    ctx: click.Context,
    /,
    node_name: str,
    outfile: str | None = None,
    **_: Any,
) -> None:
    """Get details about a node on the Mesh."""

    async def _node_details(mesh: Mesh) -> None:
        nodes: tuple[NodeEntity, ...] = mesh.nodes
        if not nodes:
            click.echo("No nodes found")
        else:
            found_node = next((node for node in nodes if node.name.value == node_name), None)
            if found_node is None:
                click.echo("Node not found")
            else:
                _output(outfile, f"# Node: {node_name}\n")
                data: dict[str, Any] = {
                    "Queried at": (
                        dt.datetime.fromtimestamp(found_node.results_time).replace(tzinfo=dt.UTC)
                        if found_node.results_time
                        else None
                    ),
                    "Device ID": found_node.unique_id.value,
                    "Online": found_node.status.value,
                    "Uptime": found_node.uptime.value,
                    "Last reboot": found_node.last_reboot,
                    "Node type": found_node.type.value.title(),
                    "Manufacturer": found_node.manufacturer.value,
                    "Model": found_node.model.value,
                    "Hardware version": found_node.hardware_version.value,
                    "Serial #": found_node.serial.value,
                    "Icon type": found_node.ui_type.value,
                }
                _display(
                    outfile,
                    pd.DataFrame.from_dict(data, orient="index", columns=[""]),
                    index=True,
                )
                data: dict[str, Any] = {
                    "Last Checked": found_node.last_update_check.value,
                }
                _display(
                    outfile,
                    pd.DataFrame.from_dict(data, orient="index", columns=[""]),
                    index=True,
                    title="Firmware details",
                )
                _display(
                    outfile,
                    pd.DataFrame([found_node.firmware.value]),
                )
                _display(
                    outfile,
                    pd.DataFrame(
                        found_node.adapter_info.value,
                        index=list(range(len(found_node.adapter_info))),
                    ),
                    title="Connections",
                )
                if found_node.type.value == NodeType.SECONDARY:
                    data: dict[str, Any] = {
                        "parent": f"{found_node.parent_name} ({found_node.parent_ip})",
                        **cast(BackhaulInfo, found_node.backhaul.value).to_dict(),
                    }
                    _display(
                        outfile,
                        pd.DataFrame.from_dict(data, orient="index", columns=[""]),
                        index=True,
                        title="Backhaul",
                    )
                _display(
                    outfile,
                    pd.DataFrame(
                        [d.name.value for d in found_node.connected_devices],
                        columns=["device"],
                        index=pd.RangeIndex(
                            start=1,
                            stop=(len(found_node.connected_devices) + 1),
                        ),
                    ),
                    index=True,
                    title="Connected Devices",
                )

    await _with_mesh(ctx, _node_details)


@node_group.command(cls=StandardCommand, name="execute")
@click.argument("node_name")
@click.argument(
    "action",
    type=click.Choice(
        list(map(str.lower, (a.key for a in Actions.values() if a.scope == ActionScope.NODE))), case_sensitive=False
    ),
)
@click.pass_context
async def node_execute(
    ctx: click.Context,
    /,
    node_name: str,
    action: str,
    **_: Any,
) -> None:
    """Execute the given action against the node."""

    async def _node_execute(mesh: Mesh):
        nodes: tuple[NodeEntity, ...] = mesh.nodes
        if not nodes:
            click.echo("No nodes found")
        else:
            found_node: NodeEntity | None = next((node for node in nodes if node.name.value == node_name), None)
            if found_node is None:
                click.echo("Node not found")
            else:
                resp: dict[str, Any] = await found_node.async_execute_action(cast(ActionKey, action.upper()))
                _output(None, json.dumps(resp))

    await _with_mesh(ctx, _node_execute)


@node_group.command(cls=StandardCommand, name="restart")
@click.argument("node_name")
@click.option("--force/--no-force", default=False)
@click.pass_context
async def node_restart(
    ctx: click.Context,
    /,
    node_name: str,
    force: bool,
    **_: Any,
) -> None:
    """Restart a node on the Mesh."""

    async def _node_restart(mesh: Mesh):
        nodes = mesh.nodes
        if not nodes:
            click.echo("No nodes found")
        else:
            found_node = next((node for node in nodes if node.name.value == node_name), None)
            if found_node is None:
                click.echo("Node not found")
            else:
                await found_node.async_reboot(force=force, wait=True)

    await _with_mesh(ctx, _node_restart)


@cli.group(name="parental_schedules")
@click.help_option()
async def parental_schedule_group() -> None:
    """Parental schedule conversions."""


@parental_schedule_group.command(name="all_blocked")
async def ps_all_blocked() -> None:
    """Display the all unblocked binary code."""

    ret = ParentalControl.ALL_PAUSED_SCHEDULE()
    _display(
        None,
        pd.DataFrame.from_dict(ret, orient="index", columns=["binary_string"]),
        index=True,
        title="All Blocked",
    )


@parental_schedule_group.command(name="all_unblocked")
async def ps_all_unblocked() -> None:
    """Display the all unblocked binary code."""

    ret = ParentalControl.ALL_ALLOWED_SCHEDULE()
    _display(
        None,
        pd.DataFrame.from_dict(ret, orient="index", columns=["binary_string"]),
        index=True,
        title="All Unblocked",
    )


@parental_schedule_group.command(name="decode")
@click.option("--sunday")
@click.option("--monday")
@click.option("--tuesday")
@click.option("--wednesday")
@click.option("--thursday")
@click.option("--friday")
@click.option("--saturday")
async def ps_decode(
    sunday: str,
    monday: str,
    tuesday: str,
    wednesday: str,
    thursday: str,
    friday: str,
    saturday: str,
) -> None:
    """Decode the given binary schedule forms to a human readable form."""

    ret: dict[str, Any] = {}
    dict_to_encode: dict[str, Any] = {
        day.name.lower(): (locals().get(day.name.lower()) if locals().get(day.name.lower()) else None)
        for day in Weekdays
    }
    decoded: str | dict[str, Any] = ParentalControl.binary_to_human_readable(dict_to_encode)
    if isinstance(decoded, dict):
        num_columns: int = -1
        for day in Weekdays:
            if locals().get(day.name.lower()) is not None:
                ret[day.name.lower()] = decoded.get(day.name.lower())
                if len(ret[day.name.lower()]) > num_columns:
                    num_columns = len(ret[day.name.lower()])

    _display(
        None,
        pd.DataFrame.from_dict(ret, orient="index", columns=["" for _ in range(0, num_columns)]),
        index=True,
    )


@parental_schedule_group.command(name="encode")
@click.option("--sunday")
@click.option("--monday")
@click.option("--tuesday")
@click.option("--wednesday")
@click.option("--thursday")
@click.option("--friday")
@click.option("--saturday")
async def ps_encode(
    sunday: str,
    monday: str,
    tuesday: str,
    wednesday: str,
    thursday: str,
    friday: str,
    saturday: str,
) -> None:
    """Encode the given human readable form schedules to binary form."""

    ret = {}
    dict_to_encode: dict[str, Any] = {
        day.name.lower(): (locals().get(day.name.lower()) if locals().get(day.name.lower()) else None)
        for day in Weekdays
    }
    encoded: str | dict[str, Any] = ParentalControl.human_readable_to_binary(dict_to_encode)
    if isinstance(encoded, dict):
        for day in Weekdays:
            if locals().get(day.name.lower()) is not None:
                ret[day.name.lower()] = encoded.get(day.name.lower())

    _display(
        None,
        pd.DataFrame.from_dict(ret, orient="index", columns=["binary_string"]),
        index=True,
    )


@parental_schedule_group.command(name="encode_for_backup")
@click.option("--sunday")
@click.option("--monday")
@click.option("--tuesday")
@click.option("--wednesday")
@click.option("--thursday")
@click.option("--friday")
@click.option("--saturday")
async def ps_encode_for_backup(
    sunday: str,
    monday: str,
    tuesday: str,
    wednesday: str,
    thursday: str,
    friday: str,
    saturday: str,
) -> None:
    """Encode the given schedule for backup."""

    to_backup: dict[str, Any] = {
        day.name.lower(): (locals().get(day.name.lower()) if locals().get(day.name.lower()) else None)
        for day in Weekdays
    }
    encoded: str | dict[str, Any] = ParentalControl.human_readable_to_binary(to_backup)
    if isinstance(encoded, dict):
        _output(None, ParentalControl.encode_for_backup(encoded))


async def _async_mesh_connect(ctx: click.Context | None = None) -> Mesh | None:
    """Return the Mesh object."""

    msg: str = ""
    if ctx is not None:
        supplementary_redactions: dict[str, set[str]] | None = None
        with contextlib.suppress(json.JSONDecodeError, UnicodeDecodeError):
            supplementary_redactions: dict[str, set[str]] | None = (
                json.load(ctx.params.get("redact_file", "")) if ctx.params.get("redact_file") is not None else None
            )
        mesh_object: Mesh = Mesh(
            node=ctx.params.get("primary_node", ""),
            password=ctx.params.get("password", ""),
            request_timeout=ctx.params.get("timeout", 30),
            session=ctx.obj if ctx.obj else None,
            username=ctx.params.get("username", ""),
            disable_redaction=not ctx.params.get("redact", True),
            supplementary_redactions=supplementary_redactions,
        )
        try:
            await mesh_object.async_initialise()
        except MeshConnectionError:
            msg = f"Unable to connect to {ctx.params.get('primary_node')}"
        except MeshInvalidCredentials as exc:
            msg = str(exc)
            if exc.details:
                msg += f", error details: {exc.details}"
        except MeshNodeNotPrimary:
            msg = f"{ctx.params.get('primary_node')} is not the primary node"
        except MeshTimeoutError:
            msg = f"Timed out connecting to {ctx.params.get('primary_node')}"
        except MeshException as exc:
            msg = str(exc)
        else:
            return mesh_object

        if msg != "":
            _write_error(msg)

    return None


def _display(
    dest: str | None,
    df: pd.DataFrame,
    *,
    index: bool = False,
    title: str = "",
) -> None:
    """Display the given dataframe in a readable format."""

    def df_apply(s) -> Any:
        return s.astype(str)

    if title != "":
        final_title: str = f" {title}" if not title.startswith("#") else title
        _output(
            dest,
            f"\n##{final_title}\n\n",
        )

    _output(
        dest,
        df.fillna("")
        .apply(df_apply)
        .to_markdown(
            index=index,
        ),
    )

    _output(dest, "\n")


def _display_attribute(attr_name: str, attr: Any) -> None:
    """Display the given attribute details."""

    def _sanitise_display(obj: Any) -> Any:
        """Remove "audit" and promote "value" recursively."""

        if isinstance(obj, dict):
            sanitised = {k: _sanitise_display(v) for k, v in obj.items() if k != "audit"}
            return sanitised.get("value", sanitised)

        if isinstance(obj, list):
            return [_sanitise_display(v) for v in obj]

        return obj

    _output(None, f"# `{attr_name}` Details\n\n")
    _attr_json: str = json.dumps(attr.to_dict(include_audit=True) if isinstance(attr, MeshAttribute) else attr)
    _attr_json_display = json.loads(_attr_json)

    _display_val = (
        _attr_json_display.get("value")
        if isinstance(_attr_json_display, dict) and "value" in _attr_json_display
        else _attr_json_display
    )
    _output(None, "## Value (JSON encoded)\n\n")
    _output(None, f"{json.dumps(_sanitise_display(_display_val))}\n")

    if isinstance(attr, MeshAttribute):
        _display(
            None,
            pd.DataFrame(
                [{**ae, **{"value": json.dumps(ae.get("value"))}} for ae in _attr_json_display.get("audit", [])],
            ),
            index=True,
            title="Audit History",
        )


def _output(dest: str | None, contents: str) -> None:
    """Write the contents to the specified location."""

    click_dest: str = "-" if dest is None else dest
    with click.open_file(click_dest, "at") as f:
        f.write(contents)


def _write_error(msg: Any) -> None:
    """Output error to the screen."""

    click.echo(click.style(msg, fg="red"), err=True)


async def _get_device_details(ctx: click.Context, device: tuple[str, ...]) -> tuple[DeviceEntity, ...] | None:
    """Retreive device details from the mesh."""

    async def _fetch_devices(mesh: Mesh) -> tuple[DeviceEntity, ...]:
        device_qry: tuple[str, ...] | None = None
        refresh: bool = True
        if device:
            device_qry = tuple(filter(lambda d: not d.startswith("${input:"), device))
        return await mesh.async_get_devices(device_qry, force_refresh=refresh)

    return await _with_mesh(ctx, _fetch_devices)


async def _with_mesh[T](
    ctx: click.Context | None,
    action: Callable[..., Awaitable[T]],
    *args: Any,
    **kwargs: Any,
) -> T | None:
    """Connect to the mesh and run the given action."""
    mesh_obj = await _async_mesh_connect(ctx)
    if mesh_obj is None:
        return None

    async with mesh_obj:
        return await action(mesh_obj, *args, **kwargs)


if __name__ == "__main__":
    cli()
