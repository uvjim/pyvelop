"""pyvelop CLI."""

# region #-- imports --#
from __future__ import annotations

import asyncio
import contextlib
import datetime as dt
import json
import logging
import sys
from enum import StrEnum, auto
from typing import Any, cast

import aiohttp
import asyncclick as click
import pandas as pd

from .action_registry import ActionDefinition, ActionKey, ActionScope
from .exceptions import (
    MeshConnectionError,
    MeshDeviceNotFoundResponse,
    MeshException,
    MeshInvalidCredentials,
    MeshNodeNotPrimary,
    MeshTimeoutError,
)
from .jnap import Actions, Response
from .logger import set_logging_format
from .mesh import (
    Mesh,
    NightModeState,
    ScheduledRebootInterval,
    SpeedtestExitCode,
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


class StandardCommand(click.Command):
    """Define standard options that should be used with all commands."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """Initialise."""
        super().__init__(*args, **kwargs)

        def _create_session(ctx: click.Context, param: click.Option, value: Any) -> None:
            """Create the session and store for late use."""
            if param.name == "create_session":
                if value:
                    _LOGGER.debug("Pre-creating a session")
                    ctx.obj = ctx.with_async_resource(aiohttp.ClientSession(raise_for_status=True))

        def _setup_logging(_: click.Context, param: click.Option, value: Any) -> None:
            """Handle logging."""
            if param.name == "verbose":
                if value:
                    logging.basicConfig(format=set_logging_format(include_func_name=True, include_lineno=True))
                    _LOGGER.setLevel(logging.DEBUG)
                    _LOGGER.debug("args: %s", sys.argv[1:])
                    _LOGGER.debug("Setting up logging")
                    if value > 1:
                        logging.getLogger(__package__).setLevel(logging.DEBUG)
                        logging.getLogger(f"{__package__}.jnap").setLevel(logging.WARNING)
                        logging.getLogger(f"{__package__}.jnap.verbose").setLevel(logging.WARNING)
                        logging.getLogger(f"{__package__}.mesh.verbose").setLevel(logging.WARNING)
                        if value > 2:
                            logging.getLogger(f"{__package__}.mesh.verbose").setLevel(logging.DEBUG)
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
                callback=_create_session,
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
                help="Redact sensitive information from output.",
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


MESH_ALLOWED_ACTIONS: set[str] = {
    "channel_scan_info",
    "channel_scan_start",
    "detect_capabilities",
    "guest_wifi_off",
    "guest_wifi_on",
    "homekit_off",
    "homekit_on",
    "night_mode_always",
    "night_mode_off",
    "night_mode_on",
    "parental_control_off",
    "parental_control_on",
    "speedtest_clear_results",
    "speedtest_results",
    "speedtest_status",
    "speedtest_start",
    "update_check_start",
    "upnp_off",
    "upnp_on",
    "wps_off",
    "wps_on",
}


class AllowedChecks(StrEnum):
    """Possible checks that can be carried out by diagnostics."""

    NETWORK_DETAILS = auto()


_LOGGER = logging.getLogger(f"{__package__}.cli")


def get_properties[T](cls: type[T]) -> set[str]:
    """Retrieve the properties for the given class."""

    _props: set[str] = set()

    for b in cls.mro():
        for name, val in b.__dict__.items():
            if isinstance(val, property):
                _props.add(name)

    return _props


@click.group()
@click.version_option(package_name=__package__)
def cli() -> None:
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

    devices: list[DeviceEntity] | None = await _get_device_details(ctx=ctx, device=(device,))
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
            try:
                await found_device.async_delete()
            except Exception as exc:
                _write_error(exc)


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
            try:
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
                if num_blocked_sites := len(found_device.parental_control_schedule.value.get("blocked_sites", [])) > 0:
                    _display(
                        outfile,
                        pd.DataFrame(
                            found_device.parental_control_schedule.get("blocked_sites"),
                            columns=["site"],
                        ),
                        title="Parental Control",
                    )
                if num_blocked_sites == 0 and (
                    schedule := found_device.parental_control_schedule.get("blocked_internet_access", {})
                ):
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
            except Exception as exc:
                _write_error(exc)


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
            try:
                await found_device.async_rename(new_name)
            except Exception as exc:
                _write_error(exc)


@device_group.command(cls=StandardCommand, name="set_icon")
@click.pass_context
@click.argument("device_id")
@click.argument("icon")
async def device_set_icon(ctx: click.Context, /, device_id: str, icon: str, **_: Any) -> None:
    """Set the icon for the given device."""

    try:
        dev_id = (device_id,)
        devices = await _get_device_details(ctx, dev_id)
        if devices is not None:
            for found_device in devices:
                try:
                    await found_device.async_set_icon(icon.lower())
                except Exception as exc:
                    _write_error(exc)
    except Exception as exc:
        _LOGGER.error(exc)
        _write_error(exc)


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

    try:
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
    except Exception as exc:
        _write_error(exc)


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
            try:
                await found_device.async_set_parental_control_urls(
                    list(urls),
                    force_enable=True,
                    merge=merge,
                )
            except Exception as exc:
                _write_error(exc)


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

    # data: dict[str, Any] = {}
    try:
        if (mesh_obj := await _async_mesh_connect(ctx)) is not None:
            async with mesh_obj:
                await mesh_obj.async_initialise()
                await mesh_obj.async_gather_details()

                devices: list[DeviceEntity] = mesh_obj.devices

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

    except Exception as exc:
        _write_error(exc)


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
        possible_capabilities: list[ActionDefinition] = [a for a in Actions.values() if a.is_capability]
        output.update({capability.key: list(capability.redactions) for capability in possible_capabilities})

    with open(path, "w") as fp:
        fp.write(json.dumps(output, indent=4))
    click.echo(path)


@cli.group(name="mesh")
@click.help_option()
async def mesh_group() -> None:
    """Work with the mesh."""


@mesh_group.command(cls=StandardCommand, name="action")
@click.argument("action", type=click.Choice(tuple(MESH_ALLOWED_ACTIONS), case_sensitive=False))
@click.pass_context
async def mesh_action(
    ctx: click.Context,
    /,
    action: str,
    **_: Any,
) -> None:
    """Carry out a specified action on the mesh."""

    ret: Any = None
    try:
        if (mesh_obj := await _async_mesh_connect(ctx)) is not None:
            async with mesh_obj:
                if action == "channel_scan_info":
                    ret = await mesh_obj.async_get_channel_scan_info()
                elif action == "channel_scan_start":
                    await mesh_obj.async_start_channel_scan()
                elif action == "detect_capabilities":
                    ret = await mesh_obj.async_detect_capabilities()
                elif action == "guest_wifi_off":
                    await mesh_obj.async_set_guest_wifi_state(state=False)
                elif action == "guest_wifi_on":
                    await mesh_obj.async_set_guest_wifi_state(state=True)
                elif action == "homekit_off":
                    await mesh_obj.async_set_homekit_state(state=False)
                elif action == "homekit_on":
                    await mesh_obj.async_set_homekit_state(state=True)
                elif action == "night_mode_always":
                    await mesh_obj.async_set_night_mode_state(NightModeState.ALWAYS)
                elif action == "night_mode_off":
                    await mesh_obj.async_set_night_mode_state(NightModeState.OFF)
                elif action == "night_mode_on":
                    await mesh_obj.async_set_night_mode_state(NightModeState.NIGHT_MODE)
                elif action == "parental_control_off":
                    await mesh_obj.async_set_parental_control_state(state=False)
                elif action == "parental_control_on":
                    await mesh_obj.async_set_parental_control_state(state=True)
                elif action == "speedtest_clear_results":
                    await mesh_obj.async_clear_speedtest_results()
                elif action == "speedtest_results":
                    await mesh_obj.async_initialise()
                    ret = await mesh_obj.async_get_speedtest_results()
                elif action == "speedtest_status":
                    await mesh_obj.async_initialise()
                    ret = await mesh_obj.async_get_speedtest_state()
                elif action == "speedtest_start":
                    await mesh_obj.async_initialise()
                    await mesh_obj.async_start_speedtest()
                    res: SpeedtestResult = await mesh_obj.async_get_speedtest_state()
                    click.echo(f"{dt.datetime.now()} state, {res.friendly_status}")
                    prev_res: SpeedtestResult = res
                    while res.exit_code == SpeedtestExitCode.UNAVAILABLE:
                        await asyncio.sleep(1)
                        res = await mesh_obj.async_get_speedtest_state()
                        if res.friendly_status != prev_res.friendly_status:
                            click.echo(f"{dt.datetime.now()} state, {res.friendly_status}")
                            prev_res = res
                    ret = await mesh_obj.async_get_speedtest_results(only_latest=True, only_completed=True)
                    ret = ret[0].as_dict()
                    ret["timestamp"] = str(ret["timestamp"])
                elif action == "update_check_start":
                    await mesh_obj.async_check_for_updates()
                elif action == "upnp_off":
                    cur_settings = await mesh_obj.async_get_upnp_state()
                    new_upnp_settings_off: dict[str, bool] = {
                        "enabled": False,
                        "allow_change_settings": cur_settings.get("canUsersConfigure", False),
                        "allow_disable_internet": cur_settings.get("canUsersDisableWANAccess", False),
                    }
                    await mesh_obj.async_set_upnp_settings(**new_upnp_settings_off)
                elif action == "upnp_on":
                    cur_settings = await mesh_obj.async_get_upnp_state()
                    new_upnp_settings_on: dict[str, bool] = {
                        "enabled": True,
                        "allow_change_settings": cur_settings.get("canUsersConfigure", False),
                        "allow_disable_internet": cur_settings.get("canUsersDisableWANAccess", False),
                    }
                    await mesh_obj.async_set_upnp_settings(**new_upnp_settings_on)
                elif action == "wps_off":
                    await mesh_obj.async_set_wps_state(state=False)
                elif action == "wps_on":
                    await mesh_obj.async_set_wps_state(state=True)
    except Exception as exc:
        raise exc
        _write_error(exc)
    else:
        _output(None, json.dumps(ret))


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

    if mesh_obj := await _async_mesh_connect(ctx):
        async with mesh_obj:
            await mesh_obj.async_initialise()
            attr: Any = getattr(mesh_obj, attribute, None)
            _display_attribute(attribute, attr)


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

    if mesh_obj := await _async_mesh_connect(ctx):
        async with mesh_obj:
            try:
                await mesh_obj.async_initialise()
            except Exception as exc:
                _write_error(exc)
                return None

            try:
                data: dict[str, Any] = {}
                _output(outfile, "# Mesh Details\n")
                data = {k: dt.datetime.fromtimestamp(v).replace(tzinfo=dt.UTC) for k, v in mesh_obj.last_gather_details}
                data.update(
                    {
                        "duration": dt.timedelta(
                            seconds=(
                                mesh_obj.last_gather_details[len(mesh_obj.last_gather_details) - 1][1]
                                - mesh_obj.last_gather_details[0][1]
                            )
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
                    pd.DataFrame(mesh_obj.capabilities, columns=[""]),
                    title="Capabilities",
                )
                if Actions.GET_LED_NIGHT_MODE.key in mesh_obj.capabilities:
                    data = {"Night mode": str(mesh_obj.night_mode)}
                    _display(
                        outfile,
                        pd.DataFrame.from_dict(data, orient="index", columns=[""]),
                        index=True,
                        title="Night mode",
                    )
                if Actions.GET_SCHEDULED_REBOOT_SETTINGS.key in mesh_obj.capabilities:
                    data = {
                        "Enabled": mesh_obj.scheduled_reboot_enabled.value,
                        "Interval": (
                            str(mesh_obj.scheduled_reboot_interval) if mesh_obj.scheduled_reboot_interval else None
                        ),
                    }
                    _display(
                        outfile,
                        pd.DataFrame.from_dict(data, orient="index", columns=[""]),
                        index=True,
                        title="Scheduled Reboot Settings",
                    )
                if Actions.GET_WAN_INFO.key in mesh_obj.capabilities:
                    data = {
                        "Internet connected": mesh_obj.wan_status.value,
                        "Bridge mode": mesh_obj.is_in_bridge_mode.value,
                        "Public IP": mesh_obj.wan_ip.value,
                        "WAN MAC": mesh_obj.wan_mac.value,
                    }
                    _display(
                        outfile,
                        pd.DataFrame.from_dict(data, orient="index", columns=[""]),
                        index=True,
                        title="WAN Info",
                    )
                if Actions.GET_LAN_SETTINGS.key in mesh_obj.capabilities:
                    data = {
                        "DHCP enabled": mesh_obj.dhcp_enabled.value,
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
                            mesh_obj.dhcp_reservations.value,
                            index=pd.RangeIndex(start=1, stop=(len(mesh_obj.dhcp_reservations) + 1)),
                        ),
                        index=True,
                        title="DHCP Reservations",
                    )
                if Actions.GET_TOPOLOGY_OPTIMISATION_SETTINGS.key in mesh_obj.capabilities:
                    data = {
                        "Client steering enabled": mesh_obj.client_steering_enabled.value,
                        "Node steering enabled": mesh_obj.node_steering_enabled.value,
                    }
                    _display(
                        outfile,
                        pd.DataFrame.from_dict(data, orient="index", columns=[""]),
                        index=True,
                        title="Topology Optimisation Settings",
                    )
                if Actions.GET_MLO_SETTINGS.key in mesh_obj.capabilities:
                    data = {
                        "Enabled": (mesh_obj.mlo_state.value if mesh_obj.mlo_state.value is not None else "Unsupported")
                    }
                    _display(
                        outfile,
                        pd.DataFrame.from_dict(data, orient="index", columns=[""]),
                        index=True,
                        title="Multi-Link Operation (MLO)",
                    )
                if Actions.GET_EXPRESS_FORWARDING.key in mesh_obj.capabilities:
                    data = {
                        "Supported": mesh_obj.express_forwarding_supported.value,
                        "Enabled": mesh_obj.express_forwarding_enabled.value,
                    }
                    _display(
                        outfile,
                        pd.DataFrame.from_dict(data, orient="index", columns=[""]),
                        index=True,
                        title="Express Forwarding",
                    )
                if Actions.GET_PARENTAL_CONTROL_INFO.key in mesh_obj.capabilities:
                    data = {
                        "Enabled": mesh_obj.parental_control_enabled.value,
                    }
                    _display(
                        outfile,
                        pd.DataFrame.from_dict(data, orient="index", columns=[""]),
                        index=True,
                        title="Parental Control",
                    )
                if Actions.GET_MAC_FILTERING_SETTINGS.key in mesh_obj.capabilities:
                    data = {
                        "Enabled": mesh_obj.mac_filtering_enabled.value,
                        "Mode": str(mesh_obj.mac_filtering_mode),
                        "Filters": (
                            mesh_obj.mac_filtering_addresses.value
                            if len(mesh_obj.mac_filtering_addresses) > 0
                            else None
                        ),
                    }
                    _display(
                        outfile,
                        pd.DataFrame.from_dict(data, orient="index", columns=[""]),
                        index=True,
                        title="MAC Filtering",
                    )
                if Actions.GET_WPS_SERVER_SETTINGS.key in mesh_obj.capabilities:
                    data = {
                        "Enabled": mesh_obj.wps_state.value,
                    }
                    _display(
                        outfile,
                        pd.DataFrame.from_dict(data, orient="index", columns=[""]),
                        index=True,
                        title="WPS Settings",
                    )
                if Actions.GET_ALG_SETTINGS.key in mesh_obj.capabilities:
                    data = {
                        "Enabled": mesh_obj.sip_enabled.value,
                    }
                    _display(
                        outfile,
                        pd.DataFrame.from_dict(data, orient="index", columns=[""]),
                        index=True,
                        title="SIP Settings",
                    )
                if Actions.GET_HOMEKIT_SETTINGS.key in mesh_obj.capabilities:
                    data = {
                        "Enabled": mesh_obj.homekit_enabled.value,
                        "Paired": mesh_obj.homekit_paired.value,
                    }
                    _display(
                        outfile,
                        pd.DataFrame.from_dict(data, orient="index", columns=[""]),
                        index=True,
                        title="HomeKit Settings",
                    )
                if Actions.GET_UPNP_SETTINGS.key in mesh_obj.capabilities:
                    data = {
                        "Enabled": mesh_obj.upnp_enabled.value,
                        "allow_change_settings": mesh_obj.upnp_allow_change_settings.value,
                        "allow_disable_internet": mesh_obj.upnp_allow_disable_internet.value,
                    }
                    _display(
                        outfile,
                        pd.DataFrame.from_dict(data, orient="index", columns=[""]),
                        index=True,
                        title="UPnP Settings",
                    )
                if Actions.GET_DEVICES.key in mesh_obj.capabilities:
                    data_list: list[str | dict[str, Any]] = [n.name.value for n in mesh_obj.nodes]
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
                if Actions.GET_SPEEDTEST_RESULTS.key in mesh_obj.capabilities:
                    _display(
                        outfile,
                        pd.DataFrame(
                            mesh_obj.speedtest_results.value,
                            index=pd.RangeIndex(start=1, stop=len(mesh_obj.speedtest_results) + 1),
                        ),
                        index=True,
                        title="Speedtest Results",
                    )
                if Actions.GET_GUEST_NETWORK_INFO.key in mesh_obj.capabilities:
                    data = {
                        "Enabled": mesh_obj.guest_wifi_enabled.value,
                    }
                    _display(
                        outfile,
                        pd.DataFrame.from_dict(data, orient="index", columns=[""]),
                        index=True,
                        title="Guest Network Settings",
                    )
                    _display(
                        outfile,
                        pd.DataFrame.from_dict(cast(dict[str, Any], mesh_obj.guest_wifi_details.value)),
                        title="# Networks",
                    )
                if Actions.GET_STORAGE_PARTITIONS.key in mesh_obj.capabilities:
                    _display(
                        outfile,
                        pd.DataFrame(mesh_obj.storage_available.value),
                        title="File Shares",
                    )
                if Actions.GET_DEVICES.key in mesh_obj.capabilities:
                    data_list = [
                        {"name": d.name.value, "ip": d.adapter_info.value[0].ip if d.adapter_info else None}
                        for d in mesh_obj.devices
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
                    data_list = [d.name.value for d in mesh_obj.devices if not d.status.value]
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
            except Exception as exc:
                _write_error(exc)


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

    try:
        if (mesh_obj := await _async_mesh_connect(ctx)) is not None:
            async with mesh_obj:
                if interval is None:
                    _LOGGER.debug("disabling scheduled reboots")
                    await mesh_obj.async_set_scheduled_reboot_state(state=False)
                else:
                    _LOGGER.debug("setting scheduled reboot interval to %s", interval.title())
                    await mesh_obj.async_set_scheduled_reboot_interval(
                        interval=ScheduledRebootInterval(interval.title())
                    )
    except Exception as exc:
        _write_error(exc)


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

    if mesh_obj := await _async_mesh_connect(ctx):
        async with mesh_obj:
            await mesh_obj.async_initialise()
            nodes: tuple[NodeEntity, ...] = mesh_obj.nodes
            if not nodes:
                click.echo("No nodes found")
            else:
                found_node = next((node for node in nodes if node.name.value == node_name), None)
                attr: Any = getattr(found_node, attribute, None)
                _display_attribute(attribute, attr)


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
    if mesh_obj := await _async_mesh_connect(ctx):
        async with mesh_obj:
            await mesh_obj.async_initialise()
            nodes: tuple[NodeEntity, ...] = mesh_obj.nodes
            if not nodes:
                click.echo("No nodes found")
            else:
                found_node = next((node for node in nodes if node.name.value == node_name), None)
                if found_node is None:
                    click.echo("Node not found")
                else:
                    try:
                        _output(outfile, f"# Node: {node_name}\n")
                        data: dict[str, Any] = {
                            "Queried at": (
                                dt.datetime.fromtimestamp(found_node.results_time).replace(tzinfo=dt.UTC)
                                if found_node.results_time
                                else None
                            ),
                            "Device ID": found_node.unique_id.value,
                            "Online": found_node.status.value,
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
                    except Exception as exc:
                        _write_error(exc)


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

    if mesh_obj := await _async_mesh_connect(ctx):
        async with mesh_obj:
            await mesh_obj.async_initialise()
            nodes: list[NodeEntity] = mesh_obj.nodes
            if not nodes:
                click.echo("No nodes found")
            else:
                found_node: NodeEntity | None = next((node for node in nodes if node.name == node_name), None)
                if found_node is None:
                    click.echo("Node not found")
                else:
                    try:
                        resp: Response = await found_node.async_execute_action(cast(ActionKey, action))
                        _output(None, json.dumps(resp.data))
                    except Exception as exc:
                        _write_error(exc)


@node_group.command(cls=StandardCommand, name="restart")
@click.argument("node_name")
@click.pass_context
async def node_restart(
    ctx: click.Context,
    /,
    node_name: str,
    **_: Any,
) -> None:
    """Restart a node on the Mesh."""

    if mesh_obj := await _async_mesh_connect(ctx):
        async with mesh_obj:
            await mesh_obj.async_initialise()
            nodes = mesh_obj.nodes
            if not nodes:
                click.echo("No nodes found")
            else:
                found_node = next((node for node in nodes if node.name == node_name), None)
                if found_node is None:
                    click.echo("Node not found")
                else:
                    try:
                        await found_node.async_reboot()
                    except Exception as exc:
                        _write_error(exc)


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
            session=await ctx.obj if ctx.obj else None,
            username=ctx.params.get("username", ""),
            disable_redaction=not ctx.params.get("redact", True),
            supplementary_redactions=supplementary_redactions,
        )
        try:
            async with mesh_object:
                if not await mesh_object.async_test_credentials():
                    raise MeshInvalidCredentials
        except MeshConnectionError:
            msg = f"Unable to connect to {ctx.params.get('primary_node')}"
        except MeshInvalidCredentials:
            msg = f"Unable to authenticate with {ctx.params.get('primary_node')} using provided credentials"
        except MeshNodeNotPrimary:
            msg = f"{ctx.params.get('primary_node')} is not the primary node"
        except MeshTimeoutError:
            msg = f"Timed out connecting to {ctx.params.get('primary_node')}"
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

    data: list[dict[str, Any]] = []

    def _json_default(obj: Any):
        """Handle known serialisation errors."""

        if hasattr(obj, "to_dict") and callable(getattr(obj, "to_dict")):
            return obj.to_dict(include_audit=False)

        return repr(obj)

    _output(None, f"# `{attr_name}` Details\n\n")
    attr_json: str = json.dumps(attr, default=_json_default)
    attr_json_display = json.loads(attr_json)
    _output(None, "## Value (JSON encoded)\n\n")
    _output(
        None, f"{json.dumps(attr_json_display.get("value") if "value" in attr_json_display else attr_json_display)}\n"
    )

    if isinstance(attr, MeshAttribute):
        data.clear()
        for audit_entry in attr.audit:
            data.append(audit_entry.to_dict())

        _display(
            None,
            pd.DataFrame(
                data,
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


async def _get_device_details(ctx: click.Context, device: tuple[str, ...]) -> list[DeviceEntity] | None:
    """Retreive device details from the mesh."""

    ret = None
    if mesh_obj := await _async_mesh_connect(ctx):
        async with mesh_obj:
            await mesh_obj.async_initialise()
            try:
                device_qry: tuple[str, ...] | None = None
                refresh: bool = True
                if device:
                    device_qry = tuple(filter(lambda d: not d.startswith("${input:"), device))
                ret = await mesh_obj.async_get_devices(device_qry, force_refresh=refresh)
            except MeshDeviceNotFoundResponse as exc:
                _write_error(f"{exc}: {exc.devices}")
                return None
            except Exception as exc:
                _write_error(exc)
                return None

    return ret


if __name__ == "__main__":
    cli()
