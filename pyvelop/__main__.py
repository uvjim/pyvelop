"""pyvelop CLI."""

# region #-- imports --#
from __future__ import annotations

import contextlib
import json
import logging
from datetime import datetime
from typing import Any, cast

import aiohttp
import asyncclick as click
import pandas as pd

from .const import MeshCapability, ScheduledRebootInterval, Weekdays
from .exceptions import (
    MeshConnectionError,
    MeshDeviceNotFoundResponse,
    MeshException,
    MeshInvalidCredentials,
    MeshNodeNotPrimary,
    MeshTimeoutError,
)
from .logger import set_logging_format
from .mesh import Mesh
from .mesh_entity import DeviceEntity, ParentalControl

# endregion


class StandardCommand(click.Command):
    """Define standard options that should be used with all commands."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """Initialise."""
        super().__init__(*args, **kwargs)

        def _create_session(
            ctx: click.Context, param: click.Option, value: Any
        ) -> None:
            """Create the session and store for late use."""
            if param.name == "create_session":
                if value:
                    _LOGGER.debug("Pre-creating a session")
                    ctx.obj = ctx.with_async_resource(
                        aiohttp.ClientSession(raise_for_status=True)
                    )

        def _setup_logging(_: click.Context, param: click.Option, value: Any) -> None:
            """Handle logging."""
            if param.name == "verbose":
                if value:
                    logging.basicConfig(
                        format=set_logging_format(
                            include_func_name=True, include_lineno=True
                        )
                    )
                    _LOGGER.setLevel(logging.DEBUG)
                    _LOGGER.debug("Setting up logging")
                    if value > 1:
                        logging.getLogger(__package__).setLevel(logging.DEBUG)
                        logging.getLogger(f"{__package__}.jnap").setLevel(
                            logging.WARNING
                        )
                        logging.getLogger(f"{__package__}.jnap.verbose").setLevel(
                            logging.WARNING
                        )
                        logging.getLogger(f"{__package__}.mesh.verbose").setLevel(
                            logging.WARNING
                        )
                        if value > 2:
                            logging.getLogger(f"{__package__}.mesh.verbose").setLevel(
                                logging.DEBUG
                            )
                            if value > 3:
                                logging.getLogger(f"{__package__}.jnap").setLevel(
                                    logging.DEBUG
                                )
                                if value > 4:
                                    logging.getLogger(
                                        f"{__package__}.jnap.verbose"
                                    ).setLevel(logging.DEBUG)

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
                default=False,
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
                help="Set the verbosity of logging.",
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
    "parental_control_off",
    "parental_control_on",
    "speedtest_results",
    "speedtest_start",
    "speedtest_state",
    "update_check_start",
    "upnp_off",
    "upnp_on",
    "wps_off",
    "wps_on",
}
DEF_INDENT: int = 2

_LOGGER = logging.getLogger(f"{__package__}.cli")


@click.group()
@click.version_option(package_name=__package__)
def cli() -> None:
    """CLI for interacting with the pyvelop module."""


@cli.group(name="device")
@click.help_option()
async def device_group() -> None:
    """Work with devices on the mesh."""


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
                    "Queried at": found_device.results_time,
                    "Device ID": found_device.unique_id,
                    "Online": found_device.status,
                    "Parent": found_device.parent_name,
                    "Manufacturer": found_device.manufacturer,
                    "Model": found_device.model,
                    "Description": found_device.description,
                    "Operating system": found_device.operating_system,
                    "Serial #": found_device.serial,
                    "Icon type": found_device.ui_type,
                }
                _display(
                    outfile,
                    pd.DataFrame.from_dict(data, orient="index", columns=[""]),
                    index=True,
                    title=found_device.name,
                )
                _display(
                    outfile,
                    pd.DataFrame(found_device.adapter_info),
                    title="# Connections",
                )
                if (
                    num_blocked_sites := len(
                        found_device.parental_control_schedule.get("blocked_sites", [])
                    )
                    > 0
                ):
                    _display(
                        outfile,
                        pd.DataFrame(
                            found_device.parental_control_schedule.get("blocked_sites"),
                            columns=["site"],
                        ),
                        title="Parental Control",
                    )
                if num_blocked_sites == 0 and (
                    schedule := found_device.parental_control_schedule.get(
                        "blocked_internet_access", {}
                    )
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
                            ParentalControl.ALL_PAUSED_SCHEDULE().get(
                                weekday.name.lower(), ""
                            )
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
async def device_rename(
    ctx: click.Context, /, device_id: str, new_name: str, **_: Any
) -> None:
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
async def device_set_icon(
    ctx: click.Context, /, device_id: str, icon: str, **_: Any
) -> None:
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
            day.name.lower(): (
                locals().get(day.name.lower())
                if locals().get(day.name.lower())
                else None
            )
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


@cli.group(name="mesh")
@click.help_option()
async def mesh_group() -> None:
    """Work with the mesh."""


@mesh_group.command(cls=StandardCommand, name="action")
@click.argument(
    "action", type=click.Choice(tuple(MESH_ALLOWED_ACTIONS), case_sensitive=False)
)
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
                elif action == "parental_control_off":
                    await mesh_obj.async_set_parental_control_state(state=False)
                elif action == "parental_control_on":
                    await mesh_obj.async_set_parental_control_state(state=True)
                elif action == "speedtest_results":
                    ret = await mesh_obj.async_get_speedtest_results()
                elif action == "speedtest_start":
                    await mesh_obj.async_start_speedtest()
                elif action == "speedtest_state":
                    ret = await mesh_obj.async_get_speedtest_state()
                elif action == "update_check_start":
                    await mesh_obj.async_check_for_updates()
                elif action == "upnp_off":
                    cur_settings = await mesh_obj.async_get_upnp_state()
                    new_upnp_settings_off: dict[str, bool] = {
                        "enabled": False,
                        "allow_change_settings": cur_settings.get(
                            "canUsersConfigure", False
                        ),
                        "allow_disable_internet": cur_settings.get(
                            "canUsersDisableWANAccess", False
                        ),
                    }
                    await mesh_obj.async_set_upnp_settings(**new_upnp_settings_off)
                elif action == "upnp_on":
                    cur_settings = await mesh_obj.async_get_upnp_state()
                    new_upnp_settings_on: dict[str, bool] = {
                        "enabled": True,
                        "allow_change_settings": cur_settings.get(
                            "canUsersConfigure", False
                        ),
                        "allow_disable_internet": cur_settings.get(
                            "canUsersDisableWANAccess", False
                        ),
                    }
                    await mesh_obj.async_set_upnp_settings(**new_upnp_settings_on)
                elif action == "wps_off":
                    await mesh_obj.async_set_wps_state(state=False)
                elif action == "wps_on":
                    await mesh_obj.async_set_wps_state(state=True)
    except Exception as exc:
        _write_error(exc)
    else:
        _output(None, json.dumps(ret))


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
                data = {
                    "Gather started": (
                        datetime.fromtimestamp(float(val if val is not None else 0))
                        if (val := mesh_obj.last_gather_details.get("gather_start", 0))
                        != 0
                        else "unknown"
                    ),
                    "Gather finished": (
                        datetime.fromtimestamp(float(val if val is not None else 0))
                        if (val := mesh_obj.last_gather_details.get("gather_end", 0))
                        != 0
                        else "unknown"
                    ),
                    "Processing started": (
                        datetime.fromtimestamp(float(val if val is not None else 0))
                        if (val := mesh_obj.last_gather_details.get("process_start", 0))
                        != 0
                        else "unknown"
                    ),
                    "Processing finished": (
                        datetime.fromtimestamp(float(val if val is not None else 0))
                        if (val := mesh_obj.last_gather_details.get("process_end", 0))
                        != 0
                        else "unknown"
                    ),
                }
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
                if (
                    MeshCapability.GET_SCHEDULED_REBOOT_SETTINGS
                    in mesh_obj.capabilities
                ):
                    data = {
                        "Enabled": mesh_obj.scheduled_reboot_enabled,
                        "Interval": (
                            mesh_obj.scheduled_reboot_interval.value
                            if mesh_obj.scheduled_reboot_interval is not None
                            else None
                        ),
                    }
                    _display(
                        outfile,
                        pd.DataFrame.from_dict(data, orient="index", columns=[""]),
                        index=True,
                        title="Scheduled Reboot Settings",
                    )
                if MeshCapability.GET_WAN_INFO in mesh_obj.capabilities:
                    data: dict[str, Any] = {
                        "Internet connected": mesh_obj.wan_status,
                        "Public IP": mesh_obj.wan_ip,
                        "WAN MAC": mesh_obj.wan_mac,
                    }
                    _display(
                        outfile,
                        pd.DataFrame.from_dict(data, orient="index", columns=[""]),
                        index=True,
                        title="WAN Info",
                    )
                if MeshCapability.GET_LAN_SETTINGS in mesh_obj.capabilities:
                    data: dict[str, Any] = {
                        "DHCP enabled": mesh_obj.dhcp_enabled,
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
                            mesh_obj.dhcp_reservations,
                            index=pd.RangeIndex(
                                start=1, stop=(len(mesh_obj.dhcp_reservations) + 1)
                            ),
                        ),
                        index=True,
                        title="DHCP Reservations",
                    )
                if (
                    MeshCapability.GET_TOPOLOGY_OPTIMISATION_SETTINGS
                    in mesh_obj.capabilities
                ):
                    data: dict[str, Any] = {
                        "Client steering enabled": mesh_obj.client_steering_enabled,
                        "Node steering enabled": mesh_obj.node_steering_enabled,
                    }
                    _display(
                        outfile,
                        pd.DataFrame.from_dict(data, orient="index", columns=[""]),
                        index=True,
                        title="Topology Optimisation Settings",
                    )
                if MeshCapability.GET_EXPRESS_FORWARDING in mesh_obj.capabilities:
                    data: dict[str, Any] = {
                        "Supported": mesh_obj.express_forwarding_supported,
                        "Enabled": mesh_obj.express_forwarding_enabled,
                    }
                    _display(
                        outfile,
                        pd.DataFrame.from_dict(data, orient="index", columns=[""]),
                        index=True,
                        title="Express Forwarding",
                    )
                if MeshCapability.GET_PARENTAL_CONTROL_INFO in mesh_obj.capabilities:
                    data: dict[str, Any] = {
                        "Enabled": mesh_obj.parental_control_enabled,
                    }
                    _display(
                        outfile,
                        pd.DataFrame.from_dict(data, orient="index", columns=[""]),
                        index=True,
                        title="Parental Control",
                    )
                if MeshCapability.GET_MAC_FILTERING_SETTINGS in mesh_obj.capabilities:
                    data: dict[str, Any] = {
                        "Enabled": mesh_obj.mac_filtering_enabled,
                        "Mode": mesh_obj.mac_filtering_mode,
                        "Filters": (
                            mesh_obj.mac_filtering_addresses
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
                if MeshCapability.GET_WPS_SERVER_SETTINGS in mesh_obj.capabilities:
                    data: dict[str, Any] = {
                        "Enabled": mesh_obj.wps_state,
                    }
                    _display(
                        outfile,
                        pd.DataFrame.from_dict(data, orient="index", columns=[""]),
                        index=True,
                        title="WPS Settings",
                    )
                if MeshCapability.GET_ALG_SETTINGS in mesh_obj.capabilities:
                    data: dict[str, Any] = {
                        "Enabled": mesh_obj.sip_enabled,
                    }
                    _display(
                        outfile,
                        pd.DataFrame.from_dict(data, orient="index", columns=[""]),
                        index=True,
                        title="SIP Settings",
                    )
                if MeshCapability.GET_HOMEKIT_SETTINGS in mesh_obj.capabilities:
                    data: dict[str, Any] = {
                        "Enabled": mesh_obj.homekit_enabled,
                        "Paired": mesh_obj.homekit_paired,
                    }
                    _display(
                        outfile,
                        pd.DataFrame.from_dict(data, orient="index", columns=[""]),
                        index=True,
                        title="HomeKit Settings",
                    )
                if MeshCapability.GET_UPNP_SETTINGS in mesh_obj.capabilities:
                    data: dict[str, Any] = {
                        "Enabled": mesh_obj.upnp_enabled,
                        "allow_change_settings": mesh_obj.upnp_allow_change_settings,
                        "allow_disable_Internet": mesh_obj.upnp_allow_disable_internet,
                    }
                    _display(
                        outfile,
                        pd.DataFrame.from_dict(data, orient="index", columns=[""]),
                        index=True,
                        title="UPnP Settings",
                    )
                if MeshCapability.GET_DEVICES in mesh_obj.capabilities:
                    data_list: list[str | dict[str, Any]] = [
                        n.name for n in mesh_obj.nodes
                    ]
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
                if MeshCapability.GET_SPEEDTEST_RESULTS in mesh_obj.capabilities:
                    _display(
                        outfile,
                        pd.DataFrame.from_dict(
                            cast(dict[str, Any], mesh_obj.latest_speedtest_result),
                            orient="index",
                            columns=[""],
                        ),
                        index=True,
                        title="Speedtest Results (Latest)",
                    )
                if MeshCapability.GET_GUEST_NETWORK_INFO in mesh_obj.capabilities:
                    data: dict[str, Any] = {
                        "Enabled": mesh_obj.guest_wifi_enabled,
                    }
                    _display(
                        outfile,
                        pd.DataFrame.from_dict(data, orient="index", columns=[""]),
                        index=True,
                        title="Guest Network Settings",
                    )
                    _display(
                        outfile,
                        pd.DataFrame.from_dict(
                            cast(dict[str, Any], mesh_obj.guest_wifi_details)
                        ),
                        title="# Networks",
                    )
                if MeshCapability.GET_STORAGE_PARTITIONS in mesh_obj.capabilities:
                    _display(
                        outfile,
                        pd.DataFrame(mesh_obj.storage_available),
                        title="File Shares",
                    )
                if MeshCapability.GET_DEVICES in mesh_obj.capabilities:
                    _LOGGER.debug(
                        [
                            {"name": d.name, "ip": d.adapter_info[0].get("ip")}
                            for d in mesh_obj.devices
                            if d.status
                        ]
                    )
                    data_list = [
                        {"name": d.name, "ip": d.adapter_info[0].get("ip")}
                        for d in mesh_obj.devices
                        if d.status
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
                    data_list = [d.name for d in mesh_obj.devices if not d.status]
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
                    _LOGGER.debug(
                        "setting scheduled reboot interval to %s", interval.title()
                    )
                    await mesh_obj.async_set_scheduled_reboot_interval(
                        interval=ScheduledRebootInterval(interval.title())
                    )
    except Exception as exc:
        _write_error(exc)


@cli.group(name="node")
@click.help_option()
async def node_group() -> None:
    """Work with nodes on the Mesh."""


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
            nodes = mesh_obj.nodes
            if not nodes:
                click.echo("No nodes found")
            else:
                found_node = next(
                    (node for node in nodes if node.name == node_name), None
                )
                if found_node is None:
                    click.echo("Node not found")
                else:
                    try:
                        _output(outfile, f"# Node: {node_name}\n")
                        data: dict[str, Any] = {
                            "Queried at": found_node.results_time,
                            "Device ID": found_node.unique_id,
                            "Online": found_node.status,
                            "Node type": found_node.type.title(),
                            "Manufacturer": found_node.manufacturer,
                            "Model": found_node.model,
                            "Hardware version": found_node.hardware_version,
                            "Serial #": found_node.serial,
                            "Icon type": found_node.ui_type,
                        }
                        _display(
                            outfile,
                            pd.DataFrame.from_dict(data, orient="index", columns=[""]),
                            index=True,
                        )
                        data: dict[str, Any] = {
                            "Last Checked": found_node.last_update_check,
                        }
                        _display(
                            outfile,
                            pd.DataFrame.from_dict(data, orient="index", columns=[""]),
                            index=True,
                            title="Firmware details",
                        )
                        _display(
                            outfile,
                            pd.DataFrame([found_node.firmware]),
                        )
                        _display(
                            outfile,
                            pd.DataFrame(
                                found_node.adapter_info,
                                index=list(range(len(found_node.adapter_info))),
                            ),
                            title="Connections",
                        )
                        if found_node.type == "secondary":
                            data: dict[str, Any] = {
                                "parent": f"{found_node.parent_name} ({found_node.parent_ip})",
                                **found_node.backhaul,
                            }
                            _display(
                                outfile,
                                pd.DataFrame.from_dict(
                                    data, orient="index", columns=[""]
                                ),
                                index=True,
                                title="Backhaul",
                            )
                        _display(
                            outfile,
                            pd.DataFrame(
                                [
                                    d.get("name", "")
                                    for d in found_node.connected_devices
                                ],
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
                found_node = next(
                    (node for node in nodes if node.name == node_name), None
                )
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
        day.name.lower(): (
            locals().get(day.name.lower()) if locals().get(day.name.lower()) else None
        )
        for day in Weekdays
    }
    decoded: str | dict[str, Any] = ParentalControl.binary_to_human_readable(
        dict_to_encode
    )
    if isinstance(decoded, dict):
        num_columns: int = -1
        for day in Weekdays:
            if locals().get(day.name.lower()) is not None:
                ret[day.name.lower()] = decoded.get(day.name.lower())
                if len(ret[day.name.lower()]) > num_columns:
                    num_columns = len(ret[day.name.lower()])

    _display(
        None,
        pd.DataFrame.from_dict(
            ret, orient="index", columns=["" for _ in range(0, num_columns)]
        ),
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
        day.name.lower(): (
            locals().get(day.name.lower()) if locals().get(day.name.lower()) else None
        )
        for day in Weekdays
    }
    encoded: str | dict[str, Any] = ParentalControl.human_readable_to_binary(
        dict_to_encode
    )
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
        day.name.lower(): (
            locals().get(day.name.lower()) if locals().get(day.name.lower()) else None
        )
        for day in Weekdays
    }
    encoded: str | dict[str, Any] = ParentalControl.human_readable_to_binary(to_backup)
    if isinstance(encoded, dict):
        _output(None, ParentalControl.encode_for_backup(encoded))


async def _async_mesh_connect(ctx: click.Context | None = None) -> Mesh | None:
    """Return the Mesh object."""

    msg: str = ""
    if ctx is not None:
        mesh_object: Mesh = Mesh(
            node=ctx.params.get("primary_node", ""),
            password=ctx.params.get("password", ""),
            request_timeout=ctx.params.get("timeout", 30),
            session=await ctx.obj if ctx.obj else None,
            username=ctx.params.get("username", ""),
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
        _output(
            dest,
            f"\n##{f" {title}" if not title.startswith("#") else title}\n\n",
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


def _output(dest: str | None, contents: str) -> None:
    """Write the contents to the specified location."""

    click_dest: str = "-" if dest is None else dest
    with click.open_file(click_dest, "at") as f:
        f.write(contents)


def _write_error(msg: Any) -> None:
    """Output error to the screen."""

    click.echo(click.style(msg, fg="red"), err=True)


async def _get_device_details(
    ctx: click.Context, device: tuple[str, ...]
) -> list[DeviceEntity] | None:
    """Retreive device details from the mesh."""

    ret = None
    if mesh_obj := await _async_mesh_connect(ctx):
        async with mesh_obj:
            await mesh_obj.async_initialise()
            try:
                device_qry: tuple[str, ...] | None = None
                refresh: bool = True
                if device:
                    device_qry = tuple(
                        filter(lambda d: not d.startswith("${input:"), device)
                    )
                ret = await mesh_obj.async_get_devices(
                    device_qry, force_refresh=refresh
                )
            except MeshDeviceNotFoundResponse as exc:
                _write_error(f"{exc}: {exc.devices}")
                return None
            except Exception as exc:
                _write_error(exc)
                return None

    return ret


if __name__ == "__main__":
    with contextlib.suppress(Exception):
        cli()
