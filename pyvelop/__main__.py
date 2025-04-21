"""pyvelop CLI."""

# region #-- imports --#
from __future__ import annotations

import contextlib
import logging
from typing import Any

import aiohttp
import asyncclick as click

from .const import Weekdays
from .exceptions import (
    MeshConnectionError,
    MeshDeviceNotFoundResponse,
    MeshException,
    MeshInvalidCredentials,
    MeshNodeNotPrimary,
    MeshTimeoutError,
)
from .mesh import Mesh, MeshCapability
from .mesh_entity import DeviceEntity, NodeEntity, ParentalControl

# endregion


class StandardCommand(click.Command):
    """Define standard options that should be used with all commands."""

    def __init__(self, *args, **kwargs) -> None:
        """Initialise."""
        super().__init__(*args, **kwargs)

        def _create_session(ctx: click.Context, param: click.Option, value) -> None:
            """Create the session and store for late use."""
            if param.name == "create_session":
                if value:
                    _LOGGER.debug("Pre-creating a session")
                    ctx.obj = ctx.with_async_resource(
                        aiohttp.ClientSession(raise_for_status=True)
                    )

        def _setup_logging(_: click.Context, param: click.Option, value) -> None:
            """Handle logging."""
            if param.name == "verbose":
                if value:
                    logging.basicConfig()
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


MESH_ALLOWED_ACTIONS: set[str] = (
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
)
DEF_INDENT: int = 2

click.anyio_backend = "aysncio"
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
    device: str,
    **_,
) -> None:
    """Delete a device on the Mesh."""

    dev = (device,)
    devices: list[DeviceEntity] | None = await _get_device_details(ctx, dev)

    if devices is not None:
        for found_device in devices:
            try:
                await found_device.async_delete()
            except Exception as exc:
                click.echo(click.style(exc, fg="red"))

    # devices: list[DeviceEntity] | None = await _get_device_details(
    #     ctx=ctx, device=device
    # )

    # if devices is not None:
    #     if mesh_obj := await _async_mesh_connect(ctx):
    #         async with mesh_obj:
    #             for found_device in devices:
    #                 try:
    #                     await mesh_obj.async_delete_device_by_id(
    #                         device=found_device.unique_id
    #                     )
    #                 except MeshException as err:
    #                     _LOGGER.error("%s (%s)", err, found_device.name)


@device_group.command(cls=StandardCommand, name="details")
@click.pass_context
@click.argument("device", nargs=-1)
async def device_details(
    ctx: click.Context,
    device: tuple[str, ...],
    **_,
) -> None:
    """Display details about a device on the Mesh."""
    devices: list[DeviceEntity] | None = await _get_device_details(
        ctx=ctx, device=device
    )

    if devices is not None:
        for found_device in devices:
            try:
                title: str = found_device.name
                click.echo(title)
                click.echo("-" * len(title))
                _display_value("Queried at", found_device.results_time)
                _display_value("Device ID", found_device.unique_id)
                _display_value("Online", found_device.status)
                _display_value("Parent", found_device.parent_name)
                _display_value("Manufacturer", found_device.manufacturer)
                _display_value("Model", found_device.model)
                _display_value("Description", found_device.description)
                _display_value("Operating system", found_device.operating_system)
                _display_value("Serial #", found_device.serial)
                _display_value("Icon type", found_device.ui_type)
                _display_value("Connections", found_device.adapter_info)
                _display_value(
                    "Parental Control",
                    {
                        "Blocked sites": found_device.parental_control_schedule.get(
                            "blocked_sites"
                        ),
                        "Schedule": [
                            f"{day.title()}\t{','.join(sched)}"
                            for day, sched in found_device.parental_control_schedule.get(
                                "blocked_internet_access", {}
                            ).items()
                        ],
                    },
                )
            except Exception as exc:
                click.echo(click.style(exc, fg="red"))


@device_group.command(cls=StandardCommand, name="internet_access")
@click.pass_context
@click.argument("device_id")
@click.option("--block/--no-block", default=False)
async def device_internet_access(
    ctx: click.Context,
    device_id: str,
    block: bool,
    **_,
) -> None:
    """Block/Unblock access to the internet."""
    if mesh_obj := await _async_mesh_connect(ctx):
        async with mesh_obj:
            await mesh_obj.async_gather_details()
            try:
                if not block:
                    rules_to_apply: dict[str, str] = {}
                else:
                    rules_to_apply: dict[str, str] = dict(
                        map(
                            lambda weekday, readable_schedule: (
                                weekday.name,
                                readable_schedule,
                            ),
                            ParentalControl.WEEKDAYS,
                            ("00:00-00:00",) * len(ParentalControl.WEEKDAYS),
                        )
                    )
                await mesh_obj.async_set_parental_control_rules(
                    device_id=device_id,
                    rules=rules_to_apply,
                )
            except MeshDeviceNotFoundResponse as err:
                _LOGGER.error("Device not found: %s", err.devices[0])
            except MeshException as err:
                _LOGGER.error(err)


@device_group.command(cls=StandardCommand, name="rename")
@click.pass_context
@click.argument("device_id")
@click.argument("new_name")
async def device_rename(ctx: click.Context, device_id: str, new_name: str, **_) -> None:
    """Rename the given device."""

    # if mesh_obj := await _async_mesh_connect(ctx):
    #     async with mesh_obj:
    #         await mesh_obj.async_rename_device(device_id=device_id, name=new_name)

    dev_id = (device_id,)
    devices: list[DeviceEntity] | None = await _get_device_details(ctx, dev_id)

    if devices is not None:
        for found_device in devices:
            try:
                await found_device.rename(new_name)
            except Exception as exc:
                click.echo(click.style(exc, fg="red"))


@device_group.command(cls=StandardCommand, name="set_icon")
@click.pass_context
@click.argument("device_id")
@click.argument("icon")
async def device_set_icon(ctx: click.Context, device_id: str, icon: str, **_) -> None:
    """Set the icon for the given device."""

    try:
        if mesh_obj := await _async_mesh_connect(ctx):
            async with mesh_obj:
                await mesh_obj.async_set_device_icon(device_id, icon.lower())
    except Exception as exc:
        _LOGGER.error(exc)
        click.echo(click.style(exc, fg="red"), err=True)


@device_group.command(cls=StandardCommand, name="set_rules")
@click.pass_context
@click.argument("device_id")
@click.argument("rules", nargs=-1)
async def device_pc_set_rules(
    ctx: click.Context, device_id: str, rules: tuple[str, ...], **_
) -> None:
    """Set the parental control rules."""

    try:
        rules_to_apply: dict[str, str] = dict(
            map(
                lambda weekday, readable_schedule: (
                    weekday.name.lower(),
                    (
                        readable_schedule
                        if not readable_schedule.startswith("${")
                        else None
                    ),
                ),
                Weekdays,
                rules,
            )
        )

        dev_id = (device_id,)
        devices: list[DeviceEntity] | None = await _get_device_details(ctx, dev_id)

        if devices is not None:
            for found_device in devices:
                await found_device.async_set_parental_control_rules(
                    rules_to_apply,
                    force_enable=True,
                )
    except Exception as exc:
        click.echo(click.style(exc, fg="red"))


@device_group.command(cls=StandardCommand, name="set_urls")
@click.pass_context
@click.argument("device_id")
@click.argument("urls", nargs=-1)
@click.option("--merge/--no-merge", default=True)
async def device_pc_set_urls(
    ctx: click.Context, device_id: str, merge: bool, urls: tuple[str, ...], **_
) -> None:
    """Set the parental control URLs."""

    dev_id = (device_id,)
    devices: list[DeviceEntity] | None = await _get_device_details(ctx, dev_id)

    if devices is not None:
        for found_device in devices:
            try:
                await found_device.async_set_parental_control_urls(
                    urls,
                    force_enable=True,
                    merge=merge,
                )
            except Exception as exc:
                click.echo(click.style(exc, fg="red"))

    # if mesh_obj := await _async_mesh_connect(ctx):
    #     async with mesh_obj:
    #         await mesh_obj.async_initialise()
    #         await mesh_obj.async_set_parental_control_urls(
    #             device_id=device_id, merge=merge, urls=list(urls)
    #         )


@cli.group(name="mesh")
@click.help_option()
async def mesh_group() -> None:
    """Work with the mesh."""


@mesh_group.command(cls=StandardCommand, name="details")
@click.pass_context
async def mesh_details(
    ctx: click.Context,
    **_,
) -> None:
    """Get details about the Mesh."""

    if mesh_obj := await _async_mesh_connect(ctx):
        async with mesh_obj:
            try:
                await mesh_obj.async_initialise()
            except Exception as exc:
                click.echo(click.style(exc, fg="red"), err=True)
                return

            try:
                title: str = "Mesh Details"
                click.echo(title)
                click.echo("-" * len(title))
                _display_value("Capabilities", mesh_obj.capabilities)
                if MeshCapability.GET_WAN_INFO in mesh_obj.capabilities:
                    _display_value("Internet connected", mesh_obj.wan_status)
                    _display_value("Public IP", mesh_obj.wan_ip)
                    _display_value("WAN MAC", mesh_obj.wan_mac)
                if MeshCapability.GET_LAN_SETTINGS in mesh_obj.capabilities:
                    _display_value("DHCP enabled", mesh_obj.dhcp_enabled)
                    _display_value(
                        "DHCP reservations",
                        [
                            f"{r.get('description')}\t{r.get('mac_address')}\t{r.get('ip_address')}"
                            for r in mesh_obj.dhcp_reservations
                        ],
                    )
                if (
                    MeshCapability.GET_TOPOLOGY_OPTIMISATION_SETTINGS
                    in mesh_obj.capabilities
                ):
                    _display_value(
                        "Client steering enabled", mesh_obj.client_steering_enabled
                    )
                    _display_value(
                        "Node steering enabled", mesh_obj.node_steering_enabled
                    )
                if MeshCapability.GET_EXPRESS_FORWARDING in mesh_obj.capabilities:
                    _display_value(
                        "Express Forwarding",
                        {
                            "Supported": mesh_obj.express_forwarding_supported,
                            "Enabled": mesh_obj.express_forwarding_enabled,
                        },
                    )
                if MeshCapability.GET_PARENTAL_CONTROL_INFO in mesh_obj.capabilities:
                    _display_value(
                        "Parental Control enabled", mesh_obj.parental_control_enabled
                    )
                if MeshCapability.GET_MAC_FILTERING_SETTINGS in mesh_obj.capabilities:
                    _display_value(
                        "MAC filtering",
                        {
                            "Enabled": mesh_obj.mac_filtering_enabled,
                            "Mode": mesh_obj.mac_filtering_mode,
                            "Filters": mesh_obj.mac_filtering_addresses,
                        },
                    )
                if MeshCapability.GET_WPS_SERVER_SETTINGS in mesh_obj.capabilities:
                    _display_value("WPS enabled", mesh_obj.wps_state)
                if MeshCapability.GET_ALG_SETTINGS in mesh_obj.capabilities:
                    _display_value("SIP enabled", mesh_obj.sip_enabled)
                if MeshCapability.GET_HOMEKIT_SETTINGS in mesh_obj.capabilities:
                    _display_value(
                        "HomeKit",
                        {
                            "Enabled": mesh_obj.homekit_enabled,
                            "Paired": mesh_obj.homekit_paired,
                        },
                    )
                if MeshCapability.GET_UPNP_SETTINGS in mesh_obj.capabilities:
                    _display_value(
                        "UPnP",
                        {
                            "Enabled": mesh_obj.upnp_enabled,
                            "allow_change_settings": mesh_obj.upnp_allow_change_settings,
                            "allow_disable_Internet": mesh_obj.upnp_allow_disable_internet,
                        },
                    )
                if MeshCapability.GET_DEVICES in mesh_obj.capabilities:
                    _display_value("Nodes", [n.name for n in mesh_obj.nodes])
                if MeshCapability.GET_SPEEDTEST_RESULTS in mesh_obj.capabilities:
                    _display_value(
                        "Latest Speedtest result", mesh_obj.latest_speedtest_result
                    )
                if MeshCapability.GET_GUEST_NETWORK_INFO in mesh_obj.capabilities:
                    _display_value(
                        "Guest network",
                        {
                            "Enabled": mesh_obj.guest_wifi_enabled,
                            "Networks": mesh_obj.guest_wifi_details,
                        },
                    )
                if MeshCapability.GET_STORAGE_PARTITIONS in mesh_obj.capabilities:
                    _display_value(
                        "Storage details", {"Shares": mesh_obj.storage_available}
                    )
                if MeshCapability.GET_DEVICES in mesh_obj.capabilities:
                    _display_value(
                        "Online devices",
                        [
                            f"{d.name}\t{d.adapter_info[0].get('ip')}"
                            for d in mesh_obj.devices
                            if d.status
                        ],
                    )
                    _display_value(
                        "Offline devices",
                        [d.name for d in mesh_obj.devices if not d.status],
                    )
            except Exception as exc:
                click.echo(click.style(exc, fg="red"))


@mesh_group.command(cls=StandardCommand, name="action")
@click.argument("action", type=click.Choice(MESH_ALLOWED_ACTIONS, case_sensitive=False))
@click.pass_context
async def mesh_action(
    ctx: click.Context,
    action: str,
    **_,
) -> None:
    """Carry out a specified action on the mesh."""

    ret: Any = None
    try:
        if (mesh_obj := await _async_mesh_connect(ctx)) is not None:
            async with mesh_obj:
                if action == "channel_scan_info":
                    ret = await mesh_obj.async_get_channel_scan_info()
                elif action == "channel_scan_start":
                    ret = await mesh_obj.async_start_channel_scan()
                elif action == "detect_capabilities":
                    ret = await mesh_obj.async_detect_capabilities()
                elif action == "guest_wifi_off":
                    ret = await mesh_obj.async_set_guest_wifi_state(state=False)
                elif action == "guest_wifi_on":
                    ret = await mesh_obj.async_set_guest_wifi_state(state=True)
                elif action == "homekit_off":
                    ret = await mesh_obj.async_set_homekit_state(state=False)
                elif action == "homekit_on":
                    ret = await mesh_obj.async_set_homekit_state(state=True)
                elif action == "parental_control_off":
                    ret = await mesh_obj.async_set_parental_control_state(state=False)
                elif action == "parental_control_on":
                    ret = await mesh_obj.async_set_parental_control_state(state=True)
                elif action == "speedtest_results":
                    ret = await mesh_obj.async_get_speedtest_results()
                elif action == "speedtest_start":
                    ret = await mesh_obj.async_start_speedtest()
                elif action == "speedtest_state":
                    ret = await mesh_obj.async_get_speedtest_state()
                elif action == "update_check_start":
                    ret = await mesh_obj.async_check_for_updates()
                elif action == "upnp_off":
                    cur_settings: dict[str, bool] = (
                        await mesh_obj.async_get_upnp_state()
                    )
                    new_settings: dict[str, bool] = {
                        "enabled": False,
                        "allow_change_settings": cur_settings.get(
                            "canUsersConfigure", False
                        ),
                        "allow_disable_internet": cur_settings.get(
                            "canUsersDisableWANAccess", False
                        ),
                    }
                    ret = await mesh_obj.async_set_upnp_settings(**new_settings)
                elif action == "upnp_on":
                    cur_settings: dict[str, bool] = (
                        await mesh_obj.async_get_upnp_state()
                    )
                    new_settings: dict[str, bool] = {
                        "enabled": True,
                        "allow_change_settings": cur_settings.get(
                            "canUsersConfigure", False
                        ),
                        "allow_disable_internet": cur_settings.get(
                            "canUsersDisableWANAccess", False
                        ),
                    }
                    ret = await mesh_obj.async_set_upnp_settings(**new_settings)
                elif action == "wps_off":
                    ret = await mesh_obj.async_set_wps_state(state=False)
                elif action == "wps_on":
                    ret = await mesh_obj.async_set_wps_state(state=True)
    except Exception as exc:
        click.echo(click.style(exc, fg="red"), err=True)
    else:
        click.echo(ret)


@cli.group(name="node")
@click.help_option()
async def node_group() -> None:
    """Work with nodes on the Mesh."""


@node_group.command(cls=StandardCommand, name="details")
@click.argument("node_name")
@click.pass_context
async def node_details(
    ctx: click.Context,
    node_name: str,
    **_,
) -> None:
    """Get details about a node on the Mesh."""
    if mesh_obj := await _async_mesh_connect(ctx):
        async with mesh_obj:
            await mesh_obj.async_initialise()
            nodes: list[NodeEntity] = mesh_obj.nodes
            if not nodes:
                click.echo("No nodes found")
            else:
                found_node: NodeEntity | None = next(
                    (node for node in nodes if node.name == node_name), None
                )
                if found_node is None:
                    click.echo("Node not found")
                else:
                    try:
                        title: str = node_name
                        click.echo(title)
                        click.echo("-" * len(title))
                        _display_value("Queried at", found_node.results_time)
                        _display_value("Device ID", found_node.unique_id)
                        _display_value("Online", found_node.status),
                        _display_value("Node type", found_node.type.title())
                        _display_value("Manufacturer", found_node.manufacturer)
                        _display_value("Model", found_node.model)
                        _display_value("Hardware version", found_node.hardware_version)
                        _display_value("Serial #", found_node.serial)
                        _display_value("Icon type", found_node.ui_type)
                        _display_value(
                            "Firmware details",
                            {
                                "Versions": found_node.firmware,
                                "last_checked": found_node.last_update_check,
                            },
                        )
                        _display_value("Connections", found_node.adapter_info)
                        if found_node.type == "secondary":
                            _display_value(
                                "Backhaul",
                                {
                                    "details": [found_node.backhaul],
                                    "parent": f"{found_node.parent_name} ({found_node.parent_ip})",
                                },
                                include_count_on_list=False,
                            )
                        _display_value(
                            "Connected Devices",
                            [d.get("name", "") for d in found_node.connected_devices],
                        )
                    except Exception as exc:
                        click.echo(click.style(exc, fg="red"))


@node_group.command(cls=StandardCommand, name="restart")
@click.argument("node_name")
@click.pass_context
async def node_restart(
    ctx: click.Context,
    node_name: str,
    **_,
) -> None:
    """Restart a node on the Mesh."""

    if mesh_obj := await _async_mesh_connect(ctx):
        async with mesh_obj:
            await mesh_obj.async_initialise()
            nodes: list[NodeEntity] = mesh_obj.nodes
            if not nodes:
                click.echo("No nodes found")
            else:
                found_node: NodeEntity | None = next(
                    (node for node in nodes if node.name == node_name), None
                )
                if found_node is None:
                    click.echo("Node not found")
                else:
                    try:
                        await found_node.async_reboot()
                    except Exception as exc:
                        click.echo(click.style(exc, fg="red"), err=True)
                        return

    # if mesh_obj := await _async_mesh_connect(ctx):
    #     async with mesh_obj:
    #         try:
    #             await mesh_obj.async_gather_details()
    #             _LOGGER.debug("Restarting %s", node_name)
    #             await mesh_obj.async_reboot_node(node_name=node_name)
    #         except (MeshDeviceNotFoundResponse, MeshInvalidInput) as err:
    #             _LOGGER.error(err)


@cli.group(name="parental_schedules")
@click.help_option()
async def parental_schedule_group() -> None:
    """Parental schedule conversions."""


@parental_schedule_group.command(name="decode")
@click.argument("to_decode", nargs=-1, required=True)
async def ps_decode(to_decode: tuple[str, ...]) -> None:
    """Decode the given binary schedule forms to a human readable form."""
    if len(to_decode) > len(ParentalControl.WEEKDAYS):
        _LOGGER.error("Too many arguments specified")
    elif len(to_decode) == 1:
        _display_value(
            "", ParentalControl.binary_to_human_readable(to_decode=to_decode[0])
        )
    else:
        dict_to_decode = dict(
            map(
                lambda weekday, binary_schedule: (weekday.name, binary_schedule),
                ParentalControl.WEEKDAYS,
                to_decode,
            )
        )
        _display_value(
            "", ParentalControl.binary_to_human_readable(to_decode=dict_to_decode)
        )


@parental_schedule_group.command(name="encode")
@click.argument("to_encode", nargs=-1, required=True)
async def ps_encode(to_encode: tuple[str, ...]) -> None:
    """Encode the given human readable form schedules to binary form."""
    if len(to_encode) > len(ParentalControl.WEEKDAYS):
        _LOGGER.error("Too many arguments specified")
    elif len(to_encode) == 1:
        _display_value(
            "", ParentalControl.human_readable_to_binary(to_encode=to_encode[0])
        )
    else:
        dict_to_encode = dict(
            map(
                lambda weekday, readable_schedule: (
                    weekday.name,
                    readable_schedule if readable_schedule else None,
                ),
                ParentalControl.WEEKDAYS,
                to_encode,
            )
        )
        _display_value(
            "", ParentalControl.human_readable_to_binary(to_encode=dict_to_encode)
        )


async def _async_mesh_connect(ctx: click.Context = None) -> Mesh | None:
    """Return the Mesh object."""

    msg: str = ""
    if ctx is not None:
        mesh_object: Mesh = Mesh(
            node=ctx.params.get("primary_node"),
            password=ctx.params.get("password"),
            request_timeout=ctx.params.get("timeout"),
            session=await ctx.obj if ctx.obj else None,
            username=ctx.params.get("username"),
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
            click.echo(click.style(msg, fg="red"))

    return None


def _display_value(
    label: str,
    value: Any,
    display_bool_false: str = "No",
    display_bool_true: str = "Yes",
    display_none: str = "N/A",
    indent_level: int = 0,
    include_count_on_list: bool = True,
) -> None:
    """Format and display."""

    def _titlecase(s) -> str:
        arr: list[str] = s.split("_")
        arr[0] = arr[0].title()
        return " ".join(arr)

    row_label: str = ""
    prefix_len: int = 4
    prefix_char: str = " "

    try:
        prefix = prefix_len * indent_level * prefix_char
        if type(value) in (dict, list):
            if type(value) is list:
                row_label = f"{prefix}{label}"
                if include_count_on_list:
                    row_label += f" (count: {len(value)})"
                row_label += ": "
                click.echo(row_label)
                prefix += prefix_len * prefix_char
                if len(value) == 0:
                    click.echo(f"{prefix}No details to show")
                else:
                    for val in value:
                        click.echo(f"{prefix}{val}")
            else:
                row_label = f"{prefix}{label}: "
                click.echo(row_label)
                prefix += prefix_len * prefix_char
                for item_label, item_value in value.items():
                    _display_value(
                        _titlecase(item_label).replace("_", " "),
                        item_value,
                        indent_level=1,
                        include_count_on_list=include_count_on_list,
                    )
        else:
            row_label = f"{prefix}{label}: "
            click.echo(row_label, nl=False)
            if type(value) is bool:
                click.echo(display_bool_true if value else display_bool_false)
            elif value is None:
                click.echo(display_none)
            else:
                click.echo(value)
    except Exception as exc:
        click.echo(click.style(exc, fg="red"))


async def _get_device_details(
    ctx: click.Context, device: tuple[str, ...]
) -> list[DeviceEntity] | None:
    """Retreive device details from the mesh."""

    ret: list[DeviceEntity | NodeEntity] | None = None
    if mesh_obj := await _async_mesh_connect(ctx):
        async with mesh_obj:
            await mesh_obj.async_initialise()
            try:
                refresh: bool = True
                if not device:
                    device = None
                device_qry: tuple[str, ...] = tuple(
                    filter(lambda d: not d.startswith("${input:"), device)
                )
                ret = await mesh_obj.async_get_devices(
                    device_qry, force_refresh=refresh
                )
            except MeshDeviceNotFoundResponse as exc:
                click.echo(click.style(f"{exc}: {exc.devices}", fg="red"), err=True)
                return
            except Exception as exc:
                click.echo(click.style(exc, fg="red"), err=True)
                return

    return ret


if __name__ == "__main__":
    with contextlib.suppress(Exception):
        cli()
