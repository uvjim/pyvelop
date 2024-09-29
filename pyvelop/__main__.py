"""pyvelop CLI."""

# region #-- imports --#
from __future__ import annotations

import json
import logging
import re
import uuid
from typing import Any, Dict, List, Set, Tuple

import aiohttp
import asyncclick as click

from .device import Device, ParentalControl
from .exceptions import (
    MeshConnectionError,
    MeshDeviceNotFoundResponse,
    MeshException,
    MeshInvalidCredentials,
    MeshInvalidInput,
    MeshNodeNotPrimary,
    MeshTimeoutError,
)
from .mesh import Mesh
from .node import Node

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

        standard_options: List[click.Option] = [
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


MESH_ALLOWED_ACTIONS: Set = (
    "channel_scan_info",
    "channel_scan_start",
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
    devices: List[Device] | None = await _get_device_details(ctx=ctx, device=device)

    if devices is not None:
        if mesh_obj := await mesh_connect(ctx):
            async with mesh_obj:
                for found_device in devices:
                    try:
                        await mesh_obj.async_delete_device_by_id(
                            device=found_device.unique_id
                        )
                    except MeshException as err:
                        _LOGGER.error("%s (%s)", err, found_device.name)


@device_group.command(cls=StandardCommand, name="details")
@click.pass_context
@click.argument("device", nargs=-1)
async def device_details(
    ctx: click.Context,
    device: Tuple[str, ...],
    **_,
) -> None:
    """Display details about a device on the Mesh."""
    devices: List[Device] | None = await _get_device_details(ctx=ctx, device=device)

    if devices is not None:
        for found_device in devices:
            _display_data(
                _build_display_data(
                    mappings=[
                        ("results_time", "Queried at"),
                        ("unique_id", "Device ID"),
                        ("ui_type", "Icon Type"),
                        ("manufacturer", "Manufacturer"),
                        ("model", "Model"),
                        ("description", "Description"),
                        ("operating_system", "Operating System"),
                        ("serial", "Serial #"),
                        ("status", "Online"),
                        ("parent_name", "Parent"),
                        (
                            "connected_adapters",
                            "Connections",
                            _connected_details(
                                adapters=found_device.connected_adapters
                            ),
                        ),
                        (
                            "parental_control_schedule",
                            "Parental Control",
                            _parental_control_schedule_details(
                                schedule=found_device.parental_control_schedule
                            ),
                        ),
                    ],
                    obj=found_device,
                    title=found_device.name,
                )
            )


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
    if mesh_obj := await mesh_connect(ctx):
        async with mesh_obj:
            await mesh_obj.async_gather_details()
            try:
                if not block:
                    rules_to_apply: Dict[str, str] = {}
                else:
                    rules_to_apply: Dict[str, str] = dict(
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
    if mesh_obj := await mesh_connect(ctx):
        async with mesh_obj:
            await mesh_obj.async_rename_device(device_id=device_id, name=new_name)


@device_group.command(cls=StandardCommand, name="set_rules")
@click.pass_context
@click.argument("device_id")
@click.argument("rules", nargs=-1)
async def device_pc_set_rules(
    ctx: click.Context, device_id: str, rules: Tuple[str, ...], **_
) -> None:
    """Set the parental control rules."""
    rules_to_apply: Dict[str, str] = dict(
        map(
            lambda weekday, readable_schedule: (weekday.name, readable_schedule),
            ParentalControl.WEEKDAYS,
            rules,
        )
    )

    if mesh_obj := await mesh_connect(ctx):
        async with mesh_obj:
            await mesh_obj.async_gather_details()
            await mesh_obj.async_set_parental_control_rules(
                device_id=device_id, rules=rules_to_apply
            )


@device_group.command(cls=StandardCommand, name="set_urls")
@click.pass_context
@click.argument("device_id")
@click.argument("urls", nargs=-1)
@click.option("--merge/--no-merge", default=True)
async def device_pc_set_urls(
    ctx: click.Context, device_id: str, merge: bool, urls: Tuple[str, ...], **_
) -> None:
    """Set the parental control URLs."""
    if mesh_obj := await mesh_connect(ctx):
        async with mesh_obj:
            await mesh_obj.async_gather_details()
            await mesh_obj.async_set_parental_control_urls(
                device_id=device_id, merge=merge, urls=list(urls)
            )


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
    indent: int = DEF_INDENT
    prefix: str = f"\n{indent * ' '}"
    if mesh_obj := await mesh_connect(ctx):
        async with mesh_obj:
            await mesh_obj.async_gather_details()
            _display_data(
                _build_display_data(
                    mappings=[
                        ("wan_status", "Internet Connected"),
                        ("wan_ip", "Public IP"),
                        ("wan_dns", "DNS Servers", ", ".join(mesh_obj.wan_dns)),
                        ("wan_mac", "MAC"),
                        (
                            "nodes",
                            "Nodes",
                            prefix
                            + prefix.join([node.name for node in mesh_obj.nodes]),
                        ),
                        (
                            "latest_speedtest_result",
                            "Latest Speedtest Result",
                            _speedtest_results(
                                speedtest_results=mesh_obj.latest_speedtest_result
                            ),
                        ),
                        ("dhcp_enabled", "DHCP Enabled"),
                        (
                            "dhcp_reservations",
                            "DHCP Reservations",
                            (
                                prefix
                                + prefix.join(
                                    [
                                        f"{reservation.get('description')},"
                                        f"{reservation.get('mac_address')},"
                                        f"{reservation.get('ip_address')}"
                                        for reservation in mesh_obj.dhcp_reservations
                                    ]
                                )
                                if len(mesh_obj.dhcp_reservations)
                                else "None"
                            ),
                        ),
                        ("parental_control_enabled", "Parental Control Enabled"),
                        ("wps_state", "WPS Enabled"),
                        ("is_channel_scan_running", "Channel Scan Running"),
                        ("homekit_enabled", "HomeKit Integration Enabled"),
                        ("homekit_paired", "HomeKit Integration Paired"),
                        ("client_steering_enabled", "Client Steering Enabled"),
                        ("node_steering_enabled", "Node Steering Enabled"),
                        ("upnp_enabled", "UPnP Enabled"),
                        ("upnp_allow_change_settings", "UPnP Allow Change Settings"),
                        ("upnp_allow_disable_internet", "UPnP Allow Disable Internet"),
                        ("sip_enabled", "SIP Enabled"),
                        (
                            "express_forwarding_supported",
                            "Express Forwarding Supported",
                        ),
                        ("express_forwarding_enabled", "Express Forwarding Enabled"),
                        (
                            "mac_filtering",
                            "MAC Filtering",
                            _mac_filtering_details(
                                addresses=mesh_obj.mac_filtering_addresses,
                                mode=mesh_obj.mac_filtering_mode,
                                state=mesh_obj.mac_filtering_enabled,
                            ),
                        ),
                        (
                            "guest_wifi_details",
                            "Guest Wi-Fi Details",
                            _guest_wifi_details(
                                state=mesh_obj.guest_wifi_enabled,
                                networks=mesh_obj.guest_wifi_details,
                            ),
                        ),
                        (
                            "storage_details",
                            "Storage Details",
                            _storage_details(
                                available_shares=mesh_obj.storage_available,
                                server_details=mesh_obj.storage_settings,
                            ),
                        ),
                        (
                            "devices",
                            f"Online Devices ({len([device for device in mesh_obj.devices if device.status])})",
                            prefix
                            + prefix.join(
                                [
                                    f"{device.name} ({device.connected_adapters[0].get('ip')})"
                                    for device in mesh_obj.devices
                                    if device.status
                                ]
                            ),
                        ),
                        (
                            "devices",
                            "Offline Devices "
                            f"({len([device for device in mesh_obj.devices if not device.status])})",
                            prefix
                            + prefix.join(
                                [
                                    device.name
                                    for device in mesh_obj.devices
                                    if not device.status
                                ]
                            ),
                        ),
                    ],
                    obj=mesh_obj,
                    title="Mesh Overview",
                )
            )


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
    if (mesh_obj := await mesh_connect(ctx)) is not None:
        if action == "channel_scan_info":
            ret = await mesh_obj.async_get_channel_scan_info()
        elif action == "channel_scan_start":
            ret = await mesh_obj.async_start_channel_scan()
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
        elif action == "wps_off":
            ret = await mesh_obj.async_set_wps_state(state=False)
        elif action == "wps_on":
            ret = await mesh_obj.async_set_wps_state(state=True)
        print(ret)
        print(json.dumps(ret))


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
    indent: int = DEF_INDENT
    prefix: str = f"\n{indent * ' '}"
    if mesh_obj := await mesh_connect(ctx):
        async with mesh_obj:
            await mesh_obj.async_gather_details()
            nodes: List[Node] = mesh_obj.nodes
            if not nodes:
                print("No nodes found")
            else:
                found_node: Node
                for found_node in nodes:
                    if found_node.name == node_name:
                        _display_data(
                            _build_display_data(
                                mappings=[
                                    ("results_time", "Queried at"),
                                    ("unique_id", "Device ID"),
                                    ("type", "Node type", found_node.type.title()),
                                    ("manufacturer", "Manufacturer"),
                                    ("model", "Model"),
                                    ("hardware_version", "Hardware version"),
                                    ("serial", "Serial #"),
                                    ("ui_type", "Icon type"),
                                    (
                                        "firmware",
                                        "Firmware",
                                        found_node.firmware.get("version"),
                                    ),
                                    (
                                        "firmware",
                                        "Latest firmware",
                                        found_node.firmware.get("latest_version"),
                                    ),
                                    ("last_update_check", "Last update check"),
                                    ("status", "Online"),
                                    (
                                        "connected_adapters",
                                        "Connections",
                                        _connected_details(
                                            adapters=found_node.connected_adapters
                                        ),
                                    ),
                                    (
                                        "backhaul",
                                        "Backhaul",
                                        "\n"
                                        + _build_display_data(
                                            indent=indent,
                                            mappings=[
                                                ("parent_name", "Parent"),
                                                ("connection", "Connection type"),
                                                (
                                                    "speed_mbps",
                                                    "Speed",
                                                    (
                                                        f"{found_node.backhaul.get('speed_mbps')}mbps"
                                                        if found_node.backhaul.get(
                                                            "speed_mbps"
                                                        )
                                                        else None
                                                    ),
                                                ),
                                                ("signal_strength", "Signal strength"),
                                                (
                                                    "rssi_dbm",
                                                    "RSSI",
                                                    (
                                                        f"{found_node.backhaul.get('rssi_dbm')}dBm"
                                                        if found_node.backhaul.get(
                                                            "rssi_dbm"
                                                        )
                                                        else None
                                                    ),
                                                ),
                                                ("last_checked", "Last checked"),
                                            ],
                                            obj=dict(
                                                **found_node.backhaul,
                                                parent_name=found_node.parent_name,
                                            ),
                                        ),
                                    ),
                                    (
                                        "connected_devices",
                                        f"Connected devices ({len(found_node.connected_devices)})",
                                        prefix
                                        + prefix.join(
                                            [
                                                device.get("name")
                                                for device in found_node.connected_devices
                                            ]
                                        ),
                                    ),
                                ],
                                obj=found_node,
                                title=node_name,
                            )
                        )
                        break


@node_group.command(cls=StandardCommand, name="restart")
@click.argument("node_name")
@click.pass_context
async def node_restart(
    ctx: click.Context,
    node_name: str,
    **_,
) -> None:
    """Restart a node on the Mesh."""
    if mesh_obj := await mesh_connect(ctx):
        async with mesh_obj:
            try:
                await mesh_obj.async_gather_details()
                _LOGGER.debug("Restarting %s", node_name)
                await mesh_obj.async_reboot_node(node_name=node_name)
            except (MeshDeviceNotFoundResponse, MeshInvalidInput) as err:
                _LOGGER.error(err)


@cli.group(name="parental_schedules")
@click.help_option()
async def parental_schedule_group() -> None:
    """Parental schedule conversions."""


@parental_schedule_group.command(name="decode")
@click.argument("to_decode", nargs=-1, required=True)
async def ps_decode(to_decode: Tuple[str, ...]) -> None:
    """Decode the given binary schedule forms to a human readable form."""
    if len(to_decode) > len(ParentalControl.WEEKDAYS):
        _LOGGER.error("Too many arguments specified")
    elif len(to_decode) == 1:
        _display_data(ParentalControl.binary_to_human_readable(to_decode=to_decode[0]))
    else:
        dict_to_decode = dict(
            map(
                lambda weekday, binary_schedule: (weekday.name, binary_schedule),
                ParentalControl.WEEKDAYS,
                to_decode,
            )
        )
        _display_data(
            ParentalControl.binary_to_human_readable(to_decode=dict_to_decode)
        )


@parental_schedule_group.command(name="encode")
@click.argument("to_encode", nargs=-1, required=True)
async def ps_encode(to_encode: Tuple[str, ...]) -> None:
    """Encode the given human readable form schedules to binary form."""
    if len(to_encode) > len(ParentalControl.WEEKDAYS):
        _LOGGER.error("Too many arguments specified")
    elif len(to_encode) == 1:
        _display_data(ParentalControl.human_readable_to_binary(to_encode=to_encode[0]))
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
        _display_data(
            ParentalControl.human_readable_to_binary(to_encode=dict_to_encode)
        )


async def mesh_connect(ctx: click.Context = None) -> Mesh | None:
    """Return the Mesh object."""
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
            _LOGGER.error("Unable to connect to %s", ctx.params.get("primary_node"))
        except MeshInvalidCredentials:
            _LOGGER.error(
                "Unable to authenticate with %s using provided credentials",
                ctx.params.get("primary_node"),
            )
        except MeshNodeNotPrimary:
            _LOGGER.error("%s is not the primary node", ctx.params.get("primary_node"))
        except MeshTimeoutError:
            _LOGGER.error("Timed out connecting to %s", ctx.params.get("primary_node"))
        else:
            return mesh_object

    return None


async def _get_device_details(
    ctx: click.Context, device: Tuple[str]
) -> List[Device] | None:
    """Retreive device details from the mesh."""
    ret: List[Device | Node] | None
    if mesh_obj := await mesh_connect(ctx):
        async with mesh_obj:
            for dev in device:
                try:  # match a GUID?
                    _ = uuid.UUID(device[0])
                    ret = await mesh_obj.async_get_device_from_id(
                        device_id=dev,
                        force_refresh=True,
                    )
                except MeshDeviceNotFoundResponse as err:
                    _LOGGER.error("%s (%s)", err, ", ".join(err.devices))
                    return
                except ValueError:  # not a GUID
                    regex_pattern: str = r"^[a-f0-9]{2}((:|-)*[a-f0-9]{2}){5}$"
                    if (  # MAC address?
                        re.match(pattern=regex_pattern, string=dev, flags=re.IGNORECASE)
                        is not None
                    ):
                        try:
                            ret = await mesh_obj.async_get_device_from_mac_address(
                                dev, force_refresh=True
                            )
                        except MeshDeviceNotFoundResponse as err:
                            _LOGGER.error("%s (%s)", err, ", ".join(err.devices))
                            return
                    else:
                        ret = [
                            found_device
                            for found_device in await mesh_obj.async_get_devices()
                            if found_device.name == dev
                        ]
                        if not ret:
                            _LOGGER.error("Device not found (%s)", dev)
                            return
    return ret


def _build_display_data(
    mappings: List[Tuple],
    obj: Device | Dict | Mesh | Node,
    indent: int = 0,
    title: str = "",
):
    """Build the string to display the given data."""
    ret: str = ""
    if title:
        ret = f"{title}\n"
        ret += f"{len(title) * '-'}\n"

    for properties in mappings:
        try:
            property_name, display_name, display_value = properties
        except ValueError:
            display_value = None
            property_name, display_name = properties

        if display_value is None:
            if isinstance(obj, Dict):
                display_value = obj.get(property_name)
            else:
                display_value = getattr(obj, property_name, None)

        ret += f"{indent * ' '}{display_name}: {display_value}\n"

    return ret.rstrip()


def _connected_details(adapters: List[Dict]) -> str:
    """Format the connected adapter details for display."""
    ret: str = ""
    indent: int = DEF_INDENT
    if not adapters:
        return "N/A"

    adapter = adapters[0]

    ret = _build_display_data(
        indent=indent,
        mappings=[
            ("mac", "MAC"),
            ("ip", "IPv4"),
            ("ipv6", "IPv6"),
            ("primary", "Primary Adapter"),
            ("reservation", "Reservation"),
            ("reservation_description", "Reserved Name"),
            ("guest_network", "Guest"),
            (
                "signal_strength",
                "Signal Strength",
                (
                    f"{adapter.get('signal_strength', None)} ({adapter.get('rssi', None)}dBm)"
                    if adapter.get("signal_strength", None)
                    else "N/A"
                ),
            ),
        ],
        obj=adapter,
    )

    return "\n" + ret.rstrip()


def _display_data(message: str = "") -> None:
    """Display the given data on screen."""
    click.echo(message)


def _guest_wifi_details(state: bool, networks: List[Dict]) -> str:
    """Format the Guest Wi-Fi details for display."""
    ret: str = ""
    indent: int = DEF_INDENT
    ret = _build_display_data(
        indent=indent,
        mappings=[
            ("state", "Enabled"),
            (
                "networks",
                "Networks",
                "\n"
                + "\n".join(
                    [
                        f"{indent * 2 * ' '}{idx}: {network.get('ssid')} ({network.get('band')})"
                        for idx, network in enumerate(networks)
                    ]
                ),
            ),
        ],
        obj={
            "state": state,
            "networks": networks,
        },
    )

    return "\n" + ret.rstrip()


def _mac_filtering_details(addresses: List[str], mode: str | None, state: bool) -> str:
    """Format the MAC filtering details for display."""
    indent: int = DEF_INDENT

    ret = _build_display_data(
        indent=indent,
        mappings=[
            ("state", "Enabled"),
            ("mode", "Mode", str(mode).title()),
            (
                "addresses",
                "Addresses",
                "\n"
                + "\n".join(
                    [
                        f"{indent * 2 * ' '}{idx}: {addr}"
                        for idx, addr in enumerate(addresses)
                    ]
                ),
            ),
        ],
        obj={
            "addresses": addresses,
            "mode": mode,
            "state": state,
        },
    )

    return "\n" + ret.rstrip()


def _parental_control_schedule_details(schedule: Dict) -> str:
    """Format the parental control schedule for display."""
    indent: int = DEF_INDENT
    prefix: str = f"\n{indent * 2 * ' '}"
    ret: str = _build_display_data(
        indent=indent,
        mappings=[
            (
                "blocked_internet_access",
                "Blocked Access",
                (
                    prefix
                    + prefix.join(
                        [
                            f"{day.title()}: {', '.join(times) if times else 'N/A'}"
                            for day, times in schedule.get(
                                "blocked_internet_access", {}
                            ).items()
                        ]
                    )
                    if schedule.get("blocked_internet_access", {})
                    else "N/A"
                ),
            ),
            (
                "blocked_sites",
                "Prohibited Sites",
                (
                    prefix + prefix.join(schedule.get("blocked_sites", []))
                    if schedule.get("blocked_sites", [])
                    else "N/A"
                ),
            ),
        ],
        obj=schedule,
    )

    return "\n" + ret.rstrip()


def _speedtest_results(speedtest_results: Dict) -> str:
    """Format the Speedtest results for display."""
    indent: int = DEF_INDENT
    ret: str = _build_display_data(
        indent=indent,
        mappings=[
            ("timestamp", "Executed at"),
            (
                "download_bandwidth",
                "Download",
                f"{round(speedtest_results.get('download_bandwidth', 0) / 1000, 2)} Mbps",
            ),
            (
                "upload_bandwidth",
                "Upload",
                f"{round(speedtest_results.get('upload_bandwidth', 0) / 1000, 2)} Mbps",
            ),
            ("latency", "Latency", f"{speedtest_results.get('latency')}ms"),
            ("exit_code", "Status"),
        ],
        obj=speedtest_results,
    )

    return "\n" + ret.rstrip()


def _storage_details(available_shares: List[Dict], server_details: Dict) -> str:
    """Format the storage details for display."""
    ret: str = ""
    indent: int = DEF_INDENT

    def _build_share_data(share_details: Dict) -> str:
        """Format the share details for display."""
        return _build_display_data(
            indent=(indent * 3),
            mappings=[
                ("ip", "IP"),
                ("used_percent", "Used", f"{share_details.get('used_percent')}%"),
            ],
            obj=share_details,
        )

    ret = _build_display_data(
        indent=indent,
        mappings=[
            ("anonymous_access", "Anonymous Access"),
            (
                "available_shares",
                "Available Shares",
                f"\n{indent * 2 * ' '}"
                + f"\n{indent * 2 * ' '}".join(
                    [
                        f"{share.get('label')}:\n{_build_share_data(share_details=share)}"
                        for share in available_shares
                    ]
                ),
            ),
        ],
        obj=dict(server_details, available_shares=available_shares),
    )

    return "\n" + ret.rstrip()


if __name__ == "__main__":
    try:
        cli()
    except:
        pass
