"""pyvelop CLI."""

# region #-- imports --#
import logging
import re
import uuid
from typing import Dict, List, Tuple

import aiohttp
import asyncclick as click

from pyvelop.const import _PACKAGE_NAME, _PACKAGE_VERSION
from pyvelop.device import Device
from pyvelop.exceptions import (
    MeshConnectionError,
    MeshDeviceNotFoundResponse,
    MeshException,
    MeshInvalidCredentials,
    MeshInvalidInput,
    MeshNodeNotPrimary,
    MeshTimeoutError,
)
from pyvelop.mesh import Mesh
from pyvelop.node import Node

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
                        logging.getLogger(_PACKAGE_NAME).setLevel(logging.DEBUG)
                        logging.getLogger(f"{_PACKAGE_NAME}.jnap").setLevel(
                            logging.WARNING
                        )
                        logging.getLogger(f"{_PACKAGE_NAME}.jnap.verbose").setLevel(
                            logging.WARNING
                        )
                        logging.getLogger(f"{_PACKAGE_NAME}.mesh.verbose").setLevel(
                            logging.WARNING
                        )
                        if value > 2:
                            logging.getLogger(f"{_PACKAGE_NAME}.mesh.verbose").setLevel(
                                logging.DEBUG
                            )
                            if value > 3:
                                logging.getLogger(f"{_PACKAGE_NAME}.jnap").setLevel(
                                    logging.DEBUG
                                )
                                if value > 4:
                                    logging.getLogger(
                                        f"{_PACKAGE_NAME}.jnap.verbose"
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


DEF_INDENT: int = 2

click.anyio_backend = "aysncio"
_LOGGER = logging.getLogger(f"{_PACKAGE_NAME}.cli")


@click.group()
@click.version_option(version=_PACKAGE_VERSION, message="%(version)s")
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
        if mesh_details := await mesh_connect(ctx):
            async with mesh_details:
                for found_device in devices:
                    try:
                        await mesh_details.async_delete_device_by_id(
                            device=found_device.unique_id
                        )
                    except MeshException as err:
                        _LOGGER.error("%s (%s)", err, found_device.name)


@device_group.command(cls=StandardCommand, name="details")
@click.pass_context
@click.argument("device")
async def device_details(
    ctx: click.Context,
    device: str,
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


@cli.command(cls=StandardCommand)
@click.pass_context
async def mesh(
    ctx: click.Context,
    **_,
) -> None:
    """Get details about the Mesh."""
    indent: int = DEF_INDENT
    prefix: str = f"\n{indent * ' '}"
    if mesh_details := await mesh_connect(ctx):
        async with mesh_details:
            await mesh_details.async_gather_details()
            _display_data(
                _build_display_data(
                    mappings=[
                        ("wan_status", "Internet Connected"),
                        ("wan_ip", "Public IP"),
                        ("wan_dns", "DNS Servers", ", ".join(mesh_details.wan_dns)),
                        ("wan_mac", "MAC"),
                        (
                            "nodes",
                            "Nodes",
                            prefix
                            + prefix.join([node.name for node in mesh_details.nodes]),
                        ),
                        ("latest_speedtest_result", "Latest Speedtest Result"),
                        ("parental_control_enabled", "Parental Control Enabled"),
                        ("wps_state", "WPS Enabled"),
                        ("homekit_enabled", "HomeKit Integration Enabled"),
                        ("homekit_paired", "HomeKit Integration Paired"),
                        ("client_steering_enabled", "Client Steering Enabled"),
                        ("node_steering_enabled", "Node Steering Enabled"),
                        (
                            "mac_filtering",
                            "MAC Filtering",
                            _mac_filtering_details(
                                addresses=mesh_details.mac_filtering_addresses,
                                mode=mesh_details.mac_filtering_mode,
                                state=mesh_details.mac_filtering_enabled,
                            ),
                        ),
                        (
                            "guest_wifi_details",
                            "Guest Wi-Fi Details",
                            _guest_wifi_details(
                                state=mesh_details.guest_wifi_enabled,
                                networks=mesh_details.guest_wifi_details,
                            ),
                        ),
                        (
                            "storage_details",
                            "Storage Details",
                            _storage_details(
                                available_shares=mesh_details.storage_available,
                                server_details=mesh_details.storage_settings,
                            ),
                        ),
                        (
                            "devices",
                            f"Online Devices ({len([device for device in mesh_details.devices if device.status])})",
                            prefix
                            + prefix.join(
                                [
                                    f"{device.name} ({device.connected_adapters[0].get('ip')})"
                                    for device in mesh_details.devices
                                    if device.status
                                ]
                            ),
                        ),
                        (
                            "devices",
                            "Offline Devices "
                            f"({len([device for device in mesh_details.devices if not device.status])})",
                            prefix
                            + prefix.join(
                                [
                                    device.name
                                    for device in mesh_details.devices
                                    if not device.status
                                ]
                            ),
                        ),
                    ],
                    obj=mesh_details,
                    title="Mesh Overview",
                )
            )


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
    if mesh_details := await mesh_connect(ctx):
        async with mesh_details:
            await mesh_details.async_gather_details()
            nodes: List[Node] = mesh_details.nodes
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
                                                    f"{found_node.backhaul.get('speed_mbps')}mbps"
                                                    if found_node.backhaul.get(
                                                        "speed_mbps"
                                                    )
                                                    else None,
                                                ),
                                                ("signal_strength", "Signal strength"),
                                                (
                                                    "rssi_dbm",
                                                    "RSSI",
                                                    f"{found_node.backhaul.get('rssi_dbm')}dBm"
                                                    if found_node.backhaul.get(
                                                        "rssi_dbm"
                                                    )
                                                    else None,
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
    if mesh_details := await mesh_connect(ctx):
        async with mesh_details:
            try:
                await mesh_details.async_gather_details()
                _LOGGER.debug("Restarting %s", node_name)
                await mesh_details.async_reboot_node(node_name=node_name)
            except (MeshDeviceNotFoundResponse, MeshInvalidInput) as err:
                _LOGGER.error(err)


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


async def _get_device_details(ctx: click.Context, device: str) -> List[Device] | None:
    """Retreive device details from the mesh."""
    ret: List[Device | Node] | None
    if mesh_details := await mesh_connect(ctx):
        async with mesh_details:
            try:  # match a GUID?
                _ = uuid.UUID(device)
                ret = [
                    await mesh_details.async_get_device_from_id(
                        device_id=device, force_refresh=True
                    )
                ]
            except MeshDeviceNotFoundResponse:
                _LOGGER.error("Device not found (%s)", device)
                return
            except ValueError:  # not a GUID
                regex_pattern: str = r"^[a-f0-9]{2}((:|-)*[a-f0-9]{2}){5}$"
                if (  # MAC address?
                    re.match(pattern=regex_pattern, string=device, flags=re.IGNORECASE)
                    is not None
                ):
                    try:
                        ret = [
                            await mesh_details.async_get_device_from_mac_address(
                                device, force_refresh=True
                            )
                        ]
                    except MeshDeviceNotFoundResponse:
                        _LOGGER.error("Device not found (%s)", device)
                        return
                else:
                    ret = [
                        found_device
                        for found_device in await mesh_details.async_get_devices()
                        if found_device.name == device
                    ]
                    if not ret:
                        _LOGGER.error("Device not found (%s)", device)
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
            ("guest_network", "Guest"),
            (
                "signal_strength",
                "Signal Strength",
                f"{adapter.get('signal_strength', None)} ({adapter.get('rssi', None)}dBm)"
                if adapter.get("signal_strength", None)
                else "N/A",
            ),
        ],
        obj=adapter,
    )

    return "\n" + ret.rstrip()


def _display_data(message: str = "") -> None:
    """Display the given data on screen."""
    print(message)


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
                else "N/A",
            ),
            (
                "blocked_sites",
                "Prohibited Sites",
                prefix + prefix.join(schedule.get("blocked_sites", []))
                if schedule.get("blocked_sites", [])
                else "N/A",
            ),
        ],
        obj=schedule,
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
    cli()
