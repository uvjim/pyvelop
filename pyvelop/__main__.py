import argparse
import asyncio
import logging
import sys
from argparse import ArgumentParser
from typing import List, ValuesView

from pyvelop.device import Device
from pyvelop.mesh import (
    Mesh,
    MeshBadResponse,
    MeshNodeNotPrimary,
    MeshInvalidCredentials,
    MeshTimeoutError,
)
from pyvelop.node import Node
from pyvelop.const import _PACKAGE_VERSION


def _setup_args(parser: ArgumentParser) -> None:
    """Initialise the arguments for the CLI"""

    parser.add_argument('--version', action="version", version=_PACKAGE_VERSION)

    sub_parsers = parser.add_subparsers(
        dest="target",
        title="Targets",
        description="Object to target in the Velop system",
        help="Select one of these objects to target"
    )

    # region #-- shared arguments --#
    parser_shared = argparse.ArgumentParser(add_help=False)
    parser_shared.add_argument("-a", "--primary-node", required=True, help="Address of the primary node in the mesh")
    parser_shared.add_argument("-p", "--password", required=True, help="Linksys Velop password")
    parser_shared.add_argument("-t", "--timeout", type=int, help="Set the timeout for a request. 0 = infinite")
    parser_shared.add_argument("-u", "--username", default="admin", help="Linksys Velop username")
    parser_shared.add_argument("-v", "--verbose", action="count", default=0, help="Set verbosity level")

    # region #-- Mesh arguments --#
    parser_mesh = sub_parsers.add_parser("mesh", parents=[parser_shared], help="Interact with the Velop mesh")
    parser_mesh.add_argument("--get-nodes", action="store_true", help="Retrieve names of nodes")
    parser_mesh.add_argument("--get-wan", action="store_true", help="Retrieve WAN details")
    parser_mesh.add_argument("--get-online-devices", action="store_true", help="Retrieve online devices")
    parser_mesh.add_argument("--get-offline-devices", action="store_true", help="Retrieve offline devices")
    parser_mesh.add_argument("--get-parental-control", action="store_true", help="Retrieve Parental Control state")
    parser_mesh.add_argument("--get-guest-wifi-details", action="store_true", help="Retrieve guest Wi-Fi details")
    parser_mesh.add_argument("--get-latest-speedtest", action="store_true", help="Retrieve latest Speedtest results")
    parser_mesh.add_argument("--get-available-storage", action="store_true", help="Retrieve external storage details")
    parser_mesh.add_argument("--get-storage-settings", action="store_true", help="Retrieve external storage settings")
    # endregion

    # region #-- Node arguments --#
    parser_node = sub_parsers.add_parser("node", parents=[parser_shared], help="Interact with a node")
    parser_node.add_argument("-r", "--reboot", action="store_true", help="Reboot a node")
    parser_node.add_argument("name", help="The name of the node to interact with")
    parser_node.add_argument("--get-backhaul", action="store_true", help="Retrieve backhaul details for the node")
    parser_node.add_argument("--get-overview", action="store_true", help="Retrieve high level details about the node")
    parser_node.add_argument("--get-network", action="store_true", help="Retrieve network details for the node")
    parser_node.add_argument("--get-connected-devices", action="store_true", help="Retrieve connected devices")
    # endregion

    # region Device arguments --#
    parser_device = sub_parsers.add_parser("device", parents=[parser_shared], help="Interact with a device")
    parser_device.add_argument("name", help="The name of the device to interact with")
    # endregion


async def main() -> None:
    """Main processing"""

    sections: List = []

    # region #-- handle arguments --#
    args_parser = ArgumentParser(prog="pyvelop")
    _setup_args(parser=args_parser)
    args = args_parser.parse_args()
    all_args: bool = False
    arg_values: dict = args.__dict__.copy()
    arg_values: ValuesView = arg_values.values()
    if not any([val for val in arg_values if isinstance(val, bool)]):
        all_args = True
    # endregion

    # region #-- handle no arguments being passed in --#
    if args.target is None:
        args_parser.print_help()
        sys.exit()
    # endregion

    # region #-- setup the logger --#
    logging.basicConfig()
    _LOGGER = logging.getLogger("pyvelop.cli")
    if args.verbose >= 1:
        _LOGGER.setLevel(logging.DEBUG)
        _LOGGER.debug("Arguments: %s", args.__dict__)
        if args.verbose > 1:
            logging.getLogger("pyvelop.mesh").setLevel(logging.DEBUG)
            logging.getLogger("pyvelop.mesh.verbose").setLevel(logging.INFO)
            if args.verbose > 2:
                logging.getLogger("pyvelop.mesh.verbose").setLevel(logging.DEBUG)
    # endregion

    async with Mesh(
        node=args.primary_node,
        username=args.username,
        password=args.password,
        request_timeout=args.timeout,
    ) as _mesh:
        try:
            _LOGGER.debug("Gathering details about the Velop system")
            await _mesh.async_gather_details()
        except MeshInvalidCredentials:
            _LOGGER.error("Invalid Credentials")
        except MeshBadResponse:
            _LOGGER.error("Bad response received.  Are you sure %s is a Velop node?", args.primary_node)
        except MeshNodeNotPrimary:
            _LOGGER.error("%s is not the primary node", args.primary_node)
        except MeshTimeoutError:
            _LOGGER.error("Timeout connecting to %s", args.primary_node)
        else:
            if args.target == "mesh":
                # region #-- get the node names --#
                if args.get_nodes or all_args:
                    _LOGGER.debug("Preparing node names")
                    section = "Nodes"
                    section += f"\n{'-' * len(section)}\n"
                    section += "\n".join([node.name for node in _mesh.nodes])
                    sections.append(section)
                # endregion

                # region #-- get WAN details --#
                if args.get_wan or all_args:
                    _LOGGER.debug("Preparing WAN details")
                    section = "WAN Details"
                    section += f"\n{'-' * len(section)}\n"
                    section += f"Connected: {_mesh.wan_status}\n"\
                               f"Public IP: {_mesh.wan_ip}\n"\
                               f"DNS Servers: {','.join(_mesh.wan_dns)}\n"\
                               f"MAC: {_mesh.wan_mac}"
                    sections.append(section)
                # endregion

                # region #-- get the Parental Control detail --#
                if args.get_parental_control or all_args:
                    _LOGGER.debug("Preparing Parental Control details")
                    section = "Parental Control"
                    section += f"\n{'-' * len(section)}\n"
                    section += f"Enabled: {_mesh.parental_control_enabled}"
                    sections.append(section)
                # endregion

                # region #-- get the guest Wi-Fi details: format = SSID (band) --#
                if args.get_guest_wifi_details or all_args:
                    _LOGGER.debug("Preparing guest Wi-Fi details")
                    section = "Guest Wi-Fi"
                    section += f"\n{'-' * len(section)}\n"
                    section += f"Enabled: {_mesh.guest_wifi_enabled}\n"
                    for idx, details in enumerate(_mesh.guest_wifi_details):
                        section += f"{details.get('ssid')} ({details.get('band')})\n"
                    sections.append(section.rstrip("\n"))
                # endregion

                # region #-- get the storage server settings --#
                if args.get_storage_settings or all_args:
                    _LOGGER.debug("Preparing storage server settings")
                    section = "Storage Settings"
                    section += f"\n{'-' * len(section)}"
                    for ss_k, ss_v in _mesh.storage_settings.items():
                        section += f"\n{ss_k}: {ss_v}"
                    sections.append(section)
                # endregion

                # region #-- get the storage server settings --#
                if args.get_available_storage or all_args:
                    _LOGGER.debug("Preparing available storage")
                    section = "Available Storage"
                    section += f"\n{'-' * len(section)}"
                    for partition in _mesh.storage_available:
                        section += f"\n{partition.get('label')}: {partition}"
                    sections.append(section)
                # endregion

                # region #-- get the latest Speedtest results --#
                if args.get_latest_speedtest or all_args:
                    _LOGGER.debug("Preparing latest Speedtest results")
                    latest_results = _mesh.speedtest_results
                    section = "Latest Speedtest Results"
                    section += f"\n{'-' * len(section)}\n"
                    if not latest_results:
                        section += "None available"
                    else:
                        latest_results = latest_results[0]
                        download_bandwidth = round(latest_results.get('download_bandwidth') / 1024, 2)
                        upload_bandwidth = round(latest_results.get('upload_bandwidth') / 1024, 2)
                        section += f"Executed: {latest_results.get('timestamp')}\n"\
                                   f"Result: {latest_results.get('exit_code')}\n"\
                                   f"Latency: {latest_results.get('latency')} ms\n"\
                                   f"Download Bandwidth: {download_bandwidth} Mbps\n" \
                                   f"Upload Bandwidth: {upload_bandwidth} Mbps"
                    sections.append(section)
                # endregion

                # region #-- get the online devices: format = name (ip) --#
                if args.get_online_devices or all_args:
                    _LOGGER.debug("Preparing online devices")
                    adapter: dict
                    device: Device
                    section = "Online Devices"
                    section += f"\n{'-' * len(section)}\n"
                    section += "\n".join(
                        [
                            f"{device.name} "
                            f"({','.join([adapter.get('ip') for adapter in device.connected_adapters])})"
                            for device in _mesh.devices
                            if device.status
                        ]
                    )
                    sections.append(section)
                # endregion

                # region #-- get the offline device names --#
                if args.get_offline_devices or all_args:
                    _LOGGER.debug("Preparing offline devices")
                    device: Device
                    section = "Offline Devices"
                    section += f"\n{'-' * len(section)}\n"
                    section += "\n".join(
                        [
                            device.name
                            for device in _mesh.devices
                            if not device.status
                        ]
                    )
                    sections.append(section)
                # endregion
            elif args.target == "node":
                _node: List[Node] = [node for node in _mesh.nodes if node.name.lower() == args.name.lower()]
                if not _node:
                    node_names = [node.name for node in _mesh.nodes]
                    args_parser.error(f"Invalid node name ({args.name}). Must be one of {node_names}")
                else:
                    _node: Node = _node[0]
                    # region #-- reboot the node --#
                    if args.reboot:
                        _LOGGER.debug("Requesting node reboot")
                        await _mesh.async_reboot_node(node_name=_node.name)
                    # endregion

                    # region #-- get the overview details --#
                    if args.get_overview or all_args:
                        _LOGGER.debug("Preparing ndoe overview details")
                        section = "Overview"
                        section += f"\n{'-' * len(section)}\n"
                        section += f"Device ID: {_node.unique_id}\n"\
                                   f"Name: {_node.name}\n"\
                                   f"Online: {_node.status}\n"\
                                   f"IP: {','.join([adapter.get('ip') for adapter in _node.connected_adapters])}\n"\
                                   f"Type: {_node.type.title()}\n"\
                                   f"Manufacturer: {_node.manufacturer}\n"\
                                   f"Model: {_node.model}\n" \
                                   f"Hardware Version: {_node.hardware_version}\n" \
                                   f"Serial #: {_node.serial}\n"\
                                   f"Firmware: {_node.firmware.get('version')}\n"\
                                   f"Latest Firmware: {_node.firmware.get('latest_version')}\n" \
                                   f"Last Update Check: {_node.last_update_check}"
                        sections.append(section)
                    # endregion

                    # region #-- get the network details --#
                    if args.get_network or all_args:
                        _LOGGER.debug("Preparing node network details")
                        section = "Network Details"
                        section += f"\n{'-' * len(section)}"
                        for adapter in _node.network:
                            section += f"\n{adapter.get('type')} "\
                                       f"(IP: {adapter.get('ip')}, MAC: {adapter.get('mac')})"
                        sections.append(section)
                    # endregion

                    # region #-- backhaul details --#
                    if args.get_backhaul or all_args:
                        _LOGGER.debug("Preparing backhaul details")
                        section = "Backhaul"
                        section += f"\n{'-' * len(section)}\n"
                        section += f"Parent: {_node.parent_name} ({_node.parent_ip})"
                        for bh_k, bh_v in _node.backhaul.items():
                            section += f"\n{bh_k}: {bh_v}"
                        sections.append(section)
                    # endregion

                    # region #-- get the connected devices: format = name (IP) (Type) (Guest Network) --#
                    if args.get_connected_devices or all_args:
                        _LOGGER.debug("Preparing node connected devices")
                        section = "Connected Devices"
                        section += f"\n{'-' * len(section)}\n"
                        d: dict
                        for d in _node.connected_devices:
                            section += f"{d.get('name')} " \
                                       f"({d.get('ip')}) " \
                                       f"({d.get('type')}) " \
                                       f"({d.get('guest_network')})\n"
                        sections.append(section.rstrip("\n"))
                    # endregion
            elif args.target == "device":
                _device: List = [device for device in _mesh.devices if device.name.lower() == args.name.lower()]
                if not _device:
                    args_parser.error(f"Invalid device name ({args.name}).")
                else:
                    for _d in _device:
                        # region #-- get the overview details --#
                        if all_args:
                            _LOGGER.debug("Preparing device overview")
                            connected_adapters: List = [
                                f"{adapter.get('ip')} {'(Guest Network)' if adapter.get('guest_network') else ''}"
                                for adapter in _d.connected_adapters
                            ]
                            section = "Overview"
                            section += f"\n{'-' * len(section)}\n"
                            section += f"Device ID: {_d.unique_id}\n"\
                                       f"Name: {_d.name}\n" \
                                       f"Manufacturer: {_d.manufacturer}\n" \
                                       f"Model: {_d.model}\n" \
                                       f"Description: {_d.description}\n" \
                                       f"Online: {_d.status}\n"\
                                       f"IP: {','.join(connected_adapters)}\n"\
                                       f"Parent: {_d.parent_name}\n"\
                                       f"Parental Control:\n"\
                                       f"  Blocked Times:"
                            for day, rule in _d.parental_control_schedule.get(
                                    'blocked_internet_access',
                                    {}
                            ).items():
                                section += f"\n    {day.title()}: {', '.join(rule)}"
                            else:
                                if not _d.parental_control_schedule.get('blocked_internet_access', {}):
                                    section += " N/A"
                            blocked_sites_text = ", ".join(_d.parental_control_schedule.get('blocked_sites', []))\
                                                 if _d.parental_control_schedule.get('blocked_sites', [])\
                                                 else "N/A"
                            section += f"\n  Blocked Sites: {blocked_sites_text}"
                            sections.append(section)
                        # endregion
    if sections:
        print("\n\n".join(sections))

if __name__ == "__main__":
    loop = asyncio.get_event_loop()
    loop.run_until_complete(main())
