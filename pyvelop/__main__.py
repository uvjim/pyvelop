import asyncio
import logging
from argparse import ArgumentParser
from typing import List, ValuesView

from pyvelop.device import Device
from pyvelop.mesh import (
    Mesh,
    MeshBadResponse,
    MeshNodeNotPrimary,
    MeshInvalidCredentials,
)
from pyvelop.node import Node
from pyvelop.const import _PACKAGE_VERSION


def _setup_args(parser: ArgumentParser) -> None:
    """Initialise the arguments for the CLI"""

    parser.add_argument("-d", "--debug", action="store_true", help="Print debug to the screen")
    parser.add_argument("-v", "--verbose", action="count", default=0, help="Set verbosity level")
    parser.add_argument("--version", action="store_true", help="Print the version number and exit")

    sub_parsers = parser.add_subparsers(
        dest="target",
        title="Targets",
        description="Object to target in the Velop system",
        help="Select one of these objects to target"
    )

    # region #-- Mesh arguments --#
    parser_mesh = sub_parsers.add_parser("mesh", help="Interact with the Velop mesh")
    parser_mesh.add_argument("-a", "--address", required=True, help="Address of a node in the mesh")
    parser_mesh.add_argument("-p", "--password", required=True, help="Linksys Velop password")
    parser_mesh.add_argument("-u", "--username", default="admin", help="Linksys Velop username")
    parser_mesh.add_argument("-n", "--get-nodes", action="store_true", help="Retrieve the names of nodes in the list")
    parser_mesh.add_argument("-w", "--get-wan", action="store_true", help="Retrieve the WAN details")
    parser_mesh.add_argument("--get-online-devices", action="store_true", help="Retrieve the online devices")
    parser_mesh.add_argument("--get-offline-devices", action="store_true", help="Retrieve the offline devices")
    parser_mesh.add_argument(
        "--get-parental-control-state",
        action="store_true",
        help="Retrieve the Parental Control state"
    )
    parser_mesh.add_argument(
        "-g",
        "--get-guest-wifi-details",
        action="store_true",
        help="Retrieve the guest Wi-Fi details"
    )
    parser_mesh.add_argument(
        "-s",
        "--get-latest-speedtest",
        action="store_true",
        help="Retrieve the latest Speedtest results"
    )
    # endregion

    # region #-- Node arguments --#
    parser_node = sub_parsers.add_parser("node", help="Interact with a node")
    parser_node.add_argument("-a", "--address", required=True, help="Address of a node in the mesh")
    parser_node.add_argument("-p", "--password", required=True, help="Linksys Velop password")
    parser_node.add_argument("-u", "--username", default="admin", help="Linksys Velop username")
    parser_node.add_argument("name", help="The name of the node to interact with")
    parser_node.add_argument(
        "-o",
        "--get-overview",
        action="store_true",
        help="Retrieve high level details about the node"
    )
    parser_node.add_argument(
        "-n",
        "--get-network",
        action="store_true",
        help="Retrieve the network details for the node"
    )
    parser_node.add_argument(
        "--get-parent",
        action="store_true",
        help="Retrieve the parent details for the node"
    )
    parser_node.add_argument(
        "-d",
        "--get-connected-devices",
        action="store_true",
        help="Retrieve the connected devices for the node"
    )
    # endregion

    # region Device arguments --#
    parser_device = sub_parsers.add_parser("device", help="Interact with a device")
    parser_device.add_argument("-a", "--address", required=True, help="Address of a node in the mesh")
    parser_device.add_argument("-p", "--password", required=True, help="Linksys Velop password")
    parser_device.add_argument("-u", "--username", default="admin", help="Linksys Velop username")
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
    arg_values.pop("debug")
    arg_values: ValuesView = arg_values.values()
    if not any([val for val in arg_values if isinstance(val, bool)]):
        all_args = True
    # endregion

    # region #-- setup the logger --#
    logging.basicConfig()
    _LOGGER = logging.getLogger("pyvelop.cli")
    if args.debug:
        _LOGGER.setLevel(logging.DEBUG)
        _LOGGER.debug("Arguments: %s", args.__dict__)
        if args.verbose > 0:
            logging.getLogger("pyvelop.mesh").setLevel(logging.DEBUG)
            logging.getLogger("pyvelop.mesh.verbose").setLevel(logging.INFO)
            if args.verbose > 1:
                logging.getLogger("pyvelop.mesh.verbose").setLevel(logging.DEBUG)

    # endregion

    if args.version:
        print(_PACKAGE_VERSION)
    else:
        async with Mesh(node=args.address, username=args.username, password=args.password) as _mesh:
            try:
                await _mesh.async_gather_details()
            except MeshInvalidCredentials:
                _LOGGER.error("Invalid Credentials")
            except MeshBadResponse:
                _LOGGER.error(f"Bad response received.  Are you sure {args.address} is a Velop node?")
            except MeshNodeNotPrimary:
                _LOGGER.error(f"{args.address} is not the primary node")
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

                    # region #-- get the Parental Control state --#
                    if args.get_parental_control_state or all_args:
                        _LOGGER.debug("Preparing Parental Control state")
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
                elif args.target == 'node':
                    _node: List = [node for node in _mesh.nodes if node.name.lower() == args.name.lower()]
                    if not _node:
                        node_names = [node.name for node in _mesh.nodes]
                        args_parser.error(f"Invalid node name ({args.name}). Must be one of {node_names}")
                    else:
                        _node: Node = _node[0]
                        # region #-- get the overview details --#
                        if args.get_overview or all_args:
                            _LOGGER.debug("Preparing ndoe overview details")
                            section = "Overview"
                            section += f"\n{'-' * len(section)}\n"
                            section += f"Name: {_node.name}\n"\
                                       f"Online: {_node.status}\n"\
                                       f"IP: {','.join([adapter.get('ip') for adapter in _node.connected_adapters])}\n"\
                                       f"Type: {_node.type.title()}\n"\
                                       f"Manufacturer: {_node.manufacturer}\n"\
                                       f"Model: {_node.model}\n"\
                                       f"Serial #: {_node.serial}\n"\
                                       f"Firmware: {_node.firmware.get('version')}"
                            sections.append(section)
                        # endregion

                        # region #-- get the network details --#
                        if args.get_network or all_args:
                            _LOGGER.debug("Preparing node network details")
                            section = "Network Details"
                            section += f"\n{'-' * len(section)}\n"
                            for adapter in _node.network:
                                section += f"{adapter.get('type')} "\
                                           f"(IP: {adapter.get('ip')}, MAC: {adapter.get('mac')})\n"
                            sections.append(section)
                        # endregion

                        # region #-- get the parent details --#
                        if args.get_parent or all_args:
                            _LOGGER.debug("Preparing node parent details")
                            section = "Parent"
                            section += f"\n{'-' * len(section)}\n"
                            section += f"{_node.parent_name} ({_node.parent_ip})"
                            sections.append(section)
                        # endregion

                        # region #-- get the connected devices: format = name (IP) --#
                        if args.get_connected_devices or all_args:
                            _LOGGER.debug("Preparing node connected devices")
                            section = "Connected Devices"
                            section += f"\n{'-' * len(section)}\n"
                            device: dict
                            for device in _node.connected_devices:
                                section += f"{device.get('name')} ({device.get('ip')})\n"
                            sections.append(section.rstrip("\n"))
                        # endregion
                elif args.target == 'device':
                    _device: List = [device for device in _mesh.devices if device.name.lower() == args.name.lower()]
                    if not _device:
                        args_parser.error(f"Invalid device name ({args.name}).")
                    else:
                        _device: Device = _device[0]
                        # region #-- get the overview details --#
                        if all_args:
                            _LOGGER.debug("Preparing device overview")
                            connected_adapters: List = [adapter.get('ip') for adapter in _device.connected_adapters]
                            section = "Overview"
                            section += f"\n{'-' * len(section)}\n"
                            section += f"Name: {_device.name}\n"\
                                       f"Online: {_device.status}\n"\
                                       f"IP: {','.join(connected_adapters)}\n"\
                                       f"Parent: {_device.parent_name}"
                            sections.append(section)
                        # endregion
        if sections:
            print("\n\n".join(sections))

if __name__ == "__main__":
    loop = asyncio.get_event_loop()
    loop.run_until_complete(main())
