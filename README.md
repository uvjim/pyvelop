# pyvelop

A Python library for the Linksys Velop Mesh system

## Purpose

This library was built with the intention of allowing easy communication with the Linksys Velop Mesh system. Primarily,
it was built to support the [linksys_velop][1] custom component in [homeassistant][0].

## Installation

`pip install pyvelop`

## Quick Start

To get started you can use the following as a skeleton.

```python
import asyncio

from pyvelop.mesh import Mesh

async def main():
    mesh = None
    try:
        mesh = Mesh(node="192.168.1.1", password="my_password")
        await mesh.async_gather_details()

        print("Mesh Overview")
        print("-" * 13)
        print(f"# Nodes: {len(mesh.nodes)}")
        devices_online = [str(device.name) for device in mesh.devices if device.status]
        devices_offline = [str(device.name) for device in mesh.devices if not device.status]
        print(f"# Devices: {len(mesh.devices)} (Online: {len(devices_online)}  Offline: {len(devices_offline)})")
        print(f"Internet Connected: {mesh.wan_status}")
        print(f"WAN Adapter: {mesh.wan_mac} --> {mesh.wan_ip}")
        print(f"WAN DNS: {mesh.wan_dns}")
        print(f"Parental Control Enabled: {mesh.parental_control_enabled}")
        print(f"Guest Wi-Fi Enabled: {mesh.guest_wifi_enabled}")
        if mesh.guest_wifi_enabled:
            for idx, details in enumerate(mesh.guest_wifi_details):
                print(f"  {idx + 1}: {details}")
        print(f"Latest Speedtest results: {mesh.speedtest_results}")
        print(f"Currently checking for updates: {mesh.check_for_update_status}")
        print()

    except Exception:
        raise
    finally:
        if mesh:
            await mesh.close()


if __name__ == "__main__":
    loop = asyncio.get_event_loop()
    loop.run_until_complete(main())
```

# Disclaimer

This is **NOT** an official module, and it is **NOT** officially supported by the vendor.

<!-- Real Links -->

[0]: https://home-assistant.io/

[1]: https://github.com/uvjim/linksys_velop