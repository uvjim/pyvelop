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
    with Mesh(node="192.168.1.1", password="my_password") as mesh:
        await mesh.async_gather_details()
        print(mesh.nodes)


if __name__ == "__main__":
    loop = asyncio.get_event_loop()
    loop.run_until_complete(main())
```

# Disclaimer

This is **NOT** an official module, and it is **NOT** officially supported by the vendor.

<!-- Real Links -->

[0]: https://home-assistant.io/

[1]: https://github.com/uvjim/linksys_velop