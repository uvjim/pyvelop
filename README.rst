.. image:: https://img.shields.io/pypi/dm/pyvelop?style=for-the-badge
   :alt: PyPI - Downloads

.. image:: https://img.shields.io/pypi/v/pyvelop?style=for-the-badge
   :alt: PyPI - Version

.. image:: https://img.shields.io/github/v/release/uvjim/pyvelop?style=for-the-badge
   :alt: GitHub Release

.. image:: https://img.shields.io/github/downloads/uvjim/pyvelop/total
   :alt: GitHub Downloads (all assets, all releases)


pyvelop
=======

A Python library for the Linksys Velop Mesh system

Purpose
-------

This library was built with the intention of allowing easy communication with the Linksys Velop Mesh system. Primarily,
it was built to support the `linksys_velop <https://github.com/uvjim/linksys_velop>`_ custom component in `Home Assistant <https://home-assistant.io/>`_.

Installation
------------

``pip install pyvelop``

Quick Start
-----------

To get started you can use the following as a skeleton.

.. code:: python

    import asyncio

    from pyvelop.mesh import Mesh


    async def main():
        async with Mesh(node="192.168.1.1", password="my_password") as mesh:
            await mesh.async_initialise()
            print(mesh.nodes)


    if __name__ == "__main__":
        loop = asyncio.get_event_loop()
        loop.run_until_complete(main())

CLI
---

The library also has a CLI which can be used like so...

``pyvelop mesh details -a PRIMARY_NODE -p PASSWORD`` - *Lists all known details about the mesh.*

``pyvelop node details bedroom -a PRIMARY_NODE -p PASSWORD`` - *Lists all known details about the given node.*

``pyvelop --help`` - *show all available options*

Disclaimer
==========

This is **NOT** an official module, and it is **NOT** officially supported by the vendor.
