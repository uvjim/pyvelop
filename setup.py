"""Setup."""

# region #-- imports --#
from setuptools import find_packages, setup

from pyvelop.const import _PACKAGE_AUTHOR, _PACKAGE_NAME, _PACKAGE_VERSION

# endregion

with open("README.rst", "r", encoding="utf-8") as f:
    long_description: str = f.read()

setup(
    name=_PACKAGE_NAME,
    version=_PACKAGE_VERSION,
    author=_PACKAGE_AUTHOR,
    description="A Python library for the Linksys Velop Mesh system",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/uvjim/pyvelop",
    packages=find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
    ],
    install_requires=[
        "aiohttp",
    ],
)
