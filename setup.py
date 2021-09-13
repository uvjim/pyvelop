from setuptools import setup, find_packages

with open("README.md", "r") as f:
    long_description: str = f.read()

setup(
    name="pyvelop",
    version="2021.9.2",
    author="uvjim",
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
