"""Representation of a mesh device"""

from .base import MeshBase


class Device(MeshBase):
    """Subclasses the base class

    Represents and user device in the mesh, i.e. not a node
    """

    def __init__(self, **kwargs):
        """Constructor

        :param kwargs: keyword arguments
        """
        self.__attributes = kwargs
        self.__device_id = self.__attributes.get("deviceID")
        super().__init__(**kwargs)
