"""Utility functionalities"""

import yaml
import os
from pypattyrn.creational.singleton import Singleton
import typing
from enum import Enum


class ConfigurationSpace(Enum):
    """Enumeration for available configuration spaces."""
    EXTRACTORS = "extractors"
    MASTER_SERVER = "master_server"
    SUBORDINATE_SERVER = "subordintate_server"
    DATABASE = "database"


class ConfigurationWorker(object, metaclass=Singleton):
    """Singleton class that implements the worker with configuration files.

    This class helps working with standard configuration file, by providing
    operations such as opening, parsing and querying.
    """
    class _Loader(yaml.SafeLoader):
        """Custom YAML loader supporting other files includes"""
        def __init__(self, stream):
            self._root = os.path.split(stream.name)[0]
            super(ConfigurationWorker._Loader, self).__init__(stream)

        def include(self, node):
            filename = os.path.join(self._root, self.construct_scalar(node))
            with open(filename, "r") as f:
                return yaml.load(f, ConfigurationWorker._Loader)

    _config: typing.Any = None

    # TODO: log "{} configuration file imported"
    def __init__(self, filename: str) -> typing.TypeVar("ConfigurationWorker"):
        """Creates a new instance

        Args:
            filename: Name of the configuration file

        Raises:
            FileNotFoundError: File does not exists

        Returns:
            Instance of the class
        """
        if (filename is None):
            return None
        ConfigurationWorker._Loader.add_constructor(
            '!include', ConfigurationWorker._Loader.include)
        try:
            with open(filename) as config_file:
                self._config = yaml.load(config_file,
                                         Loader=ConfigurationWorker._Loader)
        except:
            raise FileNotFoundError()

    def get_full_configuration(self) -> typing.Any:
        """Gets the configuration stored in the given file.

        Returns:
            A configuration object, represented by the given YAML
        """
        return self._config

    def get_configuration_space(self, space: ConfigurationSpace) -> typing.Any:
        """Gets a collection of configurations from a specific space.

        Args:
            space: The configuration space that will be used for filtering

        Returns:
            A subset of the full configuration object
        """
        return self._config[space.value]