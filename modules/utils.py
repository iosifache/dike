"""Utility functionalities"""

import yaml
import typing
from enum import Enum


class ConfigurationSpace(Enum):
    DATABASE = "database"


class ConfigurationWorker:
    """Singleton class that implements the worker with configuration files.

    This class helps working with standard configuration file, by providing
    operations such as opening, parsing and querying.
    """

    _instance: typing.TypeVar("ConfigurationWorker") = None
    _config: typing.Any = None

    def __new__(cls: typing.TypeVar("ConfigurationWorker"),
                filename: str) -> typing.TypeVar("ConfigurationWorker"):
        if (filename is None):
            return None
        if cls._instance is None:
            cls._instance = super(ConfigurationWorker, cls).__new__(cls)
            with open(filename) as config_file:
                cls._config = yaml.load(config_file, Loader=yaml.FullLoader)

        return cls._instance

    def get_full_configuration(self) -> typing.Any:
        """Gets the configuration stored in the given file

        Returns:
            A configuration object, represented by the given YAML
        """
        return self._config

    def get_configuration_space(self, space: ConfigurationSpace) -> typing.Any:
        """Gets a collection of configurations from a specific space

        Args:
            space: The configuration space that will be used for filtering
        
        Returns:
            A subset of the full configuration object
        """
        return self._config[space.value]