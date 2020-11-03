"""Utility functionalities"""

import yaml
import typing
from enum import Enum


class ConfigurationSpace(Enum):
    """Enumeration for available configuration spaces."""
    EXTRACTORS = "extractors"
    DATABASE = "database"


class ConfigurationWorker:
    """Singleton class that implements the worker with configuration files.

    This class helps working with standard configuration file, by providing
    operations such as opening, parsing and querying.
    """

    _instance: typing.TypeVar("ConfigurationWorker") = None
    _config: typing.Any = None

    # TODO: check if file exists
    # TODO: log "Configuration file imported"
    def __new__(cls: typing.TypeVar("ConfigurationWorker"),
                filename: str) -> typing.TypeVar("ConfigurationWorker"):
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
        if cls._instance is None:
            cls._instance = super(ConfigurationWorker, cls).__new__(cls)
            try:
                with open(filename) as config_file:
                    cls._config = yaml.load(config_file,
                                            Loader=yaml.FullLoader)
            except:
                raise FileNotFoundError()
        return cls._instance

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