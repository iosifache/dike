"""Module working with configuration files

Usage example:

    configuration = ConfigurationWorker()
    secrets_config = full_config.get_configuration_space(
        ConfigurationSpace.SECRETS)

"""

import os
import typing
from enum import Enum

import yaml
from configuration.platform import Files
from modules.utils.errors import (ConfigurationFileNotFoundError,
                                  ConfigurationKeyNotFoundError)
from modules.utils.logger import LoggedMessageType, Logger


class ConfigurationSpace(Enum):
    """Enumeration for available configuration spaces"""
    MASTER_SERVER = "master_server"
    SUBORDINATE_SERVER = "subordintate_server"
    PREDICTOR_COLLECTOR_SERVER = "predictor_collector_server"
    EXTRACTORS = "extractors"
    DATASET_BUILDER = "dataset_builder"
    PREPROCESSORS = "preprocessors"
    MACHINE_LEARNING = "machine_learning"
    DATABASE = "database"
    SECRETS = "secrets"


class ConfigurationWorker(object):
    """Singleton class that implements the worker with configuration files.

    This class helps to work with the standard configuration file, by providing
    operations such as opening, parsing, and querying.
    """
    class _Loader(yaml.SafeLoader):
        def __init__(self, stream) -> None:
            self._root = os.path.split(stream.name)[0]

            # pylint: disable=protected-access
            super(ConfigurationWorker._Loader, self).__init__(stream)

        # pylint: disable=missing-function-docstring
        def include(self, node):
            filename = os.path.join(self._root, self.construct_scalar(node))
            with open(filename, "r") as file:
                # pylint: disable=protected-access
                return yaml.load(file, ConfigurationWorker._Loader)

    _instance: "ConfigurationWorker" = None
    _filename: str = None
    _config: typing.Any = None

    def __new__(cls, filename: str = Files.USER_CONFIGURATION):
        """Creates a new ConfigurationWorker instance.

        Args:
            filename (str, optional): Name of the configuration file. Mentioned
                ony on the singleton instanciation. Defaults to
                Files.USER_CONFIGURATION, if the configuration was already
                readed in other part of the program or if the platform's default
                configuration file should be used.

        Raises:
            ConfigurationFileNotFoundError: The configuration file could not be
                found or opened.
        """
        if (cls._instance is None) or (cls._filename
                                       and cls._filename != filename):
            # Create the class instance
            cls._instance = super(ConfigurationWorker, cls).__new__(cls)

            # Set the filename
            cls._filename = filename

            # Add the custom YAML loader
            ConfigurationWorker._Loader.add_constructor(
                '!include', ConfigurationWorker._Loader.include)

            # Try to read the configuration from the given file
            try:
                config_file = open(filename, "r")
                cls._config = yaml.load(config_file,
                                        Loader=ConfigurationWorker._Loader)
            except:
                raise ConfigurationFileNotFoundError()

            Logger().log("Configuration file imported",
                         LoggedMessageType.SUCCESS)

        return cls._instance

    def get_full_configuration(self) -> typing.Any:
        """Gets the configuration stored in the given file.

        Returns:
            typing.Any: Configuration object, represented by the given YAML file
        """
        return self._config

    def get_configuration_space(self, space: ConfigurationSpace) -> typing.Any:
        """Gets a collection of configurations from a specific space.

        Args:
            space (ConfigurationSpace): Configuration space that will be used
                                        for filtering

        Returns:
            typing.Any: Subset of the full configuration object

        Raises:
            ConfigurationKeyNotFoundError: The requested key from the
                configuration file could not be found.
        """
        try:
            return self._config[space.value]
        except KeyError:
            raise ConfigurationKeyNotFoundError()
