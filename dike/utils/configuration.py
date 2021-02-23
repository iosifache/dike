import os
import typing
from enum import Enum

import yaml
from pypattyrn.creational.singleton import Singleton
from utils.logger import LoggedMessageType, Logger


class ConfigurationSpace(Enum):
    """Enumeration for available configuration spaces."""
    MASTER_SERVER = "master_server"
    SUBORDINATE_SERVER = "subordintate_server"
    EXTRACTORS = "extractors"
    DATASET_BUILDER = "dataset_builder"
    PREPROCESSORS = "preprocessors"
    MACHINE_LEARNING = "machine_learning"
    DATABASE = "database"
    SECRETS = "secrets"


class ConfigurationWorker(object, metaclass=Singleton):
    """Singleton class that implements the worker with configuration files.

    This class helps to work with the standard configuration file, by providing
    operations such as opening, parsing, and querying.
    """
    class _Loader(yaml.SafeLoader):
        def __init__(self, stream) -> None:
            self._root = os.path.split(stream.name)[0]

            # pylint: disable=protected-access
            super(ConfigurationWorker._Loader, self).__init__(stream)

        def include(self, node):
            """Same as the corresponding method of the parent class"""
            filename = os.path.join(self._root, self.construct_scalar(node))
            with open(filename, "r") as file:
                # pylint: disable=protected-access
                return yaml.load(file, ConfigurationWorker._Loader)

    _config: typing.Any = None

    def __init__(self, filename: str = None) -> None:
        """Initializes the ConfigurationWorker instance.

        Args:
            filename (str, optional): Name of the configuration file. Mentioned
                                      ony on the singleton instanciation.
                                      Defaults to None.

        Raises:
            FileNotFoundError: File does not exists
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
        Logger.log("Configuration file imported", LoggedMessageType.SUCCESS)

    def get_full_configuration(self) -> typing.Any:
        """Gets the configuration stored in the given file.

        Returns:
            typing.Any: Configuration object, represented by the given YAML
        """
        return self._config

    def get_configuration_space(self, space: ConfigurationSpace) -> typing.Any:
        """Gets a collection of configurations from a specific space.

        Args:
            space (ConfigurationSpace): Configuration space that will be used
                                        for filtering

        Returns:
            typing.Any: Subset of the full configuration object
        """
        return self._config[space.value]
