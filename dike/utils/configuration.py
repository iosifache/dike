import yaml
import os
from pypattyrn.creational.singleton import Singleton
import typing
from enum import Enum
from utils.logger import Logger, LoggedMessageType


class ConfigurationSpace(Enum):
    """Enumeration for available configuration spaces."""
    MASTER_SERVER = "master_server"
    SUBORDINATE_SERVER = "subordintate_server"
    EXTRACTORS = "extractors"
    DATASET_BUILDER = "dataset_builder"
    DATABASE = "database"
    SECRETS = "secrets"


class ConfigurationWorker(object, metaclass=Singleton):
    """Singleton class that implements the worker with configuration files.

    This class helps to work with the standard configuration file, by providing
    operations such as opening, parsing, and querying.
    """
    class _Loader(yaml.SafeLoader):
        def __init__(self, stream):
            self._root = os.path.split(stream.name)[0]
            super(ConfigurationWorker._Loader, self).__init__(stream)

        def include(self, node):
            filename = os.path.join(self._root, self.construct_scalar(node))
            with open(filename, "r") as f:
                return yaml.load(f, ConfigurationWorker._Loader)

    _config: typing.Any = None

    def __init__(self, filename: str):
        """Initializes the ConfigurationWorker instance.

        Args:
            filename (str): Name of the configuration file

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