"""Manager of the user configuration.

Usage example:

    # Create a configuration manager
    configuration = ConfigurationManager()

    # Get the full configuration stored in the user file
    full_config = configuration.get_full_configuration()
"""
import os

import yaml
from modules.configuration.folder_structure import Files
from modules.utils.errors import (ConfigurationFileNotFoundError,
                                  ConfigurationSpaceNotFoundError)
from modules.utils.logger import Logger
from modules.utils.types import ConfigurationSpaces, LoggedMessageTypes


class ConfigurationManager(object):
    """Class implementing the manager of the user configuration files."""

    class _Loader(yaml.SafeLoader):

        def __init__(self, stream) -> None:
            self._root = os.path.split(stream.name)[0]

            # pylint: disable=protected-access
            super(ConfigurationManager._Loader, self).__init__(stream)

        # pylint: disable=missing-function-docstring
        def include(self, node):
            filename = os.path.join(self._root, self.construct_scalar(node))
            with open(filename, "r") as file:
                # pylint: disable=protected-access
                return yaml.load(file, ConfigurationManager._Loader)  # nosec

    _instance: "ConfigurationManager" = None
    _filename: str = None
    _configuration: dict = None

    def __new__(cls, filename: str = None) -> None:
        """Creates a new ConfigurationManager instance.

        Args:
            filename (str): Name of the configuration file, mentioned only on
                the singleton instantiation. Defaults to None, if the
                configuration was already read in other parts of the program or
                if the platform's default configuration file should be used.

        Raises:
            ConfigurationFileNotFoundError: The configuration file could not be
                found or opened.

        Returns:
            ConfigurationManager: Singleton instance
        """
        if filename is None:
            filename = Files.USER_CONFIGURATION

        if ((cls._instance is None)
                or (cls._filename and cls._filename != filename)):
            cls._instance = super(ConfigurationManager, cls).__new__(cls)
            cls._filename = filename

            # Add the custom YAML loader
            ConfigurationManager._Loader.add_constructor(
                '!include', ConfigurationManager._Loader.include)

            try:
                with open(filename, "r") as config_file:
                    cls._configuration = yaml.load(  # nosec
                        config_file,
                        Loader=ConfigurationManager._Loader)
            except Exception:
                raise ConfigurationFileNotFoundError()

            Logger().log("The configuration file was imported.",
                         LoggedMessageTypes.SUCCESS)

        return cls._instance

    def get_full_configuration(self) -> dict:
        """Gets the full configuration.

        Returns:
            dict: Full configuration
        """
        Logger().log("The entire configuration was read.",
                     LoggedMessageTypes.SUCCESS)

        return self._configuration

    def get_space(self, space: ConfigurationSpaces) -> dict:
        """Gets the configuration from a specific space.

        Args:
            space (ConfigurationSpaces): Configuration space used for filtering

        Returns:
            dict: Configuration from the given space

        Raises:
            ConfigurationSpaceNotFoundError: The requested space from the
                configuration file could not be found.
        """
        try:
            current_config = self._configuration
            if "." in space:
                spaces = space.split(".")

                for inner_space in spaces:
                    # pylint: disable=unsubscriptable-object
                    current_config = current_config[inner_space]
            else:
                current_config = current_config[space]  # pylint: disable=unsubscriptable-object

            Logger().log("The configuration from a space was read.",
                         LoggedMessageTypes.SUCCESS)

            return current_config
        except KeyError:
            raise ConfigurationSpaceNotFoundError()
