"""Program testing the configuration module"""
import pytest
from modules.utils.configuration import ConfigurationSpace, ConfigurationWorker


def test_nonexistent_configuration_file_read():
    """Tests the failure of a read of an non-existent configuration file.

    An ConfigurationFileNotFoundError is expected, but the Exception is used to
    pass the pytest test."""
    with pytest.raises(Exception):
        ConfigurationWorker("path/to/nonexistent/config.yaml")


def test_nonexistent_configuration_space_read():
    """Tests the failure of a read of an existent configuration file and of a
    non-existent space from it.

    An ConfigurationKeyNotFoundError is expected, but the Exception is used to
    pass the pytest test."""
    configuration = ConfigurationWorker("tests/files/configuration.yaml")
    with pytest.raises(Exception):
        configuration.get_configuration_space(ConfigurationSpace.DATABASE)


def test_configuration_space_read():
    """Tests the read of an existent configuration file and of a space from it.
    """
    configuration = ConfigurationWorker("tests/files/configuration.yaml")
    secrets_config = configuration.get_configuration_space(
        ConfigurationSpace.SECRETS)
    assert secrets_config is not None, "Configuration space not corectly readed"
