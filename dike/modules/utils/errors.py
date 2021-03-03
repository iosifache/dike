"""Module declaring the errors from all other modules

Usage example:

    try:
        raise Error()
    except Error as e:
        print("Error catched!")
"""


class Error(Exception):
    """Generic error"""
    def __init__(self) -> None:
        # pylint: disable=bad-super-call
        super(Exception, self).__init__(self.__doc__)


class ConfigurationFileNotFoundError(Error):
    """The configuration file could not be found or opened."""


class ConfigurationKeyNotFoundError(Error):
    """The requested key from the configuration file could not be found."""


class VirusTotalRequestError(Error):
    """The request to VirusTotal API failed."""


class FileToExtractFromNotFoundError(Error):
    """The file given for the extraction process could not be found or
    opened."""


class ModelConfigurationFileNotFoundError(Error):
    """The configuration file of the model could not be found or opened."""


class ModelToLoadNotFoundError(Error):
    """The model to load could not be found or opened."""
