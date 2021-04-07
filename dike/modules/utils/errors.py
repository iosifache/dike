"""All platform-specific exceptions.

Usage example:

    # Raise and catch an error
    try:
        raise Error()
    except Error as e:
        print("Error caught!")
"""


class Error(Exception):
    """Generic error."""

    def __init__(self) -> None:
        """Initializes the Error instance."""
        # pylint: disable=bad-super-call
        super(Exception, self).__init__(self.__doc__)


class ConfigurationFileNotFoundError(Error):
    """The configuration file could not be found or opened."""


class ConfigurationSpaceNotFoundError(Error):
    """The requested space from the configuration file could not be found."""
