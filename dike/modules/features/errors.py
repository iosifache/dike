"""Errors used in this module."""

from modules.utils.errors import Error


class FileToExtractFromNotFoundError(Error):
    # pylint: disable=line-too-long
    """The file given for the extraction process could not be found or opened."""
