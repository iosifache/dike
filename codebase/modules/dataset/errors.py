"""Errors used in this module."""

from modules.utils.errors import Error


class DatasetConfigurationFileNotFoundError(Error):
    """The configuration file of the dataset could not be found or opened."""


class DatasetConfigurationMandatoryKeysNotPresentError(Error):
    """The dataset configuration file does not contain all mandatory keys."""


class InsufficientEntriesForDatasetError(Error):
    """The dataset could not be build due to insufficient entries."""


class InvalidFileExtensionError(Error):
    # pylint: disable=line-too-long
    """The mentioned file extension from the dataset configuration file is invalid."""


class VirusTotalRequestError(Error):
    """The request to VirusTotal API failed."""
