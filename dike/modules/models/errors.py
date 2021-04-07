"""Errors used in this module."""

from modules.utils.errors import Error


class ModelConfigurationFileNotFoundError(Error):
    """The configuration file of the model could not be found or opened."""


class ModelConfigurationMandatoryKeysNotPresentError(Error):
    """The model configuration file does not contain all mandatory keys."""


class InvalidModelObjectiveError(Error):
    # pylint: disable=line-too-long
    """The objective from the configuration file of the model is invalid."""


class InvalidReductionAlgorithmError(Error):
    # pylint: disable=line-too-long
    """The dimensionality reduction algorithm and its parameters from the configuration are invalid."""


class InvalidMachineLearningAlgorithmError(Error):
    """The machine learning algorithm from the configuration is invalid."""


class InvalidExtractorError(Error):
    """Some extractors from the configuration are invalid."""


class InvalidNumberOfPreprocessorsForExtractorsError(Error):
    # pylint: disable=line-too-long
    """The numbers of preprocessors from the configuration do not match the number required by the extractors."""


class InvalidTypeOfPreprocessorForExtractorError(Error):
    # pylint: disable=line-too-long
    """The types of the preprocessors from the configuration does not match the ones accepted by the extractors."""


class ModelDatasetNotFoundError(Error):
    """The dataset file from the configuration does not exist."""


class ModelToLoadNotFoundError(Error):
    """The model to load could not be found or opened."""
