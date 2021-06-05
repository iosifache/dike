"""Errors used in this module."""
from modules.utils.errors import Error


class InvalidSerializedFeaturesError(Error):
    """The submitted serialized features are invalid."""


class FailedPredictionError(Error):
    """The prediction for the given file failed."""


class TicketNotFoundError(Error):
    """The ticket was not found in the session of the server."""


class InvalidConnectionIDError(Error):
    # pylint: disable=line-too-long
    """No connection with a subordinate server, identified with this ID, could be found."""


class NoFreeServerFoundError(Error):
    """No free server to whom to delegate a task could be found."""


class InvalidNetworkError(Error):
    """The given network, in CIDR notation, is invalid."""


class DroppedCommandError(Error):
    """The current command was dropped due to timeout or internal error."""


class NoSampleToScanError(Error):
    """No sample to scan was provided."""


class NoSampleToPublishError(Error):
    """No sample to publish was provided."""


class InvalidSimilarCountError(Error):
    """The similar_count parameter is invalid."""


class InvalidSampleTypeError(Error):
    """The submitted file has a type that is not supported by the platform."""


class PredictionNotCalledFirstError(Error):
    """The prediction route was not called before the feature getting one."""
