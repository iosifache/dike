"""Types used in this module."""
from enum import Enum


class ConfigurationSpaces:
    """Class encapsulating all available spaces of the user configuration.

    The descending in the YAML structure is made until the package level is
    reached.
    """

    PACKAGES = "packages"
    DATASET = "packages.dataset"
    FEATURES = "packages.features"
    PREPROCESSING = "packages.preprocessing"
    MODELS = "packages.models"
    SERVERS = "servers"
    LEADER_SERVER = "servers.leader"
    SUBORDINATE_SERVER = "servers.subordinate"
    PREDICTOR_COLLECTOR_SERVER = "servers.predictor_collector"
    SECRETS = "secrets"


class LoggedMessageTypes(Enum):
    """Enumeration for all message types.

    Each type has an emoji attached.
    """

    STANDARD = ""
    BEGINNING = ":on:"
    END = ":end:"
    WORK = ":hammer:"
    SUCCESS = ":white_check_mark:"
    FAIL = ":no_entry_sign:"
    ERROR = ":boom:"
    NEW_MESSAGE = ":email:"
    INFORMATION = ":page_facing_up:"
    QUESTION = ":information_source:"
