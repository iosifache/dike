"""Parameters of all components of the platform."""

from enum import Enum

from modules.configuration.folder_structure import Files, Folders


class Packages:
    """Class configuring the packages."""

    class Dataset:
        """Class configuring the datasets."""

        class ConfigurationKeys(Enum):
            """Class containing the mandatory keys from dataset configuration.

            The constants whose names do not end in underscore are the one
            required in the root of the configuration file. The rest of the keys
            are optional.
            """

            FILE_EXTENSION = "file_extension"
            ENTRIES_COUNT = "entries_count"
            MIN_MALICE = "min_malice"
            DESIRED_FAMILIES = "desired_families"
            BENIGN_RATIO = "benign_ratio"
            OUTPUT_FILENAME = "output_filename"
            DESCRIPTION_ = "description"

        METADATA_LINE_START = "# "

    class Features:
        """Class configuring the feature extraction."""

        class Qiling:
            """Class configuring Qiling."""

            LOG_EXTENSION = "qlog"
            API_CALLS_REGEX = r"^((\w)+)\("

        class VirusTotal:
            """Class configuring VirusTotal."""

            ANTIVIRUS_MALWARE_CATEGORIES = ["malicious", "suspicious"]

        # Need to be synced with the one from delegate_ghidra.py script
        class Ghidra:
            """Class containing the Ghidra configuration."""

            PROJECT_NAME = "project"
            COMMAND_FMT = Files.GHIDRA_HEADLESS_ANALYZER + " " + \
                Folders.GHIDRA_PROJECT + " " + PROJECT_NAME + \
                " -import {} -overwrite -postscript " + \
                Files.GHIDRA_EXTRACTION_SCRIPT + " {} {}"
            OPCODES_LINE_START = "OPCODES: "
            APIS_LINE_START = "APIS: "
            ITEMS_DELIMITATOR = ","

    class Models:
        """Class configuring the management of models."""

        class ConfigurationKeys(Enum):
            """Class containing the mandatory keys of models configuration.

            The constants whose names does not ends in underscore are the one
            required in the root of the configuration file. The rest of the keys
            are children of the root ones.
            """

            DATASET = "dataset"
            DATASET_FILENAME_ = "filename"
            MODEL_DETAILS = "model_details"
            MODEL_DETAILS_OBJECTIVE_ = "objective"
            MODEL_DETAILS_RETRAINING_ = "retraining_needed"
            EXTRACTORS_PREPROCESSORS = "extractors_preprocessors"
            DIMENSIONALITY_REDUCTION = "dimensionality_reduction"
            DIMENSIONALITY_REDUCTION_ALGORITHM_ = "algorithm"
            DIMENSIONALITY_REDUCTION_MIN_VARIANCE_ = "min_variance"
            MACHINE_LEARNING = "machine_learning"
            MACHINE_LEARNING_ALGORITHM_ = "algorithm"
            MACHINE_LEARNING_SPLIT_RADIO_ = "split_ratio"

        class Training:
            """Class configuring the models training."""

            SCALAR_MODEL_NAME = "scalar"
            MODEL_EXTENSION = ".model"
            JSON_FILES_INDENT_SPACES = 4

        class Evaluation:
            """Class configuring the models' evaluation."""

            SAMPLING_STEPS_FOR_PLOTS = 10
            SAMPLING_STEPS_FOR_HISTOGRAM = 100

        class Retraining:
            """Class configuring the models retraining."""

            RETRAINED_FOLDER_PREFIX = "_retrain"

    class Utils:
        """Class configuring the utilities."""

        class Crypto:
            """Class configuring the cryptographic functionalities."""

            RECOMMENDED_MIN_HASH_LENGTH = 32


class Servers:
    """Class configuring the servers."""

    class Leader:
        """Class configuring the leader server."""

        class CLICommands:
            """Class encapsulating the commands from the CLI."""

            CREATE_CONNECTION = "create_connection"
            CREATE_CONNECTIONS = "create_connections"
            REMOVE_CONNECTION = "remove_connection"
            REMOVE_ALL_CONNECTIONS = "remove_all_connections"
            LIST_CONNECTIONS = "list_connections"

            GET_LOGS = "get_logs"
            REMOVE_LOGS = "remove_logs"

            START_DATA_SCAN = "start_data_scan"
            STOP_DATA_SCAN = "stop_data_scan"
            LIST_DATA_SCANS = "list_data_scans"

            UPDATE_MALWARE_LABELS = "update_malware_labels"
            CREATE_DATASET = "create_dataset"
            LIST_DATASETS = "list_datasets"
            REMOVE_DATASET = "remove_dataset"

            CREATE_MODEL = "create_model"
            UPDATE_MODEL = "update_model"
            LIST_MODELS = "list_models"
            REMOVE_MODEL = "remove_model"

            CREATE_RETRAINING = "create_retraining"
            START_RETRAINING = "start_retraining"
            LIST_RETRAININGS = "list_retrainings"
            STOP_RETRAINING = "stop_retraining"

            CREATE_TICKET = "create_ticket"
            GET_TICKET = "get_ticket"
            LIST_TICKETS = "list_tickets"
            REMOVE_TICKET = "remove_ticket"

            MANUAL = "manual"
            CLEAR = "clear"
            EXIT = "exit"

    class PredictorCollector:
        """Class configuring the predictor-collector server."""

        class Routes:
            """Class containing the routes implemented by the API."""

            DEFAULT = "/"

            GET_MALWARE_FAMILIES = "/get_malware_families"
            GET_EVALUATION = "/get_evaluation"
            GET_CONFIGURATION = "/get_configuration"

            GET_FEATURES = "/get_features"

            CREATE_TICKET = "/create_ticket"
            GET_TICKET = "/get_ticket"

            PUBLISH = "/publish"

        class Statuses:
            """Class containing the request statuses."""

            SUCCESS = "success"
            UNFINISHED = "unfinished"
            ERROR = "error"
