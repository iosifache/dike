"""Module containing the platform configuration"""

from enum import Enum


class Folders:
    """Class containing the folder structure

    The members without underscore at the beginning are the expored (useful)
    ones."""
    _ROOT = "/home/iosifache/Documents/dike/dike/"
    _CONFIGURATION = _ROOT + "configuration/"
    _CONFIGURATION_USER = _CONFIGURATION + "user/"
    _DATA = _ROOT + "data/"
    _DATA_DATASET = _DATA + "dataset/"
    _DATA_DATASET_FILES = _DATA_DATASET + "files/"
    _DATA_DATASET_LABELS = _DATA_DATASET + "labels/"
    _DATA_DATASET_OTHERS = _DATA_DATASET + "others/"
    _SCRIPTS = _ROOT + "scripts/"
    _SERVERS = _ROOT + "servers/"
    _SERVERS_SUBORDINATE = _SERVERS + "subordinate/"
    _SERVERS_SUBORDINATE_DATA = _SERVERS_SUBORDINATE + "data/"
    _SERVERS_SUBORDINATE_DATA_QILING = _SERVERS_SUBORDINATE_DATA + "qiling/"

    BENIGN_FILES = _DATA_DATASET_FILES + "benign/"
    MALICIOUS_FILES = _DATA_DATASET_FILES + "malware/"
    COLLECTED_FILES = _DATA_DATASET_FILES + "collected/"
    CUSTOM_DATASETS = _DATA_DATASET_LABELS + "custom/"
    MODELS = _DATA + "models/"
    MODEL_FMT = MODELS + "{}/"
    MODEL_PREPROCESSORS_FMT = MODEL_FMT + "preprocessors/"
    QILING_LOGS = _SERVERS_SUBORDINATE_DATA_QILING + "logs/"
    QILING_ROOTS = _SERVERS_SUBORDINATE_DATA_QILING + "rootfs/"
    GHIDRA = "/home/iosifache/Documents/Programs/ghidra/"
    GIDRA_PROJECT = _SERVERS_SUBORDINATE_DATA + "ghidra/"


class Files:
    """Class containing the relevant files

    The members without underscore at the beginning are the expored (useful)
    ones."""
    # Access of the private members only in the scope of this class, that is in
    # the same configuration module. pylint: disable=protected-access
    USER_CONFIGURATION = Folders._CONFIGURATION_USER + "config.yaml"
    MALWARE_LABELS = Folders._DATA_DATASET_LABELS + "malware.csv"
    BENIGN_LABELS = Folders._DATA_DATASET_LABELS + "benign.csv"
    MALWARE_HASHES = Folders._DATA_DATASET_OTHERS + "malware_hashes.txt"
    VT_DATA_FILE = Folders._DATA_DATASET_OTHERS + "vt_data.csv"
    MODEL_FEATURES_FMT = Folders.MODEL_FMT + "features.csv"
    MODEL_REDUCTION_MODEL_FMT = Folders.MODEL_FMT + "reduction.model"
    MODEL_PREPROCESSOR_MODEL_FMT = Folders.MODEL_PREPROCESSORS_FMT + "{}.model"
    MODEL_ML_MODEL_FMT = Folders.MODEL_FMT + "ml.model"
    MODEL_TRAINING_CONFIGURATION_FMT = Folders.MODEL_FMT + "training_configuration.yml"
    MODEL_EVALUATION_FMT = Folders.MODEL_FMT + "evaluation.json"
    MODEL_PREDICTION_CONFIGURATION_FMT = Folders.MODEL_FMT + "prediction_configuration.json"
    GHIDRA_HEADLESS_ANALYZER = Folders.GHIDRA + "support/analyzeHeadless"
    GHIDRA_EXTRACTION_SCRIPT = Folders._SCRIPTS + "delegate_ghidra.py"


class Parameters:
    """Class containing the configuration parameter"""
    class Dataset:
        """Class containing the configuration for datasets"""
        class ConfigurationKeys(Enum):
            """Class containing the mandatory keys from the user configuration
            of a dataset

            The constants whose names does not ends in underscore are the one
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

    class FeatureExtraction:
        """Class containing the configuration for feature extraction"""
        class Qiling:
            """Class containing the configuration for Qiling"""
            LOG_EXTENSION = "qlog"
            API_CALLS_REGEX = r"^((\w)+)\("

        class VirusTotal:
            """Class containing the configuration for VirusTotal"""
            ANTIVIRUS_MALWARE_CATEGORIES = ["malicious", "suspicious"]

        # Need to be synced with the one from delegate_ghidra.py script
        class Ghidra:
            """Class containing the configuration for Ghidra automatic
            feature extraction"""
            PROJECT_NAME = "project"
            COMMAND_FMT = Files.GHIDRA_HEADLESS_ANALYZER + " " + \
                Folders.GIDRA_PROJECT + " " + PROJECT_NAME + \
                " -import {} -overwrite -postscript " + \
                Files.GHIDRA_EXTRACTION_SCRIPT + " {} {}"
            OPCODES_LINE_START = "OPCODES: "
            APIS_LINE_START = "APIS: "
            ITEMS_DELIMITATOR = ","

    class ModelsManagement:
        """Class containing the configuration for the management of models"""
        class ConfigurationKeys(Enum):
            """Class containing the mandatory keys from the user configuration
            of a pipeline

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
            """Class containing the configuration for models training"""
            SCALAR_MODEL_NAME = "scalar"
            MODEL_EXTENSION = ".model"
            JSON_FILES_INDENT_SPACES = 4

        class Evaluation:
            """Class containing the configuration for models evaluation"""
            SAMPLING_STEPS_FOR_PLOTS = 10
            SAMPLING_STEPS_FOR_HISTOGRAM = 100

        class Retraining:
            """Class containing the configuration for models retraining"""
            RETRAINED_FOLDER_PREFIX = "_retrain"

    class Servers:
        """Class containing the configuration for platform servers"""
        class Master:
            """Class containing the configuration for the master server"""
            class CLICommands:
                """Class encapsulating the commands from the CLI"""
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

                CLEAR = "clear"
                EXIT = "exit"

        class PredictorCollector:
            """Class containing the configuration for the predictor-collector
            server"""
            class Statuses:
                """Class containing the request statusses"""
                SUCCESS = "success"
                UNFINISHED = "unfinished"
                ERROR = "error"
