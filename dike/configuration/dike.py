from enum import Enum


class DikeConfig:
    """Class containing the default configuration of the platform
    """
    # Folders
    DIKE_FOLDER = "/home/iosifache/Documents/dike/dike/"

    ## Cofiguration
    CONFIGURATION_FOLDER = DIKE_FOLDER + "configuration/"
    USER_CONFIGURATION_FOLDER = CONFIGURATION_FOLDER + "user/"

    ## Data
    DATA_FOLDER = DIKE_FOLDER + "data/"
    UPLOADED_CONFIGURATIONS_FOLDER = DATA_FOLDER + "configurations/"
    DATASETS_FOLDER = DATA_FOLDER + "datasets/"
    CUSTOM_DATASETS_FOLDER = DATASETS_FOLDER + "custom/"
    FULL_DATASET_FOLDER = DATASETS_FOLDER + "full/"
    MALWARE_DATASET_FOLDER = FULL_DATASET_FOLDER + "malware/"
    BENIGN_DATASET_FOLDER = FULL_DATASET_FOLDER + "benign/"
    TRAINED_MODELS_FOLDER = DATA_FOLDER + "trained_models/"
    TRAINED_MODELS_MODEL_FOLDER = TRAINED_MODELS_FOLDER + "{}"
    TRAINED_MODEL_PREPROCESSORS_FOLDER = TRAINED_MODELS_FOLDER + \
        "{}/preprocessors/"

    # Scripts
    SCRIPTS_FOLDER = DIKE_FOLDER + "scripts/"

    ## Servers
    SERVERS_FOLDER = DIKE_FOLDER + "servers/"
    MASTER_FOLDER = SERVERS_FOLDER + "master/"
    PREDICTION_FOLDER = SERVERS_FOLDER + "prediction/"

    ### Subordinate server
    SUBORDINATE_FOLDER = SERVERS_FOLDER + "subordinate/"

    #### Logs
    LOGS_FOLDER = SUBORDINATE_FOLDER + "logs/"
    QILING_FOLDER = LOGS_FOLDER + "qiling/"
    QILING_ROOTFS_FOLDER = QILING_FOLDER + "rootfs/"
    QILING_LOGS_FOLDER = QILING_FOLDER + "logs/"
    GHIDRA_PROJECT_FOLDER = LOGS_FOLDER + "ghidra/"
    GHIDRA_FOLDER = "/home/iosifache/Documents/Programs/ghidra/"

    # Files

    # Configuration
    USER_CONFIGURATON_FILE = USER_CONFIGURATION_FOLDER + "config.yaml"

    ## For files informations
    MALWARE_LABELS = FULL_DATASET_FOLDER + "malware_labels.csv"
    BENIGN_LABELS = FULL_DATASET_FOLDER + "benign_labels.csv"
    MALWARE_HASHES = FULL_DATASET_FOLDER + "malware_hashes.txt"
    VT_DATA_FILE = FULL_DATASET_FOLDER + "vt_data.csv"

    ## For trained models
    TRAINED_MODEL_FEATURES_FILE = TRAINED_MODELS_FOLDER + "{}/features.csv"
    TRAINED_MODEL_REDUCTION_MODEL = TRAINED_MODELS_FOLDER + "{}/reduction.model"
    TRAINED_MODEL_SCALAR_MODEL = "scalar"
    TRAINED_MODEL_PREPROCESSOR_MODEL = TRAINED_MODEL_PREPROCESSORS_FOLDER + \
        "{}.model"
    TRAINED_MODEL_MACHINE_LEARNING_MODEL = TRAINED_MODELS_FOLDER + "{}/ml.model"
    TRAINED_MODEL_TRAINING_CONFIGURATION = TRAINED_MODELS_FOLDER + \
        "{}/training_configuration.yml"
    TRAINED_MODEL_EVALUATION = TRAINED_MODELS_FOLDER + \
        "{}/evaluation.json"
    TRAINED_MODEL_PREDICTION_CONFIGURATION = TRAINED_MODELS_FOLDER + \
        "{}/prediction_configuration.json"

    ## Logs
    GHIDRA_HEADLESS_ANALYZER = GHIDRA_FOLDER + "support/analyzeHeadless"
    GHIDRA_EXTRACTION_SCRIPT = SCRIPTS_FOLDER + "delegate_ghidra.py"

    # Constants

    # For datasets
    DATASET_METADATA_LINE_START = "# "

    ## For feature extraction
    API_CALLS_REGEX = r"^((\w)+)\("
    VT_ANTIVIRUS_MALWARE_CATEGORIES = ["malicious", "suspicious"]

    ## For trained models evaluation
    SAMPLING_STEPS_FOR_PLOTS = 10
    SAMPLING_STEPS_FOR_HISTOGRAM = 100
    JSON_FILES_INDENT_SPACES = 4

    ## For models retraining
    RETRAIN_FOLDER_PREFIX = "_retrain"

    ## Qiling
    QILING_LOG_EXTENSION = "qlog"

    ## Ghidra (synced with the one from delegate_ghidra.py script)
    GHIDRA_PROJECT_NAME = "project"
    GHIDRA_ANALYSIS_COMMAND = GHIDRA_HEADLESS_ANALYZER + " " + \
        GHIDRA_PROJECT_FOLDER + " " + GHIDRA_PROJECT_NAME + \
        " -import {} -overwrite -postscript " + GHIDRA_EXTRACTION_SCRIPT + \
        " {} {}"
    GHIDRA_ANALYSIS_OPCODES_LINE_START = "OPCODES: "
    GHIDRA_ANALYSIS_APIS_LINE_START = "APIS: "
    GHIDRA_ANALYSIS_ITEMS_DELIMITATOR = ","

    class MandatoryConfigurationKeys(Enum):
        """Class containing the mandatory keys from the user configuration of a
        pipeline

        The constants whose names does not ends in underscore are the one
        required in the root of the configuration file. The rest of the keys are
        children of the root ones.
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

    class CLICommands(Enum):
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

        START_RETRAINING = "start_retraining"
        LIST_RETRAININGS = "list_retrainings"
        STOP_RETRAINING = "stop_retraining"

        CREATE_TICKET = "create_ticket"
        GET_TICKET = "get_ticket"
        LIST_TICKETS = "list_tickets"
        REMOVE_TICKET = "remove_ticket"

        CLEAR = "clear"
        EXIT = "exit"
