from enum import Enum


class DikeConfig:
    """Class containing the default configuration of the platform
    """
    # Folders
    DIKE_FOLDER = "/home/iosifache/Documents/dike/dike/"

    ## Data
    DATA_FOLDER = DIKE_FOLDER + "data/"
    DATASETS_FOLDER = DATA_FOLDER + "datasets/"
    CUSTOM_DATASETS_FOLDER = DATASETS_FOLDER + "custom/"
    FULL_DATASET_FOLDER = DATASETS_FOLDER + "full/"
    MALWARE_DATASET_FOLDER = FULL_DATASET_FOLDER + "malware/"
    BENIGN_DATASET_FOLDER = FULL_DATASET_FOLDER + "benign/"
    TRAINED_MODELS_FOLDER = DATA_FOLDER + "trained_models/"
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

    ## For feature extraction
    API_CALLS_REGEX = r"^((\w)+)\("
    VT_ANTIVIRUS_MALWARE_CATEGORIES = ["malicious", "suspicious"]
    MALWARE_CATEGORIES_COUNT = 9

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

        The constants whose names doesn't ends in underscore are the one
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
