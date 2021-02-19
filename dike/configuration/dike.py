from enum import Enum


class DikeConfig:
    """Class containing the default configuration of the platform
    """
    # Folders
    DIKE_FOLDER = "/home/iosifache/Documents/dike/dike/"
    SUBORDINATE_FOLDER = DIKE_FOLDER + "subordinate/"
    DATA_FOLDER = SUBORDINATE_FOLDER + "data/"
    DATASETS_FOLDER = DATA_FOLDER + "datasets/"
    CUSTOM_DATASETS_FOLDER = DATASETS_FOLDER + "custom/"
    FULL_DATASET_FOLDER = DATASETS_FOLDER + "full/"
    MALWARE_DATASET_FOLDER = FULL_DATASET_FOLDER + "malware/"
    BENIGN_DATASET_FOLDER = FULL_DATASET_FOLDER + "benign/"
    QILING_FOLDER = DATA_FOLDER + "qiling/"
    QILING_ROOTFS_FOLDER = QILING_FOLDER + "rootfs/"
    QILING_LOGS_FOLDER = QILING_FOLDER + "logs/"
    TRAINED_MODELS_FOLDER = DATA_FOLDER + "trained_models/"
    TRAINED_MODEL_PREPROCESSORS_FOLDER = TRAINED_MODELS_FOLDER \
        + "{}/preprocessors/"

    # Files
    MALWARE_LABELS = FULL_DATASET_FOLDER + "malware_labels.csv"
    BENIGN_LABELS = FULL_DATASET_FOLDER + "benign_labels.csv"
    MALWARE_HASHES = FULL_DATASET_FOLDER + "malware_hashes.txt"
    VT_DATA_FILE = FULL_DATASET_FOLDER + "vt_data.csv"
    TRAINED_MODEL_FEATURES_FILE = TRAINED_MODELS_FOLDER + "{}/features.csv"
    TRAINED_MODEL_REDUCTION_MODEL = TRAINED_MODELS_FOLDER + "{}/reduction.model"
    TRAINED_MODEL_MACHINE_LEARNING_MODEL = TRAINED_MODELS_FOLDER + "{}/ml.model"
    TRAINED_MODEL_PREPROCESSOR_MODEL = TRAINED_MODEL_PREPROCESSORS_FOLDER \
        + "{}.model"
    TRAINED_MODEL_SCALAR_MODEL = "scalar"

    # Constants
    QILING_LOG_EXTENSION = "qlog"
    API_CALLS_REGEX = r"^((\w)+)\("
    VT_ANTIVIRUS_MALWARE_CATEGORIES = ["malicious", "suspicious"]
    MALWARE_CATEGORIES_COUNT = 9

    class MandatoryConfigurationKeys(Enum):
        """Class containing the mandatory keys from the user configuration of a
        pipeline

        The constants whose names doesn't ends in underscore are the one
        required in the root of the configuration file. The rest of the keys are
        children of the root ones.
        """
        DATASET = "dataset"
        MODEL_OBJECTIVE = "model_objective"
        EXTRACTORS_PREPROCESSORS = "extractors_preprocessors"
        DIMENSIONALITY_REDUCTION = "dimensionality_reduction"
        DIMENSIONALITY_REDUCTION_ALGORITHM_ = "algorithm"
        DIMENSIONALITY_REDUCTION_MIN_VARIANCE_ = "min_variance"
        MACHINE_LEARNING = "machine_learning"
        MACHINE_LEARNING_ALGORITHM_ = "algorithm"
