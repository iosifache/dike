"""Folder structure of the platform."""


class Folders:
    """Class containing the relevant folders of the platforms.

    The members without underscore at the beginning are the exported (useful)
    ones. The tests folders are omitted.
    """

    _ROOT = "/home/iosifache/Documents/dike/dike/"
    _DATA = _ROOT + "data/"
    _DATA_USER_CONFIGURATION = _DATA + "configuration/"
    _DATA_DATASET = _DATA + "dataset/"
    _DATA_DATASET_FILES = _DATA_DATASET + "files/"
    _DATA_DATASET_LABELS = _DATA_DATASET + "labels/"
    _DATA_DATASET_OTHERS = _DATA_DATASET + "others/"
    _DATA_KEYSTORE = _DATA + "keystore/"
    _SCRIPTS = _ROOT + "scripts/"
    _SERVERS = _ROOT + "servers/"
    _SERVERS_SUBORDINATE = _SERVERS + "subordinate/"
    _SERVERS_SUBORDINATE_DATA = _SERVERS_SUBORDINATE + "data/"
    _SERVERS_SUBORDINATE_DATA_QILING = _SERVERS_SUBORDINATE_DATA + "qiling/"
    _TESTS = _ROOT + "tests/"

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
    GHIDRA_PROJECT = _SERVERS_SUBORDINATE_DATA + "ghidra/"


class Files:
    """Class containing the relevant files of the platform.

    The members without underscore at the beginning are the exported (useful)
    ones. The tests files are omitted.
    """

    # Access of the private members only in the scope of this class, that is in
    # the same configuration module. pylint: disable=protected-access
    API_CATEGORIZATION = Folders._DATA_USER_CONFIGURATION + "_apis.yaml"
    USER_CONFIGURATION = Folders._DATA_USER_CONFIGURATION + "configuration.yaml"
    SSL_CERTIFICATE = Folders._DATA_KEYSTORE + "certificate.pem"
    SSL_PRIVATE_KEY = Folders._DATA_KEYSTORE + "key.pem"
    MALWARE_LABELS = Folders._DATA_DATASET_LABELS + "malware.csv"
    BENIGN_LABELS = Folders._DATA_DATASET_LABELS + "benign.csv"
    MALWARE_HASHES = Folders._DATA_DATASET_OTHERS + "malware_hashes.txt"
    VT_DATA_FILE = Folders._DATA_DATASET_OTHERS + "vt_data.csv"
    MODEL_DATASET_FMT = Folders.MODEL_FMT + "dataset.csv"
    MODEL_FEATURES_FMT = Folders.MODEL_FMT + "features.csv"
    MODEL_REDUCTION_MODEL_FMT = Folders.MODEL_FMT + "reduction.model"
    MODEL_PREPROCESSOR_MODEL_FMT = Folders.MODEL_PREPROCESSORS_FMT + "{}.model"
    MODEL_ML_MODEL_FMT = Folders.MODEL_FMT + "ml.model"
    MODEL_TRAINING_CONFIGURATION_FMT = (Folders.MODEL_FMT
                                        + "training_configuration.yml")
    MODEL_EVALUATION_FMT = Folders.MODEL_FMT + "evaluation.json"
    MODEL_PREDICTION_CONFIGURATION_FMT = (Folders.MODEL_FMT
                                          + "prediction_configuration.json")
    GHIDRA_HEADLESS_ANALYZER = Folders.GHIDRA + "support/analyzeHeadless"
    GHIDRA_EXTRACTION_SCRIPT = Folders._SCRIPTS + "delegate_ghidra.py"
    TESTS_USER_CONFIGURATION = Folders._TESTS + "configuration.yaml"
    TESTS_DATASET_CONFIGURATION = Folders._TESTS + "dataset.yaml"
    TESTS_MODEL_CONFIGURATION = Folders._TESTS + "model.yaml"
    TESTS_EXE_SAMPLE = Folders._TESTS + "sample.exe"
    TESTS_OLE_SAMPLE = Folders._TESTS + "sample.ole"
