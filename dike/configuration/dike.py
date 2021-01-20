class DikeConfig:
    # Folders
    SUBORDINATE_FOLDER = "subordinate/"
    DATA_FOLDER = SUBORDINATE_FOLDER + "data/"
    EXTRACTED_FEATURES_FOLDER = DATA_FOLDER + "extracted_features/"
    EXECUTABLES_DATASET_FOLDER = DATA_FOLDER + "malware_datasets/"
    CUSTOM_DATASETS_FOLDER = DATA_FOLDER + "custom_datasets/"
    MALWARE_DATASET_FOLDER = EXECUTABLES_DATASET_FOLDER + "malware/"
    BENIGN_DATASET_FOLDER = EXECUTABLES_DATASET_FOLDER + "benign/"
    QILING_FOLDER = DATA_FOLDER + "qiling/"
    QILING_ROOTFS_FOLDER = QILING_FOLDER + "rootfs/"
    QILING_LOGS_FOLDER = QILING_FOLDER + "logs/"

    # Files
    MALWARE_LABELS = DATA_FOLDER + "malware_labels.csv"
    BENIGN_LABELS = DATA_FOLDER + "benign_labels.csv"
    MALWARE_HASHES = DATA_FOLDER + "malware_hashes.txt"
    VT_DATA_FILE = DATA_FOLDER + "vt_data.csv"

    # Feature extraction related
    QILING_LOG_EXTENSION = "qlog"
    API_CALLS_REGEX = r"^((\w)+)\("

    # Dataset building related
    VT_ANTIVIRUS_MALWARE_CATEGORIES = ["malicious", "suspicious"]
    MALWARE_CATEGORIES_COUNT = 9