from enum import Enum


class Endpoint(Enum):
    """Class encapsulating all endpoints exported by the subordinate servers

    For each entry in the enumeration, the first element of the tuple is the
    name of the exported method and the second one a boolean indicating if the
    operation is asynchronous."""
    GET_EMPLOYMENT = ("get_employment", False)

    GET_LOGS = ("get_logs", False)
    REMOVE_LOGS = ("clear_logs", False)

    START_DATA_SCAN = ("start_data_scan", False)
    IS_DATA_SCAN_ACTIVE = ("is_data_scan_active", False)
    STOP_DATA_SCAN = ("stop_data_scan", False)

    UPDATE_MALWARE_LABELS = ("update_malware_labels", False)
    CREATE_DATASET = ("create_dataset", True)
    LIST_DATASETS = ("list_datasets", False)
    REMOVE_DATASET = ("remove_dataset", False)

    CREATE_MODEL = ("create_model", True)
    UPDATE_MODEL = ("update_model", False)
    LIST_MODELS = ("list_models", False)
    REMOVE_MODEL = ("remove_model", False)

    CREATE_RETRAINING = ("create_retraining", True)
    START_RETRAINING = ("start_retraining", False)
    LIST_RETRAININGS = ("list_retrainings", False)
    STOP_RETRAINING = ("stop_retraining", False)

    CREATE_TICKET = ("create_ticket", False)
    GET_TICKET = ("get_ticket", False)


class Employment(Enum):
    """Class encapslating all states of employment, produced by time-consuming
    tasks of a subordinate server"""
    AVAILABLE = 0
    GENERIC_EMPLOYMENT = 1
    UPDATING_MALWARE_LABELS = 2
    CREATING_DATASET = 3
    CREATING_MODEL = 4
    PREDICTING = 5
