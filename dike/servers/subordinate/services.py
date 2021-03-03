import time
import typing
from threading import Lock

import rpyc
from modules.dataset_building.data_folder_scanner import DataFolderScanner
from modules.dataset_building.dataset_worker import DatasetWorker
from modules.utils.logger import LoggedMessageType, Logger


class SubordinateService(rpyc.Service):
    """Class implementing the RPyC service needed for the subordinate servers"""
    ALIASES: list
    _scanner: DataFolderScanner
    _busy: bool
    _busy_mutex: Lock
    _malware_families: dict
    _malware_benign_vote_ratio: int
    _min_ignored_percent: float

    def __init__(self, new_alias: str, malware_families: dict,
                 malware_benign_vote_ratio: int,
                 min_ignored_percent: float) -> None:
        """Initalizes the SubordinateService instance.

        For detailed explanation of the parameters not mentioned, see the
        documentation of the DataFolderScanner constructor and
        DataFolderScanner.start_scanning method.

        Args:
            new_alias (str): Alias used by the RPC service
        """
        self.ALIASES.append(new_alias)
        self._malware_families = malware_families
        self._malware_benign_vote_ratio = malware_benign_vote_ratio
        self._min_ignored_percent = min_ignored_percent

        # Default value of members
        self._scanner = DataFolderScanner()
        self._busy = False
        self._busy_mutex = Lock()

    # pylint: disable=unused-argument
    def on_connect(self, connection: rpyc.Connection) -> None:
        """Handles a new connection.

        Args:
            connection (rpyc.Connection): RPyC connection
        """
        Logger.log("Master server is now connected",
                   LoggedMessageType.BEGINNING)

    # pylint: disable=unused-argument
    def on_disconnect(self, connection: rpyc.Connection) -> None:
        """Handles a disconnect.

        Args:
            connection (rpyc.Connection): RPyC connection
        """
        Logger.log("Master server is now disconnected", LoggedMessageType.END)

    def is_busy(self) -> bool:
        """Checks if the server is busy.

        Returns:
            bool: Boolean indicating if the server is busy
        """
        return self._busy

    def update_malware_labels(self) -> None:
        """Updates the labels of the malware.
        """
        self._scanner.update_malware_labels()

    def start_data_scanning(self,
                            malware_folder: bool,
                            folder_watch_interval: int,
                            vt_scan_interval: int = 0,
                            vt_api_key: str = None) -> None:
        """Starts the watching of a folder corresponding to the benign files or
        to malware.

        For detailed explanation of the parameters, see the documentation of the
        DataFolderScanner constructor and DataFolderScanner.start_scanning
        method.
        """
        self._scanner.start_scanning(malware_folder, folder_watch_interval,
                                     vt_scan_interval)

    def stop_data_scanning(self) -> None:
        """Stops an already started scan of a folder.
        """
        self._scanner.stop_scanning()

    def create_dataset(self, min_malice: int,
                       desired_categories: typing.List[bool],
                       benign_ration: float, enties_count: int,
                       output_filename: str) -> None:
        """Creates a new dataset.

        For detailed explanation of the parameters, see the documentation of the
        DatasetWorker.create_dataset method.
        """
        DatasetWorker.create_dataset(min_malice, desired_categories,
                                     benign_ration, enties_count,
                                     output_filename)

    def train_new_model(self) -> None:
        """Simulates the training of a model.
        """
        # Enter critical section (one model training at a time)
        self._busy_mutex.acquire()
        self._busy = True

        # Print message
        Logger.log("Starting a model training", LoggedMessageType.BEGINNING)

        # Sleep to emulate intensive computin
        time.sleep(10)

        # End critical section
        self._busy = False
        self._busy_mutex.release()