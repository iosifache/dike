import rpyc
from threading import Lock
import time
import typing
from subordinate.modules.dataset_building.data_folder_scanner import DataFolderScanner
from subordinate.modules.dataset_building.dataset_worker import DatasetWorker
from utils.logger import Logger, LoggerMessageType


class SubordinateService(rpyc.Service):
    """Class implementing the RPyC service needed for the subordinate servers"""
    _scanner: DataFolderScanner = None
    _busy: bool = False
    _busy_mutex: Lock = Lock()
    ALIASES: list = []

    def on_connect(self, connection: rpyc.Connection) -> None:
        """Handles a new connection.

        Args:
            connection (rpyc.Connection): RPyC connection
        """
        Logger.log("Master server is now connected",
                   LoggerMessageType.BEGINNING)

    def on_disconnect(self, connection: rpyc.Connection) -> None:
        """Handles a disconnect.

        Args:
            connection (rpyc.Connection): RPyC connection
        """
        Logger.log("Master server is now disconnected", LoggerMessageType.END)

    def is_busy(self) -> bool:
        """Checks if the server is busy.

        Returns:
            bool: Boolean indicating if the server is busy
        """
        return self._busy

    def start_data_scanning(self,
                            malware_folder: bool,
                            folder_watch_interval: int,
                            vt_scan_interval: int = 0,
                            vt_api_key: str = None):
        """Starts the watching of a folder corresponding to the benign files or
        to malware.

        For detailed explanation of the parameters, see the documentation of the
        DataFolderScanner constructor and DataFolderScanner.start_scanning
        method.
        """
        self._scanner = DataFolderScanner(vt_api_key)
        self._scanner.start_scanning(malware_folder, folder_watch_interval,
                                     vt_scan_interval)

    def stop_data_scanning(self):
        """Stops an already started scan of a folder
        """
        self._scanner.stop_scanning()

    def create_dataset(self, min_malice: int,
                       desired_categories: typing.List[bool],
                       benign_ration: float, enties_count: int,
                       output_filename: str):
        """Creates a new dataset

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
        Logger.log("Starting a model training", LoggerMessageType.START)

        # Sleep to emulate intensive computin
        time.sleep(10)

        # End critical section
        self._busy = False
        self._busy_mutex.release()