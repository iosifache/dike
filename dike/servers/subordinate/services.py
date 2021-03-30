"""Module implementing the service for subordinate servers

Usage example:

    from rpyc.modules.utils.server import ThreadPoolServer

    server = ThreadPoolServer(SubordinateService, hostname="0.0.0.0", port=80)
    server.start()
"""
import os
import tempfile
import typing
from threading import Lock, Thread

import rpyc
from modules.dataset.data_folder_scanner import DataFolderScanner
from modules.dataset.dataset_worker import DatasetWorker
from modules.dataset.types import AnalyzedFileTypes
from modules.models.core import ModelsManagementCore
from modules.utils.configuration import ConfigurationSpace, ConfigurationWorker
from modules.utils.errors import Error
from modules.utils.logger import LoggedMessageType, Logger
from pypattyrn.creational.singleton import Singleton
from servers.subordinate.types import Employment


def wrapped_functionality(employment_state: Employment = None):
    """Marks a function as time consuming.

    Args:
        employment_state (Employment): Employment state while executing the
            operations
    """
    def inner_decorator(function: typing.Callable):
        def wrapper(*args, **kwargs):
            instance = SubordinateService()

            # Enter critical section
            # pylint: disable=protected-access
            if employment_state:
                instance._employment_state_mutex.acquire()
                instance._employment_state = employment_state

            try:
                result = function(*args, **kwargs)
            except Error as error:

                # Log error
                Logger().log(str(error), LoggedMessageType.ERROR)

                return None

            # Leave critical section
            if employment_state:
                instance._employment_state = Employment.AVAILABLE
                instance._employment_state_mutex.release()

            return result

        return wrapper

    return inner_decorator


class SubordinateService(rpyc.Service, metaclass=Singleton):
    """Class implementing the RPyC service needed by the subordinate servers"""
    _scanner: DataFolderScanner
    _model_management_core: ModelsManagementCore
    _employment_state: Employment
    _employment_state_mutex: Lock
    _malware_families: dict
    _malware_benign_vote_ratio: int
    _min_ignored_percent: float

    def __init__(self) -> None:
        """Initalizes the SubordinateService instance."""
        # Get configuration
        config = ConfigurationWorker()
        dataset_config = config.get_configuration_space(
            ConfigurationSpace.DATASET_BUILDER)

        # Populate the members based on the configuration
        self._malware_families = dataset_config["malware_families"]
        self._malware_benign_vote_ratio = dataset_config[
            "malware_benign_vote_ratio"]
        self._min_ignored_percent = dataset_config["min_ignored_percent"]

        # Default value of members
        self._employment_state = Employment.AVAILABLE
        self._employment_state_mutex = Lock()
        self._scanner = DataFolderScanner()
        self._model_management_core = ModelsManagementCore()

    # pylint: disable=unused-argument
    def on_connect(self, connection: rpyc.Connection) -> None:
        """Handles a new connection.

        Args:
            connection (rpyc.Connection): RPyC connection
        """

    # pylint: disable=unused-argument
    def on_disconnect(self, connection: rpyc.Connection) -> None:
        """Handles a disconnect.

        Args:
            connection (rpyc.Connection): RPyC connection
        """

    def get_employment(self) -> Employment:
        """Checks what the server does.

        Returns:
            Employment: Employment state
        """
        return self._employment_state

    @wrapped_functionality()
    def get_logs(self) -> str:
        """See the Logger.get_buffer() method."""
        return Logger().get_buffer(False)

    @wrapped_functionality()
    def clear_logs(self) -> bool:
        """See the Logger.get_buffer() method."""
        Logger().get_buffer(True)

        return True

    @wrapped_functionality()
    def start_data_scan(self,
                        malware_folder: bool,
                        folder_watch_interval: int,
                        vt_scan_interval: int = 0) -> bool:
        """See the DataFolderScanner.start_scanning() method."""
        self._scanner.start_scanning(malware_folder, folder_watch_interval,
                                     vt_scan_interval)

        return True

    @wrapped_functionality()
    def is_data_scan_active(self) -> tuple:
        """See the DataFolderScanner.is_scanning_active() method."""
        return self._scanner.is_scanning_active()

    @wrapped_functionality()
    def stop_data_scan(self) -> True:
        """See the DataFolderScanner.stop_scanning() method."""
        self._scanner.stop_scanning()

        return True

    @wrapped_functionality(employment_state=Employment.UPDATING_MALWARE_LABELS)
    def update_malware_labels(self) -> bool:
        """See the DataFolderScanner.update_malware_labels method."""
        self._scanner.update_malware_labels()

        return True

    @wrapped_functionality(employment_state=Employment.CREATING_DATASET)
    def create_dataset(self, configuration_content: str) -> bool:
        """See the DatasetWorker.create_dataset() method."""
        # Create a temporary file containing the configuration
        temp_configuration = tempfile.NamedTemporaryFile(delete=False)
        temp_configuration.write(configuration_content)
        temp_configuration.flush()
        temp_configuration_filename = temp_configuration.name

        result = DatasetWorker.create_dataset_from_file(
            temp_configuration_filename)

        # Remove the temporary file
        os.remove(temp_configuration_filename)

        return result

    @wrapped_functionality()
    def list_datasets(self) -> typing.List[typing.List]:
        """See the DatasetWorker.list_datasets() method."""
        return DatasetWorker.list_datasets()

    @wrapped_functionality()
    def remove_dataset(self, dataset_filename: str) -> bool:
        """See the DatasetWorker.remove_dataset() method."""
        DatasetWorker.remove_dataset(dataset_filename)

        return True

    @wrapped_functionality(employment_state=Employment.CREATING_MODEL)
    def create_model(self, configuration_content: str) -> str:
        """Trains a new model following the configuration from a file.

        Args:
            configuration_content (str): Content of the configuration file that
                will be used for model training

        See the ModelsManagementCore.train_model() method.
        """
        # Create a temporary file containing the configuration
        temp_configuration = tempfile.NamedTemporaryFile(delete=False)
        temp_configuration.write(configuration_content)
        temp_configuration.flush()
        temp_configuration_filename = temp_configuration.name

        model_name = self._model_management_core.train_model(
            temp_configuration_filename)

        # Remove the temporary file
        os.remove(temp_configuration_filename)

        return model_name

    @wrapped_functionality()
    def update_model(self, model_name: str, parameter_name: str,
                     parameter_value: float) -> bool:
        """See the ModelsManagementCore.set_prediction_configuration() method.
        """
        self._model_management_core.set_prediction_configuration(
            model_name, parameter_name, parameter_value)

        return True

    @wrapped_functionality()
    def list_models(self) -> typing.List[typing.List]:
        """See the ModelsManagementCore.list_models() method."""
        result = self._model_management_core.list_models()

        return result

    @wrapped_functionality()
    def remove_model(self, model_name: str) -> bool:
        """See the ModelsManagementCore.remove_model() method."""
        self._model_management_core.remove_model(model_name)

        return True

    @wrapped_functionality()
    def create_retraining(self, model_name: str) -> bool:
        """See the ModelsManagementCore.retrain_model() method."""
        return self._model_management_core.retrain_model(model_name)

    @wrapped_functionality()
    def start_retraining(self, model_name: str) -> bool:
        """See the ModelsManagementCore.add_model_to_retraining() method."""
        return self._model_management_core.add_model_to_retraining(model_name)

    @wrapped_functionality()
    def list_retrainings(self) -> typing.List[str]:
        """See the ModelsManagementCore.get_retrained_models() method."""
        return self._model_management_core.get_retrained_models()

    @wrapped_functionality()
    def stop_retraining(self, model_name: str) -> bool:
        """See the ModelsManagementCore.remove_model_from_retraining() method.
        """
        return self._model_management_core.remove_model_from_retraining(
            model_name)

    @wrapped_functionality(employment_state=Employment.PREDICTING)
    def create_ticket(self,
                      model_name: str,
                      sample_content: bytes = None,
                      features: typing.Any = None,
                      similarity_analysis: bool = False,
                      similar_count: int = 0) -> str:
        """Predicts the malice or the memberships to malware categories of a
        given file with a given model.

        Args:
            sample_content (bytes): Bytes of the sample beeing scanned

        Returns:
            str: Ticket name

        See the ModelsManagementCore.predict_with_model() method.
        """
        # Create a temporary file containing the sample
        temp_sample_filename = None
        if sample_content:
            temp_sample = tempfile.NamedTemporaryFile(delete=False)
            temp_sample.write(sample_content)
            temp_sample.flush()
            temp_sample_filename = temp_sample.name

        # Start a threaded prediction
        ticket_name = self._model_management_core.threaded_predict(
            model_name, temp_sample_filename, features, similarity_analysis,
            similar_count, True)

        return ticket_name

    @wrapped_functionality()
    def get_ticket(self, ticket_name: str) -> typing.Any:
        """See the ModelsManagementCore.get_ticket_content() method."""
        result = self._model_management_core.get_ticket_content(ticket_name)

        return result
