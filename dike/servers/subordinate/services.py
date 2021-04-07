"""Service for subordinate servers.

Usage example:

    from rpyc.modules.utils.server import ThreadPoolServer

    server = ThreadPoolServer(SubordinationService, hostname="0.0.0.0", port=80)
    server.start()
"""
import os
import tempfile
import typing
from threading import Lock, Thread

import rpyc
from modules.dataset.core import DatasetCore
from modules.dataset.data_folder_scanner import DataFolderScanner
from modules.models.core import ModelsManagementCore
from modules.utils.configuration_manager import ConfigurationManager
from modules.utils.errors import Error
from modules.utils.logger import Logger
from modules.utils.types import ConfigurationSpaces, LoggedMessageTypes
from pypattyrn.creational.singleton import Singleton
from servers.subordinate.types import Employment


def _execute_threaded_operation(function: typing.Callable, *args,
                                **kwargs) -> None:
    # Call the required function
    try:
        function(*args, **kwargs)
    except Error as error:
        Logger().log(str(error), LoggedMessageTypes.ERROR)

    # Leave the critical section. pylint: disable=protected-access
    instance = SubordinationService()
    instance._employment_state = Employment.AVAILABLE
    instance._employment_state_mutex.release()


def wrapped_functionality(
        employment_state: Employment = None) -> typing.Callable:
    """Marks a function as time-consuming.

    Args:
        employment_state (Employment): Employment state while executing the
            operations

    Returns:
        typing.Callable: Decorator
    """

    def inner_decorator(function: typing.Callable):

        def wrapper(*args, **kwargs):
            instance = SubordinationService()

            if employment_state:
                # Enter critical section. pylint: disable=protected-access
                instance._employment_state_mutex.acquire()
                instance._employment_state = employment_state

                # Create a new thread for executing the operation
                arguments = (function, ) + args
                thread = Thread(target=_execute_threaded_operation,
                                args=arguments,
                                kwargs=kwargs)
                thread.start()

                return True
            else:
                try:
                    result = function(*args, **kwargs)
                except Error as error:

                    # Log error
                    Logger().log(str(error), LoggedMessageTypes.ERROR)

                    return None

                return result

        return wrapper

    return inner_decorator


class SubordinationService(rpyc.Service, metaclass=Singleton):
    """Class implementing the RPyC service needed by the subordinate servers."""

    _scanner: DataFolderScanner
    _model_management_core: ModelsManagementCore
    _employment_state: Employment
    _employment_state_mutex: Lock
    _malware_families: dict
    _malicious_benign_votes_ratio: int
    _min_ignored_percent: float

    def __init__(self) -> None:
        """Initializes the SubordinationService instance."""
        configuration = ConfigurationManager()
        dataset_config = configuration.get_space(ConfigurationSpaces.DATASET)

        self._malware_families = dataset_config["malware_families"]
        self._malicious_benign_votes_ratio = dataset_config[
            "malicious_benign_votes_ratio"]
        self._min_ignored_percent = dataset_config["min_ignored_percent"]

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
        Logger().log("The connection with the leader server was established.",
                     LoggedMessageTypes.BEGINNING)

    # pylint: disable=unused-argument
    def on_disconnect(self, connection: rpyc.Connection) -> None:
        """Handles a disconnect.

        Args:
            connection (rpyc.Connection): RPyC connection
        """
        Logger().log("The connection with the leader server was broken.",
                     LoggedMessageTypes.END)

    def get_employment(self) -> Employment:
        """Checks what the server does.

        Returns:
            Employment: Employment state
        """
        return self._employment_state

    @wrapped_functionality()
    def get_logs(self) -> str:
        """See the Logger.get_buffer() method.

        # noqa
        """
        return Logger().get_buffer(False)

    @wrapped_functionality()
    def clear_logs(self) -> bool:
        """See the Logger.get_buffer() method.

        # noqa
        """
        Logger().get_buffer(True)

        return True

    @wrapped_functionality()
    def start_data_scan(self,
                        malware_folder: bool,
                        folder_watch_interval: int,
                        vt_scan_interval: int = 0) -> bool:
        """See the DataFolderScanner.start_scan() method.

        # noqa
        """
        self._scanner.start_scan(malware_folder, folder_watch_interval,
                                 vt_scan_interval)

        return True

    @wrapped_functionality()
    def is_data_scan_active(self) -> tuple:
        """See the DataFolderScanner.is_scan_active() method.

        # noqa
        """
        return self._scanner.is_scan_active()

    @wrapped_functionality()
    def stop_data_scan(self) -> True:
        """See the DataFolderScanner.stop_scan() method.

        # noqa
        """
        self._scanner.stop_scan()

        return True

    @wrapped_functionality(employment_state=Employment.UPDATING_MALWARE_LABELS)
    def update_malware_labels(self) -> bool:
        """See the DataFolderScanner.update_malware_labels method.

        # noqa
        """
        self._scanner.update_malware_labels()

        return True

    @wrapped_functionality(employment_state=Employment.CREATING_DATASET)
    def create_dataset(self, configuration_content: str) -> bool:
        """See the DatasetCore.create_dataset_from_config() method.

        # noqa
        """
        # Create a temporary file containing the configuration
        temp_configuration = tempfile.NamedTemporaryFile(delete=False)
        temp_configuration.write(configuration_content)
        temp_configuration.flush()
        temp_configuration_filename = temp_configuration.name

        result = DatasetCore.create_dataset_from_config(
            temp_configuration_filename)

        # Remove the temporary file
        os.remove(temp_configuration_filename)

        return result

    @wrapped_functionality()
    def list_datasets(self) -> typing.List[typing.List]:
        """See the DatasetCore.list_datasets() method.

        # noqa
        """
        return DatasetCore.list_datasets()

    @wrapped_functionality()
    def remove_dataset(self, dataset_filename: str) -> bool:
        """See the DatasetCore.remove_dataset() method.

        # noqa
        """
        DatasetCore.remove_dataset(dataset_filename)

        return True

    @wrapped_functionality(employment_state=Employment.CREATING_MODEL)
    def create_model(self, configuration_content: str) -> str:
        """Trains a new model following the configuration from a file.

        Args:
            configuration_content (str): Content of the configuration file that
                will be used for model training

        See the ModelsManagementCore.train_model() method.

        # noqa
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

        # noqa
        """
        result = self._model_management_core.set_prediction_configuration(
            model_name, parameter_name, parameter_value)

        return result

    @wrapped_functionality()
    def list_models(self) -> typing.List[typing.List]:
        """See the ModelsManagementCore.list_models() method.

        # noqa
        """
        result = self._model_management_core.list_models()

        return result

    @wrapped_functionality()
    def remove_model(self, model_name: str) -> bool:
        """See the ModelsManagementCore.remove_model() method.

        # noqa
        """
        self._model_management_core.remove_model(model_name)

        return True

    @wrapped_functionality(employment_state=Employment.CREATING_RETRAINING)
    def create_retraining(self, model_name: str) -> bool:
        """See the ModelsManagementCore.retrain_model_now() method.

        # noqa
        """
        return self._model_management_core.retrain_model_now(model_name)

    @wrapped_functionality()
    def start_retraining(self, model_name: str) -> bool:
        """See the ModelsManagementCore.add_model_to_retraining() method.

        # noqa
        """
        return self._model_management_core.add_model_to_retraining(model_name)

    @wrapped_functionality()
    def list_retrainings(self) -> typing.List[str]:
        """See the ModelsManagementCore.get_retrained_models() method.

        # noqa
        """
        return self._model_management_core.get_retrained_models()

    @wrapped_functionality()
    def stop_retraining(self, model_name: str) -> bool:
        """See the ModelsManagementCore.remove_model_from_retraining() method.

        # noqa
        """
        return self._model_management_core.remove_model_from_retraining(
            model_name)

    @wrapped_functionality()
    def create_ticket(self,
                      model_name: str,
                      sample_content: bytes = None,
                      features: typing.Any = None,
                      similarity_analysis: bool = False,
                      similar_count: int = 0) -> str:
        """Predicts the malice or the memberships to malware categories.

        As this function needs to return a result and launch a new thread, it
        does not use the decorator with an employment parameter set.

        Args:
            sample_content (bytes): Bytes of the sample being scanned

        Returns:
            str: Ticket name

        See the ModelsManagementCore.predict_synchronously() method.

        # noqa
        """
        # Set the employment
        self._employment_state_mutex.acquire()
        self._employment_state = Employment.CREATING_TICKET

        # Create a temporary file containing the sample
        temp_sample_filename = None
        if sample_content:
            temp_sample = tempfile.NamedTemporaryFile(delete=False)
            temp_sample.write(sample_content)
            temp_sample.flush()
            temp_sample_filename = temp_sample.name

        # Create a new ticket
        ticket_name = self._model_management_core.create_ticket()

        # Create a new thread for prediction
        prediction_args = (ticket_name, model_name, temp_sample_filename,
                           features, similarity_analysis, similar_count, True)
        arguments = (self._model_management_core.predict_synchronously,
                     ) + prediction_args
        thread = Thread(target=_execute_threaded_operation, args=arguments)
        thread.start()

        return ticket_name

    @wrapped_functionality()
    def get_ticket(self, ticket_name: str) -> typing.Any:
        """See the ModelsManagementCore.get_ticket_content() method.

        # noqa
        """
        result = self._model_management_core.get_ticket_content(ticket_name)

        return result
