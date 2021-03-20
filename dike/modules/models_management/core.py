"""Module implementing the core managing the training of models

Usage example:

    core = ModelsManagementCore()
    model_name = core.train_model("/tmp/model_configuration.yaml")
    core.add_model_to_retrain(model_name)

    models_info = core.list_models()

    result = core.predict_with_model(model_name, "/tmp/malware.exe")

    core.remove_model(model_name)
"""
import binascii
import os
import shutil
import threading
import time
import typing

from configuration.dike import DikeConfig
from modules.models_management.retrain import Retrainer
from modules.models_management.trainer import Trainer
from modules.utils.configuration import ConfigurationSpace, ConfigurationWorker


class _EphemeralEntry:
    """Class encapsulating details about an active object with a limited
    lifetime

    Attributes:
        last_accessed (float): Time (in seconds after UTC) when last
            access happened
        active_object (Trainer): Active object reference
    """
    last_accessed: float
    active_object: typing.Any

    def __init__(self, last_accessed: float,
                 active_object: typing.Any) -> None:
        """Initializes the _EphemeralEntry instance.
        """
        self.last_accessed = last_accessed
        self.active_object = active_object


class ModelsManagementCore:
    """Class for manipulating models"""
    _retrainer: Retrainer
    _trainers_entries: dict
    _tickets_entries: dict
    _ticket_length: int
    _predictions_count: int
    _no_prediction_mutex: threading.Lock
    _predictions_count_mutex: threading.Lock
    _insert_mutex: threading.Lock
    _models_lifetime: int
    _tickets_lifetime: int
    _delete_thread: threading.Thread
    _stop_delete_thread: bool
    _deletion_checking_interval: int

    def __init__(self) -> None:
        """Initializes the ModelsManagementCore instance.
        """
        # Read the prediction configuration
        prediction_config = ConfigurationWorker().get_configuration_space(
            ConfigurationSpace.MACHINE_LEARNING)["prediction"]
        self._models_lifetime = prediction_config["model_lifetime"]
        self._tickets_lifetime = prediction_config["ticket_lifetime"]
        self._ticket_length = prediction_config["ticket_length"]

        # Default value of members
        self._trainers_entries = dict()
        self._tickets_entries = dict()
        self._predictions_count = 0
        self._no_prediction_mutex = threading.Lock()
        self._predictions_count_mutex = threading.Lock()
        self._insert_mutex = threading.Lock()

        # Create the deletion thread
        self._stop_delete_thread = False
        self._deletion_checking_interval = prediction_config[
            "checking_interval"]
        self._delete_thread = threading.Thread(
            target=self._unload_unused_objects)
        self._delete_thread.start()

        # Start the retrainer
        self._retrainer = Retrainer()
        self._retrainer.start()

    def __del__(self) -> None:
        """Destroys the ModelsManagementCore instance.
        """
        self._retrainer.stop()

        self._stop_delete_thread = True
        self._delete_thread.join()

    def train_model(self, configuration_filename: str) -> str:
        """Trains a new model following the configuration from a file.

        Args:
            configuration_filename (str): Absolute path to the configuration
                file saved as a temporary file

        Returns:
            str: Unique name of the model
        """
        new_trainer = Trainer()
        new_trainer.train(configuration_filename)
        model_name = new_trainer.dump()

        return model_name

    def _load_model(self, model_name: str) -> _EphemeralEntry:
        # Load the module
        trainer = Trainer()
        trainer.load(model_name)

        # Create a new entry
        new_entry = _EphemeralEntry(time.time(), trainer)

        # Check (again) if the model is not in the list and insert it. The
        # critical section guarantees that there is only one insert at a time
        self._insert_mutex.acquire()
        if (model_name not in self._trainers_entries):
            self._trainers_entries[model_name] = new_entry
        self._insert_mutex.release()

        return new_entry

    def _unload_unused_objects(self):
        while (not self._stop_delete_thread):
            current_time = time.time()

            # Delete the unused models and tickets (critical section)
            self._no_prediction_mutex.acquire()
            self._trainers_entries = {
                key: entry
                for key, entry in self._trainers_entries.items()
                if (current_time - entry.last_accessed < self._models_lifetime)
            }
            self._tickets_entries = {
                key: entry
                for key, entry in self._tickets_entries.items()
                if (current_time -
                    entry.last_accessed < self._tickets_lifetime)
            }
            self._no_prediction_mutex.release()

            time.sleep(self._deletion_checking_interval)

    def create_new_ticket(self) -> str:
        """Creates a new ticket based on which a prediction will be retrieved.

        Returns:
            str: Ticket name
        """
        # Create a new ticket ID
        ticket_name = binascii.hexlify(os.urandom(
            self._ticket_length)).decode("utf-8")

        # Add a new entry for the ticket
        new_entry = _EphemeralEntry(time.time(), dict())
        self._tickets_entries[ticket_name] = new_entry

        return ticket_name

    def predict_with_model(self,
                           ticket_name: str,
                           model_name: str,
                           full_filename: str = None,
                           features: typing.Any = None,
                           similarity_analysis: bool = False,
                           similar_count: int = 0,
                           delete_file_after: bool = False) -> dict:
        """Predicts the malice or the memberships to malware categories of a
        given file with a given model.

        Args:
            model_name (str): Name of the model
            full_filename (str, optional): Full path to the file over which a
                prediction will be made, saved as a temporary file
            features (typing.Any, optional): Already extracted raw features of
                the file
            similarity_analysis (bool, optional): Boolean indicating if a
                similarity analysis needs to be done. Defaults to False.
            similar_count (int, optional): Number of similar samples to return.
                Defaults to 0, if the similarity analysis is disabled.
            delete_file_after: Boolean indicating if the file is deleted after
                the prediction. Defaults to False.

        Returns:
            dict: Prediction results
        """
        # Increase the predictions count and, eventually, mark the list as used
        # for predictions. The critical section guarantees that the prediction
        # and the deletion processes doesn't happen at the same time.
        self._predictions_count_mutex.acquire()
        if (self._predictions_count == 0):
            self._no_prediction_mutex.acquire()
        self._predictions_count += 1
        self._predictions_count_mutex.release()

        # Check if the model needs to be loaded in memory
        if (model_name in self._trainers_entries):
            entry = self._trainers_entries[model_name]
        else:
            entry = self._load_model(model_name)

        # Predict using the entry and link the result to the ticket
        result = entry.active_object.predict(full_filename, features,
                                             similarity_analysis,
                                             similar_count)
        ticket_entry = self._tickets_entries[ticket_name]
        ticket_entry.active_object = result
        ticket_entry.last_accessed = time.time()

        # Mark the model as used at this moment
        entry.last_accessed = time.time()

        # Delete the file
        if delete_file_after:
            os.remove(full_filename)

        # Decrease the predictions count and, eventually, mark the list as
        # unused for predictions
        self._predictions_count_mutex.acquire()
        self._predictions_count -= 1
        if (self._predictions_count == 0):
            self._no_prediction_mutex.release()
        self._predictions_count_mutex.release()

    def get_ticket_content(self, ticket_name: str) -> typing.Any:
        """Gets the ticket content.

        Args:
            ticket_name (str): Ticket name

        Returns:
            typing.Any: Result of the prediction. Empty dictionary if the
                prediction is not finished yet.
        """
        if ticket_name not in self._tickets_entries:
            return dict()

        ticket_entry = self._tickets_entries[ticket_name]
        ticket_entry.last_accessed = time.time()

        return ticket_entry.active_object

    def set_prediction_configuration(self, model_name: str,
                                     parameter_name: str,
                                     parameter_value: typing.Any) -> None:
        """See the Trainer.set_prediction_configuration() method."""
        new_trainer = Trainer()
        new_trainer.set_prediction_configuration(model_name, parameter_name,
                                                 parameter_value)

    def add_model_to_retraining(self, model_name: str) -> bool:
        return self._retrainer.retrain_model(model_name)

    def remove_model_from_retraining(self, model_name: str) -> bool:
        return self._retrainer.remove_model(model_name)

    def get_retrained_models(self) -> typing.List:
        """Gets the models added to retrain.

        Returns:
            typing.List[str]: List with retrained models
        """
        return self._retrainer.get_retrained_models()

    @staticmethod
    def list_models() -> typing.List[typing.List]:
        """Lists the trained models details.

        Returns:
            typing.List[typing.List]: Details about trained models
        """
        all_metadata = []

        filenames = os.listdir(DikeConfig.TRAINED_MODELS_FOLDER)
        for filename in filenames:
            # Skip the hidden files
            if not filename.startswith("."):
                # Read the training configuration file
                training_configuration_filename = DikeConfig.TRAINED_MODEL_TRAINING_CONFIGURATION.format(
                    filename)
                with open(training_configuration_filename,
                          "r") as training_configuration_file:
                    training_configuration = training_configuration_file.read()

                # Read the prediction configuration file
                prediction_configuration_filename = DikeConfig.TRAINED_MODEL_PREDICTION_CONFIGURATION.format(
                    filename)
                with open(prediction_configuration_filename,
                          "r") as prediction_configuration_file:
                    prediction_configuration = prediction_configuration_file.read(
                    )

                # Append the metadata of the current model
                all_metadata.append([
                    filename, training_configuration, prediction_configuration
                ])

        return all_metadata

    @staticmethod
    def remove_model(model_name: str) -> None:
        """Remove a trained model.

        Args:
            model_name (str): Name of the trained model
        """
        try:
            full_filname = DikeConfig.TRAINED_MODELS_MODEL_FOLDER.format(
                model_name)
            shutil.rmtree(full_filname)
        except FileNotFoundError:
            pass
