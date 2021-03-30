"""Module implementing the periodical retraining of models

Usage example:

    import time

    # Start the retraining of a model
    retrainer = Retrainer()
    retrainer.retrain_model(
        "0c002b1fb9d4082d39c82eb5a0f6e7fcc22077ecf6de4cca7fc331a76327f418")
    retrainer.start()

    # Wait a day and stop the retrain process
    time.sleep(24 * 60 * 60)
    retrainer.stop()
"""
import typing

from modules.models.trainer import Trainer
from modules.utils.configuration import ConfigurationSpace, ConfigurationWorker
from modules.utils.scheduler import ReplicatedDailyScheduler
from pypattyrn.creational.singleton import Singleton


class Retrainer(object, metaclass=Singleton):
    """Class retraining periodically the tracked models"""
    _model_names: typing.List[str]
    _scheduler: ReplicatedDailyScheduler

    def __init__(self) -> None:
        """Initializes the Retrainer instance."""
        self._model_names = []

        # Default value of members
        self._scheduler = None

    def retrain_model(self, model_name: str) -> bool:
        """Adds a model to be retrained.

        Args:
            model_name (str): Name of the model

        Returns:
            bool: Boolean indicating if the model was added to the retrain
        """
        # Check if the model is already added to the retrain
        if model_name in self._model_names:
            return False

        self._model_names.append(model_name)
        return True

    def get_retrained_models(self) -> typing.List[str]:
        """Gets the models added to retrain.

        Returns:
            typing.List[str]: List with retrained models
        """
        return self._model_names

    def remove_model(self, model_name: str) -> bool:
        """Removes a model from the retraining.

        Args:
            model_name (str): Model name

        Returns:
            bool: Boolean indicating if the model was removed
        """
        if model_name not in self._model_names:
            return False

        self._model_names = [
            name for name in self._model_names if name != model_name
        ]

        return True

    @staticmethod
    def retrain_model_now(model_name: str) -> None:
        """Retrain a model.

        Args:
            model_name (str): Model name
        """
        trainer = Trainer()

        trainer.load(model_name)
        trainer.retrain()
        trainer.dump()

    def start(self):
        """Starts the periodical retraining of models."""
        # Read the retraining configuration
        retrain_config = ConfigurationWorker().get_configuration_space(
            ConfigurationSpace.MACHINE_LEARNING)["retraining"]

        # Schedule the retraining
        self._scheduler = ReplicatedDailyScheduler(
            retrain_config["workers_count"],
            retrain_config["stringified_time"], Retrainer.retrain_model_now,
            self._model_names)
        self._scheduler.start()

    def stop(self):
        """Stops the periodical retraining of models."""
        self._scheduler.stop()
