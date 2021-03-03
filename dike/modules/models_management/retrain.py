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

from modules.models_management.core import ModelsManagementCore
from modules.utils.configuration import ConfigurationSpace, ConfigurationWorker
from modules.utils.scheduler import ReplicatedDailyScheduler
from pypattyrn.creational.singleton import Singleton


class Retrainer(object, metaclass=Singleton):
    """Class retraining periodically the tracked models"""
    _model_names: typing.List[str]
    _scheduler: ReplicatedDailyScheduler

    def retrain_model(self, model_name: str) -> None:
        """Adds a model to be retrained.

        Args:
            model_name (str): Name of the model
        """
        self._model_names = []
        self._model_names.append(model_name)

        # Default value of members
        self._scheduler = None

    @staticmethod
    def _retrain(model_name: str) -> None:
        core = ModelsManagementCore()

        core.load(model_name)
        core.retrain()
        core.dump()

    def start(self):
        """Starts the periodical retraining of models."""
        # Read the retraining configuration
        retrain_config = ConfigurationWorker().get_configuration_space(
            ConfigurationSpace.MACHINE_LEARNING)["retraining"]

        # Schedule the retraining
        self._scheduler = ReplicatedDailyScheduler(
            retrain_config["workers_count"],
            retrain_config["stringified_time"], Retrainer._retrain,
            self._model_names)
        self._scheduler.start()

    def stop(self):
        """Stops the periodical retraining of models."""
        self._scheduler.stop()
