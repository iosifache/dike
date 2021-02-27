import typing

from modules.models_management.core import ModelsManagementCore
from modules.utils.configuration import ConfigurationSpace, ConfigurationWorker
from modules.utils.scheduler import ReplicatedDailyScheduler
from pypattyrn.creational.singleton import Singleton


class Retrainer(object, metaclass=Singleton):
    """Class retraining periodically the tracked models"""
    _model_names: typing.List[str] = []
    _scheduler: ReplicatedDailyScheduler = None

    def retrain_model(self, model_name: str) -> None:
        """Adds a model to be retrained.

        Args:
            model_name (str): Name of the model
        """
        self._model_names.append(model_name)

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

    def stop(self):
        """Stops the periodical retraining of models."""
        self._scheduler.stop()
