"""Program testing the models trainer"""
import datetime
import os
import shutil
import time

import pytest
from configuration.dike import DikeConfig
from modules.models_management.retrain import Retrainer
from modules.models_management.trainer import Trainer
from modules.utils.configuration import ConfigurationSpace, ConfigurationWorker
from modules.utils.errors import (ModelConfigurationFileNotFoundError,
                                  ModelToLoadNotFoundError)


@pytest.fixture(scope="session", autouse=True)
def initialize_environment_for_tests(request: "FixtureRequest") -> None:
    """Initializes the environment for the tests.

    Args:
        request (FixtureRequest): Request passed by pytest
    """
    # Initialize the configuration
    ConfigurationWorker()

    # Add a cleanup function
    request.addfinalizer(clean_environment_after_tests)


@pytest.fixture(autouse=True)
def initialize_environment_for_test(monkeypatch: "MonkeyPatch") -> None:
    """Initializes the environment for each test.

    Args:
        monkeypatch (MonkeyPatch): Patching object passed by pytest
    """
    # Modify the configuration
    monkeypatch.setattr(DikeConfig, "DATA_FOLDER",
                        DikeConfig.DIKE_FOLDER + "tests/files/data/")
    monkeypatch.setattr(DikeConfig, "DATASETS_FOLDER",
                        DikeConfig.DATA_FOLDER + "datasets/")
    monkeypatch.setattr(DikeConfig, "CUSTOM_DATASETS_FOLDER",
                        DikeConfig.DATASETS_FOLDER + "custom/")
    monkeypatch.setattr(DikeConfig, "TRAINED_MODELS_FOLDER",
                        DikeConfig.DATA_FOLDER + "trained_models/")
    monkeypatch.setattr(DikeConfig, "TRAINED_MODELS_MODEL_FOLDER",
                        DikeConfig.TRAINED_MODELS_FOLDER + "{}")
    monkeypatch.setattr(DikeConfig, "TRAINED_MODEL_PREPROCESSORS_FOLDER", DikeConfig.TRAINED_MODELS_FOLDER + \
        "{}/preprocessors/")
    monkeypatch.setattr(DikeConfig, "TRAINED_MODEL_FEATURES_FILE",
                        DikeConfig.TRAINED_MODELS_FOLDER + "{}/features.csv")
    monkeypatch.setattr(
        DikeConfig, "TRAINED_MODEL_REDUCTION_MODEL",
        DikeConfig.TRAINED_MODELS_FOLDER + "{}/reduction.model")
    monkeypatch.setattr(DikeConfig, "TRAINED_MODEL_SCALAR_MODEL", "scalar")
    monkeypatch.setattr(DikeConfig, "TRAINED_MODEL_PREPROCESSOR_MODEL", DikeConfig.TRAINED_MODEL_PREPROCESSORS_FOLDER + \
        "{}.model")
    monkeypatch.setattr(DikeConfig, "TRAINED_MODEL_MACHINE_LEARNING_MODEL",
                        DikeConfig.TRAINED_MODELS_FOLDER + "{}/ml.model")
    monkeypatch.setattr(DikeConfig, "TRAINED_MODEL_TRAINING_CONFIGURATION", DikeConfig.TRAINED_MODELS_FOLDER + \
        "{}/training_configuration.yml")
    monkeypatch.setattr(DikeConfig, "TRAINED_MODEL_EVALUATION", DikeConfig.TRAINED_MODELS_FOLDER + \
        "{}/evaluation.json")
    monkeypatch.setattr(DikeConfig, "TRAINED_MODEL_PREDICTION_CONFIGURATION", DikeConfig.TRAINED_MODELS_FOLDER + \
        "{}/prediction_configuration.json")


def clean_environment_after_tests():
    """Cleanup the environment after the tests executes."""
    model_full_path = os.path.join("tests/files/data/trained_models",
                                   pytest.model_name)
    shutil.rmtree(model_full_path)


def test_train_with_nonexistent_model():
    """Tests the failure when an invalid model configuration is given as
    parameter from the training process."""
    trainer = Trainer()

    with pytest.raises(ModelConfigurationFileNotFoundError):
        trainer.train("path/to/nonexistent/model.yaml")


def test_model_training():
    """Tests the training, prediction and dumping of a model."""
    # Train and dump a model
    trainer = Trainer()
    trainer.train("tests/files/model.yaml")

    # Predict using the model
    pytest.initial_result = trainer.predict("tests/files/sample.exe")
    assert pytest.initial_result is not None, "The prediction using the model failed."

    # Dump the model
    pytest.model_name = trainer.dump()
    assert pytest.model_name, "The training of the model failed."


def test_prediction_for_nonexistent_file():
    """Tests the loading of a model and the failure of the prediction for a
    non-existent file."""
    # Load the model again
    trainer = Trainer()
    trainer.load(pytest.model_name)

    # Predict using the model
    result = trainer.predict("path/to/nonexistent/sample.exe")
    assert result == {
        "status": "error"
    }, "The returned status for a non-existent file is invalid."


def test_loading_of_an_nonexistent_model():
    """Tests the failure of an non-existent model."""
    trainer = Trainer()
    with pytest.raises(ModelToLoadNotFoundError):
        trainer.load("invalid_model_hash")


def test_model_loading():
    """Tests the loading and prediction of a model."""
    # Load the model again
    trainer = Trainer()
    trainer.load(pytest.model_name)

    # Predict using the model
    result = trainer.predict("tests/files/sample.exe")
    assert result == pytest.initial_result, "The prediction results differs."


def test_model_retrain():
    """Tests the retraining of a model."""
    # Get execution time
    now = datetime.datetime.now()
    now += datetime.timedelta(minutes=1)
    execution_time = "{}:{:02d}".format(now.hour, now.minute)

    # Get the creation time of the first model
    model_dump_folder = os.path.join(DikeConfig.TRAINED_MODELS_FOLDER,
                                     pytest.model_name)
    first_time = os.path.getctime(model_dump_folder)

    # Change the configuration
    retraining_config = ConfigurationWorker().get_configuration_space(
        ConfigurationSpace.MACHINE_LEARNING)["retraining"]
    retraining_config["stringified_time"] = execution_time

    # Retrain the model
    retrainer = Retrainer()
    retrainer.retrain_model(pytest.model_name)
    retrainer.start()
    time.sleep(60)
    retrainer.stop()

    # Check if the creation time changed
    second_time = os.path.getctime(model_dump_folder)
    assert first_time != second_time, "The retrain of the model does not happend."
