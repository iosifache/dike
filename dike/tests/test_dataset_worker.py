"""Program testing the manipulation of datasets"""
import os

import pytest
from configuration.dike import DikeConfig
from modules.dataset_building.dataset_worker import DatasetWorker
from modules.dataset_building.types import AnalyzedFileTypes


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
    monkeypatch.setattr(DikeConfig, "MALWARE_LABELS",
                        DikeConfig.FULL_DATASET_FOLDER + "malware_labels.csv")
    monkeypatch.setattr(DikeConfig, "BENIGN_LABELS",
                        DikeConfig.FULL_DATASET_FOLDER + "benign_labels.csv")


def test_dataset_creation():
    """Tests the creation of a dataset."""
    dataset_filename = "test.csv"

    status = DatasetWorker.create_dataset(AnalyzedFileTypes.PE, 0.9,
                                          9 * [True], 20, 0.5,
                                          dataset_filename, "")
    assert status is True, "The creation of a dataset returned an invalid result."

    # Cleanup
    os.remove(os.path.join(DikeConfig.CUSTOM_DATASETS_FOLDER,
                           dataset_filename))


def test_failed_dataset_creation():
    """Tests the failure of creation of a dataset, due to the huge requested
    samples count."""
    status = DatasetWorker.create_dataset(AnalyzedFileTypes.PE, 0.9,
                                          9 * [True], 1000000, 0.5,
                                          "dataset.csv", "")
    assert status is False, "The failure of creation of a dataset was not correctly flagged."
