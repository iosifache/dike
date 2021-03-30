"""Program testing the scanning of the folders with samples"""
import os
import shutil
import time

import pytest
from configuration.dike import DikeConfig
from modules.dataset.data_folder_scanner import DataFolderScanner
from modules.utils.configuration import ConfigurationWorker


def _delete_all_files_from_folder(filename: str) -> None:
    for file in os.listdir(filename):
        os.remove(os.path.join(filename, file))


def _remove_all_added_lines(filename: str) -> None:
    lines = []

    with open(filename, "r") as file:
        lines = file.readlines()
        if lines:
            lines = [lines[0]]

    with open(filename, "w") as file:
        file.writelines(lines)


@pytest.fixture(scope="session", autouse=True)
# pylint: disable=unused-argument
def initialize_environment_for_tests(request: "FixtureRequest") -> None:
    """Initializes the environment for the tests.

    Args:
        request (FixtureRequest): Request passed by pytest
    """
    # Initialize the configuration
    ConfigurationWorker()


@pytest.fixture(autouse=True)
def initialize_environment_for_test(monkeypatch: "MonkeyPatch") -> None:
    """Initializes the environment for each test.

    Args:
        monkeypatch (MonkeyPatch): Patching object passed by pytest
    """
    # Modify the configuration
    monkeypatch.setattr(DikeConfig, "FULL_DATASET_FOLDER",
                        "tests/files/data/datasets/full/")
    monkeypatch.setattr(DikeConfig, "MALWARE_DATASET_FOLDER",
                        DikeConfig.FULL_DATASET_FOLDER + "malware/")
    monkeypatch.setattr(DikeConfig, "BENIGN_DATASET_FOLDER",
                        DikeConfig.FULL_DATASET_FOLDER + "benign/")
    monkeypatch.setattr(DikeConfig, "MALWARE_LABELS",
                        DikeConfig.FULL_DATASET_FOLDER + "malware_labels.csv")
    monkeypatch.setattr(DikeConfig, "BENIGN_LABELS",
                        DikeConfig.FULL_DATASET_FOLDER + "benign_labels.csv")
    monkeypatch.setattr(DikeConfig, "MALWARE_HASHES",
                        DikeConfig.FULL_DATASET_FOLDER + "malware_hashes.txt")
    monkeypatch.setattr(DikeConfig, "VT_DATA_FILE",
                        DikeConfig.FULL_DATASET_FOLDER + "vt_data.csv")


def clean_environment_after_test() -> None:
    """Cleanup the environment after the tests executes."""
    # Delete the created files
    _delete_all_files_from_folder(DikeConfig.MALWARE_DATASET_FOLDER)
    _delete_all_files_from_folder(DikeConfig.BENIGN_DATASET_FOLDER)

    # Remove the added lines from files
    _remove_all_added_lines(DikeConfig.MALWARE_LABELS)
    _remove_all_added_lines(DikeConfig.BENIGN_LABELS)
    _remove_all_added_lines(DikeConfig.MALWARE_HASHES)
    _remove_all_added_lines(DikeConfig.VT_DATA_FILE)


@pytest.mark.usefixtures("clean_environment_after_test")
def test_scan_benign_folder():
    """Tests the scan of the folder with benign files."""
    filename = "benign.exe"

    # Create the file
    full_filename = os.path.join(DikeConfig.BENIGN_DATASET_FOLDER, filename)
    open(full_filename, "w").close()

    # Start the scanning, wait and stop the scanning
    data_folder_scanner = DataFolderScanner()
    data_folder_scanner.start_scanning(False, 1)
    time.sleep(1)
    data_folder_scanner.stop_scanning()

    # Check if the label was added
    with open(DikeConfig.BENIGN_LABELS, "r") as benign_labels_files:
        lines = benign_labels_files.readlines()
        label_added = (len(lines) == 2)

    assert label_added is True, "The label corresponding to the new benign file was not added into the specific file."


@pytest.mark.usefixtures("clean_environment_after_test")
def test_scan_malware_folder():
    """Tests the scan of the folder with benign files."""
    malware_filename = "aaac07a9712aa49877419d70efda6e727fe37484b5673b043d8534180b319854.exe"
    source_full_filename = "data/datasets/full/malware/" + malware_filename
    destination_full_filename = os.path.join(DikeConfig.MALWARE_DATASET_FOLDER,
                                             "malware.exe")
    renamed_destination_full_filename = DikeConfig.MALWARE_DATASET_FOLDER + malware_filename

    # Copy the malicious file
    shutil.copyfile(source_full_filename, destination_full_filename)

    # Start the scanning, wait and stop the scanning
    data_folder_scanner = DataFolderScanner()
    data_folder_scanner.start_scanning(True, 0.1, 0.1)
    time.sleep(3)
    data_folder_scanner.stop_scanning()

    # Check if the label was added
    with open(DikeConfig.MALWARE_LABELS, "r") as benign_labels_files:
        lines = benign_labels_files.readlines()
        label_added = (len(lines) == 2)
    assert label_added is True, "The label corresponding to the new malware file was not added into the specific file."

    # Cleanup
    os.remove(renamed_destination_full_filename)


@pytest.mark.usefixtures("clean_environment_after_test")
def test_update_malware_labels():
    """Tests the update of malware labels."""
    file_hash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    filename = file_hash + ".exe"
    vt_data_line = "{},10,0,Trojan Malware Generic\n".format(file_hash)

    # Create the file
    full_filename = os.path.join(DikeConfig.MALWARE_DATASET_FOLDER, filename)
    open(full_filename, "a").close()

    # Append new line to the file containing the Virus Total scans details
    with open(DikeConfig.VT_DATA_FILE, "a") as vt_data_file:
        vt_data_file.write(vt_data_line)

    # Update the malware labels via the scanner
    data_folder_scanner = DataFolderScanner()
    data_folder_scanner.update_malware_labels()

    # Check the added label
    with open(DikeConfig.MALWARE_LABELS, "r") as malware_labels_file:
        lines = malware_labels_file.readlines()
        label_added = (len(lines) == 2)

    # Additional cleanup
    os.remove(full_filename)

    assert label_added is True, "The labels corresponding to the new data was not added into the specific file."
