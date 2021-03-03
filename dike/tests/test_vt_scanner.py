"""Program testing the scanning using VirusTotal"""
import pytest
from modules.dataset_building.vt_scanner import VirusTotalScanner
from modules.utils.configuration import ConfigurationSpace, ConfigurationWorker


def test_invalid_api_key():
    """Tests a Virus Total request with an invalid API key.

    An VirusTotalRequestError is expected, but the Exception is used to pass the
    pytest test."""
    with pytest.raises(Exception):
        scanner = VirusTotalScanner("invalid_api_key")
        scanner.scan("hash")


def test_hash_scan():
    """Tests a valid VirusTotal request."""
    # Read the API key from the configuration file
    configuration = ConfigurationWorker()
    secrets_config = configuration.get_configuration_space(
        ConfigurationSpace.SECRETS)
    vt_api_key = secrets_config["virus_total_api_key"]

    # Scan the file hash
    scanner = VirusTotalScanner(vt_api_key)
    results = scanner.scan(
        "5eef863845526e801e60b581e61b51245df69ead118f2caa59150e8caf4f480d")

    # A detail should be present in the result
    assert "Trojan" in results[
        "raw_tags"], "The result of the VirusTotal scan does not contains all required data."
