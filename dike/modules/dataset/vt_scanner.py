"""Module implementing VirusTotal scanning functionality

Usage example:

    scanner = VirusTotalScanner(
        "86708bfb237c723356f50ac8e64889d1b97a9babb281c01bc4cdfa69d2508792")
    results = scanner.scan(
        "000cb7a0624d52380f164f2c99984e5dde248458f36bfb932dca4e3ed2df69b1")

"""
import re
import typing

import vt
from configuration.platform import Parameters
from modules.utils.errors import VirusTotalRequestError


class FileResults(dict):
    """Class encapsulating the relevant details of a VirusTotal scan

    Attributes:
        benign_votes (int): The number of benign votes from antivirus engines
        malware_votes (int): The number of malware votes from antivirus
            engines
        raw_tags (typing.List[str]): List of raw tags, extracted from the
            detection of each antivirus engine
    """
    benign_votes: int
    malware_votes: int
    raw_tags: typing.List[str]

    def __init__(self, benign_votes: int, malware_votes: int,
                 raw_tags: typing.List[str]) -> None:
        """Initializes the FileResults instance."""
        dict.__init__(self,
                      benign_votes=benign_votes,
                      malware_votes=malware_votes,
                      raw_tags=raw_tags)


class VirusTotalScanner:
    """Class for scanning with VirusTotal a file hash"""
    _api_client: vt.Client

    def __init__(self, api_key: str) -> None:
        """Initializes the VirusTotalScanner instance.

        Args:
            api_key (str): VirusTotal API key
        """
        self._api_client = vt.Client(api_key)

    def __del__(self):
        """Destroys the VirusTotalScanner instance."""
        self._api_client.close()

    def scan(self, file_hash: str) -> FileResults:
        """Scans a file hash using VirusTotal API.

        Args:
            file_hash (str): Hash of the file

        Raises:
            VirusTotalRequestError: The request to VirusTotal API failed.

        Returns:
            FileResults: The results of scanning the hash
        """
        try:
            file = self._api_client.get_object("/files/{}".format(file_hash))
        except Exception:
            raise VirusTotalRequestError()

        benign_votes = 0
        malware_votes = 0
        raw_tags = []
        for vendor in file.last_analysis_results.keys():
            antivirus_scan = file.last_analysis_results[vendor]

            # Get votes
            if (antivirus_scan["category"]
                    and antivirus_scan["category"] in Parameters.
                    FeatureExtraction.VirusTotal.ANTIVIRUS_MALWARE_CATEGORIES):
                malware_votes += 1
            else:
                benign_votes += 1

            # Extract tags
            if (antivirus_scan["result"]):
                raw_tags.extend(
                    re.sub(r"[^\w]", " ", antivirus_scan["result"]).split())

        return FileResults(benign_votes, malware_votes, raw_tags)
