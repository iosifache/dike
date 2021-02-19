import re
import typing

import vt
from configuration.dike import DikeConfig


class FileResults(dict):
    """Class encapsulating the relevant details of a Virus Total scan

    Attributes:
        benign_votes (int): The number of benign votes from antivirus engines
        malware_votes (int): The number of malware votes from antivirus
                               engines
        raw_tags (typing.List[str]): List of raw tags, extracted from the
                                     detection of each antivirus engine
    """
    benign_votes: int = 0
    malware_votes: int = 0
    raw_tags: typing.List[str] = []

    def __init__(self, benign_votes: int, malware_votes: int,
                 raw_tags: typing.List[str]):
        """Initializes the FileResults instance."""
        dict.__init__(self,
                      benign_votes=benign_votes,
                      malware_votes=malware_votes,
                      raw_tags=raw_tags)


class VirusTotalScanner:
    """Class for scanning with Virus Total a file hash"""
    _api_client: vt.Client = None

    def __init__(self, api_key: str):
        """Initializes the VirusTotalScanner instance.

        Args:
            api_key (str): Virus Total API key
        """
        self._api_client = vt.Client(api_key)

    def __del__(self):
        """Destroys the VirusTotalScanner instance."""
        self._api_client.close()

    def scan(self, file_hash: str) -> FileResults:
        """Scans a file hash using Virus Total API.

        Args:
            file_hash (str): Hash of the file

        Returns:
            FileResults: The results of scanning the hash
        """
        file = self._api_client.get_object("/files/{}".format(file_hash))

        benign_votes = 0
        malware_votes = 0
        raw_tags = []
        for vendor in file.last_analysis_results.keys():
            antivirus_scan = file.last_analysis_results[vendor]

            # Get votes
            if (antivirus_scan["category"] and antivirus_scan["category"]
                    in DikeConfig.VT_ANTIVIRUS_MALWARE_CATEGORIES):
                malware_votes += 1
            else:
                benign_votes += 1

            # Extract tags
            if (antivirus_scan["result"]):
                raw_tags.extend(
                    re.sub(r"[^\w]", " ", antivirus_scan["result"]).split())

        return FileResults(benign_votes, malware_votes, raw_tags)
