"""VirusTotal scan.

Usage example:

    # Create a scanner
    scanner = VirusTotalScanner(
        "86708bfb237c723356f50ac8e64889d1b97a9babb281c01bc4cdfa69d2508792")

    # Scan a hash and get the results
    results = scanner.scan(
        "000cb7a0624d52380f164f2c99984e5dde248458f36bfb932dca4e3ed2df69b1")
"""
import re
import typing

import vt
from modules.configuration.parameters import Packages
from modules.dataset.errors import VirusTotalRequestError


class FileResults(dict):
    """Class encapsulating the relevant details of a VirusTotal scan.

    Attributes:
        benign_votes (int): The number of benign votes from antivirus engines
        malicious_votes (int): The number of malicious votes from antivirus
            engines
        raw_tags (typing.List[str]): List of raw tags, extracted from the
            detections of each antivirus engine
    """

    benign_votes: int
    malicious_votes: int
    raw_tags: typing.List[str]

    def __init__(self, benign_votes: int, malicious_votes: int,
                 raw_tags: typing.List[str]) -> None:
        """Initializes the FileResults instance.

        Args:
            benign_votes (int): Number of votes which considers the file benign
            malicious_votes (int): Number of votes which considers the file
                malicious
            raw_tags (typing.List[str]): Raw tags attributed by the antivirus
                engines
        """
        dict.__init__(self,
                      benign_votes=benign_votes,
                      malicious_votes=malicious_votes,
                      raw_tags=raw_tags)


class VirusTotalScanner:
    """Class for scanning a file hash with VirusTotal."""

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
            FileResults: The results of the scan
        """
        scan_url = "/files/{}".format(file_hash)
        try:
            file = self._api_client.get_object(scan_url)
        except Exception:
            raise VirusTotalRequestError()

        benign_votes = 0
        malicious_votes = 0
        raw_tags = []
        for vendor in file.last_analysis_results.keys():
            vendor_verdict = file.last_analysis_results[vendor]

            # Get the vote of the vendor
            if (vendor_verdict["category"] and vendor_verdict["category"] in
                    Packages.Features.VirusTotal.ANTIVIRUS_MALWARE_CATEGORIES):
                malicious_votes += 1
            else:
                benign_votes += 1

            # Get the raw tags assigned by the vendor
            tags = vendor_verdict["result"]
            if tags:
                raw_tags.extend(re.sub(r"[^\w]", " ", tags).split())

        return FileResults(benign_votes, malicious_votes, raw_tags)
