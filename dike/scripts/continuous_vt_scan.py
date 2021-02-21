"""Script for continuously scan hashes using Virus Total API

It needs to be deployed as a Google Cloud Function. It consumes hashes from a
file on a bucket from Google Cloud Storage, scan them using Virus Total, and
adds a new entry into a CSV file saved in the same bucket.

The script is platform-independent (the required classes are already included)
and runs without other files from dike.

Environment variables that must be set are:
- BUCKET_NAME, for the name of the bucket from Google Cloud Storage;
- HASHES_FILENAME, for the name of the file containing hashes;
- CSV_FILENAME, for the name of the CSV file where results are dumped; and
- VT_API_KEY, for Virus Total API key.

Required modules, to be noted in requirements.txt in the Cloud Function are:
- vt_py (used version at the time was 0.6.1); and
- google-cloud-storage (used version at the time was 1.35.0).
"""

import os
import re
import typing

import vt
from google.cloud import functions, storage

# Contants
ANTIVIRUSES_MALWARE_CATEGORIES = ["malicious", "suspicious"]

# Get environment variables
BUCKET_NAME = os.environ["BUCKET_NAME"]
HASHES_FILENAME = os.environ["HASHES_FILENAME"]
CSV_FILENAME = os.environ["CSV_FILENAME"]
VT_API_KEY = os.environ["VT_API_KEY"]

# Get full paths
TEMP_HASHES_FILENAME = os.path.join("/tmp", HASHES_FILENAME)
TEMP_CSV_FILENAME = os.path.join("/tmp", CSV_FILENAME)


class FileResults(dict):
    """Class description found in
    subordinate/modules/dataset_building/vt_scanner.py
    """
    benign_votes: int = 0
    malware_votes: int = 0
    raw_tags: typing.List[str] = []

    def __init__(self, benign_votes: int, malware_votes: int,
                 raw_tags: typing.List[str]) -> None:
        dict.__init__(self,
                      benign_votes=benign_votes,
                      malware_votes=malware_votes,
                      raw_tags=raw_tags)


class VirusTotalScanner:
    """Class description can be found in
    subordinate/modules/dataset_building/vt_scanner.py
    """
    _api_client: vt.Client = None

    def __init__(self, api_key: str) -> None:
        self._api_client = vt.Client(api_key)

    def __del__(self):
        self._api_client.close()

    def scan(self, file_hash: str):
        """Function description can be found in
        subordinate/modules/dataset_building/vt_scanner.py
        """
        file = self._api_client.get_object("/files/{}".format(file_hash))

        benign_votes = 0
        malware_votes = 0
        raw_tags = []
        for vendor in file.last_analysis_results.keys():
            antivirus_scan = file.last_analysis_results[vendor]

            # Get votes
            if (antivirus_scan["category"] and antivirus_scan["category"]
                    in ANTIVIRUSES_MALWARE_CATEGORIES):
                malware_votes += 1
            else:
                benign_votes += 1

            # Extract tags
            if (antivirus_scan["result"]):
                raw_tags.extend(
                    re.sub(r"[^\w]", " ", antivirus_scan["result"]).split())

        return FileResults(benign_votes, malware_votes, raw_tags)


# pylint: disable=unused-argument
def scan_hashes_automatically(event: dict, context: functions.Context):
    """Cloud function triggered by a Pub/Sub event

    Args:
        event (dict): Dictionary with data specific to this type of event
        context (functions.Context): Cloud Functions event metadata
    """
    # Read all hashes from the file
    client = storage.Client()
    bucket = client.get_bucket(BUCKET_NAME)
    hashes_file_read = bucket.get_blob(HASHES_FILENAME)
    content = hashes_file_read.download_as_string()
    content = content.decode("utf-8").splitlines(True)

    # Check if the file is empty
    if (len(content) == 0):
        return

    # Write all hashes, except the first one, to a temporary file, upload it to
    # Google Storage and delete it after
    with open(TEMP_HASHES_FILENAME, "w") as temp_hash_file:
        temp_hash_file.writelines(content[1:])
    hashes_file_write = bucket.get_blob(HASHES_FILENAME)
    hashes_file_write.upload_from_filename(TEMP_HASHES_FILENAME)
    os.remove(TEMP_HASHES_FILENAME)

    # Get first hash
    file_hash = content[0].rstrip()

    # Scan the given hash with VirusTotal
    client = VirusTotalScanner(VT_API_KEY)
    result = client.scan(file_hash)

    # Dump the result into the CSV file
    csv_file_read = bucket.get_blob(CSV_FILENAME)
    content = csv_file_read.download_as_string()
    content = content.decode("utf-8").splitlines(True)
    csv_row = file_hash + "," + str(result["benign_votes"]) + "," + str(
        result["malware_votes"]) + "," + " ".join(result["raw_tags"]) + "\n"
    content.append(csv_row)

    # Write to a local file, upload it and delete it after
    with open(TEMP_CSV_FILENAME, "w") as temp_csv_file:
        temp_csv_file.writelines(content)
    csv_file_write = bucket.get_blob(CSV_FILENAME)
    csv_file_write.upload_from_filename(TEMP_CSV_FILENAME)
    os.remove(TEMP_CSV_FILENAME)
