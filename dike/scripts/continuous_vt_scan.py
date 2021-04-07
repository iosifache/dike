"""Script for continuous scanning of hashes using VirusTotal API.

The script contains functionalities extracted from the dike's modules. It is
platform-independent (the required classes are already included) and runs
without other files.

It needs to be deployed as a Google Cloud Function. It consumes hashes from a
file on a bucket from Google Cloud Storage, scans them using VirusTotal, and
adds a new entry into a CSV file saved in the same bucket.

Environment variables that must be set are:
- BUCKET_NAME, for the name of the bucket from Google Cloud Storage;
- HASHES_FILENAME, for the name of the file containing hashes;
- CSV_FILENAME, for the name of the CSV file where results are dumped; and
- VT_API_KEY, for VirusTotal API key.

Required modules, to be noted in requirements.txt of the Cloud Function, are:
- vt_py (used version at the time was 0.6.1); and
- google-cloud-storage (used version at the time was 1.35.0).
"""
import os
import re
import typing

import vt
from google.cloud import functions, storage

ANTIVIRUSES_MALWARE_CATEGORIES = ["malicious", "suspicious"]
BUCKET_NAME = os.environ["BUCKET_NAME"]
HASHES_FILENAME = os.environ["HASHES_FILENAME"]
CSV_FILENAME = os.environ["CSV_FILENAME"]
VT_API_KEY = os.environ["VT_API_KEY"]
TEMP_HASHES_FILENAME = os.path.join("/tmp", HASHES_FILENAME)  # nosec
TEMP_CSV_FILENAME = os.path.join("/tmp", CSV_FILENAME)  # nosec


class FileResults(dict):
    """See the modules/dataset/vt_scanner.py file."""

    benign_votes: int
    malicious_votes: int
    raw_tags: typing.List[str]

    def __init__(  # noqa
            self, benign_votes: int, malicious_votes: int,
            raw_tags: typing.List[str]) -> None:
        dict.__init__(self,
                      benign_votes=benign_votes,
                      malicious_votes=malicious_votes,
                      raw_tags=raw_tags)


class VirusTotalScanner:
    """See the modules/dataset/vt_scanner.py file."""

    _api_client: vt.Client

    def __init__(self, api_key: str) -> None:  # noqa
        self._api_client = vt.Client(api_key)

    def __del__(self):  # noqa
        self._api_client.close()

    # pylint: disable=missing-function-docstring
    def scan(self, file_hash: str) -> FileResults:  # noqa
        scan_url = "/files/{}".format(file_hash)
        try:
            file = self._api_client.get_object(scan_url)
        except Exception:
            return None

        benign_votes = 0
        malicious_votes = 0
        raw_tags = []
        for vendor in file.last_analysis_results.keys():
            vendor_verdict = file.last_analysis_results[vendor]

            # Get the vote of the vendor
            if (vendor_verdict["category"] and vendor_verdict["category"]
                    in ANTIVIRUSES_MALWARE_CATEGORIES):
                malicious_votes += 1
            else:
                benign_votes += 1

            # Get the raw tags assigned by the vendor
            tags = vendor_verdict["result"]
            if tags:
                raw_tags.extend(re.sub(r"[^\w]", " ", tags).split())

        return FileResults(benign_votes, malicious_votes, raw_tags)


# pylint: disable=unused-argument
def scan_hashes_automatically(event: dict, context: functions.Context):
    """Scans the next file hash.

    This function is implemented as a Cloud Function triggered by a Pub/Sub
    event.

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
    if len(content) == 0:
        return

    # Write all hashes, except the first one, to a temporary file, upload it to
    # Google Storage and delete it after
    with open(TEMP_HASHES_FILENAME, "w") as temp_hash_file:
        temp_hash_file.writelines(content[1:])
    hashes_file_write = bucket.get_blob(HASHES_FILENAME)
    hashes_file_write.upload_from_filename(TEMP_HASHES_FILENAME)
    os.remove(TEMP_HASHES_FILENAME)

    # Scan the first hash with VirusTotal
    file_hash = content[0].rstrip()
    client = VirusTotalScanner(VT_API_KEY)
    result = client.scan(file_hash)

    # Dump the result into the CSV file
    csv_file_read = bucket.get_blob(CSV_FILENAME)
    content = csv_file_read.download_as_string()
    content = content.decode("utf-8").splitlines(True)
    csv_row = file_hash + "," + str(result["benign_votes"]) + "," + str(
        result["malicious_votes"]) + "," + " ".join(result["raw_tags"]) + "\n"
    content.append(csv_row)

    # Write to a local file, upload it and delete it after
    with open(TEMP_CSV_FILENAME, "w") as temp_csv_file:
        temp_csv_file.writelines(content)
    csv_file_write = bucket.get_blob(CSV_FILENAME)
    csv_file_write.upload_from_filename(TEMP_CSV_FILENAME)
    os.remove(TEMP_CSV_FILENAME)
