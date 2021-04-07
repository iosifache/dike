"""Continuously scanning the benign and malware folders.

Usage example:

    # Create a scanner
    scanner = DataFolderScanner()

    # In case of manual edit of the malware labels files
    scanner.update_malware_labels()

    # Start the scanning of the malware folder (each 30 minutes, with 20 seconds
    # between two consecutive VirusTotal scans) and of the benign one (each 30
    # minutes). After one hour, stop the scanning.
    scanner.start_scan(True, 30 * 60, 20)
    scanner.start_scan(False, 30 * 60)
    time.sleep(60 * 60)
    scanner.stop_scan()
"""
import os
import time
from threading import Lock, Thread

import pandas
from modules.configuration.folder_structure import Files, Folders
from modules.dataset.types import AnalyzedFileTypes
from modules.dataset.vt_scanner import VirusTotalScanner
from modules.preprocessing.preprocessors import GroupCounter
from modules.utils.configuration_manager import ConfigurationManager
from modules.utils.crypto import HashingEngine
from modules.utils.logger import Logger
from modules.utils.types import ConfigurationSpaces, LoggedMessageTypes
from sklearn import preprocessing


class DataFolderScanner:
    """Class for continuous scanning of folders.

    Each instance can scan only one folder at a time.
    """

    _folder_watch_thread: Thread
    _vt_scan_thread: Thread
    _mutex: Lock
    _stop_scan_threads: bool
    _scan_parameters: tuple

    def __init__(self) -> None:
        """Initializes the DataFolderScanner instance."""
        configuration = ConfigurationManager()
        dataset_config = configuration.get_space(ConfigurationSpaces.DATASET)
        secrets_config = configuration.get_space(ConfigurationSpaces.SECRETS)

        self._malware_families = dataset_config["malware_families"]
        self._malicious_benign_votes_ratio = dataset_config[
            "malicious_benign_votes_ratio"]
        self._min_ignored_percent = dataset_config["min_ignored_percent"]
        self._vt_api_key = secrets_config["vt_api_key"]

        self._folder_watch_thread = None
        self._vt_scan_thread = None
        self._mutex = Lock()
        self._stop_scan_threads = True
        self._scan_parameters = (None, None, None)

    def _process_new_samples(self, malware_folder: bool) -> None:
        # Open the required files
        vt_data_content = None
        if malware_folder:
            work_dir = Folders.MALICIOUS_FILES
            next_step_filename = Files.MALWARE_HASHES

            with open(Files.VT_DATA_FILE, "r") as vt_data_read:
                vt_data_content = vt_data_read.read()
        else:
            work_dir = Folders.BENIGN_FILES
            next_step_filename = Files.BENIGN_LABELS

        next_step_write = open(next_step_filename, "a")
        with open(next_step_filename, "r") as next_step_read:
            next_step_content = next_step_read.read()

        filenames = next(os.walk(work_dir))[2]
        new_malware = 0

        for filename in filenames:
            extension = os.path.splitext(filename)[1][1:]

            full_path = os.path.join(work_dir, filename)
            file_hash = HashingEngine.compute_content_sha256(full_path)

            # Check if the file is named correctly
            standard_type = AnalyzedFileTypes.map_extension_to_type(extension)
            standard_name = file_hash
            standard_name += "." + standard_type.value.STANDARD_EXTENSION
            standard_full_name = os.path.join(work_dir, standard_name)
            if full_path != standard_full_name:
                os.rename(full_path, standard_full_name)

            # Continue if the file hash was already tracked
            if file_hash in next_step_content:
                continue

            # Continue if the file hash was already scanned
            if malware_folder and (file_hash in vt_data_content):
                continue

            # Dump the hash or the corresponding label of the file, depending on
            # its malice
            if malware_folder:
                new_malware += 1
                next_step_write.write(file_hash + "\n")
            else:
                new_label_line = str(
                    standard_type.value.ID) + "," + file_hash + (
                        len(self._malware_families) + 1) * ",0" + "\n"
                next_step_write.write(new_label_line)

        self.update_malware_labels()

        next_step_write.close()

        Logger().log(
            "{} files from the folder were processed.".format(len(filenames)),
            LoggedMessageTypes.SUCCESS)

    def _scan_next_hash(self) -> None:
        # Read all hashes from the file
        with open(Files.MALWARE_HASHES, "r") as hash_file_read:
            content = hash_file_read.read().splitlines(True)

        # Check if the file is empty
        if len(content) == 0:
            return

        # Write all hashes, except the first one
        hash_file = open(Files.MALWARE_HASHES, "w")
        hash_file.writelines(content[1:])
        hash_file.close()

        # Process the first hash
        scanned_hash = content[0].rstrip()
        try:
            # Scan the given hash with VirusTotal
            client = VirusTotalScanner(self._vt_api_key)
            result = client.scan(scanned_hash)

            # Dump to the VirusTotal results CSV file
            output_file = open(Files.VT_DATA_FILE, "a")
            raw_tags = " ".join(result["raw_tags"])
            row_data = [
                scanned_hash,
                str(result["benign_votes"]),
                str(result["malicious_votes"]), raw_tags
            ]
            row = ",".join(row_data) + "\n"
            output_file.write(row)
            output_file.close()

            Logger().log(
                "The hash {} was found in the VirusTotal database.".format(
                    scanned_hash), LoggedMessageTypes.SUCCESS)
        except Exception:
            Logger().log(
                "The hash {} is not tracked by VirusTotal.".format(
                    scanned_hash), LoggedMessageTypes.INFORMATION)

    @staticmethod
    def _compute_malice(malicious_benign_votes_ratio: int, malice_votes: int,
                        harmless_votes: int) -> int:
        # Compute the weighted average from the antivirus engines votes
        return (malicious_benign_votes_ratio * malice_votes) / (
            malicious_benign_votes_ratio * malice_votes + harmless_votes)

    def update_malware_labels(self) -> None:
        """Updates the labels of the malware.

        This can be used in order to forcefully process VirusTotal new tags,
        manually placed into the specific file (for example, after running in
        the Google Cloud Platform the extraction script).
        """
        # Read the raw tags from file and process them by lowercasing
        vt_data_df = pandas.read_csv(Files.VT_DATA_FILE)
        raw_tags = vt_data_df["raw_tags"]
        processed_raw_tags = []
        for elem in raw_tags:
            processed_raw_tags.extend(elem.lower().split(" "))

        # Create a new data frame having the malware families included in the
        # malware families YAML file
        malware_families_names = [
            family.lower() for family in list(self._malware_families.keys())
        ]
        columns = ["type", "hash", "malice"]
        columns.extend(malware_families_names)
        labels_df = pandas.DataFrame(columns=columns)

        # Populate the created data frame
        all_families = []
        extractor = GroupCounter(self._malware_families, True)
        for _, entry in vt_data_df.iterrows():
            # Get the file extension
            for filename in os.listdir(Folders.MALICIOUS_FILES):
                if filename.startswith(entry["hash"]):
                    extension = os.path.splitext(filename)[1][1:]
                    file_type = AnalyzedFileTypes.map_extension_to_type(
                        extension).value.ID
                    break

            all_families.extend(entry["raw_tags"].split(" "))

            tags = [entry["raw_tags"].split(" ")]
            family_votes = extractor.fit_transform(tags)[0]
            new_entry = [
                file_type, entry["hash"],
                DataFolderScanner._compute_malice(
                    self._malicious_benign_votes_ratio,
                    entry["malicious_votes"], entry["harmless_votes"]),
                *(preprocessing.normalize([family_votes], "l1")[0])
            ]
            labels_df = labels_df.append(
                [pandas.Series(new_entry, index=labels_df.columns)],
                ignore_index=True)

        # Print all outliers that were not considered into malware families
        # groups
        extractor = GroupCounter(self._malware_families, True, True,
                                 self._min_ignored_percent)
        extractor.fit_transform([all_families])

        # Dump data frame to CSV file
        labels_df.to_csv(Files.MALWARE_LABELS, index=False)

        Logger().log("The processed malware labels were dumped to file.",
                     LoggedMessageTypes.SUCCESS)

    def _watch_continuously(self, malware_folder: bool,
                            sleep_in_seconds: int) -> None:
        while not self._stop_scan_threads:
            self._mutex.acquire()
            self._process_new_samples(malware_folder)
            self._mutex.release()

            time.sleep(sleep_in_seconds)

    def _scan_continuously(self, sleep_in_seconds: int) -> None:
        while not self._stop_scan_threads:
            self._mutex.acquire()
            self._scan_next_hash()
            self._mutex.release()

            time.sleep(sleep_in_seconds)

    def start_scan(self,
                   malware_folder: bool,
                   folder_watch_interval: int,
                   vt_scan_interval: int = 0) -> None:
        """Starts the continuous scanning of a given folder.

        The hashes of the new files from the malware folder are scanned
        periodically with VirusTotal. This step is skipped for the benign ones,
        which are assumed completely clear.

        Besides this, it updates the malware labels file based on the features
        extracted from VirusTotal. This behavior is triggered by the detection
        of folder change.

        The malice score is computed as a weighted average, where each antivirus
        engine vote has a weight: 1 for benign and malicious_benign_votes_ratio
        for malware.

        Args:
            malware_folder (bool): Boolean indicating if the scanning should be
                for the folder with benign files or the one with malware samples
            folder_watch_interval (int): Number of seconds between two
                consecutive scans of the given folder
            vt_scan_interval (int): Number of seconds between two consecutive
                scans of a malware hash with VirusTotal. Only for malware folder
                scanning and useful to respect the quota of the used account
        """
        self._stop_scan_threads = False

        self._folder_watch_thread = Thread(target=self._watch_continuously,
                                           args=(malware_folder,
                                                 folder_watch_interval))
        self._folder_watch_thread.start()

        if malware_folder:
            self._vt_scan_thread = Thread(target=self._scan_continuously,
                                          args=(vt_scan_interval, ))
            self._vt_scan_thread.start()

        self._scan_parameters = (malware_folder, folder_watch_interval,
                                 vt_scan_interval)

        Logger().log("The scan of data folder was started.",
                     LoggedMessageTypes.BEGINNING)

    def is_scan_active(self) -> tuple:
        """Checks if a folder scanning is active.

        Returns:
            tuple: Tuple containing on the first element a boolean indicating if
                the scanning is active. If it is set, then the second element in
                the tuple will contain the scan parameters.
        """
        return (not self._stop_scan_threads, self._scan_parameters)

    def stop_scan(self) -> None:
        """Stops a previously started continuous scanning."""
        self._stop_scan_threads = True
        self._scan_parameters = (None, None, None)

        Logger().log("The scan of data folder was stopped.",
                     LoggedMessageTypes.END)
