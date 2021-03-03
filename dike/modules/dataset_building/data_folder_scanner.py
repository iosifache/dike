"""Module continuously scanning the benign files and malware folders

Usage example:

    data_folder_scanner = DataFolderScanner()

    # In case of manual edit of the files
    data_folder_scanner.update_malware_labels()

    # Start the scanning of the malware folder (each 30 minutes, with 20 seconds
    # between two consecutive VirusTotal scans) and of the benign one (each 30
    # minutes). After one hour, stop the scanning.
    data_folder_scanner.start_scanning(True, 30 * 60, 20)
    data_folder_scanner.start_scanning(False, 30 * 60)
    time.sleep(2 * 30 * 60)
    data_folder_scanner.stop_scanning()
"""
import os
import time
from threading import Lock, Thread

import pandas
from configuration.dike import DikeConfig
from Crypto.Hash import SHA256
from modules.dataset_building.types import AnalyzedFileTypes
from modules.dataset_building.vt_scanner import VirusTotalScanner
from modules.preprocessing.preprocessors import GroupCounter
from modules.utils.configuration import ConfigurationSpace, ConfigurationWorker
from modules.utils.logger import LoggedMessageType, Logger
from sklearn import preprocessing


class DataFolderScanner:
    """Class for continuous scanning of folders containing benign files or
    malware"""
    _folder_watch_thread: Thread
    _vt_scan_thread: Thread
    _mutex: Lock
    _stop_scan_threads: bool

    def __init__(self) -> None:
        """Initializes the DataFolderScanner instance."""
        # Read the configuration
        configuration = ConfigurationWorker()
        dataset_builder_config = configuration.get_configuration_space(
            ConfigurationSpace.DATASET_BUILDER)
        secrets_config = configuration.get_configuration_space(
            ConfigurationSpace.SECRETS)

        # Initialize the members
        self._vt_api_key = secrets_config["virus_total_api_key"]
        self._malware_families = dataset_builder_config["malware_families"]
        self._malware_benign_vote_ratio = dataset_builder_config[
            "malware_benign_vote_ratio"]
        self._min_ignored_percent = dataset_builder_config[
            "min_ignored_percent"]

        # Default members values
        self._folder_watch_thread = None
        self._vt_scan_thread = None
        self._mutex = Lock()
        self._stop_scan_threads = False

    def _process_new_samples(self, malware_folder: bool) -> None:
        Logger.log("Start processing files from the given folder\n",
                   LoggedMessageType.BEGINNING)

        # Open required files
        vt_data_content = None
        if malware_folder:

            work_dir = DikeConfig.MALWARE_DATASET_FOLDER
            next_step_filename = DikeConfig.MALWARE_HASHES

            with open(DikeConfig.VT_DATA_FILE, "r") as vt_data_read:
                vt_data_content = vt_data_read.read()

        else:
            work_dir = DikeConfig.BENIGN_DATASET_FOLDER
            next_step_filename = DikeConfig.BENIGN_LABELS

        next_step_write = open(next_step_filename, "a")
        with open(next_step_filename, "r") as next_step_read:
            next_step_content = next_step_read.read()

        filenames = next(os.walk(work_dir))[2]
        new_malware = 0

        for filename in filenames:
            # Get extension
            extension = os.path.splitext(filename)[1][1:]

            # Get hash of file
            full_path = os.path.join(work_dir, filename)
            with open(full_path, "rb") as current_file_read:
                content = current_file_read.read()
            file_hash = SHA256.new(data=content).hexdigest()

            # Check if the file is named correctly
            standard_type = AnalyzedFileTypes.map_extension_to_type(extension)
            standard_full_name = os.path.join(
                work_dir, file_hash + "." + standard_type.value.EXTENSION)
            if (full_path != standard_full_name):
                os.rename(full_path, standard_full_name)

            # Continue if the file hash was already tracked or scanned
            if (file_hash in next_step_content
                    or (malware_folder and file_hash in vt_data_content)):
                continue

            # Write to file
            if malware_folder:
                new_malware += 1
                next_step_write.write(file_hash + "\n")
            else:
                next_step_write.write(
                    str(standard_type.value.ID) + "," + file_hash +
                    (len(self._malware_families) + 1) * ",0" + "\n")

        self.update_malware_labels()

        next_step_write.close()

        Logger.log("")
        Logger.log(
            "Successfully dumped {} hashes into file".format(len(filenames)),
            LoggedMessageType.SUCCESS)

    def _scan_file_hash(self) -> None:
        # Read all hashes from the file
        with open(DikeConfig.MALWARE_HASHES, "r") as hash_file_read:
            content = hash_file_read.read().splitlines(True)

        # Check if the file is empty
        if (len(content) == 0):
            Logger.log("The given file is empty", LoggedMessageType.FAIL)
            return

        # Write all hashes, except the first one
        hash_file = open(DikeConfig.MALWARE_HASHES, "w")
        hash_file.writelines(content[1:])
        hash_file.close()

        # Process first hash
        hash_file = content[0].rstrip()
        Logger.log("Hash to be scanned is {}".format(hash_file),
                   LoggedMessageType.WORK)

        try:

            # Scan the given hash with VirusTotal
            client = VirusTotalScanner(self._vt_api_key)
            result = client.scan(hash_file)

            # Dump the result into the CSV file
            already_exists = os.path.isfile(DikeConfig.VT_DATA_FILE)
            output_file = open(DikeConfig.VT_DATA_FILE, "a")
            if not already_exists:
                output_file.write(
                    "hash,harmless_votes,malicious_votes,raw_tags\n")
            csv_row = hash_file + "," + str(
                result["benign_votes"]) + "," + str(
                    result["malware_votes"]) + "," + " ".join(
                        result["raw_tags"]) + "\n"
            output_file.write(csv_row)
            output_file.close()

            Logger.log("The given hash was found in the VirusTotal database",
                       LoggedMessageType.SUCCESS)

        except:
            Logger.log("The given hash is not tracked by VirusTotal",
                       LoggedMessageType.FAIL)

    @staticmethod
    def _get_malice_score(malware_benign_vote_ratio: int, malice_votes: int,
                          harmless_votes: int) -> int:
        # Compute the weighted average from the antivirus engines votes
        return (malware_benign_vote_ratio * malice_votes) / (
            malware_benign_vote_ratio * malice_votes + harmless_votes)

    def update_malware_labels(self) -> None:
        """Updates the labels of the malware.

        This can be used in order to forcefully process VirusTotal new tags,
        manually placed into the specific file (for example, after running in
        the Google Cloud Platform the extraction script)."""
        Logger.log("Start processing new malware labels\n",
                   LoggedMessageType.BEGINNING)

        # Read raw tags from file
        vt_data_df = pandas.read_csv(DikeConfig.VT_DATA_FILE)
        raw_tags = vt_data_df["raw_tags"]

        # Get lowercase individual tags
        raw_tags = []
        for elem in raw_tags:
            raw_tags.extend(elem.lower().split(" "))

        # Create a new data frame
        malware_families_names = [
            family.lower() for family in list(self._malware_families.keys())
        ]
        columns = ["type", "hash", "malice"]
        columns.extend(malware_families_names)
        labels_df = pandas.DataFrame(columns=columns)

        import tqdm

        progress_bar = tqdm.tqdm(total=len(labels_df))

        progress_bar.display()

        # Populate the created data frame
        all_families = []
        extractor = GroupCounter(self._malware_families, True)
        for _, entry in vt_data_df.iterrows():
            # Get the file extension
            for filename in os.listdir(DikeConfig.MALWARE_DATASET_FOLDER):
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
                DataFolderScanner._get_malice_score(
                    self._malware_benign_vote_ratio, entry["malicious_votes"],
                    entry["harmless_votes"]),
                *(preprocessing.normalize([family_votes], "l1")[0])
            ]
            labels_df = labels_df.append(
                [pandas.Series(new_entry, index=labels_df.columns)],
                ignore_index=True)

            progress_bar.update(1)

        progress_bar.close()

        Logger.log("")

        # Print all outliers that were not considered into malware families
        # groups
        extractor = GroupCounter(self._malware_families, True, True,
                                 self._min_ignored_percent)
        extractor.fit_transform([all_families])

        # Dump data frame to CSV file
        labels_df.to_csv(DikeConfig.MALWARE_LABELS, index=False)

        Logger.log("Successfully dumped labels to file",
                   LoggedMessageType.SUCCESS)

    def _continuous_folder_watch(self, malware_folder: bool,
                                 sleep_in_seconds: int) -> None:
        # While the stop function is not called, scan and sleep
        while (not self._stop_scan_threads):
            self._mutex.acquire()
            self._process_new_samples(malware_folder)
            self._mutex.release()

            time.sleep(sleep_in_seconds)

    def _continuous_vt_scan(self, sleep_in_seconds: int) -> None:
        # While the stop function is not called, scan and sleep
        while (not self._stop_scan_threads):
            self._mutex.acquire()
            self._scan_file_hash()
            self._mutex.release()

            time.sleep(sleep_in_seconds)

    def start_scanning(self,
                       malware_folder: bool,
                       folder_watch_interval: int,
                       vt_scan_interval: int = 0) -> None:
        """Starts the continuous scanning of a given folder, containing benign
        programs or malware.

        The hashes of the new files from the malware folder are scanned
        periodically with VirusTotal. This step is skipped for the benign ones,
        which are assumed completely clear.

        Besides this, it updates the malware labels file based on the features
        extracted from VirusTotal. This behavior is triggered by the detection
        of folder change.

        The malice score is computed as a weighted average, where each antivirus
        engine vote has a weight: 1 for benign and malware_benign_vote_ratio for
        malware.

        Args:
            malware_folder (bool): Boolean indicating if the scanning should be
                for the folder with benign files or the one with malware samples
            folder_watch_interval (int): Number of seconds between two
                consecutive scans of the given folder
            vt_scan_interval (int, optional): Number of seconds between two
                consecutive scans of a malware hash with VirusTotal. Only for
                malware folder scanning and useful to respect the quota of the
                used account
        """
        self._folder_watch_thread = Thread(
            target=self._continuous_folder_watch,
            args=(malware_folder, folder_watch_interval))
        self._folder_watch_thread.start()

        if (malware_folder):
            self._vt_scan_thread = Thread(target=self._continuous_vt_scan,
                                          args=(vt_scan_interval, ))
            self._vt_scan_thread.start()

        Logger.log("Starting the scan of data folder",
                   LoggedMessageType.BEGINNING)

    def stop_scanning(self) -> None:
        """Stops the continuous scanning, previously started."""
        self._stop_scan_threads = True

        Logger.log("Stopping the scan of data folder", LoggedMessageType.END)
