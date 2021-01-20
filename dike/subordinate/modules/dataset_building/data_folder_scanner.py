from sklearn import preprocessing
import pandas
from threading import Thread, Lock
from Crypto.Hash import SHA256
import tqdm
import os
import time
from subordinate.modules.dataset_building.vt_scanner import VirusTotalScanner
from subordinate.modules.preprocessors import GroupCounter
from configuration.dike import DikeConfig
from utils.logger import Logger, LoggedMessageType


class DataFolderScanner:
    """Class for continuous scanning of folders containing malign files or
    malware"""
    _vt_api_key: str = None
    _malware_families: dict = None
    _malware_benign_vote_ratio: int = 1
    _folder_watch_thread: Thread = None
    _vt_scan_thread: Thread = None
    _mutex: Lock = Lock()
    _stop_scan_threads: bool = False

    def __init__(self,
                 vt_api_key: str = None,
                 malware_families: dict = None,
                 malware_benign_vote_ratio: int = 0):
        """Initializes the DataFolderScanner instance.

        Args:
            vt_api_key (str, optional): The API key from Virus Total, used to
                                            scan malware hashed. Defaults to 
                                            None, because of the possibility to
                                            scan the benign folder too.
            malware_families (dict, optional): Dictionary with malware families
                                               and patterns for antivirus 
                                               engine detections. Defaults to
                                               None, because of the possibility
                                               to scan the benign folder too.
            malware_benign_vote_ratio (int, optional): The weight of a malware 
                                                       antivirus engine vote.
                                                       Defaults to None, because
                                                       of the possibility to
                                                       scan the benign folder
                                                       too.
        """
        self._vt_api_key = vt_api_key
        self._malware_families = malware_families
        self._malware_benign_vote_ratio = malware_benign_vote_ratio

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
        progress_bar = tqdm.tqdm(total=len(list(filenames)))
        new_malware = 0

        for filename in filenames:

            # Get hash of file
            full_path = os.path.join(work_dir, filename)
            with open(full_path, "rb") as current_file_read:
                content = current_file_read.read()
            file_hash = SHA256.new(data=content).hexdigest()

            # Check if the file is named correctly
            standard_full_name = os.path.join(work_dir, file_hash + ".exe")
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
                    file_hash +
                    (DikeConfig.MALWARE_CATEGORIES_COUNT + 1) * ",0" + "\n")

            # Update the progress
            progress_bar.update(1)

        # Check if the malware labels must be updated
        if (new_malware != 0):
            self._update_malware_labels(self._malware_families,
                                        self._malware_benign_vote_ratio)

        progress_bar.close()
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
        hash = content[0].rstrip()
        Logger.log("Hash to be scanned is {}".format(hash),
                   LoggedMessageType.WORK)

        try:

            # Scan the given hash with VirusTotal
            client = VirusTotalScanner(self._vt_api_key)
            result = client.scan(hash)

            # Dump the result into the CSV file
            already_exists = os.path.isfile(DikeConfig.VT_DATA_FILE)
            print(already_exists)
            output_file = open(DikeConfig.VT_DATA_FILE, "a")
            if not already_exists:
                output_file.write("hash,benign_votes,malware_votes,raw_tags\n")
            csv_row = hash + "," + str(result["benign_votes"]) + "," + str(
                result["malware_votes"]) + "," + " ".join(
                    result["raw_tags"]) + "\n"
            output_file.write(csv_row)
            output_file.close()

            Logger.log("The given hash was found in the Virus Total database",
                       LoggedMessageType.SUCCESS)

        except:
            Logger.log("The given hash is not tracked by Virus Total",
                       LoggedMessageType.FAIL)

    @staticmethod
    def _get_malice_score(malware_benign_vote_ratio: int, malice_votes: int,
                          benign_votes: int) -> int:
        # Compute the weighted average from the antivirus engines votes
        return (malware_benign_vote_ratio * malice_votes) / (
            malware_benign_vote_ratio * malice_votes + benign_votes)

    @staticmethod
    def _update_malware_labels(malware_families: dict,
                               malware_benign_vote_ratio: int) -> None:
        # Read raw tags from file
        vt_data_df = pandas.read_csv(DikeConfig.VT_DATA_FILE)
        raw_tags = vt_data_df["raw_tags"]

        # Get lowercase individual tags
        raw_tags = []
        for elem in raw_tags:
            raw_tags.extend(elem.lower().split(" "))

        # Create a new data frame
        malware_families = [
            family.lower() for family in list(malware_families.keys())
        ]
        columns = ["hash", "malice"]
        columns.extend(malware_families)
        labels_df = pandas.DataFrame(columns=columns)

        # Populate the created data frame
        extractor = GroupCounter(malware_families, True, 1, True)
        for _, entry in vt_data_df.iterrows():
            family_votes = extractor.fit_transform(
                entry["raw_tags"].split(" "))
            new_entry = [
                entry["hash"],
                DataFolderScanner._get_malice_score(malware_benign_vote_ratio,
                                                    entry["malware_votes"],
                                                    entry["benign_votes"]),
                *(preprocessing.normalize([family_votes], "l1")[0])
            ]
            labels_df = labels_df.append(
                [pandas.Series(new_entry, index=labels_df.columns)],
                ignore_index=True)

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
                                   for the folder with benign files or the one
                                   with malware samples
            folder_watch_interval (int): Number of seconds between two
                                         consecutive scans of the given
                                         folder
            vt_scan_interval (int, optional): Number of seconds between two 
                                              consecutive scans of a malware
                                              hash with VirusTotal. Only for
                                              malware folder scanning and useful
                                              to respect the quota of the used
                                              account
        """
        self._folder_watch_thread = Thread(
            target=self._continuous_folder_watch,
            args=(malware_folder, folder_watch_interval))
        self._folder_watch_thread.start()

        if (malware_folder):
            self._vt_scan_thread = Thread(target=self._continuous_vt_scan,
                                          args=(vt_scan_interval))
            self._vt_scan_thread.start()

        Logger.log("Starting the scan of data folder",
                   LoggedMessageType.BEGINNING)

    def stop_scanning(self) -> None:
        """Stops the continuous scanning, previously started."""
        self._stop_scan_threads = True

        Logger.log("Stopping the scan of data folder", LoggedMessageType.END)