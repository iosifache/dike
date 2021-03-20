"""Module for manipulating datasets

Usage example:

    # Create a dataset of 100 benign PE and 100 malware samples, with minimum
    # malice of 0.9
    DatasetWorker.create_dataset(AnalyzedFileTypes.PE, 0.9, 9 * [True], 200,
                                 0.5, "pe_malice.csv")

    # Create a dataset of 200 generic and trojan PE samples, with minimum malice
    # of 0.9
    DatasetWorker.create_dataset(
        AnalyzedFileTypes.PE, 0.9,
        [True, True, False, False, False, False, False, False, False], 200, 0,
        "pe_generic_vs_tojan.csv")
"""
import json
import os
import typing

import pandas
from configuration.dike import DikeConfig
from modules.dataset_building.types import AnalyzedFileTypes
from modules.utils.logger import LoggedMessageType, Logger


class DatasetWorker:
    """Class for working with datasets"""
    @staticmethod
    def create_dataset(file_type: AnalyzedFileTypes,
                       min_malice: float,
                       desired_families: typing.List[bool],
                       entries_count: int,
                       benign_ratio: float,
                       output_filename: str,
                       description: str = "") -> bool:
        """Creates a custom dataset (a CSV containing the labels of the selected
        samples) based on the given parameters.

        Args:
            file_type (AnalyzedFileTypes): Type of files to include
            min_malice (float): Minimum malice score of malware samples included
                in the dataset
            desired_families (typing.List[bool]): Array of booleans, in which
                each entry indicates if the pointed family (via index) is
                included into the dataset
            entries_count (int): Mandatory number of entries in the dataset
            benign_ratio (float): Ratio between the size of benign samples and
                of the whole dataset
            output_filename (str): The basename of the output file
            description (str, optional): Description of the dataset. Defaults to
                "".

        Returns:
            bool: Boolean indicating if the dataset was successfully created
        """
        malware_labels_df = pandas.read_csv(DikeConfig.MALWARE_LABELS)
        benign_labels_df = pandas.read_csv(DikeConfig.BENIGN_LABELS)

        # Select only the desired file type
        malware_labels_df = malware_labels_df[malware_labels_df["type"] ==
                                              file_type.value.ID]
        benign_labels_df = benign_labels_df[benign_labels_df["type"] ==
                                            file_type.value.ID]

        # Get entries count for each type of sample
        malware_count = int((1 - benign_ratio) * entries_count)
        benign_count = entries_count - malware_count

        # Select entries with minimum malice
        malware_labels_df = malware_labels_df[
            malware_labels_df["malice"] >= min_malice]

        # Check if a dataset can be built
        if (len(malware_labels_df) < malware_count
                or len(benign_labels_df) < benign_count):
            Logger().log("Insufficient entries to build a dataset",
                         LoggedMessageType.FAIL)

            return False

        # Select entries with maximum membership to the given categories
        desired_families_int = [1 if elem else 0 for elem in desired_families]
        malware_labels_df["membership"] = malware_labels_df.iloc[:, 3:].dot(
            desired_families_int)
        malware_labels_df.sort_values("membership")
        del malware_labels_df["membership"]
        malware_labels_df = malware_labels_df.head(malware_count)

        # Select random benign entries
        benign_labels_df = benign_labels_df.sample(n=benign_count)

        # Merge data frames
        all_labels_df = pandas.concat([malware_labels_df, benign_labels_df])
        all_labels_df = all_labels_df.sample(frac=1).reset_index(drop=True)

        # Dump to files
        output_full_filename = os.path.join(DikeConfig.CUSTOM_DATASETS_FOLDER,
                                            output_filename)
        all_labels_df.to_csv(output_full_filename, index=False)

        # Create the metadata and place it to the file
        desired_families_names = [
            name for include, name in zip(
                desired_families, malware_labels_df.columns[3:]) if include
        ]
        metadata = {
            "description": description,
            "extension": file_type.value.EXTENSION,
            "min_malice": min_malice,
            "desired_families": desired_families_names,
            "entries_count": entries_count,
            "benign_ratio": benign_ratio
        }
        stringified_metadata = json.dumps(metadata)
        with open(output_full_filename, "r+") as output_file:
            content = output_file.read()
            output_file.seek(0, 0)
            output_file.write(DikeConfig.DATASET_METADATA_LINE_START +
                              stringified_metadata + "\n" + content)

        return True

    @staticmethod
    def list_datasets() -> typing.List[typing.List]:
        """Lists the metadata of all created datasets.

        Returns:
            typing.List[typing.List]: Datasets metadatas
        """
        all_metadata = pandas.DataFrame()

        filenames = os.listdir(DikeConfig.CUSTOM_DATASETS_FOLDER)
        for filename in filenames:
            # Skip the hidden files
            if not filename.startswith("."):
                full_filename = os.path.join(DikeConfig.CUSTOM_DATASETS_FOLDER,
                                             filename)
                with open(full_filename, "r") as file:
                    lines = file.readlines()
                    if (len(lines) == 0):
                        continue
                    metadata_line = lines[0]

                    if (not metadata_line.startswith(
                            DikeConfig.DATASET_METADATA_LINE_START)):
                        continue

                    metadata_line = metadata_line[
                        len(DikeConfig.DATASET_METADATA_LINE_START):]
                    metadata = json.loads(metadata_line)
                    metadata["filename"] = filename

                    all_metadata = all_metadata.append(metadata,
                                                       ignore_index=True)

        datasets_details = all_metadata.values.tolist()
        datasets_details.insert(0, all_metadata.columns.to_list())

        return datasets_details

    @staticmethod
    def remove_dataset(dataset_filename: str) -> None:
        """Removes a created dataset.

        Args:
            dataset_filename (str): Name of the dataset
        """
        full_filename = os.path.join(DikeConfig.CUSTOM_DATASETS_FOLDER,
                                     dataset_filename)
        os.remove(full_filename)
