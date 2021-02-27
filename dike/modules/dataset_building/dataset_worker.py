import os
import typing

import pandas
from configuration.dike import DikeConfig
from modules.dataset_building.types import AnalyzedFileTypes
from modules.utils.logger import LoggedMessageType, Logger


class DatasetWorker:
    """Class for working with datasets"""
    @staticmethod
    def create_dataset(file_type: AnalyzedFileTypes, min_malice: float,
                       desired_families: typing.List[bool], enties_count: int,
                       benign_ratio: float, output_filename: str) -> None:
        """Creates a custom dataset (a CSV containing the labels of the selected
        samples) based on the given parameters.

        Args:
            file_type (AnalyzedFileTypes): Type of files to include
            min_malice (float): Minimum malice score of malware samples included
                                in the dataset
            desired_families (typing.List[bool]): Array of booleans, in which
                                                  each entry indicates if the
                                                  pointed family (via index) is
                                                  included into the dataset
            enties_count (int): Mandatory number of entries in the dataset
            benign_ratio (float): Ratio between the size of benign samples and
                                  of the whole dataset
            output_filename (str): The basename of the output file
        """
        malware_labels_df = pandas.read_csv(DikeConfig.MALWARE_LABELS)
        benign_labels_df = pandas.read_csv(DikeConfig.BENIGN_LABELS)

        # Select only the desired file type
        malware_labels_df = malware_labels_df[malware_labels_df["type"] ==
                                              file_type.value]
        benign_labels_df = benign_labels_df[benign_labels_df["type"] ==
                                            file_type.value]

        # Get entries count for each type of sample
        malware_count = int((1 - benign_ratio) * enties_count)
        benign_count = enties_count - malware_count

        # Select entries with minimum malice
        malware_labels_df = malware_labels_df[
            malware_labels_df["malice"] >= min_malice]

        # Check if a dataset can be built
        if (len(malware_labels_df) < malware_count
                or len(benign_labels_df) < benign_count):
            Logger.log("Insufficient entries to build a dataset",
                       LoggedMessageType.FAIL)

        # Select entries with maximum membership to the given categories
        desired_families_int = [1 if elem else 0 for elem in desired_families]
        malware_labels_df["membership"] = malware_labels_df.iloc[:, 2:].dot(
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
