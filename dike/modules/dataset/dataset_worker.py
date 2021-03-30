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
import yaml
from configuration.platform import Files, Folders, Parameters
from modules.dataset.types import AnalyzedFileTypes
from modules.utils.configuration import ConfigurationSpace, ConfigurationWorker
from modules.utils.errors import (DatasetConfigurationFileNotFoundError,
                                  InvalidFileExtensionError)
from modules.utils.logger import LoggedMessageType, Logger

# Get the specific configuration
CONFIGURATION_KEYS = Parameters.Dataset.ConfigurationKeys


class DatasetWorker:
    """Class for working with datasets"""
    @staticmethod
    def _get_metadata(dataset_filename: str) -> dict:
        full_filename = os.path.join(Folders.CUSTOM_DATASETS, dataset_filename)

        with open(full_filename, "r") as file:
            lines = file.readlines()
            if (len(lines) == 0):
                return None
            metadata_line = lines[0]

            if (not metadata_line.startswith(
                    Parameters.Dataset.METADATA_LINE_START)):
                return None

            metadata_line = metadata_line[len(Parameters.Dataset.
                                              METADATA_LINE_START):]
            metadata = json.loads(metadata_line)

            return metadata

    @staticmethod
    def _dump_metadata(dataset_filename: str, metadata: dict) -> None:
        stringified_metadata = json.dumps(metadata)

        full_filename = os.path.join(Folders.CUSTOM_DATASETS, dataset_filename)
        with open(full_filename, "r+") as output_file:
            content = output_file.read()
            output_file.seek(0, 0)
            output_file.write(Parameters.Dataset.METADATA_LINE_START +
                              stringified_metadata + "\n" + content)

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
        malware_labels_df = pandas.read_csv(Files.MALWARE_LABELS)
        benign_labels_df = pandas.read_csv(Files.BENIGN_LABELS)

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
        output_full_filename = os.path.join(Folders.CUSTOM_DATASETS,
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
        DatasetWorker._dump_metadata(output_filename, metadata)

        return True

    @staticmethod
    def create_dataset_from_file(config_file: str) -> bool:
        # Get the malware families
        config = ConfigurationWorker()
        dataset_config = config.get_configuration_space(
            ConfigurationSpace.DATASET_BUILDER)
        malware_families = dataset_config["malware_families"].keys()
        malware_families = [family.lower() for family in malware_families]

        # Try to read the configuration file
        try:
            with open(config_file, "r") as config_file:
                configuration = yaml.load(config_file, Loader=yaml.SafeLoader)
        except:
            raise DatasetConfigurationFileNotFoundError()

        # Check if the main keys are present
        valid_keys = [
            elem.value for elem in CONFIGURATION_KEYS
            if not elem.name.endswith("_")
        ]
        for key in valid_keys:
            if (key not in configuration.keys()):
                Logger().log(
                    "The dataset configuration file does not contain all mandatory keys",
                    LoggedMessageType.FAIL)
                return False

        # Preprocess the configuration
        processed_desired_categories = 9 * [False]
        for family in configuration[CONFIGURATION_KEYS.DESIRED_FAMILIES.value]:
            try:
                index = malware_families.index(family)
                processed_desired_categories[index] = True
            except:
                pass
        configuration[CONFIGURATION_KEYS.DESIRED_FAMILIES.
                      value] = processed_desired_categories

        file_type = AnalyzedFileTypes.map_extension_to_type(
            configuration.pop(CONFIGURATION_KEYS.FILE_EXTENSION.value))
        if (not file_type):
            raise InvalidFileExtensionError()
        configuration["file_type"] = file_type

        return DatasetWorker.create_dataset(**configuration)

    @staticmethod
    def list_datasets() -> typing.List[typing.List]:
        """Lists the metadata of all created datasets.

        Returns:
            typing.List[typing.List]: Datasets metadatas
        """
        all_metadata = pandas.DataFrame()

        filenames = os.listdir(Folders.CUSTOM_DATASETS)
        for filename in filenames:
            # Skip the hidden files
            if not filename.startswith("."):
                metadata = DatasetWorker._get_metadata(filename)
                metadata["filename"] = filename
                all_metadata = all_metadata.append(metadata, ignore_index=True)

        datasets_details = all_metadata.values.tolist()
        datasets_details.insert(0, all_metadata.columns.to_list())

        return datasets_details

    @staticmethod
    def remove_dataset(dataset_filename: str) -> None:
        """Removes a created dataset.

        Args:
            dataset_filename (str): Name of the dataset
        """
        full_filename = os.path.join(Folders.CUSTOM_DATASETS, dataset_filename)
        os.remove(full_filename)

    @staticmethod
    def update_dataset(dataset_filename: str,
                       file_type: AnalyzedFileTypes,
                       file_hash: str,
                       malice: float = None,
                       memberships: typing.List[float] = None) -> bool:
        full_filename = os.path.join(Folders.CUSTOM_DATASETS, dataset_filename)

        # Get the metadata line
        metadata = DatasetWorker._get_metadata(dataset_filename)

        # Read the dataframe
        dataset_df = pandas.read_csv(full_filename,
                                     index_col=False,
                                     skiprows=1)

        # Check if the malice was provided
        if malice is not None:
            malice_exists = True
        else:
            # Create dummy values
            malice = -1

            malice_exists = False

        # Check if memberships for all families were provided
        if memberships:
            number_of_families = len(dataset_df.columns[3:])
            if len(memberships) != number_of_families:
                return False
            memberships_exists = True
        else:
            # Create dummy values
            memberships = len(dataset_df.columns[3:]) * [-1]

            memberships_exists = False

        # Check if an entry is already in the dataset
        row_index = dataset_df.loc[dataset_df["hash"] == file_hash].index
        exists = row_index.tolist()

        if exists:
            row_index = exists[0]

            # Populate the malice
            if malice_exists:
                old_malice = dataset_df.iat[
                    row_index, dataset_df.columns.get_loc("malice")]
                dataset_df.iloc[row_index,
                                dataset_df.columns.get_loc("malice")] = malice

            # Populate the membership
            if memberships_exists:
                for col_index in range(3, len(dataset_df.columns)):
                    dataset_df.iloc[row_index,
                                    col_index] = memberships[col_index - 3]

        else:
            # Create a new row
            new_row = [file_type.value.ID, file_hash, malice, *memberships]
            dataset_df = dataset_df.append(
                [pandas.Series(new_row, index=dataset_df.columns)],
                ignore_index=True)

        # Save the dataframe
        dataset_df.to_csv(full_filename, index=False)

        # Update the metadata
        entries_count = metadata["entries_count"]
        benign_ratio = metadata["benign_ratio"]
        malware_count = int((1 - benign_ratio) * entries_count)
        benign_count = entries_count - malware_count
        if exists:
            if malice_exists:
                if (malice == 0 and old_malice > 0):
                    # Malware marked as benign
                    malware_count -= 1
                    benign_count += 1
                elif (malice > 0 and old_malice == 0):
                    # Benign marked as malware
                    malware_count += 1
                    benign_count -= 1
        else:
            if (malice > 0):
                malware_count += 1
            elif (malice == 0):
                benign_count += 1

            entries_count += 1

        metadata["entries_count"] = entries_count
        metadata["benign_ratio"] = benign_count / entries_count
        DatasetWorker._dump_metadata(dataset_filename, metadata)

        return exists
