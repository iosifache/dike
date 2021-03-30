"""Module implementing the preprocessing core, namely a pipeline for applying
preprocessors

Usage example:

    # Read the required configuration
    configuration = ConfigurationWorker()

    # Create the core
    core = PreprocessingCore()

    # Attach some preprocessors to the core
    core.attach(PreprocessorsTypes.IDENTITY)

    # Preprocess the data stored in the constant DATA
    preprocessed_data = core.preprocess([[1, 2, 0, 4], [0, 1, 3, 6]])
"""
import typing

import joblib
import numpy as np
import pandas
import scipy
from configuration.platform import Files, Parameters
from modules.features.types import ExtractorsType
from modules.preprocessing.preprocessors import (Counter, CountVectorizer,
                                                 GroupCounter, Identity,
                                                 NGrams, Preprocessor,
                                                 SameLengthImputer)
from modules.preprocessing.types import PreprocessorsTypes
from modules.utils.configuration import ConfigurationSpace, ConfigurationWorker
from sklearn.preprocessing import Binarizer, KBinsDiscretizer, MinMaxScaler


class PreprocessingCore:
    """Class for preprocessing data by applying preprocessors"""
    _is_loaded: bool
    _extractors_config: typing.Any
    _preprocessors_config: typing.Any
    _preprocessors: typing.List[Preprocessor]
    _columns_to_be_filled: list
    _last_scalar_model: MinMaxScaler

    def __init__(self) -> None:
        """Initializes the PreprocessingCore instance."""
        # Read the user configuration
        configuration_worker = ConfigurationWorker()
        self._extractors_config = configuration_worker.get_configuration_space(
            ConfigurationSpace.EXTRACTORS)
        self._preprocessors_config = \
            configuration_worker.get_configuration_space(
                ConfigurationSpace.PREPROCESSORS)

        # Default value of members
        self._is_loaded = False
        self._preprocessors = []
        self._columns_to_be_filled = []
        self._last_scalar_model = None

    def attach(self,
               preprocessor_type: PreprocessorsTypes,
               parent_extractor_type: ExtractorsType = None) -> None:
        """Attaches a preprocessor to master.

        Args:
            preprocessor_type (PreprocessorsTypes): Type of the preprocessor
            parent_extractor_type (ExtractorsType): Type of the parent
                extractor. Defaults to None, in case of a preprocessor that
                does not require special arguments.
        """
        # Check what arguments are needed for the current preprocessor
        arguments = {}
        if (preprocessor_type == PreprocessorsTypes.N_GRAMS):
            charset = NGrams.Charset[self._preprocessors_config["ngrams"]
                                     ["valid_charset"]]
            arguments = {
                "n":
                self._preprocessors_config["ngrams"]["n"],
                "to_lowercase":
                self._preprocessors_config["ngrams"]["to_lowercase"],
                "valid_charset":
                charset
            }
        elif (preprocessor_type == PreprocessorsTypes.GROUP_COUNTER):
            if (parent_extractor_type == ExtractorsType.STATIC_OPCODES or
                    parent_extractor_type == ExtractorsType.DYNAMIC_OPCODES):
                arguments = {
                    "categories":
                    self._extractors_config["opcodes"]["categories"],
                    "allow_multiple_categories":
                    self._extractors_config["opcodes"]
                    ["allow_multiple_categories"],
                    "verbose":
                    self._extractors_config["opcodes"]["verbose"],
                    "min_ignored_percent":
                    self._extractors_config["opcodes"]["min_ignored_percent"]
                }
            elif (parent_extractor_type == ExtractorsType.STATIC_APIS
                  or parent_extractor_type == ExtractorsType.DYNAMIC_APIS):
                arguments = {
                    "categories":
                    self._extractors_config["apis"]["categories"],
                    "allow_multiple_categories":
                    self._extractors_config["apis"]
                    ["allow_multiple_categories"],
                    "verbose":
                    self._extractors_config["apis"]["verbose"],
                    "min_ignored_percent":
                    self._extractors_config["apis"]["min_ignored_percent"]
                }

        # Create the preprocessor
        preprocessor = None
        if (preprocessor_type == PreprocessorsTypes.IDENTITY):
            preprocessor = Identity()
        elif (preprocessor_type == PreprocessorsTypes.BINARIZER):
            preprocessor = Binarizer()
        elif (preprocessor_type == PreprocessorsTypes.K_BINS_DISCRETIZER):
            preprocessor = KBinsDiscretizer()

            # Save this column in case of imputation needs
            self._columns_to_be_filled.append(len(self._preprocessors))

        elif (preprocessor_type == PreprocessorsTypes.COUNTER):
            preprocessor = Counter()
        elif (preprocessor_type == PreprocessorsTypes.COUNT_VECTORIZER):
            preprocessor = CountVectorizer()
        elif (preprocessor_type == PreprocessorsTypes.N_GRAMS):
            preprocessor = NGrams(**arguments)
        elif (preprocessor_type == PreprocessorsTypes.GROUP_COUNTER):
            preprocessor = GroupCounter(**arguments)
        elif (preprocessor_type == PreprocessorsTypes.SAME_LENGTH_IMPUTER):
            preprocessor = SameLengthImputer()

        self._preprocessors.append(preprocessor)

    def _impute_values(self, X: np.array, desired_length: int = 0) -> np.array:
        if (desired_length == 0):
            imputed_features_df = pandas.DataFrame(X)
            for column_id in self._columns_to_be_filled:
                # Apply the imputer to each column
                column = imputed_features_df.iloc[:, column_id].values
                imputed_values = SameLengthImputer().fit_transform(column)

                # Insert the imputed value into the cell
                for index, value in enumerate(imputed_values):
                    imputed_features_df.at[index, column_id] = list(value)

            return imputed_features_df.values

        # If the desired length is set, then ensure that each vector has that
        # length
        return SameLengthImputer(desired_length).fit_transform(X)

    def preprocess(self, X: np.array) -> np.array:
        """Preprocesses the given features.

        Args:
            X (np.array): Raw features

        Returns:
            np.array: Preprocessed features
        """
        # Impute values for some preprocessors
        X = self._impute_values(X)

        # Apply the preprocessors manually
        processed_features = []
        for index, preprocessor in enumerate(self._preprocessors):
            features = [x[index] for x in X]
            if self._is_loaded:
                try:
                    processed_features.append(preprocessor.transform(features))
                except ValueError:
                    # If there is a differences between features count, pad the
                    # vectors
                    features = self._impute_values(features,
                                                   preprocessor.n_features_in_)
                    processed_features.append(preprocessor.transform(features))
            else:
                processed_features.append(preprocessor.fit_transform(features))
        processed_features = list(map(list, zip(*processed_features)))

        # Drop the array and sparse matrix representations
        converted_features = []
        for preprocessor_id, _ in enumerate(processed_features):
            converted_features.append(list())
            for feature_id in range(len(processed_features[preprocessor_id])):
                feature = processed_features[preprocessor_id][feature_id]
                if isinstance(feature, scipy.sparse.csr.csr_matrix):
                    converted_features[preprocessor_id].extend(
                        feature.toarray()[0])
                elif isinstance(feature, list):
                    converted_features[preprocessor_id].extend(feature)
                else:
                    converted_features[preprocessor_id].append(feature)

        # Apply a scalar
        if self._is_loaded:
            converted_features = self._last_scalar_model.transform(
                converted_features)
        else:
            # If the core is not loaded from dumped models, then create a new
            # scalar, fit it and transform the data
            self._last_scalar_model = MinMaxScaler()
            converted_features = self._last_scalar_model.fit_transform(
                converted_features)

        return converted_features

    def dump(self, model_name: str) -> None:
        """Dumps the preprocessors and the scalar to files.

        Args:
            model_name (str): Name of the trained model
        """
        # Dump each preprocessor
        for index, preprocessor in enumerate(self._preprocessors):
            preprocessor_model_filename = Files.MODEL_PREPROCESSOR_MODEL_FMT.format(
                model_name, index)
            joblib.dump(preprocessor, preprocessor_model_filename)

        # Dump the scalar
        filename = Files.MODEL_PREPROCESSOR_MODEL_FMT.format(
            model_name, Parameters.ModelsManagement.Training.SCALAR_MODEL_NAME)
        joblib.dump(self._last_scalar_model, filename)

    def load(self, model_name: str, preprocessors_count: int) -> None:
        """Loads the preprocessor and the scalar from file.

        Args:
            model_name (str): Name of the trained model
            preprocessors_count (int): Number of saved preprocessors
        """
        # Load each preprocessor
        for preprocessor_id in range(preprocessors_count):
            preprocessor_model_filename = Files.MODEL_PREPROCESSOR_MODEL_FMT.format(
                model_name, preprocessor_id)
            self._preprocessors.append(
                joblib.load(preprocessor_model_filename))

        # Dump the scalar
        scalar_model_filename = Files.MODEL_PREPROCESSOR_MODEL_FMT.format(
            model_name, Parameters.ModelsManagement.Training.SCALAR_MODEL_NAME)
        self._last_scalar_model = joblib.load(scalar_model_filename)

        self._is_loaded = True
