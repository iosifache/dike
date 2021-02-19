import typing

import numpy as np
import pandas
import scipy
from configuration.dike import DikeConfig
from joblib import dump as joblib_dump
from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import Binarizer, KBinsDiscretizer, MinMaxScaler
from subordinate.modules.features_extraction.types import ExtractorsType
from subordinate.modules.preprocessing.preprocessors import (
    Counter, CountVectorizer, GroupCounter, Identity, NGrams, Preprocessor,
    SameLengthImputer)
from subordinate.modules.preprocessing.types import PreprocessorsTypes
from utils.configuration import ConfigurationSpace, ConfigurationWorker


class PreprocessingCore:
    """Class for preprocessing data by applying preprocessors"""
    _extractors_config: typing.Any = None
    _preprocessors_config: typing.Any = None
    _preprocessors: typing.List[Preprocessor] = []
    _columns_to_be_filled: list = []
    _last_scalar_model: MinMaxScaler = None

    def __init__(self):
        """Initializes the PreprocessingCore instance."""
        # Read the user configuration
        configuration_worker = ConfigurationWorker()
        self._extractors_config = configuration_worker.get_configuration_space(
            ConfigurationSpace.EXTRACTORS)
        self._preprocessors_config = \
            configuration_worker.get_configuration_space(\
                ConfigurationSpace.PREPROCESSORS)

    def attach(self, preprocessor_type: PreprocessorsTypes,
               parent_extractor_type: ExtractorsType) -> None:
        """Attaches a preprocessor to master.

        Args:
            preprocessor_type (PreprocessorsTypes): Type of the preprocessor
            parent_extractor_type (ExtractorsType): Type of the parent extractor
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
        elif (preprocessor_type == PreprocessorsTypes.GROUP_COUNTER.name):
            if (parent_extractor_type == ExtractorsType.DYNAMIC_OPCODES):
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
            elif (parent_extractor_type == ExtractorsType.DYNAMIC_APIS):
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

    def _impute_values(self, X: np.array) -> np.array:
        # Impute missing values
        included_transformers = [(str(i), SameLengthImputer(), i)
                                 for i in self._columns_to_be_filled]

        transformer = ColumnTransformer(included_transformers,
                                        remainder="passthrough")
        X_imputed = transformer.fit_transform(X)

        # Reorder the matrix after the imputation
        imputed_features_df = pandas.DataFrame(X_imputed)
        columns_count = len(imputed_features_df.columns)
        modified_order = []
        modified_order.extend(self._columns_to_be_filled)
        for i in range(columns_count):
            if i not in modified_order:
                modified_order.append(i)
        real_order = columns_count * [0]
        for index, modified_index in enumerate(modified_order):
            real_order[modified_index] = index
        imputed_features_df = imputed_features_df[real_order]

        return imputed_features_df.values

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
            processed_features.append(preprocessor.fit_transform(features))
        processed_features = list(map(list, zip(*processed_features)))

        # Drop the array and sparse matrix representations
        converted_features = []
        for sample_id, _ in enumerate(processed_features):
            converted_features.append(list())
            for feature_id in range(len(processed_features[sample_id])):
                feature = processed_features[sample_id][feature_id]
                if isinstance(feature, scipy.sparse.csr.csr_matrix):
                    converted_features[sample_id].extend(feature.toarray()[0])
                elif isinstance(feature, list):
                    converted_features[sample_id].extend(feature)
                else:
                    converted_features[sample_id].append(feature)

        # Apply a scalar
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
            filename = DikeConfig.TRAINED_MODEL_PREPROCESSOR_MODEL.format(
                model_name, index)
            joblib_dump(preprocessor, filename)

        # Dump the scalar
        filename = DikeConfig.TRAINED_MODEL_PREPROCESSOR_MODEL.format(
            model_name, DikeConfig.TRAINED_MODEL_SCALAR_MODEL)
        joblib_dump(self._last_scalar_model, filename)
