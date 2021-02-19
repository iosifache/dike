import os
import typing
from datetime import datetime, timezone
from enum import Enum

import numpy as np
import pandas
import yaml
from configuration.dike import DikeConfig
from Crypto.Hash import SHA256
from joblib import dump
from sklearn.decomposition import NMF, PCA, FastICA
from sklearn.ensemble import RandomForestRegressor
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import cross_validate
from sklearn.multioutput import MultiOutputRegressor
from sklearn.svm import LinearSVC
from sklearn.tree import DecisionTreeRegressor
from subordinate.modules.features_extraction.core import ExtractionCore
from subordinate.modules.features_extraction.types import ExtractorsType
from subordinate.modules.models_training.types import (ModelObjective,
                                                       ReductionAlgorithm,
                                                       RegressionAlgorithms)
from subordinate.modules.preprocessing.core import PreprocessingCore
from subordinate.modules.preprocessing.types import PreprocessorsTypes
from utils.logger import LoggedMessageType, Logger


class TrainingMaster:
    """Class managing the process of model training"""
    _configuration: dict = None
    _dataset_filename: str = None
    _extractors_types: typing.List[ExtractorsType] = []
    _preprocessors_types: typing.List[typing.List[PreprocessorsTypes]] = []
    _model_objective: ModelObjective = None
    _reduction_algorithm: ReductionAlgorithm = None
    _min_variance: float = 0
    _ml_algorithm: Enum = None

    def _check_and_load_configuration(self, filename: str):
        # Try to read the configuration file
        try:
            with open(filename, "r") as config_file:
                self._configuration = yaml.load(config_file,
                                                Loader=yaml.SafeLoader)
        except:
            Logger.log("The model configuration file does not exists",
                       LoggedMessageType.FAIL)
            return False

        # Check if the main keys are present
        valid_keys = [
            elem.value for elem in DikeConfig.MandatoryConfigurationKeys
            if not elem.name.endswith("_")
        ]
        valid_keys.remove(
            DikeConfig.MandatoryConfigurationKeys.MACHINE_LEARNING.value)
        for key in valid_keys:
            if (key not in self._configuration.keys()):
                Logger.log(
                    "The model configuration file does not contain all mandatory keys",
                    LoggedMessageType.FAIL)
                return False

        # Check if the dataset file exists
        self._dataset_filename = self._configuration[
            DikeConfig.MandatoryConfigurationKeys.DATASET.value]
        self._dataset_filename = os.path.join(
            DikeConfig.CUSTOM_DATASETS_FOLDER, self._dataset_filename)
        if (not os.path.isfile(self._dataset_filename)):
            Logger.log("The dataset file does not exists",
                       LoggedMessageType.FAIL)

        # Check if model objective is valid
        try:
            self._model_objective = ModelObjective[self._configuration[
                DikeConfig.MandatoryConfigurationKeys.MODEL_OBJECTIVE.value]]
        except:
            Logger.log(
                "Invalid model objective specified in the model configuration file",
                LoggedMessageType.FAIL)
            return False

        # Check if the dimensionality reduction algorithm and parameters are
        # valid
        reduction_config = self._configuration[
            DikeConfig.MandatoryConfigurationKeys.DIMENSIONALITY_REDUCTION.
            value]
        try:
            self._reduction_algorithm = ReductionAlgorithm[
                reduction_config[DikeConfig.MandatoryConfigurationKeys.
                                 DIMENSIONALITY_REDUCTION_ALGORITHM_.value]]
            self._min_variance = reduction_config[
                DikeConfig.MandatoryConfigurationKeys.
                DIMENSIONALITY_REDUCTION_MIN_VARIANCE_.value]
        except:
            Logger.log(
                "Invalid dimensionality reduction algorithm or parameters specified in the model configuration file",
                LoggedMessageType.FAIL)
            return False

        # Check if the machine learning algorithm is valid
        try:
            ml_configuration = self._configuration[
                DikeConfig.MandatoryConfigurationKeys.MACHINE_LEARNING.value]
            ml_algorithm = ml_configuration[
                DikeConfig.MandatoryConfigurationKeys.
                MACHINE_LEARNING_ALGORITHM_.value]
            self._ml_algorithm = RegressionAlgorithms[ml_algorithm]
        except:
            Logger.log(
                "Invalid machine learning algorithm specified in the model configuration file",
                LoggedMessageType.FAIL)
            return False

        # Check the selected extractors and preprocessors
        pairs = self._configuration[DikeConfig.MandatoryConfigurationKeys.
                                    EXTRACTORS_PREPROCESSORS.value]
        for pair in pairs:

            # Get the selected extractor and preprocessor
            extractor = (list(pair.keys()))[0]
            corresponding_preprocessors = pair[extractor]

            # Get the selected extractor as a class
            valid_extractor_names = [
                extractor.name for extractor in ExtractorsType
            ]
            if (extractor not in valid_extractor_names):
                Logger.log(
                    "Invalid extractor specified in the model configuration file",
                    LoggedMessageType.FAIL)
                return False

            # Check the number of given preprocessors
            extractor_class = ExtractionCore.load_extractor_by_name(
                ExtractorsType[extractor].value)
            valid_preprocessors = extractor_class.get_supported_preprocessors()
            if (len(valid_preprocessors) != len(corresponding_preprocessors)):
                Logger.log(
                    "Invalid number of preprocessors specified in the model configuration file for the extractor {}"
                    .format(extractor), LoggedMessageType.FAIL)
                return False

            # Get the name of the valid preprocessors
            valid_preprocessors_types = []
            for preprocessor_group in valid_preprocessors:
                names = []
                for preprocessor in preprocessor_group:
                    names.append(preprocessor.name)
                valid_preprocessors_types.append(names.copy())
                names.clear()

            # Check the given preprocessors
            for preprocessor_id, _ in enumerate(corresponding_preprocessors):
                if (corresponding_preprocessors[preprocessor_id]
                        not in valid_preprocessors_types[preprocessor_id]):
                    Logger.log(
                        "Invalid preprocessors specified in the model configuration file for the extractor {} at index {}"
                        .format(extractor,
                                preprocessor_id), LoggedMessageType.FAIL)
                    return False

            # Save the extractors
            self._extractors_types.append(ExtractorsType[extractor])

            # Save the preprocessors
            corresponding_preprocessors_types = []
            for preprocessor in corresponding_preprocessors:
                corresponding_preprocessors_types.append(
                    PreprocessorsTypes[preprocessor])
            self._preprocessors_types.append(corresponding_preprocessors_types)

        return True

    @staticmethod
    def _generate_unique_model_name(filename: str) -> str:
        current_time = datetime.now(timezone.utc)
        to_hash = (filename + str(current_time)).encode("utf-8")
        model_name = SHA256.new(data=to_hash).hexdigest()

        return model_name

    def train_model(self, configuration_filename: str) -> bool:
        """Trains a new model following the configuration from a file.

        Args:
            configuration_filename (str): Name of the configuration file

        Returns:
            bool: [description]
        """
        # Verify the configuration file
        if not self._check_and_load_configuration(configuration_filename):
            return False

        # Load the dataset
        dataset = pandas.read_csv(self._dataset_filename)

        # Create the extractor master and attach the needed extractor to it
        extractor_master = ExtractionCore()
        for extractor_type in self._extractors_types:
            extractor_master.attach(extractor_type)

        # Create the preprocessors
        preprocessing_core = PreprocessingCore()
        for extractor, corresponding_preprocessors in zip(
                self._extractors_types, self._preprocessors_types):
            for current_preprocessor_type in corresponding_preprocessors:
                preprocessing_core.attach(current_preprocessor_type, extractor)

        # Extract features from each file in the dataset
        raw_features = []
        extraction_errors_indexes = []
        for entry_id, entry in dataset.iterrows():
            # Get the malware full path
            if (entry["malice"] == 0):
                parent_folder = DikeConfig.BENIGN_DATASET_FOLDER
            else:
                parent_folder = DikeConfig.MALWARE_DATASET_FOLDER
            full_filename = os.path.join(parent_folder, entry["hash"] + ".exe")

            # Scan the file
            try:
                result = extractor_master.squeeze(full_filename)
                raw_features.append(result)
            except:
                extraction_errors_indexes.append(entry_id)

        # Apply the preprocessors
        preprocessed_features = preprocessing_core.preprocess(raw_features)

        # Apply the dimensionality reduction algorithm
        if (self._reduction_algorithm == ReductionAlgorithm.PCA):
            reduction_model = PCA(n_components=self._min_variance)
        elif (self._reduction_algorithm == ReductionAlgorithm.FAST_ICA):
            reduction_model = FastICA(n_components=self._min_variance)
        elif (self._reduction_algorithm == ReductionAlgorithm.NMF):
            reduction_model = NMF(n_components=self._min_variance)
        reduced_features = reduction_model.fit_transform(preprocessed_features)

        # Get the labels and remove the entries where extraction errors occured
        if (self._model_objective == ModelObjective.MALICE):
            y = dataset["malice"]
            if extraction_errors_indexes:
                y = [
                    elem for index, elem in enumerate(y)
                    if index not in extraction_errors_indexes
                ]
        elif (self._model_objective == ModelObjective.CLASSIFICATION):
            y = dataset.iloc[:, range(2, len(dataset.columns))]
            if extraction_errors_indexes:
                y = y.drop(extraction_errors_indexes)

            # TODO(@iosifache): Remove this normalization after (re)verifying
            # the one from data_folder_scanner.py:209
            y = y.div(y.sum(axis=1), axis=0)
            y = y.fillna(0)

            y = y.values

        # Create the model
        if (self._ml_algorithm == RegressionAlgorithms.LOGISTIC):
            regression_model = LogisticRegression()
        elif (self._ml_algorithm == RegressionAlgorithms.DECISION_TREE):
            regression_model = DecisionTreeRegressor()
        elif (self._ml_algorithm ==
              RegressionAlgorithms.LINEAR_SUPPORT_VECTOR_MACHINE):
            regression_model = LinearSVC()
        elif (self._ml_algorithm == RegressionAlgorithms.RANDOM_FOREST):
            regression_model = RandomForestRegressor()

        if (self._model_objective == ModelObjective.MALICE):
            prediction_model = regression_model
        elif (self._model_objective == ModelObjective.CLASSIFICATION):
            prediction_model = MultiOutputRegressor(regression_model)

        # Use cross validation to select the best model
        cv_results = cross_validate(prediction_model,
                                    reduced_features,
                                    y,
                                    return_estimator=True,
                                    scoring="neg_root_mean_squared_error",
                                    n_jobs=-1)
        best_model = cv_results["estimator"][np.argmax(
            cv_results["test_score"])]

        # Generate an unique name for the model to be used to dump it
        model_name = self._generate_unique_model_name(configuration_filename)

        # Get the names of the files and the folders
        model_dump_folder = os.path.join(DikeConfig.TRAINED_MODELS_FOLDER,
                                         model_name)
        preprocessors_models_dump_folder = \
            DikeConfig.TRAINED_MODEL_PREPROCESSORS_FOLDER.format(model_name)
        reduction_model_path = DikeConfig.TRAINED_MODEL_REDUCTION_MODEL.format(
            model_name)
        ml_model_path = DikeConfig.TRAINED_MODEL_MACHINE_LEARNING_MODEL.format(
            model_name)

        # Create the folder structure
        os.mkdir(model_dump_folder)
        os.mkdir(preprocessors_models_dump_folder)

        # Dump the models
        dump(reduction_model, reduction_model_path)
        dump(best_model, ml_model_path)

        # Dump the preprocessors
        preprocessing_core.dump(model_name)

        # Dump the preprocessed features
        reduced_features_df = pandas.DataFrame(reduced_features)
        filename = DikeConfig.TRAINED_MODEL_FEATURES_FILE.format(model_name)
        reduced_features_df.to_csv(filename, header=False, index=False)
