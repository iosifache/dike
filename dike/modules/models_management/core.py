"""Module implementing the core managing the training of models

Usage example:

    core = ModelsManagementCore()
    model_name = core.train("model_configuration.yaml")
    prediction = core.predict("path/to/malware.exe", True, 3)
    core.dump()
"""
import json
import os
import shutil
import typing
from datetime import datetime, timezone
from enum import Enum

import joblib
import numpy as np
import pandas
import yaml
from configuration.dike import DikeConfig
from Crypto.Hash import SHA256
from modules.dataset_building.types import AnalyzedFileTypes
from modules.features_extraction.core import ExtractionCore
from modules.features_extraction.types import ExtractorsType
from modules.models_management.evaluation import ModelsEvaluator
from modules.models_management.types import (ModelObjective,
                                             ReductionAlgorithm,
                                             RegressionAlgorithms)
from modules.preprocessing.core import PreprocessingCore
from modules.preprocessing.types import PreprocessorsTypes
from modules.utils.configuration import ConfigurationSpace, ConfigurationWorker
from modules.utils.errors import (FileToExtractFromNotFoundError,
                                  ModelConfigurationFileNotFoundError,
                                  ModelToLoadNotFoundError)
from modules.utils.logger import LoggedMessageType, Logger
from sklearn.base import BaseEstimator
from sklearn.decomposition import NMF, PCA, FastICA
from sklearn.ensemble import RandomForestRegressor
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import cross_validate, train_test_split
from sklearn.multioutput import MultiOutputRegressor
from sklearn.preprocessing import normalize
from sklearn.svm import LinearSVC
from sklearn.tree import DecisionTreeRegressor


class ModelsManagementCore:
    """Class managing the process of model training and exploitation
    (for prediction)"""
    _is_ready: bool
    _is_unchanged: bool
    _configuration_filename: str
    _dataset_filename: str
    _files_extension: AnalyzedFileTypes
    _extractors_types: typing.List[ExtractorsType]
    _preprocessors_types: typing.List[typing.List[PreprocessorsTypes]]
    _model_objective: ModelObjective
    _reduction_algorithm: ReductionAlgorithm
    _min_variance: float
    _ml_algorithm: Enum
    _dataset: pandas.DataFrame
    _extraction_core: ExtractionCore
    _preprocessing_core: PreprocessingCore
    _reduction_model: BaseEstimator
    _ml_model: BaseEstimator
    _split_ratio: float
    _reduced_features: np.array
    _model_unique_name: str
    _evaluation_results: dict

    def __init__(self) -> None:
        # Default values of members
        self._is_ready = False
        self._is_unchanged = False
        self._configuration_filename = None
        self._dataset_filename = None
        self._files_extension = None
        self._extractors_types = []
        self._preprocessors_types = []
        self._model_objective = None
        self._reduction_algorithm = None
        self._min_variance = 0
        self._ml_algorithm = None
        self._dataset = None
        self._extraction_core = None
        self._preprocessing_core = None
        self._reduction_model = None
        self._ml_model = None
        self._split_ratio = None
        self._reduced_features = None
        self._model_unique_name = None
        self._evaluation_results = None

    def _check_and_load_configuration(self, filename: str):
        # Try to read the configuration file
        try:
            with open(filename, "r") as config_file:
                configuration = yaml.load(config_file, Loader=yaml.SafeLoader)
        except:
            raise ModelConfigurationFileNotFoundError()

        # Check if the main keys are present
        valid_keys = [
            elem.value for elem in DikeConfig.MandatoryConfigurationKeys
            if not elem.name.endswith("_")
        ]
        valid_keys.remove(
            DikeConfig.MandatoryConfigurationKeys.MACHINE_LEARNING.value)
        for key in valid_keys:
            if (key not in configuration.keys()):
                Logger.log(
                    "The model configuration file does not contain all mandatory keys",
                    LoggedMessageType.FAIL)
                return False

        # Check if the dataset file exists
        dataset_config = configuration[
            DikeConfig.MandatoryConfigurationKeys.DATASET.value]
        self._dataset_filename = dataset_config[
            DikeConfig.MandatoryConfigurationKeys.DATASET_FILENAME_.value]
        self._dataset_filename = os.path.join(
            DikeConfig.CUSTOM_DATASETS_FOLDER, self._dataset_filename)
        if (not os.path.isfile(self._dataset_filename)):
            Logger.log("The dataset file does not exists",
                       LoggedMessageType.FAIL)

        # Check if model objective is valid
        model_details_config = configuration[
            DikeConfig.MandatoryConfigurationKeys.MODEL_DETAILS.value]
        try:
            self._model_objective = ModelObjective[
                model_details_config[DikeConfig.MandatoryConfigurationKeys.
                                     MODEL_DETAILS_OBJECTIVE_.value]]
        except:
            Logger.log(
                "Invalid model objective specified in the model configuration file",
                LoggedMessageType.FAIL)
            return False

        # Check if the model needs to be retrained
        if (DikeConfig.MandatoryConfigurationKeys.MODEL_DETAILS_RETRAINING_
                in model_details_config
                and model_details_config[DikeConfig.MandatoryConfigurationKeys.
                                         MODEL_DETAILS_RETRAINING_]):
            # pylint: disable=import-outside-toplevel
            from modules.models_management.retrain import Retrainer

            Retrainer().retrain_model(self._model_unique_name)

        # Check if the dimensionality reduction algorithm and parameters are
        # valid
        reduction_config = configuration[DikeConfig.MandatoryConfigurationKeys.
                                         DIMENSIONALITY_REDUCTION.value]
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
            ml_configuration = configuration[
                DikeConfig.MandatoryConfigurationKeys.MACHINE_LEARNING.value]
            ml_algorithm = ml_configuration[
                DikeConfig.MandatoryConfigurationKeys.
                MACHINE_LEARNING_ALGORITHM_.value]
            self._ml_algorithm = RegressionAlgorithms[ml_algorithm]
            self._split_ratio = ml_configuration[
                DikeConfig.MandatoryConfigurationKeys.
                MACHINE_LEARNING_SPLIT_RADIO_.value]
        except:
            Logger.log(
                "Invalid machine learning algorithm specified in the model configuration file",
                LoggedMessageType.FAIL)
            return False

        # Check the selected extractors and preprocessors
        pairs = configuration[DikeConfig.MandatoryConfigurationKeys.
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

    def _load_models_components(self,
                                configuration_filename: str,
                                attach_preprocessors: bool = True) -> None:
        # Verify the configuration file
        if not self._check_and_load_configuration(configuration_filename):
            return False

        # Create the preprocessors core
        self._preprocessing_core = PreprocessingCore()

        # Attach the preprocessors
        if attach_preprocessors:
            for extractor, corresponding_preprocessors in zip(
                    self._extractors_types, self._preprocessors_types):
                for current_preprocessor_type in corresponding_preprocessors:
                    self._preprocessing_core.attach(current_preprocessor_type,
                                                    extractor)

        # Create the extractor master and attach the needed extractor to it
        self._extraction_core = ExtractionCore()
        for extractor_type in self._extractors_types:
            self._extraction_core.attach(extractor_type)

        # Load the dataset
        self._dataset = pandas.read_csv(self._dataset_filename)

        # Set the core as loaded
        self._is_ready = True

    def _base_train(self) -> None:

        # Extract features from each file in the dataset
        raw_features = []
        extraction_errors_indexes = []
        for entry_id, entry in self._dataset.iterrows():
            if (self._files_extension is None):
                self._files_extension = AnalyzedFileTypes.map_id_to_type(
                    entry["type"]).value.EXTENSION

            # Get the malware full path
            if (entry["malice"] == 0):
                parent_folder = DikeConfig.BENIGN_DATASET_FOLDER
            else:
                parent_folder = DikeConfig.MALWARE_DATASET_FOLDER
            full_filename = os.path.join(
                parent_folder, entry["hash"] + "." + self._files_extension)

            # Scan the file
            try:
                result = self._extraction_core.squeeze(full_filename)
                raw_features.append(result)
            except:
                extraction_errors_indexes.append(entry_id)

        # Apply the preprocessors
        preprocessed_features = self._preprocessing_core.preprocess(
            raw_features)

        # Apply the dimensionality reduction algorithm
        if (self._reduction_algorithm == ReductionAlgorithm.PCA):
            self._reduction_model = PCA(n_components=self._min_variance)
        elif (self._reduction_algorithm == ReductionAlgorithm.FAST_ICA):
            self._reduction_model = FastICA(n_components=self._min_variance)
        elif (self._reduction_algorithm == ReductionAlgorithm.NMF):
            self._reduction_model = NMF(n_components=self._min_variance)
        self._reduced_features = self._reduction_model.fit_transform(
            preprocessed_features)

        # Get the labels and remove the entries where extraction errors occured
        if (self._model_objective == ModelObjective.MALICE):
            y = self._dataset["malice"]
            if extraction_errors_indexes:
                y = [
                    elem for index, elem in enumerate(y)
                    if index not in extraction_errors_indexes
                ]
        elif (self._model_objective == ModelObjective.CLASSIFICATION):
            y = self._dataset.iloc[:, range(3, len(self._dataset.columns))]
            if extraction_errors_indexes:
                y = y.drop(extraction_errors_indexes)
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

        # Split the dataset
        X_train, X_test, y_train, y_test = train_test_split(
            self._reduced_features, y, train_size=self._split_ratio)

        # Use cross validation to select the best model
        cv_results = cross_validate(prediction_model,
                                    X_train,
                                    y_train,
                                    return_estimator=True,
                                    scoring="neg_root_mean_squared_error",
                                    n_jobs=-1)
        self._ml_model = cv_results["estimator"][np.argmax(
            cv_results["test_score"])]

        # Predict on the test samples and compute the accuracy measures
        y_pred = self._ml_model.predict(X_test)
        if (self._model_objective == ModelObjective.MALICE):
            self._evaluation_results = ModelsEvaluator.evaluate_regression(
                y_test, y_pred)
        elif (self._model_objective == ModelObjective.CLASSIFICATION):
            labels = list(self._dataset.columns)[3:]
            self._evaluation_results = \
                ModelsEvaluator.evaluate_soft_multilabel_classification(
                    y_test, y_pred, labels)

        self._is_unchanged = False

        Logger.log(
            "Successfully trained model {}".format(self._model_unique_name),
            LoggedMessageType.SUCCESS)

    def train(self, configuration_filename) -> None:
        """Trains a new model following the configuration from a file.

        Args:
            configuration_filename (str): Name of the configuration file
        """
        # Generate an unique name for the model to be used to dump it
        self._model_unique_name = self._generate_unique_model_name(
            configuration_filename)

        # Save the configuration filename
        self._configuration_filename = configuration_filename

        # Initialize components
        self._load_models_components(configuration_filename)

        # Train
        self._base_train()

    def retrain(self) -> None:
        """Retrains the already loaded model."""
        self._base_train()

    def predict(self,
                filename: str,
                similarity_analysis: bool = False,
                similar_count: int = 0) -> dict:
        """Predicts the malice or the memberships to malware categories.

        The similarity consists in computing the Pearson correlation between the
        extracted features of the given samples and the one of each sample in
        the dataset and selecting the first samples with the largest similarity
        score.

        Args:
            filename (str): Name of the file over which a prediction will be
                made
            similarity_analysis (bool, optional): Boolean indicating if a
                similarity analysis needs to be done. Defaults to False.
            similar_count (int, optional): Number of similar samples to return.
                Defaults to 0, if the similarity analysis is disabled.

        Returns:
            dict: Prediction results
        """
        # Check if the core is ready to predict
        if (not self._is_ready):
            return None

        # Extract features from file
        try:
            raw_features = self._extraction_core.squeeze(filename)
        except FileToExtractFromNotFoundError:
            return {"status": "error"}

        # Apply the preprocessors and the dimensionality reduction algorithm
        preprocessed_features = self._preprocessing_core.preprocess(
            [raw_features])
        reduced_features = self._reduction_model.transform(
            preprocessed_features)

        # Predict the results with the machine learning algorithm
        result = self._ml_model.predict(reduced_features)

        # Detect the most similar samples in the dataframe
        if similarity_analysis:
            reduced_features_df = pandas.DataFrame(self._reduced_features)
            reduced_features_sr = pandas.Series(reduced_features[0])
            correlations = reduced_features_df.corrwith(reduced_features_sr,
                                                        axis=1)
            correlations.sort_values(inplace=True, ascending=False)
            similarities = correlations[:similar_count]
            indexes = correlations.index[:similar_count]
            similar_samples = self._dataset.iloc[indexes]["hash"].values

        # Build the result
        returned_result = {"status": "ok"}
        if (self._model_objective == ModelObjective.MALICE):
            returned_result["malice"] = result[0]
        elif (self._model_objective == ModelObjective.CLASSIFICATION):
            labels = list(self._dataset.columns)[3:]
            normalized_memberships = normalize([result[0]], "l1")[0]
            returned_result["membership"] = dict(
                zip(labels, normalized_memberships))
        if similarity_analysis:
            returned_result["similar"] = [{
                "hash": details[0],
                "similarity": details[1]
            } for details in zip(similar_samples, similarities)]

        return returned_result

    def dump(self) -> str:
        """Dumps the trained components (models).

        Returns:
            str: Unique name of the model
        """
        # Check if the model is a loaded one
        if self._is_unchanged:
            return self._model_unique_name

        # Create the folder structure
        model_dump_folder = os.path.join(DikeConfig.TRAINED_MODELS_FOLDER,
                                         self._model_unique_name)
        if os.path.isdir(model_dump_folder):
            is_retraining = True

            original_model_dump_folder = model_dump_folder
            model_dump_folder += DikeConfig.RETRAIN_FOLDER_PREFIX

            original_model_name = self._model_unique_name
            self._model_unique_name += DikeConfig.RETRAIN_FOLDER_PREFIX
        else:
            is_retraining = False
        os.mkdir(model_dump_folder)
        preprocessors_models_dump_folder = \
            DikeConfig.TRAINED_MODEL_PREPROCESSORS_FOLDER.format(\
                self._model_unique_name)
        os.mkdir(preprocessors_models_dump_folder)

        # Copy the configuration file
        configuration_filename = DikeConfig.TRAINED_MODEL_TRAINING_CONFIGURATION.format(
            self._model_unique_name)
        shutil.copyfile(self._configuration_filename, configuration_filename)

        # Dump the dimensionality reduction model
        reduction_model_path = DikeConfig.TRAINED_MODEL_REDUCTION_MODEL.format(
            self._model_unique_name)
        joblib.dump(self._reduction_model, reduction_model_path)

        # Dump the machine learning model
        ml_model_path = DikeConfig.TRAINED_MODEL_MACHINE_LEARNING_MODEL.format(
            self._model_unique_name)
        joblib.dump(self._ml_model, ml_model_path)

        # Dump the preprocessors
        self._preprocessing_core.dump(self._model_unique_name)

        # Dump the preprocessed and reduced features
        reduced_features_path = DikeConfig.TRAINED_MODEL_FEATURES_FILE.format(
            self._model_unique_name)
        reduced_features_df = pandas.DataFrame(self._reduced_features)
        reduced_features_df.to_csv(reduced_features_path,
                                   header=False,
                                   index=False)

        # Dump the results of the evaluation
        evaluation_path = DikeConfig.TRAINED_MODEL_EVALUATION.format(
            self._model_unique_name)
        with open(evaluation_path, "w") as evaluation_output_file:
            json.dump(self._evaluation_results,
                      evaluation_output_file,
                      indent=DikeConfig.JSON_FILES_INDENT_SPACES)

        # Get the configuration
        ml_config = ConfigurationWorker().get_configuration_space(
            ConfigurationSpace.MACHINE_LEARNING)

        # Dump the prediction configuration
        if (self._model_objective == ModelObjective.MALICE):
            prediction_configuration = {
                "min_malware_malice":
                ml_config["default_min_thresholds"]["malice"]
            }
        elif (self._model_objective == ModelObjective.CLASSIFICATION):
            prediction_configuration = {
                "min_category_membership":
                ml_config["default_min_thresholds"]["class_membership"]
            }
        prediction_configuration_path = DikeConfig.TRAINED_MODEL_PREDICTION_CONFIGURATION.format(
            self._model_unique_name)
        with open(prediction_configuration_path,
                  "w") as prediction_configuration_output_file:
            json.dump(prediction_configuration,
                      prediction_configuration_output_file,
                      indent=DikeConfig.JSON_FILES_INDENT_SPACES)

        # Remove the old folder and rename the current one
        if is_retraining:
            self._model_unique_name = original_model_name
            shutil.rmtree(original_model_dump_folder)
            shutil.move(model_dump_folder, original_model_dump_folder)

        # Log success
        Logger.log(
            "Successfully dumped model {}".format(self._model_unique_name),
            LoggedMessageType.SUCCESS)

        return self._model_unique_name

    def load(self, model_name: str) -> None:
        """Loads the trained components (models).

        Args:
            model_name (str): Name of the model to be loaded
        """
        # Check the existence of the given model
        model_full_path = DikeConfig.TRAINED_MODELS_MODEL_FOLDER.format(
            model_name)
        print(model_full_path)
        if (not os.path.isdir(model_full_path)):
            raise ModelToLoadNotFoundError()

        self._model_unique_name = model_name

        # Get and load the configuration
        configuration_filename = DikeConfig.TRAINED_MODEL_TRAINING_CONFIGURATION.format(
            model_name)
        self._configuration_filename = configuration_filename

        # Initialize components
        self._load_models_components(self._configuration_filename, False)

        # Load the dimensionality reduction model
        reduction_model_path = DikeConfig.TRAINED_MODEL_REDUCTION_MODEL.format(
            model_name)
        self._reduction_model = joblib.load(reduction_model_path)

        # Load the machine learning model
        ml_model_path = DikeConfig.TRAINED_MODEL_MACHINE_LEARNING_MODEL.format(
            model_name)
        self._ml_model = joblib.load(ml_model_path)

        # Load the preprocessors
        preprocessors_count = sum(map(len, self._preprocessors_types))
        self._preprocessing_core.load(model_name, preprocessors_count)

        # Load the reduced features
        reduced_features_path = DikeConfig.TRAINED_MODEL_FEATURES_FILE.format(
            model_name)
        reduced_features_df = pandas.read_csv(reduced_features_path,
                                              header=None,
                                              index_col=False)
        self._reduced_features = reduced_features_df.values

        # Mark the model as loaded
        self._is_unchanged = True

        # Log success
        Logger.log("Successfully loaded model {}".format(model_name),
                   LoggedMessageType.SUCCESS)