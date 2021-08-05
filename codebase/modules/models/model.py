"""Trained model.

Usage example:

    # Create a model based on a configuration file
    model = Model()
    model_name = model.train("model_configuration.yaml")

    # Use the model to predict for a PE file
    prediction = model.predict("/tmp/malware.exe", None, True, 3)

    # Dump the model
    model.dump()
"""
import json
import os
import pickle  # nosec
import shutil
import typing
from enum import Enum

import joblib
import modules.models.errors as errors
import numpy as np
import pandas
import yaml
from Crypto.Hash import SHA256  # nosec
from modules.configuration.folder_structure import Files, Folders
from modules.configuration.parameters import Packages
from modules.dataset.core import DatasetCore
from modules.dataset.types import AnalyzedFileTypes
from modules.features.core import ExtractionCore
from modules.features.types import ExtractorsTypes
from modules.models.evaluation import ModelsEvaluator
from modules.models.types import ModelObjective, RegressionAlgorithms
from modules.preprocessing.core import PreprocessingCore
from modules.preprocessing.types import PreprocessorsTypes, ReductionAlgorithm
from modules.utils.configuration_manager import ConfigurationManager
from modules.utils.crypto import HashingEngine
from modules.utils.logger import Logger
from modules.utils.types import ConfigurationSpaces, LoggedMessageTypes
from sklearn.base import BaseEstimator
from sklearn.ensemble import RandomForestRegressor
from sklearn.model_selection import cross_validate, train_test_split
from sklearn.multioutput import MultiOutputRegressor
from sklearn.preprocessing import normalize
from sklearn.svm import LinearSVR
from sklearn.tree import DecisionTreeRegressor

TRAINING_CONFIG = Packages.Models.Training
EVALUATION_CONFIG = Packages.Models.Evaluation
RETRAINING_CONFIG = Packages.Models.Retraining
CONFIGURATION_KEYS = Packages.Models.ConfigurationKeys


# pylint: disable=invalid-name
class Model:
    """Class managing the process of model training and prediction."""

    _is_ready: bool
    _is_unchanged: bool
    _configuration: dict
    _configuration_filename: str
    _dataset_filename: str
    _extractors_types: typing.List[ExtractorsTypes]
    _preprocessors_types: typing.List[typing.List[PreprocessorsTypes]]
    _model_objective: ModelObjective
    _reduction_algorithm: ReductionAlgorithm
    _components_count: float
    _ml_algorithm: Enum
    _dataset: pandas.DataFrame
    _extraction_core: ExtractionCore
    _preprocessing_core: PreprocessingCore
    _ml_model: BaseEstimator
    _split_ratio: float
    _preprocessed_features: np.array
    _reduced_features: np.array
    _model_unique_name: str
    _evaluation_results: dict

    def __init__(self) -> None:
        """Initializes the Model instance."""
        self._is_ready = False
        self._is_unchanged = False
        self._configuration = None
        self._configuration_filename = None
        self._dataset_filename = None
        self._extractors_types = []
        self._preprocessors_types = []
        self._model_objective = None
        self._reduction_algorithm = None
        self._components_count = 0
        self._ml_algorithm = None
        self._dataset = None
        self._extraction_core = None
        self._preprocessing_core = None
        self._ml_model = None
        self._split_ratio = None
        self._preprocessed_features = None
        self._reduced_features = None
        self._model_unique_name = None
        self._evaluation_results = None

    def _check_and_load_configuration(self, filename: str, is_load: bool):
        # Try to read the configuration file
        try:
            with open(filename, "r") as config_file:
                configuration = yaml.load(config_file, Loader=yaml.SafeLoader)
        except Exception:
            raise errors.ModelConfigurationFileNotFoundError()
        self._configuration = configuration

        # Check if the main keys are present
        valid_keys = [
            elem.value for elem in CONFIGURATION_KEYS
            if not elem.name.endswith("_")
        ]
        valid_keys.remove(CONFIGURATION_KEYS.MACHINE_LEARNING.value)
        for key in valid_keys:
            if key not in configuration.keys():
                raise errors.ModelConfigurationMandatoryKeysNotPresentError()

        # Check if the dataset file exists
        if is_load:
            self._dataset_filename = Files.MODEL_DATASET_FMT.format(
                self._model_unique_name)
        else:
            dataset_config = configuration[CONFIGURATION_KEYS.DATASET.value]
            self._dataset_filename = dataset_config[
                CONFIGURATION_KEYS.DATASET_FILENAME_.value]
            self._dataset_filename = os.path.join(Folders.CUSTOM_DATASETS,
                                                  self._dataset_filename)
        if not os.path.isfile(self._dataset_filename):
            raise errors.ModelDatasetNotFoundError()

        # Check if the model objective is valid
        model_details_config = configuration[
            CONFIGURATION_KEYS.MODEL_DETAILS.value]
        try:
            self._model_objective = ModelObjective[model_details_config[
                CONFIGURATION_KEYS.MODEL_DETAILS_OBJECTIVE_.value]]
        except KeyError:
            raise errors.InvalidModelObjectiveError()

        # Check if the model needs to be retrained
        if (CONFIGURATION_KEYS.MODEL_DETAILS_RETRAINING_.value
                in model_details_config and model_details_config[
                    CONFIGURATION_KEYS.MODEL_DETAILS_RETRAINING_.value]):
            # pylint: disable=import-outside-toplevel
            from modules.models.retrainer import Retrainer

            Retrainer().add_model(self._model_unique_name)

        # Check if the dimensionality reduction algorithm and parameters are
        # valid
        reduction_config = configuration[
            CONFIGURATION_KEYS.DIMENSIONALITY_REDUCTION.value]
        try:
            self._reduction_algorithm = ReductionAlgorithm[reduction_config[
                CONFIGURATION_KEYS.DIMENSIONALITY_REDUCTION_ALGORITHM_.value]]
            self._components_count = reduction_config[
                CONFIGURATION_KEYS.DIMENSIONALITY_REDUCTION_COMPONENTS_COUNT_.
                value]
        except KeyError:
            raise errors.InvalidReductionAlgorithmError()

        # Check if the machine learning algorithm is valid
        try:
            ml_configuration = configuration[
                CONFIGURATION_KEYS.MACHINE_LEARNING.value]
            ml_algorithm = ml_configuration[
                CONFIGURATION_KEYS.MACHINE_LEARNING_ALGORITHM_.value]
            self._ml_algorithm = RegressionAlgorithms[ml_algorithm]
            self._split_ratio = ml_configuration[
                CONFIGURATION_KEYS.MACHINE_LEARNING_SPLIT_RADIO_.value]
        except KeyError:
            raise errors.InvalidMachineLearningAlgorithmError()

        # Check the selected extractors and preprocessors
        pairs = configuration[
            CONFIGURATION_KEYS.EXTRACTORS_PREPROCESSORS.value]
        for pair in pairs:

            # Get the selected extractor and preprocessor
            extractor = (list(pair.keys()))[0]
            corresponding_preprocessors = pair[extractor]

            # Get the selected extractor as a class
            valid_extractor_names = [
                extractor.name for extractor in ExtractorsTypes
            ]
            if extractor not in valid_extractor_names:
                raise errors.InvalidExtractorError()

            # Check the number of given preprocessors
            extractor_class = ExtractionCore.load_extractor_by_name(
                ExtractorsTypes[extractor].value)
            valid_preprocessors = extractor_class.get_supported_preprocessors()
            if len(valid_preprocessors) != len(corresponding_preprocessors):
                raise errors.InvalidNumberOfPreprocessorsForExtractorsError()

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
                    raise errors.InvalidTypeOfPreprocessorForExtractorError()

            # Save the extractors
            self._extractors_types.append(ExtractorsTypes[extractor])

            # Save the preprocessors
            corresponding_preprocessors_types = []
            for preprocessor in corresponding_preprocessors:
                corresponding_preprocessors_types.append(
                    PreprocessorsTypes[preprocessor])
            self._preprocessors_types.append(corresponding_preprocessors_types)

        return True

    def _load_models_components(self,
                                configuration_filename: str,
                                attach_preprocessors: bool = True,
                                is_load: bool = False) -> None:
        # Verify the configuration file
        if not self._check_and_load_configuration(configuration_filename,
                                                  is_load):
            return False

        # Create the preprocessors core
        self._preprocessing_core = PreprocessingCore(self._reduction_algorithm,
                                                     self._components_count)

        # Attach the preprocessors
        if attach_preprocessors:
            for extractor, corresponding_preprocessors in zip(
                    self._extractors_types, self._preprocessors_types):
                for current_preprocessor_type in corresponding_preprocessors:
                    self._preprocessing_core.attach(current_preprocessor_type,
                                                    extractor)

        # Create the extractor core and attach the needed extractor to it
        self._extraction_core = ExtractionCore()
        for extractor_type in self._extractors_types:
            self._extraction_core.attach(extractor_type)

        # Load the dataset
        self._dataset = DatasetCore.read_dataset(self._dataset_filename)

        # Set the core as loaded
        self._is_ready = True

    def _base_train(self) -> None:

        # Extract features from each file in the dataset
        raw_features = []
        extraction_errors_indexes = []
        for entry_id, entry in self._dataset.iterrows():
            file_type = AnalyzedFileTypes.map_id_to_type(entry["type"])
            extension = file_type.value.STANDARD_EXTENSION
            basename = entry["hash"] + "." + extension

            try:

                if file_type == AnalyzedFileTypes.FEATURES:
                    full_filename = os.path.join(Folders.COLLECTED_FILES,
                                                 basename)

                    # Load the features directly from the file
                    with open(full_filename, "rb") as features_file:
                        features = pickle.loads(features_file.read())  # nosec

                else:
                    # Get the malware full path
                    if entry["malice"] == 0:
                        parent_folder = Folders.BENIGN_FILES
                    else:
                        parent_folder = Folders.MALICIOUS_FILES

                    full_filename = os.path.join(parent_folder, basename)

                    # Check if the file is from the original dataset or a
                    # collected one
                    if not os.path.isfile(full_filename):
                        full_filename = os.path.join(Folders.COLLECTED_FILES,
                                                     basename)
                        if not os.path.isfile(full_filename):
                            raise FileNotFoundError()

                    # Scan the file
                    features = self._extraction_core.squeeze(full_filename)

                raw_features.append(features)

            except Exception:
                extraction_errors_indexes.append(entry_id)

        # Apply the preprocessors and the dimensionality reduction
        features = self._preprocessing_core.preprocess(raw_features)
        self._preprocessed_features, self._reduced_features = features

        # Get the labels and remove the entries where extraction errors occurred
        if self._model_objective == ModelObjective.MALICE:
            y = self._dataset["malice"]
            if extraction_errors_indexes:
                y = [
                    elem for index, elem in enumerate(y)
                    if index not in extraction_errors_indexes
                ]
        elif self._model_objective == ModelObjective.CLASSIFICATION:
            y = self._dataset.iloc[:, range(3, len(self._dataset.columns))]
            if extraction_errors_indexes:
                y = y.drop(extraction_errors_indexes)
            y = y.values

        # Create the model
        if self._ml_algorithm == RegressionAlgorithms.DECISION_TREE:
            regression_model = DecisionTreeRegressor()
        elif (self._ml_algorithm ==
              RegressionAlgorithms.LINEAR_SUPPORT_VECTOR_MACHINE):
            regression_model = LinearSVR()
        elif self._ml_algorithm == RegressionAlgorithms.RANDOM_FOREST:
            regression_model = RandomForestRegressor()

        if self._model_objective == ModelObjective.MALICE:
            prediction_model = regression_model
        elif self._model_objective == ModelObjective.CLASSIFICATION:
            prediction_model = MultiOutputRegressor(regression_model)

        # Split the dataset
        X_train, X_test, y_train, y_test = train_test_split(
            self._reduced_features, y, train_size=self._split_ratio)

        # Use cross-validation to select the best model
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
        if self._model_objective == ModelObjective.MALICE:
            self._evaluation_results = ModelsEvaluator.evaluate_regression(
                y_test, y_pred)
        elif self._model_objective == ModelObjective.CLASSIFICATION:
            labels = list(self._dataset.columns)[3:]
            self._evaluation_results = \
                ModelsEvaluator.evaluate_soft_multilabel_classification(
                    y_test, y_pred, labels)

        self._is_unchanged = False

        Logger().log(
            "Successfully trained model {}".format(self._model_unique_name),
            LoggedMessageTypes.SUCCESS)

    def train(self, configuration_filename) -> None:
        """Trains a new model following the configuration from a file.

        This method can raise multiple exceptions, that inherit the platform's
        base one, depending on the unexpected behavior that appears.

        Args:
            configuration_filename (str): Name of the configuration file
        """
        # Generate a unique name for the model to be used to dump it
        self._model_unique_name = HashingEngine.generate_random_hash()

        # Save the configuration filename
        self._configuration_filename = configuration_filename

        # Initialize components
        self._load_models_components(configuration_filename, is_load=False)

        # Train
        self._base_train()

    def retrain(self) -> None:
        """Retrains the already loaded model.

        This method can raise multiple exceptions, that inherit the platform's
        base one, depending on the unexpected behavior that appears.
        """
        self._base_train()

    def _beautify_features(self, features: list) -> list:
        features = self._preprocessing_core.split_preprocessed_features(
            features)
        if not features:
            return None

        # Get the pairs of extractor - preprocessors from the configuration
        pairs = self._configuration[
            CONFIGURATION_KEYS.EXTRACTORS_PREPROCESSORS.value]

        returned_list = []
        feature_index = 0
        for pair in pairs:
            # Get the current extractor and preprocessor
            extractor = (list(pair.keys()))[0]
            corresponding_preprocessors = pair[extractor]

            # Get the descriptions of the features
            extractor_class = ExtractionCore.load_extractor_by_name(
                ExtractorsTypes[extractor].value)
            feature_types = extractor_class.get_feature_types()

            # Save each preprocessor output
            extractor_list = []
            for feature_type, preprocessor in zip(feature_types,
                                                  corresponding_preprocessors):
                feature = features[feature_index]
                feature_index += 1

                extractor_list.append({
                    "meaning": feature_type[0],
                    "preprocessor": preprocessor,
                    "features": feature
                })

            # Save the outputs of this extractor
            returned_list.append({
                "extractor": extractor,
                "features": extractor_list
            })

        return returned_list

    def predict(self,
                filename: str = None,
                features: typing.Any = None,
                analyst_mode: bool = False,
                similar_count: int = 0) -> dict:
        """Predicts the malice or the memberships to malware categories.

        Either the filename or the parameters of the feature must be set.

        The similarity consists in computing the Pearson correlation between the
        extracted features of the given samples and the one of each sample in
        the dataset and selecting the first samples with the largest similarity
        score.

        This method can raise multiple exceptions, that inherit the platform's
        base one, depending on the unexpected behavior that appears.

        Args:
            filename (str): Name of the file over which a prediction will be
                made
            features(typing.Any, optional): Already extracted raw features of
                the file
            analyst_mode (bool): Boolean indicating if the analyst mode is
                enabled. Defaults to False.
            similar_count (int): Number of similar samples to return. Defaults
                to 0, if the similarity analysis is disabled.

        Returns:
            dict: Prediction results
        """
        # Check if the core is ready to predict
        if (not self._is_ready or not (filename or features)):
            return None

        # Extract the features from the file
        if filename:
            try:
                raw_features = self._extraction_core.squeeze(filename)
            except errors.Error:
                return None
        else:
            raw_features = features

        # Apply the preprocessors and the dimensionality reduction algorithm
        features = self._preprocessing_core.preprocess([raw_features])
        (preprocessed_features, reduced_features) = features

        # Predict the results with the machine learning algorithm
        result = self._ml_model.predict(reduced_features)

        # Build the result
        returned_result = {}
        if self._model_objective == ModelObjective.MALICE:
            returned_result["malice"] = result[0]
        elif self._model_objective == ModelObjective.CLASSIFICATION:
            labels = list(self._dataset.columns)[3:]
            normalized_memberships = normalize([result[0]], "l1")[0]
            returned_result["memberships"] = dict(
                zip(labels, normalized_memberships))
        if analyst_mode:
            # Beautify the features
            beautified_features = self._beautify_features(
                preprocessed_features[0].tolist())
            returned_result["features"] = beautified_features

            # Detect the most similar samples in the dataframe
            reduced_features_df = pandas.DataFrame(self._reduced_features)
            reduced_features_sr = pandas.Series(reduced_features[0])
            correlations = reduced_features_df.corrwith(reduced_features_sr,
                                                        axis=1)
            correlations.sort_values(inplace=True, ascending=False)
            similarities = correlations[:similar_count]
            indexes = correlations.index[:similar_count]
            similar_samples = self._dataset.iloc[indexes]["hash"].values
            returned_result["similar"] = [{
                "hash": details[0],
                "similarity": details[1]
            } for details in zip(similar_samples, similarities)]

        return returned_result

    def get_file_features(self, file_hash: str) -> dict:
        """Gets the features of a file from the dataset.

        Args:
            file_hash (str): Hash of the file

        Returns:
            dict: Dictionary containing the features
        """
        index = int(self._dataset[self._dataset['hash'] == file_hash].index[0])
        features = self._beautify_features(
            self._preprocessed_features[index].tolist())

        return {"features": features} if features else None

    def dump(self) -> str:
        """Dumps the trained components (models).

        Returns:
            str: Unique name of the model
        """
        # Check if the model is a loaded one
        if self._is_unchanged:
            return self._model_unique_name

        # Create the folder structure
        model_dump_folder = Folders.MODEL_FMT.format(self._model_unique_name)
        if os.path.isdir(model_dump_folder):
            is_retraining = True

            original_model_dump_folder = model_dump_folder
            model_dump_folder = model_dump_folder[:-1]
            model_dump_folder += RETRAINING_CONFIG.RETRAINED_FOLDER_PREFIX

            original_model_name = self._model_unique_name
            self._model_unique_name += RETRAINING_CONFIG.RETRAINED_FOLDER_PREFIX
        else:
            is_retraining = False
        os.mkdir(model_dump_folder)
        used_format = Folders.MODEL_PREPROCESSORS_FMT
        preprocessors_models_dump_folder = used_format.format(
            self._model_unique_name)
        os.mkdir(preprocessors_models_dump_folder)

        # Copy the configuration file
        configuration_filename = Files.MODEL_TRAINING_CONFIGURATION_FMT.format(
            self._model_unique_name)
        shutil.copyfile(self._configuration_filename, configuration_filename)

        # Copy the dataset
        dataset_path = Files.MODEL_DATASET_FMT.format(self._model_unique_name)
        shutil.copyfile(self._dataset_filename, dataset_path)

        # Dump the machine learning model
        ml_model_path = Files.MODEL_ML_MODEL_FMT.format(
            self._model_unique_name)
        joblib.dump(self._ml_model, ml_model_path)

        # Dump the preprocessors
        self._preprocessing_core.dump(self._model_unique_name)

        # Dump the preprocessed features
        used_format = Files.MODEL_PREPROCESSED_FEATURES_FMT
        preprocessed_features_path = used_format.format(
            self._model_unique_name)
        preprocessed_features_df = pandas.DataFrame(
            self._preprocessed_features)
        preprocessed_features_df.to_csv(preprocessed_features_path,
                                        header=False,
                                        index=False)

        # Dump the reduced features
        reduced_features_path = Files.MODEL_REDUCED_FEATURES_FMT.format(
            self._model_unique_name)
        reduced_features_df = pandas.DataFrame(self._reduced_features)
        reduced_features_df.to_csv(reduced_features_path,
                                   header=False,
                                   index=False)

        # Dump the results of the evaluation
        evaluation_path = Files.MODEL_EVALUATION_FMT.format(
            self._model_unique_name)
        with open(evaluation_path, "w") as evaluation_output_file:
            json.dump(self._evaluation_results,
                      evaluation_output_file,
                      indent=TRAINING_CONFIG.JSON_FILES_INDENT_SPACES)

        ml_config = ConfigurationManager().get_space(
            ConfigurationSpaces.MODELS)

        # Dump the prediction configuration
        if self._model_objective == ModelObjective.MALICE:
            prediction_configuration = {
                "min_malice_suspect":
                ml_config["training"]["default_min_thresholds"]
                ["suspect_malice"],
                "min_malice_malicious":
                ml_config["training"]["default_min_thresholds"]
                ["malicious_malice"]
            }
        elif self._model_objective == ModelObjective.CLASSIFICATION:
            prediction_configuration = {
                "min_category_membership":
                ml_config["training"]["default_min_thresholds"]
                ["family_membership"]
            }

        used_format = Files.MODEL_PREDICTION_CONFIGURATION_FMT
        prediction_configuration_path = used_format.format(
            self._model_unique_name)
        with open(prediction_configuration_path,
                  "w") as prediction_configuration_output_file:
            json.dump(prediction_configuration,
                      prediction_configuration_output_file,
                      indent=TRAINING_CONFIG.JSON_FILES_INDENT_SPACES)

        # Remove the old folder and rename the current one
        if is_retraining:
            self._model_unique_name = original_model_name
            shutil.rmtree(original_model_dump_folder)
            shutil.move(model_dump_folder, original_model_dump_folder)

        # Log success
        Logger().log(
            "Successfully dumped model {}".format(self._model_unique_name),
            LoggedMessageTypes.SUCCESS)

        return self._model_unique_name

    def load(self, model_name: str) -> None:
        """Loads the trained components (models).

        Args:
            model_name (str): Name of the model to be loaded

        Raises:
            ModelToLoadNotFoundError: The model to load could not be found or
                opened.
        """
        # Check the existence of the given model
        model_full_path = Folders.MODEL_FMT.format(model_name)
        if not os.path.isdir(model_full_path):
            raise errors.ModelToLoadNotFoundError()

        self._model_unique_name = model_name

        # Get and load the configuration
        configuration_filename = Files.MODEL_TRAINING_CONFIGURATION_FMT.format(
            model_name)
        self._configuration_filename = configuration_filename

        # Initialize components
        self._load_models_components(self._configuration_filename, False, True)

        # Load the machine learning model
        ml_model_path = Files.MODEL_ML_MODEL_FMT.format(model_name)
        self._ml_model = joblib.load(ml_model_path)

        # Load the preprocessors
        preprocessors_count = sum(map(len, self._preprocessors_types))
        self._preprocessing_core.load(model_name, preprocessors_count)

        # Load the preprocessed features
        used_format = Files.MODEL_PREPROCESSED_FEATURES_FMT
        preprocessed_features_path = used_format.format(model_name)
        preprocessed_features_df = pandas.read_csv(preprocessed_features_path,
                                                   header=None,
                                                   index_col=False)
        self._preprocessed_features = preprocessed_features_df.values

        # Load the reduced features
        reduced_features_path = Files.MODEL_REDUCED_FEATURES_FMT.format(
            model_name)
        reduced_features_df = pandas.read_csv(reduced_features_path,
                                              header=None,
                                              index_col=False)
        self._reduced_features = reduced_features_df.values

        # Mark the model as loaded
        self._is_unchanged = True

        # Log success
        Logger().log("Successfully loaded model {}".format(model_name),
                     LoggedMessageTypes.SUCCESS)

    def set_prediction_configuration(self, model_name: str,
                                     parameter_name: str,
                                     parameter_value: float) -> bool:
        """Sets a new value for a parameter from the prediction configuration.

        Args:
            model_name (str): Name of the model
            parameter_name (str): Name of the parameter
            parameter_value (float): New value of the parameter

        Returns:
            bool: Boolean indicating if the configuration was successfully
                updated
        """
        # Read the current configuration
        used_format = Files.MODEL_PREDICTION_CONFIGURATION_FMT
        prediction_configuration_path = used_format.format(model_name)
        prediction_configuration_file = open(prediction_configuration_path,
                                             "r")
        configuration = json.load(prediction_configuration_file)
        prediction_configuration_file.close()

        # Modify its parameter if exists
        if parameter_name in configuration:
            configuration[parameter_name] = parameter_value

            # Dump the new configuration
            prediction_configuration_output_file = open(
                prediction_configuration_path, "w")
            json.dump(configuration,
                      prediction_configuration_output_file,
                      indent=TRAINING_CONFIG.JSON_FILES_INDENT_SPACES)

            return True

        return False

    def publish_prediction(self,
                           file_type: AnalyzedFileTypes,
                           full_filename: str = None,
                           features: typing.Any = None,
                           malice: float = None,
                           memberships: typing.List[float] = None) -> None:
        """Publishes an accurate prediction.

        Args:
            file_type (AnalyzedFileTypes): Type of the file being published
            full_filename (str): Name of the file for which the prediction was
                made. Defaults to None if the features are set.
            features (typing.Any): Serialized features for which the prediction
                was made. Defaults to None, if the filename is set.
            malice (float): Accurate malice score. Defaults to None, if the
                memberships are set.
            memberships (typing.List[float]): Array of accurate memberships to
                malware families. Defaults to None, if the malice is set.
        """
        if file_type == AnalyzedFileTypes.FEATURES:
            content = repr(features).encode("utf-8")
        else:
            # Get hash of file
            with open(full_filename, "rb") as file:
                content = file.read()
        file_hash = SHA256.new(data=content).hexdigest()

        # Update the dataset
        file_exists = DatasetCore.publish_to_dataset(self._dataset_filename,
                                                     file_type, file_hash,
                                                     malice, memberships)

        # Save the file if needed
        if not file_exists:
            standard_filename = file_hash
            standard_filename += "." + file_type.value.STANDARD_EXTENSION
            standard_filename = os.path.join(Folders.COLLECTED_FILES,
                                             standard_filename)

            # Save the content to a local file
            if full_filename:
                with open(full_filename, "rb") as sample_file:
                    content = sample_file.read()
            else:
                content = pickle.dumps(features)
            with open(standard_filename, "wb") as collected_file:
                collected_file.write(content)
