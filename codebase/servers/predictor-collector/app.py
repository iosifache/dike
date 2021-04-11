#!/usr/bin/env python3
"""Prediction server main script.

Usage:
    ./app.py
"""
import os
import pickle  # nosec
import tempfile
from threading import Thread

import servers.errors as errors
from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS
from modules.configuration.folder_structure import Files
from modules.configuration.parameters import Servers
from modules.dataset.types import AnalyzedFileTypes
from modules.models.core import ModelsManagementCore
from modules.models.errors import ModelToLoadNotFoundError
from modules.utils.configuration_manager import ConfigurationManager
from modules.utils.types import ConfigurationSpaces

ROUTES = Servers.PredictorCollector.Routes
STATUSES = Servers.PredictorCollector.Statuses

# The variables are global, not constants. pylint: disable=invalid-name
malware_families = []

app = Flask(__name__)
CORS(app)

model_management_core = ModelsManagementCore()


def create_success_response(response_dict: dict = None) -> str:
    """Creates a successful response.

    Args:
        response_dict (dict): Dictionary on which the status is added to build
            the response. Defaults to None, when only the status will be
            returned.

    Returns:
        str: JSON success response
    """
    if response_dict:
        response_dict["status"] = STATUSES.SUCCESS
    else:
        response_dict = {"status": STATUSES.SUCCESS}

    return jsonify(response_dict)


def create_unfinished_response() -> str:
    """Creates an unfinished response.

    Returns:
        str: JSON unfinished response
    """
    return jsonify({"status": STATUSES.UNFINISHED})


def create_error_response(error: errors.Error) -> str:
    """Creates an error response.

    Args:
        error (errors.Error): Occurred error

    Returns:
        str: JSON error response
    """
    error_result = {"status": STATUSES.ERROR, "message": str(error)}

    return jsonify(error_result)


@app.route(ROUTES.DEFAULT)
def default_route() -> str:
    """Checks the availability of the API.

    Returns:
        str: JSON encapsulating the status
    """
    return create_success_response()


@app.route(ROUTES.GET_MALWARE_FAMILIES, methods=["GET"])
def get_malware_families_route() -> str:
    """Gets a list of malware families used in the platform.

    Returns:
        str: JSON encapsulating the array with malware families
    """
    families = {"families": malware_families}

    return create_success_response(families)


@app.route(ROUTES.GET_EVALUATION + "/<string:model_name>", methods=["GET"])
def get_evaluation_route(model_name: str) -> str:
    """Gets the evaluation file of a model.

    Args:
        model_name (str): Name of the model

    Raises:
        ModelToLoadNotFoundError: The model to load could not be found or
            opened.

    Returns:
        str: Evaluation file
    """
    try:
        full_filename = Files.MODEL_EVALUATION_FMT.format(model_name)
        if os.path.isfile(full_filename):
            return send_from_directory(os.path.dirname(full_filename),
                                       os.path.basename(full_filename))

        raise ModelToLoadNotFoundError()
    except errors.Error as error:
        return create_error_response(error)


@app.route(ROUTES.GET_CONFIGURATION + "/<string:model_name>", methods=["GET"])
def get_configuration_route(model_name: str) -> str:
    """Gets the prediction configuration file of a model.

    Args:
        model_name (str): Name of the model

    Raises:
        ModelToLoadNotFoundError: The model to load could not be found or
            opened.

    Returns:
        str: Evaluation file
    """
    try:
        full_filename = Files.MODEL_PREDICTION_CONFIGURATION_FMT.format(
            model_name)
        if os.path.isfile(full_filename):
            return send_from_directory(os.path.dirname(full_filename),
                                       os.path.basename(full_filename))

        raise ModelToLoadNotFoundError()
    except errors.Error as error:
        return create_error_response(error)


@app.route(ROUTES.CREATE_TICKET + "/<string:model_name>", methods=["POST"])
def create_ticket_route(model_name: str) -> str:
    """Predicts the objective value from the given file or features.

    Args:
        model_name (str): Model name

    Raises:
        InvalidSimilarCountError: The similar_count parameter is invalid.
        InvalidSampleTypeError: The submitted file has a type that is not
            supported by the platform.
        InvalidSerializedFeaturesError: The submitted serialized features are
            invalid.
        NoSampleToScanError: No sample to scan was provided.

    Returns:
        str: JSON encapsulating the status and the ticket name
    """
    try:
        # Get the similarity analysis parameters
        similarity_analysis = request.form.get("similarity_analysis",
                                               type=int,
                                               default=0)
        if similarity_analysis:
            similar_count = request.form.get("similars_count", type=int)
            if similar_count == 0:
                raise errors.InvalidSimilarCountError()
        else:
            similar_count = 0

        # Get the sample file or features
        if "sample" in request.files:
            sample = request.files["sample"]

            if not AnalyzedFileTypes.has_valid_extension(sample.filename):
                raise errors.InvalidSampleTypeError()

            # Save the file in a temporary location
            temp_sample = tempfile.NamedTemporaryFile(delete=False)
            sample.save(temp_sample.name)

            prediction_args = (model_name, temp_sample.name, None,
                               similarity_analysis, similar_count, True)

        elif "features" in request.form:
            # Get the features
            features = request.form["features"]
            try:
                features = pickle.loads(features.encode("utf-8"))  # nosec
            except Exception:
                raise errors.InvalidSerializedFeaturesError()

            prediction_args = (model_name, None, features, similarity_analysis,
                               similar_count)
        else:
            raise errors.NoSampleToScanError()

        # Create a new ticket
        ticket_name = model_management_core.create_ticket()

        # Create a new thread for prediction
        prediction_args = (ticket_name, ) + prediction_args
        thread = Thread(target=model_management_core.predict_synchronously,
                        args=prediction_args)
        thread.start()

        return create_success_response({"name": ticket_name})

    except errors.Error as error:
        return create_error_response(error)


@app.route(ROUTES.GET_TICKET + "/<string:ticket_name>", methods=["GET"])
def get_ticket_route(ticket_name: str) -> str:
    """Gets the content of a ticket.

    Args:
        ticket_name (str): Name of the ticket

    Returns:
        str: JSON encapsulating the status and the ticket content
    """
    content = model_management_core.get_ticket_content(ticket_name)

    if content:
        return create_success_response(content)
    elif content is None:
        return create_error_response(errors.FailedPredictionError())
    else:
        return create_unfinished_response()


@app.route(ROUTES.PUBLISH + "/<string:model_name>", methods=["POST"])
def publish_route(model_name: str) -> str:
    """Saves a more accurate result of a file scan.

    Args:
        model_name (str): Model ID

    Raises:
        InvalidSampleTypeError: The submitted file has a type that is not
            supported by the platform.
        InvalidSerializedFeaturesError: The submitted serialized features are
            invalid.
        NoSampleToPublishError: No sample to publish was provided.

    Returns:
        str: JSON encapsulating the status
    """
    try:
        full_filename = None
        features = None
        if "sample" in request.files:
            sample = request.files["sample"]

            # Check the file extension
            file_type = AnalyzedFileTypes.map_extension_to_type(
                sample.filename)
            if not file_type:
                raise errors.InvalidSampleTypeError()

            # Save the file in a temporary location
            temp_sample = tempfile.NamedTemporaryFile(delete=False)
            sample.save(temp_sample.name)
            full_filename = temp_sample.name

        elif "features" in request.form:
            # Get the features
            features = request.form["features"]
            try:
                features = pickle.loads(features.encode("utf-8"))  # nosec
            except Exception:
                raise errors.InvalidSerializedFeaturesError()

            file_type = AnalyzedFileTypes.FEATURES
        else:
            raise errors.NoSampleToPublishError()

        # Get the request parameters
        malice = request.form.get("malice", type=float, default=None)
        memberships = request.form.get("memberships", type=str, default=None)
        if memberships:
            memberships = [
                float(memberships) for memberships in memberships.split(",")
            ]
        model_management_core.publish_prediction(model_name, file_type,
                                                 full_filename, features,
                                                 malice, memberships)

        return create_success_response()

    except errors.Error as error:
        return create_error_response(error)


def main() -> None:
    """Main function."""
    # pylint: disable=global-statement
    global malware_families

    configuration = ConfigurationManager()

    # Get the server parameters from the configuration
    server_config = configuration.get_space(
        ConfigurationSpaces.PREDICTOR_COLLECTOR_SERVER)
    host = server_config["hostname"]
    port = server_config["port"]
    is_secure = server_config["is_secure"]
    is_debug = server_config["is_debug"]

    # Get the malware families
    dataset_builder_config = configuration.get_space(
        ConfigurationSpaces.DATASET)
    malware_families = [
        str(key).lower()
        for key in dataset_builder_config["malware_families"].keys()
    ]

    ssl_context = None
    if is_secure:
        ssl_context = (Files.SSL_CERTIFICATE, Files.SSL_PRIVATE_KEY)

    # Run the server
    app.run(host=host, port=port, debug=is_debug, ssl_context=ssl_context)


if __name__ == "__main__":
    main()
