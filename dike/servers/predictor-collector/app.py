#!/usr/bin/env python3
"""Script running dike's software for prediction servers on this machine"""

import os
import pickle
import tempfile

import modules.utils.errors as errors
from configuration.platform import Files, Parameters
from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS
from modules.dataset.types import AnalyzedFileTypes
from modules.models.core import ModelsManagementCore
from modules.utils.configuration import ConfigurationSpace, ConfigurationWorker

STATUSES = Parameters.Servers.PredictorCollector.Statuses

# Global variables
malware_families = []

# Create the Flask app
app = Flask(__name__)
CORS(app)

# Create the models core
model_management_core = ModelsManagementCore()


def create_success_response(response_dict: dict = None) -> str:
    """Creates a success response.

    Args:
        response_dict (dict, optional): Dictionary on which the status is added
            to build the response. Defaults to None, when only the status will
            be returned.

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


@app.route("/")
def default_route() -> str:
    """Checks the availability of the API.

    Returns:
        str: JSON encapsulating the status
    """
    return create_success_response()


@app.route("/get_malware_families", methods=["GET"])
def get_malware_families_route() -> str:
    """Gets a list of malware families used in the platform.

    Returns:
        str: JSON encapsulating the array with malware families
    """
    families = {"families": malware_families}

    return create_success_response(families)


@app.route("/get_evaluation/<string:model_name>", methods=["GET"])
def get_evaluation_route(model_name: str) -> str:
    """Gets the evaluation file of a model.

    Args:
        model_name (str): Name of the model

    Returns:
        str: Evaluation file
    """
    try:
        full_filename = Files.MODEL_EVALUATION_FMT.format(model_name)
        if os.path.isfile(full_filename):
            return send_from_directory(os.path.dirname(full_filename),
                                       os.path.basename(full_filename))

        raise errors.ModelToLoadNotFoundError()
    except errors.Error as error:
        return create_error_response(error)


@app.route("/get_configuration/<string:model_name>", methods=["GET"])
def get_configuration_route(model_name: str) -> str:
    """Gets the prediction configuration file of a model.

    Args:
        model_name (str): Name of the model

    Returns:
        str: Evaluation file
    """
    try:
        full_filename = Files.MODEL_PREDICTION_CONFIGURATION_FMT.format(
            model_name)
        if os.path.isfile(full_filename):
            return send_from_directory(os.path.dirname(full_filename),
                                       os.path.basename(full_filename))

        raise errors.ModelToLoadNotFoundError()
    except errors.Error as error:
        return create_error_response(error)


@app.route("/create_ticket/<string:model_name>", methods=["POST"])
def create_ticket_route(model_name: str) -> str:
    """Predicts the objective value from the given file or features.

    Args:
        model_name (str): Model name

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
            if (similar_count == 0):
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
                features = pickle.loads(features.encode("utf-8"))
            except:
                raise errors.InvalidSerializedFeaturesError()

            prediction_args = (model_name, None, features, similarity_analysis,
                               similar_count)

        # Start a new threaded prediction
        ticket_name = model_management_core.threaded_predict(*prediction_args)

        return create_success_response({"name": ticket_name})

    except errors.Error as error:
        return create_error_response(error)


@app.route("/get_ticket/<string:ticket_name>", methods=["GET"])
def get_ticket_route(ticket_name: str) -> str:
    """Gets the content of a ticket.

    Args:
        ticket_name (str): Name of the ticket

    Returns:
        str: JSON encapsulating the status and the ticket content
    """
    content = model_management_core.get_ticket_content(ticket_name)

    if (content):
        return create_success_response(content)
    elif (content is None):
        return create_error_response(errors.FailedPredictionError())
    else:
        return create_unfinished_response()


@app.route("/publish/<string:model_name>", methods=["POST"])
def publish_route(model_name: str) -> str:
    """Saves a more accurate result of a file scan.

    Args:
        model_name (str): Model ID

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
                features = pickle.loads(features.encode("utf-8"))
            except:
                raise errors.InvalidSerializedFeaturesError()

            file_type = AnalyzedFileTypes.FEATURES

        # Get the request parameters
        malice = request.form.get("malice", type=float, default=None)
        memberships = request.form.get("memberships", type=str, default=None)
        if memberships:
            memberships = [
                float(memberships) for memberships in memberships.split(",")
            ]
        model_management_core.publish(model_name, file_type, full_filename,
                                      features, malice, memberships)

        return create_success_response()

    except errors.Error as error:
        return create_error_response(error)


def main() -> None:
    """Main function"""
    # pylint: disable=global-statement
    global malware_families

    # Get the configuration
    config = ConfigurationWorker()

    # Get the server parameters from the configuration
    server_config = config.get_configuration_space(
        ConfigurationSpace.PREDICTOR_COLLECTOR_SERVER)
    host = server_config["hostname"]
    port = server_config["port"]
    is_debug = server_config["is_debug"]

    # Get the malware families
    dataset_builder_config = config.get_configuration_space(
        ConfigurationSpace.DATASET_BUILDER)
    malware_families = [
        str(key).lower()
        for key in dataset_builder_config["malware_families"].keys()
    ]

    # Run the server
    app.run(host=host, port=port, debug=is_debug)


if __name__ == "__main__":
    main()
