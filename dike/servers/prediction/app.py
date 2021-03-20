#!/usr/bin/env python3
"""Script running dike's software for prediction servers on this machine"""

import base64
import pickle
import random

from flask import Flask, jsonify, request

# Constants
PORT = 10101

# Create the Flask app
app = Flask(__name__)


@app.route("/")
def default_route() -> str:
    """Identifies the API.

    Returns:
        str: API's identification message
    """
    return "This is dike's prediction server!\n"


@app.route("/predict/<string:model_id>", methods=["POST"])
def predict_route(model_id: str) -> str:
    """Predicts the objective attribute from the given features.

    Args:
        model_id (str): Model ID

    Returns:
        str: Computed prediction
    """
    if (request.method == "POST"):
        features = request.form["features"]
        try:
            features = pickle.loads(features.encode("utf-8"))
        except:
            pass
        print("Prediction for model {} with features {}".format(
            model_id, features))

        random_malice = random.randint(0, 100) / 100
        result = {"status": "ok", "malice": random_malice}

        return jsonify(result)


@app.route("/publish/<string:model_id>", methods=["POST"])
def publish_route(model_id: str) -> str:
    """Saves a more accurate result of a file scan.

    Args:
        model_id (str): Model ID

    Returns:
        str: Empty string
    """
    if (request.method == "POST"):
        features = request.form["features"]
        try:
            features = pickle.loads(features.encode("utf-8"))
        except:
            pass
        malice = request.form["malice"]
        print("Publish to model {} the malice {} of features {}".format(
            model_id, malice, features))

        return ""


def main() -> None:
    """Main function
    """
    app.run(host="0.0.0.0", port=PORT, debug=True)


if __name__ == "__main__":
    main()
