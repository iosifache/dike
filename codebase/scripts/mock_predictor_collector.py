#!/usr/bin/env python3
"""Script for emulating the dike's predictor-collector server.

Tests can be performed using httpie as follows:

```
# Ticket creation. pylint: disable=line-too-long
http -f POST http://127.0.0.1:10101/create_ticket/model features="(lp0\nVa\np1\naVb\np2\na."

# Ticket inspection
http http://127.0.0.1:10101/get_ticket/ticket

# Accurate results publishing. pylint: disable=line-too-long
http -f POST http://127.0.0.1:10101/publish/model features="(lp0\nVa\np1\naVb\np2\na." malice=0.95
```
"""

import pickle  # nosec
import random
import string

from flask import Flask, jsonify, request

# Constants
PORT = 10101
MAX_FEATURES_CHARS = 30
TICKET_NAME_LENGTH = 64

# Create the Flask app. pylint: disable=invalid-name
app = Flask(__name__)


def _trim_features(features: bytes) -> str:
    return str(features)[0:MAX_FEATURES_CHARS] + "..."


def _generate_random_ticket_name() -> str:
    return "".join(
        random.choice(string.ascii_letters)  # nosec
        for x in range(TICKET_NAME_LENGTH))


@app.route("/")
def default_route() -> str:
    """Identifies the API.

    Returns:
        str: Identification message of the API
    """
    return "This is dike's prediction server!\n"


@app.route("/create_ticket/<string:model_id>", methods=["POST"])
def create_ticket_route(model_id: str) -> str:
    """Creates a ticket for a prediction.

    Args:
        model_id (str): Model ID

    Returns:
        str: JSON encapsulating the status and the ticket name
    """
    features = request.form["features"]
    try:
        features = pickle.loads(features.encode("utf-8"))  # nosec
    except Exception:  # nosec
        pass
    result = {"status": "ok", "name": _generate_random_ticket_name()}

    print("Creating a ticket for model \"{}\" with the features \"{}\"".format(
        model_id, _trim_features(features)))

    return jsonify(result)


@app.route("/get_ticket/<string:ticket_name>", methods=["GET"])
def get_ticket_route(ticket_name: str) -> str:
    """Gets the content of a ticket.

    Args:
        ticket_name (str): Name of the ticket

    Returns:
        str: JSON encapsulating the status and the ticket content
    """
    random_malice = random.randint(0, 100) / 100  # nosec
    result = {"status": "ok", "malice": random_malice}

    print("Getting the content of the ticket \"{}\", namely the malice of {}".
          format(ticket_name, random_malice))

    return jsonify(result)


@app.route("/publish/<string:model_id>", methods=["POST"])
def publish_route(model_id: str) -> str:
    """Saves a more accurate result of a file scan.

    Args:
        model_id (str): Model ID

    Returns:
        str: Empty string
    """
    features = request.form["features"]
    try:
        features = pickle.loads(features.encode("utf-8"))  # nosec
    except Exception:  # nosec
        pass
    malice = request.form["malice"]
    result = {"status": "ok"}

    print(
        "Publish to model \"{}\" the malice \"{}\" of features \"{}\"".format(
            model_id, malice, _trim_features(features)))

    return jsonify(result)


def main() -> None:
    """Main function."""
    app.run(host="0.0.0.0", port=PORT, debug=True)  # nosec


if __name__ == "__main__":
    main()
