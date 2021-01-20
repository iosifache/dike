#!/usr/bin/env python3
"""Script running dike's software for prediction servers on this machine"""

from flask import Flask

app = Flask(__name__)


# Default route
@app.route("/")
def default():
    return "This is the prediction server!\n"


def main() -> None:
    app.run(host="0.0.0.0", port=443)


if __name__ == "__main__":
    main()