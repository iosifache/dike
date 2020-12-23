from flask import Flask

app = Flask(__name__)


@app.route("/")
def default():
    return "This is the prediction server!"


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=443)