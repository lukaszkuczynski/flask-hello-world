import json

from flask import Flask

app = Flask(__name__)


@app.route("/")
def hello_world():
    locations = [{"id": 1, "name": "Wroclaw"}, {"id": 2, "name": "Krakow"}]
    return json.dumps(locations)
