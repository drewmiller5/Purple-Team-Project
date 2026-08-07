import hmac
import os

import docker
from flask import Flask, jsonify, request

# Real container names (docker-compose.yml's container_name: values), not
# compose service names -- these containers already exist (built once by
# `docker compose up`); this revives them via docker.sock directly, it never
# builds or recreates anything.
ALLOWED_CONTAINERS = ["purple-lab-referee", "purple-lab-red", "purple-lab-blue"]


def create_app() -> Flask:
    app = Flask(__name__)
    app.config["INTERNAL_ACTION_TOKEN"] = os.environ.get("INTERNAL_ACTION_TOKEN")

    @app.route("/start-round", methods=["POST"])
    def start_round():
        expected_token = app.config.get("INTERNAL_ACTION_TOKEN")
        supplied_token = request.headers.get("X-Internal-Action-Token")

        if not (expected_token and supplied_token and hmac.compare_digest(expected_token, supplied_token)):
            return jsonify({"error": "unauthorized"}), 401

        # Root-cause fix: the image's docker.io apt package only installs
        # dockerd, never the `docker` CLI binary -- subprocess.run(["docker",
        # "start", ...]) always failed with FileNotFoundError, live-verified.
        # The SDK talks to docker.sock directly, no CLI binary dependency.
        #
        # .restart(), not .start(): a plain `docker start` no-ops on an
        # already-running container, so clicking this mid-round did nothing
        # -- user found this live. restart() forces a fresh process every
        # time regardless of whether the containers were running or already
        # exited, and referee/loop.py already unconditionally clears
        # go.flag/stop.flag on every fresh start, so no separate
        # flag-clearing step is needed either.
        try:
            client = docker.from_env()
            for name in ALLOWED_CONTAINERS:
                client.containers.get(name).restart()
        except (docker.errors.DockerException, OSError) as exc:
            # Review-round fix: docker-py's per-request HTTP calls only wrap
            # requests.exceptions.HTTPError into a DockerException -- a raw
            # ConnectionError (daemon mid-restart, socket hiccup) isn't a
            # DockerException subclass but IS an OSError (requests'
            # RequestException subclasses IOError/OSError), so this still
            # degrades to the endpoint's JSON error contract instead of
            # propagating into Flask's generic 500 page.
            return jsonify({"error": str(exc)}), 500
        return jsonify({"started": ALLOWED_CONTAINERS})

    return app


if __name__ == "__main__":
    create_app().run(host="0.0.0.0", port=8090)
