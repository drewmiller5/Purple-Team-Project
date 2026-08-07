import hmac
import os

import docker
from flask import Flask, jsonify, request

# Real container names (docker-compose.yml's container_name: values), not
# compose service names -- these containers already exist (built once by
# `docker compose up`); this revives them via docker.sock directly, it never
# builds or recreates anything.
ALLOWED_CONTAINERS = ["purple-lab-referee", "purple-lab-red", "purple-lab-blue"]

# block_ip (target/routes/internal.py) inserts iptables DROP rules on
# target's INPUT/FORWARD chains with no expiry. target is never restarted
# between rounds (only the 3 containers above are), and red keeps the same
# IP across restarts on the same network, so a single successful block from
# any past round silently pre-blocks red in every round since -- live-
# confirmed. Flushed at the start of every round below so each round is an
# independent trial; never touches red/blue/white_memory.json.
TARGET_CONTAINER = "purple-lab-target"


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

            # See TARGET_CONTAINER comment above: reset block_ip's
            # round-scoped network state so it doesn't silently carry over
            # from a prior round. Fixed commands, no user input -- checked
            # exit codes rather than assuming success (K3's lesson: a
            # defensive action that claims success regardless of outcome is
            # its own bug class).
            target = client.containers.get(TARGET_CONTAINER)
            for chain in ("INPUT", "FORWARD"):
                result = target.exec_run(["iptables", "-F", chain])
                if result.exit_code != 0:
                    return jsonify({
                        "error": f"iptables -F {chain} failed: {result.output!r}"
                    }), 500
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
