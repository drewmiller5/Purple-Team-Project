import subprocess

from flask import Flask, jsonify

# Real container names (docker-compose.yml's container_name: values), not
# compose service names -- `docker start` operates on the container, and
# these containers already exist (built once by `docker compose up`); this
# revives them, it never builds or recreates anything, so it needs no
# compose file or build context inside this container, only the socket.
ALLOWED_CONTAINERS = ["purple-lab-referee", "purple-lab-red", "purple-lab-blue"]


def create_app() -> Flask:
    app = Flask(__name__)

    @app.route("/restart-round", methods=["POST"])
    def restart_round():
        result = subprocess.run(
            ["docker", "start", *ALLOWED_CONTAINERS],
            capture_output=True, text=True, timeout=60,
        )
        if result.returncode != 0:
            return jsonify({"error": result.stderr or "docker start failed"}), 500
        return jsonify({"restarted": ALLOWED_CONTAINERS})

    return app


if __name__ == "__main__":
    create_app().run(host="0.0.0.0", port=8090)
