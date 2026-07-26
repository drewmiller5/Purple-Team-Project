# target/app.py
from pathlib import Path

from flask import Flask
from werkzeug.security import generate_password_hash

from target.db import init_db, seed_db
from target.logging_middleware import register_logging
from target.routes.admin import admin_bp
from target.routes.diagnostics import diagnostics_bp
from target.routes.documents import documents_bp
from target.routes.internal import internal_bp
from target.routes.public import public_bp

DEFAULT_DB_PATH = "target/purple_lab.db"
DEFAULT_LOG_PATH = "target/logs/requests.jsonl"


def create_app(db_path: str = None, log_path: str = None) -> Flask:
    app = Flask(__name__)
    app.config["SECRET_KEY"] = "purple-lab-dev-key"  # sandboxed lab target, not production
    app.config["DB_PATH"] = db_path or DEFAULT_DB_PATH

    Path(app.config["DB_PATH"]).parent.mkdir(parents=True, exist_ok=True)
    init_db(app.config["DB_PATH"])
    seed_db(app.config["DB_PATH"], generate_password_hash)

    register_logging(app, log_path=log_path or DEFAULT_LOG_PATH)

    app.register_blueprint(public_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(documents_bp)
    app.register_blueprint(diagnostics_bp)
    app.register_blueprint(internal_bp)

    return app


if __name__ == "__main__":
    flask_app = create_app()
    flask_app.run(host="0.0.0.0", port=5000)
