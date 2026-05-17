import os

from flask import Flask

from .models import db


def create_app():
    app = Flask(__name__)

    # Load config
    app.config.from_object("config.Config")

    # Ensure upload folder exists
    os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

    # Initialize database
    db.init_app(app)

    # Register blueprints
    from .routes.main import main_bp

    app.register_blueprint(main_bp)

    # Create tables if they don't exist
    with app.app_context():
        db.create_all()

    return app
