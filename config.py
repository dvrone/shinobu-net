import os

BASE_DIR = os.path.abspath(os.path.dirname(__file__))


class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "shinobu-dev-key")

    # Uploads
    UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
    ALLOWED_EXTENSIONS = {"pcap", "pcapng"}
    MAX_CONTENT_LENGTH = 100 * 1024 * 1024  # 100 MB max upload

    # Database
    SQLALCHEMY_DATABASE_URI = "sqlite:///" + os.path.join(
        BASE_DIR, "instance", "shinobu.db"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
