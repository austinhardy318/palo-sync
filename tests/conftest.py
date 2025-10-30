import os
import pytest


@pytest.fixture(scope="session")
def flask_app():
    os.environ.setdefault("FLASK_SECRET_KEY", "test_secret_key_for_pytest")
    # Avoid external dependencies during tests
    os.environ.setdefault("REDIS_URL", "redis://localhost:6380/0")
    # Minimal NMS credentials to satisfy Config on import
    os.environ.setdefault("PROD_NMS_HOST", "test-host")
    os.environ.setdefault("PROD_NMS_USERNAME", "user")
    os.environ.setdefault("PROD_NMS_PASSWORD", "pass")
    os.environ.setdefault("LAB_NMS_HOST", "test-host")
    os.environ.setdefault("LAB_NMS_USERNAME", "user")
    os.environ.setdefault("LAB_NMS_PASSWORD", "pass")
    from app.main import app as flask_app
    flask_app.testing = True
    return flask_app


@pytest.fixture()
def client(flask_app):
    with flask_app.test_client() as c:
        yield c


