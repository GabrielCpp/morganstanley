import pytest
from fastapi.testclient import TestClient
from vulnerabilitieserver.app import build_app


@pytest.fixture
def app():
    """Create a FastAPI app instance for testing."""
    return build_app()


@pytest.fixture
def test_client(app):
    """Create a TestClient instance for the FastAPI app."""
    return TestClient(app)
