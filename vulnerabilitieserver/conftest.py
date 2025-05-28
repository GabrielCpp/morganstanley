import pytest
from fastapi.testclient import TestClient
from vulnerabilitieserver.app import build_app
from vulnerabilitieserver.modules import build_container


@pytest.fixture
def container():
    return build_container()


@pytest.fixture
def app(container):
    """Create a FastAPI app instance for testing."""
    return build_app(container)


@pytest.fixture
def test_client(app):
    """Create a TestClient instance for the FastAPI app."""
    return TestClient(app)
