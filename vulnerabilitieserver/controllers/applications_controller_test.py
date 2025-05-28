import io
import pytest
import json
from vulnerabilitieserver.main import app
from vulnerabilitieserver.models import Application
from vulnerabilitieserver.io import Repository


def test_list_applications_without_application(test_client):
    response = test_client.get("/api/v1/applications")
    assert response.status_code == 200
    assert response.json() == {"limit": 50, "next_page_token": None, "data": []}


def test_create_application(test_client):
    requirements_content = "fastapi\npytest\n"
    files = {
        "requirements_file": (
            "requirements.txt",
            io.BytesIO(requirements_content.encode("utf-8")),
            "text/plain",
        ),
        "new_application": (
            None,
            json.dumps(
                {"name": "MyApp", "description": "A test app", "version": "1.0.0"}
            ),
            "text/plain",
        ),
    }

    response = test_client.post(
        "/api/v1/applications",
        files=files,
    )

    assert response.status_code == 200


@pytest.mark.asyncio
async def test_get_application_dependencies(test_client, container):
    # First, create an application
    applications = container.get(Repository[Application])
    application = await applications.add(
        Application(
            name="test",
            version="3.5.7",
            description="test app",
            requirements=[],
            is_processing_dependencies=False,
        )
    )

    dep_response = test_client.get(
        f"/api/v1/applications/{application.id}/dependencies"
    )

    assert dep_response.status_code == 200
    payload = dep_response.json()
    assert payload == {'limit': 50, 'next_page_token': None, 'data': []}
