import io
import json
from fastapi.testclient import TestClient
from vulnerabilitieserver.main import app


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
