import pytest
import httpx
import json
import asyncio
import time
import subprocess


@pytest.fixture
def server():
    proc = subprocess.Popen(
        [
            "uvicorn",
            "vulnerabilitieserver.app:build_app",
            "--factory",
            "--host",
            "0.0.0.0",
            "--port",
            "3131",
        ]
    )
    yield
    proc.terminate()
    proc.wait()


@pytest.mark.asyncio
async def test_create_application_and_fetch_vulnerabilities(server):
    base_url = "http://localhost:3131"
    new_application = {"name": "TestApp", "description": "desc", "version": "1.0.0"}
    files = {
        "requirements_file": (
            "requirements.txt",
            b"fastapi==1.2.3\npytest\n",
            "text/plain",
        ),
        "new_application": (None, json.dumps(new_application)),
    }

    async with httpx.AsyncClient(base_url=base_url) as client:
        response = await client.post("/api/v1/applications", files=files)
        assert response.status_code == 200
        data = response.json()
        assert data["name"] == "TestApp"
        assert data["version"] == "1.0.0"
        assert data["description"] == "desc"

        for _ in range(20):
            dep_response = await client.get(
                f"/api/v1/applications/{data['id']}/dependencies"
            )
            assert dep_response.status_code == 200
            payload = dep_response.json()

            if len(payload["data"]) > 0:
                break

            await asyncio.sleep(1)


        assert len(payload["data"]) > 0
