import pytest
from vulnerabilitieserver.services.application_service import ApplicationService
from vulnerabilitieserver.models import Application, NewApplication, Requirement, Page
from vulnerabilitieserver.io.repository import Repository


@pytest.fixture
def applications():
    return Repository[Application]()


@pytest.fixture
def application_service(applications):
    return ApplicationService(applications)


@pytest.mark.asyncio
async def test_application_service_create_application(
    application_service, applications
):
    new_app = NewApplication(name="TestApp", version="1.0", description="desc")
    requirements = ["fastapi==1.2.3", "pytest==7.0.0"]

    app = await application_service.create_application(new_app, requirements)
    all_apps = await applications.all()

    assert app in all_apps
    assert app.name == "TestApp"
    assert app.version == "1.0"
    assert app.description == "desc"
    assert app.is_processing_dependencies is True
    assert isinstance(app.requirements, list)
    assert app.requirements[0].name == "fastapi"
    assert app.requirements[0].version == "1.2.3"
    assert app.requirements[1].name == "pytest"
    assert app.requirements[1].version == "7.0.0"


@pytest.mark.asyncio
async def test_application_service_find_applications(application_service, applications):
    await applications.add_all(
        [
            Application(
                description="My test",
                name="Foo",
                version="0.0.0",
                requirements=[Requirement(name="pytest", version="7.0.0")],
                is_processing_dependencies=True,
            ),
            Application(
                description="My test2",
                name="Bar",
                version="0.0.0",
                requirements=[Requirement(name="pytest", version="7.0.0")],
                is_processing_dependencies=True,
            ),
        ]
    )

    page = await application_service.find_applications(limit=1, next_page_token=None)

    assert page == Page(
        limit=1,
        next_page_token="Mg==",
        data=[
            Application(
                id=1,
                name="Foo",
                version="0.0.0",
                description="My test",
                requirements=[Requirement(name="pytest", version="7.0.0")],
                is_processing_dependencies=True,
            )
        ],
    )

    page = await application_service.find_applications(limit=1, next_page_token="Mg==")

    assert page == Page(
        limit=1,
        next_page_token=None,
        data=[
            Application(
                id=2,
                name="Bar",
                version="0.0.0",
                description="My test2",
                requirements=[Requirement(name="pytest", version="7.0.0")],
                is_processing_dependencies=True,
            )
        ],
    )
