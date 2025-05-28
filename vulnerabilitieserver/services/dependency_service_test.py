import pytest
from unittest.mock import AsyncMock, MagicMock
from vulnerabilitieserver.services.dependency_service import DependencyService
from vulnerabilitieserver.models import (
    Dependency,
    Vulnerability,
    Application,
    Page,
    Requirement,
)
from vulnerabilitieserver.io.repository import Repository
from vulnerabilitieserver.io.cache import Cache
from vulnerabilitieserver.fixtures.vulnerability import VULNERABILITY


@pytest.fixture
def applications():
    return Repository[Application]()


@pytest.fixture
def dependencies():
    return Repository[Dependency]()


@pytest.fixture
def dependency_service(applications, dependencies):
    mock_osv_client = MagicMock()
    mock_osv_client.find_vulnerabilities = AsyncMock(return_value=[VULNERABILITY])
    cache = Cache[list[Vulnerability]]()
    service = DependencyService(
        os_dev_client=mock_osv_client,
        dependencies=dependencies,
        cache=cache,
        applications=applications,
    )

    return service


@pytest.mark.asyncio
async def test_dependency_service_gather_dependencies(
    dependency_service, applications, dependencies
):
    application = await applications.add(
        Application(
            name="app2",
            version="1.0",
            description="",
            requirements=[Requirement(name="pandas", version="1.0.0")],
            is_processing_dependencies=True,
        )
    )

    await dependency_service.gather_dependencies(application)
    all_deps = await dependencies.all()

    assert all_deps == [
        Dependency(
            id=1,
            name="pandas",
            version="1.0.0",
            application_id=application.id,
            vulnerabilities=[VULNERABILITY],
        )
    ]
    assert application.is_processing_dependencies == False


@pytest.mark.asyncio
async def test_dependency_service_get_application_dependencies(
    dependency_service, dependencies
):
    await dependencies.add(
        Dependency(application_id=1, name="foo", version="1.0", vulnerabilities=[])
    )

    page = await dependency_service.get_application_dependencies(
        application_id=1, limit=10, next_page_token=None
    )

    assert page == Page(
        limit=10,
        next_page_token=None,
        data=[
            Dependency(
                id=1, name="foo", version="1.0", application_id=1, vulnerabilities=[]
            )
        ],
    )


@pytest.mark.asyncio
async def test_dependency_service_get_dependencies(dependency_service, dependencies):
    await dependencies.add_all(
        [
            Dependency(application_id=1, name="foo", version="1.0", vulnerabilities=[]),
            Dependency(application_id=2, name="bar", version="2.0", vulnerabilities=[]),
        ]
    )

    page = await dependency_service.get_dependencies(limit=2, next_page_token=None)

    assert page == Page(
        limit=2,
        next_page_token=None,
        data=[
            Dependency(
                id=1, name="foo", version="1.0", application_id=1, vulnerabilities=[]
            ),
            Dependency(
                id=2, name="bar", version="2.0", application_id=2, vulnerabilities=[]
            ),
        ],
    )


@pytest.mark.asyncio
async def test_dependency_service_get_dependency_details(
    dependency_service, dependencies
):
    dependency = await dependencies.add(
        Dependency(application_id=1, name="foo", version="1.0", vulnerabilities=[])
    )

    result = await dependency_service.get_dependency_details(1)

    assert result == dependency
