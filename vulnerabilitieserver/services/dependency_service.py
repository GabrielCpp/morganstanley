from vulnerabilitieserver.models import Dependency, Page, Vulnerability, Application
from vulnerabilitieserver.io import Repository, OsvDevClient, Cache, Filter
from typing import Optional
from vulnerabilitieserver.utils import find_paginated
from datetime import timedelta


class DependencyService:
    def __init__(
        self,
        os_dev_client: OsvDevClient,
        dependencies: Repository[Dependency],
        cache: Cache[list[Vulnerability]],
        applications: Repository[Application],
    ):
        self._os_dev_client = os_dev_client
        self._dependencies = dependencies
        self._cache = cache
        self._applications = applications

    async def gather_dependencies(self, application: Application):
        dependencies = []
        for requirement in application.requirements:
            cache_key = f"{requirement.name}={requirement.version}"
            vulnerabilities = await self._cache.get(cache_key)

            if vulnerabilities is None:
                vulnerabilities = await self._os_dev_client.find_vulnerabilities(
                    requirement.version, requirement.name
                )
                await self._cache.set(cache_key, vulnerabilities, ttl=timedelta(days=1))

            dependencies.append(
                Dependency(
                    application_id=application.id,
                    name=requirement.name,
                    version=requirement.version,
                    vulnerabilities=vulnerabilities,
                )
            )

        await self._dependencies.add_all(dependencies)
        application.is_processing_dependencies = False
        await self._applications.update(application)

    async def get_application_dependencies(
        self, application_id: int, limit, next_page_token
    ) -> Page[Dependency]:
        return await find_paginated(
            self._dependencies,
            limit,
            next_page_token,
            filters=[Filter("application_id", "==", application_id)],
        )

    async def get_dependencies(self, limit: int, next_page_token: Optional[str]):
        return await find_paginated(
            self._dependencies,
            limit,
            next_page_token,
        )

    async def get_dependency_details(self, dependency_id):
        return await self._dependencies.find(dependency_id)
