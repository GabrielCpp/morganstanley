from vulnerabilitieserver.io import Repository, Cache, Filter
from vulnerabilitieserver.models import (
    Application,
    NewApplication,
    Requirement,
    Page,
    Dependency,
)
from vulnerabilitieserver.utils import find_paginated
from typing import Optional


class ApplicationService:
    def __init__(
        self,
        applications: Repository[Application],
    ):
        self._applications = applications

    async def create_application(
        self, new_application: NewApplication, requirements: list[str]
    ):
        parsed_requirements = self._parse_requirements(requirements)
        application = await self._applications.add(
            Application(
                name=new_application.name,
                version=new_application.version,
                description=new_application.description,
                requirements=parsed_requirements,
                is_processing_dependencies=True,
            )
        )

        return application

    async def find_applications(
        self, limit: int, next_page_token: Optional[str]
    ) -> Page[Application]:
        return await find_paginated(self._applications, limit, next_page_token)

    def _parse_requirements(self, requirements: list[str]) -> list[Requirement]:
        parsed_requirements = []
        for req in requirements:
            # Example: "package==1.2.3"
            if "==" in req:
                name, version = req.split("==", 1)
                parsed_requirements.append(
                    Requirement(name=name.strip(), version=version.strip())
                )

        return parsed_requirements
