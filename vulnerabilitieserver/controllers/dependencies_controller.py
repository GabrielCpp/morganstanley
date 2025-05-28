from fastapi import APIRouter, Depends
from typing import Annotated, Union
from vulnerabilitieserver.services import DependencyService
from vulnerabilitieserver.middlewares import Inject

router = APIRouter()


# List all dependencies tracked across the user’s
# applications. Identify vulnerable dependencies.
@router.get("/dependencies", tags=["dependencies"])
async def get_dependencies(
    dependency_service: Annotated[
        DependencyService, Depends(Inject(DependencyService))
    ],
    limit: int = 100,
    next_page_token: Union[str, None] = None,
):
    return dependency_service.get_dependencies(limit, next_page_token)


# Provide details about a specific dependency, including usage
# and associated vulnerabilities
@router.get("/dependencies/{dependency_id}", tags=["dependencies"])
async def get_dependency_details(
    dependency_id: int,
    dependency_service: Annotated[
        DependencyService, Depends(Inject(DependencyService))
    ],
):
    return dependency_service.get_dependency_details(dependency_id)
