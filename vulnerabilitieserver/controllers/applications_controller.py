from fastapi import APIRouter, UploadFile, File, Form, Depends, BackgroundTasks
from typing import Annotated, Union
from vulnerabilitieserver.services import ApplicationService
from vulnerabilitieserver.models import NewApplication, Application
from vulnerabilitieserver.middlewares import Inject
from vulnerabilitieserver.services import DependencyService

router = APIRouter()


# List users’ applications. Identify vulnerable applications.
@router.get("/applications", tags=["applications"])
async def get_applications(
    application_service: Annotated[
        ApplicationService, Depends(Inject(ApplicationService))
    ],
    limit: int = 50,
    next_page_token: Union[str, None] = None,
):
    return await application_service.find_applications(limit, next_page_token)


# Retrieve the dependencies for a specified application
# and identify which of these dependencies are vulnerable.
@router.get("/applications/{:application_id}/dependencies", tags=["applications"])
async def get_application_dependencies(
    application_id: int,
    dependency_service: Annotated[
        DependencyService, Depends(Inject(DependencyService))
    ],
    limit: int = 50,
    next_page_token: Union[str, None] = None,
):
    return await dependency_service.get_application_dependencies(
        application_id, limit, next_page_token
    )


# Allow users to create a Python application by submitting
# a name, description, and requirements.txt file.
@router.post("/applications", tags=["applications"])
async def create_application(
    application_service: Annotated[
        ApplicationService, Depends(Inject(ApplicationService))
    ],
    dependency_service: Annotated[
        DependencyService, Depends(Inject(DependencyService))
    ],
    background_tasks: BackgroundTasks,
    new_application: str = Form(...),
    requirements_file: UploadFile = File(...),
) -> Application:
    new_application = NewApplication.model_validate_json(new_application)
    content = await requirements_file.read()
    requirements = content.decode("utf-8").split()
    application = await application_service.create_application(
        new_application, requirements
    )
    background_tasks.add_task(dependency_service.gather_dependencies, application)
    return application
