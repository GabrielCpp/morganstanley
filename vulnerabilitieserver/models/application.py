from pydantic import BaseModel


class Requirement(BaseModel):
    name: str
    version: str


class Application(BaseModel):
    id: int = 0

    # The name of the application.
    name: str

    # The version of the application.
    version: str

    # A brief description of the application.
    description: str

    # The requirement.txt associated with that application.
    requirements: list[Requirement]

    # True if the background job is still working
    # on identifying vulnerabilities
    is_processing_dependencies: bool


class NewApplication(BaseModel):
    name: str
    version: str
    description: str
