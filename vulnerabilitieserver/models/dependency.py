from pydantic import BaseModel, Field
from vulnerabilitieserver.models.vulnerability import Vulnerability


class Dependency(BaseModel):
    """
    A class representing a software dependency.

    Attributes:
        name (str): The name of the dependency.
        version (str): The version of the dependency.
        description (str): A brief description of the dependency.
        license (str): The license under which the dependency is released.
    """

    id: int
    name: str
    version: str
    description: str
    license: str
    vulnerabilities: list[Vulnerability] = Field(default_factory=list)
