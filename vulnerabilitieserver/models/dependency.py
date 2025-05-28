from pydantic import BaseModel, Field
from vulnerabilitieserver.models.vulnerability import Vulnerability


class Dependency(BaseModel):
    id: int = 0

    # The name of the dependency. eg. pandas
    name: str

    # The version of the dependency. eg: 0.2.1
    version: str

    # The application to which it relate to
    application_id: int

    # Vulnerabilities associated with the depedency
    vulnerabilities: list[Vulnerability] = Field(default_factory=list)
