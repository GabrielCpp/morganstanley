from pydantic import BaseModel


class Application(BaseModel):
    """
    A class representing a software application.

    Attributes:
        name (str): The name of the application.
        version (str): The version of the application.
        description (str): A brief description of the application.
        license (str): The license under which the application is released.
    """

    id: int
    name: str
    version: str
    description: str
