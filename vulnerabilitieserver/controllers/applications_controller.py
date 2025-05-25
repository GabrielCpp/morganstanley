from fastapi import APIRouter

router = APIRouter()


# List users’ applications. Identify vulnerable applications.
@router.get("/applications", tags=["applications"])
async def get_applications():
    return [{"username": "Rick"}, {"username": "Morty"}]


# Retrieve the dependencies for a specified application
# and identify which of these dependencies are vulnerable.
@router.get("/applications/{:id}/dependencies", tags=["applications"])
async def get_application_dependencies():
    return [{"username": "Rick"}, {"username": "Morty"}]


# Allow users to create a Python application by submitting
# a name, description, and requirements.txt file.
@router.post("/applications", tags=["applications"])
async def create_application():
    return [{"username": "Rick"}, {"username": "Morty"}]
