from fastapi import APIRouter

router = APIRouter()


# List all dependencies tracked across the user’s
# applications. Identify vulnerable dependencies.
@router.get("/dependencies", tags=["dependencies"])
async def get_dependencies():
    return [{"username": "Rick"}, {"username": "Morty"}]


# Provide details about a specific dependency, including usage
# and associated vulnerabilities
@router.get("/dependencies/{:id}", tags=["dependencies"])
async def get_dependency_details():
    return [{"username": "Rick"}, {"username": "Morty"}]
