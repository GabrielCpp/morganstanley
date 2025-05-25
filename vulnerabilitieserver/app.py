from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from vulnerabilitieserver.controllers import applications_router, dependencies_router
from vulnerabilitieserver.middlewares import ErrorHandlerMiddleware, ContainerMiddleware
from vulnerabilitieserver.modules import build_container


def build_app():
    app = FastAPI()
    container = build_container()
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    app.add_middleware(ErrorHandlerMiddleware)
    app.add_middleware(ContainerMiddleware, container=container)
    app.include_router(applications_router, prefix="/api/v1")
    app.include_router(dependencies_router, prefix="/api/v1")
    return app
