from typing import Optional
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from vulnerabilitieserver.controllers import applications_router, dependencies_router
from vulnerabilitieserver.middlewares import ErrorHandlerMiddleware, ContainerMiddleware
from vulnerabilitieserver.modules import build_container, Container


def build_app(container: Optional[Container] = None):
    app = FastAPI()
    container = container or build_container()
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    app.add_middleware(GZipMiddleware, minimum_size=1000)
    app.add_middleware(ErrorHandlerMiddleware)
    app.add_middleware(ContainerMiddleware, container=container)
    app.include_router(applications_router, prefix="/api/v1")
    app.include_router(dependencies_router, prefix="/api/v1")
    return app
