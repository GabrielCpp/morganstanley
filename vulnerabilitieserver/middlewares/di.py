from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.types import ASGIApp, Receive, Scope, Send


class Container:
    def __init__(self):
        self.services = {}

    def get(self, key):
        return self.services[key]

    def set(self, key, value):
        self.services[key] = value

    def add(self, value, key=None):
        self.services[key or type(value)] = value
        return value


class ContainerMiddleware(BaseHTTPMiddleware):
    def __init__(self, app: ASGIApp, container: Container):
        super().__init__(app)
        self.container = container

    async def dispatch(self, request: Request, call_next):
        request.state.container = self.container
        response = await call_next(request)
        return response


class Inject:
    def __init__(self, cls):
        self.cls = cls

    def __call__(self, request: Request):
        return request.state.container.get(self.cls)
