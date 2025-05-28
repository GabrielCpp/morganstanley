from vulnerabilitieserver.middlewares import Container
import vulnerabilitieserver.services as core
import vulnerabilitieserver.models as models
import vulnerabilitieserver.io as io
import httpx


def build_container():
    container = Container()

    application_repository = container.add(io.Repository[models.Application]())
    dependencies_repository = container.add(io.Repository[models.Dependency]())
    cache = container.add(io.Cache[models.Vulnerability]())
    http_client = container.add(httpx.AsyncClient(http2=True))
    os_dev_client = container.add(io.OsvDevClient(http_client))
    container.add(core.ApplicationService(application_repository))
    container.add(
        core.DependencyService(
            os_dev_client, dependencies_repository, cache, application_repository
        )
    )

    return container
