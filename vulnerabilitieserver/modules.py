from vulnerabilitieserver.middlewares import Container
import vulnerabilitieserver.services as core


def build_container():
    container = Container()
    container.add(core.ApplicationService())

    return container
