from httpx import AsyncClient
from vulnerabilitieserver.models import Vulnerability
from json import dumps


class OsvDevClient:
    def __init__(self, client: AsyncClient):
        self.client = client

    async def find_vulnerabilities(
        self, version: str, package_name: str, ecosystem: str = "PyPI"
    ) -> list[Vulnerability]:
        response = await self.client.post(
            "https://api.osv.dev/v1/query",
            content=dumps(
                {
                    "version": version,
                    "package": {"name": package_name, "ecosystem": ecosystem},
                }
            ),
        )

        response.raise_for_status()
        data = response.json()
        vulnerabilities = [Vulnerability(**item) for item in data.get("vulns", [])]
        return vulnerabilities
