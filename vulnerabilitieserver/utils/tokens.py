import base64
from typing import TypeVar, Optional
from vulnerabilitieserver.io import Repository, HasId, Filter
from vulnerabilitieserver.models import Page

T = TypeVar("T")


def decode_int_token(token: str) -> int:
    decoded = base64.urlsafe_b64decode(token.encode()).decode()
    return int(decoded)


def encode_int_token(token: int) -> str:
    as_str = str(token).encode()
    return base64.urlsafe_b64encode(as_str).decode()


async def find_paginated(
    repository: Repository[T],
    limit: int,
    next_page_token: Optional[str] = None,
    filters: list[Filter] = [],
) -> Page[T]:
    last_id = decode_int_token(next_page_token) if next_page_token else 0
    results = await repository.query(
        filters=[Filter("id", ">=", last_id), *filters],
        limit=limit + 1,
        order_by=["id", "asc"],
    )

    return Page[T](
        limit=limit,
        data=results if len(results) <= limit else results[:-1],
        next_page_token=(
            None if len(results) <= limit else encode_int_token(results[-1].id)
        ),
    )
