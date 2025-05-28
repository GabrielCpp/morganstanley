from pydantic import BaseModel
from typing import Generic, TypeVar

T = TypeVar("T")


class Page(BaseModel, Generic[T]):
    model_config = {"arbitrary_types_allowed": True}

    # Maximum items per page
    limit: int

    # Token to fetch the next page or None
    # if it is the last one
    next_page_token: str | None

    # The items of the page
    data: list[T]
