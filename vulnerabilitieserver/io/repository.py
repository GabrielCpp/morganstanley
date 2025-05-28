from typing import Protocol, Any, TypeVar, Generic, Optional, Tuple
from dataclasses import dataclass


class HasId(Protocol):
    id: int


T = TypeVar("T", bound=HasId)


@dataclass
class Filter:
    name: str
    op: str
    value: Any


class Repository(Generic[T]):
    """
    A simple in-memory repository to store items.
    """

    def __init__(self):
        self._items: dict[int, Repository] = {}
        self._sequence_number = 0

    async def find(self, id: int) -> T:
        return self._items[id]

    async def all(self) -> list[T]:
        return list(self._items.values())

    async def add(self, item: T) -> T:
        self._sequence_number += 1
        item.id = self._sequence_number
        self._items[item.id] = item
        return item

    async def add_all(self, items: list[T]) -> list[T]:
        for item in items:
            self._sequence_number += 1
            item.id = self._sequence_number
            self._items[item.id] = item

        return items

    async def update(self, item: T) -> None:
        self._items[item.id] = item

    async def delete(self, id: int) -> None:
        del self._items[id]

    async def query(
        self,
        filters: list[Filter],
        order_by: Optional[Tuple[str, str]] = None,
        limit: Optional[int] = 1000,
    ) -> list[T]:
        selected_items = []

        for item in self._items.values():
            keep_item = True
            for filter in filters:
                if filter.op == ">=" and not (
                    getattr(item, filter.name) >= filter.value
                ):
                    keep_item = False

                if filter.op == "==" and getattr(item, filter.name) != filter.value:
                    keep_item = False

                if not keep_item:
                    break

            if keep_item:
                selected_items.append(item)

            if len(selected_items) >= limit:
                break

        if order_by:
            selected_items.sort(
                reverse=order_by[1] == "desc",
                key=lambda x: getattr(x, order_by[0]),
            )

        return selected_items
