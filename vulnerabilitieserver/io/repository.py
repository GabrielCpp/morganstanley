from typing import Protocol, Any, TypeVar, Generic


class HasId(Protocol):
    id: Any


T = TypeVar("T", bound=HasId)


class Repository(Generic[T]):
    """
    A simple in-memory repository to store items.
    """

    def __init__(self):
        self.items: dict[Any, Repository] = {}

    def find(self, id: Any) -> T:
        return self.items[id]

    def all(self) -> list[T]:
        return list(self.items.values())

    def add(self, item: T) -> None:
        self.items[item.id] = item

    def update(self, item: T) -> None:
        self.items[item.id] = item

    def delete(self, id: Any) -> None:
        del self.items[id]
