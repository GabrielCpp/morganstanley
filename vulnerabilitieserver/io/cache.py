from typing import TypeVar, Generic

T = TypeVar("T")


class Cache(Generic[T]):
    """
    A simple in-memory cache to store key-value pairs.
    """

    def __init__(self):
        self._cache = {}

    def get(self, key: str) -> T | None:
        return self._cache.get(key)

    def set(self, key: str, value: T, ttl=None) -> None:
        self._cache[key] = value

    def delete(self, key: str) -> None:
        if key in self._cache:
            del self._cache[key]

    def clear(self) -> None:
        self._cache.clear()
