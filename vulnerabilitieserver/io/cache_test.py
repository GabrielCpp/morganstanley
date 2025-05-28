import pytest
from vulnerabilitieserver.io.cache import Cache


@pytest.mark.asyncio
async def test_cache_get_returns_none_for_missing_key():
    cache = Cache()
    result = await cache.get("missing")
    assert result is None


@pytest.mark.asyncio
async def test_cache_set_and_get_returns_value():
    cache = Cache()
    await cache.set("foo", 123)
    result = await cache.get("foo")
    assert result == 123


@pytest.mark.asyncio
async def test_cache_delete_removes_key():
    cache = Cache()
    await cache.set("foo", "bar")
    await cache.delete("foo")
    result = await cache.get("foo")
    assert result is None


@pytest.mark.asyncio
async def test_cache_clear_removes_all_keys():
    cache = Cache()
    await cache.set("a", 1)
    await cache.set("b", 2)
    await cache.clear()
    assert await cache.get("a") is None
    assert await cache.get("b") is None
