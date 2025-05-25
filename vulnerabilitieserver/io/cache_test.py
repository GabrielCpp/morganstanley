from vulnerabilitieserver.io.cache import Cache


def test_cache_set_and_get():
    cache = Cache()
    cache.set("foo", "bar")
    assert cache.get("foo") == "bar"


def test_cache_get_missing_key():
    cache = Cache()
    assert cache.get("missing") is None


def test_cache_delete():
    cache = Cache()
    cache.set("foo", "bar")
    cache.delete("foo")
    assert cache.get("foo") is None


def test_cache_clear():
    cache = Cache()
    cache.set("foo", "bar")
    cache.set("baz", "qux")
    cache.clear()
    assert cache.get("foo") is None
    assert cache.get("baz") is None
