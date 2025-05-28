import pytest
from vulnerabilitieserver.io.repository import Repository, Filter


class DummyItem:
    def __init__(self, id=None, value=None):
        self.id = id
        self.value = value


@pytest.mark.asyncio
async def test_repository_add_and_find_returns_item():
    repo = Repository[DummyItem]()
    item = DummyItem(value="foo")
    await repo.add(item)
    found = await repo.find(item.id)
    assert found is item
    assert found.value == "foo"


@pytest.mark.asyncio
async def test_repository_all_returns_all_items():
    repo = Repository[DummyItem]()
    item1 = DummyItem(value="foo")
    item2 = DummyItem(value="bar")
    await repo.add(item1)
    await repo.add(item2)
    all_items = await repo.all()
    assert item1 in all_items
    assert item2 in all_items
    assert len(all_items) == 2


@pytest.mark.asyncio
async def test_repository_update_changes_item():
    repo = Repository[DummyItem]()
    item = DummyItem(value="foo")
    await repo.add(item)
    item.value = "bar"
    await repo.update(item)
    found = await repo.find(item.id)
    assert found.value == "bar"


@pytest.mark.asyncio
async def test_repository_delete_removes_item():
    repo = Repository[DummyItem]()
    item = DummyItem(value="foo")
    await repo.add(item)
    await repo.delete(item.id)
    with pytest.raises(KeyError):
        await repo.find(item.id)


@pytest.mark.asyncio
async def test_repository_query_filters_and_limits():
    repo = Repository[DummyItem]()
    for i in range(5):
        await repo.add(DummyItem(value=i))
    # Filter for value >= 2
    filters = [Filter(name="value", op=">=", value=2)]
    results = await repo.query(filters, limit=2)
    assert all(item.value >= 2 for item in results)
    assert len(results) == 2
