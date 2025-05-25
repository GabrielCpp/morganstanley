import pytest
from vulnerabilitieserver.io.repository import Repository


class DummyItem:
    def __init__(self, id, value):
        self.id = id
        self.value = value


def test_repository_find_added_item():
    repo = Repository()
    item = DummyItem(1, "foo")
    repo.add(item)
    assert repo.find(1) == item


def test_repository_get_all_items():
    repo = Repository()
    item1 = DummyItem(1, "foo")
    item2 = DummyItem(2, "bar")
    repo.add(item1)
    repo.add(item2)
    all_items = repo.all()
    assert item1 in all_items and item2 in all_items
    assert len(all_items) == 2


def test_repository_update_item():
    repo = Repository()
    item = DummyItem(1, "foo")
    repo.add(item)
    updated_item = DummyItem(1, "bar")
    repo.update(updated_item)
    assert repo.find(1).value == "bar"


def test_repository_delete_item():
    repo = Repository()
    item = DummyItem(1, "foo")
    repo.add(item)
    repo.delete(1)
    with pytest.raises(KeyError):
        repo.find(1)
