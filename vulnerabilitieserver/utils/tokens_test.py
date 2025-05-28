import pytest
from vulnerabilitieserver.utils.tokens import find_paginated, encode_int_token
from vulnerabilitieserver.io.repository import Repository, HasId
from pydantic import BaseModel


class DummyItem(BaseModel):
    id: int = 0
    value: str = ""


@pytest.mark.asyncio
async def test_find_paginated_no_item():
    repo = Repository[DummyItem]()

    page = await find_paginated(repo, limit=1)

    assert page.limit == 1
    assert page.data == []
    assert page.next_page_token is None


@pytest.mark.asyncio
async def test_find_paginated_one_item_page_of_1():
    repo = Repository[DummyItem]()
    await repo.add(DummyItem(value="foo"))

    page = await find_paginated(repo, limit=1)

    assert page.limit == 1
    assert len(page.data) == 1
    assert page.data[0].value == "foo"
    assert page.next_page_token is None


@pytest.mark.asyncio
async def test_find_paginated_two_items_page_of_1():
    repo = Repository[DummyItem]()
    await repo.add_all([DummyItem(value="foo"), DummyItem(value="bar")])

    # First page
    page1 = await find_paginated(repo, limit=1)
    assert page1.limit == 1
    assert len(page1.data) == 1
    assert page1.data[0].value == "foo"
    assert page1.next_page_token is not None

    # Second page using next_page_token
    page2 = await find_paginated(repo, limit=1, next_page_token=page1.next_page_token)
    assert page2.limit == 1
    assert len(page2.data) == 1
    assert page2.data[0].value == "bar"
    assert page2.next_page_token is None
