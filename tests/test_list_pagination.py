from __future__ import annotations

import unittest

from app.common.listing import paginate, sort_items


class ListPaginationHelpersTestCase(unittest.TestCase):
    def test_paginate(self) -> None:
        items = [{"id": i} for i in range(1, 51)]
        page_items, meta = paginate(items, page=2, page_size=10)
        self.assertEqual(len(page_items), 10)
        self.assertEqual(page_items[0]["id"], 11)
        self.assertEqual(meta["total_pages"], 5)

    def test_sort_items(self) -> None:
        items = [{"id": 2, "name": "b"}, {"id": 1, "name": "a"}]
        sorted_items = sort_items(items, "id", "asc", {"id"})
        self.assertEqual(sorted_items[0]["id"], 1)
        sorted_items = sort_items(items, "id", "desc", {"id"})
        self.assertEqual(sorted_items[0]["id"], 2)


if __name__ == "__main__":
    unittest.main()
