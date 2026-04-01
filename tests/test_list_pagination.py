from __future__ import annotations

import unittest

from app.common.listing import build_list_payload, filter_items, paginate, sort_items


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

    def test_filter_items(self) -> None:
        items = [
            {"id": 1, "event_type": "suricata.alert", "src_ip": "203.0.113.10"},
            {"id": 2, "event_type": "auth.failure", "src_ip": "10.0.0.8"},
        ]
        filtered = filter_items(items, "suricata", fields=["event_type"])
        self.assertEqual(len(filtered), 1)
        self.assertEqual(filtered[0]["id"], 1)

    def test_build_list_payload(self) -> None:
        items = [
            {"id": 3, "status": "failed"},
            {"id": 1, "status": "success"},
            {"id": 2, "status": "success"},
        ]
        payload = build_list_payload(
            items,
            page=1,
            page_size=2,
            sort_by="id",
            sort_order="asc",
            allowed_sort_fields={"id"},
            query="success",
            search_fields=["status"],
        )
        self.assertEqual(payload["pagination"]["total"], 2)
        self.assertEqual(payload["items"][0]["id"], 1)
        self.assertEqual(payload["items"][1]["id"], 2)


if __name__ == "__main__":
    unittest.main()
