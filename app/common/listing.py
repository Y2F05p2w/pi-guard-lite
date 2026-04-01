from __future__ import annotations

import math
from typing import Any


def paginate(
    items: list[dict[str, Any]],
    *,
    page: int,
    page_size: int,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    total = len(items)
    page_size = max(1, min(page_size, 100))
    total_pages = max(1, math.ceil(total / page_size))
    page = max(1, min(page, total_pages))
    start = (page - 1) * page_size
    end = start + page_size
    return items[start:end], {
        "page": page,
        "page_size": page_size,
        "total": total,
        "total_pages": total_pages,
        "has_prev": page > 1,
        "has_next": page < total_pages,
        "prev_page": page - 1,
        "next_page": page + 1,
    }


def sort_items(
    items: list[dict[str, Any]],
    sort_by: str,
    sort_order: str,
    allowed: set[str],
) -> list[dict[str, Any]]:
    if sort_by not in allowed:
        return items
    reverse = sort_order == "desc"
    return sorted(items, key=lambda item: _sortable_value(item.get(sort_by)), reverse=reverse)


def filter_items(
    items: list[dict[str, Any]],
    query: str,
    *,
    fields: list[str] | None = None,
) -> list[dict[str, Any]]:
    keyword = (query or "").strip().lower()
    if not keyword:
        return items

    matched: list[dict[str, Any]] = []
    for item in items:
        values = fields or list(item.keys())
        haystack = " ".join(str(item.get(field, "")) for field in values).lower()
        if keyword in haystack:
            matched.append(item)
    return matched


def build_list_payload(
    items: list[dict[str, Any]],
    *,
    page: int,
    page_size: int,
    sort_by: str,
    sort_order: str,
    allowed_sort_fields: set[str],
    query: str = "",
    search_fields: list[str] | None = None,
    summary: dict[str, Any] | None = None,
) -> dict[str, Any]:
    filtered_items = filter_items(items, query, fields=search_fields)
    sorted_items = sort_items(filtered_items, sort_by, sort_order, allowed_sort_fields)
    page_items, pagination = paginate(sorted_items, page=page, page_size=page_size)
    return {
        "items": page_items,
        "pagination": pagination,
        "sort_by": sort_by,
        "sort_order": sort_order,
        "query": query,
        "summary": summary or {},
    }


def _sortable_value(value: Any) -> tuple[bool, Any]:
    if value is None:
        return True, ""
    if isinstance(value, str):
        return False, value.lower()
    return False, value
