from __future__ import annotations

import math


def paginate(
    items: list[dict],
    *,
    page: int,
    page_size: int,
) -> tuple[list[dict], dict]:
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


def sort_items(items: list[dict], sort_by: str, sort_order: str, allowed: set[str]) -> list[dict]:
    if sort_by not in allowed:
        return items
    reverse = sort_order == "desc"
    return sorted(items, key=lambda item: (item.get(sort_by) is None, item.get(sort_by)), reverse=reverse)
