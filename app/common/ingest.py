from __future__ import annotations

from collections.abc import Iterable

from fastapi import HTTPException, Request

from app.common.config import get_settings
from app.common.schemas import IngestBatchItem, RawInputEvent
from app.policy.pipeline import PipelineProcessor


def process_ingest_event(
    *,
    source: str,
    payload: dict,
    raw_path: str | None = None,
    apply_policy: bool = True,
    run_probe: bool = True,
) -> dict:
    processor = PipelineProcessor()
    raw_event = RawInputEvent(source=source, payload=payload, raw_path=raw_path)
    return processor.process_raw_event(raw_event, apply_policy=apply_policy, run_probe=run_probe)


def process_ingest_batch(
    *,
    events: Iterable[IngestBatchItem],
    apply_policy: bool = True,
    run_probe: bool = True,
) -> dict:
    processor = PipelineProcessor()
    results = []
    for item in events:
        raw_event = RawInputEvent(source=item.source, payload=item.payload, raw_path=item.raw_path)
        results.append(processor.process_raw_event(raw_event, apply_policy=apply_policy, run_probe=run_probe))
    return {
        "processed": len(results),
        "event_ids": [item["event_id"] for item in results],
        "results": results,
    }


def ensure_ingest_allowed(request: Request) -> None:
    token = str(get_settings().get("ingest", {}).get("auth_token", "") or "")
    if not token:
        return
    if request.headers.get("x-pi-guard-token", "") != token:
        raise HTTPException(status_code=401, detail="invalid ingest token")
