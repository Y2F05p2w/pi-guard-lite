from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, Field


class HealthResponse(BaseModel):
    status: str
    app: str


class StatsResponse(BaseModel):
    events: int
    policies: int
    blocked: int


class RawInputEvent(BaseModel):
    source: str
    payload: dict[str, Any]
    raw_path: str | None = None
    received_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class SecurityEvent(BaseModel):
    ts: datetime
    source: str
    event_type: str
    src_ip: str | None = None
    dst_ip: str | None = None
    src_port: int | None = None
    dst_port: int | None = None
    protocol: str | None = None
    service: str | None = None
    severity: int = 0
    username: str | None = None
    signature: str | None = None
    category: str | None = None
    action: str | None = None
    domain: str | None = None
    url: str | None = None
    http_method: str | None = None
    http_status: int | None = None
    tls_sni: str | None = None
    sensor: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    raw_path: str | None = None


class FeatureVector(BaseModel):
    event_type: str
    src_ip: str | None = None
    request_count_1m: int = 0
    same_event_count_10m: int = 0
    unique_dst_ports_5m: int = 0
    login_failures_5m: int = 0
    http_error_ratio_5m: float = 0.0
    dns_query_length: int = 0
    off_hours: bool = False
    hits_blacklist: bool = False
    is_whitelisted: bool = False
    asset_importance: int = 1
    signature_severity: int = 0


class RuleMatch(BaseModel):
    rule_id: str
    name: str
    severity: int
    score: float
    matched: bool
    reason: str


class RiskScoreResult(BaseModel):
    anomaly_score: float = 0.0
    risk_score: float = 0.0
    risk_level: str = "low"
    reasons: list[str] = Field(default_factory=list)


class PolicyDecision(BaseModel):
    action: str
    target: str | None = None
    ttl_seconds: int = 0
    status: str = "pending"
    reason: str = ""


class ExecutionResult(BaseModel):
    success: bool
    action: str
    target: str | None = None
    device: str = "unknown"
    simulated: bool = False
    command: str | None = None
    stdout: str | None = None
    stderr: str | None = None
    detail: str | None = None


class ProbeTarget(BaseModel):
    type: str
    target: str
    timeout_seconds: int = 3
    required: bool = True


class ProbeExecutionResult(BaseModel):
    target: str
    probe_type: str
    success: bool
    required: bool = True
    latency_ms: int | None = None
    detail: str | None = None


class ManualBlockRequest(BaseModel):
    ip: str
    ttl_seconds: int = 1800
    reason: str = "manual block"


class ManualUnblockRequest(BaseModel):
    ip: str
    reason: str = "manual unblock"
