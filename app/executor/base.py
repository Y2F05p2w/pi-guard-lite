from __future__ import annotations

from abc import ABC, abstractmethod

from app.common.schemas import ExecutionResult


class BaseExecutor(ABC):
    @abstractmethod
    def block_ip(self, ip: str, ttl_seconds: int) -> ExecutionResult: ...

    @abstractmethod
    def unblock_ip(self, ip: str) -> ExecutionResult: ...

    @abstractmethod
    def limit_ip(self, ip: str, ttl_seconds: int) -> ExecutionResult: ...

    @abstractmethod
    def check_connection(self) -> ExecutionResult: ...
