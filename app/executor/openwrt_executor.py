from __future__ import annotations

from pathlib import Path

import paramiko

from app.common.schemas import ExecutionResult
from app.executor.base import BaseExecutor


class OpenWrtSSHExecutor(BaseExecutor):
    def __init__(self, config: dict) -> None:
        self.config = config
        self.device_name = config.get("device_name", "openwrt")
        self.dry_run = bool(config.get("dry_run", True))
        self.host = config.get("host")
        self.port = int(config.get("port", 22))
        self.username = config.get("username")
        self.password = config.get("password") or None
        self.key_path = config.get("key_path") or None
        self.block_command = config.get("block_command", "ipset add pi_guard_blacklist {ip} timeout {ttl}")
        self.unblock_command = config.get("unblock_command", "ipset del pi_guard_blacklist {ip}")
        self.limit_command = config.get("limit_command", "echo limit {ip} {ttl}")

    def block_ip(self, ip: str, ttl_seconds: int) -> ExecutionResult:
        command = self.block_command.format(ip=ip, ttl=ttl_seconds)
        return self._run("block_ip", ip, command)

    def unblock_ip(self, ip: str) -> ExecutionResult:
        command = self.unblock_command.format(ip=ip)
        return self._run("unblock_ip", ip, command)

    def limit_ip(self, ip: str, ttl_seconds: int) -> ExecutionResult:
        command = self.limit_command.format(ip=ip, ttl=ttl_seconds)
        return self._run("limit_ip", ip, command)

    def check_connection(self) -> ExecutionResult:
        if self.dry_run:
            return ExecutionResult(
                success=True,
                action="check_connection",
                device=self.device_name,
                simulated=True,
                detail="dry-run enabled",
            )
        try:
            client = self._connect()
            client.close()
            return ExecutionResult(success=True, action="check_connection", device=self.device_name)
        except Exception as exc:
            return ExecutionResult(
                success=False,
                action="check_connection",
                device=self.device_name,
                stderr=str(exc),
                detail="SSH connection failed",
            )

    def _run(self, action: str, target: str, command: str) -> ExecutionResult:
        if self.dry_run:
            return ExecutionResult(
                success=True,
                action=action,
                target=target,
                device=self.device_name,
                simulated=True,
                command=command,
                detail="dry-run enabled, command not executed",
            )
        try:
            client = self._connect()
            _, stdout, stderr = client.exec_command(command)
            out = stdout.read().decode("utf-8", errors="ignore").strip()
            err = stderr.read().decode("utf-8", errors="ignore").strip()
            exit_status = stdout.channel.recv_exit_status()
            client.close()
            return ExecutionResult(
                success=exit_status == 0,
                action=action,
                target=target,
                device=self.device_name,
                simulated=False,
                command=command,
                stdout=out,
                stderr=err,
                detail="command executed",
            )
        except Exception as exc:
            return ExecutionResult(
                success=False,
                action=action,
                target=target,
                device=self.device_name,
                simulated=False,
                command=command,
                stderr=str(exc),
                detail="command execution failed",
            )

    def _connect(self) -> paramiko.SSHClient:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        connect_kwargs = dict(
            hostname=self.host,
            port=self.port,
            username=self.username,
            timeout=5,
            look_for_keys=False,
            allow_agent=False,
        )
        if self.key_path:
            connect_kwargs["key_filename"] = str(Path(self.key_path))
        elif self.password:
            connect_kwargs["password"] = self.password
        client.connect(**connect_kwargs)
        return client
