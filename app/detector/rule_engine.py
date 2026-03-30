from __future__ import annotations

from functools import lru_cache

import yaml

from app.common.config import PROJECT_ROOT
from app.common.schemas import FeatureVector, RuleMatch, SecurityEvent


RULES_FILE = PROJECT_ROOT / "config" / "rules.yaml"


@lru_cache(maxsize=1)
def load_rule_config() -> dict:
    if not RULES_FILE.exists():
        return {}
    with RULES_FILE.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


class RuleEngine:
    def __init__(self) -> None:
        self.config = load_rule_config()

    def evaluate(self, event: SecurityEvent, features: FeatureVector) -> list[RuleMatch]:
        matches = [
            self._detect_whitelist_bypass(features),
            self._detect_port_scan(event, features),
            self._detect_ssh_bruteforce(event, features),
            self._detect_http_flood(event, features),
            self._detect_suspicious_dns(event, features),
        ]
        return [match for match in matches if match.matched]

    def _detect_whitelist_bypass(self, features: FeatureVector) -> RuleMatch:
        if features.is_whitelisted:
            return RuleMatch(
                rule_id="whitelist",
                name="白名单命中",
                severity=0,
                score=-40,
                matched=True,
                reason="源 IP 或域名命中白名单，后续风险评分将被降低。",
            )
        return self._no_match("whitelist")

    def _detect_port_scan(self, event: SecurityEvent, features: FeatureVector) -> RuleMatch:
        threshold = int(self.config.get("scan_unique_ports_threshold", 10))
        signature = (event.signature or "").lower()
        if "scan" in signature or features.unique_dst_ports_5m >= threshold:
            return RuleMatch(
                rule_id="port_scan",
                name="端口扫描",
                severity=3,
                score=35,
                matched=True,
                reason=f"5 分钟内目标端口离散度为 {features.unique_dst_ports_5m}，疑似扫描行为。",
            )
        return self._no_match("port_scan")

    def _detect_ssh_bruteforce(self, event: SecurityEvent, features: FeatureVector) -> RuleMatch:
        threshold = int(self.config.get("ssh_bruteforce_failures_threshold", 5))
        signature = (event.signature or "").lower()
        if (event.dst_port == 22 and ("brute" in signature or "ssh" in signature)) or features.login_failures_5m >= threshold:
            return RuleMatch(
                rule_id="ssh_bruteforce",
                name="SSH 爆破",
                severity=3,
                score=40,
                matched=True,
                reason=f"5 分钟内认证失败 {features.login_failures_5m} 次，或命中 SSH 爆破特征。",
            )
        return self._no_match("ssh_bruteforce")

    def _detect_http_flood(self, event: SecurityEvent, features: FeatureVector) -> RuleMatch:
        threshold = int(self.config.get("http_request_rate_threshold", 20))
        if event.url and features.request_count_1m >= threshold:
            return RuleMatch(
                rule_id="http_flood",
                name="HTTP 高频访问",
                severity=2,
                score=25,
                matched=True,
                reason=f"1 分钟内同源请求 {features.request_count_1m} 次，超过阈值 {threshold}。",
            )
        return self._no_match("http_flood")

    def _detect_suspicious_dns(self, event: SecurityEvent, features: FeatureVector) -> RuleMatch:
        suspicious_tlds = set(self.config.get("suspicious_tlds", ["top", "xyz", "click"]))
        if not event.domain:
            return self._no_match("suspicious_dns")
        tld = event.domain.rsplit(".", 1)[-1].lower() if "." in event.domain else ""
        if features.dns_query_length >= int(self.config.get("long_dns_query_threshold", 45)) or tld in suspicious_tlds:
            return RuleMatch(
                rule_id="suspicious_dns",
                name="可疑 DNS",
                severity=2,
                score=20,
                matched=True,
                reason=f"DNS 查询域名 {event.domain} 长度异常或命中高风险后缀。",
            )
        return self._no_match("suspicious_dns")

    @staticmethod
    def _no_match(rule_id: str) -> RuleMatch:
        return RuleMatch(
            rule_id=rule_id,
            name=rule_id,
            severity=0,
            score=0,
            matched=False,
            reason="not matched",
        )
