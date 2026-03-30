from __future__ import annotations

from urllib.parse import unquote_plus

from app.common.schemas import (
    AdvancedFinding,
    AnalysisResult,
    AttackGraphEdge,
    AttackGraphNode,
    FeatureVector,
    MLInferenceResult,
    RuleMatch,
    SecurityEvent,
)
from app.detector.mitre_mapper import map_event_to_mitre


class AdvancedAnalyzer:
    def analyze(
        self,
        event: SecurityEvent,
        features: FeatureVector,
        matches: list[RuleMatch],
        ml_result: MLInferenceResult,
    ) -> AnalysisResult:
        findings: list[AdvancedFinding] = []
        url = unquote_plus((event.url or "").lower())
        message = str(event.metadata.get("message", "")).lower()
        command = str(event.metadata.get("command", "") or event.metadata.get("command_line", "")).lower()

        findings.extend(self._detect_sqli(event, url))
        findings.extend(self._detect_rce(event, url, command, message))
        findings.extend(self._detect_webshell(event, url))
        findings.extend(self._detect_lateral_movement(event, features))
        findings.extend(self._detect_edr_process(event, command))
        findings.extend(self._detect_sample(event))

        techniques = map_event_to_mitre(event, features)
        graph_nodes, graph_edges = self._build_graph(event, techniques, findings)
        impacted_assets = [item for item in [event.dst_ip, event.sensor] if item]
        summary = self._build_summary(event, findings, techniques, impacted_assets, matches, ml_result)
        return AnalysisResult(
            findings=findings,
            techniques=techniques,
            graph_nodes=graph_nodes,
            graph_edges=graph_edges,
            impacted_assets=impacted_assets,
            summary=summary,
        )

    def _detect_sqli(self, event: SecurityEvent, url: str) -> list[AdvancedFinding]:
        tokens = ("union select", "or 1=1", "information_schema", "sleep(", "benchmark(")
        if event.url and any(token in url for token in tokens):
            return [
                AdvancedFinding(
                    finding_id="sqli",
                    name="SQL 注入迹象",
                    category="sqli",
                    severity=3,
                    confidence=0.88,
                    description="URL 中包含典型 SQL 注入关键字。",
                    metadata={"url": event.url},
                )
            ]
        return []

    def _detect_rce(self, event: SecurityEvent, url: str, command: str, message: str) -> list[AdvancedFinding]:
        tokens = ("cmd=", "powershell", "/bin/sh", "bash -c", "wget http", "curl http", "whoami", "cmd.exe")
        if any(token in url or token in command or token in message for token in tokens):
            return [
                AdvancedFinding(
                    finding_id="rce",
                    name="RCE/命令执行迹象",
                    category="rce",
                    severity=3,
                    confidence=0.84,
                    description="检测到命令执行或远程代码执行特征。",
                    metadata={"url": event.url, "command": command},
                )
            ]
        return []

    def _detect_webshell(self, event: SecurityEvent, url: str) -> list[AdvancedFinding]:
        tokens = ("shell.php", "cmd.php", "webshell", "c99.php", "r57.php", "eval-stdin.php")
        if event.url and any(token in url for token in tokens):
            return [
                AdvancedFinding(
                    finding_id="webshell",
                    name="疑似 WebShell",
                    category="webshell",
                    severity=3,
                    confidence=0.9,
                    description="URL 中包含典型 WebShell 文件名或执行参数。",
                    metadata={"url": event.url},
                )
            ]
        return []

    def _detect_lateral_movement(self, event: SecurityEvent, features: FeatureVector) -> list[AdvancedFinding]:
        lateral_ports = {22, 135, 139, 445, 3389, 5985, 5986}
        if event.dst_port in lateral_ports and (features.unique_dst_ports_5m >= 5 or event.event_type == "system.auth_success"):
            return [
                AdvancedFinding(
                    finding_id="lateral_movement",
                    name="横向移动迹象",
                    category="lateral_movement",
                    severity=2,
                    confidence=0.74,
                    description="内部高价值端口被多目标探测或出现新的远程登录行为。",
                    metadata={"dst_port": event.dst_port, "src_ip": event.src_ip, "dst_ip": event.dst_ip},
                )
            ]
        return []

    def _detect_edr_process(self, event: SecurityEvent, command: str) -> list[AdvancedFinding]:
        if event.source != "edr.process":
            return []
        suspicious_parent = str(event.metadata.get("parent_process_name", "")).lower()
        suspicious = suspicious_parent in {"w3wp.exe", "apache2", "nginx", "php-fpm"} and any(
            token in command for token in ("cmd", "powershell", "/bin/sh", "bash")
        )
        if suspicious:
            event.metadata["suspicious_parent_child"] = True
            return [
                AdvancedFinding(
                    finding_id="edr_process_chain",
                    name="EDR 可疑进程树",
                    category="edr",
                    severity=3,
                    confidence=0.86,
                    description="Web 服务父进程衍生 shell/命令解释器，疑似 RCE 或 WebShell。",
                    metadata=event.metadata,
                )
            ]
        return []

    def _detect_sample(self, event: SecurityEvent) -> list[AdvancedFinding]:
        if event.source != "sample.report":
            if event.source != "sample.sandbox":
                return []
        entropy = float(event.metadata.get("entropy", 0.0) or 0.0)
        file_name = str(event.metadata.get("file_name", "")).lower()
        yara_hits = event.metadata.get("yara_hits") or []
        sandbox_verdict = str(event.metadata.get("sandbox_verdict", "")).lower()
        suspicious = (
            entropy >= 7.0
            or file_name.endswith((".ps1", ".js", ".vbs", ".exe", ".dll"))
            or bool(yara_hits)
            or sandbox_verdict in {"malicious", "high_risk", "suspicious"}
        )
        if suspicious:
            event.metadata["suspicious_sample"] = True
            return [
                AdvancedFinding(
                    finding_id="sample_suspicious",
                    name="疑似恶意样本",
                    category="sample",
                    severity=2,
                    confidence=0.68,
                    description="样本熵值较高、YARA 命中或沙箱结论异常，建议进一步静态/动态分析。",
                    metadata=event.metadata,
                )
            ]
            return []
        return []

    def _build_graph(
        self,
        event: SecurityEvent,
        techniques: list,
        findings: list[AdvancedFinding],
    ) -> tuple[list[AttackGraphNode], list[AttackGraphEdge]]:
        nodes: list[AttackGraphNode] = []
        edges: list[AttackGraphEdge] = []
        seen = set()

        def add_node(node: AttackGraphNode) -> None:
            if node.node_key in seen:
                return
            seen.add(node.node_key)
            nodes.append(node)

        if event.src_ip:
            add_node(AttackGraphNode(node_key=f"ip:{event.src_ip}", node_type="ip", label=event.src_ip))
        if event.dst_ip:
            add_node(AttackGraphNode(node_key=f"asset:{event.dst_ip}", node_type="asset", label=event.dst_ip))
        for finding in findings:
            add_node(AttackGraphNode(node_key=f"finding:{finding.finding_id}", node_type="finding", label=finding.name))
        for technique in techniques:
            add_node(
                AttackGraphNode(
                    node_key=f"technique:{technique.technique_id}",
                    node_type="mitre",
                    label=f"{technique.technique_id} {technique.name}",
                )
            )

        if event.src_ip and event.dst_ip:
            edges.append(AttackGraphEdge(src_key=f"ip:{event.src_ip}", dst_key=f"asset:{event.dst_ip}", relation="targets"))
        for finding in findings:
            if event.dst_ip:
                edges.append(
                    AttackGraphEdge(
                        src_key=f"asset:{event.dst_ip}",
                        dst_key=f"finding:{finding.finding_id}",
                        relation="has_finding",
                    )
                )
        for technique in techniques:
            if event.dst_ip:
                edges.append(
                    AttackGraphEdge(
                        src_key=f"asset:{event.dst_ip}",
                        dst_key=f"technique:{technique.technique_id}",
                        relation="mapped_to",
                    )
                )
        return nodes, edges

    def _build_summary(
        self,
        event: SecurityEvent,
        findings: list[AdvancedFinding],
        techniques: list,
        impacted_assets: list[str],
        matches: list[RuleMatch],
        ml_result: MLInferenceResult,
    ) -> str:
        parts = [f"event={event.event_type}"]
        if findings:
            parts.append("findings=" + ",".join(item.name for item in findings))
        if techniques:
            parts.append("mitre=" + ",".join(item.technique_id for item in techniques))
        if impacted_assets:
            parts.append("assets=" + ",".join(impacted_assets))
        if matches:
            parts.append("rules=" + ",".join(item.rule_id for item in matches))
        if ml_result.model_loaded:
            parts.append(
                f"ml=anomaly:{ml_result.anomaly_score}/classifier:{ml_result.classifier_score}"
            )
        return " | ".join(parts)
