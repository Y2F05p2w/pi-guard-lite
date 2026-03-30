from __future__ import annotations

from urllib.parse import unquote_plus

from app.common.schemas import AttackTechnique, FeatureVector, SecurityEvent


def map_event_to_mitre(event: SecurityEvent, features: FeatureVector) -> list[AttackTechnique]:
    techniques: list[AttackTechnique] = []
    event_type = event.event_type.lower()
    signature = (event.signature or "").lower()
    url = unquote_plus((event.url or "").lower())

    if event_type in {"system.scan_probe", "suricata.alert"} and (features.unique_dst_ports_5m >= 10 or "scan" in signature):
        techniques.append(
            AttackTechnique(
                technique_id="T1046",
                name="Network Service Scanning",
                tactic="Discovery",
                confidence=0.92,
            )
        )

    if event_type == "system.auth_failure" or "brute" in signature:
        techniques.append(
            AttackTechnique(
                technique_id="T1110",
                name="Brute Force",
                tactic="Credential Access",
                confidence=0.9,
            )
        )

    if event_type in {"suricata.dns"}:
        techniques.append(
            AttackTechnique(
                technique_id="T1071.004",
                name="Application Layer Protocol: DNS",
                tactic="Command and Control",
                confidence=0.72,
            )
        )

    if any(token in url for token in ("union select", "or 1=1", "information_schema", "sleep(", "benchmark(")):
        techniques.append(
            AttackTechnique(
                technique_id="T1190",
                name="Exploit Public-Facing Application",
                tactic="Initial Access",
                confidence=0.88,
            )
        )

    if any(token in url for token in ("cmd=", "powershell", "/bin/sh", "bash -c", "wget http", "curl http")):
        techniques.append(
            AttackTechnique(
                technique_id="T1059",
                name="Command and Scripting Interpreter",
                tactic="Execution",
                confidence=0.84,
            )
        )

    if any(token in url for token in ("shell.php", "cmd.php", "webshell", "c99.php", "r57.php")):
        techniques.append(
            AttackTechnique(
                technique_id="T1505.003",
                name="Server Software Component: Web Shell",
                tactic="Persistence",
                confidence=0.9,
            )
        )

    if event_type == "system.privilege_use":
        techniques.append(
            AttackTechnique(
                technique_id="T1548",
                name="Abuse Elevation Control Mechanism",
                tactic="Privilege Escalation",
                confidence=0.7,
            )
        )

    if event_type == "edr.process" and event.metadata.get("suspicious_parent_child"):
        techniques.append(
            AttackTechnique(
                technique_id="T1059",
                name="Command and Scripting Interpreter",
                tactic="Execution",
                confidence=0.86,
            )
        )

    if event_type == "sample.report" and event.metadata.get("suspicious_sample"):
        techniques.append(
            AttackTechnique(
                technique_id="T1204",
                name="User Execution",
                tactic="Execution",
                confidence=0.62,
            )
        )

    unique: dict[str, AttackTechnique] = {}
    for item in techniques:
        unique.setdefault(item.technique_id, item)
    return list(unique.values())
