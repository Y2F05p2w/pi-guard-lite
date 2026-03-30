from __future__ import annotations

import unittest

from app.common.db import get_connection, init_db
from app.common.event_store import get_analysis_result
from app.common.schemas import RawInputEvent
from app.policy.pipeline import PipelineProcessor
from tests.test_helpers import cleanup_isolated_db, setup_isolated_db


class AdvancedAnalysisTestCase(unittest.TestCase):
    def setUp(self) -> None:
        setup_isolated_db(self.__class__.__name__)
        init_db()
        with get_connection() as conn:
            for table in (
                "event",
                "feature",
                "policy",
                "blocklist",
                "probe_result",
                "audit_log",
                "baseline_profile",
                "analysis_result",
            ):
                conn.execute(f"DELETE FROM {table}")
            conn.commit()

    def tearDown(self) -> None:
        cleanup_isolated_db()

    def test_detects_sqli_and_mitre_mapping(self) -> None:
        raw = RawInputEvent(
            source="nginx.access",
            payload={
                "message": '203.0.113.7 - - [30/Mar/2026:10:05:05 +0800] "GET /item?id=1%20union%20select%20password HTTP/1.1" 500 12 "-" "curl/8.0"'
            },
        )
        result = PipelineProcessor().process_raw_event(raw, apply_policy=False, run_probe=False)
        findings = result["analysis"]["findings"]
        techniques = result["analysis"]["techniques"]
        self.assertTrue(any(item["category"] == "sqli" for item in findings))
        self.assertTrue(any(item["technique_id"] == "T1190" for item in techniques))

    def test_detects_edr_process_chain(self) -> None:
        raw = RawInputEvent(
            source="edr.process",
            payload={
                "message": '{"host_ip":"192.168.1.20","process_name":"cmd.exe","parent_process_name":"w3wp.exe","command_line":"cmd.exe /c whoami","user":"www-data"}'
            },
        )
        result = PipelineProcessor().process_raw_event(raw, apply_policy=False, run_probe=False)
        findings = result["analysis"]["findings"]
        self.assertTrue(any(item["finding_id"] == "edr_process_chain" for item in findings))
        self.assertTrue(any(item["technique_id"] == "T1059" for item in result["analysis"]["techniques"]))

    def test_detects_sample_report_and_stores_graph(self) -> None:
        raw = RawInputEvent(
            source="sample.report",
            payload={
                "message": '{"file_name":"payload.exe","entropy":7.8,"sha256":"deadbeef","severity":2}'
            },
        )
        result = PipelineProcessor().process_raw_event(raw, apply_policy=False, run_probe=False)
        self.assertTrue(any(item["finding_id"] == "sample_suspicious" for item in result["analysis"]["findings"]))
        stored = get_analysis_result(result["event_id"])
        self.assertIsNotNone(stored)
        assert stored is not None
        self.assertIn("graph_json", stored)


if __name__ == "__main__":
    unittest.main()
