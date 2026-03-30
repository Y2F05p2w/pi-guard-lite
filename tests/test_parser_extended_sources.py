from __future__ import annotations

import unittest

from app.common.schemas import RawInputEvent
from app.parser.system_parser import parse_text_log


class ParserExtendedSourcesTestCase(unittest.TestCase):
    def test_parse_edr_sysmon(self) -> None:
        raw = RawInputEvent(
            source="edr.sysmon",
            payload={
                "message": '{"HostIp":"192.168.1.20","Image":"C:\\\\Windows\\\\System32\\\\cmd.exe","CommandLine":"cmd.exe /c whoami","ParentImage":"C:\\\\inetpub\\\\w3wp.exe","User":"IIS APPPOOL\\\\DefaultAppPool"}'
            },
        )
        event = parse_text_log(raw)
        self.assertEqual(event.event_type, "edr.process")
        self.assertEqual(event.signature, "C:\\Windows\\System32\\cmd.exe")
        self.assertEqual(event.metadata["parent_process_name"], "C:\\inetpub\\w3wp.exe")

    def test_parse_sample_sandbox(self) -> None:
        raw = RawInputEvent(
            source="sample.sandbox",
            payload={
                "message": '{"fileName":"dropper.exe","Entropy":7.9,"verdict":"malicious","yaraHits":["Suspicious_Exe"]}'
            },
        )
        event = parse_text_log(raw)
        self.assertEqual(event.event_type, "sample.report")
        self.assertEqual(event.metadata["sandbox_verdict"], "malicious")
        self.assertEqual(event.metadata["yara_hits"], ["Suspicious_Exe"])


if __name__ == "__main__":
    unittest.main()
