from __future__ import annotations

import unittest

from app.collector.scan_listener_service import ScanListenerService


class DummyListener:
    def __init__(self, bind_host, report_host, ports, on_event):
        self.bind_host = bind_host
        self.report_host = report_host
        self.ports = ports
        self.on_event = on_event
        self.started = False
        self.stopped = False

    def start(self):
        self.started = True

    def stop(self):
        self.stopped = True


class FailingListener(DummyListener):
    def start(self):
        raise OSError("bind failed")


class DummyProcessor:
    def __init__(self):
        self.calls = []

    def process_raw_event(self, raw, apply_policy=True, run_probe=False):
        self.calls.append((raw, apply_policy, run_probe))
        return {"event_id": 1}


class ScanListenerServiceTestCase(unittest.TestCase):
    def test_start_and_stop_enabled_service(self) -> None:
        processor = DummyProcessor()
        service = ScanListenerService(
            {
                "enabled": True,
                "auto_start_with_web": True,
                "bind_host": "127.0.0.1",
                "report_host": "127.0.0.1",
                "ports": "2201-2202",
            },
            listener_class=DummyListener,
            processor_factory=lambda: processor,
        )
        status = service.start()
        self.assertTrue(status["running"])
        self.assertEqual(status["ports"], [2201, 2202])
        service.stop()
        self.assertFalse(service.running)

    def test_disabled_service_does_not_start(self) -> None:
        service = ScanListenerService({"enabled": False}, listener_class=DummyListener, processor_factory=DummyProcessor)
        status = service.start()
        self.assertFalse(status["running"])

    def test_start_failure_is_captured(self) -> None:
        service = ScanListenerService(
            {"enabled": True, "auto_start_with_web": True, "ports": "2201"},
            listener_class=FailingListener,
            processor_factory=DummyProcessor,
        )
        status = service.start()
        self.assertFalse(status["running"])
        self.assertIn("bind failed", status["last_error"])


if __name__ == "__main__":
    unittest.main()
