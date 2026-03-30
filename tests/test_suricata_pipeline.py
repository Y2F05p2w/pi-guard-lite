from __future__ import annotations

import unittest
from pathlib import Path

from app.collector.suricata_reader import SuricataFileReader
from app.detector.rule_engine import RuleEngine
from app.features.extractor import FeatureExtractor
from app.parser.suricata_parser import parse_suricata_event
from app.scorer.risk_scoring import RiskScorer


class SuricataPipelineTestCase(unittest.TestCase):
    def test_parse_and_score_sample_file(self) -> None:
        sample = Path(__file__).parent / "samples" / "suricata_eve.jsonl"
        reader = SuricataFileReader(sample)
        extractor = FeatureExtractor()
        engine = RuleEngine()
        scorer = RiskScorer()

        results = []
        for raw in reader.read_existing():
            event = parse_suricata_event(raw)
            features = extractor.extract(event)
            matches = engine.evaluate(event, features)
            risk = scorer.score(event, features, matches)
            results.append((event, features, matches, risk))

        self.assertEqual(len(results), 5)
        self.assertTrue(any(item[3].risk_score > 0 for item in results))
        self.assertTrue(any(item[2] for item in results))


if __name__ == "__main__":
    unittest.main()
