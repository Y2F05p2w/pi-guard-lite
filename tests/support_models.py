from __future__ import annotations


class MockAnomalyModel:
    def score_samples(self, vectors: list[list[float]]) -> list[float]:
        scores = []
        for vector in vectors:
            base = sum(vector[:5]) / max(len(vector[:5]), 1)
            scores.append(-2.0 if base > 5 else 2.0)
        return scores


class MockClassifierModel:
    def predict_proba(self, vectors: list[list[float]]) -> list[list[float]]:
        results = []
        for vector in vectors:
            risk = min(0.95, max(0.05, (sum(vector[:6]) / 100.0)))
            results.append([1 - risk, risk])
        return results
