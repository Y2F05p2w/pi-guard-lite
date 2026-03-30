from __future__ import annotations


class DemoAnomalyModel:
    def score_samples(self, vectors: list[list[float]]) -> list[float]:
        scores = []
        for vector in vectors:
            base = sum(vector[:5]) / max(len(vector[:5]), 1)
            scores.append(-2.5 if base > 6 else 1.5)
        return scores


class DemoClassifierModel:
    def predict_proba(self, vectors: list[list[float]]) -> list[list[float]]:
        results = []
        for vector in vectors:
            risk = min(0.97, max(0.03, (sum(vector[:8]) / 120.0)))
            results.append([1 - risk, risk])
        return results
