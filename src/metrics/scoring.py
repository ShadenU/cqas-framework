"""Scoring engine — generates composite quality scores and daily scorecards."""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from src.utils.logger import get_logger

logger = get_logger(__name__)

# Weight configuration for composite quality score
SCORE_WEIGHTS = {
    "dar": 0.35,
    "fpr_inverted": 0.25,   # (100 - FPR)
    "sla_compliance": 0.20,
    "escalation_accuracy": 0.10,
    "ept_coverage": 0.10,
}

GRADE_THRESHOLDS = [
    (90, "A"),
    (80, "B"),
    (70, "C"),
    (60, "D"),
    (0,  "F"),
]


class QualityScore:
    """Represents the computed quality score for a measurement period."""

    def __init__(
        self,
        composite_score: float,
        grade: str,
        component_scores: Dict[str, float],
        period_start: Optional[str] = None,
        period_end: Optional[str] = None,
    ) -> None:
        self.composite_score = composite_score
        self.grade = grade
        self.component_scores = component_scores
        self.period_start = period_start
        self.period_end = period_end
        self.generated_at = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "composite_score": round(self.composite_score, 2),
            "grade": self.grade,
            "component_scores": {k: round(v, 2) for k, v in self.component_scores.items()},
            "period_start": self.period_start,
            "period_end": self.period_end,
            "generated_at": self.generated_at,
        }


class ScoringEngine:
    """Generates composite quality scores from individual metric components.

    Args:
        weights: Optional custom weight dict overriding SCORE_WEIGHTS.
    """

    def __init__(self, weights: Optional[Dict[str, float]] = None) -> None:
        self.weights = weights or SCORE_WEIGHTS
        self._score_history: List[QualityScore] = []

    def compute_score(
        self,
        dar: float,
        fpr: float,
        sla_compliance: float,
        escalation_accuracy: float,
        ept_coverage: float = 100.0,
        period_start: Optional[str] = None,
        period_end: Optional[str] = None,
    ) -> QualityScore:
        """Compute a composite quality score.

        Args:
            dar: Detection Accuracy Rate (0–100).
            fpr: False Positive Rate (0–100, lower is better).
            sla_compliance: SLA compliance rate (0–100).
            escalation_accuracy: Escalation accuracy (0–100).
            ept_coverage: EPT detection coverage (0–100).
            period_start: ISO 8601 period start timestamp.
            period_end: ISO 8601 period end timestamp.

        Returns:
            QualityScore object.
        """
        fpr_inverted = max(0.0, 100.0 - fpr)

        components = {
            "dar": dar,
            "fpr_inverted": fpr_inverted,
            "sla_compliance": sla_compliance,
            "escalation_accuracy": escalation_accuracy,
            "ept_coverage": ept_coverage,
        }

        composite = sum(
            self.weights.get(key, 0) * value
            for key, value in components.items()
        )
        composite = min(100.0, max(0.0, composite))
        grade = self._compute_grade(composite)

        score = QualityScore(
            composite_score=composite,
            grade=grade,
            component_scores=components,
            period_start=period_start,
            period_end=period_end,
        )
        self._score_history.append(score)
        logger.info(
            f"Quality score computed: {composite:.1f} ({grade}) — "
            f"DAR={dar:.1f}% FPR={fpr:.1f}% SLA={sla_compliance:.1f}%"
        )
        return score

    def score_from_metrics_report(
        self,
        metrics_report: Dict[str, Any],
        ept_coverage: float = 100.0,
    ) -> QualityScore:
        """Compute score from a PerformanceMetrics.full_report() dict.

        Args:
            metrics_report: Output of PerformanceMetrics.full_report().
            ept_coverage: EPT coverage percentage.

        Returns:
            QualityScore object.
        """
        return self.compute_score(
            dar=metrics_report.get("dar_percent", 0.0),
            fpr=metrics_report.get("fpr_percent", 0.0),
            sla_compliance=metrics_report.get("sla_compliance_percent", 100.0),
            escalation_accuracy=metrics_report.get("escalation_accuracy_percent", 100.0),
            ept_coverage=ept_coverage,
            period_start=metrics_report.get("period_start"),
            period_end=metrics_report.get("period_end"),
        )

    def get_score_history(self) -> List[QualityScore]:
        return list(self._score_history)

    def trend_summary(self) -> Dict[str, Any]:
        """Summarize score trends over the score history."""
        if not self._score_history:
            return {"message": "No score history available"}
        scores = [s.composite_score for s in self._score_history]
        latest = self._score_history[-1]
        return {
            "latest_score": round(latest.composite_score, 2),
            "latest_grade": latest.grade,
            "average_score": round(sum(scores) / len(scores), 2),
            "min_score": round(min(scores), 2),
            "max_score": round(max(scores), 2),
            "total_periods": len(scores),
            "trend": "improving" if len(scores) >= 2 and scores[-1] > scores[-2] else
                     "declining" if len(scores) >= 2 and scores[-1] < scores[-2] else "stable",
        }

    @staticmethod
    def _compute_grade(score: float) -> str:
        for threshold, grade in GRADE_THRESHOLDS:
            if score >= threshold:
                return grade
        return "F"
