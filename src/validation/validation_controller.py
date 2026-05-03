"""ValidationController — orchestrates IQC and EPT validation cycles."""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from src.utils.logger import get_logger

logger = get_logger(__name__)


class ValidationController:
    """Orchestrates IQC and EPT validation cycles.

    Provides a single entry point to run both validation types,
    aggregate results, and compute the overall quality score.

    Args:
        iqc_engine: Initialized IQCEngine instance.
        ept_engine: Initialized EPTEngine instance.
    """

    def __init__(self, iqc_engine: Any, ept_engine: Any) -> None:
        self.iqc_engine = iqc_engine
        self.ept_engine = ept_engine
        self._run_history: List[Dict] = []

    def run_iqc(self) -> Dict[str, Any]:
        """Run the full IQC synthetic IOC injection cycle.

        Returns:
            IQC summary dict with DAR and individual results.
        """
        logger.info("Starting IQC validation cycle")
        self.iqc_engine._results.clear()
        results = self.iqc_engine.run_all()
        summary = self.iqc_engine.summary()
        logger.info(f"IQC complete: DAR={summary['dar_percent']:.1f}%")
        return summary

    def run_ept(self, scenarios: Optional[List[str]] = None) -> Dict[str, Any]:
        """Run EPT attack simulations.

        Args:
            scenarios: Optional list of scenario names to run.
                       If None, runs all available scenarios.

        Returns:
            EPT summary dict with coverage and individual results.
        """
        logger.info("Starting EPT validation cycle")
        self.ept_engine._results.clear()

        if scenarios:
            for scenario in scenarios:
                self.ept_engine.run_scenario(scenario)
        else:
            self.ept_engine.run_all()

        summary = self.ept_engine.summary()
        logger.info(f"EPT complete: coverage={summary['coverage_percent']:.1f}%")
        return summary

    def run_full_validation(self, ept_scenarios: Optional[List[str]] = None) -> Dict[str, Any]:
        """Run both IQC and EPT and generate a combined validation report.

        Args:
            ept_scenarios: Optional list of EPT scenarios to run.

        Returns:
            Combined validation report dict.
        """
        logger.info("Starting full CQAS validation cycle")
        started_at = datetime.now(timezone.utc).isoformat()

        iqc_summary = self.run_iqc()
        ept_summary = self.run_ept(ept_scenarios)

        quality_score = self._compute_quality_score(
            dar=iqc_summary["dar_percent"],
            ept_coverage=ept_summary["coverage_percent"],
        )

        report = {
            "started_at": started_at,
            "completed_at": datetime.now(timezone.utc).isoformat(),
            "iqc": iqc_summary,
            "ept": ept_summary,
            "quality_score": quality_score,
            "grade": self._grade(quality_score),
        }
        self._run_history.append(report)
        logger.info(f"Full validation complete: quality_score={quality_score:.1f} grade={report['grade']}")
        return report

    def get_run_history(self) -> List[Dict]:
        """Return all historical validation run reports."""
        return list(self._run_history)

    @staticmethod
    def _compute_quality_score(dar: float, ept_coverage: float) -> float:
        """Weighted quality score from DAR and EPT coverage.

        Weights: DAR=60%, EPT coverage=40%
        """
        return (dar * 0.60) + (ept_coverage * 0.40)

    @staticmethod
    def _grade(score: float) -> str:
        if score >= 90:
            return "A"
        if score >= 80:
            return "B"
        if score >= 70:
            return "C"
        if score >= 60:
            return "D"
        return "F"
