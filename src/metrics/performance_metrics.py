"""Performance metrics — computes DAR, FPR, MTTR, and other SOC quality KPIs."""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from src.utils.logger import get_logger

logger = get_logger(__name__)


class PerformanceMetrics:
    """Calculates quality metrics for security operations.

    Accepts raw alert data and computes:
    - DAR (Detection Accuracy Rate)
    - FPR (False Positive Rate)
    - MTTR (Mean Time to Respond)
    - MTTD (Mean Time to Detect)
    - Escalation Accuracy
    - SLA Compliance Rate

    Args:
        sla_thresholds: Dict mapping severity to SLA in minutes.
    """

    DEFAULT_SLA = {
        "critical": 15,
        "high": 60,
        "medium": 240,
        "low": 1440,
    }

    def __init__(self, sla_thresholds: Optional[Dict[str, int]] = None) -> None:
        self.sla_thresholds = sla_thresholds or self.DEFAULT_SLA

    # ------------------------------------------------------------------ #
    # Core metric calculations                                             #
    # ------------------------------------------------------------------ #

    def calculate_dar(
        self, true_positives: int, false_negatives: int
    ) -> float:
        """Calculate Detection Accuracy Rate.

        Args:
            true_positives: Number of threats correctly detected.
            false_negatives: Number of threats NOT detected.

        Returns:
            DAR as percentage (0.0 – 100.0).
        """
        total = true_positives + false_negatives
        if total == 0:
            return 100.0
        return (true_positives / total) * 100.0

    def calculate_fpr(
        self, false_positives: int, total_alerts: int
    ) -> float:
        """Calculate False Positive Rate.

        Args:
            false_positives: Number of false positive alerts.
            total_alerts: Total number of alerts generated.

        Returns:
            FPR as percentage (0.0 – 100.0).
        """
        if total_alerts == 0:
            return 0.0
        return (false_positives / total_alerts) * 100.0

    def calculate_mttr(
        self, alert_resolution_pairs: List[Tuple[datetime, datetime]]
    ) -> float:
        """Calculate Mean Time to Respond in minutes.

        Args:
            alert_resolution_pairs: List of (created_at, resolved_at) tuples.

        Returns:
            MTTR in minutes. 0.0 if no pairs provided.
        """
        if not alert_resolution_pairs:
            return 0.0
        total_minutes = sum(
            (resolved - created).total_seconds() / 60.0
            for created, resolved in alert_resolution_pairs
            if resolved > created
        )
        return total_minutes / len(alert_resolution_pairs)

    def calculate_mttd(
        self, event_detection_pairs: List[Tuple[datetime, datetime]]
    ) -> float:
        """Calculate Mean Time to Detect in minutes.

        Args:
            event_detection_pairs: List of (event_time, detection_time) tuples.

        Returns:
            MTTD in minutes.
        """
        if not event_detection_pairs:
            return 0.0
        total_minutes = sum(
            (detected - event).total_seconds() / 60.0
            for event, detected in event_detection_pairs
            if detected >= event
        )
        return total_minutes / len(event_detection_pairs)

    def calculate_sla_compliance(
        self, alerts: List[Dict[str, Any]]
    ) -> float:
        """Calculate the percentage of alerts resolved within SLA.

        Args:
            alerts: List of alert dicts with keys:
                    - severity (str)
                    - created_at (datetime)
                    - resolved_at (datetime or None)

        Returns:
            SLA compliance rate as percentage.
        """
        if not alerts:
            return 100.0

        compliant = 0
        evaluated = 0
        for alert in alerts:
            resolved_at = alert.get("resolved_at")
            if resolved_at is None:
                evaluated += 1  # unresolved = SLA breach
                continue
            created_at = alert["created_at"]
            severity = alert.get("severity", "low")
            sla_minutes = self.sla_thresholds.get(severity, 1440)
            elapsed_minutes = (resolved_at - created_at).total_seconds() / 60.0
            evaluated += 1
            if elapsed_minutes <= sla_minutes:
                compliant += 1

        return (compliant / evaluated) * 100.0 if evaluated > 0 else 100.0

    def calculate_escalation_accuracy(
        self, alerts: List[Dict[str, Any]]
    ) -> float:
        """Calculate the percentage of correctly escalated alerts.

        Args:
            alerts: List of alert dicts with:
                    - computed_severity (str): severity assigned by SeverityEngine
                    - actual_severity (str): severity confirmed by analyst

        Returns:
            Escalation accuracy as percentage.
        """
        if not alerts:
            return 100.0
        correct = sum(
            1 for a in alerts
            if a.get("computed_severity") == a.get("actual_severity")
        )
        return (correct / len(alerts)) * 100.0

    def full_report(
        self,
        iqc_results: Optional[List[Any]] = None,
        alerts: Optional[List[Dict]] = None,
        event_detection_pairs: Optional[List[Tuple[datetime, datetime]]] = None,
    ) -> Dict[str, Any]:
        """Generate a comprehensive metrics report.

        Args:
            iqc_results: List of IQCResult objects.
            alerts: List of alert dicts.
            event_detection_pairs: For MTTD calculation.

        Returns:
            Metrics report dict.
        """
        iqc_results = iqc_results or []
        alerts = alerts or []
        event_detection_pairs = event_detection_pairs or []

        tp = sum(1 for r in iqc_results if r.detected)
        fn = sum(1 for r in iqc_results if not r.detected)
        fp = sum(1 for a in alerts if not a.get("is_true_positive", True))
        total_alerts = len(alerts)

        resolution_pairs = []
        for a in alerts:
            if a.get("created_at") and a.get("resolved_at"):
                resolution_pairs.append((a["created_at"], a["resolved_at"]))

        dar = self.calculate_dar(tp, fn)
        fpr = self.calculate_fpr(fp, total_alerts)
        mttr = self.calculate_mttr(resolution_pairs)
        mttd = self.calculate_mttd(event_detection_pairs)
        sla = self.calculate_sla_compliance(alerts)
        esc_acc = self.calculate_escalation_accuracy(alerts)

        report = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "dar_percent": round(dar, 2),
            "fpr_percent": round(fpr, 2),
            "mttr_minutes": round(mttr, 2),
            "mttd_minutes": round(mttd, 2),
            "sla_compliance_percent": round(sla, 2),
            "escalation_accuracy_percent": round(esc_acc, 2),
            "total_iqc_tests": len(iqc_results),
            "iqc_true_positives": tp,
            "iqc_false_negatives": fn,
            "total_alerts": total_alerts,
            "false_positives": fp,
        }
        logger.info(
            f"Metrics report: DAR={dar:.1f}% FPR={fpr:.1f}% MTTR={mttr:.1f}min"
        )
        return report
