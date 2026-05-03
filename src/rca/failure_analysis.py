"""Failure analysis — tracks and aggregates detection failure patterns over time."""

from collections import Counter
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from src.utils.logger import get_logger

logger = get_logger(__name__)


class FailureTrend:
    """Represents a systemic failure pattern identified across multiple findings."""

    def __init__(
        self,
        category: str,
        count: int,
        affected_rules: List[str],
        first_seen: str,
        last_seen: str,
    ) -> None:
        self.category = category
        self.count = count
        self.affected_rules = affected_rules
        self.first_seen = first_seen
        self.last_seen = last_seen

    def to_dict(self) -> Dict[str, Any]:
        return {
            "category": self.category,
            "count": self.count,
            "affected_rules": list(set(self.affected_rules)),
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
        }


class FailureAnalysis:
    """Aggregates RCA findings and identifies systemic failure patterns.

    Tracks findings over time and surfaces recurring root cause categories
    that indicate systemic weaknesses in the detection pipeline.

    Args:
        recurrence_threshold: Number of occurrences before a category is
                              classified as a systemic trend (default: 3).
    """

    def __init__(self, recurrence_threshold: int = 3) -> None:
        self.recurrence_threshold = recurrence_threshold
        self._findings: List[Any] = []  # List of RCAFinding objects

    def add_findings(self, findings: List[Any]) -> None:
        """Add RCA findings from a validation cycle.

        Args:
            findings: List of RCAFinding objects.
        """
        self._findings.extend(findings)
        logger.info(f"FailureAnalysis: added {len(findings)} findings ({len(self._findings)} total)")

    def identify_trends(self) -> List[FailureTrend]:
        """Identify recurring root cause categories.

        Returns:
            List of FailureTrend objects for categories meeting the threshold.
        """
        category_groups: Dict[str, List[Any]] = {}
        for finding in self._findings:
            cat = finding.root_cause_category
            if cat not in category_groups:
                category_groups[cat] = []
            category_groups[cat].append(finding)

        trends = []
        for category, group in category_groups.items():
            if len(group) >= self.recurrence_threshold:
                rules = [r for f in group for r in f.related_rules]
                timestamps = sorted(f.created_at for f in group)
                trends.append(
                    FailureTrend(
                        category=category,
                        count=len(group),
                        affected_rules=rules,
                        first_seen=timestamps[0],
                        last_seen=timestamps[-1],
                    )
                )

        trends.sort(key=lambda t: t.count, reverse=True)
        return trends

    def top_failing_rules(self, n: int = 10) -> List[Dict[str, Any]]:
        """Return the rules with the most associated RCA findings.

        Args:
            n: Number of top entries to return.

        Returns:
            List of dicts with rule_id and failure_count.
        """
        rule_counter: Counter = Counter()
        for finding in self._findings:
            for rule_id in finding.related_rules:
                rule_counter[rule_id] += 1
        return [
            {"rule_id": rule_id, "failure_count": count}
            for rule_id, count in rule_counter.most_common(n)
        ]

    def report(self) -> Dict[str, Any]:
        """Generate a comprehensive failure analysis report.

        Returns:
            Dict with summary stats, trends, and top failing rules.
        """
        category_counter: Counter = Counter(f.root_cause_category for f in self._findings)
        priority_counter: Counter = Counter(f.priority for f in self._findings)
        trends = self.identify_trends()

        return {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "total_findings": len(self._findings),
            "findings_by_category": dict(category_counter),
            "findings_by_priority": dict(priority_counter),
            "systemic_trends": [t.to_dict() for t in trends],
            "top_failing_rules": self.top_failing_rules(),
            "recommendations": self._generate_recommendations(trends),
        }

    def _generate_recommendations(self, trends: List[FailureTrend]) -> List[str]:
        recs = []
        for trend in trends:
            if trend.category == "missing_rule":
                recs.append(
                    f"Create detection rules for {len(set(trend.affected_rules))} "
                    f"undetected techniques (recurred {trend.count}x)"
                )
            elif trend.category == "threshold_too_high":
                recs.append(
                    f"Review detection thresholds — {trend.count} threshold failures detected"
                )
            elif trend.category == "log_source_gap":
                recs.append(
                    f"Address log source gaps — {trend.count} failures due to missing telemetry"
                )
            elif trend.category == "escalation_failure":
                recs.append(
                    f"Review escalation policies — {trend.count} alerts not acknowledged in SLA"
                )
        return recs
