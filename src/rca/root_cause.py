"""Root cause analyzer — identifies why security incidents occurred."""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from src.utils.logger import get_logger

logger = get_logger(__name__)

# MITRE ATT&CK-based root cause classification taxonomy
RCA_TAXONOMY = {
    "missing_rule": {
        "description": "No detection rule exists for the observed attack technique",
        "recommendation": "Create a new detection rule for this technique",
        "priority": "critical",
    },
    "misconfigured_rule": {
        "description": "Detection rule exists but is misconfigured (wrong threshold, wrong field)",
        "recommendation": "Review and tune the rule parameters",
        "priority": "high",
    },
    "log_source_gap": {
        "description": "Required log source is not being collected",
        "recommendation": "Enable logging on the relevant system and ingest into SIEM",
        "priority": "high",
    },
    "threshold_too_high": {
        "description": "Detection threshold is set above the attack activity level",
        "recommendation": "Lower the threshold or use a tighter time window",
        "priority": "high",
    },
    "rule_disabled": {
        "description": "A relevant rule exists but is disabled",
        "recommendation": "Re-enable the rule after reviewing the disable reason",
        "priority": "medium",
    },
    "correlation_gap": {
        "description": "Individual events were detected but not correlated into an attack chain",
        "recommendation": "Add an attack chain correlation definition",
        "priority": "medium",
    },
    "escalation_failure": {
        "description": "Alert was generated but not escalated or acknowledged in time",
        "recommendation": "Review on-call roster and escalation policy configuration",
        "priority": "medium",
    },
    "unknown": {
        "description": "Root cause could not be automatically determined",
        "recommendation": "Manual investigation required",
        "priority": "low",
    },
}


class RCAFinding:
    """A single root cause analysis finding."""

    def __init__(
        self,
        incident_id: str,
        root_cause_category: str,
        description: str,
        recommendation: str,
        priority: str,
        evidence: Optional[List[str]] = None,
        related_rules: Optional[List[str]] = None,
    ) -> None:
        self.incident_id = incident_id
        self.root_cause_category = root_cause_category
        self.description = description
        self.recommendation = recommendation
        self.priority = priority
        self.evidence = evidence or []
        self.related_rules = related_rules or []
        self.created_at = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "incident_id": self.incident_id,
            "root_cause_category": self.root_cause_category,
            "description": self.description,
            "recommendation": self.recommendation,
            "priority": self.priority,
            "evidence": self.evidence,
            "related_rules": self.related_rules,
            "created_at": self.created_at,
        }


class RootCauseAnalyzer:
    """Identifies root causes for security detection failures.

    Analyzes missed detections from IQC and EPT results, or from
    real incidents, and classifies them using the RCA taxonomy.

    Args:
        rule_engine: RuleEngine instance (for rule lookup).
        active_rules_config_path: Optional path to siem_rules.yaml.
    """

    def __init__(
        self,
        rule_engine: Optional[Any] = None,
        active_rules_config_path: Optional[str] = None,
    ) -> None:
        self.rule_engine = rule_engine
        self.active_rules_config_path = active_rules_config_path
        self._findings: List[RCAFinding] = []

    def analyze_iqc_failure(self, iqc_result: Any) -> RCAFinding:
        """Analyze an IQC test failure to determine root cause.

        Args:
            iqc_result: IQCResult object with ioc_name, expected_rule, detected=False.

        Returns:
            RCAFinding for the failure.
        """
        incident_id = f"IQC-FAIL-{iqc_result.ioc_name}"
        expected_rule = iqc_result.expected_rule
        evidence = [
            f"IOC '{iqc_result.ioc_name}' injected with {iqc_result.injected_count} events",
            f"Expected rule '{expected_rule}' did not fire",
        ]

        category, extra_evidence = self._classify_rule_gap(expected_rule)
        evidence.extend(extra_evidence)

        taxonomy = RCA_TAXONOMY.get(category, RCA_TAXONOMY["unknown"])
        finding = RCAFinding(
            incident_id=incident_id,
            root_cause_category=category,
            description=taxonomy["description"],
            recommendation=taxonomy["recommendation"],
            priority=taxonomy["priority"],
            evidence=evidence,
            related_rules=[expected_rule],
        )
        self._findings.append(finding)
        logger.info(f"RCA finding: {incident_id} → {category}")
        return finding

    def analyze_ept_failure(self, ept_result: Any) -> List[RCAFinding]:
        """Analyze EPT scenario failures.

        Args:
            ept_result: EPTResult object.

        Returns:
            List of RCAFinding, one per missed expected rule.
        """
        findings = []
        missed_rules = [
            r for r in ept_result.expected_rules if r not in ept_result.detected_rules
        ]
        for rule_id in missed_rules:
            incident_id = f"EPT-FAIL-{ept_result.scenario_name}-{rule_id}"
            category, evidence = self._classify_rule_gap(rule_id)
            taxonomy = RCA_TAXONOMY.get(category, RCA_TAXONOMY["unknown"])
            finding = RCAFinding(
                incident_id=incident_id,
                root_cause_category=category,
                description=taxonomy["description"],
                recommendation=taxonomy["recommendation"],
                priority=taxonomy["priority"],
                evidence=[
                    f"Scenario '{ept_result.scenario_name}' did not trigger rule '{rule_id}'"
                ] + evidence,
                related_rules=[rule_id],
            )
            findings.append(finding)
            self._findings.append(finding)
            logger.info(f"RCA finding: {incident_id} → {category}")
        return findings

    def get_findings(self) -> List[RCAFinding]:
        return list(self._findings)

    def summary(self) -> Dict[str, Any]:
        by_category: Dict[str, int] = {}
        by_priority: Dict[str, int] = {}
        for f in self._findings:
            by_category[f.root_cause_category] = by_category.get(f.root_cause_category, 0) + 1
            by_priority[f.priority] = by_priority.get(f.priority, 0) + 1
        return {
            "total_findings": len(self._findings),
            "by_category": by_category,
            "by_priority": by_priority,
            "findings": [f.to_dict() for f in self._findings],
        }

    def _classify_rule_gap(self, rule_id: str) -> tuple:
        """Attempt to classify why a rule did not fire."""
        evidence = []

        if self.rule_engine is None:
            return "unknown", ["No rule engine available for gap analysis"]

        active_ids = {r["rule_id"] for r in self.rule_engine.rules}

        if rule_id not in active_ids:
            all_ids_in_config = active_ids
            evidence.append(f"Rule '{rule_id}' not found in active rules ({len(all_ids_in_config)} loaded)")
            return "missing_rule", evidence

        rule = next((r for r in self.rule_engine.rules if r["rule_id"] == rule_id), None)
        if rule and not rule.get("enabled", True):
            evidence.append(f"Rule '{rule_id}' is disabled")
            return "rule_disabled", evidence

        evidence.append(f"Rule '{rule_id}' is active but did not match injected events")
        return "misconfigured_rule", evidence
