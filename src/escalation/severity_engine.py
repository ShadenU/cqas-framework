"""Severity engine — scores alert severity on a 0.0–1.0 scale."""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from src.utils.logger import get_logger

logger = get_logger(__name__)

# Severity weights and base scores
SEVERITY_BASE_SCORES = {
    "critical": 0.90,
    "high": 0.70,
    "medium": 0.50,
    "low": 0.25,
    "info": 0.10,
}

# Modifier factors applied to base scores
MODIFIERS = {
    "is_dc_asset": 0.15,        # Domain controller involved — escalate
    "after_hours": 0.10,        # Outside business hours
    "repeated_source": 0.10,    # Same src_ip seen multiple times
    "known_bad_ip": 0.20,       # IP on threat intelligence blocklist
    "data_involved": 0.15,      # Potential data exfiltration
    "lateral_movement": 0.15,   # Lateral movement indicators
}


class ScoredAlert:
    """An alert with a computed severity score."""

    def __init__(
        self,
        alert_id: str,
        rule_id: str,
        rule_name: str,
        base_severity: str,
        score: float,
        computed_severity: str,
        modifiers_applied: List[str],
        event: Dict[str, Any],
    ) -> None:
        self.alert_id = alert_id
        self.rule_id = rule_id
        self.rule_name = rule_name
        self.base_severity = base_severity
        self.score = score
        self.computed_severity = computed_severity
        self.modifiers_applied = modifiers_applied
        self.event = event
        self.created_at = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "alert_id": self.alert_id,
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "base_severity": self.base_severity,
            "score": round(self.score, 3),
            "computed_severity": self.computed_severity,
            "modifiers_applied": self.modifiers_applied,
            "created_at": self.created_at,
            "event_summary": {
                "src_ip": self.event.get("src_ip"),
                "dst_ip": self.event.get("dst_ip"),
                "event_type": self.event.get("event_type"),
                "timestamp": self.event.get("timestamp"),
            },
        }


class SeverityEngine:
    """Calculates severity scores for security alerts.

    Starts from a rule's base severity and applies contextual modifiers
    (asset criticality, time-of-day, threat intelligence, etc.).

    Args:
        escalation_config: Escalation policies config dict (from escalation_policies.yaml).
        known_bad_ips: Optional set of IPs from threat intelligence feeds.
        critical_assets: Optional set of hostnames/IPs classified as critical.
    """

    def __init__(
        self,
        escalation_config: Optional[Dict] = None,
        known_bad_ips: Optional[set] = None,
        critical_assets: Optional[set] = None,
    ) -> None:
        self.escalation_config = escalation_config or {}
        self.known_bad_ips: set = known_bad_ips or set()
        self.critical_assets: set = critical_assets or set()
        self._severity_ranges = self._build_severity_ranges()

    def score(self, rule_match: Any, context: Optional[Dict] = None) -> ScoredAlert:
        """Score a rule match and return a ScoredAlert.

        Args:
            rule_match: RuleMatch object (must have rule_id, rule_name, severity, event).
            context: Optional context dict with additional signals.

        Returns:
            ScoredAlert with computed severity.
        """
        import uuid

        context = context or {}
        base_severity = rule_match.severity.lower()
        base_score = SEVERITY_BASE_SCORES.get(base_severity, 0.5)

        score = base_score
        applied = []

        for modifier_name, modifier_value in MODIFIERS.items():
            if self._should_apply(modifier_name, rule_match.event, context):
                score = min(1.0, score + modifier_value)
                applied.append(modifier_name)

        computed_severity = self._score_to_severity(score)

        return ScoredAlert(
            alert_id=str(uuid.uuid4()),
            rule_id=rule_match.rule_id,
            rule_name=rule_match.rule_name,
            base_severity=base_severity,
            score=score,
            computed_severity=computed_severity,
            modifiers_applied=applied,
            event=rule_match.event,
        )

    def score_many(
        self, rule_matches: List[Any], context: Optional[Dict] = None
    ) -> List[ScoredAlert]:
        return [self.score(m, context) for m in rule_matches]

    # ------------------------------------------------------------------ #
    # Private helpers                                                      #
    # ------------------------------------------------------------------ #

    def _should_apply(self, modifier: str, event: Dict, context: Dict) -> bool:
        if modifier == "known_bad_ip":
            src_ip = event.get("src_ip") or ""
            dst_ip = event.get("dst_ip") or ""
            return src_ip in self.known_bad_ips or dst_ip in self.known_bad_ips
        if modifier == "is_dc_asset":
            hostname = event.get("hostname") or event.get("dst_ip") or ""
            return hostname in self.critical_assets
        if modifier == "after_hours":
            return context.get("after_hours", False)
        if modifier == "repeated_source":
            return context.get("repeated_source", False)
        if modifier == "data_involved":
            bytes_sent = event.get("bytes_sent", 0) or 0
            return int(bytes_sent) > 10_000_000  # > 10 MB
        if modifier == "lateral_movement":
            return event.get("protocol") == "smb" or event.get("dst_port") == 445
        return False

    def _score_to_severity(self, score: float) -> str:
        for level, (low, high) in self._severity_ranges.items():
            if low <= score <= high:
                return level
        return "low"

    def _build_severity_ranges(self) -> Dict[str, tuple]:
        severity_levels = self.escalation_config.get("severity_levels", {})
        ranges = {}
        for level, cfg in severity_levels.items():
            score_range = cfg.get("score_range", [0, 1])
            ranges[level] = (score_range[0], score_range[1])
        if not ranges:
            # defaults matching escalation_policies.yaml
            ranges = {
                "critical": (0.85, 1.0),
                "high": (0.65, 0.85),
                "medium": (0.40, 0.65),
                "low": (0.0, 0.40),
            }
        return ranges
