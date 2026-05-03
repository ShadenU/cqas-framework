"""Rule engine that evaluates SIEM detection rules against security events."""

import time
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from src.utils.helpers import load_config
from src.utils.logger import get_logger

logger = get_logger(__name__)


class RuleMatch:
    """Represents a rule match result."""

    def __init__(
        self,
        rule_id: str,
        rule_name: str,
        severity: str,
        event: Dict[str, Any],
        matched_at: Optional[str] = None,
        details: Optional[Dict] = None,
    ) -> None:
        self.rule_id = rule_id
        self.rule_name = rule_name
        self.severity = severity
        self.event = event
        self.matched_at = matched_at or datetime.now(timezone.utc).isoformat()
        self.details = details or {}

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "severity": self.severity,
            "matched_at": self.matched_at,
            "details": self.details,
            "event_summary": {
                "timestamp": self.event.get("timestamp"),
                "event_type": self.event.get("event_type"),
                "src_ip": self.event.get("src_ip"),
                "dst_ip": self.event.get("dst_ip"),
                "username": self.event.get("username"),
            },
        }


class RuleEngine:
    """Evaluates a set of detection rules against incoming security events.

    Supports threshold-based rules with sliding window aggregation (in-memory).

    Args:
        rules_config_path: Path to the siem_rules.yaml configuration file.
    """

    def __init__(self, rules_config_path: str) -> None:
        config = load_config(rules_config_path)
        self.rules: List[Dict] = [r for r in config.get("rules", []) if r.get("enabled", True)]
        # Sliding window counters: rule_id -> group_key -> list of timestamps
        self._window: Dict[str, Dict[str, List[float]]] = defaultdict(lambda: defaultdict(list))
        logger.info(f"RuleEngine loaded {len(self.rules)} active rules")

    def evaluate(self, event: Dict[str, Any]) -> List[RuleMatch]:
        """Evaluate all rules against a single event.

        Args:
            event: Normalized event dictionary.

        Returns:
            List of RuleMatch objects for rules that fired.
        """
        matches = []
        for rule in self.rules:
            match = self._evaluate_rule(rule, event)
            if match:
                matches.append(match)
                logger.info(
                    "Rule matched",
                    extra={"rule_id": rule["rule_id"], "severity": rule["severity"]},
                )
        return matches

    def evaluate_many(self, events: List[Dict[str, Any]]) -> List[RuleMatch]:
        """Evaluate all rules against a list of events.

        Args:
            events: List of normalized event dicts.

        Returns:
            Flattened list of all RuleMatch results.
        """
        all_matches = []
        for event in events:
            all_matches.extend(self.evaluate(event))
        return all_matches

    # ------------------------------------------------------------------ #
    # Private evaluation helpers                                           #
    # ------------------------------------------------------------------ #

    def _evaluate_rule(self, rule: Dict, event: Dict) -> Optional[RuleMatch]:
        conditions = rule.get("conditions", {})

        if not self._check_event_type(conditions, event):
            return None
        if not self._check_field_match(conditions, event):
            return None

        threshold = conditions.get("threshold")
        if threshold:
            return self._check_threshold(rule, threshold, event)

        # Simple match (no threshold required)
        return RuleMatch(
            rule_id=rule["rule_id"],
            rule_name=rule["name"],
            severity=rule["severity"],
            event=event,
        )

    def _check_event_type(self, conditions: Dict, event: Dict) -> bool:
        required_type = conditions.get("event_type")
        if required_type and event.get("event_type") != required_type:
            return False
        return True

    def _check_field_match(self, conditions: Dict, event: Dict) -> bool:
        for field, expected in conditions.items():
            if field in ("event_type", "threshold", "source_field", "filter", "match_any"):
                continue
            if isinstance(expected, (str, int, float)):
                if str(event.get(field, "")).lower() != str(expected).lower():
                    return False
        return True

    def _check_threshold(
        self, rule: Dict, threshold: Dict, event: Dict
    ) -> Optional[RuleMatch]:
        rule_id = rule["rule_id"]
        window_seconds = rule.get("timeframe_seconds", 60)
        count_required = threshold.get("count", 1)
        source_field = rule.get("conditions", {}).get("source_field", "src_ip")
        group_key = event.get(source_field, "unknown")

        now = time.monotonic()
        cutoff = now - window_seconds

        window_list = self._window[rule_id][group_key]
        window_list.append(now)
        # Prune old entries
        self._window[rule_id][group_key] = [t for t in window_list if t >= cutoff]

        current_count = len(self._window[rule_id][group_key])

        if current_count >= count_required:
            self._window[rule_id][group_key] = []  # reset after firing
            return RuleMatch(
                rule_id=rule["rule_id"],
                rule_name=rule["name"],
                severity=rule["severity"],
                event=event,
                details={"count": current_count, "window_seconds": window_seconds, "group_key": group_key},
            )
        return None
