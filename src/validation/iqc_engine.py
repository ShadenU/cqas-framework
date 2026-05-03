"""IQC Engine — Internal Quality Control via synthetic IOC injection."""

import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from src.utils.logger import get_logger

logger = get_logger(__name__)

# Library of synthetic IOC templates
SYNTHETIC_IOCS = {
    "malicious_ip_connection": {
        "event_type": "network",
        "src_ip": "10.99.0.1",
        "dst_ip": "198.51.100.99",  # TEST-NET-3 — safe for simulation
        "dst_port": 4444,
        "action": "accept",
        "bytes_sent": 512,
        "expected_rule": "CQAS-005",
    },
    "brute_force_sequence": {
        "event_type": "authentication",
        "action": "failure",
        "src_ip": "10.99.0.2",
        "username": "cqas_test_user",
        "expected_rule": "CQAS-002",
        "repeat": 12,
    },
    "port_scan_sequence": {
        "event_type": "network",
        "src_ip": "10.99.0.3",
        "dst_ip": "10.0.0.1",
        "action": "drop",
        "expected_rule": "CQAS-001",
        "repeat": 25,
        "vary_field": "dst_port",
        "vary_values": list(range(1, 26)),
    },
    "malware_download": {
        "event_type": "network",
        "src_ip": "10.99.0.4",
        "dst_ip": "198.51.100.10",
        "dst_port": 80,
        "action": "accept",
        "url": "http://malicious.example.com/payload.exe",
        "http_response_code": 200,
        "file_mime_type": "application/octet-stream",
        "expected_rule": "CQAS-003",
    },
}


class IQCResult:
    """Result of a single IQC injection test."""

    def __init__(
        self,
        ioc_name: str,
        expected_rule: str,
        injected_count: int,
        detected: bool,
        detection_time_seconds: Optional[float],
        details: Optional[Dict] = None,
    ) -> None:
        self.ioc_name = ioc_name
        self.expected_rule = expected_rule
        self.injected_count = injected_count
        self.detected = detected
        self.detection_time_seconds = detection_time_seconds
        self.timestamp = datetime.now(timezone.utc).isoformat()
        self.details = details or {}

    @property
    def passed(self) -> bool:
        return self.detected

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ioc_name": self.ioc_name,
            "expected_rule": self.expected_rule,
            "injected_count": self.injected_count,
            "detected": self.detected,
            "passed": self.passed,
            "detection_time_seconds": self.detection_time_seconds,
            "timestamp": self.timestamp,
            "details": self.details,
        }


class IQCEngine:
    """Internal Quality Control engine.

    Injects synthetic IOC events into a detection pipeline and validates
    that the expected detection rules fire within the allowed SLA window.

    Args:
        rule_engine: An instance of RuleEngine used for detection evaluation.
        sla_seconds: Maximum allowed detection time in seconds (default: 300).
    """

    def __init__(self, rule_engine: Any, sla_seconds: int = 300) -> None:
        self.rule_engine = rule_engine
        self.sla_seconds = sla_seconds
        self._results: List[IQCResult] = []

    def inject_and_validate(self, ioc_name: str) -> IQCResult:
        """Inject a named synthetic IOC and validate detection.

        Args:
            ioc_name: Key from SYNTHETIC_IOCS library.

        Returns:
            IQCResult describing pass/fail and timing.

        Raises:
            ValueError: If ioc_name is not in the library.
        """
        if ioc_name not in SYNTHETIC_IOCS:
            raise ValueError(f"Unknown IOC: {ioc_name}. Available: {list(SYNTHETIC_IOCS.keys())}")

        template = SYNTHETIC_IOCS[ioc_name]
        events = self._generate_events(template)
        expected_rule = template.get("expected_rule", "")

        logger.info(f"IQC: Injecting {len(events)} events for IOC '{ioc_name}'")
        start = time.monotonic()

        matches = self.rule_engine.evaluate_many(events)
        elapsed = time.monotonic() - start

        detected = any(m.rule_id == expected_rule for m in matches)
        detection_time = elapsed if detected else None

        result = IQCResult(
            ioc_name=ioc_name,
            expected_rule=expected_rule,
            injected_count=len(events),
            detected=detected,
            detection_time_seconds=detection_time,
            details={
                "matched_rules": [m.rule_id for m in matches],
                "within_sla": detection_time is not None and detection_time <= self.sla_seconds,
            },
        )
        self._results.append(result)

        if detected:
            logger.info(f"IQC PASS: '{ioc_name}' detected by rule {expected_rule} in {elapsed:.3f}s")
        else:
            logger.warning(f"IQC FAIL: '{ioc_name}' not detected. Expected rule: {expected_rule}")

        return result

    def run_all(self) -> List[IQCResult]:
        """Run IQC injection for all defined synthetic IOCs.

        Returns:
            List of IQCResult objects.
        """
        results = []
        for ioc_name in SYNTHETIC_IOCS:
            results.append(self.inject_and_validate(ioc_name))
        return results

    def calculate_dar(self) -> float:
        """Calculate Detection Accuracy Rate from all IQC results.

        Returns:
            DAR as a percentage (0.0 – 100.0).
        """
        if not self._results:
            return 0.0
        detected = sum(1 for r in self._results if r.detected)
        return (detected / len(self._results)) * 100.0

    def get_results(self) -> List[IQCResult]:
        """Return all IQC results collected so far."""
        return list(self._results)

    def summary(self) -> Dict[str, Any]:
        """Return a summary dict of IQC run results."""
        total = len(self._results)
        passed = sum(1 for r in self._results if r.passed)
        return {
            "total": total,
            "passed": passed,
            "failed": total - passed,
            "dar_percent": self.calculate_dar(),
            "results": [r.to_dict() for r in self._results],
        }

    @staticmethod
    def _generate_events(template: Dict) -> List[Dict[str, Any]]:
        """Generate one or more event dicts from a template."""
        repeat = template.get("repeat", 1)
        vary_field = template.get("vary_field")
        vary_values = template.get("vary_values", [])

        events = []
        for i in range(repeat):
            event = {
                k: v
                for k, v in template.items()
                if k not in ("expected_rule", "repeat", "vary_field", "vary_values")
            }
            event["_iqc_id"] = str(uuid.uuid4())
            event["timestamp"] = datetime.now(timezone.utc).isoformat()
            if vary_field and i < len(vary_values):
                event[vary_field] = vary_values[i]
            events.append(event)
        return events
