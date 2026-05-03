"""Correlation engine — links related events into attack chain sequences."""

import time
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from src.utils.logger import get_logger

logger = get_logger(__name__)

# Ordered attack-chain stage definitions
ATTACK_CHAINS = {
    "brute_force_to_success": {
        "description": "Brute force followed by successful authentication",
        "stages": [
            {"event_type": "authentication", "action": "failure", "min_count": 5},
            {"event_type": "authentication", "action": "success"},
        ],
        "window_seconds": 600,
        "severity": "critical",
    },
    "scan_to_exploitation": {
        "description": "Port scan followed by connection to discovered port",
        "stages": [
            {"event_type": "network", "action": "drop"},
            {"event_type": "network", "action": "accept"},
        ],
        "window_seconds": 300,
        "severity": "high",
    },
    "login_then_lateral": {
        "description": "Authentication success followed by lateral movement indicators",
        "stages": [
            {"event_type": "authentication", "action": "success"},
            {"event_type": "network", "dst_port": 445},
        ],
        "window_seconds": 1800,
        "severity": "critical",
    },
}


class CorrelatedIncident:
    """Represents a multi-stage correlated security incident."""

    def __init__(
        self,
        chain_name: str,
        description: str,
        severity: str,
        events: List[Dict[str, Any]],
        src_ip: Optional[str] = None,
    ) -> None:
        self.chain_name = chain_name
        self.description = description
        self.severity = severity
        self.events = events
        self.src_ip = src_ip
        self.detected_at = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "chain_name": self.chain_name,
            "description": self.description,
            "severity": self.severity,
            "detected_at": self.detected_at,
            "src_ip": self.src_ip,
            "event_count": len(self.events),
            "events": [
                {
                    "timestamp": e.get("timestamp"),
                    "event_type": e.get("event_type"),
                    "action": e.get("action"),
                    "src_ip": e.get("src_ip"),
                    "dst_ip": e.get("dst_ip"),
                }
                for e in self.events
            ],
        }


class CorrelationEngine:
    """Correlates streams of events to identify multi-stage attack patterns.

    Maintains in-memory sliding windows of recent events per source IP,
    then checks for defined attack chain sequences.

    Args:
        window_seconds: Default event retention window in seconds.
    """

    def __init__(self, window_seconds: int = 3600) -> None:
        self.window_seconds = window_seconds
        # src_ip -> list of (timestamp_monotonic, event)
        self._event_buffer: Dict[str, List] = defaultdict(list)
        self._incidents: List[CorrelatedIncident] = []

    def ingest(self, event: Dict[str, Any]) -> List[CorrelatedIncident]:
        """Add an event to the correlation buffer and check for chain matches.

        Args:
            event: Normalized event dict.

        Returns:
            List of newly detected CorrelatedIncidents (may be empty).
        """
        src_ip = event.get("src_ip") or event.get("hostname") or "unknown"
        now = time.monotonic()

        self._event_buffer[src_ip].append((now, event))
        self._prune(src_ip, now)

        new_incidents = []
        for chain_name, chain_def in ATTACK_CHAINS.items():
            incident = self._check_chain(src_ip, chain_name, chain_def, now)
            if incident:
                new_incidents.append(incident)
                self._incidents.append(incident)
                logger.info(
                    "Correlated incident detected",
                    extra={"chain": chain_name, "src_ip": src_ip, "severity": chain_def["severity"]},
                )
        return new_incidents

    def ingest_many(self, events: List[Dict[str, Any]]) -> List[CorrelatedIncident]:
        """Ingest multiple events and return all correlated incidents.

        Args:
            events: List of normalized event dicts.

        Returns:
            All newly detected incidents.
        """
        incidents = []
        for event in events:
            incidents.extend(self.ingest(event))
        return incidents

    def get_incidents(self) -> List[CorrelatedIncident]:
        """Return all correlated incidents detected so far."""
        return list(self._incidents)

    # ------------------------------------------------------------------ #
    # Private helpers                                                      #
    # ------------------------------------------------------------------ #

    def _prune(self, src_ip: str, now: float) -> None:
        cutoff = now - self.window_seconds
        self._event_buffer[src_ip] = [
            (ts, ev) for ts, ev in self._event_buffer[src_ip] if ts >= cutoff
        ]

    def _check_chain(
        self, src_ip: str, chain_name: str, chain_def: Dict, now: float
    ) -> Optional[CorrelatedIncident]:
        chain_window = chain_def.get("window_seconds", self.window_seconds)
        cutoff = now - chain_window
        recent = [ev for ts, ev in self._event_buffer[src_ip] if ts >= cutoff]

        stages = chain_def["stages"]
        matched_events: List[Dict] = []

        for stage in stages:
            required_count = stage.get("min_count", 1)
            stage_matches = [e for e in recent if self._event_matches_stage(e, stage)]
            if len(stage_matches) < required_count:
                return None
            matched_events.extend(stage_matches[:required_count])

        # Avoid duplicate reporting within the window
        for existing in self._incidents[-20:]:
            if existing.chain_name == chain_name and existing.src_ip == src_ip:
                return None

        return CorrelatedIncident(
            chain_name=chain_name,
            description=chain_def["description"],
            severity=chain_def["severity"],
            events=matched_events,
            src_ip=src_ip,
        )

    @staticmethod
    def _event_matches_stage(event: Dict, stage: Dict) -> bool:
        for key, expected in stage.items():
            if key == "min_count":
                continue
            actual = event.get(key)
            if isinstance(expected, int):
                if actual != expected and str(actual) != str(expected):
                    return False
            elif str(actual).lower() != str(expected).lower():
                return False
        return True
